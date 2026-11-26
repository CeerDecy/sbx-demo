//! Interactive `attach`: a host pty relayed between the client and runsc.

use crate::{daemon::Daemon, error, sandbox};
use anyhow::Result;
use sbx_proto::ErrorCode;
use serde_json::json;
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        io::{AsRawFd, FromRawFd},
    },
    process::{Child, Command, Stdio},
    thread,
};

/// A pseudo-terminal pair created on the host. `master` stays with the daemon
/// (relayed to the client socket); `slave` is handed to the child as its
/// controlling terminal so interactive shells get job control.
struct Pty {
    master: File,
    slave: File,
}

impl Pty {
    /// Opens a pty sized `rows` x `cols`.
    fn open(rows: u16, cols: u16) -> io::Result<Self> {
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `openpty` fills the two fds and reads `size`; both are owned
        // by this stack frame and the call has no other preconditions.
        let rc = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both fds are open and owned by us; wrapping transfers
        // ownership so they are closed on drop instead of leaked.
        unsafe {
            Ok(Self {
                master: File::from_raw_fd(master_fd),
                slave: File::from_raw_fd(slave_fd),
            })
        }
    }

    /// Applies a window size to the pty master; false when the ioctl fails.
    fn resize(fd: &File, rows: u16, cols: u16) -> bool {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `fd` is a live pty master; TIOCSWINSZ only reads `size`.
        unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) == 0 }
    }
}

/// Spawns the interactive shell and returns it with its pty.
fn start(
    daemon: &Daemon,
    id: &str,
    shell: bool,
    rows: u16,
    cols: u16,
) -> Result<(Child, String, Pty)> {
    if !sandbox::valid_id(id) {
        return Err(error::coded(ErrorCode::InvalidId, "invalid id"));
    }
    if !shell {
        return Err(error::coded(
            ErrorCode::InvalidRequest,
            "attach requires shell=true",
        ));
    }
    if !sandbox::exists(&daemon.config, id)? {
        return Err(error::coded(
            ErrorCode::NotFound,
            format!("no such sandbox '{id}'"),
        ));
    }
    let bash = daemon
        .config
        .bundles
        .join(format!("sbx-{id}/rootfs/bin/bash"));
    let shell = if bash
        .metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    {
        "/bin/bash"
    } else {
        "/bin/sh"
    };
    let pty = Pty::open(rows.max(1), cols.max(1))?;
    // All three stdio slots point at the same terminal: a shell that talks to a
    // pipe for stdout would still report "can't access tty".
    let child = Command::new(&daemon.config.runsc)
        .args(["--root", &daemon.config.runsc_root, "exec", id, shell, "-i"])
        .stdin(Stdio::from(pty.slave.try_clone()?))
        .stdout(Stdio::from(pty.slave.try_clone()?))
        .stderr(Stdio::from(pty.slave.try_clone()?))
        .spawn()?;
    Ok((child, shell.to_owned(), pty))
}

/// Relays an attach session: terminal output flows daemon -> client, while the
/// client may interleave data and control frames (resize) in the other
/// direction. Control frames never reach the shell.
pub fn relay(
    daemon: &Daemon,
    stream: &mut std::os::unix::net::UnixStream,
    id: &str,
    shell: bool,
    rows: u16,
    cols: u16,
) -> Result<()> {
    let mut input = stream.try_clone()?;
    let (mut child, shell, pty) = start(daemon, id, shell, rows, cols)?;
    if let Err(e) = sbx_proto::write_line(
        stream,
        &sbx_proto::Response::success(json!({"id":id,"shell":shell,"tty":true})),
    ) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.into());
    }
    // Only the master end may be held open by this process. `pty.slave` is
    // still alive here, so the output thread would never see EOF after the
    // shell exits; drop our copies now that the child inherits them.
    drop(pty.slave);
    let mut output = stream.try_clone()?;
    let mut master_for_output = pty.master.try_clone()?;
    let outgoing = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match master_for_output.read(&mut buf) {
                // EIO is how a pty master reports that the slave side is gone.
                Ok(0) => break,
                Ok(n) => {
                    if sbx_proto::write_frame(&mut output, sbx_proto::FRAME_DATA, &buf[..n])
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = sbx_proto::write_frame(&mut output, sbx_proto::FRAME_EXIT, &[]);
    });
    let master_fd = pty.master.try_clone()?;
    let resize_fd = pty.master.try_clone()?;
    let child_pid = child.id();
    // The client may stop sending at any time without closing the socket, so
    // the read side cannot be the thing that ends the session: wait on the
    // child, and let the output thread finish the last frame. A vanished
    // client is the other way round -- the reader notices and ends the shell.
    let input_thread = thread::spawn(move || {
        while let Ok(Some((tag, payload))) = sbx_proto::read_frame(&mut input) {
            match tag {
                sbx_proto::FRAME_DATA => {
                    let mut master = &master_fd;
                    if master.write_all(&payload).is_err() {
                        break;
                    }
                }
                sbx_proto::FRAME_CONTROL => {
                    if let Ok(sbx_proto::Request::Resize { rows, cols }) =
                        serde_json::from_slice::<sbx_proto::Request>(&payload)
                    {
                        Pty::resize(&resize_fd, rows.max(1), cols.max(1));
                    }
                }
                _ => break,
            }
        }
        // SAFETY: signalling a child we spawned by its pid; a stale pid is
        // harmless because the process has reaped it by the time we exit.
        unsafe {
            libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
        }
    });
    let _ = child.wait();
    let _ = outgoing.join();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = input_thread;
    Ok(())
}
