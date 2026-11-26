//! The daemon object: shared state, request dispatch and the connection loop.

use crate::{attach, config::Config, ebpf, error, files, net, sandbox, state::State};
use anyhow::{Context, Result, anyhow};
use sbx_proto::{ErrorBody, ErrorCode, Request, Response};
use serde_json::Value;
use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

/// Everything a request handler may touch. Shared by every connection thread
/// through an `Arc`.
pub struct Daemon {
    pub config: Config,
    pub state: Mutex<State>,
    /// Serializes create and remove: only one lifecycle change at a time.
    pub lifecycle: Mutex<()>,
    /// Loaded eBPF programs; attaching is serialized with this lock.
    pub ebpf: Mutex<ebpf::Datapath>,
}

impl Daemon {
    /// Reads the persisted state and returns a daemon ready to serve.
    pub fn load(config: Config, ebpf: ebpf::Datapath) -> Result<Self> {
        let state = match fs::read(&config.state) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid daemon state")?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            config,
            state: Mutex::new(state),
            lifecycle: Mutex::new(()),
            ebpf: Mutex::new(ebpf),
        })
    }

    /// Re-attaches the datapath to veths that outlived a previous daemon run.
    ///
    /// TCX links die with the daemon, so this only matters for sandboxes that
    /// were created by an earlier instance. A stale interface is reported and
    /// skipped rather than stopping the daemon.
    pub fn attach_existing(&self) {
        for interface in net::sandbox_veths().unwrap_or_default() {
            if let Err(e) = self
                .ebpf
                .lock()
                .expect("ebpf lock poisoned")
                .attach(&interface)
            {
                eprintln!("eBPF attach {interface}: {e:#}");
            }
        }
    }

    /// Writes the current state through an atomic rename.
    pub fn persist(&self) -> Result<()> {
        let state = self.state.lock().expect("state lock poisoned");
        if let Some(parent) = self.config.state.parent() {
            fs::create_dir_all(parent)?;
        }
        files::atomic_write(&self.config.state, &serde_json::to_vec_pretty(&*state)?)
    }

    /// Binds the socket and serves until the listener fails.
    pub fn serve(self: Arc<Self>) -> Result<()> {
        let listener = bind_socket(&self.config.socket)?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let daemon = Arc::clone(&self);
                    thread::spawn(move || handle(daemon, stream));
                }
                Err(e) => eprintln!("connection: {e}"),
            }
        }
        Ok(())
    }
}

/// Binds the client socket, refusing to clobber anything that is not a stale
/// socket of ours.
fn bind_socket(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(anyhow!("refusing to remove non-socket {}", path.display()));
        }
        match UnixStream::connect(path) {
            Ok(_) => return Err(anyhow!("socket {} is already in use", path.display())),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Handles one non-attach request and returns its data payload.
pub fn dispatch(daemon: &Daemon, request: Request) -> Result<Value> {
    match request {
        Request::New { id, bundle, gpu } => Ok(serde_json::to_value(sandbox::create(
            daemon, id, bundle, gpu,
        )?)?),
        Request::Ls {} => sandbox::list(&daemon.config),
        Request::Run { id, argv } => sandbox::run(&daemon.config, id, argv),
        Request::Rm { id } => sandbox::remove(daemon, id),
        Request::GpuAttach { .. } => Err(error::coded(
            ErrorCode::NotImplemented,
            "GPU attach is not implemented",
        )),
        Request::Attach { .. } => Err(error::coded(
            ErrorCode::InvalidRequest,
            "attach must be handled on its connection",
        )),
        Request::Resize { .. } => Err(error::coded(
            ErrorCode::InvalidRequest,
            "resize is only valid inside an attach session",
        )),
    }
}

/// Serves one client connection: one request line, then either a single
/// response or, for `attach`, the framed terminal relay.
fn handle(daemon: Arc<Daemon>, mut stream: UnixStream) {
    let request = sbx_proto::read_line(&mut stream)
        .map_err(|e| ErrorBody::new(ErrorCode::InvalidRequest, e.to_string()))
        .and_then(|line| {
            serde_json::from_slice::<Request>(&line)
                .map_err(|e| ErrorBody::new(ErrorCode::InvalidRequest, e.to_string()))
        });
    let response = match request {
        Ok(Request::Attach {
            id,
            shell,
            rows,
            cols,
        }) => match attach::relay(&daemon, &mut stream, &id, shell, rows, cols) {
            Ok(()) => return,
            Err(err) => error::into_response(err),
        },
        Ok(request) => dispatch(&daemon, request)
            .map(Response::success)
            .unwrap_or_else(error::into_response),
        Err(err) => Response::failure(err),
    };
    let _ = sbx_proto::write_line(&mut stream, &response);
}
