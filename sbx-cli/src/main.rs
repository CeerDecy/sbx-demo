use clap::{Parser, Subcommand, ValueEnum};
use sbx_proto::{DEFAULT_SOCKET, ErrorBody, Request, Response};
use serde_json::Value;
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::exit,
};

/// Client for the sbxd sandbox daemon. All privileged work happens in the
/// daemon; this binary only parses arguments and speaks the socket protocol.
#[derive(Parser)]
#[command(
    name = "sbx",
    version,
    about = "gVisor sandbox client (talks to sbxd over a Unix socket)",
    arg_required_else_help = true
)]
struct Cli {
    /// Path to the sbxd Unix socket
    #[arg(
        long,
        global = true,
        env = "SBX_SOCKET",
        value_name = "PATH",
        default_value = DEFAULT_SOCKET
    )]
    socket: PathBuf,

    /// Output format
    #[arg(short = 'o', long, global = true, value_enum, default_value_t = Output::Table)]
    output: Output,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Output {
    /// Human readable output
    Table,
    /// Raw daemon response
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Create a sandbox together with its own network namespace
    New {
        /// Sandbox id: lowercase letters, digits and dash
        id: String,

        /// Base bundle directory (defaults to the daemon's configured bundle)
        #[arg(long, value_name = "DIR")]
        bundle: Option<String>,

        /// Reserved: GPU device injection is not implemented
        #[arg(long)]
        gpu: bool,
    },

    /// List sandboxes with their address and network namespace
    Ls,

    /// Stop a sandbox and remove its network
    Rm {
        /// Sandbox id
        id: String,
    },

    /// Run one command inside a sandbox
    Run {
        /// Sandbox id
        id: String,

        /// Command and arguments (everything after the id)
        #[arg(
            required = true,
            num_args = 1..,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "CMD"
        )]
        argv: Vec<String>,
    },

    /// Open an interactive shell inside a sandbox
    Shell {
        /// Sandbox id
        id: String,
    },

    /// Reserved: attach a GPU to a sandbox
    GpuAttach {
        /// Sandbox id
        id: String,
    },
}

impl From<Command> for Request {
    fn from(command: Command) -> Self {
        match command {
            Command::New { id, bundle, gpu } => Request::New { id, bundle, gpu },
            Command::Ls => Request::Ls {},
            Command::Rm { id } => Request::Rm { id },
            Command::Run { id, argv } => Request::Run { id, argv },
            Command::Shell { id } => Request::Attach {
                id,
                shell: true,
                rows: 24,
                cols: 80,
            },
            Command::GpuAttach { id } => Request::GpuAttach { id },
        }
    }
}

fn fail(resp: Response) -> ! {
    let e = resp.error.unwrap_or(ErrorBody {
        code: sbx_proto::ErrorCode::IoError,
        message: "unknown daemon error".into(),
    });
    eprintln!("{}", e.message);
    exit(1)
}

fn field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(Value::as_str).unwrap_or("-")
}

/// Left-aligned columns with two spaces between them, sized to the content.
fn print_table(header: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let render = |cells: &[String]| {
        let mut line = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                line.push_str(cell);
            } else {
                line.push_str(cell);
                for _ in cell.chars().count()..widths[i] + 2 {
                    line.push(' ');
                }
            }
        }
        line
    };
    let head: Vec<String> = header.iter().map(|h| h.to_string()).collect();
    println!("{}", render(&head));
    for row in rows {
        println!("{}", render(row));
    }
}

fn render_new(data: &Value) {
    println!("sandbox/{} created", field(data, "id"));
    println!("  address   {}", field(data, "ident"));
    println!("  veth      {}", field(data, "veth"));
    println!("  netns     {}", field(data, "netns"));
    println!("  bundle    {}", field(data, "bundle"));
}

fn render_ls(data: &Value) {
    let mut rows: Vec<Vec<String>> = data
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    vec![
                        field(item, "id").to_string(),
                        field(item, "status").to_string(),
                        field(item, "address").to_string(),
                        field(item, "netns").to_string(),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        eprintln!("No sandboxes found.");
        return;
    }
    rows.sort();
    print_table(&["ID", "STATUS", "ADDRESS", "NETNS"], &rows);
}

/// `run` passes the child's streams through untouched, like `kubectl exec`.
fn render_run(data: &Value) {
    if let Some(out) = data.get("stdout").and_then(Value::as_str) {
        print!("{out}");
    }
    if let Some(err) = data.get("stderr").and_then(Value::as_str) {
        eprint!("{err}");
    }
}

fn render(request: &Request, data: &Value) {
    match request {
        Request::New { .. } => render_new(data),
        Request::Ls {} => render_ls(data),
        Request::Rm { .. } => println!("sandbox/{} removed", field(data, "id")),
        Request::Run { .. } => render_run(data),
        _ => println!("{}", serde_json::to_string_pretty(data).unwrap_or_default()),
    }
}

mod term {
    use std::{
        fs::File,
        io::Read,
        os::unix::io::FromRawFd,
        sync::{
            OnceLock,
            atomic::{AtomicI32, Ordering},
        },
        thread,
    };

    /// Saved `termios` for the controlling terminal, restored on exit.
    pub struct Saved(pub libc::termios);

    pub struct Terminal {
        fd: i32,
        saved: Saved,
    }

    /// `(rows, cols)`, falling back to 24x80 when stdin is not a terminal.
    pub fn size() -> (u16, u16) {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ only writes into `ws`.
        let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
            (ws.ws_row, ws.ws_col)
        } else {
            (24, 80)
        }
    }

    impl Terminal {
        /// Puts stdin/stdout into raw mode so every keystroke reaches the
        /// sandbox immediately and Ctrl-C is delivered as a byte, not a signal.
        pub fn enter_raw() -> Self {
            let fd = libc::STDIN_FILENO;
            // SAFETY: tcgetattr/tcsetattr operate on the fd we checked above.
            unsafe {
                let mut saved: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut saved) != 0 {
                    return Self {
                        fd,
                        saved: Saved(std::mem::zeroed()),
                    };
                }
                let mut raw = saved;
                // Equivalent to cfmakeraw(3).
                raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
                raw.c_iflag &=
                    !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
                raw.c_oflag &= !libc::OPOST;
                raw.c_cflag |= libc::CS8;
                raw.c_cc[libc::VMIN] = 1;
                raw.c_cc[libc::VTIME] = 0;
                libc::tcsetattr(fd, libc::TCSANOW, &raw);
                Self {
                    fd,
                    saved: Saved(saved),
                }
            }
        }
    }

    /// Restores the modes saved by `enter_raw`. Safe to call more than once.
    pub fn restore(saved: &Saved) {
        // SAFETY: restoring a previously captured termios for our own tty.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved.0);
        }
    }

    static WINCH_FD: AtomicI32 = AtomicI32::new(-1);

    /// Installs a SIGWINCH handler on a dedicated thread that forwards each
    /// resize through `notify`. The handler itself only writes one byte to a
    /// self-pipe; signal-safety rules forbid doing more.
    pub fn on_winch<F: Fn() + Send + 'static>(notify: F) {
        static READ_END: OnceLock<i32> = OnceLock::new();
        let read_end = *READ_END.get_or_init(|| {
            let mut fds = [0i32; 2];
            // SAFETY: pipe(2) fills a two-element array we own.
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            if rc != 0 {
                return -1;
            }
            WINCH_FD.store(fds[1], Ordering::SeqCst);
            // SAFETY: signal() with a bare extern "C" fn is the standard ABI.
            unsafe {
                libc::signal(
                    libc::SIGWINCH,
                    handle_winch as *const () as libc::sighandler_t,
                );
            }
            fds[0]
        });
        if read_end < 0 {
            return;
        }
        thread::spawn(move || {
            // SAFETY: wrapping the read end we created just above.
            let mut file = unsafe { File::from_raw_fd(read_end) };
            let mut byte = [0u8; 1];
            while file.read_exact(&mut byte).is_ok() {
                notify();
            }
        });
    }

    extern "C" fn handle_winch(_: libc::c_int) {
        let fd = WINCH_FD.load(Ordering::Relaxed);
        if fd >= 0 {
            // SAFETY: async-signal-safe write of one byte; ignoring the result.
            unsafe {
                libc::write(fd, [1u8].as_ptr() as *const libc::c_void, 1);
            }
        }
    }

    impl Drop for Terminal {
        fn drop(&mut self) {
            if self.fd >= 0 {
                restore(&self.saved);
            }
        }
    }
}

/// Reads local keystrokes and ships them as data frames.
fn spawn_input(mut socket: UnixStream) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if sbx_proto::write_frame(&mut socket, sbx_proto::FRAME_DATA, &buf[..n])
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = socket.shutdown(Shutdown::Write);
    })
}

/// Writes server frames to stdout until the daemon ends the session.
fn relay_output(stream: &mut UnixStream) {
    let mut stdout = io::stdout();
    while let Ok(Some((tag, payload))) = sbx_proto::read_frame(stream) {
        match tag {
            sbx_proto::FRAME_DATA => {
                if stdout.write_all(&payload).is_err() {
                    return;
                }
                let _ = stdout.flush();
            }
            sbx_proto::FRAME_EXIT => return,
            _ => {}
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let socket = cli.socket;
    let output = cli.output;
    let mut request: Request = cli.command.into();
    if let Request::Attach { rows, cols, .. } = &mut request {
        let (r, c) = term::size();
        *rows = r;
        *cols = c;
    }

    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {e}", socket.display());
            exit(1)
        }
    };
    if let Err(e) = sbx_proto::write_line(&mut stream, &request) {
        eprintln!("{e}");
        exit(1)
    }
    let line = match sbx_proto::read_line(&mut stream) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            exit(1)
        }
    };
    let resp: Response = match serde_json::from_slice(&line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            exit(1)
        }
    };
    if !resp.ok {
        fail(resp)
    }

    // `shell` puts the local terminal in raw mode and relays framed data, so
    // the sandbox sees a real tty and line editing / job control work.
    if let Request::Attach { .. } = &request {
        let terminal = term::Terminal::enter_raw();
        let socket_in = stream.try_clone().expect("clone socket");

        // Forward window-size changes so the remote pty re-wraps too.
        let resize_socket = socket_in.try_clone().ok();
        term::on_winch(move || {
            if let Some(mut s) = resize_socket.as_ref().and_then(|s| s.try_clone().ok()) {
                let (rows, cols) = term::size();
                let msg = serde_json::to_vec(&Request::Resize { rows, cols }).unwrap_or_default();
                let _ = sbx_proto::write_frame(&mut s, sbx_proto::FRAME_CONTROL, &msg);
            }
        });

        let input_thread = spawn_input(socket_in);
        relay_output(&mut stream);
        drop(terminal);
        // The session is over; the terminal is restored. The input thread is
        // still parked in read(2) on a terminal nobody will type into again, so
        // joining it would hang the client. A second Enter wakes it, and the
        // process exits either way.
        let _ = input_thread;
        return;
    }

    let data = resp.data.unwrap_or(Value::Null);
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(&data).unwrap()),
        Output::Table => render(&request, &data),
    }

    // `run` propagates the sandboxed command's exit status so callers can
    // branch on it, while `new`/`rm`/`ls` always exit 0 on success.
    if matches!(&request, Request::Run { .. })
        && let Some(code) = data.get("code").and_then(Value::as_i64)
    {
        exit(code.clamp(0, 255) as i32);
    }
}
