use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};

pub const DEFAULT_SOCKET: &str = "/run/sbxd.sock";

fn default_rows() -> u16 {
    24
}
fn default_cols() -> u16 {
    80
}

/// Frames carried on the attach connection after the JSON handshake.
///
/// The socket is a byte stream, so control messages cannot simply be
/// interleaved with terminal output. Every frame is one tag byte plus a
/// little-endian u32 length and that many payload bytes:
///   'D' terminal data (either direction)
///   'C' control: a JSON object, client -> daemon only
///   'E' end of session: the daemon closes the shell
pub const FRAME_DATA: u8 = b'D';
pub const FRAME_CONTROL: u8 = b'C';
pub const FRAME_EXIT: u8 = b'E';
pub const MAX_FRAME: usize = 64 * 1024;

pub fn write_frame(writer: &mut impl Write, tag: u8, payload: &[u8]) -> io::Result<()> {
    let mut header = [0u8; 5];
    header[0] = tag;
    header[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    writer.write_all(&header)?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Returns `(tag, payload)`. `Ok(None)` means the peer closed the stream.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 5];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(header[1..].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attach frame exceeds 64 KiB",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some((header[0], payload)))
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    New {
        id: String,
        bundle: Option<String>,
        #[serde(default)]
        gpu: bool,
    },
    Rm {
        id: String,
    },
    Ls {},
    Run {
        id: String,
        argv: Vec<String>,
    },
    Attach {
        id: String,
        shell: bool,
        /// Initial terminal size; clients without a tty may omit both.
        #[serde(default = "default_rows")]
        rows: u16,
        #[serde(default = "default_cols")]
        cols: u16,
    },
    /// Window-size change for an attach session already in progress.
    Resize {
        rows: u16,
        cols: u16,
    },
    GpuAttach {
        id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidId,
    NotFound,
    AlreadyExists,
    InvalidRequest,
    IoError,
    CommandFailed,
    NotImplemented,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}
impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl From<io::Error> for ErrorBody {
    fn from(e: io::Error) -> Self {
        Self::new(ErrorCode::IoError, e.to_string())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}
impl Response {
    pub fn success(data: Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn failure(error: ErrorBody) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(error),
        }
    }
}

// Read only the JSON line: attach bytes following it must remain on the socket.
pub fn read_line(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() == 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JSON line exceeds 1 MiB",
            ));
        }
        line.push(byte[0]);
    }
}
pub fn write_line(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

impl std::fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ErrorBody {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn protocol_round_trip() {
        for value in [
            json!({"op":"new","id":"x","bundle":null,"gpu":false}),
            json!({"op":"rm","id":"x"}),
            json!({"op":"ls"}),
            json!({"op":"run","id":"x","argv":["/sbin/ip","addr"]}),
            json!({"op":"attach","id":"x","shell":true,"rows":24,"cols":80}),
            json!({"op":"attach","id":"x","shell":true,"rows":50,"cols":200}),
            json!({"op":"resize","rows":40,"cols":120}),
            json!({"op":"gpu-attach","id":"x"}),
        ] {
            let request: Request = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(&request).unwrap(), value);
        }
        for response in [
            Response::success(json!({"code":0,"stdout":"hi\n","stderr":""})),
            Response::failure(ErrorBody::new(ErrorCode::InvalidId, "bad id")),
        ] {
            let bytes = serde_json::to_vec(&response).unwrap();
            assert_eq!(
                serde_json::from_slice::<Response>(&bytes).unwrap(),
                response
            );
        }
    }
    #[test]
    fn line_reader_preserves_attach_bytes() {
        let mut stream = &b"{\"ok\":true}\nfirst shell output"[..];
        assert_eq!(read_line(&mut stream).unwrap(), b"{\"ok\":true}");
        assert_eq!(stream, b"first shell output");
    }
    #[test]
    fn malformed_requests_are_rejected() {
        for s in [
            r#"{"op":"run","id":"x"}"#,
            r#"{"op":"unknown"}"#,
            r#"{"op":"ls","extra":true}"#,
        ] {
            assert!(serde_json::from_str::<Request>(s).is_err());
        }
    }
}
