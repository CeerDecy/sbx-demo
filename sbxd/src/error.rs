//! Bridging `anyhow` errors to the wire-level [`ErrorBody`].

use anyhow::Error;
use sbx_proto::{ErrorBody, ErrorCode, Response};

/// Builds an error carrying a protocol-level code.
///
/// Any error that already is an [`ErrorBody`] survives the trip back to the
/// client with its code; everything else becomes `IoError`.
pub fn coded(code: ErrorCode, message: impl Into<String>) -> Error {
    ErrorBody::new(code, message).into()
}

/// Turns any error into the failure response sent to the client.
pub fn into_response(err: Error) -> Response {
    Response::failure(
        err.downcast_ref::<ErrorBody>()
            .cloned()
            .unwrap_or_else(|| ErrorBody::new(ErrorCode::IoError, format!("{err:#}"))),
    )
}
