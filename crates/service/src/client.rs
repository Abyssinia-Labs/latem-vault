//! The CLI's side of the local API.

use std::io::{self, ErrorKind};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::api::{self, DecodeError, Request, Response};

/// Whether a service answers on `socket`.
pub fn is_running(socket: &Path) -> bool {
    UnixStream::connect(socket).is_ok()
}

/// Sends `request` to the service on `socket`. `Ok(None)` if no service is running there.
pub fn call(socket: &Path, request: &Request) -> io::Result<Option<Response>> {
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        // No socket, or one left over from a service that crashed.
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    api::write_message(&mut stream, &request.encode())?;
    let (kind, body) = api::read_message(&mut stream).map_err(|e| match e {
        DecodeError::Io(e) if e.kind() == ErrorKind::UnexpectedEof => io::Error::new(
            ErrorKind::UnexpectedEof,
            "the service closed the connection without answering",
        ),
        DecodeError::Io(e) => e,
        DecodeError::Bad(reason) => io::Error::new(ErrorKind::InvalidData, reason),
    })?;
    Response::decode(kind, &body)
        .map(Some)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))
}
