//! Messages on a stream (sync.md, framing): `u32 length ‖ type ‖ body`, at most 2 MiB of type
//! and body.

use iroh::endpoint::{RecvStream, SendStream};

/// The most a message's type and body may take.
pub const MAX_MESSAGE: usize = 2 << 20;

/// `0x7f` error: sent just before closing.
pub const ERROR: u8 = 0x7f;

/// Why a peer ended a session (sync.md, framing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    WrongVault,
    NotAMember,
    Fork,
    BadMessage,
    WrongCode,
    JoinRefused,
    Other(u8),
}

impl Reason {
    fn code(self) -> u8 {
        match self {
            Self::WrongVault => 0x01,
            Self::NotAMember => 0x02,
            Self::Fork => 0x03,
            Self::BadMessage => 0x04,
            Self::WrongCode => 0x05,
            Self::JoinRefused => 0x06,
            Self::Other(code) => code,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::WrongVault,
            0x02 => Self::NotAMember,
            0x03 => Self::Fork,
            0x04 => Self::BadMessage,
            0x05 => Self::WrongCode,
            0x06 => Self::JoinRefused,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongVault => f.write_str("wrong vault"),
            Self::NotAMember => f.write_str("not a member"),
            Self::Fork => f.write_str("fork"),
            Self::BadMessage => f.write_str("bad message"),
            Self::WrongCode => f.write_str("wrong code"),
            Self::JoinRefused => f.write_str("join refused"),
            Self::Other(code) => write!(f, "error {code:#04x}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("the peer ended the session: {reason} ({detail})")]
    Peer { reason: Reason, detail: String },
    #[error("bad message: {0}")]
    Bad(&'static str),
    #[error("connection failed: {0}")]
    Connection(String),
}

pub async fn write(send: &mut SendStream, kind: u8, body: &[u8]) -> Result<(), FrameError> {
    let len = 1 + body.len();
    assert!(len <= MAX_MESSAGE, "callers keep messages within the limit");
    let message = [&(len as u32).to_be_bytes()[..], &[kind], body].concat();
    send.write_all(&message)
        .await
        .map_err(|e| FrameError::Connection(e.to_string()))
}

/// Reads one message. An error message from the peer comes back as [`FrameError::Peer`].
pub async fn read(recv: &mut RecvStream) -> Result<(u8, Vec<u8>), FrameError> {
    let mut prefix = [0; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|e| FrameError::Connection(e.to_string()))?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(FrameError::Bad("length"));
    }
    let mut message = vec![0; len];
    recv.read_exact(&mut message)
        .await
        .map_err(|e| FrameError::Connection(e.to_string()))?;
    let body = message.split_off(1);
    if message[0] == ERROR {
        let (&code, rest) = body.split_first().ok_or(FrameError::Bad("error"))?;
        let detail = rest
            .get(2..)
            .map(|detail| String::from_utf8_lossy(detail).into_owned())
            .unwrap_or_default();
        return Err(FrameError::Peer {
            reason: Reason::from_code(code),
            detail,
        });
    }
    Ok((message[0], body))
}

/// Sends `0x7f` error, `reason u8 ‖ u16 length ‖ UTF-8 detail`, finishes the stream, and waits
/// briefly for the peer to receive it, so closing the connection next doesn't lose it. The
/// detail is for logs only.
pub async fn send_error(send: &mut SendStream, reason: Reason, detail: &str) {
    let detail = &detail.as_bytes()[..detail.len().min(1024)];
    let body = [
        &[reason.code()][..],
        &(detail.len() as u16).to_be_bytes(),
        detail,
    ]
    .concat();
    let _ = write(send, ERROR, &body).await;
    let _ = send.finish();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), send.stopped()).await;
}
