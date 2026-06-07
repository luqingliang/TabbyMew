use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::sleep,
};
use tracing::{debug, warn};

const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
pub const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 1024;
#[cfg(not(test))]
pub const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(unix)]
const EMFILE: i32 = 24;
#[cfg(unix)]
const ENFILE: i32 = 23;

pub fn enable_nodelay(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        debug!(context = %context, error = %err, "failed to enable TCP_NODELAY");
    }
}

pub async fn accept_with_backoff(
    listener: &TcpListener,
    context: &str,
) -> io::Result<(TcpStream, SocketAddr)> {
    let mut backoff = ACCEPT_BACKOFF_INITIAL;
    loop {
        match listener.accept().await {
            Ok(accepted) => return Ok(accepted),
            Err(err) if is_retriable_accept_error(&err) => {
                warn!(
                    context = %context,
                    error = %err,
                    backoff_ms = backoff.as_millis(),
                    "TCP accept failed; retrying"
                );
                sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Clone)]
pub struct ConnectionLimiter {
    context: Arc<str>,
    max: usize,
    semaphore: Arc<Semaphore>,
}

impl ConnectionLimiter {
    pub fn new(context: impl Into<String>, max: usize) -> Self {
        Self {
            context: Arc::<str>::from(context.into()),
            max,
            semaphore: Arc::new(Semaphore::new(max)),
        }
    }

    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        if self.semaphore.available_permits() == 0 {
            warn!(
                context = %self.context,
                max = self.max,
                "inbound connection limit reached; applying accept backpressure"
            );
        }
        self.semaphore.clone().acquire_owned().await.ok()
    }
}

pub async fn relay_until_first_eof<L, R>(left: &mut L, right: &mut R) -> io::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    relay_until_first_eof_with_counters(left, right, |_| {}, |_| {}).await
}

pub async fn relay_until_first_eof_with_counters<L, R, F, G>(
    left: &mut L,
    right: &mut R,
    on_left_to_right: F,
    on_right_to_left: G,
) -> io::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
    F: Fn(u64),
    G: Fn(u64),
{
    let result = {
        let (mut left_read, mut left_write) = tokio::io::split(&mut *left);
        let (mut right_read, mut right_write) = tokio::io::split(&mut *right);
        tokio::select! {
            result = copy_with_counter(&mut left_read, &mut right_write, on_left_to_right) => result.map(|_| ()),
            result = copy_with_counter(&mut right_read, &mut left_write, on_right_to_left) => result.map(|_| ()),
        }
    };
    let _ = left.shutdown().await;
    let _ = right.shutdown().await;
    result
}

async fn copy_with_counter<R, W, F>(reader: &mut R, writer: &mut W, on_chunk: F) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Fn(u64),
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        let bytes = n as u64;
        total = total.saturating_add(bytes);
        on_chunk(bytes);
    }
}

fn is_retriable_accept_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    ) || is_fd_exhaustion_error(err)
}

#[cfg(unix)]
fn is_fd_exhaustion_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(EMFILE | ENFILE))
}

#[cfg(not(unix))]
fn is_fd_exhaustion_error(_err: &io::Error) -> bool {
    false
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn retries_fd_exhaustion_accept_errors() {
        assert!(is_retriable_accept_error(&io::Error::from_raw_os_error(
            EMFILE
        )));
        assert!(is_retriable_accept_error(&io::Error::from_raw_os_error(
            ENFILE
        )));
    }

    #[test]
    fn does_not_retry_unexpected_accept_errors() {
        assert!(!is_retriable_accept_error(&io::Error::from_raw_os_error(
            98
        )));
    }
}
