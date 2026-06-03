use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError},
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

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(TryAcquireError::NoPermits) => {
                warn!(
                    context = %self.context,
                    max = self.max,
                    "inbound connection limit reached; closing accepted stream"
                );
                None
            }
            Err(TryAcquireError::Closed) => None,
        }
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
