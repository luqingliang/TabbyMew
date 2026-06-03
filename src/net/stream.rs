use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type AnyStream = Box<dyn ProxyStream>;

pub fn boxed<T>(stream: T) -> AnyStream
where
    T: ProxyStream + 'static,
{
    Box::new(stream)
}
