use std::{io, net::SocketAddr};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::sync::{
    RwLock,
    atomic::{AtomicU32, Ordering},
};

#[cfg(target_os = "macos")]
use std::{ffi::CString, os::fd::AsRawFd};

#[cfg(target_os = "macos")]
use system_configuration::{
    core_foundation::{
        base::TCFType,
        dictionary::CFDictionary,
        propertylist::{CFPropertyList, CFPropertyListSubClass},
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};

#[cfg(target_os = "windows")]
use std::{
    ffi::{c_char, c_void},
    net::IpAddr,
    os::windows::io::{AsRawSocket, RawSocket},
};

#[cfg(any(target_os = "windows", test))]
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::platform;

#[cfg(target_os = "macos")]
static BOUND_INTERFACE_INDEX: AtomicU32 = AtomicU32::new(0);
#[cfg(target_os = "windows")]
static BOUND_INTERFACE_INDEX_V4: AtomicU32 = AtomicU32::new(0);
#[cfg(target_os = "windows")]
static BOUND_INTERFACE_INDEX_V6: AtomicU32 = AtomicU32::new(0);
#[cfg(target_os = "windows")]
static BOUND_INTERFACE_ADDR_V4: RwLock<Option<Ipv4Addr>> = RwLock::new(None);
#[cfg(target_os = "windows")]
static BOUND_INTERFACE_ADDR_V6: RwLock<Option<Ipv6Addr>> = RwLock::new(None);
#[cfg(any(target_os = "macos", target_os = "windows"))]
static BOUND_INTERFACE_NAME: RwLock<Option<String>> = RwLock::new(None);

#[cfg(any(target_os = "windows", test))]
const WINDOWS_INTERFACE_KEY_PREFIX: &str = "ifindex:";

#[cfg(target_os = "windows")]
const AF_INET: u16 = 2;
#[cfg(target_os = "windows")]
const AF_INET6: u16 = 23;
#[cfg(target_os = "windows")]
const NO_ERROR: u32 = 0;
#[cfg(target_os = "windows")]
const SOCKET_ERROR: i32 = -1;
#[cfg(target_os = "windows")]
const IPPROTO_IP: i32 = 0;
#[cfg(target_os = "windows")]
const IPPROTO_IPV6: i32 = 41;
#[cfg(target_os = "windows")]
const IP_UNICAST_IF: i32 = 31;
#[cfg(target_os = "windows")]
const IPV6_UNICAST_IF: i32 = 31;

#[cfg(target_os = "macos")]
pub fn default_interface_name() -> io::Result<String> {
    let store = SCDynamicStoreBuilder::new("TabbyMew egress interface")
        .build()
        .ok_or_else(|| io::Error::other("failed to create SC DynamicStore"))?;
    let Some(property_list) = store.get("State:/Network/Global/IPv4") else {
        return Err(io::Error::other("failed to read network state"));
    };
    let Some(dict) = property_list.downcast::<CFDictionary>() else {
        return Err(io::Error::other("network state is not a dictionary"));
    };
    let Some(interface) = get_cf_dict_entry::<CFString>(&dict, "PrimaryInterface".into()) else {
        return Err(io::Error::other("failed to read primary network interface"));
    };
    Ok(interface.to_string())
}

#[cfg(target_os = "windows")]
pub fn default_interface_name() -> io::Result<String> {
    let v4_target = Ipv4Addr::new(8, 8, 8, 8);
    let v6_target = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    let v4 = windows_best_interface_v4(v4_target).ok();
    let v6 = windows_best_interface_v6(v6_target).ok();
    let v4_addr = windows_local_addr_for_remote(SocketAddr::new(IpAddr::V4(v4_target), 53))
        .ok()
        .and_then(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        });
    let v6_addr = windows_local_addr_for_remote(SocketAddr::new(IpAddr::V6(v6_target), 53))
        .ok()
        .and_then(|addr| match addr.ip() {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        });
    format_windows_interface_key(WindowsInterfaceKey {
        v4,
        v6,
        v4_addr,
        v6_addr,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn default_interface_name() -> io::Result<String> {
    Err(io::Error::other(
        "egress interface binding is not implemented on this platform",
    ))
}

pub fn interface_binding_supported() -> bool {
    platform::tun_egress_binding_supported()
}

#[cfg(target_os = "macos")]
pub fn set_bound_interface(interface: Option<&str>) -> io::Result<()> {
    match interface {
        Some(interface) => {
            let name = CString::new(interface).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
            })?;
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            BOUND_INTERFACE_INDEX.store(index, Ordering::SeqCst);
            *BOUND_INTERFACE_NAME
                .write()
                .expect("egress interface lock must not be poisoned") = Some(interface.to_string());
            Ok(())
        }
        None => {
            BOUND_INTERFACE_INDEX.store(0, Ordering::SeqCst);
            *BOUND_INTERFACE_NAME
                .write()
                .expect("egress interface lock must not be poisoned") = None;
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub fn set_bound_interface(interface: Option<&str>) -> io::Result<()> {
    match interface {
        Some(interface) => {
            let parsed = parse_windows_interface_key(interface)?;
            BOUND_INTERFACE_INDEX_V4.store(parsed.v4.unwrap_or(0), Ordering::SeqCst);
            BOUND_INTERFACE_INDEX_V6.store(parsed.v6.unwrap_or(0), Ordering::SeqCst);
            *BOUND_INTERFACE_ADDR_V4
                .write()
                .expect("egress interface address lock must not be poisoned") = parsed.v4_addr;
            *BOUND_INTERFACE_ADDR_V6
                .write()
                .expect("egress interface address lock must not be poisoned") = parsed.v6_addr;
            *BOUND_INTERFACE_NAME
                .write()
                .expect("egress interface lock must not be poisoned") = Some(interface.to_string());
            Ok(())
        }
        None => {
            BOUND_INTERFACE_INDEX_V4.store(0, Ordering::SeqCst);
            BOUND_INTERFACE_INDEX_V6.store(0, Ordering::SeqCst);
            *BOUND_INTERFACE_ADDR_V4
                .write()
                .expect("egress interface address lock must not be poisoned") = None;
            *BOUND_INTERFACE_ADDR_V6
                .write()
                .expect("egress interface address lock must not be poisoned") = None;
            *BOUND_INTERFACE_NAME
                .write()
                .expect("egress interface lock must not be poisoned") = None;
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn set_bound_interface(_interface: Option<&str>) -> io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn bound_interface_name() -> Option<String> {
    BOUND_INTERFACE_NAME
        .read()
        .expect("egress interface lock must not be poisoned")
        .clone()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn bound_interface_name() -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
pub fn remote_addr_supported(remote_addr: SocketAddr) -> bool {
    if remote_addr.ip().is_loopback() || bound_interface_name().is_none() {
        return true;
    }
    match remote_addr {
        SocketAddr::V4(_) => BOUND_INTERFACE_INDEX_V4.load(Ordering::SeqCst) != 0,
        SocketAddr::V6(_) => BOUND_INTERFACE_INDEX_V6.load(Ordering::SeqCst) != 0,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn remote_addr_supported(_remote_addr: SocketAddr) -> bool {
    true
}

#[cfg(target_os = "macos")]
pub fn bind_tcp_socket(socket: &tokio::net::TcpSocket, remote_addr: SocketAddr) -> io::Result<()> {
    bind_raw_socket(socket.as_raw_fd(), remote_addr)
}

#[cfg(target_os = "windows")]
pub fn bind_tcp_socket(socket: &tokio::net::TcpSocket, remote_addr: SocketAddr) -> io::Result<()> {
    bind_windows_raw_socket(socket.as_raw_socket(), remote_addr)?;
    if let Some(local_addr) = windows_local_bind_addr(remote_addr) {
        socket.bind(local_addr)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn bind_tcp_socket(
    _socket: &tokio::net::TcpSocket,
    _remote_addr: SocketAddr,
) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn bind_socket2_udp_socket(
    socket: &socket2::Socket,
    remote_addr: SocketAddr,
) -> io::Result<()> {
    bind_raw_socket(socket.as_raw_fd(), remote_addr)
}

#[cfg(target_os = "windows")]
pub fn bind_socket2_udp_socket(
    socket: &socket2::Socket,
    remote_addr: SocketAddr,
) -> io::Result<()> {
    bind_windows_raw_socket(socket.as_raw_socket(), remote_addr)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn bind_socket2_udp_socket(
    _socket: &socket2::Socket,
    _remote_addr: SocketAddr,
) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn local_bind_addr_for_remote(remote_addr: SocketAddr) -> Option<SocketAddr> {
    windows_local_bind_addr(remote_addr)
}

#[cfg(not(target_os = "windows"))]
pub fn local_bind_addr_for_remote(_remote_addr: SocketAddr) -> Option<SocketAddr> {
    None
}

#[cfg(target_os = "macos")]
fn bind_raw_socket(fd: std::os::fd::RawFd, remote_addr: SocketAddr) -> io::Result<()> {
    let index = BOUND_INTERFACE_INDEX.load(Ordering::SeqCst);
    if index == 0 || remote_addr.ip().is_loopback() {
        return Ok(());
    }

    let value = index as libc::c_uint;
    let (level, name) = if remote_addr.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "windows")]
fn bind_windows_raw_socket(socket: RawSocket, remote_addr: SocketAddr) -> io::Result<()> {
    if remote_addr.ip().is_loopback() {
        return Ok(());
    }

    let (level, optname, value) = if remote_addr.is_ipv4() {
        let index = BOUND_INTERFACE_INDEX_V4.load(Ordering::SeqCst);
        if index == 0 {
            return Ok(());
        }
        // Windows expects IP_UNICAST_IF in network byte order for IPv4.
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    } else {
        let index = BOUND_INTERFACE_INDEX_V6.load(Ordering::SeqCst);
        if index == 0 {
            return Ok(());
        }
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    };

    let result = unsafe {
        windows_setsockopt(
            socket,
            level,
            optname,
            &value as *const _ as *const c_char,
            std::mem::size_of_val(&value) as i32,
        )
    };
    if result != SOCKET_ERROR {
        Ok(())
    } else {
        Err(windows_socket_error())
    }
}

#[cfg(target_os = "windows")]
fn windows_local_bind_addr(remote_addr: SocketAddr) -> Option<SocketAddr> {
    if remote_addr.ip().is_loopback() {
        return None;
    }
    match remote_addr {
        SocketAddr::V4(_) => BOUND_INTERFACE_ADDR_V4
            .read()
            .expect("egress interface address lock must not be poisoned")
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0)),
        SocketAddr::V6(_) => BOUND_INTERFACE_ADDR_V6
            .read()
            .expect("egress interface address lock must not be poisoned")
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0)),
    }
}

#[cfg(target_os = "windows")]
fn windows_local_addr_for_remote(remote_addr: SocketAddr) -> io::Result<SocketAddr> {
    let socket = std::net::UdpSocket::bind(match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    })?;
    socket.connect(remote_addr)?;
    socket.local_addr()
}

#[cfg(target_os = "windows")]
fn windows_best_interface_v4(target: Ipv4Addr) -> io::Result<u32> {
    let sockaddr = WindowsSockaddrIn {
        family: AF_INET,
        port: 0,
        addr: target.octets(),
        zero: [0; 8],
    };
    windows_best_interface(&sockaddr as *const _ as *const c_void)
}

#[cfg(target_os = "windows")]
fn windows_best_interface_v6(target: Ipv6Addr) -> io::Result<u32> {
    let sockaddr = WindowsSockaddrIn6 {
        family: AF_INET6,
        port: 0,
        flowinfo: 0,
        addr: target.octets(),
        scope_id: 0,
    };
    windows_best_interface(&sockaddr as *const _ as *const c_void)
}

#[cfg(target_os = "windows")]
fn windows_best_interface(sockaddr: *const c_void) -> io::Result<u32> {
    let mut index = 0;
    let result = unsafe { get_best_interface_ex(sockaddr, &mut index) };
    if result != NO_ERROR {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    if index == 0 {
        return Err(io::Error::other(
            "GetBestInterfaceEx returned interface index 0",
        ));
    }
    Ok(index)
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsInterfaceKey {
    v4: Option<u32>,
    v6: Option<u32>,
    v4_addr: Option<Ipv4Addr>,
    v6_addr: Option<Ipv6Addr>,
}

#[cfg(any(target_os = "windows", test))]
fn format_windows_interface_key(key: WindowsInterfaceKey) -> io::Result<String> {
    if key.v4.unwrap_or(0) == 0 && key.v6.unwrap_or(0) == 0 {
        return Err(io::Error::other(
            "failed to find a usable Windows egress interface",
        ));
    }

    let mut parts = Vec::new();
    if let Some(index) = key.v4.filter(|index| *index != 0) {
        parts.push(format!("v4={index}"));
    }
    if let Some(addr) = key.v4_addr {
        parts.push(format!("addr4={addr}"));
    }
    if let Some(index) = key.v6.filter(|index| *index != 0) {
        parts.push(format!("v6={index}"));
    }
    if let Some(addr) = key.v6_addr {
        parts.push(format!("addr6={addr}"));
    }
    Ok(format!("{WINDOWS_INTERFACE_KEY_PREFIX}{}", parts.join(",")))
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_interface_key(interface: &str) -> io::Result<WindowsInterfaceKey> {
    let Some(rest) = interface.strip_prefix(WINDOWS_INTERFACE_KEY_PREFIX) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows interface key must start with ifindex:",
        ));
    };
    if rest.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows interface key has no interface indices",
        ));
    }

    let mut v4 = None;
    let mut v6 = None;
    let mut v4_addr = None;
    let mut v6_addr = None;
    for part in rest.split(',') {
        let Some((family, value)) = part.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows interface key part must be family=value",
            ));
        };
        match family {
            "v4" if v4.is_none() => v4 = Some(parse_windows_interface_index(value)?),
            "v6" if v6.is_none() => v6 = Some(parse_windows_interface_index(value)?),
            "v4" | "v6" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows interface key contains a duplicate address family",
                ));
            }
            "addr4" if v4_addr.is_none() => {
                v4_addr = Some(value.parse::<Ipv4Addr>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows IPv4 interface address is invalid",
                    )
                })?);
            }
            "addr6" if v6_addr.is_none() => {
                v6_addr = Some(value.parse::<Ipv6Addr>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows IPv6 interface address is invalid",
                    )
                })?);
            }
            "addr4" | "addr6" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows interface key contains a duplicate interface address",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows interface key contains an unknown address family",
                ));
            }
        }
    }

    if v4.is_none() && v6.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows interface key has no interface indices",
        ));
    }
    Ok(WindowsInterfaceKey {
        v4,
        v6,
        v4_addr,
        v6_addr,
    })
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_interface_index(value: &str) -> io::Result<u32> {
    let index = value.parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows interface index must be a positive integer",
        )
    })?;
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows interface index must not be 0",
        ));
    }
    Ok(index)
}

#[cfg(target_os = "windows")]
fn windows_socket_error() -> io::Error {
    let code = unsafe { wsa_get_last_error() };
    io::Error::from_raw_os_error(code)
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WindowsSockaddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WindowsSockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    #[link_name = "GetBestInterfaceEx"]
    fn get_best_interface_ex(sockaddr: *const c_void, best_if_index: *mut u32) -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "ws2_32")]
unsafe extern "system" {
    #[link_name = "setsockopt"]
    fn windows_setsockopt(
        socket: RawSocket,
        level: i32,
        optname: i32,
        optval: *const c_char,
        optlen: i32,
    ) -> i32;

    #[link_name = "WSAGetLastError"]
    fn wsa_get_last_error() -> i32;
}

#[cfg(target_os = "macos")]
fn get_cf_dict_entry<T>(dict: &CFDictionary, key: CFString) -> Option<T>
where
    T: CFPropertyListSubClass,
{
    let result = dict.find(key.as_CFTypeRef())?;
    if result.is_null() {
        return None;
    }
    let property_list = unsafe { CFPropertyList::wrap_under_get_rule(*result) };
    property_list.downcast::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_interface_is_empty_by_default() {
        let _ = set_bound_interface(None);
        assert!(bound_interface_name().is_none());
    }

    #[test]
    fn windows_interface_key_round_trips() {
        let key = format_windows_interface_key(WindowsInterfaceKey {
            v4: Some(12),
            v6: Some(34),
            v4_addr: Some(Ipv4Addr::new(192, 0, 2, 10)),
            v6_addr: Some(Ipv6Addr::LOCALHOST),
        })
        .unwrap();
        assert_eq!(key, "ifindex:v4=12,addr4=192.0.2.10,v6=34,addr6=::1");
        assert_eq!(
            parse_windows_interface_key(&key).unwrap(),
            WindowsInterfaceKey {
                v4: Some(12),
                v6: Some(34),
                v4_addr: Some(Ipv4Addr::new(192, 0, 2, 10)),
                v6_addr: Some(Ipv6Addr::LOCALHOST),
            }
        );

        let key = format_windows_interface_key(WindowsInterfaceKey {
            v4: Some(56),
            v6: None,
            v4_addr: None,
            v6_addr: None,
        })
        .unwrap();
        assert_eq!(key, "ifindex:v4=56");
        assert_eq!(
            parse_windows_interface_key(&key).unwrap(),
            WindowsInterfaceKey {
                v4: Some(56),
                v6: None,
                v4_addr: None,
                v6_addr: None,
            }
        );
    }

    #[test]
    fn windows_interface_key_can_omit_ipv6_binding() {
        let key = parse_windows_interface_key("ifindex:v4=12,addr4=192.0.2.10").unwrap();

        assert!(key.v4.is_some());
        assert!(key.v6.is_none());
        assert!(key.v4_addr.is_some());
        assert!(key.v6_addr.is_none());
    }

    #[test]
    fn windows_interface_key_rejects_invalid_values() {
        assert!(
            format_windows_interface_key(WindowsInterfaceKey {
                v4: None,
                v6: None,
                v4_addr: None,
                v6_addr: None,
            })
            .is_err()
        );
        assert!(parse_windows_interface_key("en0").is_err());
        assert!(parse_windows_interface_key("ifindex:").is_err());
        assert!(parse_windows_interface_key("ifindex:v4=0").is_err());
        assert!(parse_windows_interface_key("ifindex:v4=1,v4=2").is_err());
        assert!(parse_windows_interface_key("ifindex:v4=1,addr4=::1").is_err());
        assert!(
            parse_windows_interface_key("ifindex:v4=1,addr4=192.0.2.1,addr4=192.0.2.2").is_err()
        );
        assert!(parse_windows_interface_key("ifindex:v8=1").is_err());
    }
}
