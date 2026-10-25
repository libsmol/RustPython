//! Socket names that wasi-libc provides on `wasm32-wasip2` but the libc crate does not bind.
//!
//! The values come from the wasi-sdk 34 sysroot headers (`netdb.h`,
//! `netinet/in.h`, `sys/socket.h`), which Rust's `wasm32-wasip2` libc is built from.

use core::ffi::{c_char, c_int};

pub const AI_PASSIVE: c_int = 0x01;
pub const AI_CANONNAME: c_int = 0x02;
pub const AI_NUMERICHOST: c_int = 0x04;
pub const AI_ADDRCONFIG: c_int = 0x20;
pub const AI_NUMERICSERV: c_int = 0x400;

pub const NI_NUMERICHOST: c_int = 0x01;
pub const NI_NUMERICSERV: c_int = 0x02;
pub const NI_NOFQDN: c_int = 0x04;
pub const NI_NAMEREQD: c_int = 0x08;
pub const NI_DGRAM: c_int = 0x10;
pub const NI_MAXHOST: c_int = 255;
pub const NI_MAXSERV: c_int = 32;

pub const EAI_BADFLAGS: c_int = -1;
pub const EAI_NONAME: c_int = -2;
pub const EAI_AGAIN: c_int = -3;
pub const EAI_FAIL: c_int = -4;
pub const EAI_NODATA: c_int = -5;
pub const EAI_FAMILY: c_int = -6;
pub const EAI_SOCKTYPE: c_int = -7;
pub const EAI_SERVICE: c_int = -8;
pub const EAI_MEMORY: c_int = -10;

pub const INADDR_ANY: u32 = 0x0000_0000;
pub const INADDR_BROADCAST: u32 = 0xffff_ffff;
pub const INADDR_LOOPBACK: u32 = 0x7f00_0001;
pub const INADDR_NONE: u32 = 0xffff_ffff;

pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_ICMPV6: c_int = 58;

pub const MSG_OOB: c_int = 0x0001;
pub const MSG_DONTROUTE: c_int = 0x0004;
pub const MSG_CTRUNC: c_int = 0x0008;
/// `__WASI_ROFLAGS_RECV_DATA_TRUNCATED`, which shares its bit with `MSG_OOB`
pub const MSG_TRUNC: c_int = 0x0001;
pub const MSG_WAITALL: c_int = 0x0100;

pub const SO_OOBINLINE: c_int = 10;
pub const SOMAXCONN: c_int = 128;

#[repr(C)]
pub struct servent {
    pub s_name: *mut c_char,
    pub s_aliases: *mut *mut c_char,
    pub s_port: c_int,
    pub s_proto: *mut c_char,
}

#[repr(C)]
pub struct protoent {
    pub p_name: *mut c_char,
    pub p_aliases: *mut *mut c_char,
    pub p_proto: c_int,
}

unsafe extern "C" {
    pub fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut servent;
    pub fn getservbyport(port: c_int, proto: *const c_char) -> *mut servent;
    pub fn getprotobyname(name: *const c_char) -> *mut protoent;
    pub fn hstrerror(ecode: c_int) -> *const c_char;
}

/// The part of the `dns-lookup` API that the socket module uses, since that crate has no WASI support.
pub mod dns {
    use super::{NI_DGRAM, NI_NAMEREQD, NI_NUMERICHOST, NI_NUMERICSERV};
    use alloc::ffi::CString;
    use core::ffi::{CStr, c_int};
    use core::net::SocketAddr;
    use socket2::{SockAddr, SockAddrStorage};
    use std::io;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct AddrInfoHints {
        pub flags: i32,
        pub address: i32,
        pub socktype: i32,
        pub protocol: i32,
    }

    #[derive(Clone, Debug)]
    pub struct AddrInfo {
        pub flags: i32,
        pub address: i32,
        pub socktype: i32,
        pub protocol: i32,
        pub sockaddr: SocketAddr,
        pub canonname: Option<String>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LookupErrorKind {
        /// The error is in `errno`, and converting to `io::Error` carries it
        System,
        Other,
    }

    #[derive(Debug)]
    pub struct LookupError {
        err_num: i32,
        inner: io::Error,
    }

    impl LookupError {
        fn new(err_num: i32) -> Self {
            let inner = match err_num {
                libc::EAI_SYSTEM => io::Error::last_os_error(),
                _ => io::Error::other(crate::socket::gai_error_string(err_num)),
            };
            Self { err_num, inner }
        }

        pub fn kind(&self) -> LookupErrorKind {
            match self.err_num {
                libc::EAI_SYSTEM => LookupErrorKind::System,
                _ => LookupErrorKind::Other,
            }
        }

        pub fn error_num(&self) -> i32 {
            self.err_num
        }
    }

    impl From<LookupError> for io::Error {
        fn from(err: LookupError) -> Self {
            err.inner
        }
    }

    fn c_string(text: Option<&str>) -> Result<Option<CString>, LookupError> {
        let Some(text) = text else {
            return Ok(None);
        };
        match CString::new(text) {
            Ok(text) => Ok(Some(text)),
            Err(_) => Err(LookupError::new(super::EAI_NONAME)),
        }
    }

    pub fn getaddrinfo(
        host: Option<&str>,
        service: Option<&str>,
        hints: Option<AddrInfoHints>,
    ) -> Result<impl Iterator<Item = io::Result<AddrInfo>>, LookupError> {
        let host = c_string(host)?;
        let service = c_string(service)?;
        // SAFETY: `addrinfo` is plain C data, for which all zeroes is the empty hints
        let mut c_hints: libc::addrinfo = unsafe { core::mem::zeroed() };
        if let Some(hints) = hints {
            c_hints.ai_flags = hints.flags;
            c_hints.ai_family = hints.address;
            c_hints.ai_socktype = hints.socktype;
            c_hints.ai_protocol = hints.protocol;
        }

        let mut list = core::ptr::null_mut();
        let host_ptr = host
            .as_ref()
            .map_or(core::ptr::null(), |host| host.as_ptr());
        let service_ptr = service.as_ref().map_or(core::ptr::null(), |s| s.as_ptr());
        // SAFETY: The strings outlive the call and `list` receives a list freed below
        let err = unsafe { libc::getaddrinfo(host_ptr, service_ptr, &c_hints, &mut list) };
        if err != 0 {
            return Err(LookupError::new(err));
        }

        let mut infos = Vec::new();
        let mut node = list;
        while !node.is_null() {
            // SAFETY: `node` is an entry of the list that getaddrinfo returned
            let entry = unsafe { &*node };
            infos.push(addr_info(entry));
            node = entry.ai_next;
        }
        // SAFETY: `list` came from getaddrinfo and nothing borrows from it any more
        unsafe { libc::freeaddrinfo(list) };
        Ok(infos.into_iter())
    }

    fn addr_info(entry: &libc::addrinfo) -> io::Result<AddrInfo> {
        let len = entry.ai_addrlen as usize;
        let mut storage = SockAddrStorage::zeroed();
        if entry.ai_addr.is_null() || len > storage.size_of() as usize {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        // SAFETY: `ai_addr` points to `len` bytes, which fit in the storage
        unsafe {
            let source = entry.ai_addr.cast::<u8>();
            let target = (&raw mut storage).cast::<u8>();
            core::ptr::copy_nonoverlapping(source, target, len);
        }
        // SAFETY: The storage holds a socket address of `len` bytes
        let address = unsafe { SockAddr::new(storage, entry.ai_addrlen) };
        let sockaddr = address
            .as_socket()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        let canonname = (!entry.ai_canonname.is_null()).then(|| {
            // SAFETY: A non-null canonical name is a NUL-terminated string
            let name = unsafe { CStr::from_ptr(entry.ai_canonname) };
            name.to_string_lossy().into_owned()
        });
        Ok(AddrInfo {
            flags: entry.ai_flags,
            address: entry.ai_family,
            socktype: entry.ai_socktype,
            protocol: entry.ai_protocol,
            sockaddr,
            canonname,
        })
    }

    /// WASI has no reverse lookup, so the only name known is `localhost` for loopback
    /// addresses, as in a hosts file. Other hosts stay numeric, which is what
    /// getnameinfo gives when it finds no name, unless `NI_NAMEREQD` asks for one.
    pub fn getnameinfo(sock: &SocketAddr, flags: i32) -> Result<(String, String), LookupError> {
        let named = sock.ip().is_loopback() && flags & NI_NUMERICHOST == 0;
        if flags & NI_NAMEREQD != 0 && !named {
            return Err(LookupError::new(super::EAI_NONAME));
        }
        let host = match sock {
            _ if named => "localhost".to_owned(),
            SocketAddr::V6(addr) if addr.scope_id() != 0 => {
                format!("{}%{}", addr.ip(), addr.scope_id())
            }
            _ => sock.ip().to_string(),
        };
        let port = sock.port();
        let service = match flags & NI_NUMERICSERV {
            0 => service_name(port, flags & NI_DGRAM != 0),
            _ => None,
        };
        let service = service.unwrap_or_else(|| port.to_string());
        Ok((host, service))
    }

    fn service_name(port: u16, datagram: bool) -> Option<String> {
        let proto = if datagram { c"udp" } else { c"tcp" };
        // SAFETY: getservbyport takes the port in network order and returns null or a static entry
        let entry = unsafe { super::getservbyport(c_int::from(port.to_be()), proto.as_ptr()) };
        if entry.is_null() {
            return None;
        }
        // SAFETY: A non-null entry has a NUL-terminated name
        let name = unsafe { CStr::from_ptr((*entry).s_name) };
        Some(name.to_string_lossy().into_owned())
    }
}
