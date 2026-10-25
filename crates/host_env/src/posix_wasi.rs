use alloc::ffi::CString;
use core::ffi::{CStr, c_char, c_int};
use rustix::fd::AsFd;
use rustix::fs::{self, Access, AtFlags};
use std::{ffi::OsStr, io, path::Path};

pub use super::posix_unix_like::*;

use crate::{crt_fd, os::CheckLibcResult};

pub fn stat_fd(fd: crate::crt_fd::Borrowed<'_>) -> io::Result<crate::fileutils::StatStruct> {
    crate::fileutils::fstat(fd)
}

pub fn set_file_times_at(
    dir_fd: i32,
    path: &CStr,
    access: crate::os::FileTime,
    modified: crate::os::FileTime,
    follow_symlinks: bool,
) -> io::Result<()> {
    let ts = |time: crate::os::FileTime| libc::timespec {
        tv_sec: time.seconds,
        tv_nsec: time.nanoseconds as _,
    };
    let times = [ts(access), ts(modified)];
    unsafe {
        libc::utimensat(
            dir_fd,
            path.as_ptr(),
            times.as_ptr(),
            if follow_symlinks {
                0
            } else {
                libc::AT_SYMLINK_NOFOLLOW
            },
        )
    }
    .check_libc_neg()?;
    Ok(())
}

/// Asks wasi-libc, since WASI has no permission bits to check the way Unix does
pub fn access(path: &Path, mode: u8) -> bool {
    let access = Access::from_bits_retain(mode.into());
    fs::accessat(fs::CWD, path, access, AtFlags::empty()).is_ok()
}

pub fn symlinkat(
    src: impl AsRef<Path>,
    dir_fd: Option<crt_fd::Borrowed<'_>>,
    dst: impl AsRef<Path>,
) -> io::Result<()> {
    let dir_fd = dir_fd.as_ref().map_or(fs::CWD, AsFd::as_fd);
    fs::symlinkat(src.as_ref(), dir_fd, dst.as_ref()).map_err(Into::into)
}

/// `struct utsname` from wasi-libc's `sys/utsname.h`, which the libc crate does not bind
#[repr(C)]
struct Utsname {
    sysname: [c_char; 65],
    nodename: [c_char; 65],
    release: [c_char; 65],
    version: [c_char; 65],
    machine: [c_char; 65],
    _domainname: [c_char; 65],
}

unsafe extern "C" {
    fn uname(buf: *mut Utsname) -> c_int;
}

pub fn uname_info() -> Result<UnameInfo, UnameDecodeError> {
    // SAFETY: All zeroes is a valid `Utsname`, and wasi-libc's uname only copies
    // constant strings into it and never fails
    let mut info: Utsname = unsafe { core::mem::zeroed() };
    unsafe { uname(&mut info) };

    let field = |value: &[c_char; 65]| {
        let bytes = value.map(|byte| byte as u8);
        let text = CStr::from_bytes_until_nul(&bytes).unwrap_or_default();
        uname_field(text)
    };
    Ok(UnameInfo {
        sysname: field(&info.sysname)?,
        nodename: field(&info.nodename)?,
        release: field(&info.release)?,
        version: field(&info.version)?,
        machine: field(&info.machine)?,
    })
}
