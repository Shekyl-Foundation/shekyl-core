// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tor's public directory cache, copied file by file (`TSR-Q8`).
//!
//! The daemon keeps four files across boots and nothing else. Guards, keys
//! and the onion stay in the per-boot directory. A file is copied by reading
//! the descriptor that was opened, never by trusting the path and never by
//! hard link: Tor appends to `cached-microdescs.new` in place, so a link
//! would be a second name for a file Tor is still writing.
//!
//! A file that is not a regular file, that is a symbolic link, or that is
//! over its limit is missing. It is not truncated and it is not followed.
//! The limits are Tor 0.4.9.14's own, at tag `tor-0.4.9.14`:
//!
//! - `MAX_DIR_DL_SIZE` in `src/feature/dirclient/dirclient.c` is `(1<<24)-1`,
//!   the largest directory object Tor will download. That is the largest
//!   consensus it will store. The consensus file and the certificate file
//!   are twice that, so a file Tor accepted still copies.
//! - `should_rebuild_md_cache` in `src/feature/nodelist/microdesc.c` leaves
//!   the journal alone until it reaches 16 KiB, and otherwise rebuilds when
//!   the journal is larger than half the store. `clean_caches_callback` in
//!   `src/core/mainloop/mainloop.c` runs that check every
//!   `CLEAN_CACHES_INTERVAL` (30 minutes). Until then a fresh directory's
//!   journal holds every microdescriptor body Tor accepted, and each body
//!   arrived under `MAX_DIR_DL_SIZE`. The store and the journal are eight of
//!   those objects. The factor is that cap, not a multiple of a measured size.
//!
//! A save writes a temporary name in the same directory, syncs it, and renames
//! it over the previous file. A save that stops before the rename leaves the
//! previous file. The temporary name is not one of the four, so a later copy
//! does not pick it up.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Largest directory object Tor 0.4.9.14 will download (`MAX_DIR_DL_SIZE`).
pub const TOR_MAX_DIR_OBJECT: u64 = (1 << 24) - 1;

/// Consensus file. Twice Tor's download cap.
pub const CONSENSUS_LIMIT: u64 = TOR_MAX_DIR_OBJECT * 2;

/// Authority certificates. The same cap as the consensus: one class of
/// directory object, with the same margin.
pub const CERTS_LIMIT: u64 = TOR_MAX_DIR_OBJECT * 2;

/// Microdescriptor store and the `.new` journal. Eight download caps, the
/// margin past a single object and past the half-store rebuild trigger.
pub const MICRODESC_LIMIT: u64 = TOR_MAX_DIR_OBJECT * 8;

/// One cache file: its exact Tor name and the limit above which it is missing.
#[derive(Clone, Copy)]
pub struct CacheFile {
    /// The file name Tor uses. Not a path.
    pub name: &'static str,
    /// Bytes. A longer file is refused whole.
    pub limit: u64,
}

/// The only names that cross a boot, in the order a copy walks them.
pub const FILES: &[CacheFile] = &[
    CacheFile {
        name: "cached-microdesc-consensus",
        limit: CONSENSUS_LIMIT,
    },
    CacheFile {
        name: "cached-microdescs",
        limit: MICRODESC_LIMIT,
    },
    CacheFile {
        name: "cached-microdescs.new",
        limit: MICRODESC_LIMIT,
    },
    CacheFile {
        name: "cached-certs",
        limit: CERTS_LIMIT,
    },
];

/// Environment variable the live-test lane sets to the cache this job's first
/// boot wrote. Absent from production builds: the read is compiled only into
/// test builds (`unpinned-tor-for-tests`, which no release edge enables).
#[cfg(any(test, feature = "unpinned-tor-for-tests"))]
const JOB_CACHE_ENV: &str = "SHEKYL_TEST_TOR_DIRECTORY_CACHE";

/// Copy the cache into `data_dir`.
///
/// A missing cache directory, a directory that is not a real directory, and
/// each refused file are an empty contribution. `Err` is a failure to write
/// `data_dir`, which the caller created and owns.
pub fn copy_into(cache_dir: &Path, data_dir: &Path) -> io::Result<Vec<&'static str>> {
    copy_files(cache_dir, data_dir, FILES)
}

/// After a clean stop, write the four names from `data_dir` back into
/// `cache_dir`. `cache_dir` must already be a real directory
/// ([`ensure_directory`]). A refused source leaves that name's previous file
/// untouched.
pub fn save_from(data_dir: &Path, cache_dir: &Path) -> io::Result<()> {
    save_files(data_dir, cache_dir, FILES)
}

/// Create `path` as an owner-only directory, or accept it when it already is
/// a real directory. A symbolic link is an error: the cache is never the
/// directory a link points at.
pub fn ensure_directory(path: &Path) -> io::Result<()> {
    if open_real_dir(path).is_ok() {
        tighten_existing(path)?;
        return Ok(());
    }
    match create_owner_only(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    open_real_dir(path)?;
    tighten_existing(path)?;
    Ok(())
}

/// Copy the job's seeded cache into `data_dir` when the live-test lane set
/// [`JOB_CACHE_ENV`]. A production build does not contain this function.
#[cfg(any(test, feature = "unpinned-tor-for-tests"))]
pub fn copy_job_cache_into(data_dir: &Path) {
    let Some(cache) = std::env::var_os(JOB_CACHE_ENV) else {
        return;
    };
    if cache.is_empty() {
        return;
    }
    drop(copy_into(Path::new(&cache), data_dir));
}

/// Save `data_dir` into the job cache, creating that directory if the lane
/// named one. Same build gate as [`copy_job_cache_into`].
#[cfg(any(test, feature = "unpinned-tor-for-tests"))]
pub fn save_job_cache_from(data_dir: &Path) {
    let Some(cache) = std::env::var_os(JOB_CACHE_ENV) else {
        return;
    };
    if cache.is_empty() {
        return;
    }
    let cache = std::path::PathBuf::from(cache);
    if ensure_directory(&cache).is_err() {
        return;
    }
    drop(save_from(data_dir, &cache));
}

fn copy_files(
    cache_dir: &Path,
    data_dir: &Path,
    files: &[CacheFile],
) -> io::Result<Vec<&'static str>> {
    if open_real_dir(cache_dir).is_err() {
        return Ok(Vec::new());
    }
    let mut copied = Vec::new();
    for file in files {
        let Some(bytes) = read_named(cache_dir, file.name, file.limit) else {
            continue;
        };
        replace(data_dir, file.name, &bytes)?;
        copied.push(file.name);
    }
    Ok(copied)
}

fn save_files(data_dir: &Path, cache_dir: &Path, files: &[CacheFile]) -> io::Result<()> {
    open_real_dir(data_dir)?;
    for file in files {
        let Some(bytes) = read_named(data_dir, file.name, file.limit) else {
            continue;
        };
        replace(cache_dir, file.name, &bytes)?;
    }
    Ok(())
}

fn partial_name(name: &str) -> String {
    format!(".{name}.partial")
}

/// Write `bytes` to `.{name}.partial` and leave the destination alone.
fn stage(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let partial = dir.join(partial_name(name));
    // A leftover from a save that did not finish. `remove_file` on a symlink
    // removes the link, not whatever it names.
    match fs::remove_file(&partial) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = create_exclusive(&partial)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Rename the staged file over `name`. The destination becomes the new bytes
/// in one replacement, or it is unchanged.
fn commit(dir: &Path, name: &str) -> io::Result<()> {
    let partial = dir.join(partial_name(name));
    if !is_regular_file(&partial) {
        drop(fs::remove_file(&partial));
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the staged cache file is not a regular file",
        ));
    }
    let dest = dir.join(name);
    replace_name(&partial, &dest)
}

fn replace(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    stage(dir, name, bytes)?;
    commit(dir, name)
}

fn create_owner_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::create_dir(path)?;
        tighten_existing(path)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        shekyl_win_sec::create_owner_only_dir(path).map_err(|error| match error {
            shekyl_win_sec::FileCreateError::Create(io_error) => io_error,
            other => io::Error::other(other),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::create_dir(path)
    }
}

fn tighten_existing(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _path = path;
    }
    Ok(())
}

/// Open `path` and keep it only when the opened object is a real directory.
fn open_real_dir(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache path is not a directory",
            ));
        }
        Ok(file)
    }
    #[cfg(windows)]
    {
        let file = open_handle(path, OpenAs::Directory)?;
        let info = file_info(&file)?;
        if info.dwFileAttributes
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache path is a reparse point",
            ));
        }
        if info.dwFileAttributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY
            == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache path is not a directory",
            ));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let file = File::open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache path is not a directory",
            ));
        }
        Ok(file)
    }
}

/// Read `name` inside `dir`, or `None` when the file is missing or refused.
///
/// On Unix the directory is opened with `O_NOFOLLOW` and the file with
/// `openat`, so the component that is read is the one in that directory.
/// On Windows the directory was already refused when it was a reparse point,
/// and the file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and refused
/// when that handle is one. The bytes come from the handle either way.
fn read_named(dir: &Path, name: &str, limit: u64) -> Option<Vec<u8>> {
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return None;
    }
    #[cfg(unix)]
    {
        let dir = open_real_dir(dir).ok()?;
        let file = open_at(&dir, name).ok()?;
        read_regular_file(file, limit)
    }
    #[cfg(windows)]
    {
        let file = open_handle(&dir.join(name), OpenAs::File).ok()?;
        read_regular_file(file, limit)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let file = File::open(dir.join(name)).ok()?;
        read_regular_file(file, limit)
    }
}

fn read_regular_file(file: File, limit: u64) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        let meta = file.metadata().ok()?;
        if !meta.is_file() {
            return None;
        }
        read_capped(file, meta.len(), limit)
    }
    #[cfg(windows)]
    {
        let info = file_info(&file).ok()?;
        let attributes = info.dwFileAttributes;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            return None;
        }
        let len = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        read_capped(file, len, limit)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let meta = file.metadata().ok()?;
        if !meta.is_file() {
            return None;
        }
        read_capped(file, meta.len(), limit)
    }
}

fn read_capped(file: File, len: u64, limit: u64) -> Option<Vec<u8>> {
    if len > limit {
        return None;
    }
    let mut buf = Vec::new();
    let allowed = limit.saturating_add(1);
    file.take(allowed).read_to_end(&mut buf).ok()?;
    let read = u64::try_from(buf.len()).ok()?;
    if read > limit {
        return None;
    }
    Some(buf)
}

fn is_regular_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        else {
            return false;
        };
        file.metadata().is_ok_and(|meta| meta.is_file())
    }
    #[cfg(windows)]
    {
        let Ok(file) = open_handle(path, OpenAs::File) else {
            return false;
        };
        let Ok(info) = file_info(&file) else {
            return false;
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::metadata(path).is_ok_and(|meta| meta.is_file())
    }
}

#[cfg(unix)]
fn open_at(dir: &File, name: &str) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c_name = std::ffi::CString::new(name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `dir` owns a directory descriptor that stays open for the call.
    // `c_name` is one NUL-terminated component, so `openat` cannot leave the
    // directory. `O_NOFOLLOW` refuses a symlink as that component. On success
    // the descriptor is new and owned by the `File` below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor from `openat` that no one else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// What `CreateFileW` is opening. A directory needs backup semantics; a file
/// does not.
#[cfg(windows)]
enum OpenAs {
    File,
    Directory,
}

#[cfg(windows)]
fn open_handle(path: &Path, kind: OpenAs) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    match kind {
        OpenAs::Directory => flags |= FILE_FLAG_BACKUP_SEMANTICS,
        OpenAs::File => flags |= FILE_ATTRIBUTE_NORMAL,
    }
    // SAFETY: `wide` is NUL-terminated and outlives the call. No security
    // descriptor is passed. On success the handle is owned by the `File`.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` came from `CreateFileW` and is not shared. `File`
    // closes it. The attribute check happens on this same handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn file_info(
    file: &File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns the handle. `info` is a valid out-buffer for the call.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn create_exclusive(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        shekyl_win_sec::create_owner_only_file(path).map_err(|error| match error {
            shekyl_win_sec::FileCreateError::Create(io_error) => io_error,
            other => io::Error::other(other),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new().write(true).create_new(true).open(path)
    }
}

fn replace_name(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
    #[cfg(windows)]
    {
        if path_is_reparse(to) {
            // The name is a link. Remove the link itself, not its target,
            // then move the new file onto the name. A crash between the two
            // leaves the name absent, which a copy treats as missing.
            fs::remove_file(to)?;
        }
        move_replace(from, to)
    }
}

#[cfg(windows)]
fn path_is_reparse(path: &Path) -> bool {
    let Ok(file) = open_handle(path, OpenAs::File) else {
        return false;
    };
    let Ok(info) = file_info(&file) else {
        return false;
    };
    info.dwFileAttributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(windows)]
fn move_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from_w: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to_w: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    let ok = unsafe {
        MoveFileExW(
            from_w.as_ptr(),
            to_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cache_file(name: &'static str, limit: u64) -> CacheFile {
        CacheFile { name, limit }
    }

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let parent = tempfile::tempdir().unwrap();
        let cache = parent.path().join("cache");
        let data = parent.path().join("data");
        fs::create_dir(&cache).unwrap();
        fs::create_dir(&data).unwrap();
        (parent, cache, data)
    }

    #[test]
    fn limits_follow_tors_download_cap() {
        assert_eq!(TOR_MAX_DIR_OBJECT, (1 << 24) - 1);
        assert_eq!(CONSENSUS_LIMIT, TOR_MAX_DIR_OBJECT * 2);
        assert_eq!(CERTS_LIMIT, TOR_MAX_DIR_OBJECT * 2);
        assert_eq!(MICRODESC_LIMIT, TOR_MAX_DIR_OBJECT * 8);
        assert_eq!(FILES.len(), 4);
        assert_eq!(FILES[0].name, "cached-microdesc-consensus");
        assert_eq!(FILES[0].limit, CONSENSUS_LIMIT);
        assert_eq!(FILES[1].name, "cached-microdescs");
        assert_eq!(FILES[1].limit, MICRODESC_LIMIT);
        assert_eq!(FILES[2].name, "cached-microdescs.new");
        assert_eq!(FILES[3].name, "cached-certs");
        assert_eq!(FILES[3].limit, CERTS_LIMIT);
    }

    #[test]
    fn a_file_at_the_limit_is_copied_and_one_past_it_is_not() {
        // Fails if the size comparison is removed or inverted: five bytes
        // would land in the data directory, or the four-byte file would not.
        let (_parent, cache, data) = dirs();
        let name = "cached-certs";
        fs::write(cache.join(name), b"abcd").unwrap();
        let copied = copy_files(&cache, &data, &[cache_file(name, 4)]).unwrap();
        assert_eq!(copied, vec![name]);
        assert_eq!(fs::read(data.join(name)).unwrap(), b"abcd");

        fs::write(cache.join(name), b"abcde").unwrap();
        let fresh = data.join("next");
        fs::create_dir(&fresh).unwrap();
        let copied = copy_files(&cache, &fresh, &[cache_file(name, 4)]).unwrap();
        assert!(copied.is_empty());
        assert!(!fresh.join(name).exists());
        assert_eq!(fs::read(cache.join(name)).unwrap(), b"abcde");
    }

    #[test]
    fn a_directory_at_a_cache_name_is_refused() {
        // Fails if a directory is accepted as the file: the data directory
        // would gain an entry of that name.
        let (_parent, cache, data) = dirs();
        fs::create_dir(cache.join("cached-certs")).unwrap();
        let copied = copy_into(&cache, &data).unwrap();
        assert!(copied.is_empty());
        assert!(!data.join("cached-certs").exists());
    }

    #[test]
    fn a_state_file_in_the_cache_is_not_copied() {
        // Fails if the copy walks the directory instead of the four names:
        // `state` would appear in the data directory.
        let (_parent, cache, data) = dirs();
        fs::write(cache.join("state"), b"guards").unwrap();
        fs::write(cache.join("cached-certs"), b"certs").unwrap();
        let copied = copy_into(&cache, &data).unwrap();
        assert_eq!(copied, vec!["cached-certs"]);
        assert!(!data.join("state").exists());
        assert_eq!(fs::read(data.join("cached-certs")).unwrap(), b"certs");
    }

    #[test]
    fn a_missing_cache_copies_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        fs::create_dir(&data).unwrap();
        let copied = copy_into(&parent.path().join("absent"), &data).unwrap();
        assert!(copied.is_empty());
    }

    #[test]
    fn an_interrupted_save_leaves_the_old_file_or_the_new_one() {
        // Fails if the destination is written in place: after `stage` and
        // before `commit` the destination would already be the new bytes,
        // or a prefix of them.
        let (_parent, cache, _data) = dirs();
        let name = "cached-certs";
        let dest = cache.join(name);
        fs::write(&dest, b"old-cache-complete").unwrap();
        stage(&cache, name, b"new-cache-complete-bytes").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"old-cache-complete");
        assert!(cache.join(partial_name(name)).is_file());
        commit(&cache, name).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"new-cache-complete-bytes");
        assert!(!cache.join(partial_name(name)).exists());
    }

    #[test]
    fn save_from_replaces_only_the_four_names() {
        let (_parent, cache, data) = dirs();
        fs::write(cache.join("cached-certs"), b"old").unwrap();
        fs::write(cache.join("state"), b"keep-me").unwrap();
        fs::write(data.join("cached-certs"), b"new").unwrap();
        fs::write(data.join("state"), b"guards").unwrap();
        save_from(&data, &cache).unwrap();
        assert_eq!(fs::read(cache.join("cached-certs")).unwrap(), b"new");
        assert_eq!(fs::read(cache.join("state")).unwrap(), b"keep-me");
    }

    #[test]
    fn an_oversize_source_does_not_replace_the_saved_file() {
        let (_parent, cache, data) = dirs();
        fs::write(cache.join("cached-certs"), b"kept").unwrap();
        fs::write(data.join("cached-certs"), b"too-big").unwrap();
        save_files(&data, &cache, &[cache_file("cached-certs", 3)]).unwrap();
        assert_eq!(fs::read(cache.join("cached-certs")).unwrap(), b"kept");
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_refused_and_its_target_is_untouched() {
        // Fails if the copy follows the link: the data directory would
        // contain the canary, or the canary would change.
        let (_parent, cache, data) = dirs();
        let canary = cache.join("canary");
        fs::write(&canary, b"do-not-follow").unwrap();
        std::os::unix::fs::symlink(&canary, cache.join("cached-certs")).unwrap();
        let copied = copy_into(&cache, &data).unwrap();
        assert!(copied.is_empty());
        assert!(!data.join("cached-certs").exists());
        assert_eq!(fs::read(&canary).unwrap(), b"do-not-follow");
    }

    #[cfg(unix)]
    #[test]
    fn a_cache_directory_reached_through_a_symlink_copies_nothing() {
        let (_parent, cache, data) = dirs();
        fs::write(cache.join("cached-certs"), b"certs").unwrap();
        let link = _parent.path().join("link");
        std::os::unix::fs::symlink(&cache, &link).unwrap();
        let copied = copy_into(&link, &data).unwrap();
        assert!(copied.is_empty());
        assert!(!data.join("cached-certs").exists());
    }

    #[cfg(unix)]
    #[test]
    fn copy_does_not_hard_link() {
        // Fails if the copy is `hard_link`: the two names would share an inode.
        use std::os::unix::fs::MetadataExt;
        let (_parent, cache, data) = dirs();
        fs::write(cache.join("cached-certs"), b"certs").unwrap();
        copy_into(&cache, &data).unwrap();
        let source = fs::metadata(cache.join("cached-certs")).unwrap().ino();
        let copied = fs::metadata(data.join("cached-certs")).unwrap().ino();
        assert_ne!(source, copied);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_directory_refuses_a_symlink() {
        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = parent.path().join("cache");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_directory(&link).is_err());
    }
}
