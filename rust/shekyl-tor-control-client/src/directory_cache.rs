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
//! A copy into a fresh per-boot directory is not synced. Tor reads the files
//! when it starts, and a failed launch wipes the directory, so there is
//! nothing for that copy to protect. A save writes a temporary name in the
//! cache directory, syncs it, and renames it over the previous file. A save
//! that stops before the rename leaves the previous file. The temporary name
//! is not one of the four, so a later copy does not pick it up.
//!
//! A boot has one source. The daemon's own cache is that source when it holds
//! a file a boot may copy. A test build may otherwise install the job lane's
//! seed. A data directory that already holds such a file is left alone: the
//! two sources are never mixed, and a respawn into a kept directory does not
//! replace what this boot already fetched.
//!
//! These functions are synchronous so a test can call them directly. A caller
//! on an async worker moves the call onto a blocking thread. Each file is one
//! read and one write; the thread is what keeps that off the runtime worker.

#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

// A third target used to open by path and follow a symlink. Fail the build
// instead of copying whatever that path names.
#[cfg(not(any(unix, windows)))]
compile_error!("the Tor directory cache is implemented for Unix and Windows");

/// Owner-only directory. `mkdir` applies this in the call that creates the
/// inode. A umask can clear bits and cannot add them, so the directory is
/// never wider than this.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Owner-only file, applied when the staged file is created and again on the
/// descriptor that holds it. The same shape as [`DIR_MODE`].
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// `mode_t` is `u16` on some Unix targets and `u32` on others. These bits fit
/// either width.
#[cfg(unix)]
fn posix_mode(bits: u32) -> libc::mode_t {
    libc::mode_t::try_from(bits).expect("owner-only mode fits mode_t")
}

/// Staged bytes sit beside the real name. A crash before the rename leaves
/// the previous file, and this name is not one of [`FILES`].
const STAGED_PREFIX: &str = ".";
const STAGED_SUFFIX: &str = ".partial";

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

/// Read one cache name without following a symlink and without blocking when
/// that name is a fifo. A regular file's reads ignore the non-blocking bit.
#[cfg(unix)]
fn read_only_nofollow() -> i32 {
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
}

/// Open a directory without following a symlink at the final component.
#[cfg(unix)]
fn directory_nofollow() -> i32 {
    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

/// The directory that holds Tor's public directory files.
///
/// The daemon's durable cache and a test job's seed are both this type. A
/// boot copies from one of them into a data directory. The data directory is
/// not a [`DirectoryCache`]: it also holds guards, keys, and the onion, and
/// those names never travel through this type.
#[derive(Clone, Debug)]
pub struct DirectoryCache {
    path: PathBuf,
}

impl DirectoryCache {
    /// The cache at `path`. The directory need not exist yet.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The directory this cache names.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create this directory owner-only, or accept it when it already is a
    /// real directory. A symbolic link is an error.
    pub fn ensure(&self) -> io::Result<()> {
        ensure_directory(&self.path)
    }

    /// Whether any of the four names is a regular file within its limit.
    ///
    /// This opens each name and reads its length. It does not read the bytes.
    /// A missing directory, a symlink, a fifo, and a file over its limit are
    /// all empty.
    #[must_use]
    pub fn holds_a_file(&self) -> bool {
        holds_a_cache_file(&self.path)
    }

    /// Bytes [`Self::copy_into`] would write.
    ///
    /// A name the copy skips — missing, not a regular file, or longer than
    /// its limit — adds nothing. The copy refuses an over-limit file whole,
    /// so the count is not the limit. Staging names are not in [`FILES`]: a
    /// leftover partial already occupies the disk the free-space probe reads.
    #[must_use]
    pub fn copy_bytes(&self) -> u64 {
        copy_byte_len(&self.path)
    }

    /// Copy the four names into `data_dir`. A refused file is skipped.
    /// `Err` is a failure to write `data_dir`.
    pub fn copy_into(&self, data_dir: &Path) -> io::Result<Vec<&'static str>> {
        copy_files(&self.path, data_dir, FILES)
    }

    /// Write the four names from `data_dir` back here. This directory must
    /// already be a real directory ([`Self::ensure`]). A refused source leaves
    /// that name's previous file.
    pub fn save_from(&self, data_dir: &Path) -> io::Result<()> {
        save_files(data_dir, &self.path, FILES)
    }
}

/// Install one cache into `data_dir`.
///
/// The daemon's own cache wins when it holds a copyable file. Otherwise a
/// test build may install the job lane's seed. A production build with an
/// empty own cache installs nothing. A data directory that already holds a
/// copyable file installs nothing either: that is a boot already in progress.
pub fn install_into(own_cache: &Path, data_dir: &Path) -> io::Result<Vec<&'static str>> {
    install_from(
        &DirectoryCache::at(own_cache),
        job_cache().as_ref(),
        data_dir,
    )
}

fn install_from(
    own: &DirectoryCache,
    job: Option<&DirectoryCache>,
    data_dir: &Path,
) -> io::Result<Vec<&'static str>> {
    match source_for(own, job) {
        Some(source) => copy_into_fresh(source, data_dir),
        None => Ok(Vec::new()),
    }
}

/// The one directory a boot copies from. The own cache wins. The job seed is
/// the source only when the own cache has nothing a boot may copy.
fn source_for<'a>(
    own: &'a DirectoryCache,
    job: Option<&'a DirectoryCache>,
) -> Option<&'a DirectoryCache> {
    if own.holds_a_file() {
        Some(own)
    } else {
        job.filter(|cache| cache.holds_a_file())
    }
}

/// Copy `source` when `data_dir` does not already hold a cache file.
///
/// The second check is what keeps two sources from mixing: an own cache that
/// supplied three names cannot be topped up from the job seed's fourth, and a
/// respawn into a kept directory copies nothing.
fn copy_into_fresh(source: &DirectoryCache, data_dir: &Path) -> io::Result<Vec<&'static str>> {
    if holds_a_cache_file(data_dir) {
        return Ok(Vec::new());
    }
    source.copy_into(data_dir)
}

#[cfg(any(test, feature = "unpinned-tor-for-tests"))]
fn job_cache() -> Option<DirectoryCache> {
    let path = std::env::var_os(JOB_CACHE_ENV)?;
    if path.is_empty() {
        return None;
    }
    Some(DirectoryCache::at(path))
}

#[cfg(not(any(test, feature = "unpinned-tor-for-tests")))]
fn job_cache() -> Option<DirectoryCache> {
    None
}

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
/// directory a link points at. Unix sets the mode on an existing directory.
/// Windows applies the owner-only access list at create and does not rewrite
/// an existing directory's access list.
pub fn ensure_directory(path: &Path) -> io::Result<()> {
    if open_real_dir(path).is_ok() {
        #[cfg(unix)]
        restrict_existing(path)?;
        return Ok(());
    }
    match create_owner_only(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    open_real_dir(path)?;
    #[cfg(unix)]
    restrict_existing(path)?;
    Ok(())
}

/// Set an existing directory to [`DIR_MODE`].
///
/// Windows has no mode bits. The owner-only access list is applied by
/// `CreateDirectoryW` in [`create_owner_only`], and [`open_real_dir`] has
/// already refused a reparse point.
#[cfg(unix)]
fn restrict_existing(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))
}

/// Fill `data_dir` from the job lane when the lane named a seed and `data_dir`
/// does not already hold a cache file. A production build does not contain
/// this function. The daemon installs its one source before spawn, so this
/// call finds that file and copies nothing.
#[cfg(any(test, feature = "unpinned-tor-for-tests"))]
pub fn copy_job_cache_into(data_dir: &Path) {
    let Some(job) = job_cache() else {
        return;
    };
    drop(copy_into_fresh(&job, data_dir));
}

/// Publish `saved` as the job lane's seed. `saved` is the cache a clean stop
/// wrote, not a data directory Tor still has open. Same build gate as
/// [`copy_job_cache_into`]. A failure leaves whatever the lane already held.
#[cfg(any(test, feature = "unpinned-tor-for-tests"))]
pub fn publish_job_seed(saved: &Path) {
    let Some(job) = job_cache() else {
        return;
    };
    if job.ensure().is_err() {
        return;
    }
    drop(DirectoryCache::at(saved).copy_into(job.path()));
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
        place(data_dir, file.name, &bytes, Durability::Launch)?;
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
        place(cache_dir, file.name, &bytes, Durability::Save)?;
    }
    Ok(())
}

fn partial_name(name: &str) -> String {
    format!("{STAGED_PREFIX}{name}{STAGED_SUFFIX}")
}

/// Whether the write has to survive a crash.
///
/// [`Durability::Launch`] is a copy into a fresh directory that a failed
/// launch wipes. [`Durability::Save`] replaces a cache file that must still
/// be the previous bytes if the write stops halfway.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Durability {
    Launch,
    Save,
}

/// Write `bytes` to the temporary name and leave the destination alone.
fn stage(dir: &Path, name: &str, bytes: &[u8], durability: Durability) -> io::Result<()> {
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
    if durability == Durability::Save {
        file.sync_all()?;
    }
    Ok(())
}

/// Rename the staged file over `name`. The destination becomes the new bytes
/// in one replacement, or it is unchanged. A save asks the rename to reach
/// disk; a launch copy does not.
fn commit(dir: &Path, name: &str, durability: Durability) -> io::Result<()> {
    let partial = dir.join(partial_name(name));
    if !is_regular_file(&partial) {
        drop(fs::remove_file(&partial));
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the staged cache file is not a regular file",
        ));
    }
    let dest = dir.join(name);
    replace_name(&partial, &dest, durability)
}

fn place(dir: &Path, name: &str, bytes: &[u8], durability: Durability) -> io::Result<()> {
    stage(dir, name, bytes, durability)?;
    commit(dir, name, durability)
}

fn create_owner_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let c_path = std::ffi::CString::new(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        // SAFETY: `c_path` is NUL-terminated and lives for the call. `mkdir`
        // reads the path and creates one directory at [`DIR_MODE`]; it does
        // not retain the pointer. A umask may clear bits and cannot add them.
        let created = unsafe { libc::mkdir(c_path.as_ptr(), posix_mode(DIR_MODE)) };
        if created != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        shekyl_win_sec::create_owner_only_dir(path).map_err(|error| match error {
            shekyl_win_sec::FileCreateError::Create(io_error) => io_error,
            other => io::Error::other(other),
        })
    }
}

/// Open `path` and keep it only when the opened object is a real directory.
fn open_real_dir(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(directory_nofollow())
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
}

/// Read `name` inside `dir`, or `None` when the file is missing or refused.
///
/// On Unix the directory is opened with `O_NOFOLLOW` and the file with
/// `openat`, so the component that is read is the one in that directory.
/// On Windows the directory was already refused when it was a reparse point,
/// and the file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and refused
/// when that handle is one. The bytes come from the handle either way.
fn holds_a_cache_file(dir: &Path) -> bool {
    FILES.iter().any(|file| cache_file_fits(dir, file))
}

/// Length of `file` when the copy would write it, or `None` when the copy
/// skips the name.
fn fitting_len(dir: &Path, file: &CacheFile) -> Option<u64> {
    let opened = open_named(dir, file.name)?;
    let len = regular_len(&opened)?;
    (len <= file.limit).then_some(len)
}

fn cache_file_fits(dir: &Path, file: &CacheFile) -> bool {
    fitting_len(dir, file).is_some()
}

fn copy_byte_len(dir: &Path) -> u64 {
    FILES.iter().fold(0, |sum, file| {
        sum.saturating_add(fitting_len(dir, file).unwrap_or(0))
    })
}

fn is_one_component(name: &str) -> bool {
    !name.contains('/') && !name.contains('\\') && !name.contains('\0')
}

/// Open `name` inside `dir`, or `None` when it is missing or not one component.
///
/// On Unix the directory is opened with `O_NOFOLLOW` and the file with
/// `openat`, so the component that is opened is the one in that directory.
/// On Windows the directory was already refused when it was a reparse point,
/// and the file is opened with `FILE_FLAG_OPEN_REPARSE_POINT`.
fn open_named(dir: &Path, name: &str) -> Option<File> {
    if !is_one_component(name) {
        return None;
    }
    #[cfg(unix)]
    {
        let dir = open_real_dir(dir).ok()?;
        open_at(&dir, name).ok()
    }
    #[cfg(windows)]
    {
        open_handle(&dir.join(name), OpenAs::File).ok()
    }
}

/// Length of `file` when the opened object is a regular file.
fn regular_len(file: &File) -> Option<u64> {
    #[cfg(unix)]
    {
        let meta = file.metadata().ok()?;
        meta.is_file().then_some(meta.len())
    }
    #[cfg(windows)]
    {
        let info = file_info(file).ok()?;
        let attributes = info.dwFileAttributes;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            return None;
        }
        Some((u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow))
    }
}

fn read_named(dir: &Path, name: &str, limit: u64) -> Option<Vec<u8>> {
    let file = open_named(dir, name)?;
    let len = regular_len(&file)?;
    read_capped(file, len, limit)
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
            .custom_flags(read_only_nofollow())
            .open(path)
        else {
            return false;
        };
        regular_len(&file).is_some()
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
}

#[cfg(unix)]
fn open_at(dir: &File, name: &str) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c_name = std::ffi::CString::new(name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `dir` owns a directory descriptor that stays open for the call.
    // `c_name` is one NUL-terminated component, so `openat` cannot leave the
    // directory. `O_NOFOLLOW` refuses a symlink as that component.
    // `O_NONBLOCK` returns instead of waiting when the name is a fifo. On
    // success the descriptor is new and owned by the `File` below.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c_name.as_ptr(), read_only_nofollow()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor from `openat` that no one else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// What `CreateFileW` is opening. A directory needs backup semantics; a file
/// does not. A mode tag: copied, never owned.
#[cfg(windows)]
#[derive(Clone, Copy)]
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
    // SAFETY: `file` owns the handle. `info` is a valid out-buffer for the call
    // and is not borrowed again until the call returns.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) };
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
            .mode(FILE_MODE)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        shekyl_win_sec::create_owner_only_file(path).map_err(|error| match error {
            shekyl_win_sec::FileCreateError::Create(io_error) => io_error,
            other => io::Error::other(other),
        })
    }
}

fn replace_name(from: &Path, to: &Path, durability: Durability) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        let _ = durability;
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
        move_replace(from, to, durability)
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
fn move_replace(from: &Path, to: &Path, durability: Durability) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let mut flags = MOVEFILE_REPLACE_EXISTING;
    if durability == Durability::Save {
        flags |= MOVEFILE_WRITE_THROUGH;
    }
    let from_w: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to_w: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), flags) };
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

    /// The spawn's space check counts what the copy writes. A partial, a
    /// stranger, and a file over its limit add nothing.
    #[test]
    fn copy_bytes_counts_only_files_the_copy_writes() {
        let parent = tempfile::tempdir().unwrap();
        let cache = parent.path().join("cache");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("cached-certs"), vec![0u8; 1000]).unwrap();
        fs::write(cache.join("notes"), vec![0u8; 4000]).unwrap();
        fs::write(cache.join(".cached-certs.partial"), vec![0u8; 5000]).unwrap();
        let consensus = cache.join("cached-microdesc-consensus");
        fs::File::create(&consensus)
            .unwrap()
            .set_len(CONSENSUS_LIMIT + 1)
            .unwrap();
        assert_eq!(DirectoryCache::at(&cache).copy_bytes(), 1000);
        assert!(!DirectoryCache::at(parent.path().join("missing")).holds_a_file());
        assert_eq!(
            DirectoryCache::at(parent.path().join("missing")).copy_bytes(),
            0
        );
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
        stage(&cache, name, b"new-cache-complete-bytes", Durability::Save).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"old-cache-complete");
        assert!(cache.join(partial_name(name)).is_file());
        commit(&cache, name, Durability::Save).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn a_new_cache_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let created = parent.path().join("created");
        create_owner_only(&created).unwrap();
        let created_mode = fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(created_mode, DIR_MODE);

        let ensured = parent.path().join("ensured");
        ensure_directory(&ensured).unwrap();
        let ensured_mode = fs::metadata(&ensured).unwrap().permissions().mode() & 0o777;
        assert_eq!(ensured_mode, DIR_MODE);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_at_a_cache_name_is_refused() {
        // Fails by hanging if the open blocks, and by copying if a fifo is
        // accepted as the file. `O_NONBLOCK` is what makes the open return.
        use std::os::unix::ffi::OsStrExt;
        let (_parent, cache, data) = dirs();
        let fifo = cache.join("cached-certs");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is NUL-terminated and outlives the call. `mkfifo`
        // creates the node and does not retain the pointer.
        let created = unsafe { libc::mkfifo(name.as_ptr(), posix_mode(FILE_MODE)) };
        assert_eq!(created, 0, "{}", io::Error::last_os_error());
        assert!(!is_regular_file(&fifo));
        let copied = copy_into(&cache, &data).unwrap();
        assert!(copied.is_empty());
        assert!(!data.join("cached-certs").exists());
        assert!(!DirectoryCache::at(&cache).holds_a_file());
    }

    fn three_dirs() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let parent = tempfile::tempdir().unwrap();
        let own = parent.path().join("own");
        let job = parent.path().join("job");
        let data = parent.path().join("data");
        fs::create_dir(&own).unwrap();
        fs::create_dir(&job).unwrap();
        fs::create_dir(&data).unwrap();
        (parent, own, job, data)
    }

    #[test]
    fn the_own_cache_wins_when_it_holds_a_file() {
        let (_parent, own, job, data) = three_dirs();
        fs::write(own.join("cached-certs"), b"own").unwrap();
        fs::write(job.join("cached-certs"), b"job").unwrap();
        fs::write(job.join("cached-microdescs"), b"extra").unwrap();
        let copied = install_from(
            &DirectoryCache::at(&own),
            Some(&DirectoryCache::at(&job)),
            &data,
        )
        .unwrap();
        assert_eq!(copied, vec!["cached-certs"]);
        assert_eq!(fs::read(data.join("cached-certs")).unwrap(), b"own");
        assert!(!data.join("cached-microdescs").exists());
    }

    #[test]
    fn an_empty_own_cache_installs_the_job_seed() {
        let (_parent, own, job, data) = three_dirs();
        fs::write(job.join("cached-certs"), b"job").unwrap();
        let copied = install_from(
            &DirectoryCache::at(&own),
            Some(&DirectoryCache::at(&job)),
            &data,
        )
        .unwrap();
        assert_eq!(copied, vec!["cached-certs"]);
        assert_eq!(fs::read(data.join("cached-certs")).unwrap(), b"job");
    }

    #[test]
    fn an_empty_own_cache_installs_nothing_without_a_job_seed() {
        let (_parent, own, _job, data) = three_dirs();
        let copied = install_from(&DirectoryCache::at(&own), None, &data).unwrap();
        assert!(copied.is_empty());
        assert!(!data.join("cached-certs").exists());
    }

    #[test]
    fn a_data_directory_that_already_holds_a_file_is_left_alone() {
        // Fails if a second source can fill a name the first source did not
        // supply: `cached-microdescs` would appear beside the file already there.
        let (_parent, own, job, data) = three_dirs();
        fs::write(own.join("cached-certs"), b"own").unwrap();
        fs::write(own.join("cached-microdescs"), b"more").unwrap();
        fs::write(job.join("cached-certs"), b"job").unwrap();
        fs::write(data.join("cached-certs"), b"kept").unwrap();
        let copied = install_from(
            &DirectoryCache::at(&own),
            Some(&DirectoryCache::at(&job)),
            &data,
        )
        .unwrap();
        assert!(copied.is_empty());
        assert_eq!(fs::read(data.join("cached-certs")).unwrap(), b"kept");
        assert!(!data.join("cached-microdescs").exists());
    }

    #[test]
    fn the_job_lane_does_not_replace_an_installed_file() {
        let (_parent, source, _job, data) = three_dirs();
        fs::write(source.join("cached-certs"), b"job").unwrap();
        fs::write(source.join("cached-microdescs"), b"fill").unwrap();
        fs::write(data.join("cached-certs"), b"own").unwrap();
        let copied = copy_into_fresh(&DirectoryCache::at(&source), &data).unwrap();
        assert!(copied.is_empty());
        assert_eq!(fs::read(data.join("cached-certs")).unwrap(), b"own");
        assert!(!data.join("cached-microdescs").exists());
    }

    #[test]
    fn install_into_copies_nothing_when_the_own_cache_is_absent_and_no_lane_is_set() {
        if std::env::var_os(JOB_CACHE_ENV).is_some() {
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        fs::create_dir(&data).unwrap();
        let copied = install_into(&parent.path().join("absent"), &data).unwrap();
        assert!(copied.is_empty());
    }
}
