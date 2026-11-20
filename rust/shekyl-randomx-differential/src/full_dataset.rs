// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One full-dataset VM, built the way a miner builds it.
//!
//! The light differential build does not compile this module. The Hole-1
//! bins (`full-parity`, `miner-kat`) are the callers, and they cannot pass
//! light-mode flags: [`FullDatasetVm::build`] takes a seed and chooses the
//! miner flags itself.
//!
//! Build order: allocate and initialize a cache, allocate a dataset, fill
//! it on one thread per core, drop the cache, then create the VM over the
//! dataset alone (fast mode). The cache guard ends before the VM exists.
//! The dataset guard moves into the VM and releases the dataset after the
//! VM is destroyed.

use std::os::raw::c_ulong;
use std::ptr;
use std::thread;

use randomx_v2_sys::{
    randomx_alloc_cache, randomx_alloc_dataset, randomx_calculate_hash, randomx_create_vm,
    randomx_dataset_item_count, randomx_destroy_vm, randomx_get_flags, randomx_init_cache,
    randomx_init_dataset, randomx_release_cache, randomx_release_dataset, RandomxCache,
    RandomxDataset, RandomxFlags, RandomxVm, RANDOMX_FLAG_FULL_MEM, RANDOMX_FLAG_V2,
};

/// Why a full-dataset VM could not be built.
#[derive(Debug)]
pub enum BuildError {
    /// `randomx_alloc_cache` returned null.
    CacheAlloc,
    /// `randomx_alloc_dataset` returned null.
    DatasetAlloc,
    /// The library reported a dataset of zero items.
    DatasetEmpty,
    /// `randomx_create_vm` returned null after the dataset was filled.
    VmCreate,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CacheAlloc => f.write_str("randomx_alloc_cache failed"),
            Self::DatasetAlloc => f.write_str("randomx_alloc_dataset failed (~2 080 MiB)"),
            Self::DatasetEmpty => f.write_str("randomx_dataset_item_count returned 0"),
            Self::VmCreate => f.write_str("randomx_create_vm(FULL_MEM|V2) failed"),
        }
    }
}

impl std::error::Error for BuildError {}

/// A C full-dataset VM. Drop destroys the VM, then releases the dataset.
pub struct FullDatasetVm {
    vm: *mut RandomxVm,
    dataset: OwnedDataset,
}

impl FullDatasetVm {
    /// Build the miner's VM for `seed`.
    ///
    /// # Errors
    ///
    /// An allocation failed, or the library reported an empty dataset.
    /// The dataset needs about 2 080 MiB.
    pub fn build(seed: &[u8; 32]) -> Result<Self, BuildError> {
        let flags = miner_flags();
        let cache = OwnedCache::alloc(flags)?;
        // SAFETY: `cache` is a live allocation. `seed` is 32 bytes.
        unsafe {
            randomx_init_cache(cache.as_ptr(), seed.as_ptr().cast(), seed.len());
        }
        let dataset = OwnedDataset::alloc(flags)?;
        fill(dataset.as_ptr(), cache.as_ptr())?;
        drop(cache);
        // SAFETY: the cache is released, which is fast mode. `dataset` is
        // a filled dataset and stays alive for the VM's whole life.
        let vm = unsafe { randomx_create_vm(flags, ptr::null_mut(), dataset.as_ptr()) };
        if vm.is_null() {
            return Err(BuildError::VmCreate);
        }
        Ok(Self { vm, dataset })
    }

    /// The full-dataset hash of `blob`.
    ///
    /// One caller at a time: the VM's working state is not shared.
    #[must_use]
    pub fn hash(&self, blob: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: `self.vm` is a live VM. `blob` and `out` are valid for
        // their lengths, and `out` is the 32 bytes the hash writes.
        unsafe {
            randomx_calculate_hash(
                self.vm,
                blob.as_ptr().cast(),
                blob.len(),
                out.as_mut_ptr().cast(),
            );
        }
        out
    }
}

impl Drop for FullDatasetVm {
    fn drop(&mut self) {
        if !self.vm.is_null() {
            // SAFETY: `build` stored a live VM. The dataset is released
            // after this, so it outlives the VM.
            unsafe { randomx_destroy_vm(self.vm) };
            self.vm = ptr::null_mut();
        }
        self.dataset.release();
    }
}

/// The flags a miner runs.
///
/// `randomx_get_flags` reports JIT, hardware AES, and the Argon2 SIMD
/// variant. It does not include full-mem, large pages, or the secure flag.
/// Fast mode is full-mem, ORed here, plus v2. `randomx_alloc_cache` masks
/// its argument to JIT and large pages, so the v2 and full-mem bits do not
/// change the cache. `randomx_alloc_dataset` honors large pages only, and
/// this set does not request them.
fn miner_flags() -> RandomxFlags {
    // SAFETY: no arguments; the call reads CPU features.
    let recommended = unsafe { randomx_get_flags() };
    recommended | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2
}

/// A cache the guard releases unless the pointer has been cleared.
struct OwnedCache(*mut RandomxCache);

impl OwnedCache {
    fn alloc(flags: RandomxFlags) -> Result<Self, BuildError> {
        // SAFETY: a null return is [`BuildError::CacheAlloc`].
        let ptr = unsafe { randomx_alloc_cache(flags) };
        if ptr.is_null() {
            Err(BuildError::CacheAlloc)
        } else {
            Ok(Self(ptr))
        }
    }

    fn as_ptr(&self) -> *mut RandomxCache {
        self.0
    }
}

impl Drop for OwnedCache {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: `alloc` stored a live cache, and this is the one release.
        unsafe { randomx_release_cache(self.0) };
        self.0 = ptr::null_mut();
    }
}

/// A dataset the guard releases unless the pointer has been cleared.
struct OwnedDataset(*mut RandomxDataset);

impl OwnedDataset {
    fn alloc(flags: RandomxFlags) -> Result<Self, BuildError> {
        // SAFETY: a null return is [`BuildError::DatasetAlloc`].
        let ptr = unsafe { randomx_alloc_dataset(flags) };
        if ptr.is_null() {
            Err(BuildError::DatasetAlloc)
        } else {
            Ok(Self(ptr))
        }
    }

    fn as_ptr(&self) -> *mut RandomxDataset {
        self.0
    }

    /// Release the dataset now. A later [`Drop`] sees a null pointer.
    fn release(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: `alloc` stored a live dataset, and the pointer is cleared
        // before any second release.
        unsafe { randomx_release_dataset(self.0) };
        self.0 = ptr::null_mut();
    }
}

impl Drop for OwnedDataset {
    fn drop(&mut self) {
        self.release();
    }
}

/// The two pointers the fill threads share. They do not own either one.
///
/// The owning guards stay outside the scope and outlive every thread.
#[derive(Clone, Copy)]
struct FillShare {
    dataset: *mut RandomxDataset,
    cache: *mut RandomxCache,
}

// SAFETY: each thread writes a disjoint item range of one dataset. The
// cache is only read. [`fill`] joins every thread before either guard drops.
unsafe impl Send for FillShare {}

/// Fill every item. Each thread's range is non-empty and the ranges cover
/// the dataset without overlap ([`item_ranges`]).
fn fill(dataset: *mut RandomxDataset, cache: *mut RandomxCache) -> Result<(), BuildError> {
    // SAFETY: no arguments. The count is the library's dataset size.
    let items = u64_from_c_ulong(unsafe { randomx_dataset_item_count() });
    if items == 0 {
        return Err(BuildError::DatasetEmpty);
    }
    let cores = thread::available_parallelism().map_or(1, usize::from);
    let threads = u64::try_from(cores).unwrap_or(1);
    let ranges = item_ranges(items, threads);
    let share = FillShare { dataset, cache };
    thread::scope(|scope| {
        for (start, count) in ranges {
            scope.spawn(move || {
                // Name the carrier as a value. Rust 2021 would otherwise
                // capture the two raw pointers, which are not `Send`.
                let share = share;
                let start_item = c_ulong::try_from(start).expect("a dataset index fits c_ulong");
                let item_count = c_ulong::try_from(count).expect("a dataset range fits c_ulong");
                // SAFETY: `share` names one live dataset and the cache that
                // fills it. This range does not overlap another thread's.
                // The scope joins every thread before either pointer is released.
                unsafe {
                    randomx_init_dataset(share.dataset, share.cache, start_item, item_count);
                }
            });
        }
    });
    Ok(())
}

/// The library's `unsigned long` as a `u64`.
///
/// On LP64 the two types are the same width, so the value is the count.
/// On Windows `unsigned long` is 32 bits and the count is widened. A
/// dataset's item count fits either width.
fn u64_from_c_ulong(value: c_ulong) -> u64 {
    #[cfg(windows)]
    {
        u64::from(value)
    }
    #[cfg(not(windows))]
    {
        value
    }
}

/// Split `items` into non-empty ranges that cover `0..items` without overlap.
///
/// `randomx_init_dataset` requires `start_item` below the dataset size and
/// `start_item + item_count` within it (`external/randomx-v2` `randomx.cpp`).
/// A zero `item_count` still enters the library's init, so this split never
/// emits one: `threads` is clamped to `1..=items`. Zero items yields no ranges;
/// the caller reports [`BuildError::DatasetEmpty`] and does not call into C.
fn item_ranges(items: u64, threads: u64) -> Vec<(u64, u64)> {
    if items == 0 {
        return Vec::new();
    }
    let threads = threads.clamp(1, items);
    let mut start = 0u64;
    let mut ranges = Vec::with_capacity(usize::try_from(threads).unwrap_or(0));
    for t in 0..threads {
        let count = items / threads + u64::from(t < items % threads);
        ranges.push((start, count));
        start += count;
    }
    ranges
}

#[cfg(test)]
mod tests {
    //! Range splits only. A test here does not call into the C library
    //! and does not allocate a dataset. The structural job runs this
    //! module with `full-dataset`; the light test lane does not compile it.

    use super::item_ranges;

    fn covers(items: u64, threads: u64) {
        let ranges = item_ranges(items, threads);
        if items == 0 {
            assert!(ranges.is_empty());
            return;
        }
        let mut cursor = 0u64;
        assert!(!ranges.is_empty());
        for (start, count) in ranges {
            assert!(count >= 1, "an empty range at {start}");
            assert_eq!(start, cursor);
            cursor += count;
        }
        assert_eq!(cursor, items);
    }

    #[test]
    fn ranges_cover_the_dataset_without_empty_or_overlap() {
        for (items, threads) in [(1, 8), (32, 32), (10, 3), (10, 0), (33, 8), (0, 4)] {
            covers(items, threads);
        }
        assert_eq!(item_ranges(1, 8), vec![(0, 1)]);
        assert_eq!(item_ranges(32, 32).len(), 32);
        assert!(item_ranges(32, 32).iter().all(|range| range.1 == 1));
        assert_eq!(item_ranges(0, 4), Vec::new());
        assert_eq!(item_ranges(10, 0), vec![(0, 10)]);
    }
}
