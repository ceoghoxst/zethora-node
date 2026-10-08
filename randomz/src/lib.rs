// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # RandomX
//!
//! The `randomx-rs` crate provides bindings to the RandomX proof-of-work (PoW) system.
//!
//! From the [RandomX github repo]:
//!
//! "RandomX is a proof-of-work (PoW) algorithm that is optimized for general-purpose CPUs. RandomX uses random code
//! execution together with several memory-hard techniques to minimize the efficiency advantage of specialized
//! hardware."
//!
//! Read more about how RandomX works in the [design document].
//!
//! [RandomX github repo]: <https://github.com/tevador/RandomX>
//! [design document]: <https://github.com/tevador/RandomX/blob/master/doc/design.md>
mod bindings;
/// Test utilities for fuzzing
pub mod test_utils;

use std::{convert::TryFrom, num::TryFromIntError, ptr, sync::Arc};

use bindings::{
    randomx_alloc_cache,
    randomx_alloc_dataset,
    randomx_cache,
    randomx_calculate_hash,
    randomx_create_vm,
    randomx_dataset,
    randomx_dataset_item_count,
    randomx_destroy_vm,
    randomx_get_dataset_memory,
    randomx_init_cache,
    randomx_init_dataset,
    randomx_release_cache,
    randomx_release_dataset,
    randomx_vm,
    randomx_vm_set_cache,
    randomx_vm_set_dataset,
    RANDOMX_HASH_SIZE,
};
use bitflags::bitflags;
use libc::{c_ulong, c_void};
use thiserror::Error;

/// The size, in bytes, of a single RandomX dataset item. The full dataset returned by
/// [`RandomXDataset::get_data`] is `RandomXDataset::count()` items of this size.
pub use crate::bindings::RANDOMX_DATASET_ITEM_SIZE;
use crate::bindings::{
    randomx_calculate_hash_first,
    randomx_calculate_hash_last,
    randomx_calculate_hash_next,
    randomx_get_flags,
};

bitflags! {
    /// RandomX Flags are used to configure the library.
    pub struct RandomXFlag: u32 {
        /// No flags set. Works on all platforms, but is the slowest.
        const FLAG_DEFAULT      = 0b0000_0000;
        /// Allocate memory in large pages.
        const FLAG_LARGE_PAGES  = 0b0000_0001;
        /// Use hardware accelerated AES.
        const FLAG_HARD_AES     = 0b0000_0010;
        /// Use the full dataset.
        const FLAG_FULL_MEM     = 0b0000_0100;
        /// Use JIT compilation support.
        const FLAG_JIT          = 0b0000_1000;
        /// When combined with FLAG_JIT, the JIT pages are never writable and executable at the
        /// same time.
        const FLAG_SECURE       = 0b0001_0000;
        /// Optimize Argon2 for CPUs with the SSSE3 instruction set.
        const FLAG_ARGON2_SSSE3 = 0b0010_0000;
        /// Optimize Argon2 for CPUs with the AVX2 instruction set.
        const FLAG_ARGON2_AVX2  = 0b0100_0000;
        /// Optimize Argon2 for CPUs without the AVX2 or SSSE3 instruction sets.
        const FLAG_ARGON2       = 0b0110_0000;
    }
}

impl RandomXFlag {
    /// Returns the recommended flags to be used.
    ///
    /// Does not include:
    /// * FLAG_LARGE_PAGES
    /// * FLAG_FULL_MEM
    /// * FLAG_SECURE
    ///
    /// The above flags need to be set manually, if required.
    pub fn get_recommended_flags() -> RandomXFlag {
        RandomXFlag {
            bits: unsafe { randomx_get_flags() },
        }
    }
}

impl Default for RandomXFlag {
    /// Default value for RandomXFlag
    fn default() -> RandomXFlag {
        RandomXFlag::FLAG_DEFAULT
    }
}

#[derive(Debug, Clone, Error)]
/// This enum specifies the possible errors that may occur.
pub enum RandomXError {
    #[error("Problem creating the RandomX object: {0}")]
    CreationError(String),
    #[error("Problem with configuration flags: {0}")]
    FlagConfigError(String),
    #[error("Problem with parameters supplied: {0}")]
    ParameterError(String),
    #[error("Failed to convert Int to usize")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("Unknown problem running RandomX: {0}")]
    Other(String),
}

#[derive(Debug)]
struct RandomXCacheInner {
    cache_ptr: *mut randomx_cache,
}

impl Drop for RandomXCacheInner {
    /// De-allocates memory for the `cache` object
    fn drop(&mut self) {
        unsafe {
            randomx_release_cache(self.cache_ptr);
        }
    }
}

#[derive(Debug, Clone)]
/// The Cache is used for light verification and Dataset construction.
pub struct RandomXCache {
    inner: Arc<RandomXCacheInner>,
}

impl RandomXCache {
    /// Creates and alllcates memory for a new cache object, and initializes it with
    /// the key value.
    ///
    /// `flags` is any combination of the following two flags:
    /// * FLAG_LARGE_PAGES
    /// * FLAG_JIT
    ///
    /// and (optionally) one of the following flags (depending on instruction set supported):
    /// * FLAG_ARGON2_SSSE3
    /// * FLAG_ARGON2_AVX2
    ///
    /// `key` is a sequence of u8 used to initialize SuperScalarHash.
    pub fn new(flags: RandomXFlag, key: &[u8]) -> Result<RandomXCache, RandomXError> {
        if key.is_empty() {
            Err(RandomXError::ParameterError("key is empty".to_string()))
        } else {
            let cache_ptr = unsafe { randomx_alloc_cache(flags.bits) };
            if cache_ptr.is_null() {
                Err(RandomXError::CreationError("Could not allocate cache".to_string()))
            } else {
                let inner = RandomXCacheInner { cache_ptr };
                let result = RandomXCache { inner: Arc::new(inner) };
                let key_ptr = key.as_ptr() as *mut c_void;
                let key_size = key.len();
                unsafe {
                    randomx_init_cache(result.inner.cache_ptr, key_ptr, key_size);
                }
                Ok(result)
            }
        }
    }
}

#[derive(Debug)]
struct RandomXDatasetInner {
    dataset_ptr: *mut randomx_dataset,
    dataset_count: u32,
    #[allow(dead_code)]
    cache: RandomXCache,
}

impl Drop for RandomXDatasetInner {
    /// De-allocates memory for the `dataset` object.
    fn drop(&mut self) {
        unsafe {
            randomx_release_dataset(self.dataset_ptr);
        }
    }
}

#[derive(Debug, Clone)]
/// The Dataset is a read-only memory structure that is used during VM program execution.
pub struct RandomXDataset {
    inner: Arc<RandomXDatasetInner>,
}

impl RandomXDataset {
    /// Creates a new dataset object, allocates memory to the `dataset` object and initializes it.
    ///
    /// `flags` is one of the following:
    /// * FLAG_DEFAULT
    /// * FLAG_LARGE_PAGES
    ///
    /// `cache` is a cache object.
    ///
    /// `start` is the item number where initialization should start. **Pass 0.** The items
    /// `[start, RandomXDataset::count())` are initialized by the RandomX library; the leading `start` items are
    /// zeroed, since the library never writes them.
    ///
    /// # Warning
    ///
    /// The RandomX API requires that *every* item from `0` to `RandomXDataset::count() - 1` is initialized before a
    /// dataset may be used (see the note on `randomx_init_dataset` in `randomx.h`). A non-zero `start` therefore
    /// produces a dataset that does **not** satisfy that precondition and must **not** be passed to
    /// [`RandomXVM::new`] or [`RandomXVM::reinit_dataset`]. Doing so is not detected or reported: the VM will read
    /// the zeroed leading items as though they were real dataset items and silently compute hashes that disagree
    /// with every other RandomX implementation.
    ///
    /// The only legitimate use of a non-zero `start` in the upstream API is splitting the initialization of a single
    /// *shared* dataset across several threads, each initializing a different item range. This wrapper cannot express
    /// that, because `new` always allocates its own dataset, so there is no correct value other than 0.
    // Conversions may be lossy on Windows or Linux
    #[allow(clippy::useless_conversion)]
    pub fn new(flags: RandomXFlag, cache: RandomXCache, start: u32) -> Result<RandomXDataset, RandomXError> {
        let item_count = RandomXDataset::count()
            .map_err(|e| RandomXError::CreationError(format!("Could not get dataset count: {e:?}")))?;

        let test = unsafe { randomx_alloc_dataset(flags.bits) };
        if test.is_null() {
            Err(RandomXError::CreationError("Could not allocate dataset".to_string()))
        } else {
            let inner = RandomXDatasetInner {
                dataset_ptr: test,
                dataset_count: item_count,
                cache,
            };
            let result = RandomXDataset { inner: Arc::new(inner) };

            if start < item_count {
                // `randomx_init_dataset` initialises the items `[start, start + count)`, so the count passed to it
                // must be the number of *remaining* items. Passing the full `item_count` with a non-zero `start`
                // writes `start` items past the end of the allocation (a heap buffer overflow, silent in release
                // builds because the library's assertions are compiled out by `NDEBUG`).
                let remaining = item_count.saturating_sub(start);
                // `randomx_alloc_dataset` hands back uninitialised memory (only `FLAG_LARGE_PAGES` gets zero pages),
                // and the call below only writes from `start` onwards, so zero the leading `start` items. Without
                // this the first `start * RANDOMX_DATASET_ITEM_SIZE` bytes stay uninitialised and reading them in
                // `get_data` would be undefined behaviour as well as an information leak.
                if start > 0 {
                    let memory = unsafe { randomx_get_dataset_memory(result.inner.dataset_ptr) };
                    if memory.is_null() {
                        return Err(RandomXError::CreationError(
                            "Could not get dataset memory to zero the uninitialised prefix".to_string(),
                        ));
                    }
                    let prefix_len = usize::try_from(start)?
                        .checked_mul(RANDOMX_DATASET_ITEM_SIZE)
                        .ok_or_else(|| {
                            RandomXError::CreationError(format!("Dataset prefix size overflows: {start}"))
                        })?;
                    // SAFETY: `memory` is the non-null start of the dataset buffer, which the library allocated with
                    // room for `item_count` items of `RANDOMX_DATASET_ITEM_SIZE` bytes. `start < item_count`, so
                    // `prefix_len` bytes lie inside that allocation. `u8` is always valid for any bit pattern and has
                    // an alignment of 1, and nothing else refers to the buffer yet.
                    unsafe {
                        ptr::write_bytes(memory.cast::<u8>(), 0, prefix_len);
                    }
                }
                unsafe {
                    randomx_init_dataset(
                        result.inner.dataset_ptr,
                        result.inner.cache.inner.cache_ptr,
                        c_ulong::from(start),
                        c_ulong::from(remaining),
                    );
                }
                Ok(result)
            } else {
                Err(RandomXError::CreationError(format!(
                    "start must be less than item_count: start: {start}, item_count: {item_count}",
                )))
            }
        }
    }

    /// Returns the number of items in the `dataset` or an error on failure.
    pub fn count() -> Result<u32, RandomXError> {
        match unsafe { randomx_dataset_item_count() } {
            0 => Err(RandomXError::Other("Dataset item count was 0".to_string())),
            x => {
                // This weirdness brought to you by c_ulong being different on Windows and Linux
                #[cfg(target_os = "windows")]
                return Ok(x);
                #[cfg(not(target_os = "windows"))]
                return Ok(u32::try_from(x)?);
            },
        }
    }

    /// Returns a copy of the *entire* internal memory buffer of the `dataset`, or an error on failure.
    ///
    /// The returned buffer is `RandomXDataset::count()` items of [`RANDOMX_DATASET_ITEM_SIZE`] (64) bytes each, i.e.
    /// approximately 2.03 GB with the default RandomX configuration. This is an expensive, fully allocating copy of
    /// the dataset, so avoid calling it on a hot path. The allocation is fallible: an out-of-memory condition is
    /// reported as a [`RandomXError`] instead of aborting the process.
    ///
    /// If the dataset was created with a non-zero `start`, the first `start` items were never initialised by the
    /// RandomX library; [`RandomXDataset::new`] zeroes them, so they are returned here as zero bytes.
    pub fn get_data(&self) -> Result<Vec<u8>, RandomXError> {
        let memory = unsafe { randomx_get_dataset_memory(self.inner.dataset_ptr) };
        if memory.is_null() {
            return Err(RandomXError::Other("Could not get dataset memory".into()));
        }
        // `dataset_count` is an *item* count, not a byte count; each item is `RANDOMX_DATASET_ITEM_SIZE` bytes.
        let item_count = usize::try_from(self.inner.dataset_count)?;
        let size_in_bytes = item_count.checked_mul(RANDOMX_DATASET_ITEM_SIZE).ok_or_else(|| {
            RandomXError::Other(format!(
                "Dataset size overflows usize: {item_count} items of {RANDOMX_DATASET_ITEM_SIZE} bytes each",
            ))
        })?;
        // SAFETY: `memory` is a non-null pointer to the dataset buffer owned by the RandomX library. The library
        // allocated that buffer with room for `randomx_dataset_item_count()` items of `RANDOMX_DATASET_ITEM_SIZE`
        // bytes each, and `dataset_count` was set from that same call, so exactly `size_in_bytes` bytes are inside
        // the allocation. Every one of those bytes is initialised: `RandomXDataset::new` has the library write the
        // items `[start, count)` and zeroes the `[0, start)` prefix that the library leaves untouched. `u8` has an
        // alignment of 1, so the pointer is trivially aligned. The buffer outlives the slice: `&self` keeps the
        // `Arc<RandomXDatasetInner>` (and hence the dataset allocation) alive, the dataset is read-only once
        // initialised, and the slice is copied into an owned `Vec` before this function returns.
        let data = unsafe { std::slice::from_raw_parts(memory.cast::<u8>(), size_in_bytes) };
        // Allocate fallibly: a plain `to_vec` of ~2 GB would call `handle_alloc_error` and abort the whole process
        // on failure, which is not an acceptable outcome for a library that returns a `Result`.
        let mut result = Vec::new();
        result.try_reserve_exact(size_in_bytes).map_err(|e| {
            RandomXError::Other(format!(
                "Could not allocate {size_in_bytes} bytes for the dataset copy: {e}"
            ))
        })?;
        result.extend_from_slice(data);
        Ok(result)
    }
}

#[derive(Debug)]
/// The RandomX Virtual Machine (VM) is a complex instruction set computer that executes generated programs.
pub struct RandomXVM {
    flags: RandomXFlag,
    vm: *mut randomx_vm,
    linked_cache: Option<RandomXCache>,
    linked_dataset: Option<RandomXDataset>,
}

impl Drop for RandomXVM {
    /// De-allocates memory for the `VM` object.
    fn drop(&mut self) {
        unsafe {
            randomx_destroy_vm(self.vm);
        }
    }
}

impl RandomXVM {
    /// Creates a new `VM` and initializes it, error on failure.
    ///
    /// `flags` is any combination of the following 5 flags:
    /// * FLAG_LARGE_PAGES
    /// * FLAG_HARD_AES
    /// * FLAG_FULL_MEM
    /// * FLAG_JIT
    /// * FLAG_SECURE
    ///
    /// Or
    ///
    /// * FLAG_DEFAULT
    ///
    /// `cache` is a cache object, optional if FLAG_FULL_MEM is set.
    ///
    /// `dataset` is a dataset object, optional if FLAG_FULL_MEM is not set.
    pub fn new(
        flags: RandomXFlag,
        cache: Option<RandomXCache>,
        dataset: Option<RandomXDataset>,
    ) -> Result<RandomXVM, RandomXError> {
        let is_full_mem = flags.contains(RandomXFlag::FLAG_FULL_MEM);
        match (cache, dataset) {
            (None, None) => Err(RandomXError::CreationError("Failed to allocate VM".to_string())),
            (None, _) if !is_full_mem => Err(RandomXError::FlagConfigError(
                "No cache and FLAG_FULL_MEM not set".to_string(),
            )),
            (_, None) if is_full_mem => Err(RandomXError::FlagConfigError(
                "No dataset and FLAG_FULL_MEM set".to_string(),
            )),
            (cache, dataset) => {
                let cache_ptr = cache
                    .as_ref()
                    .map(|stash| stash.inner.cache_ptr)
                    .unwrap_or_else(ptr::null_mut);
                let dataset_ptr = dataset
                    .as_ref()
                    .map(|data| data.inner.dataset_ptr)
                    .unwrap_or_else(ptr::null_mut);
                let vm = unsafe { randomx_create_vm(flags.bits, cache_ptr, dataset_ptr) };
                Ok(RandomXVM {
                    vm,
                    flags,
                    linked_cache: cache,
                    linked_dataset: dataset,
                })
            },
        }
    }

    /// Re-initializes the `VM` with a new cache that was initialised without
    /// RandomXFlag::FLAG_FULL_MEM.
    pub fn reinit_cache(&mut self, cache: RandomXCache) -> Result<(), RandomXError> {
        if self.flags.contains(RandomXFlag::FLAG_FULL_MEM) {
            Err(RandomXError::FlagConfigError(
                "Cannot reinit cache with FLAG_FULL_MEM set".to_string(),
            ))
        } else {
            unsafe {
                randomx_vm_set_cache(self.vm, cache.inner.cache_ptr);
            }
            self.linked_cache = Some(cache);
            Ok(())
        }
    }

    /// Re-initializes the `VM` with a new dataset that was initialised with
    /// RandomXFlag::FLAG_FULL_MEM.
    pub fn reinit_dataset(&mut self, dataset: RandomXDataset) -> Result<(), RandomXError> {
        if self.flags.contains(RandomXFlag::FLAG_FULL_MEM) {
            unsafe {
                randomx_vm_set_dataset(self.vm, dataset.inner.dataset_ptr);
            }
            self.linked_dataset = Some(dataset);
            Ok(())
        } else {
            Err(RandomXError::FlagConfigError(
                "Cannot reinit dataset without FLAG_FULL_MEM set".to_string(),
            ))
        }
    }

    /// Calculates a RandomX hash value and returns it, error on failure.
    ///
    /// `input` is a sequence of u8 to be hashed.
    pub fn calculate_hash(&self, input: &[u8]) -> Result<Vec<u8>, RandomXError> {
        if input.is_empty() {
            Err(RandomXError::ParameterError("input was empty".to_string()))
        } else {
            let size_input = input.len();
            let input_ptr = input.as_ptr() as *mut c_void;
            let arr = [0; RANDOMX_HASH_SIZE as usize];
            let output_ptr = arr.as_ptr() as *mut c_void;
            unsafe {
                randomx_calculate_hash(self.vm, input_ptr, size_input, output_ptr);
            }
            // if this failed, arr should still be empty
            if arr == [0; RANDOMX_HASH_SIZE as usize] {
                Err(RandomXError::Other("RandomX calculated hash was empty".to_string()))
            } else {
                let result = arr.to_vec();
                Ok(result)
            }
        }
    }

    /// Calculates hashes from a set of inputs.
    ///
    /// `input` is an array of a sequence of u8 to be hashed.
    #[allow(clippy::needless_range_loop)] // Range loop is not only for indexing `input`
    pub fn calculate_hash_set(&self, input: &[&[u8]]) -> Result<Vec<Vec<u8>>, RandomXError> {
        if input.is_empty() {
            // Empty set
            return Err(RandomXError::ParameterError("input was empty".to_string()));
        }

        let mut result = Vec::new();
        // For single input
        if input.len() == 1 {
            let hash = self.calculate_hash(input[0])?;
            result.push(hash);
            return Ok(result);
        }

        // For multiple inputs
        let mut output_ptr: *mut c_void = ptr::null_mut();
        let arr = [0; RANDOMX_HASH_SIZE as usize];

        // Not len() as last iteration assigns final hash
        let iterations = input.len() + 1;
        for i in 0..iterations {
            if i == iterations - 1 {
                // For last iteration
                unsafe {
                    randomx_calculate_hash_last(self.vm, output_ptr);
                }
            } else {
                if input[i].is_empty() {
                    // Stop calculations
                    if arr != [0; RANDOMX_HASH_SIZE as usize] {
                        // Complete what was started
                        unsafe {
                            randomx_calculate_hash_last(self.vm, output_ptr);
                        }
                    }
                    return Err(RandomXError::ParameterError("input was empty".to_string()));
                };
                let size_input = input[i].len();
                let input_ptr = input[i].as_ptr() as *mut c_void;
                output_ptr = arr.as_ptr() as *mut c_void;
                if i == 0 {
                    // For first iteration
                    unsafe {
                        randomx_calculate_hash_first(self.vm, input_ptr, size_input);
                    }
                } else {
                    unsafe {
                        // For every other iteration
                        randomx_calculate_hash_next(self.vm, input_ptr, size_input, output_ptr);
                    }
                }
            }

            if i != 0 {
                // First hash is only available in 2nd iteration
                if arr == [0; RANDOMX_HASH_SIZE as usize] {
                    return Err(RandomXError::Other("RandomX hash was zero".to_string()));
                }
                let output: Vec<u8> = arr.to_vec();
                result.push(output);
            }
        }
        Ok(result)
    }
}
