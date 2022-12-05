// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Track memory regions that are mapped to the guest microVM.

use std::io::IoSlice;
use std::io::{Read, Write, Seek, SeekFrom};
use std::fs::{OpenOptions, File};
use std::path::PathBuf;
use std::sync::Arc;
use std::{mem, result};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::io::{IntoRawFd, AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use guest_address::GuestAddress;
use mmap::{self, MemoryMapping};
use DataInit;

const PAGE_SIZE: usize = 4096;

/// Snapshot memory file option
#[derive(Default, Clone, Copy)]
pub struct MemoryFileOption {
    /// Restore eagerly
    pub copy: bool,
    /// Memory file should be opened with O_DIRECT
    pub odirect: bool,
}

/// Alias for memory region list
pub type RegionList = Vec<(usize, usize)>;
/// Metadata per snapshot layer
/// A single-layer snapshot: `dirty_regions` defines the memory dump and `accessed_regions` defines the
/// working set.
/// A two-layer base-diff snapshot: for the base layer only `dirty_regions` are used and for the diff
/// layer `dirty_regions` defines the memory dump and `access_regions` defines the working set.
#[derive(Default, Serialize, Deserialize)]
pub struct MemorySnapshotLayer {
    /// regions that are written to during the snapshotting phase
    pub dirty_regions: RegionList,
    /// regions that are accessed during the execution resumed from the snapshot
    pub ws: RegionList,
    /// regions that are not accessed during the execution resumed from the snapshot
    pub non_ws: RegionList,
}
///Memory snapshot metadata
pub type MemorySnapshotMeta = Vec<MemorySnapshotLayer>;

/// Errors associated with handling guest memory regions.
#[derive(Debug)]
pub enum Error {
    /// Failure in finding a guest address in any memory regions mapped by this guest.
    InvalidGuestAddress(GuestAddress),
    /// Failure in finding a guest address range in any memory regions mapped by this guest.
    InvalidGuestAddressRange(GuestAddress, usize),
    /// Failure in finding a host address in any memory regions mapped by this guest.
    InvalidHostAddress(u64),
    /// Failure in accessing the memory located at some address.
    MemoryAccess(GuestAddress, mmap::Error),
    /// Failure in creating an anonymous shared mapping.
    MemoryMappingFailed(mmap::Error),
    /// Failure in initializing guest memory.
    MemoryNotInitialized,
    /// Two of the memory regions are overlapping.
    MemoryRegionOverlap,
    /// No memory regions were provided for initializing the guest memory.
    NoMemoryRegions,
    /// I/O Error
    IoError(std::io::Error),
}
type Result<T> = result::Result<T, Error>;

/// Tracks a mapping of anonymous memory in the current process and the corresponding base address
/// in the guest's memory space.
pub struct MemoryRegion {
    mapping: MemoryMapping,
    guest_base: GuestAddress,
}

impl MemoryRegion {
    pub fn size(&self) -> usize {
        self.mapping.size()
    }
}

fn region_end(region: &MemoryRegion) -> GuestAddress {
    // unchecked_add is safe as the region bounds were checked when it was created.
    region.guest_base.unchecked_add(region.mapping.size())
}

/// Tracks all memory regions allocated for the guest in the current process.
#[derive(Clone)]
pub struct GuestMemory {
    regions: Arc<Vec<MemoryRegion>>,
}

impl GuestMemory {
    /// Creates a container for guest memory regions.
    /// Valid memory regions are specified as a Vec of (Address, Size) tuples sorted by Address.
    pub fn new(ranges: &[(GuestAddress, usize)], clear_soft_dirty_bits: bool) -> Result<GuestMemory> {
        if ranges.is_empty() {
            return Err(Error::NoMemoryRegions);
        }

        let mut regions = Vec::<MemoryRegion>::new();
        for range in ranges.iter() {
            if let Some(last) = regions.last() {
                if last
                    .guest_base
                    .checked_add(last.mapping.size())
                    .map_or(true, |a| a > range.0)
                {
                    return Err(Error::MemoryRegionOverlap);
                }
            }

            println!("To guest base {:?}", range.0);

            let mapping = MemoryMapping::new(range.1).map_err(Error::MemoryMappingFailed)?;
            println!("To mapping {:?}", mapping);
            regions.push(MemoryRegion {
                mapping,
                guest_base: range.0,
            });
        }

        if clear_soft_dirty_bits {
            GuestMemory::clear_soft_dirty_bits();
        }

        Ok(GuestMemory {
            regions: Arc::new(regions),
        })
    }

    fn copy_load_memory(&self, memory_dump: &mut File, dirty_regions: &RegionList) -> Result<()> {
        let mut i = 0;
        let mut bufs = Vec::new();
        // iterate through the regions for the current layer
        self.with_regions_mut(|_, guest_base, size, ptr| -> Result<()> {
            // need to check if the region is within the mapping
            // the x86 carved out is at 4GiB, so for VM up to 3GiB
            // the check should never be reached as there is only one mapping
            while i < dirty_regions.len() && (dirty_regions[i].0 < guest_base.offset() + size) {
                println!("VMM: copying region at {}:{}", dirty_regions[i].0, dirty_regions[i].1);
                let guest_addr = dirty_regions[i].0 * PAGE_SIZE;
                let region_len = dirty_regions[i].1 * PAGE_SIZE;

                // println!("Prin to add toy addr");
                // println!("to ptr: {:?}", ptr);
                // println!("to guest_addr: {:?}", guest_addr);
                // println!("to guest_base.offset: {:?}", guest_base.offset());
                let addr = ptr + guest_addr;
                // let addr = ptr + (guest_addr - guest_base.offset());
                let buf = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, region_len) };
                bufs.push(std::io::IoSliceMut::new(buf));
                i += 1;
            }
            Ok(())
        })?;
        // getter-scatter read done here
        memory_dump.read_vectored(bufs.as_mut_slice()).map(|_| ()).map_err(|e| Error::IoError(e))
    }
    /// Creates a container for guest memory regions MAP_PRIVATE from the provided memory dump file
    /// `path`: path to the memory dump file
    /// `hugepage`: use MAP_HUGETLB when creating memory mappings
    /// `copy`: create anonymous memory and then copy content from the memory dump into the new
    /// mappings
    pub fn new_from_snapshot(
        ranges: &[(GuestAddress, usize)],
        load_dir: &Vec<PathBuf>,
        memory_meta: &MemorySnapshotMeta,
        load_ws: bool,
        _hugepage: bool,
        base: MemoryFileOption,
        diff: MemoryFileOption,
        clear_soft_dirty_bits: bool,
    ) -> Result<GuestMemory> {
        if ranges.is_empty() {
            return Err(Error::NoMemoryRegions);
        }

        let guest_mem = GuestMemory::new(ranges, false)?;

        for (i, layer) in memory_meta.iter().enumerate() {
            // open the memory dump file for the current layer
            let mut dir = load_dir[i].clone();
            let odirect = (i == 0  && base.odirect) || (i == 1 && diff.odirect);

            if !load_ws && (i == 1 && diff.copy) || (i == 0 && load_dir.len() == 1 && base.copy) {
                // eagerly only applicable when diff with no WS or only base with no WS
                // WS dealt at the end
                println!("VMM: eagerly restoring layer {} in {:?}...", i, dir);
                dir.push("memory_dump");
                let mut memory_dump = OpenOptions::new()
                    .read(true)
                    .custom_flags(if odirect { libc::O_DIRECT } else { 0 })
                    .open(dir.as_path())
                    .map_err(|e| Error::IoError(e))?;
                guest_mem.copy_load_memory(&mut memory_dump, &layer.dirty_regions)?;
            } else if load_ws || (i == 0 && (!base.copy || load_dir.len() > 1)) || (i == 1 && !diff.copy) {
                // lazily
                let dirty_regions = if load_ws && i == 1 {
                    &layer.non_ws
                } else {
                    &layer.dirty_regions
                };
                dir.push("memory_dump_sparse");
                println!("VMM: lazily restoring layer {} in {:?}...", i, dir);
                let memory_dump = OpenOptions::new()
                    .read(true)
                    .custom_flags(if odirect { libc::O_DIRECT } else { 0 })
                    .open(dir.as_path())
                    .map_err(|e| Error::IoError(e))?;
                let mut i = 0;
                let memory_dump_fd = memory_dump.into_raw_fd();
                guest_mem.with_regions_mut(|_, guest_base, size, ptr| -> Result<()> {
                    // iterate through the regions for the current layer
                    while i < dirty_regions.len() && (dirty_regions[i].0 + dirty_regions[i].1) * PAGE_SIZE <= guest_base.offset() + size {
                        let offset = dirty_regions[i].0 * PAGE_SIZE;
                        let addr = ptr + offset - guest_base.offset();
                        let region_len = dirty_regions[i].1 * PAGE_SIZE;

                        // we have to first unmap, then file-mmap
                        unsafe {
                            if libc::munmap(addr as *mut libc::c_void, region_len) < 0 {
                                panic!("Unable to munmap a memory mapping");
                            }
                        }
                        let mapped_addr = unsafe {
                            libc::mmap(
                                addr as *mut libc::c_void,
                                region_len,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                                memory_dump_fd,
                                offset as libc::off_t,
                            )
                        };
                        if mapped_addr  == libc::MAP_FAILED {
                            panic!("Unable to mmap the diff snapshot");
                        }
                        println!("file-mmap {}:{}", dirty_regions[i].0, dirty_regions[i].1);
                        i += 1;
                    }
                    Ok(())
                })?;
            }
        }
        if load_ws {
            let mut dir = load_dir.last().unwrap().clone();
            dir.push("WS_dump");
            //println!("VMM: eagerly restoring WS at {:?}...", dir);
            let mut memory_dump = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECT)
                .open(dir.as_path())
                .map_err(|e| Error::IoError(e))?;
            guest_mem.copy_load_memory(&mut memory_dump, &memory_meta.last().unwrap().ws)?;
        }
        if clear_soft_dirty_bits {
            GuestMemory::clear_soft_dirty_bits();
            //let (_, dirty_gfns) = guest_mem.get_pagemap(false);
            //println!("pages marked soft dirty: {}", dirty_gfns.len());
        }
        //println!("VMM: restored memory");
        //std::thread::sleep(std::time::Duration::from_millis(100000000));

        Ok(guest_mem)
    }

    /// Returns the end address of memory.
    ///
    /// # Examples
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_end_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     assert_eq!(start_addr.checked_add(0x400), Some(gm.end_addr()));
    ///     Ok(())
    /// # }
    /// ```
    pub fn end_addr(&self) -> GuestAddress {
        // let mut base = 2147483648usize;
        self.regions
            .iter()
            .max_by_key(|region| region.guest_base)
            .map_or(GuestAddress(0), |region| region_end(region))
    }

    /// Returns true if the given address is within the memory range available to the guest.
    pub fn address_in_range(&self, addr: GuestAddress, flag: bool) -> bool {
        let mut temp;
        for region in self.regions.iter() {

            // println!("{:?}: ", region.guest_base);
            // println!("{:?}: ", region_end(region));

            if flag {
                temp = addr.unchecked_add(region.guest_base.offset());
                // println!("{:?} ", temp);
            } else {
                temp = addr;
            }

            if temp >= region.guest_base && addr < region_end(region) {
                return true;
            }
        }
        false
    }

    /// Returns the address plus the offset if it is in range.
    pub fn checked_offset(&self, base: GuestAddress, offset: usize) -> Option<GuestAddress> {
        if let Some(addr) = base.checked_add(offset) {
            for region in self.regions.iter() {
                if addr >= region.guest_base && addr < region_end(region) {
                    return Some(addr);
                }
            }
        }
        None
    }

    /// Returns the size of the memory region in bytes.
    pub fn num_regions(&self) -> usize {
        self.regions.len()
    }

    // echo 4 > proc/PID/clear_refs
    fn clear_soft_dirty_bits() {

        println!("Bika clear_soft_dirty_bits");

        let path = format!("/proc/{}/clear_refs", std::process::id());
        let mut proc_file = OpenOptions::new().write(true).open(path).expect("Failed to open /proc/PID/clear_refs");
        proc_file.write_all(b"4").expect("Failed to clear soft dirty bits");
    }

    /// Read /proc/PID/pagemap, return a mapping between host and guest physical page numbers
    /// and the list of dirty guest physical page numbers.
    /// If `pfn_to_gfn` is true, the mapping is from host to guest.
    /// Otherwise, the mapping is from guest to host.
    pub fn get_pagemap(&self, pfn_to_gfn: bool) -> (BTreeMap<usize, usize>, Vec<usize>) {
        let mut mapping = BTreeMap::new();
        let mut dirty_list = Vec::new();
        let mut page_i_base = 0usize;
        // let mut page_i_base = 2147483648usize;
        for region in self.regions.iter() {
            println!("to page_i_base: {}", page_i_base);
            let (mut partial_mapping, mut partial_dirty_list) =
                region.mapping.get_pagemap(pfn_to_gfn, page_i_base, PAGE_SIZE);
            mapping.append(&mut partial_mapping);
            dirty_list.append(&mut partial_dirty_list);
            page_i_base += region.mapping.size() / PAGE_SIZE;
        }
        (mapping, dirty_list)
    }

    unsafe fn punch_holes(fd: RawFd, offset: libc::off_t, len: libc::off_t) -> std::result::Result<(), std::io::Error>{
        // punch holes
        //println!("punch a hole at {} of size {} Bytes", offset, len);
        let r = libc::fallocate(
            fd,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            len
        );
        if r != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn generate_memory_dump(&self, gfns_dirty_vec: &Vec<usize>, memory_dump: &mut File) -> Result<()> {
        let mut test = 1usize;
        let mut start = 0usize;
        let mut base = 2147483648usize;

        println!("To gfns_dirty_vec len {:?}", gfns_dirty_vec.len());

        while start < gfns_dirty_vec.len() {
            // find the end of current dirty region
            while test < gfns_dirty_vec.len() && gfns_dirty_vec[test] - gfns_dirty_vec[test-1] == 1 {
                test += 1;
            }
            let guest_frame_number = gfns_dirty_vec[start];
            let num_guest_frames = test - start; // test - 1 - start + 1
            // println!("VMM: dump region {}:{}", guest_frame_number, num_guest_frames);
            self.write_from_memory(
                GuestAddress(base + guest_frame_number as usize * PAGE_SIZE),
                memory_dump,
                num_guest_frames * PAGE_SIZE,
                false
            )?;
            start = test;
            test = start + 1;
        }
        Ok(())
    }

    /// Generate a memory dump that contains only dirty pages to the directory given by the input
    /// parameter. Additionally return the dirty guest frame number list
    /// Note `page_numbers` used for memory access pattern analysis only not for restoration
    pub fn snapshot_memory(&self, mut dir: PathBuf) -> Result<BTreeSet<usize>>
    {
        let (gfns_to_pfns, gfns_dirty_vec) = self.get_pagemap(false);

        // println!("Ta accessed pages");
        // for (x, y) in &gfns_to_pfns {
        //     println!("{x}: \"{y}\"");
        // }

        // println!("Ta written pages");
        // let temp_iter = gfns_dirty_vec.iter();
        // for val in temp_iter {
        //     println!("page: {}", val);
        // }

        // resident (dirty + read-only)
        let gfns_accessed_vec: Vec<_> = gfns_to_pfns.keys().cloned().collect();
        let gfns_accessed_set: BTreeSet<_> = gfns_accessed_vec.iter().cloned().collect();
        // dirty
        let gfns_dirty_set: BTreeSet<_> = gfns_dirty_vec.iter().cloned().collect();
        // read-only
        let gfns_ro_vec: Vec<_> = gfns_accessed_set.difference(&gfns_dirty_set).cloned().collect();
        println!("VMM: {} pages accessed, {} pages only read, {} pages written",
            gfns_accessed_vec.len(),
            gfns_ro_vec.len(),
            gfns_dirty_vec.len());

        // open files
        dir.push("memory_dump");
        let mut memory_dump = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(dir.as_path())
            .map_err(|e| Error::IoError(e))?;
        dir.set_file_name("memory_dump_sparse");
        let mut memory_dump_sparse = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(dir.as_path())
            .map_err(|e| Error::IoError(e))?;
        dir.set_file_name("page_numbers");
        let mut gfn_recorder = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(dir.as_path())
            .map_err(|e| Error::IoError(e))?;

        // write page_numbers
        // first, pages that're written
        // second, pages that're only read
        // third, pages that're acecssed
        write!(&mut gfn_recorder, "number of pages written: {}\n", gfns_dirty_vec.len())
            .map_err(|e| Error::IoError(e))?;
        for i in 0..gfns_dirty_vec.len() {
            write!(&mut gfn_recorder, "{}\n", gfns_dirty_vec[i])
                .map_err(|e| Error::IoError(e))?;
        }
        write!(&mut gfn_recorder, "number of pages only read: {}\n", gfns_ro_vec.len())
            .map_err(|e| Error::IoError(e))?;
        for i in 0..gfns_ro_vec.len() {
            write!(&mut gfn_recorder, "{}\n", gfns_ro_vec[i])
                .map_err(|e| Error::IoError(e))?;
        }
        write!(&mut gfn_recorder, "number of pages accessed: {}\n", gfns_accessed_vec.len())
            .map_err(|e| Error::IoError(e))?;
        for i in 0..gfns_accessed_vec.len() {
            write!(&mut gfn_recorder, "{}\n", gfns_accessed_vec[i])
                .map_err(|e| Error::IoError(e))?;
        }

        self.generate_memory_dump(&gfns_dirty_vec, &mut memory_dump)?;

        println!("PERASA GENERATE_MEMORY_DUMP");

        let mut base = 2147483648usize;
        let mut temp = 134217728usize;
        // write memory_dump_sparse
        self.write_from_memory(
            GuestAddress(base),
            &mut memory_dump_sparse,
            temp,
            // self.end_addr().offset(),
            true)?;
        println!("punching holes...");
        // a hole at the beginning
        if gfns_dirty_vec[0] > 0 {
            let offset = 0;
            let len = gfns_dirty_vec[0] as usize * PAGE_SIZE;
            unsafe {
                GuestMemory::punch_holes(memory_dump_sparse.as_raw_fd(), offset as libc::off_t, len as libc::off_t)
                    .or_else(|e| Err(Error::IoError(e)))?;
            }
        }
        let mut test = 0;
        while test < gfns_dirty_vec.len() {
            // find the end of current dump region
            test += 1;
            while test < gfns_dirty_vec.len() && gfns_dirty_vec[test] - gfns_dirty_vec[test-1] == 1 {
                test += 1;
            }
            let offset = (gfns_dirty_vec[test-1] as usize + 1) * PAGE_SIZE;
            let len = if test < gfns_dirty_vec.len() {
                (gfns_dirty_vec[test] - gfns_dirty_vec[test-1] - 1) as usize * PAGE_SIZE
            } else {
                self.end_addr().offset() - (gfns_dirty_vec[test-1] as usize + 1) * PAGE_SIZE
            };
            if len == 0 {
                break;
            }
            unsafe {
                GuestMemory::punch_holes(memory_dump_sparse.as_raw_fd(), offset as libc::off_t, len as libc::off_t)
                    .or_else(|e| Err(Error::IoError(e)))?;
            }
        }
        Ok(gfns_dirty_set)
    }

    /// covert a ordered set of page numbers into a region list
    pub fn convert_to_regionlist(dirty_pages_set: BTreeSet<usize>) -> RegionList {
        // convert page list to region list
        let dirty_pages_vec: Vec<_> = dirty_pages_set.iter().cloned().collect();

        let mut start = 0;
        let mut test = 1;
        let mut dirty_regions = Vec::new();
        while start < dirty_pages_vec.len() {
            while test < dirty_pages_vec.len() && dirty_pages_vec[test]-dirty_pages_vec[test-1] == 1 {
                test += 1;
            }
            dirty_regions.push((dirty_pages_vec[start], test-start));
            start = test;
            test = start + 1;
        }
        dirty_regions
    }

    /// generate WS_dump and update last layer memory snapshot metadata
    pub fn dump_working_set(&self, mut dir: PathBuf, base_layer: &mut MemorySnapshotLayer) -> Result<()>
    {
        let (gfns_to_pfns, _) = self.get_pagemap(false);
        let accessed_vec: Vec<_> = gfns_to_pfns.keys().cloned().collect();
        let accessed_set: BTreeSet<_> = accessed_vec.iter().cloned().collect();

        let mut base_set = BTreeSet::new();
        for (start_gfn, count) in &base_layer.dirty_regions {
            let mut gfn = *start_gfn;
            let mut cnt = *count;
            while cnt > 0 {
                base_set.insert(gfn);
                gfn += 1;
                cnt -= 1;
            }
        }

        let ws_page_set: BTreeSet<_> = base_set.intersection(&accessed_set).cloned().collect();
        let non_ws_page_set: BTreeSet<_> = base_set.difference(&accessed_set).cloned().collect();
        base_layer.ws = GuestMemory::convert_to_regionlist(ws_page_set);
        base_layer.non_ws = GuestMemory::convert_to_regionlist(non_ws_page_set);

        dir.push("WS_dump");
        let mut ws_dump = OpenOptions::new().write(true).truncate(true).create(true).open(dir.as_path())
            .map_err(|e| Error::IoError(e))?;
        dir.set_file_name("memory_dump_sparse");
        let mut memory_dump = OpenOptions::new().read(true).open(dir.as_path()).map_err(|e| Error::IoError(e))?;
        let mut bufs = Vec::new();
        for (ref gfn, ref count) in &base_layer.ws {
            memory_dump.seek(SeekFrom::Start((gfn*PAGE_SIZE) as u64)).map_err(|e| Error::IoError(e))?;
            bufs.push(vec![0u8; count * PAGE_SIZE]);
            memory_dump.read_exact(bufs.last_mut().unwrap()).map_err(|e| Error::IoError(e))?;
        }
        let iovec: Vec<_> = bufs.iter().map(|buf| IoSlice::new(&buf)).collect();
        ws_dump.write_vectored(&iovec).map(|_| ()).map_err(|e| Error::IoError(e))
    }

    ///// Write all initialized guest memory pages out to the writer and the guest physical page
    ///// numbers of these pages to the `page_number_file`.
    ///// Here being initialized means being present in physical RAM.
    ///// The writer should be backed by a file in `/dev/shm` of the same size
    ///// as the guest memory.
    //pub fn dump_initialized_memory_to_shm<F>(&self, writer: &mut F, page_number_file: &mut File) -> Result<()>
    //where
    //    F: Write + Seek,
    //{
    //    let (gfns_to_pfns, _) = self.get_pagemap(false);
    //    for (gfn, _) in gfns_to_pfns.iter() {
    //        write!(page_number_file, "{}\n", gfn).expect("failed to write to page_numbers");
    //        writer.seek(SeekFrom::Start(gfn * PAGE_SIZE as u64)).expect("seek failed");
    //        // write page content
    //        self.write_from_memory(
    //            GuestAddress(*gfn as usize * PAGE_SIZE),
    //            writer,
    //            PAGE_SIZE as usize
    //        )?;
    //    }
    //    Ok(())
    //}

    ///// Write all initialized guest memory pages to the provided writer.
    ///// Here being initialized means being present in physical RAM.
    ///// The byte stream being written out consists of a sequence of
    ///// (start page's gpfn, region size, region content)
    //pub fn dump_initialized_memory<F>(&self, writer: &mut F) -> Result<()>
    //where
    //    F: Write,
    //{
    //    let (gfns_to_pfns, _) = self.get_pagemap(false);
    //    let gfns = gfns_to_pfns.keys().cloned().collect::<Vec<u64>>();
    //    let mut start = 0usize;
    //    let mut test = 1usize;
    //    let mut ri = 0usize; // index into self.regions
    //    let mut gfn_recorder = std::fs::OpenOptions::new()
    //        .write(true)
    //        .truncate(true)
    //        .create(true)
    //        .open("page_numbers")
    //        .expect("failed to open page_numbers");
    //    for i in 0..gfns.len() {
    //        write!(&mut gfn_recorder, "{:x}\n", gfns[i]).expect("failed to write to page_numbers");
    //    }
    //    loop {
    //        // find the end of current dump region
    //        while test < gfns.len() && gfns[test] - gfns[test-1] == 1
    //            && gfns[test] as usize * PAGE_SIZE < region_end(&self.regions[ri]).offset() {
    //            test += 1;
    //        }
    //        writer.write_all(&gfns[start].to_le_bytes()).map_err(|e| Error::IoError(e))?;
    //        writer.write_all(&(test-start).to_le_bytes()).map_err(|e| Error::IoError(e))?;
    //        // write page content
    //        self.write_from_memory(
    //            GuestAddress(gfns[start] as usize * PAGE_SIZE),
    //            writer,
    //            (test - start) * PAGE_SIZE)?;
    //        // start a new dump region
    //        start = test;
    //        test = start + 1;
    //        if start >= gfns.len() {
    //            break;
    //        }
    //        while gfns[start] as usize * PAGE_SIZE >= region_end(&self.regions[ri]).offset() {
    //            ri += 1;
    //        }
    //    }
    //    Ok(())
    //}

    ///// read from the provided memory dump file into guest memory
    //pub fn load_initialized_memory<F>(&self, reader: &mut F) -> Result<()>
    //where
    //    F: Read,
    //{
    //    let buf = &mut [0u8; 8usize];
    //    // the loop should break out upon UnexpectedEof when the end is reached
    //    while reader.read_exact(buf).is_ok() {
    //        let gpfn = usize::from_le_bytes(*buf);
    //        reader.read_exact(buf).map_err(|e| Error::IoError(e))?;
    //        let cnt = usize::from_le_bytes(*buf);
    //        self.read_to_memory(GuestAddress(gpfn * PAGE_SIZE), reader, cnt * PAGE_SIZE)?;
    //    }
    //    Ok(())
    //}

    /// Perform the specified action on each region's addresses.
    pub fn with_regions<F, E>(&self, cb: F) -> result::Result<(), E>
    where
        F: Fn(usize, GuestAddress, usize, usize) -> result::Result<(), E>,
    {
        for (index, region) in self.regions.iter().enumerate() {
            cb(
                index,
                region.guest_base,
                region.mapping.size(),
                region.mapping.as_ptr() as usize,
            )?;
        }
        Ok(())
    }

    /// Perform the specified action on each region's addresses mutably.
    pub fn with_regions_mut<F, E>(&self, mut cb: F) -> result::Result<(), E>
    where
        F: FnMut(usize, GuestAddress, usize, usize) -> result::Result<(), E>,
    {
        for (index, region) in self.regions.iter().enumerate() {
            cb(
                index,
                region.guest_base,
                region.mapping.size(),
                region.mapping.as_ptr() as usize,
            )?;
        }
        Ok(())
    }

    /// Writes a slice to guest memory at the specified guest address.
    /// Returns the number of bytes written. The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at guestaddress 0x200.
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let res = gm.write_slice_at_addr(&[1,2,3,4,5], GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(5, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn write_slice_at_addr(&self, buf: &[u8], guest_addr: GuestAddress) -> Result<usize> {
        self.do_in_region_partial(guest_addr, move |mapping, offset| {
            mapping
                .write_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads to a slice from guest memory at the specified guest address.
    /// Returns the number of bytes read.  The number of bytes read can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x200.
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let buf = &mut [0u8; 16];
    ///     let res = gm.read_slice_at_addr(buf, GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(16, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn read_slice_at_addr(
        &self,
        buf: &mut [u8],
        guest_addr: GuestAddress,
    ) -> Result<usize> {
        self.do_in_region_partial(guest_addr, move |mapping, offset| {
            mapping
                .read_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads an object from guest memory at the given guest address.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// Caller needs to guarantee that the object does not cross MemoryRegion
    /// boundary, otherwise it fails.
    ///
    /// # Examples
    /// * Read a u64 from two areas of guest memory backed by separate mappings.
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_read_u64() -> Result<u64, ()> {
    /// #     let start_addr1 = GuestAddress(0x0);
    /// #     let start_addr2 = GuestAddress(0x400);
    /// #     let mut gm = GuestMemory::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)])
    /// #         .map_err(|_| ())?;
    ///       let num1: u64 = gm.read_obj_from_addr(GuestAddress(32)).map_err(|_| ())?;
    ///       let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x400+32)).map_err(|_| ())?;
    /// #     Ok(num1 + num2)
    /// # }
    /// ```
    pub fn read_obj_from_addr<T: DataInit>(&self, guest_addr: GuestAddress) -> Result<T> {
        self.do_in_region(guest_addr, mem::size_of::<T>(), |mapping, offset| {
            mapping
                .read_obj(offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        }, false)
    }

    /// Writes an object to the memory region at the specified guest address.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// Caller needs to guarantee that the object does not cross MemoryRegion
    /// boundary, otherwise it fails.
    ///
    /// # Examples
    /// * Write a u64 at guest address 0x1100.
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     gm.write_obj_at_addr(55u64, GuestAddress(0x1100))
    ///         .map_err(|_| ())
    /// # }
    /// ```
    pub fn write_obj_at_addr<T: DataInit>(&self, val: T, guest_addr: GuestAddress) -> Result<()> {
        self.do_in_region(guest_addr, mem::size_of::<T>(), move |mapping, offset| {
            mapping
                .write_obj(val, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        }, false)
    }

    /// Reads data from a readable object like a File and writes it to guest memory.
    ///
    /// # Arguments
    /// * `guest_addr` - Begin writing memory at this offset.
    /// * `src` - Read from `src` to memory.
    /// * `count` - Read `count` bytes from `src` to memory.
    ///
    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let start_addr = GuestAddress(0x1000);
    /// #     let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       let addr = GuestAddress(0x1010);
    ///       gm.read_to_memory(addr, &mut file, 128).map_err(|_| ())?;
    ///       let read_addr = addr.checked_add(8).ok_or(())?;
    ///       let rand_val: u32 = gm.read_obj_from_addr(read_addr).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory<F>(
        &self,
        guest_addr: GuestAddress,
        src: &mut F,
        count: usize,
    ) -> Result<()>
    where
        F: Read,
    {
        self.do_in_region(guest_addr, count, move |mapping, offset| {
            mapping
                .read_to_memory(offset, src, count)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        }, false)
    }

    /// Writes data from memory to a writable object.
    ///
    /// # Arguments
    /// * `guest_addr` - Begin reading memory from this offset.
    /// * `dst` - Write from memory to `dst`.
    /// * `count` - Read `count` bytes from memory to `src`.
    ///
    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory, MemoryMapping};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let start_addr = GuestAddress(0x1000);
    /// #     let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       let addr = GuestAddress(0x1010);
    ///       gm.write_from_memory(addr, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    pub fn write_from_memory<F>(
        &self,
        guest_addr: GuestAddress,
        dst: &mut F,
        count: usize,
        flag: bool,
    ) -> Result<()>
    where
        F: Write,
    {
        // println!("BIKA WRITE_FROM_MEMORY");

        // println!("to guest_addr: {:?}", guest_addr);
        // println!("to count: {:?}", count);

        // println!("AYTA APO WRITE_FROM_MEMORY");

        self.do_in_region(guest_addr, count, move |mapping, offset| {
            mapping
                .write_from_memory(offset, dst, count, flag)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        }, true)
    }

    ///// Converts a GuestAddress into a pointer in the address space of this
    ///// process. This should only be necessary for giving addresses to the
    ///// kernel, as with vhost ioctls. Normal reads/writes to guest memory should
    ///// be done through `write_from_memory`, `read_obj_from_addr`, etc.
    /////
    ///// # Arguments
    ///// * `guest_addr` - Guest address to convert.
    /////
    ///// # Examples
    /////
    ///// ```
    ///// # use memory_model::{GuestAddress, GuestMemory};
    ///// # fn test_host_addr() -> Result<(), ()> {
    /////     let start_addr = GuestAddress(0x1000);
    /////     let mut gm = GuestMemory::new(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    /////     let addr = gm.get_host_address(GuestAddress(0x1200)).unwrap();
    /////     println!("Host address is {:p}", addr);
    /////     Ok(())
    ///// # }
    ///// ```
    pub fn get_host_address(&self, guest_addr: GuestAddress) -> Result<*const u8> {
       self.do_in_region(guest_addr, 1, |mapping, offset| {
           // This is safe; `do_in_region` already checks that offset is in
           // bounds.
           Ok(unsafe { mapping.as_ptr().add(offset) } as *const u8)
       }, false)
    }

    /// Only used by vhost-vsock snapshotting
    pub fn get_guest_address(&self, host_addr: u64) -> Result<GuestAddress> {
        let mut guest_addr: Option<GuestAddress> = None;
        for region in self.regions.iter() {
            let host_base = region.mapping.as_ptr() as u64;
            if host_addr >= host_base && host_addr < host_base + region.size() as u64 {
                let offset = host_addr - host_base;
                guest_addr = Some(region.guest_base.unchecked_add(offset as usize));
                break;
            }
        }
        if let Some(guest_addr) = guest_addr {
            Ok(guest_addr)
        } else {
            Err(Error::InvalidHostAddress(host_addr))
        }
    }

    /// Applies two functions, specified as callbacks, on the inner memory regions.
    ///
    /// # Arguments
    /// * `init` - Starting value of the accumulator for the `foldf` function.
    /// * `mapf` - "Map" function, applied to all the inner memory regions. It returns an array of
    ///            the same size as the memory regions array, containing the function's results
    ///            for each region.
    /// * `foldf` - "Fold" function, applied to the array returned by `mapf`. It acts as an
    ///             operator, applying itself to the `init` value and to each subsequent elemnent
    ///             in the array returned by `mapf`.
    ///
    /// # Examples
    ///
    /// * Compute the total size of all memory mappings in KB by iterating over the memory regions
    ///   and dividing their sizes to 1024, then summing up the values in an accumulator.
    ///
    /// ```
    /// # use memory_model::{GuestAddress, GuestMemory};
    /// # fn test_map_fold() -> Result<(), ()> {
    ///     let start_addr1 = GuestAddress(0x0);
    ///     let start_addr2 = GuestAddress(0x400);
    ///     let mem = GuestMemory::new(&vec![(start_addr1, 1024), (start_addr2, 2048)]).unwrap();
    ///     let total_size = mem.map_and_fold(
    ///         0,
    ///         |(_, region)| region.size() / 1024,
    ///         |acc, size| acc + size
    ///     );
    ///     println!("Total memory size = {} KB", total_size);
    ///     Ok(())
    /// # }
    /// ```
    pub fn map_and_fold<F, G, T>(&self, init: T, mapf: F, foldf: G) -> T
    where
        F: FnMut((usize, &MemoryRegion)) -> T,
        G: Fn(T, T) -> T,
    {
        self.regions.iter().enumerate().map(mapf).fold(init, foldf)
    }

    /// Read the whole object from a single MemoryRegion
    pub fn do_in_region<F, T>(&self, guest_addr: GuestAddress, size: usize, cb: F, flag: bool) -> Result<T>
    where
        F: FnOnce(&MemoryMapping, usize) -> Result<T>,
    {
        let mut base = 2147483648usize;
        for region in self.regions.iter() {
            // if flag {
                // println!("BIKA DO_IN_REGION");
                // println!("me guest_addr {:?}", guest_addr);
                // println!("me base {:?}", region.guest_base);
                // println!("me end {:?}", region_end(region));
            // }
            if guest_addr >= region.guest_base && guest_addr < region_end(region) {
                // if flag {
                    // println!("BIKA 1h IF");
                // }
                let offset = guest_addr.offset_from(region.guest_base);
                // let offset = base + temp;
                // if flag {
                    // println!("TO PROVIDED SIZE: {:?}", size);
                    // println!("TO REGION.MAPPING.SIZE(): {:?}", region.mapping.size());   
                    // println!("TO OFFSET: {:?}", offset);
                // }
                if size <= (region.mapping.size() - offset) {
                    // if flag {
                        // println!("BIKA 2h IF");
                        // println!("me region.mapping {:?}", region.mapping);
                    // }
                    return cb(&region.mapping, offset);
                }
                break;
            }
        }
        Err(Error::InvalidGuestAddressRange(guest_addr, size))
    }

    /// Read the whole or partial content from a single MemoryRegion
    fn do_in_region_partial<F>(&self, guest_addr: GuestAddress, cb: F) -> Result<usize>
    where
        F: FnOnce(&MemoryMapping, usize) -> Result<usize>,
    {
        for region in self.regions.iter() {
            if guest_addr >= region.guest_base && guest_addr < region_end(region) {
                return cb(&region.mapping, guest_addr.offset_from(region.guest_base));
            }
        }
        Err(Error::InvalidGuestAddress(guest_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::mem;
    use std::path::Path;

    #[test]
    fn test_regions() {
        // No regions provided should return error.
        assert_eq!(
            // format!("{:?}", GuestMemory::new(&[]).err().unwrap()),
            format!("{:?}", Error::NoMemoryRegions)
        );

        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x800);
        // let guest_mem = GuestMemory::new(&[(start_addr1, 0x400), (start_addr2, 0x400)]).unwrap();
        assert_eq!(guest_mem.num_regions(), 2);
        assert!(guest_mem.address_in_range(GuestAddress(0x200)));
        assert!(!guest_mem.address_in_range(GuestAddress(0x600)));
        assert!(guest_mem.address_in_range(GuestAddress(0xa00)));
        let end_addr = GuestAddress(0xc00);
        assert!(!guest_mem.address_in_range(end_addr));
        assert_eq!(guest_mem.end_addr(), end_addr);
        assert!(guest_mem.checked_offset(start_addr1, 0x900).is_some());
        assert!(guest_mem.checked_offset(start_addr1, 0x700).is_none());
        assert!(guest_mem.checked_offset(start_addr2, 0xc00).is_none());
    }

    #[test]
    fn overlap_memory() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        // let res = GuestMemory::new(&[(start_addr1, 0x2000), (start_addr2, 0x2000)]);
        assert_eq!(
            format!("{:?}", res.err().unwrap()),
            format!("{:?}", Error::MemoryRegionOverlap)
        );
    }

    #[test]
    fn test_read_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let bad_addr = GuestAddress(0x2001);
        let bad_addr2 = GuestAddress(0x1ffc);

        // let gm = GuestMemory::new(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55_aa55_aa55_aa55;
        let val2: u64 = 0x55aa_55aa_55aa_55aa;
        assert_eq!(
            format!("{:?}", gm.write_obj_at_addr(val1, bad_addr).err().unwrap()),
            format!(
                "InvalidGuestAddressRange({:?}, {:?})",
                bad_addr,
                std::mem::size_of::<u64>()
            )
        );
        assert_eq!(
            format!("{:?}", gm.write_obj_at_addr(val1, bad_addr2).err().unwrap()),
            format!(
                "InvalidGuestAddressRange({:?}, {:?})",
                bad_addr2,
                std::mem::size_of::<u64>()
            )
        );

        gm.write_obj_at_addr(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj_at_addr(val2, GuestAddress(0x1000 + 32))
            .unwrap();
        let num1: u64 = gm.read_obj_from_addr(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x1000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn write_and_read_slice() {
        let mut start_addr = GuestAddress(0x1000);
        // let gm = GuestMemory::new(&[(start_addr, 0x400)]).unwrap();
        let sample_buf = &[1, 2, 3, 4, 5];

        assert_eq!(gm.write_slice_at_addr(sample_buf, start_addr).unwrap(), 5);

        let buf = &mut [0u8; 5];
        assert_eq!(gm.read_slice_at_addr(buf, start_addr).unwrap(), 5);
        assert_eq!(buf, sample_buf);

        start_addr = GuestAddress(0x13ff);
        assert_eq!(gm.write_slice_at_addr(sample_buf, start_addr).unwrap(), 1);
        assert_eq!(gm.read_slice_at_addr(buf, start_addr).unwrap(), 1);
        assert_eq!(buf[0], sample_buf[0]);
    }

    #[test]
    fn read_to_and_write_from_mem() {
        // let gm = GuestMemory::new(&[(GuestAddress(0x1000), 0x400)]).unwrap();
        let addr = GuestAddress(0x1010);
        gm.write_obj_at_addr(!0u32, addr).unwrap();
        gm.read_to_memory(
            addr,
            &mut File::open(Path::new("/dev/zero")).unwrap(),
            mem::size_of::<u32>(),
        )
        .unwrap();
        let value: u32 = gm.read_obj_from_addr(addr).unwrap();
        assert_eq!(value, 0);

        let mut sink = Vec::new();
        gm.write_from_memory(addr, &mut sink, mem::size_of::<u32>())
            .unwrap();
        assert_eq!(sink, vec![0; mem::size_of::<u32>()]);
    }

    #[test]
    fn create_vec_with_regions() {
        let region_size = 0x400;
        let regions = vec![
            (GuestAddress(0x0), region_size),
            (GuestAddress(0x1000), region_size),
        ];
        let mut iterated_regions = Vec::new();
        // let gm = GuestMemory::new(&regions).unwrap();

        let res: Result<()> = gm.with_regions(|_, _, size, _| {
            assert_eq!(size, region_size);
            Ok(())
        });
        assert!(res.is_ok());

        let res: Result<()> = gm.with_regions_mut(|_, guest_addr, size, _| {
            iterated_regions.push((guest_addr, size));
            Ok(())
        });
        assert!(res.is_ok());
        assert_eq!(regions, iterated_regions);
        assert_eq!(gm.clone().regions[0].guest_base, regions[0].0);
        assert_eq!(gm.clone().regions[1].guest_base, regions[1].0);
    }

    // Get the base address of the mapping for a GuestAddress.
    fn get_mapping(mem: &GuestMemory, addr: GuestAddress) -> Result<*const u8> {
        mem.do_in_region(addr, 1, |mapping, _| Ok(mapping.as_ptr() as *const u8), false)
    }

    #[test]
    fn guest_to_host() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x100);
        // let mem = GuestMemory::new(&[(start_addr1, 0x100), (start_addr2, 0x400)]).unwrap();

        // Verify the host addresses match what we expect from the mappings.
        let addr1_base = get_mapping(&mem, start_addr1).unwrap();
        let addr2_base = get_mapping(&mem, start_addr2).unwrap();
        let host_addr1 = mem.get_host_address(start_addr1).unwrap();
        let host_addr2 = mem.get_host_address(start_addr2).unwrap();
        assert_eq!(host_addr1, addr1_base);
        assert_eq!(host_addr2, addr2_base);

        // Check that a bad address returns an error.
        let bad_addr = GuestAddress(0x12_3456);
        assert!(mem.get_host_address(bad_addr).is_err());
    }

    #[test]
    fn test_map_fold() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x400);
        // let mem = GuestMemory::new(&[(start_addr1, 1024), (start_addr2, 2048)]).unwrap();

        assert_eq!(
            mem.map_and_fold(
                0,
                |(_, region)| region.size() / 1024,
                |acc, size| acc + size
            ),
            3
        );
    }
}
