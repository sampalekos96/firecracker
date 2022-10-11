// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// extern crate vmm;

pub(crate) mod cache_info;
pub mod fdt;

pub mod layout;

pub mod gic;

pub mod regs;

use std::cmp::min;
// use std::io;
use std::fmt::Debug;
use std::collections::HashMap;
use std::convert::TryInto;

use memory_model::{GuestAddress, GuestMemory};

pub use self::fdt::DeviceInfoForFDT;

use self::gic::GICDevice;

// use crate::vmm;
// use crate::vstate::Vcpu;    
// use vstate::Vcpu;
// use regs;

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    let dram_size = min(size, layout::DRAM_MEM_END);
    vec![(GuestAddress(layout::DRAM_MEM_START.try_into().unwrap()), dram_size)]
}

/// Configures the system and should be called once per vm before starting vcpu threads.
/// For aarch64, we only setup the FDT.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_cstring` - The kernel commandline.
/// * `vcpu_mpidr` - Array of MPIDR register values per vcpu.
/// * `device_info` - A hashmap containing the attached devices for building FDT device nodes.
/// * `gic_device` - The GIC device.
/// * `initrd` - Information about an optional initrd.


pub fn configure_system<T: DeviceInfoForFDT + Clone + Debug, S: std::hash::BuildHasher>(
    guest_mem: &GuestMemory,
    vcpu_mpidr: Vec<u64>,
    device_info: &HashMap<String, T, S>,
    gic_device: &dyn GICDevice,
) -> super::Result<()> {

    fdt::create_fdt(
        guest_mem,
        vcpu_mpidr,
        device_info,
        gic_device,
    ).unwrap();

    Ok(())
}



fn get_fdt_addr(mem: &GuestMemory) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(addr) = mem.end_addr().checked_sub((layout::FDT_MAX_SIZE as u64 - 1).try_into().unwrap()) {
        if mem.address_in_range(addr) {
            return addr.offset().try_into().unwrap();
        }
    }

    layout::DRAM_MEM_START.try_into().unwrap()
}



// fn get_fdt_addr(mem: &GuestMemory) -> u64 {
//     // If the memory allocated is smaller than the size allocated for the FDT,
//     // we return the start of the DRAM so that
//     // we allow the code to try and load the FDT.

//     if let Some(addr) = mem.last_addr().checked_sub(layout::FDT_MAX_SIZE as u64 - 1) {
//         if mem.address_in_range(addr) {
//             return addr.raw_value();
//         }
//     }

//     layout::DRAM_MEM_START
// }



/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn get_reserved_mem_addr() -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_lt_1024gb() {
        let regions = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_1024gb() {
        let regions = arch_memory_regions(1usize << 41);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(super::layout::DRAM_MEM_END, regions[0].1);
    }
}
