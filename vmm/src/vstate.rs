// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use fc_util::now_monotime_us;

use std::io;
use std::io::{Seek, SeekFrom, Write, Read, BufReader, BufWriter};
use std::result;
use std::sync::{Arc, Barrier};
use std::collections::{BTreeSet, BTreeMap};
use std::path::PathBuf;
use std::fs::File;

use super::{KvmContext, TimestampUs};
use arch;
#[cfg(target_arch = "x86_64")]
use cpuid::{c3, filter_cpuid, t2};
use default_syscalls;
use kvm::*;
use kvm_bindings::{ kvm_regs, kvm_sregs, kvm_msrs, kvm_msr_entry, kvm_irqchip, kvm_lapic_state,
    kvm_mp_state, kvm_vcpu_events, kvm_xsave, kvm_xcrs,
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    kvm_pic_state, kvm_ioapic_state__bindgen_ty_1__bindgen_ty_1,
    kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use logger::{LogOption, Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory, GuestMemoryError};
use sys_util::{EventFd};
#[cfg(target_arch = "x86_64")]
use vmm_config::machine_config::CpuFeaturesTemplate;
use vmm_config::machine_config::VmConfig;

const KVM_MEM_LOG_DIRTY_PAGES: u32 = 0x1;

const MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE: u16 = 0x03f0;
const MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE: u8 = 123;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    #[cfg(target_arch = "x86_64")]
    /// A call to cpuid instruction failed.
    CpuId(cpuid::Error),
    /// Invalid guest memory configuration.
    GuestMemory(GuestMemoryError),
    /// Hyperthreading flag is not initialized.
    HTNotInitialized,
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot open the VM file descriptor.
    VmFd(io::Error),
    /// Cannot open the VCPU file descriptor.
    VcpuFd(io::Error),
    /// Cannot configure the microvm.
    VmSetup(io::Error),
    /// Cannot run the VCPUs.
    VcpuRun(io::Error),
    /// The call to KVM_SET_CPUID2 failed.
    SetSupportedCpusFailed(io::Error),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(io::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),
    /// Cannot configure the IRQ.
    Irq(io::Error),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(std::io::Error),
    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// Error getting the dirty log
    GetDirtyLog(io::Error),
    /// Error restoring all vcpu states
    LoadSnapshot(io::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl ::std::convert::From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::SetUserMemoryRegion(e)
    }
}

#[derive(Serialize, Deserialize)]
struct IoapicState {
   pub base_address: u64,
   pub ioregsel: u32,
   pub id: u32,
   pub irr: u32,
   pub pad: u32,
   pub redirtbl: [kvm_ioapic_state__bindgen_ty_1__bindgen_ty_1; 24usize],
}
    
fn get_ioapic_state(vmfd: &VmFd) -> result::Result<IoapicState, io::Error> {
    let mut irqchip = kvm_irqchip {
        chip_id: KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    vmfd.get_irqchip(&mut irqchip)?;
    let kioapic = unsafe { irqchip.chip.ioapic };
    let mut ioapic = IoapicState {
        base_address: kioapic.base_address,
        ioregsel: kioapic.ioregsel,
        id: kioapic.id,
        irr: kioapic.irr,
        pad: kioapic.pad,
        redirtbl: [kvm_ioapic_state__bindgen_ty_1__bindgen_ty_1::default(); 24usize],
    };
    unsafe {
        for i in 0..24 {
            ioapic.redirtbl[i] = kioapic.redirtbl[i].fields;
        }
    };
    Ok(ioapic)
}

fn get_pic_state(vmfd: &VmFd, master: bool) -> result::Result<kvm_pic_state, io::Error> {
    let mut irqchip = kvm_irqchip {
        chip_id: if master { KVM_IRQCHIP_PIC_MASTER } else { KVM_IRQCHIP_PIC_SLAVE },
        ..Default::default()
    };
    vmfd.get_irqchip(&mut irqchip)?;
    unsafe { Ok(irqchip.chip.pic) }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    fd: VmFd,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
    guest_mem: Option<GuestMemory>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm.create_vm().map_err(Error::VmFd)?;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let cpuid = kvm
            .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;
        Ok(Vm {
            fd: vm_fd,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            supported_cpuid: cpuid,
            guest_mem: None,
        })
    }

    /// Returns a clone of the supported `CpuId` for this Vm.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self) -> CpuId {
        self.supported_cpuid.clone()
    }

    /// Initializes the guest memory.
    pub fn memory_init(&mut self, guest_mem: GuestMemory, kvm_context: &KvmContext) -> Result<()> {
        if guest_mem.num_regions() > kvm_context.max_memslots() {
            return Err(Error::NotEnoughMemorySlots);
        }
        guest_mem.with_regions(|index, guest_addr, size, host_addr| {
            info!("Guest memory starts at {:x?}", host_addr);

            let flags = if LOGGER.flags() & LogOption::LogDirtyPages as usize > 0 {
                KVM_MEM_LOG_DIRTY_PAGES
            } else {
                0
            };
            let memory_region = kvm_userspace_memory_region {
                slot: index as u32,
                guest_phys_addr: guest_addr.offset() as u64,
                memory_size: size as u64,
                userspace_addr: host_addr as u64,
                flags,
            };
            self.fd.set_user_memory_region(memory_region)
        })?;
        self.guest_mem = Some(guest_mem);

        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(GuestAddress(arch::x86_64::layout::KVM_TSS_ADDRESS).offset())
            .map_err(Error::VmSetup)?;

        Ok(())
    }

    fn setup_irqchip_from_file(&self, dir: &mut PathBuf) -> result::Result<(), io::Error> {
        dir.push("ioapic.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let ioapic: IoapicState = serde_json::from_reader(reader)?;
        let mut irqchip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default() 
        };
        unsafe {
            irqchip.chip.ioapic.base_address = ioapic.base_address;
            irqchip.chip.ioapic.ioregsel = ioapic.ioregsel;
            irqchip.chip.ioapic.id = ioapic.id;
            irqchip.chip.ioapic.irr = ioapic.irr;
            irqchip.chip.ioapic.pad = ioapic.pad;
            for i in 0..24 {
                irqchip.chip.ioapic.redirtbl[i].fields = ioapic.redirtbl[i];
            }
        }
        self.fd.set_irqchip(&irqchip)?;

        dir.set_file_name("pic_master.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let pic: kvm_pic_state = serde_json::from_reader(reader)?;
        irqchip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        irqchip.chip.pic = pic;
        self.fd.set_irqchip(&irqchip)?;

        dir.set_file_name("pic_slave.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let pic: kvm_pic_state = serde_json::from_reader(reader)?;
        irqchip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        irqchip.chip.pic = pic;
        self.fd.set_irqchip(&irqchip)?;

        dir.pop();
        Ok(())
    }

    /// This function creates the irq chip and adds 3 interrupt events to the IRQ.
    pub fn setup_irqchip(
        &self,
        com_evt_1_3: &EventFd,
        com_evt_2_4: &EventFd,
        kbd_evt: &EventFd,
        load_dir: &mut Option<PathBuf>,
    ) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;
        if let Some(dir) = load_dir {
            let start = now_monotime_us();
            self.setup_irqchip_from_file(dir).expect("Failed to restore irqchip");
            let end = now_monotime_us();
            info!("restoring irqchip took {}us", end-start);
        }

        self.fd.register_irqfd(com_evt_1_3, 4).map_err(Error::Irq)?;
        self.fd.register_irqfd(com_evt_2_4, 3).map_err(Error::Irq)?;
        self.fd.register_irqfd(kbd_evt, 1).map_err(Error::Irq)?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    /// Creates an in-kernel device model for the PIT.
    pub fn create_pit(&self) -> Result<()> {
        let mut pit_config = kvm_pit_config::default();
        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
        self.fd.create_pit2(pit_config).map_err(Error::VmSetup)?;
        Ok(())
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> Option<&GuestMemory> {
        self.guest_mem.as_ref()
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    ///
    pub fn get_fd(&self) -> &VmFd {
        &self.fd
    }
}

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    #[cfg(target_arch = "x86_64")]
    cpuid: CpuId,
    fd: VcpuFd,
    id: u8,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    create_ts: TimestampUs,
    guest_mem: GuestMemory,
    _vmfd: VmFd,
    magic_124_cnt: usize,
    magic_port_cnt: usize,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn new(
        id: u8,
        vm: &Vm,
        io_bus: devices::Bus,
        mmio_bus: devices::Bus,
        create_ts: TimestampUs,
    ) -> Result<Self> {
        let kvm_vcpu = vm.fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Yue: added for Vcpu threads to access memory
        let guest_mem = vm.get_memory().unwrap().clone();

        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            #[cfg(target_arch = "x86_64")]
            cpuid: vm.get_supported_cpuid(),
            fd: kvm_vcpu,
            id,
            io_bus,
            mmio_bus,
            create_ts,
            guest_mem: guest_mem.clone(),
            _vmfd: vm.fd.clone(),
            magic_124_cnt: 0usize,
            magic_port_cnt: 0usize,
        })
    }

    fn write_msrs_to_file(&self, dir: &mut PathBuf) -> result::Result<(), io::Error> {
        let entry_vec = arch::x86_64::regs::create_msr_entries();
        let vec_size_bytes =
            std::mem::size_of::<kvm_msrs>() + (entry_vec.len() * std::mem::size_of::<kvm_msr_entry>());
        let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        #[allow(clippy::cast_ptr_alignment)]
        let msrs: &mut kvm_msrs = unsafe {
            &mut *(vec.as_ptr() as *mut kvm_msrs)
        };

        unsafe {
            let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(entry_vec.len());
            entries.copy_from_slice(&entry_vec);
        }
        msrs.nmsrs = entry_vec.len() as u32;
        self.fd.get_msrs(msrs)?;

        unsafe {
            let entries: Vec<kvm_msr_entry> = msrs.entries.as_slice(entry_vec.len()).to_vec();
            dir.set_file_name("kvm_msrs.json");
            std::fs::write(dir.as_path(), serde_json::to_string(&entries)?)
        }
    }

    fn setup_msrs_from_file(&self, dir: &mut PathBuf) -> result::Result<(), std::io::Error> {
        dir.set_file_name("kvm_msrs.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let entries: Vec<kvm_msr_entry> = serde_json::from_reader(reader)?;

        let vec_size_bytes =
            std::mem::size_of::<kvm_msrs>() + (entries.len() * std::mem::size_of::<kvm_msr_entry>());
        let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        #[allow(clippy::cast_ptr_alignment)]
        let msrs: &mut kvm_msrs = unsafe {
            &mut *(vec.as_ptr() as *mut kvm_msrs)
        };

        unsafe {
            msrs.entries.as_mut_slice(entries.len()).copy_from_slice(&entries);
        }
        msrs.nmsrs = entries.len() as u32;
        self.fd.set_msrs(msrs)
    }

    fn setup_regs_from_file(&self, dir: &mut PathBuf) -> result::Result<(), io::Error> {
        dir.push("kvm_regs.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let regs: kvm_regs = serde_json::from_reader(reader)?;
        self.fd.set_regs(&regs)?;

        dir.set_file_name("kvm_xsave.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let region_vec: Vec<u32> = serde_json::from_reader(reader)?;
        let mut region = [0u32; 1024usize];
        for idx in 0..region.len() {
            region[idx] = region_vec[idx];
        }
        let xsave = kvm_xsave{ region };
        self.fd.set_xsave(&xsave)?;
        
        dir.set_file_name("kvm_xcrs.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let xcrs: kvm_xcrs = serde_json::from_reader(reader)?;
        self.fd.set_xcrs(&xcrs)?;

        dir.set_file_name("kvm_sregs.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let sregs: kvm_sregs = serde_json::from_reader(reader)?;
        self.fd.set_sregs(&sregs)?;

        self.setup_msrs_from_file(dir)?;

        dir.set_file_name("kvm_vcpu_events.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let vcpu_events: kvm_vcpu_events = serde_json::from_reader(reader)?;
        self.fd.set_vcpu_events(&vcpu_events)?;

        dir.set_file_name("kvm_mp_state.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let mp_state: kvm_mp_state = serde_json::from_reader(reader)?;
        self.fd.set_mp_state(&mp_state)?;

        dir.set_file_name("kvm_lapic.json");
        let reader = BufReader::new(File::open(dir.as_path())?);
        let regs_vec: Vec<std::os::raw::c_char> = serde_json::from_reader(reader)?;
        let mut regs = [0 as std::os::raw::c_char; 1024usize];
        for (idx, _) in regs_vec.iter().enumerate() {
            regs[idx] = regs_vec[idx];
        }
        let lapic = kvm_lapic_state { regs };
        self.fd.set_lapic(&lapic)?;

        dir.pop();
        Ok(())
    }

    fn write_regs_to_file(&self, dir: &mut PathBuf) -> result::Result<(), io::Error> {
        let vcpu_events = self.fd.get_vcpu_events()?;
        dir.push("kvm_vcpu_events.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&vcpu_events)?)?;

        let mp_state = self.fd.get_mp_state().unwrap();
        dir.set_file_name("kvm_mp_state.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&mp_state)?)?;

        let regs = self.fd.get_regs().unwrap();
        dir.set_file_name("kvm_regs.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&regs)?)?;

        let xsave = self.fd.get_xsave()?;
        dir.set_file_name("kvm_xsave.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&xsave.region.to_vec())?)?;

        let xcrs = self.fd.get_xcrs()?;
        dir.set_file_name("kvm_xcrs.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&xcrs)?)?;

        let sregs = self.fd.get_sregs()?;
        dir.set_file_name("kvm_sregs.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&sregs)?)?;

        self.write_msrs_to_file(dir)?;

        let lapic = self.fd.get_lapic()?;
        dir.set_file_name("kvm_lapic.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&lapic.regs.to_vec())?)?;

        dir.pop();
        Ok(())
    }

    fn write_irqchip_to_file(&self, dir: &mut PathBuf) -> result::Result<(), io::Error> {
        let ioapic = get_ioapic_state(&self._vmfd)?;
        dir.push("ioapic.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&ioapic)?)?;
        let pic = get_pic_state(&self._vmfd, true)?;
        dir.set_file_name("pic_master.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&pic)?)?;
        let pic = get_pic_state(&self._vmfd, false)?;
        dir.set_file_name("pic_slave.json");
        std::fs::write(dir.as_path(), serde_json::to_string(&pic)?)?;

        dir.pop();
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    /// Configures a x86_64 specific vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - Specifies necessary info used for the CPUID configuration.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn configure(
        &mut self,
        machine_config: &VmConfig,
        kernel_start_addr: GuestAddress,
        vm: &Vm,
        load_dir: &mut Option<PathBuf>,
    ) -> Result<()> {
        // the MachineConfiguration has defaults for ht_enabled and vcpu_count hence it is safe to unwrap
        filter_cpuid(
            self.id,
            machine_config
                .vcpu_count
                .ok_or(Error::VcpuCountNotInitialized)?,
            machine_config.ht_enabled.ok_or(Error::HTNotInitialized)?,
            &mut self.cpuid,
        )
        .map_err(Error::CpuId)?;

        if let Some(template) = machine_config.cpu_template {
            match template {
                CpuFeaturesTemplate::T2 => t2::set_cpuid_entries(self.cpuid.mut_entries_slice()),
                CpuFeaturesTemplate::C3 => c3::set_cpuid_entries(self.cpuid.mut_entries_slice()),
            }
        }

        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(Error::SetSupportedCpusFailed)?;

        if let Some(dir) = load_dir.as_mut() {
            let start = now_monotime_us();
            self.setup_regs_from_file(dir).expect("Failed to restore registers");
            let end = now_monotime_us();
            info!("loading registers took {}us", end-start);
        } else {
            arch::x86_64::regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
            // Safe to unwrap because this method is called after the VM is configured
            let vm_memory = vm
                .get_memory()
                .ok_or(Error::GuestMemory(GuestMemoryError::MemoryNotInitialized))?;
            arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.offset() as u64)
                .map_err(Error::REGSConfiguration)?;
            arch::x86_64::regs::setup_sregs(vm_memory, &self.fd).map_err(Error::SREGSConfiguration)?;
            arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
            arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        }
        Ok(())
    }

    fn _set_himem_readonly(&self) -> Result<()> {
        self.guest_mem.with_himem_regions(|index, guest_addr, size, host_addr| {
            info!("Making guest memory read-only starting at {:x?} with size {}", host_addr, size);
            // delete
            let mut memory_region = kvm_userspace_memory_region {
                slot: index as u32,
                guest_phys_addr: guest_addr.offset() as u64,
                memory_size:0u64,
                userspace_addr: host_addr as u64,
                flags: 0u32,
            };
            self._vmfd.set_user_memory_region(memory_region)?;
            // add back as read only
            memory_region = kvm_userspace_memory_region {
                slot: index as u32,
                guest_phys_addr: guest_addr.offset() as u64,
                memory_size: size as u64,
                userspace_addr: host_addr as u64,
                flags: 0x2u32,
            };
            self._vmfd.set_user_memory_region(memory_region)
        })?;
        Ok(())
    }

    // Get the list of indexes where bits are set in the number's binary representation
    fn _list_set_bits(num_pages: usize, offset: usize, num: u64) -> BTreeSet<usize> {
        let mut mask: u64 = 1;
        let mut res: BTreeSet<usize> = BTreeSet::new();
        for index in 0..64 as usize {
            if num & mask != 0 {
                res.insert(num_pages + offset * 64 + index);
            }
            mask <<= 1;
        }
        return res
    }

    // Get the list of dirty pages since the last call to this function.
    // Because this is used for metrics, it swallows most errors and simply returns empty set
    // if the KVM operation fails.
    fn _get_dirty_page_list(&self) -> BTreeSet<usize> {
        let mut num_pages: usize = 0;
        let dirty_pages = self.guest_mem.map_and_fold(
            BTreeSet::new(),
            |(slot, memory_region)| {
                let bitmap = self
                    ._vmfd
                    .get_dirty_log(slot as u32, memory_region.size());
                match bitmap {
                    Ok(v) => {
                        let union = v
                            .iter()
                            .enumerate()
                            .map(|(offset, page)| Vcpu::_list_set_bits(num_pages, offset, *page))
                            .fold(BTreeSet::new(),
                                  |init, page_list| init.union(&page_list).cloned().collect());
                        num_pages += memory_region.size()/(4<<10);
                        return union
                    },
                    Err(_) => BTreeSet::new(),
                }
            },
            |dirty_pages, region_dirty_pages|
                dirty_pages.union(&region_dirty_pages).cloned().collect(),
        );
        dirty_pages
    }

    /// set all pfns in pagemap to idle
    fn _clear_accessed_log(sorted_pfns: &Vec<u64>) {
        let path = "/sys/kernel/mm/page_idle/bitmap";
        let mut idle_log = std::fs::OpenOptions::new().write(true).open(&path).unwrap();

        let seek_offset = (sorted_pfns[0] / 64) * 8;
        idle_log.seek(SeekFrom::Start(seek_offset)).err();

        let buf_size: usize = 8 * (1 + sorted_pfns[sorted_pfns.len()-1] / 64 - sorted_pfns[0] / 64) as usize;
        let buf = vec![0xff as u8; buf_size];
        idle_log.write_all(&buf).err();
    }

    fn _read_accessed_log(pagemap: &BTreeMap<u64, usize>, sorted_pfns: &Vec<u64>) -> BTreeSet<usize> {
        // open the bitmap file
        let path = "/sys/kernel/mm/page_idle/bitmap";
        let mut idle_log = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        // decide the start index,
        // pfn/64 the index into the array with entry size 8B
        // pfn/64 * 8 number of bytes to skip
        let seek_offset = (sorted_pfns[0] / 64) * 8;
        idle_log.seek(SeekFrom::Start(seek_offset)).err();
        // decide number of bytes to read
        let buf_size: usize = 8 * (1 + sorted_pfns[sorted_pfns.len()-1] / 64 - sorted_pfns[0] / 64) as usize;
        let mut buf = vec![0 as u8; buf_size];
        idle_log.read_exact(&mut buf).err();

        let mut byte_array = [0u8; 8];
        let mut accessed_list = BTreeSet::new();
        let mut buf_i = 0 as usize;
        let mut bitmap_i = sorted_pfns[0] / 64;
        for (pfn, page_i) in pagemap.iter() {
            while pfn / 64 != bitmap_i {
                bitmap_i += 1;
                buf_i += 8;
            }
            for i in 0..8 {
                byte_array[i] = buf[buf_i+i];
            }
            let entry = u64::from_le_bytes(byte_array);
            let bit_pos = pfn % 64;
            if memory_model::get_bit(entry, bit_pos) == 0 {
                accessed_list.insert(*page_i);
            }
        }

        accessed_list
    }

    fn _get_and_clear_accessed_log(&self, pagemap: &BTreeMap<u64, usize>) -> BTreeSet<usize> {
        let sorted_pfns: Vec<u64> = pagemap.keys().cloned().collect();

        let ret = Vcpu::_read_accessed_log(&pagemap, &sorted_pfns);
        if sorted_pfns.len() > 0 {
            Vcpu::_clear_accessed_log(&sorted_pfns);
        }
        ret
    }

    fn _calculate_intersection(sets: &Vec<BTreeSet<usize>>) -> Vec<Vec<BTreeSet<usize>>> {
        let mut unioned_setup: BTreeSet<usize>;
        let mut unioned_app: BTreeSet<usize>;
        let mut unions: Vec<Vec<BTreeSet<usize>>> = Vec::new();
        for i in 0..(sets.len()-1) {
            unioned_setup = BTreeSet::new();
            unioned_app = BTreeSet::new();
            let mut tuple: Vec<BTreeSet<usize>> = Vec::new();
            for j in 0..=i {
                unioned_setup = unioned_setup.union(&sets[j]).cloned().collect();
            }
            for j in (i+1)..sets.len() {
                unioned_app = unioned_app.union(&sets[j]).cloned().collect();
            }
            let unioned = unioned_app.intersection(&unioned_setup).cloned().collect();
            tuple.push(unioned_setup);
            tuple.push(unioned_app);
            tuple.push(unioned);
            unions.push(tuple);
        }
        unions
    }

    fn run_emulation(&mut self, from_snapshot: bool, dump_dir: &mut Option<PathBuf>) -> Result<()> {
        match self.fd.run() {
            Ok(run) => match run {
                VcpuExit::IoIn(addr, data) => {
                    self.io_bus.read(u64::from(addr), data);
                    METRICS.vcpu.exit_io_in.inc();
                    Ok(())
                }
                VcpuExit::IoOut(addr, data) => {
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE && data[0] == 124 {
                        self.magic_124_cnt += 1;
                        info!("magic port value 124 count {}", self.magic_124_cnt);
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE && data[0] == 125 {
                        panic!("mounting app file system failed");
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE && data[0] == 126 {
                        panic!("loading app failed");
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE
                        && data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE
                    {
                        self.magic_port_cnt += 1;
                        if self.magic_port_cnt == 1 {
                            if from_snapshot {
                                info!("App done. Shutting down...");
                                return Err(Error::VcpuUnhandledKvmExit);
                            } else {
                                super::Vmm::log_boot_time(&self.create_ts);
                                info!("Boot done.");
                            }
                        } else if self.magic_port_cnt == 2 {
                            info!("Init done.");
                        } else if self.magic_port_cnt == 3 {
                            info!("Runtime is up.");
                            if let Some(dir) = dump_dir {
                                self.write_regs_to_file(dir)?;
                                self.write_irqchip_to_file(dir)?;
                                dir.push("runtime_mem_dump");
                                let mem_dump = std::fs::OpenOptions::new()
                                    .write(true)
                                    .truncate(true)
                                    .create(true)
                                    .open(dir.as_path())
                                    .unwrap();
                                let writer = &mut BufWriter::new(mem_dump);
                                self.guest_mem.dump_initialized_memory(writer).unwrap();
                                dir.pop();
                                return Err(Error::VcpuUnhandledKvmExit);
                            }
                        } else {
                            info!("App done. Shutting down...");
                            return Err(Error::VcpuUnhandledKvmExit);
                        }
                    }

                    self.io_bus.write(u64::from(addr), data);
                    METRICS.vcpu.exit_io_out.inc();
                    Ok(())
                }
                VcpuExit::MmioRead(addr, data) => {
                    self.mmio_bus.read(addr, data);
                    METRICS.vcpu.exit_mmio_read.inc();
                    Ok(())
                }
                VcpuExit::MmioWrite(addr, data) => {
                    self.mmio_bus.write(addr, data);
                    METRICS.vcpu.exit_mmio_write.inc();
                    Ok(())
                }
                VcpuExit::Hlt => {
                    info!("Received KVM_EXIT_HLT signal");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::Shutdown => {
                    info!("Received KVM_EXIT_SHUTDOWN signal");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                // Documentation specifies that below kvm exits are considered
                // errors.
                VcpuExit::FailEntry(reason) => {
                    METRICS.vcpu.failures.inc();
                    error!("Received KVM_EXIT_FAIL_ENTRY signal with reason: 0x{:x}", reason);
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::InternalError(suberror, _data) => {
                    METRICS.vcpu.failures.inc();
                    error!("Received KVM_EXIT_INTERNAL_ERROR signal with suberror: 0x{:x}", suberror);
                    Err(Error::VcpuUnhandledKvmExit)
                }
                r => {
                    METRICS.vcpu.failures.inc();
                    // TODO: Are we sure we want to finish running a vcpu upon
                    // receiving a vm exit that is not necessarily an error?
                    error!("Unexpected exit reason on vcpu run: {:?}", r);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
            // The unwrap on raw_os_error can only fail if we have a logic
            // error in our code in which case it is better to panic.
            Err(ref e) => {
                match e.raw_os_error().unwrap() {
                    // Why do we check for these if we only return EINVAL?
                    libc::EAGAIN => Ok(()),
                    libc::EFAULT => Ok(()),
                    _ => {
                        METRICS.vcpu.failures.inc();
                        error!("Failure during vcpu run: {}", e);
                        Err(Error::VcpuUnhandledKvmExit)
                    }
                }
            }
        }
    }

    /// Main loop of the vCPU thread.
    ///
    ///
    /// Runs the vCPU in KVM context in a loop. Handles KVM_EXITs then goes back in.
    /// Also registers a signal handler to be able to kick this thread out of KVM_RUN.
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(
        &mut self,
        thread_barrier: Arc<Barrier>,
        seccomp_level: u32,
        vcpu_exit_evt: EventFd,
        mut dump_dir: Option<PathBuf>,
        from_snapshot: bool,
    ) {
        // Load seccomp filters for this vCPU thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        if let Err(e) = default_syscalls::set_seccomp_level(seccomp_level) {
            panic!(
                "Failed to set the requested seccomp filters on vCPU {}: Error: {}",
                self.id, e
            );
        }

        thread_barrier.wait();

        if from_snapshot {
            super::Vmm::log_boot_time(&self.create_ts);
        }
        loop {
            let ret = self.run_emulation(from_snapshot, &mut dump_dir);
            if !ret.is_ok() {
                match ret.err() {
                    _ => {
                        // Nothing we need do for the success case.
                        if let Err(e) = vcpu_exit_evt.write(1) {
                            METRICS.vcpu.failures.inc();
                            error!("Failed signaling vcpu exit event: {}", e);
                        }
                        break;
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::super::devices;
    use super::*;

    use libc::{c_int, c_void, siginfo_t};
    use sys_util::{register_signal_handler, Killable, SignalHandler};

    #[test]
    fn create_vm() {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(gm, &kvm).is_ok());
    }

    #[test]
    fn get_memory() {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(gm, &kvm).is_ok());
        let obj_addr = GuestAddress(0xf0);
        vm.get_memory()
            .unwrap()
            .write_obj_at_addr(67u8, obj_addr)
            .unwrap();
        let read_val: u8 = vm
            .get_memory()
            .unwrap()
            .read_obj_from_addr(obj_addr)
            .unwrap();
        assert_eq!(read_val, 67u8);
    }

    fn setup_vcpu() -> (Vm, Vcpu) {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(gm, &kvm).is_ok());
        let dummy_eventfd_1 = EventFd::new().unwrap();
        let dummy_eventfd_2 = EventFd::new().unwrap();
        let dummy_kbd_eventfd = EventFd::new().unwrap();

        vm.setup_irqchip(&dummy_eventfd_1, &dummy_eventfd_2, &dummy_kbd_eventfd)
            .unwrap();
        vm.create_pit().unwrap();

        let vcpu = Vcpu::new(
            1,
            &vm,
            devices::Bus::new(),
            devices::Bus::new(),
            super::super::TimestampUs::default(),
        )
        .unwrap();

        (vm, vcpu)
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_configure_vcpu() {
        let (vm, mut vcpu) = setup_vcpu();

        let vm_config = VmConfig::default();
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());

        // Test configure while using the T2 template.
        let mut vm_config = VmConfig::default();
        vm_config.cpu_template = Some(CpuFeaturesTemplate::T2);
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());

        // Test configure while using the C3 template.
        let mut vm_config = VmConfig::default();
        vm_config.cpu_template = Some(CpuFeaturesTemplate::C3);
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_vcpu() {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {}

        let signum = 0;
        // We install a signal handler for the specified signal; otherwise the whole process will
        // be brought down when the signal is received, as part of the default behaviour. Signal
        // handlers are global, so we install this before starting the thread.
        unsafe {
            register_signal_handler(signum, SignalHandler::Siginfo(handle_signal), true)
                .expect("failed to register vcpu signal handler");
        }

        let (vm, mut vcpu) = setup_vcpu();

        let vm_config = VmConfig::default();
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());

        let thread_barrier = Arc::new(Barrier::new(2));
        let exit_evt = EventFd::new().unwrap();

        let vcpu_thread_barrier = thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().expect("eventfd clone failed");
        let seccomp_level = 0;

        let thread = thread::Builder::new()
            .name("fc_vcpu0".to_string())
            .spawn(move || {
                vcpu.run(vcpu_thread_barrier, seccomp_level, vcpu_exit_evt);
            })
            .expect("failed to spawn thread ");

        thread_barrier.wait();

        // Wait to make sure the vcpu starts its KVM_RUN ioctl.
        thread::sleep(Duration::from_millis(100));

        // Kick the vcpu out of KVM_RUN.
        thread.kill(signum).expect("failed to signal thread");

        // Wait some more.
        thread::sleep(Duration::from_millis(100));

        // Validate vcpu handled the EINTR gracefully and didn't exit.
        let err = exit_evt.read().unwrap_err();
        assert_eq!(err.raw_os_error().unwrap(), libc::EAGAIN);
    }

    #[test]
    fn not_enough_mem_slots() {
        let kvm_fd = Kvm::new().unwrap();
        let mut vm = Vm::new(&kvm_fd).expect("new vm failed");

        let kvm = KvmContext {
            kvm: kvm_fd,
            max_memslots: 1,
        };
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        assert!(vm.memory_init(gm, &kvm).is_err());
    }
}
