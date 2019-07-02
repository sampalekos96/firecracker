// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use fc_util::now_cputime_us;

use std::io;
use std::io::{Seek, SeekFrom, Write, Read, BufReader};
use std::result;
use std::sync::{Arc, Barrier};
use std::collections::{BTreeSet, BTreeMap};

use super::{KvmContext, TimestampUs};
use arch;
#[cfg(target_arch = "x86_64")]
use cpuid::{c3, filter_cpuid, t2};
use default_syscalls;
use kvm::*;
use kvm_bindings::{ kvm_regs, kvm_sregs, kvm_msrs, kvm_msr_entry, kvm_irqchip, kvm_lapic_state,
    kvm_mp_state, kvm_vcpu_events, kvm_fpu, kvm_xsave, kvm_xcrs,
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    kvm_pic_state, kvm_ioapic_state__bindgen_ty_1__bindgen_ty_1,
    //kvm_irqfd, kvm_ioeventfd,
    //kvm_ioeventfd_flag_nr_datamatch, kvm_ioeventfd_flag_nr_deassign,
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
    
fn get_ioapic_state(vmfd: &VmFd) -> IoapicState {
    let mut irqchip = kvm_irqchip {
        chip_id: KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    vmfd.get_irqchip(&mut irqchip).ok();
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
    ioapic
}

fn get_pic_state(vmfd: &VmFd, master: bool) -> kvm_pic_state {
    let mut irqchip = kvm_irqchip {
        chip_id: if master { KVM_IRQCHIP_PIC_MASTER } else { KVM_IRQCHIP_PIC_SLAVE },
        ..Default::default()
    };
    vmfd.get_irqchip(&mut irqchip).ok();
    unsafe { irqchip.chip.pic }
}

fn setup_irqchip_from_file(vmfd: &VmFd) {
    let reader = BufReader::new(std::fs::File::open("ioapic.json").unwrap());
    let ioapic: IoapicState = serde_json::from_reader(reader).unwrap();
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
    vmfd.set_irqchip(&irqchip).ok();

    let reader = BufReader::new(std::fs::File::open("pic_master.json").unwrap());
    let pic: kvm_pic_state = serde_json::from_reader(reader).unwrap();
    irqchip = kvm_irqchip {
        chip_id: KVM_IRQCHIP_PIC_MASTER,
        ..Default::default()
    };
    irqchip.chip.pic = pic;
    vmfd.set_irqchip(&irqchip).ok();

    let reader = BufReader::new(std::fs::File::open("pic_slave.json").unwrap());
    let pic: kvm_pic_state = serde_json::from_reader(reader).unwrap();
    irqchip = kvm_irqchip {
        chip_id: KVM_IRQCHIP_PIC_SLAVE,
        ..Default::default()
    };
    irqchip.chip.pic = pic;
    vmfd.set_irqchip(&irqchip).ok();
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

            //let flags = if LOGGER.flags() & LogOption::LogDirtyPages as usize > 0 {
            //    KVM_MEM_LOG_DIRTY_PAGES
            //} else {
            //    0
            //};
            // Force dirty page logging
            let flags = KVM_MEM_LOG_DIRTY_PAGES;
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

    /// This function creates the irq chip and adds 3 interrupt events to the IRQ.
    pub fn setup_irqchip(
        &self,
        com_evt_1_3: &EventFd,
        com_evt_2_4: &EventFd,
        kbd_evt: &EventFd,
        from_file: bool,
    ) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;
        if from_file {
            setup_irqchip_from_file(&self.fd);
        }
        //let ioapic = get_ioapic_state(&self.fd);
        //std::fs::write("ioapic_before_register_irqfd.json", serde_json::to_string(&ioapic).unwrap()).ok();
        //let pic = get_pic_state(&self.fd, true);
        //std::fs::write("pic_master_before_register_irqfd.json", serde_json::to_string(&pic).unwrap()).ok();
        //let pic = get_pic_state(&self.fd, false);
        //std::fs::write("pic_slave_before_register_irqfd.json", serde_json::to_string(&pic).unwrap()).ok();

        self.fd.register_irqfd(com_evt_1_3, 4).map_err(Error::Irq)?;
        self.fd.register_irqfd(com_evt_2_4, 3).map_err(Error::Irq)?;
        self.fd.register_irqfd(kbd_evt, 1).map_err(Error::Irq)?;

        //let ioapic = get_ioapic_state(&self.fd);
        //std::fs::write("ioapic_after_register_irqfd.json", serde_json::to_string(&ioapic).unwrap()).ok();
        //let pic = get_pic_state(&self.fd, true);
        //std::fs::write("pic_master_after_register_irqfd.json", serde_json::to_string(&pic).unwrap()).ok();
        //let pic = get_pic_state(&self.fd, false);
        //std::fs::write("pic_slave_after_register_irqfd.json", serde_json::to_string(&pic).unwrap()).ok();

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
        let from_file = unsafe { super::FROM_FILE };
        let kvm_vcpu = vm.fd.create_vcpu(id, from_file).map_err(Error::VcpuFd)?;
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

    fn write_msrs_to_file(&self) {
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
        self.fd.get_msrs(msrs).ok();

        unsafe {
            let entries: Vec<kvm_msr_entry> = msrs.entries.as_slice(entry_vec.len()).to_vec();
            std::fs::write("kvm_msrs.json", serde_json::to_string(&entries).unwrap()).ok();
        }
    }

    fn setup_msrs_from_file(&self) {
        let reader = BufReader::new(std::fs::File::open("kvm_msrs.json").unwrap());
        let entries: Vec<kvm_msr_entry> = serde_json::from_reader(reader).unwrap();

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
        self.fd.set_msrs(msrs).ok();
    }

    fn setup_regs_from_file(&self) {
        let reader = BufReader::new(std::fs::File::open("kvm_regs.json").unwrap());
        let regs: kvm_regs = serde_json::from_reader(reader).unwrap();
        self.fd.set_regs(&regs).ok();

        let reader = BufReader::new(std::fs::File::open("kvm_xsave.json").unwrap());
        let region_vec: Vec<u32> = serde_json::from_reader(reader).unwrap();
        let mut region = [0u32; 1024usize];
        for idx in 0..region.len() {
            region[idx] = region_vec[idx];
        }
        let xsave = kvm_xsave{ region };
        self.fd.set_xsave(&xsave).ok();
        //let reader = BufReader::new(std::fs::File::open("kvm_fpu.json").unwrap());
        //let fpu: kvm_fpu = serde_json::from_reader(reader).unwrap();
        //self.fd.set_fpu(&fpu).ok();
        
        let reader = BufReader::new(std::fs::File::open("kvm_xcrs.json").unwrap());
        let xcrs: kvm_xcrs = serde_json::from_reader(reader).unwrap();
        self.fd.set_xcrs(&xcrs).ok();

        let reader = BufReader::new(std::fs::File::open("kvm_sregs.json").unwrap());
        let sregs: kvm_sregs = serde_json::from_reader(reader).unwrap();
        self.fd.set_sregs(&sregs).ok();

        self.setup_msrs_from_file();

        let reader = BufReader::new(std::fs::File::open("kvm_vcpu_events.json").unwrap());
        let vcpu_events: kvm_vcpu_events = serde_json::from_reader(reader).unwrap();
        self.fd.set_vcpu_events(&vcpu_events).ok();

        let reader = BufReader::new(std::fs::File::open("kvm_mp_state.json").unwrap());
        let mp_state: kvm_mp_state = serde_json::from_reader(reader).unwrap();
        self.fd.set_mp_state(&mp_state).ok();

        let reader = BufReader::new(std::fs::File::open("kvm_lapic.json").unwrap());
        let regs_vec: Vec<std::os::raw::c_char> = serde_json::from_reader(reader).unwrap();
        let mut regs = [0 as std::os::raw::c_char; 1024usize];
        for (idx, _) in regs_vec.iter().enumerate() {
            regs[idx] = regs_vec[idx];
        }
        let lapic = kvm_lapic_state { regs };
        self.fd.set_lapic(&lapic).ok();
    }

    fn write_regs_to_file(&self) {
        let vcpu_events = self.fd.get_vcpu_events().unwrap();
        std::fs::write("kvm_vcpu_events.json", serde_json::to_string(&vcpu_events).unwrap()).ok();

        let mp_state = self.fd.get_mp_state().unwrap();
        std::fs::write("kvm_mp_state.json", serde_json::to_string(&mp_state).unwrap()).ok();

        let regs = self.fd.get_regs().unwrap();
        std::fs::write("kvm_regs.json", serde_json::to_string(&regs).unwrap()).ok();

        let xsave = self.fd.get_xsave().unwrap();
        std::fs::write("kvm_xsave.json", serde_json::to_string(&xsave.region.to_vec()).unwrap()).ok();
        //let fpu = self.fd.get_fpu().unwrap();
        //std::fs::write("kvm_fpu.json", serde_json::to_string(&fpu).unwrap()).ok();

        let xcrs = self.fd.get_xcrs().unwrap();
        std::fs::write("kvm_xcrs.json", serde_json::to_string(&xcrs).unwrap()).ok();

        let sregs = self.fd.get_sregs().unwrap();
        std::fs::write("kvm_sregs.json", serde_json::to_string(&sregs).unwrap()).ok();

        self.write_msrs_to_file();

        let lapic = self.fd.get_lapic().unwrap();
        std::fs::write("kvm_lapic.json", serde_json::to_string(&lapic.regs.to_vec()).unwrap()).ok();
    }

    fn write_irqchip_to_file(&self) {
        let ioapic = get_ioapic_state(&self._vmfd);
        std::fs::write("ioapic.json", serde_json::to_string(&ioapic).unwrap()).ok();
        let pic = get_pic_state(&self._vmfd, true);
        std::fs::write("pic_master.json", serde_json::to_string(&pic).unwrap()).ok();
        let pic = get_pic_state(&self._vmfd, false);
        std::fs::write("pic_slave.json", serde_json::to_string(&pic).unwrap()).ok();
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
        from_file: bool,
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

        if from_file {
            let start = now_cputime_us();
            self.setup_regs_from_file();
            println!("loading registers took {}us", now_cputime_us()-start);
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
    // Yue: page size = 0x1000 Bytes (4KiB)
    //      We will get EINVAL if the requirements below do not hold:
    //      1. guest_phys_addr & 0xfff = 0
    //      2. memory_size & 0xfff = 0
    //      3. userspace_addr & 0xfff = 0 (this should hold if the first holds)
    //      4. userspace_addr is accessible to guest OS
    //fn set_page_writable(&self, data_addr: u64) -> Result<()> {
    //    let data_size = 4 << 10; // page size = 4KiB

    //    // assuming there is only one memory region
    //    // this is true with 128 MB guest memory on x86
    //    self.guest_mem.with_regions(|index, guest_addr, size, host_addr| {
    //        info!("Making guest memory page containing {:x?} writable", data_addr);
    //        if self.mmio_cnt == 0 {
    //            let mut memory_region = kvm_userspace_memory_region {
    //                slot: 0u32,
    //                guest_phys_addr: guest_addr.offset() as u64,
    //                memory_size: 0u64,
    //                userspace_addr: host_addr as u64,
    //                flags: 0u32,
    //            };
    //        }
    //        self.vmfd.set_user_memory_region(memory_region)?;
    //        info!("Deleted the entire memory region");
    //        memory_region = kvm_userspace_memory_region {
    //            slot: 0u32,
    //            guest_phys_addr: guest_addr.offset() as u64,
    //            memory_size: data_addr as u64,
    //            userspace_addr: host_addr as u64,
    //            flags: 0x2u32,
    //        };
    //        self.vmfd.set_user_memory_region(memory_region)?;
    //        info!("Added memory before {:x?} as read-only", data_addr);
    //        memory_region = kvm_userspace_memory_region {
    //            slot: 1u32,
    //            guest_phys_addr: data_addr as u64,
    //            memory_size: data_size as u64,
    //            userspace_addr: host_addr as u64 + data_addr,
    //            flags: 0u32,
    //        };
    //        self.vmfd.set_user_memory_region(memory_region)?;
    //        info!("Added target memory at {:x?} as writable", data_addr);
    //        memory_region = kvm_userspace_memory_region {
    //            slot: 2u32,
    //            guest_phys_addr: data_addr + data_size as u64,
    //            memory_size: (size - data_size) as u64 - data_addr + 1u64,
    //            userspace_addr: (host_addr + data_size) as u64 + data_addr,
    //            flags: 0x2u32,
    //        };
    //        self.vmfd.set_user_memory_region(memory_region)
    //    })?;
    //    info!("Succeeded");
    //    Ok(())
    //}

    // Get the list of indexes where bits are set in the number's binary representation
    fn list_set_bits(num_pages: usize, offset: usize, num: u64) -> BTreeSet<usize> {
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
    fn get_dirty_page_list(&self) -> BTreeSet<usize> {
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
                            .map(|(offset, page)| Vcpu::list_set_bits(num_pages, offset, *page))
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
    fn clear_accessed_log(sorted_pfns: &Vec<u64>) {
        let path = "/sys/kernel/mm/page_idle/bitmap";
        let mut idle_log = std::fs::OpenOptions::new().write(true).open(&path).unwrap();

        let seek_offset = (sorted_pfns[0] / 64) * 8;
        idle_log.seek(SeekFrom::Start(seek_offset)).err();

        let buf_size: usize = 8 * (1 + sorted_pfns[sorted_pfns.len()-1] / 64 - sorted_pfns[0] / 64) as usize;
        let buf = vec![0xff as u8; buf_size];
        idle_log.write_all(&buf).err();
    }

    fn read_accessed_log(pagemap: &BTreeMap<u64, usize>, sorted_pfns: &Vec<u64>) -> BTreeSet<usize> {
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
        //println!("smallest pfn = {} largest pfn = {}", sorted_pfns[0], sorted_pfns[sorted_pfns.len()-1]);
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

    fn get_and_clear_accessed_log(&self, pagemap: &BTreeMap<u64, usize>) -> BTreeSet<usize> {
        let sorted_pfns: Vec<u64> = pagemap.keys().cloned().collect();

        let ret = Vcpu::read_accessed_log(&pagemap, &sorted_pfns);
        if sorted_pfns.len() > 0 {
            Vcpu::clear_accessed_log(&sorted_pfns);
        }
        ret
    }

    fn calculate_intersection(sets: &Vec<BTreeSet<usize>>) -> Vec<Vec<BTreeSet<usize>>> {
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

    fn run_emulation(&mut self,
                     accessed: &mut Vec<BTreeSet<usize>>,
                     dirtied: &mut Vec<BTreeSet<usize>>,
                     read: &mut Vec<BTreeSet<usize>>) -> Result<()> {
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
                        match self.magic_124_cnt {
                            1 => println!("loading json file done"),
                            2 => println!("calculation file done"),
                            3 => println!("outputing result done"),
                            _ => println!("unknown event")
                        }
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE
                        && data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE
                    {
                        let pagemap = self.guest_mem.get_pagemap();
                        let accessed_pages = self.get_and_clear_accessed_log(&pagemap);
                        let dirtied_pages = self.get_dirty_page_list();
                        let mut log = std::fs::OpenOptions::new().append(true).open("pages.log").unwrap();
                        write!(log, "{},{},{},{}\n",
                              pagemap.len(),
                              accessed_pages.len(),
                              dirtied_pages.len(),
                              accessed_pages.difference(&dirtied_pages).collect::<BTreeSet<_>>().len()).ok();
                        read.push(accessed_pages.difference(&dirtied_pages).cloned().collect());
                        accessed.push(accessed_pages);
                        dirtied.push(dirtied_pages);

                        self.magic_port_cnt += 1;
                        if self.magic_port_cnt == 1 {
                            if unsafe { super::FROM_FILE } {
                                println!("Import done.");
                            } else {
                                super::Vmm::log_boot_time(&self.create_ts);
                                println!("Received BOOT COMPLETE signal. #pages in memory is {}", pagemap.len());
                            }
                        } else if self.magic_port_cnt == 2 {
                            if unsafe { super::FROM_FILE } {
                                println!("App done. Shutting down...");
                                return Err(Error::VcpuUnhandledKvmExit);
                            }
                            info!("Init finished. #pages in memory is {}", pagemap.len());
                        } else if self.magic_port_cnt == 3 {
                            info!("Runtime is up. #pages in memory is {}", pagemap.len());
                            println!("Runtime is up. #pages in memory is {}", pagemap.len());
                            if unsafe{ super::DUMP } {
                                //unsafe { libc::sleep(30) };
                                println!("dumping states");
                                self.write_regs_to_file();
                                self.write_irqchip_to_file();
                                let mut mem_dump = std::fs::OpenOptions::new()
                                    .write(true).truncate(true).create(true).open("runtime_mem_dump").unwrap();
                                mem_dump.write_all(self.guest_mem.dump_regions().as_slice()).ok();
                                self.fd.dump_kvm_run(self._vmfd.get_run_size());
                                return Err(Error::VcpuUnhandledKvmExit);
                            } else {
                                let regs = self.fd.get_regs().unwrap();
                                std::fs::write("kvm_regs_regular_run.json",
                                               serde_json::to_string(&regs).unwrap()).ok();
                            }
                        } else if self.magic_port_cnt == 4 {
                            info!("Imports finished. #pages in memory is {}", pagemap.len());
                        } else if self.magic_port_cnt == 5 {
                            info!("App done. #pages in memory is {}", pagemap.len());
                            //write!(log, "{},{}\n",
                            //       dirtied[3].intersection(&dirtied[4]).collect::<BTreeSet<_>>().len(),
                            //       dirtied[3].intersection(&read[4]).collect::<BTreeSet<_>>().len()).ok();
                            // the end of the application, we do the set intersections and exit
                            //let accessed_intersect = Vcpu::calculate_intersection(&accessed);
                            //let dirtied_intersect = Vcpu::calculate_intersection(&dirtied);
                            //let read_intersect = Vcpu::calculate_intersection(&read);
                            //for i in 0..accessed_intersect.len() {
                            //    write!(log, "{},{},{}\n",
                            //           accessed_intersect[i].len(),
                            //           dirtied_intersect[i].len(),
                            //           read_intersect[i].len()).ok();
                            //}
                            //for tuple in accessed_intersect.iter() {
                            //    write!(log, "{},{},{}\n",
                            //           tuple[0].len(),
                            //           tuple[2].len(),
                            //           tuple[1].len()).ok();
                            //}
                            //for i in 0..accessed_intersect.len() {
                            //    write!(log, "{},{},{}\n",
                            //           dirtied_intersect[i][0].len(),
                            //           accessed_intersect[i][1].len(),
                            //           dirtied_intersect[i][0]
                            //            .intersection(&accessed_intersect[i][1])
                            //            .collect::<BTreeSet<_>>().len()).ok();
                            //}
                            return Err(Error::VcpuUnhandledKvmExit)
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
                    // BOOT COMPLETE and addr is not in reserved memory region
                    if self.magic_port_cnt > 0 && addr < arch::get_reserved_mem_addr() as u64 {
                        info!("Received KVM_EXIT_MMIO_WRITE signal at address 0x{:x?} with {} B data",
                            addr, data.len());
                        let guest_addr = GuestAddress(addr as usize);
                        info!("Calling write_slice_at_addr");
                        self.guest_mem.write_slice_at_addr(data, guest_addr)
                            .map_err(|e| Error::GuestMemory(e))?;
                        info!("write_slice_at_addr succeeded");
                        Ok(())
                        //self.set_page_writable(addr)
                    }
                    else {
                        self.mmio_bus.write(addr, data);
                        METRICS.vcpu.exit_mmio_write.inc();
                        Ok(())
                    }
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
                    libc::EINTR => {
                        let pagemap = self.guest_mem.get_pagemap();
                        let accessed_pages = self.get_and_clear_accessed_log(&pagemap);
                        let dirtied_pages = self.get_dirty_page_list();
                        // #pages present, #pages accessed, #pages dirtied, #pages only read
                        info!("{},{},{},{}",
                              pagemap.len(),
                              accessed_pages.len(),
                              dirtied_pages.len(),
                              accessed_pages.difference(&dirtied_pages).collect::<BTreeSet<_>>().len());
                        Ok(())
                    },
                    //libc::EFAULT => {
                    //    info!("Bad Address");
                    //},
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

        //let my_pthread_t = unsafe { libc::pthread_self() };
        //std::thread::Builder::new()
        //    .name("kill_thread".to_string())
        //    .spawn(move || {
        //        const ONE_MILLI_TO_MICRO: u32 = 1000;
        //        loop {
        //            unsafe { libc::usleep(ONE_MILLI_TO_MICRO) };
        //            unsafe { libc::pthread_kill(my_pthread_t, libc::SIGUSR1) };
        //        }
        //    }).err();
        std::fs::OpenOptions::new().create(true).write(true).truncate(true).open("pages.log").ok();
        let pagemap = self.guest_mem.get_pagemap();
        let sorted_pfns: Vec<u64> = pagemap.keys().cloned().collect();
        if sorted_pfns.len() > 0 {
            Vcpu::clear_accessed_log(&sorted_pfns);
        }
        let mut accessed = Vec::new();
        let mut dirtied = Vec::new();
        let mut read = Vec::new();
        //let ioapic = get_ioapic_state(&self._vmfd);
        //std::fs::write("ioapic_initial.json", serde_json::to_string(&ioapic).unwrap()).ok();
        //let pic = get_pic_state(&self._vmfd, true);
        //std::fs::write("pic_master_initial.json", serde_json::to_string(&pic).unwrap()).ok();
        //let pic = get_pic_state(&self._vmfd, false);
        //std::fs::write("pic_slave_initial.json", serde_json::to_string(&pic).unwrap()).ok();
        println!("entering kvm_run");
        loop {
            let ret = self.run_emulation(&mut accessed, &mut dirtied, &mut read);
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
