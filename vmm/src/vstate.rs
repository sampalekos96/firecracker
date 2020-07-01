// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use fc_util::{now_monotime_us, now_cputime_us};

use std::io;
use std::io::BufWriter;
use std::result;
use std::sync::{Arc, Barrier};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::fs::{File, OpenOptions};
use std::io::Write;

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

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct VcpuState {
    pub vcpu_events: kvm_vcpu_events,
    pub mp_state: kvm_mp_state,
    pub regs: kvm_regs,
    pub xsave_region: Vec<std::os::raw::c_uint>,
    pub xcrs: kvm_xcrs,
    pub sregs: kvm_sregs,
    pub msr_entries: Vec<kvm_msr_entry>,
    pub lapic_regs: Vec<std::os::raw::c_char>,
}

pub struct VcpuInfo {
    pub id: u8,
    pub state: VcpuState,
}

#[derive(Default, Serialize, Deserialize)]
pub struct IoapicState {
   pub base_address: u64,
   pub ioregsel: u32,
   pub id: u32,
   pub irr: u32,
   pub pad: u32,
   pub redirtbl: [kvm_ioapic_state__bindgen_ty_1__bindgen_ty_1; 24usize],
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct VirtioState {
    pub queues: Vec<devices::virtio::queue::Queue>
}

/// Snapshot
#[derive(Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// IOAPIC
    pub ioapic: IoapicState,
    /// PIC master
    pub pic_master: kvm_pic_state,
    /// PIC slave
    pub pic_slave: kvm_pic_state,
    // TODO: currently only block devices
    /// Virtio block device
    pub block_states: Vec<VirtioState>,
    /// Virtio net device
    pub net_states: Vec<VirtioState>,
    /// Vcpu
    pub vcpu_states: Vec<VcpuState>,
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
        //let t0 = now_monotime_us();
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

    /// Generate memory dump under the provided directory `dir`.
    /// Memory dump contains only dirtied memory.
    pub fn dump_initialized_memory_to_file(&self, dir: PathBuf) {
        self.guest_mem.as_ref().unwrap().dump_initialized_memory_to_file(dir)
            .expect("Failed to dump memory to a sparse file");
    }

    fn load_irqchip(&self, snapshot: &Snapshot) -> result::Result<(), io::Error> {
        let mut irqchip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        let ioapic = &snapshot.ioapic;
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

        irqchip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        irqchip.chip.pic = snapshot.pic_master;
        self.fd.set_irqchip(&irqchip)?;

        irqchip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        irqchip.chip.pic = snapshot.pic_slave;
        self.fd.set_irqchip(&irqchip)
    }

    /// This function dumps irqchip's states
    pub fn dump_irqchip(&self, snapshot: &mut Snapshot) -> result::Result<(), io::Error> {
        snapshot.ioapic = get_ioapic_state(&self.fd)?;
        snapshot.pic_master = get_pic_state(&self.fd, true)?;
        snapshot.pic_slave = get_pic_state(&self.fd, false)?;

        Ok(())
    }

    /// This function creates the irq chip and adds 3 interrupt events to the IRQ.
    pub fn setup_irqchip(
        &self,
        com_evt_1_3: &EventFd,
        com_evt_2_4: &EventFd,
        kbd_evt: &EventFd,
        maybe_snapshot: Option<&Snapshot>,
    ) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;
        if let Some(snapshot) = maybe_snapshot {
            let start = now_monotime_us();
            self.load_irqchip(snapshot).map_err(|e| Error::LoadSnapshot(e))?;
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
    ts_126: Vec<TimestampUs>,
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

        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            #[cfg(target_arch = "x86_64")]
            cpuid: vm.get_supported_cpuid(),
            fd: kvm_vcpu,
            id,
            io_bus,
            mmio_bus,
            create_ts,
            ts_126: Vec::new(),
        })
    }

    fn get_msrs(&self, vcpu_state: &mut VcpuState) -> result::Result<(), io::Error> {
        let mut entry_vec = arch::x86_64::regs::create_msr_entries();
        entry_vec.push(arch::x86_64::regs::create_msr_tscdeadline());
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
            vcpu_state.msr_entries = entries;
        }

        Ok(())
    }

    fn set_msrs(&self, vcpu_state: &VcpuState) -> result::Result<(), std::io::Error> {
        let entries = &vcpu_state.msr_entries;

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

    fn load_vcpu_state(&self, vcpu_state: &VcpuState) -> result::Result<(), io::Error> {
        self.fd.set_regs(&vcpu_state.regs)?;

        let region_vec = &vcpu_state.xsave_region;
        let mut region = [0 as std::os::raw::c_uint; 1024usize];
        for idx in 0..region.len() {
            region[idx] = region_vec[idx];
        }
        let xsave = kvm_xsave{ region };
        self.fd.set_xsave(&xsave)?;

        self.fd.set_xcrs(&vcpu_state.xcrs)?;

        self.fd.set_sregs(&vcpu_state.sregs)?;

        let regs_vec = &vcpu_state.lapic_regs;
        // from kvm api documentation, KVM_APIC_REG_SIZE = 0x400/1024
        let mut regs = [0 as std::os::raw::c_char; 1024usize];
        for (idx, _) in regs_vec.iter().enumerate() {
            regs[idx] = regs_vec[idx];
        }

        let lapic = kvm_lapic_state { regs };
        self.fd.set_lapic(&lapic)?;

        // this must be after lapic is restored
        // write to msr_tscdeadline only takes effect when lapic is in `tscdeadline` mode
        self.set_msrs(vcpu_state)?;

        self.fd.set_vcpu_events(&vcpu_state.vcpu_events)?;

        self.fd.set_mp_state(&vcpu_state.mp_state)?;

        Ok(())
    }

    fn dump_vcpu_state(&self, vcpu_state: &mut VcpuState) -> result::Result<(), io::Error> {
        vcpu_state.vcpu_events = self.fd.get_vcpu_events()?;

        vcpu_state.mp_state = self.fd.get_mp_state()?;

        vcpu_state.regs = self.fd.get_regs()?;

        let xsave = self.fd.get_xsave()?;
        vcpu_state.xsave_region = xsave.region.to_vec();

        vcpu_state.xcrs = self.fd.get_xcrs()?;

        vcpu_state.sregs = self.fd.get_sregs()?;

        self.get_msrs(vcpu_state)?;

        let lapic = self.fd.get_lapic()?;
        vcpu_state.lapic_regs = lapic.regs.to_vec();

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
        maybe_vcpu_state: Option<&VcpuState>,
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

        if let Some(vcpu_state) = maybe_vcpu_state {
            let start = now_monotime_us();
            self.load_vcpu_state(vcpu_state).map_err(|e| Error::LoadSnapshot(e))?;
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

    fn run_emulation(&mut self,
                     snap_barrier: &Arc<Barrier>,
                     vcpu_snap_evt: &EventFd,
                     snap_sender: &Option<Sender<VcpuInfo>>,
                     from_snapshot: bool,
                     ready_notifier: &Option<File>,
                     notifier_id: u32) -> Result<()> {
        match self.fd.run() {
            Ok(run) => match run {
                VcpuExit::IoIn(addr, data) => {
                    assert_eq!(1, data.len());
                    self.io_bus.read(u64::from(addr), data);
                    METRICS.vcpu.exit_io_in.inc();
                    Ok(())
                }
                VcpuExit::IoOut(addr, data) => {
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE
                        && data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE
                    {
                        super::Vmm::log_boot_time(&self.create_ts);
                        //println!("Boot done.");
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE && data[0] == 124 {
                        //println!("vcpu {} signaled", self.id);
                        if let Some(ref sender) = snap_sender {
                            let mut vcpu_state = VcpuState::default();
                            self.dump_vcpu_state(&mut vcpu_state)?;
                            sender.send(VcpuInfo{
                                id: self.id,
                                state: vcpu_state,
                            }).expect("Failed sending vcpu state");
                            vcpu_snap_evt.write(1).expect("Failed signaling vcpu snap event");
                            snap_barrier.wait();
                            return Err(Error::VcpuUnhandledKvmExit);
                        }
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE && data[0] == 125 {
                        panic!("mounting app file system failed");
                    }
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE && data[0] == 126 {
                        if self.ts_126.len() == 0 {
                            //super::Vmm::log_boot_time(&self.create_ts);
                            if let Some(mut notifier) = ready_notifier.as_ref() {
                                notifier.write_all(&notifier_id.to_le_bytes()).expect("Failed to notify that boot is complete");
                            }
                        }
                        self.ts_126.push(TimestampUs {
                            time_us: now_monotime_us(),
                            cputime_us: now_cputime_us()
                        });
                        let len = self.ts_126.len();
                        if len > 0 {
                            eprintln!("since create_ts: time: {}us, cputime: {}us",
                                self.ts_126[len-1].time_us - self.create_ts.time_us,
                                self.ts_126[len-1].cputime_us - self.create_ts.cputime_us);
                        }
                        //return Err(Error::VcpuUnhandledKvmExit)
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
                    libc::EAGAIN | libc::EINTR => Ok(()),
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
        snap_barrier: Arc<Barrier>,
        seccomp_level: u32,
        vcpu_exit_evt: EventFd,
        vcpu_snap_evt: EventFd,
        snap_sender: Option<Sender<VcpuInfo>>,
        from_snapshot: bool,
        ready_notifier: Option<File>,
        notifier_id: u32,
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

        loop {
            let ret = self.run_emulation(&snap_barrier, &vcpu_snap_evt, &snap_sender, from_snapshot, &ready_notifier, notifier_id);
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
