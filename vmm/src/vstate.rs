// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io;
use std::result;
use std::sync::{Arc, Barrier};

use super::{KvmContext, TimestampUs};
use arch;
#[cfg(target_arch = "x86_64")]
use cpuid::{c3, filter_cpuid, t2};
use default_syscalls;
use kvm::*;
use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use logger::{LogOption, Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory, GuestMemoryError};
use sys_util::EventFd;
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
    // Boot done
    VcpuDone,
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


    // Yue
    //pub fn memory_del(&mut self) -> Result<()> {
    //    match self.guest_mem {
    //        Some(ref mem) => {
    //            mem.with_regions(|index, guest_addr, size, host_addr| {
    //                info!("Removing guest memory starting at {:x?} with size {}", host_addr, size);

    //                let mut memory_region = kvm_userspace_memory_region {
    //                    slot: index as u32,
    //                    guest_phys_addr: guest_addr.offset() as u64,
    //                    memory_size: 0u64,
    //                    userspace_addr: host_addr as u64,
    //                    flags: 0u32,
    //                };
    //                self.fd.set_user_memory_region(memory_region)?;

    //                memory_region = kvm_userspace_memory_region {
    //                    slot: index as u32,
    //                    guest_phys_addr: guest_addr.offset() as u64,
    //                    memory_size: size as u64,
    //                    userspace_addr: host_addr as u64,
    //                    flags: 0x2u32,
    //                };
    //                self.fd.set_user_memory_region(memory_region)
    //            })?;
    //        },
    //        None => {
    //            info!("Guest Memory is empty");
    //        }
    //    }
    //    Ok(())
    //}

    /// This function creates the irq chip and adds 3 interrupt events to the IRQ.
    pub fn setup_irqchip(
        &self,
        com_evt_1_3: &EventFd,
        com_evt_2_4: &EventFd,
        kbd_evt: &EventFd,
    ) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;

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
    _mmio_cnt: usize,
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
            _mmio_cnt: 0usize,
            magic_port_cnt: 0usize,
        })
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

        arch::x86_64::regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        // Safe to unwrap because this method is called after the VM is configured
        let vm_memory = vm
            .get_memory()
            .ok_or(Error::GuestMemory(GuestMemoryError::MemoryNotInitialized))?;
        arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.offset() as u64)
            .map_err(Error::REGSConfiguration)?;
        arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        arch::x86_64::regs::setup_sregs(vm_memory, &self.fd).map_err(Error::SREGSConfiguration)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    fn _set_mem_readonly(&self) -> Result<()> {
        self.guest_mem.with_regions(|index, guest_addr, size, host_addr| {
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
                flags: 0x3u32,
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

    fn run_emulation(&mut self) -> Result<()> {
        match self.fd.run() {
            Ok(run) => match run {
                VcpuExit::IoIn(addr, data) => {
                    self.io_bus.read(u64::from(addr), data);
                    METRICS.vcpu.exit_io_in.inc();
                    Ok(())
                }
                VcpuExit::IoOut(addr, data) => {
                    if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE
                        && data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE
                    {
                        self.magic_port_cnt += 1;
                        if self.magic_port_cnt == 1 {
                            super::Vmm::log_boot_time(&self.create_ts);
                            info!("Received BOOT COMPLETE signal");
                            // set guest memory to read only
                            //info!("Setting guest memory to read-only");
                            //self._set_mem_readonly()?;
                            //info!("Set guest memory to read-only");
                            return Err(Error::VcpuDone);
                        }
                        else if self.magic_port_cnt == 2 {
                            info!("/sbin/init and openrc finished");
                            return Err(Error::VcpuDone)
                        }
                        else {
                            info!("Python code is executed");
                            return Err(Error::VcpuDone)
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
                        //if self._mmio_cnt == 2 {
                        //    return Err(Error::VcpuUnhandledKvmExit)
                        //}
                        //self._mmio_cnt += 1;
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
        done_barriers: Vec<Arc<Barrier>>,
        seccomp_level: u32,
        vcpu_exit_evt: EventFd,
        vcpu_done_evt: EventFd,
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
            let ret = self.run_emulation();
            if !ret.is_ok() {
                match ret.err() {
                    Some(Error::VcpuDone) => {
                        if let Err(e) = vcpu_done_evt.write(1) {
                            METRICS.vcpu.failures.inc();
                            error!("Failed signaling vcpu boot complete event: {}", e);
                        }
                        done_barriers[self.magic_port_cnt-1].wait();
                        info!("Pass done_barrier {}", self.magic_port_cnt);
                        if self.magic_port_cnt == 3 {
                            if let Err(e) = vcpu_exit_evt.write(1) {
                                METRICS.vcpu.failures.inc();
                                error!("Failed signaling vcpu exit event: {}", e);
                            }
                        }
                    },
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
