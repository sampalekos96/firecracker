// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual Machine Monitor that leverages the Linux Kernel-based Virtual Machine (KVM),
//! and other virtualization features to run a single lightweight micro-virtual
//! machine (microVM).
#![deny(missing_docs)]
extern crate chrono;
extern crate epoll;
extern crate futures;
extern crate kvm_bindings;
extern crate libc;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate time;
extern crate timerfd;
extern crate byteorder;

extern crate arch;
#[cfg(target_arch = "x86_64")]
extern crate cpuid;
extern crate devices;
extern crate fc_util;
extern crate kernel;
extern crate kvm;
#[macro_use]
extern crate logger;
extern crate memory_model;
extern crate net_util;
extern crate rate_limiter;
extern crate seccomp;
extern crate sys_util;

/// Syscalls allowed through the seccomp filter.
pub mod default_syscalls;
mod device_manager;
/// Signal handling utilities for seccomp violations.
mod sigsys_handler;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
mod vstate;

use byteorder::{ByteOrder, LittleEndian};
use futures::sync::oneshot;
use std::collections::{BTreeSet,HashMap};
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::fs::{metadata, File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::result;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Barrier, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use std::convert::TryInto;

use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use arch::DeviceType;

use device_manager::legacy::LegacyDeviceManager;
use device_manager::mmio::MMIODeviceManager;
use device_manager::mmio::MMIODeviceInfo;
use devices::legacy::I8042DeviceError;
use devices::virtio;
use devices::{DeviceEventT, EpollHandler, EpollHandlerPayload};
use fc_util::{now_monotime_us, now_cputime_us};
use kernel::cmdline as kernel_cmdline;
use kernel::loader as kernel_loader;
use kvm::*;
use logger::error::LoggerError;
use logger::{AppInfo, Level, LogOption, Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory, MemoryFileOption, MemorySnapshotMeta, MemorySnapshotLayer};
#[cfg(target_arch = "aarch64")]
use serde_json::Value;
pub use sigsys_handler::setup_sigsys_handler;
use sys_util::{EventFd, Terminal};
use vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
use vmm_config::instance_info::{InstanceInfo, InstanceState, StartMicrovmError};
use vmm_config::logger::{LoggerConfig, LoggerConfigError, LoggerLevel};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
    NetworkInterfaceUpdateConfig,
};
#[cfg(feature = "vsock")]
use vmm_config::vsock::{VsockDeviceConfig, VsockDeviceConfigs, VsockError};
use vstate::{Vcpu, Vm, VcpuInfo};
pub use vstate::Snapshot;

use devices::virtio::{BLOCK_EVENTS_COUNT, TYPE_BLOCK};
use devices::virtio::{NET_EVENTS_COUNT, TYPE_NET};
use devices::virtio::vsock::{TYPE_VSOCK, VSOCK_EVENTS_COUNT};

// use virtio::TYPE_BLOCK;
// use virtio::TYPE_NET;
// use virtio::BLOCK_EVENTS_COUNT;


/// Default guest kernel command line:
/// - `reboot=k` shut down the guest on reboot, instead of well... rebooting;
/// - `panic=1` on panic, reboot after 1 second;
/// - `pci=off` do not scan for PCI devices (save boot time);
/// - `nomodules` disable loadable kernel module support;
/// - `8250.nr_uarts=0` disable 8250 serial interface;
/// - `i8042.noaux` do not probe the i8042 controller for an attached mouse (save boot time);
/// - `i8042.nomux` do not probe i8042 for a multiplexing controller (save boot time);
/// - `i8042.nopnp` do not use ACPIPnP to discover KBD/AUX controllers (save boot time);
/// - `i8042.dumbkbd` do not attempt to control kbd state via the i8042 (save boot time).
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 \
                                      i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";
const WRITE_METRICS_PERIOD_SECONDS: u64 = 60;

/// Success exit code.
pub const FC_EXIT_CODE_OK: u8 = 0;
/// Generic error exit code.
pub const FC_EXIT_CODE_GENERIC_ERROR: u8 = 1;
/// Generic exit code for an error considered not possible to occur if the program logic is sound.
pub const FC_EXIT_CODE_UNEXPECTED_ERROR: u8 = 2;
/// Firecracker was shut down after intercepting a restricted system call.
pub const FC_EXIT_CODE_BAD_SYSCALL: u8 = 148;

pub const MMIO_MEM_SIZE: u64 = arch::aarch64::layout::DRAM_MEM_START - arch::aarch64::layout::MAPPED_IO_START;

/// Errors associated with the VMM internal logic. These errors cannot be generated by direct user
/// input, but can result from bad configuration of the host (for example if Firecracker doesn't
/// have permissions to open the KVM fd).
pub enum Error {
    /// Cannot receive message from the API.
    ApiChannel,
    /// Legacy devices work with Event file descriptors and the creation can fail because
    /// of resource exhaustion.
    CreateLegacyDevice(device_manager::legacy::Error),
    /// An operation on the epoll instance failed due to resource exhaustion or bad configuration.
    EpollFd(io::Error),
    /// Cannot read from an Event file descriptor.
    EventFd(io::Error),
    /// An event arrived for a device, but the dispatcher can't find the event (epoll) handler.
    DeviceEventHandlerNotFound,
    /// Cannot open /dev/kvm. Either the host does not have KVM or Firecracker does not have
    /// permission to open the file descriptor.
    Kvm(io::Error),
    /// The host kernel reports an invalid KVM API version.
    KvmApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    KvmCap(kvm::Cap),
    /// Epoll wait failed.
    Poll(io::Error),
    /// Write to the serial console failed.
    Serial(io::Error),
    /// Cannot create Timer file descriptor.
    TimerFd(io::Error),
    /// Cannot open the VM file descriptor.
    Vm(vstate::Error),
    /// Cannot write snapshot
    SaveSnapshot(io::Error),
}

// Implementing Debug as these errors are mostly used in panics & expects.
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            ApiChannel => write!(f, "ApiChannel: error receiving data from the API server"),
            CreateLegacyDevice(e) => write!(f, "Error creating legacy device: {:?}", e),
            EpollFd(e) => write!(f, "Epoll fd error: {}", e.to_string()),
            EventFd(e) => write!(f, "Event fd error: {}", e.to_string()),
            DeviceEventHandlerNotFound => write!(
                f,
                "Device event handler not found. This might point to a guest device driver issue."
            ),
            Kvm(os_err) => write!(f, "Cannot open /dev/kvm. Error: {}", os_err.to_string()),
            KvmApiVersion(ver) => write!(f, "Bad KVM API version: {}", ver),
            KvmCap(cap) => write!(f, "Missing KVM capability: {:?}", cap),
            Poll(e) => write!(f, "Epoll wait failed: {}", e.to_string()),
            Serial(e) => write!(f, "Error writing to the serial console: {:?}", e),
            TimerFd(e) => write!(f, "Error creating timer fd: {}", e.to_string()),
            Vm(e) => write!(f, "Error opening VM fd: {:?}", e),
            SaveSnapshot(e) => write!(f, "Error writing snapshot: {:?}", e),
        }
    }
}

/// Types of errors associated with vmm actions.
#[derive(Debug)]
pub enum ErrorKind {
    /// User Errors describe bad configuration (user input).
    User,
    /// Internal Errors are unrelated to the user and usually refer to logical errors
    /// or bad management of resources (memory, file descriptors & others).
    Internal,
}

/// Wrapper for all errors associated with VMM actions.
#[derive(Debug)]
pub enum VmmActionError {
    /// The action `ConfigureBootSource` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    BootSource(ErrorKind, BootSourceConfigError),
    /// One of the actions `InsertBlockDevice`, `RescanBlockDevice` or `UpdateBlockDevicePath`
    /// failed either because of bad user input (`ErrorKind::User`) or an
    /// internal error (`ErrorKind::Internal`).
    DriveConfig(ErrorKind, DriveError),
    /// The action `ConfigureLogger` failed either because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    Logger(ErrorKind, LoggerConfigError),
    /// One of the actions `GetVmConfiguration` or `SetVmConfiguration` failed either because of bad
    /// input (`ErrorKind::User`) or an internal error (`ErrorKind::Internal`).
    MachineConfig(ErrorKind, VmConfigError),
    /// The action `InsertNetworkDevice` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    NetworkConfig(ErrorKind, NetworkInterfaceError),
    /// The action `StartMicroVm` failed either because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    StartMicrovm(ErrorKind, StartMicrovmError),
    /// The action `SendCtrlAltDel` failed. Details are provided by the device-specific error
    /// `I8042DeviceError`.
    SendCtrlAltDel(ErrorKind, I8042DeviceError),
    #[cfg(feature = "vsock")]
    /// The action `insert_vsock_device` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    VsockConfig(ErrorKind, VsockError),
    /// The action `dump_working_set` failed because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    DumpWorkingSet(ErrorKind, memory_model::GuestMemoryError),
}

impl VmmActionError {
    /// Returns the error type.
    pub fn get_kind(&self) -> &ErrorKind {
        use self::VmmActionError::*;

        match *self {
            BootSource(ref kind, _) => kind,
            DriveConfig(ref kind, _) => kind,
            Logger(ref kind, _) => kind,
            MachineConfig(ref kind, _) => kind,
            NetworkConfig(ref kind, _) => kind,
            StartMicrovm(ref kind, _) => kind,
            SendCtrlAltDel(ref kind, _) => kind,
            #[cfg(feature = "vsock")]
            VsockConfig(ref kind, _) => kind,
            DumpWorkingSet(ref kind, _) => kind,
        }
    }
}

impl Display for VmmActionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VmmActionError::*;

        match *self {
            BootSource(_, ref err) => write!(f, "{}", err.to_string()),
            DriveConfig(_, ref err) => write!(f, "{}", err.to_string()),
            Logger(_, ref err) => write!(f, "{}", err.to_string()),
            MachineConfig(_, ref err) => write!(f, "{}", err.to_string()),
            NetworkConfig(_, ref err) => write!(f, "{}", err.to_string()),
            StartMicrovm(_, ref err) => write!(f, "{}", err.to_string()),
            SendCtrlAltDel(_, ref err) => write!(f, "{}", err.to_string()),
            #[cfg(feature = "vsock")]
            VsockConfig(_, ref err) => write!(f, "{}", err.to_string()),
            DumpWorkingSet(_, ref err) => write!(f, "{:?}", err),
        }
    }
}

/// SnapFaaS config
#[derive(Default)]
pub struct SnapFaaSConfig {
    /// snapshot directory to load from
    pub load_dir: Vec<PathBuf>,
    /// parsed snapshot.json
    pub parsed_json: Option<Snapshot>,
    /// directory to dump to
    pub dump_dir: Option<PathBuf>,
    /// restore base memory by copying
    pub base: MemoryFileOption,
    /// restore diff memory by copying
    pub diff: MemoryFileOption,
    /// use huge pages
    pub huge_page: bool,
    ///// diff snapshot directory
    //pub diff_dirs: Vec<PathBuf>,
    /// apply working set optimization
    pub load_ws: bool,
}

/// This enum represents the public interface of the VMM. Each action contains various
/// bits of information (ids, paths, etc.), together with an OutcomeSender, which is always present.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum VmmAction {
    /// Configure the boot source of the microVM using as input the `ConfigureBootSource`. This
    /// action can only be called before the microVM has booted. The response is sent using the
    /// `OutcomeSender`.
    ConfigureBootSource(BootSourceConfig, OutcomeSender),
    /// Configure the logger using as input the `LoggerConfig`. This action can only be called
    /// before the microVM has booted. The response is sent using the `OutcomeSender`.
    ConfigureLogger(LoggerConfig, OutcomeSender),
    /// Get the configuration of the microVM. The action response is sent using the `OutcomeSender`.
    GetVmConfiguration(OutcomeSender),
    /// Flush the metrics. This action can only be called after the logger has been configured.
    /// The response is sent using the `OutcomeSender`.
    FlushMetrics(OutcomeSender),
    /// Add a new block device or update one that already exists using the `BlockDeviceConfig` as
    /// input. This action can only be called before the microVM has booted. The response
    /// is sent using the `OutcomeSender`.
    InsertBlockDevice(BlockDeviceConfig, OutcomeSender),
    /// Add a new network interface config or update one that already exists using the
    /// `NetworkInterfaceConfig` as input. This action can only be called before the microVM has
    /// booted. The response is sent using the `OutcomeSender`.
    InsertNetworkDevice(NetworkInterfaceConfig, OutcomeSender),
    #[cfg(feature = "vsock")]
    /// Add a new vsock device or update one that already exists using the
    /// `VsockDeviceConfig` as input. This action can only be called before the microVM has
    /// booted. The response is sent using the `OutcomeSender`.
    InsertVsockDevice(VsockDeviceConfig, OutcomeSender),
    /// Update the size of an existing block device specified by an ID. The ID is the first data
    /// associated with this enum variant. This action can only be called after the microVM is
    /// started. The response is sent using the `OutcomeSender`.
    RescanBlockDevice(String, OutcomeSender),
    /// Set the microVM configuration (memory & vcpu) using `VmConfig` as input. This
    /// action can only be called before the microVM has booted. The action
    /// response is sent using the `OutcomeSender`.
    SetVmConfiguration(VmConfig, OutcomeSender),
    /// Launch the microVM. This action can only be called before the microVM has booted.
    /// The response is sent using the `OutcomeSender`.
    StartMicroVm(OutcomeSender),
    /// Send CTRL+ALT+DEL to the microVM, using the i8042 keyboard function. If an AT-keyboard
    /// driver is listening on the guest end, this can be used to shut down the microVM gracefully.
    SendCtrlAltDel(OutcomeSender),
    /// Update the path of an existing block device. The data associated with this variant
    /// represents the `drive_id` and the `path_on_host`. The response is sent using
    /// the `OutcomeSender`.
    UpdateBlockDevicePath(String, String, OutcomeSender),
    /// Update a network interface, after microVM start. Currently, the only updatable properties
    /// are the RX and TX rate limiters.
    UpdateNetworkInterface(NetworkInterfaceUpdateConfig, OutcomeSender),
    /// Dump the working set of current VM, i.e. all resident memory pages
    DumpWorkingSet(OutcomeSender),
}

/// The enum represents the response sent by the VMM in case of success. The response is either
/// empty, when no data needs to be sent, or an internal VMM structure.
#[derive(Debug)]
pub enum VmmData {
    /// No data is sent on the channel.
    Empty,
    /// The microVM configuration represented by `VmConfig`.
    MachineConfiguration(VmConfig),
}

/// Data type used to communicate between the API and the VMM.
pub type VmmRequestOutcome = std::result::Result<VmmData, VmmActionError>;
/// One shot channel used to send a request.
pub type OutcomeSender = oneshot::Sender<VmmRequestOutcome>;
/// One shot channel used to receive a response.
pub type OutcomeReceiver = oneshot::Receiver<VmmRequestOutcome>;

type Result<T> = std::result::Result<T, Error>;

/// Holds a micro-second resolution timestamp with both the real time and cpu time.
#[derive(Clone, Default)]
pub struct TimestampUs {
    /// Real time in microseconds.
    pub time_us: u64,
    /// Cpu time in microseconds.
    pub cputime_us: u64,
}

/// Describes a KVM context that gets attached to the micro vm instance.
/// It gives access to the functionality of the KVM wrapper as long as every required
/// KVM capability is present on the host.
pub struct KvmContext {
    kvm: Kvm,
    max_memslots: usize,
}

impl KvmContext {
    fn new() -> Result<Self> {

        fn check_cap(kvm: &Kvm, cap: Cap) -> std::result::Result<(), Error> {
            if !kvm.check_extension(cap) {
                return Err(Error::KvmCap(cap));
            }
            Ok(())
        }
        
        let kvm = Kvm::new().map_err(Error::Kvm)?;

        if kvm.get_api_version() != kvm::KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm.get_api_version()));
        }

        //check_cap(&kvm, Cap::Xsave)?;
        //check_cap(&kvm, Cap::Xcrs)?;
        // check_cap(&kvm, Cap::MpState)?;
        // check_cap(&kvm, Cap::VcpuEvents)?;
        check_cap(&kvm, Cap::Irqchip)?;
        check_cap(&kvm, Cap::Ioeventfd)?;
        check_cap(&kvm, Cap::Irqfd)?;
        // check_cap(&kvm, Cap::ImmediateExit)?;
        // #[cfg(target_arch = "x86_64")]
        // check_cap(&kvm, Cap::SetTssAddr)?;
        check_cap(&kvm, Cap::UserMemory)?;
        // check_cap(&kvm, Cap::ReadonlyMem)?;
        // check_cap(&kvm, Cap::SyncMmu)?;
        check_cap(&kvm, Cap::ArmPsci02)?;
        check_cap(&kvm, Cap::DeviceCtrl)?;
        check_cap(&kvm, Cap::MpState)?;
        check_cap(&kvm, Cap::OneReg)?;

        // println!("Meta ta check caps");

        let max_memslots = kvm.get_nr_memslots();

        Ok(KvmContext { kvm, max_memslots })
    }

    fn fd(&self) -> &Kvm {
        &self.kvm
    }

    /// Get the maximum number of memory slots reported by this KVM context.
    pub fn max_memslots(&self) -> usize {
        self.max_memslots
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EpollDispatch {
    Exit,
    Stdin,
    DeviceHandler(usize, DeviceEventT),
    VmmActionRequest,
    WriteMetrics,
    Snap,
}

struct MaybeHandler {
    handler: Option<Box<dyn EpollHandler>>,
    receiver: Receiver<Box<dyn EpollHandler>>,
}

impl MaybeHandler {
    fn new(receiver: Receiver<Box<dyn EpollHandler>>) -> Self {
        MaybeHandler {
            handler: None,
            receiver,
        }
    }
}

struct EpollEvent<T: AsRawFd> {
    fd: T,
}

// Handles epoll related business.
// A glaring shortcoming of the current design is the liberal passing around of raw_fds,
// and duping of file descriptors. This issue will be solved when we also implement device removal.
struct EpollContext {
    epoll_raw_fd: RawFd,
    stdin_index: u64,
    // FIXME: find a different design as this does not scale. This Vec can only grow.
    dispatch_table: Vec<Option<EpollDispatch>>,
    device_handlers: Vec<MaybeHandler>,
    // device_id_to_handler_id: HashMap<(u32, String), usize>,

    // This part of the class relates to incoming epoll events. The incoming events are held in
    // `events[event_index..num_events)`, followed by the events not yet read from `epoll_raw_fd`.

    // events: Vec<epoll::Event>,
    // num_events: usize,
    // event_index: usize,
}

impl EpollContext {
    fn new() -> Result<Self> {

        // const EPOLL_EVENTS_LEN: usize = 100;

        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 stdin event
        // * 2 queue events for virtio block
        // * 4 for virtio net
        // The total is 8 elements; allowing spare capacity to avoid reallocations.
        let mut dispatch_table = Vec::with_capacity(20);
        let stdin_index = dispatch_table.len() as u64;
        dispatch_table.push(None);
        Ok(EpollContext {
            epoll_raw_fd,
            stdin_index,
            dispatch_table,
            device_handlers: Vec::with_capacity(6),
            // device_id_to_handler_id: HashMap::new(),
            // events: vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN],
            // num_events: 0,
            // event_index: 0,
        })
    }

    fn enable_stdin_event(&mut self) -> Result<()> {
        if let Err(e) = epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, self.stdin_index),
        ) {
            // TODO: We just log this message, and immediately return Ok, instead of returning the
            // actual error because this operation always fails with EPERM when adding a fd which
            // has been redirected to /dev/null via dup2 (this may happen inside the jailer).
            // Find a better solution to this (and think about the state of the serial device
            // while we're at it). This also led to commenting out parts of the
            // enable_disable_stdin_test() unit test function.
            warn!("Could not add stdin event to epoll. {:?}", e);
            return Ok(());
        }

        self.dispatch_table[self.stdin_index as usize] = Some(EpollDispatch::Stdin);

        Ok(())
    }

    fn disable_stdin_event(&mut self) -> Result<()> {
        // Ignore failure to remove from epoll. The only reason for failure is
        // that stdin has closed or changed in which case we won't get
        // any more events on the original event_fd anyway.
        let _ = epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, self.stdin_index),
        )
        .map_err(Error::EpollFd);
        self.dispatch_table[self.stdin_index as usize] = None;

        Ok(())
    }

    fn add_event<T>(&mut self, fd: T, token: EpollDispatch) -> Result<EpollEvent<T>>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )
        .map_err(Error::EpollFd)?;
        self.dispatch_table.push(Some(token));

        Ok(EpollEvent { fd })
    }

    /// Given a file descriptor `fd`, and an EpollDispatch token `token`,
    /// associate `token` with an `EPOLLIN` event for `fd`, through the
    /// `dispatch_table`.
    
    // fn add_epollin_event<T: AsRawFd + ?Sized>(
    //     &mut self,
    //     fd: &T,
    //     token: EpollDispatch,
    // ) -> Result<()> {
    //     // The index in the dispatch where the new token will be added.
    //     let dispatch_index = self.dispatch_table.len() as u64;

    //     // Add a new epoll event on `fd`, associated with index
    //     // `dispatch_index`.
    //     epoll::ctl(
    //         self.epoll_raw_fd,
    //         epoll::ControlOptions::EPOLL_CTL_ADD,
    //         fd.as_raw_fd(),
    //         epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
    //     )
    //     .map_err(Error::EpollFd)?;

    //     // Add the associated token at index `dispatch_index`
    //     self.dispatch_table.push(Some(token));

    //     Ok(())
    // }

    fn allocate_tokens(&mut self, count: usize) -> (u64, Sender<Box<dyn EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        for x in 0..count {

            // println!("Paw na pusharw EpollDispatch::DeviceHandler me device_idx:");
            // println!("{}", device_idx);

            self.dispatch_table.push(Some(EpollDispatch::DeviceHandler(
                device_idx,
                x as DeviceEventT,
            )));
        }

        println!("Paw na pusharw device_handler");
        self.device_handlers.push(MaybeHandler::new(receiver));
        println!("Pushara sto device_handlers");

        (dispatch_base, sender)
    }

    // See the below comment for `allocate_virtio_net_tokens`, for an explanation on the returned
    // values.

    fn allocate_virtio_block_tokens(&mut self) -> (virtio::block::EpollConfig, usize) {
        let (dispatch_base, sender) = self.allocate_tokens(BLOCK_EVENTS_COUNT);
        (
            virtio::block::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender),
            self.device_handlers.len() - 1,
        )
    }

    /// Allocates `count` dispatch tokens, simultaneously registering them in
    /// `dispatch_table`. The tokens will be associated with a device.
    /// This device's handler will be added to the end of `device_handlers`.
    /// This returns the index of the first token, and a channel on which to
    /// send an epoll handler for the relevant device.
    
    // fn allocate_tokens_for_device(&mut self, count: usize) -> (u64, Sender<Box<dyn EpollHandler>>) {
    //     let dispatch_base = self.dispatch_table.len() as u64;
    //     let device_idx = self.device_handlers.len();
    //     let (sender, receiver) = channel();

    //     self.dispatch_table.extend((0..count).map(|index| {
    //         Some(EpollDispatch::DeviceHandler(
    //             device_idx,
    //             index as DeviceEventT,
    //         ))
    //     }));
    //     self.device_handlers.push(MaybeHandler::new(receiver));

    //     (dispatch_base, sender)
    // }

    /// Allocate tokens for a virtio device, as with `allocate_tokens_for_device`,
    /// but also call T::new to create a device handler for the device. This handler
    /// will then be associated to a given `device_id` through the `device_id_to_handler_id`
    /// table. Finally, return the handler.
    
    // fn allocate_tokens_for_virtio_device<T: EpollConfigConstructor>(
    //     &mut self,
    //     type_id: u32,
    //     device_id: &str,
    //     count: usize,
    // ) -> T {
    //     let (dispatch_base, sender) = self.allocate_tokens_for_device(count);

    //     self.device_id_to_handler_id.insert(
    //         (type_id, device_id.to_string()),
    //         self.device_handlers.len() - 1,
    //     );

    //     T::new(dispatch_base, self.epoll_raw_fd, sender)
    // }

    // Horrible, horrible hack, because velocity: return a tuple (epoll_config, handler_idx),
    // since, for some reason, the VMM doesn't own and cannot contact its live devices. I.e.
    // after VM start, the device objects become some kind of useless hollow husks, their
    // actual data being _moved_ to their corresponding `EpollHandler`s.
    // The `handler_idx`, that we're returning here, can be used by the VMM to contact the
    // device, by faking an event, sent straight to the device `EpollHandler`.

    fn allocate_virtio_net_tokens(&mut self) -> (virtio::net::EpollConfig, usize) {
        let (dispatch_base, sender) = self.allocate_tokens(virtio::net::NET_EVENTS_COUNT);
        (
            virtio::net::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender),
            self.device_handlers.len() - 1,
        )
    }

    // #[cfg(feature = "vsock")]
    fn allocate_virtio_vsock_tokens(&mut self) -> virtio::vsock::EpollConfig {
        let (dispatch_base, sender) =
            self.allocate_tokens(virtio::vsock::VSOCK_EVENTS_COUNT);
        virtio::vsock::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    fn get_device_handler(&mut self, device_idx: usize) -> Result<&mut dyn EpollHandler> {
        let maybe = &mut self.device_handlers[device_idx];
        match maybe.handler {
            Some(ref mut v) => Ok(v.as_mut()),
            None => {
                // This should only be called in response to an epoll trigger.
                // Moreover, this branch of the match should only be active on the first call
                // (the first epoll event for this device), therefore the channel is guaranteed
                // to contain a message for the first epoll event since both epoll event
                // registration and channel send() happen in the device activate() function.
                let received = maybe
                    .receiver
                    .try_recv()
                    .map_err(|_| Error::DeviceEventHandlerNotFound)?;
                Ok(maybe.handler.get_or_insert(received).as_mut())
            }
        }
    }



    // fn get_device_handler_by_handler_id(&mut self, id: usize) -> Result<&mut dyn EpollHandler> {
    //     let maybe = &mut self.device_handlers[id];
    //     match maybe.handler {
    //         Some(ref mut v) => Ok(v.as_mut()),
    //         None => {
    //             // This should only be called in response to an epoll trigger.
    //             // Moreover, this branch of the match should only be active on the first call
    //             // (the first epoll event for this device), therefore the channel is guaranteed
    //             // to contain a message for the first epoll event since both epoll event
    //             // registration and channel send() happen in the device activate() function.
    //             let received = maybe
    //                 .receiver
    //                 .try_recv()
    //                 .map_err(|_| Error::DeviceEventHandlerNotFound)?;
    //             Ok(maybe.handler.get_or_insert(received).as_mut())
    //         }
    //     }
    // }

    // fn get_device_handler_by_device_id<T: EpollHandler + 'static>(
    //     &mut self,
    //     type_id: u32,
    //     device_id: &str,
    // ) -> Result<&mut T> {
    //     let handler_id = *self
    //         .device_id_to_handler_id
    //         .get(&(type_id, device_id.to_string()))
    //         .ok_or(Error::DeviceEventHandlerNotFound)?;
    //     let device_handler = self.get_device_handler_by_handler_id(handler_id)?;
    //     device_handler
    //         .as_mut_any()
    //         .downcast_mut::<T>()
    //         .ok_or(Error::DeviceEventHandlerInvalidDowncast)
    // }

    // /// Gets the next event from `epoll_raw_fd`.
    // fn get_event(&mut self) -> Result<epoll::Event> {
    //     // Check if no events are left in `events`:
    //     while self.num_events == self.event_index {
    //         // If so, get more events.
    //         // Note that if there is an error, we propagate it.
    //         self.num_events =
    //             epoll::wait(self.epoll_raw_fd, -1, &mut self.events[..]).map_err(Error::Poll)?;
    //         // And reset the event_index.
    //         self.event_index = 0;
    //     }

    //     // Now, move our position in the stream.
    //     self.event_index += 1;

    //     // And return the appropriate event.
    //     Ok(self.events[self.event_index - 1])
    // }

}

impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.epoll_raw_fd) };
        if rc != 0 {
            warn!("Cannot close epoll.");
        }
    }
}




struct KernelConfig {
    cmdline: kernel_cmdline::Cmdline,
    kernel_file: File,
    // cmdline_addr: GuestAddress,
}

struct Vmm {
    kvm: KvmContext,

    vm_config: VmConfig,
    shared_info: Arc<RwLock<InstanceInfo>>,

    stdin_handle: io::Stdin,

    // Guest VM core resources.
    guest_memory: Option<GuestMemory>,
    kernel_config: Option<KernelConfig>,
    vcpus_handles: Vec<thread::JoinHandle<()>>,
    exit_evt: Option<EpollEvent<EventFd>>,
    vm: Vm,

    // Guest VM devices.
    mmio_device_manager: Option<MMIODeviceManager>,
    legacy_device_manager: LegacyDeviceManager,
    drive_handler_id_map: HashMap<String, usize>,
    net_handler_id_map: HashMap<String, usize>,

    // Device configurations.
    // If there is a Root Block Device, this should be added as the first element of the list.
    // This is necessary because we want the root to always be mounted on /dev/vda.
    block_device_configs: BlockDeviceConfigs,
    network_interface_configs: NetworkInterfaceConfigs,
    #[cfg(feature = "vsock")]
    vsock_device_configs: VsockDeviceConfigs,

    epoll_context: EpollContext,

    // API resources.
    api_event: EpollEvent<EventFd>,
    from_api: Receiver<Box<VmmAction>>,

    write_metrics_event: EpollEvent<TimerFd>,

    // The level of seccomp filtering used. Seccomp filters are loaded before executing guest code.
    seccomp_level: u32,

    // Snapshot
    // load
    load_dir: Vec<PathBuf>,
    snap_to_load: Option<Snapshot>,
    // dump
    dump_dir: Option<PathBuf>,
    snap_to_dump: Option<Snapshot>,
    snap_receiver: Option<Receiver<VcpuInfo>>,
    snap_sender: Option<Sender<VcpuInfo>>,
    snap_evt: EventFd,

    // restore memory by copying
    base: MemoryFileOption,
    huge_page: bool,
    //diff_dirs: Vec<PathBuf>,
    diff: MemoryFileOption,
    load_ws: bool,
}

impl Vmm {
    fn new(
        api_shared_info: Arc<RwLock<InstanceInfo>>,
        api_event_fd: EventFd,
        from_api: Receiver<Box<VmmAction>>,
        seccomp_level: u32,
        snapfaas_config: SnapFaaSConfig,
    ) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        // If this fails, it's fatal; using expect() to crash.
        let api_event = epoll_context
            .add_event(api_event_fd, EpollDispatch::VmmActionRequest)
            .expect("Cannot add API eventfd to epoll.");

        let write_metrics_event = epoll_context
            .add_event(
                // non-blocking & close on exec
                TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(Error::TimerFd)?,
                EpollDispatch::WriteMetrics,
            )
            .expect("Cannot add write metrics TimerFd to epoll.");

        let block_device_configs = BlockDeviceConfigs::new();
        let kvm = KvmContext::new()?;
        let vm = Vm::new(kvm.fd()).map_err(Error::Vm)?;

        // Snapshot
        let dump_dir = snapfaas_config.dump_dir;
        let (snap_sender, snap_receiver) = match dump_dir {
            Some(_) => {
                let (sender, receiver) = channel();
                (Some(sender), Some(receiver))
            },
            None => (None, None)
        };
        let evtfd = EventFd::new().expect("Cannot create snap event fd");
        let snap_evt = evtfd.try_clone().expect("Cannot clone snap event fd");
        epoll_context.add_event(evtfd, EpollDispatch::Snap).expect("Cannot add snap event fd");

        Ok(Vmm {
            kvm,
            vm_config: VmConfig::default(),
            shared_info: api_shared_info,
            stdin_handle: io::stdin(),
            guest_memory: None,
            kernel_config: None,
            vcpus_handles: vec![],
            exit_evt: None,
            vm,
            mmio_device_manager: None,
            legacy_device_manager: LegacyDeviceManager::new().map_err(Error::CreateLegacyDevice)?,
            block_device_configs,
            drive_handler_id_map: HashMap::new(),
            net_handler_id_map: HashMap::new(),
            network_interface_configs: NetworkInterfaceConfigs::new(),
            #[cfg(feature = "vsock")]
            vsock_device_configs: VsockDeviceConfigs::new(),
            epoll_context,
            api_event,
            from_api,
            write_metrics_event,
            seccomp_level,
            load_dir: snapfaas_config.load_dir,
            snap_to_load: snapfaas_config.parsed_json,
            dump_dir,
            snap_to_dump: None,
            snap_receiver,
            snap_sender,
            snap_evt,
            base: snapfaas_config.base,
            huge_page: snapfaas_config.huge_page,
            //diff_dirs: snapfaas_config.diff_dirs,
            diff: snapfaas_config.diff,
            load_ws: snapfaas_config.load_ws,
        })
    }

    fn update_drive_handler(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        if let Some(device_idx) = self.drive_handler_id_map.get(drive_id) {
            match self.epoll_context.get_device_handler(*device_idx) {
                Ok(handler) => {
                    match handler.handle_event(
                        virtio::block::FS_UPDATE_EVENT,
                        *device_idx as u32,
                        EpollHandlerPayload::DrivePayload(disk_image),
                        epoll::Events::empty(),
                    ) {
                        Err(devices::Error::PayloadExpected) => {
                            panic!("Received update disk image event with empty payload.")
                        }
                        Err(devices::Error::UnknownEvent { device, event }) => {
                            panic!("Unknown event: {:?} {:?}", device, event)
                        }
                        _ => Ok(()),
                    }
                }
                Err(e) => {
                    warn!("invalid handler for device {}: {:?}", device_idx, e);
                    Err(DriveError::BlockDeviceUpdateFailed)
                }
            }
        } else {
            Err(DriveError::BlockDeviceUpdateFailed)
        }
    }

    // Attaches all block devices from the BlockDevicesConfig.

    fn attach_block_devices_snapshot(
        &mut self,
    ) -> std::result::Result<(), StartMicrovmError> {
        let epoll_context = &mut self.epoll_context;

        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for drive_config in self.block_device_configs.config_list.iter_mut() {

            println!("drive config: {:?}", drive_config);

            // Add the block device from file.
            let block_file = OpenOptions::new()
                .read(true)
                .write(!drive_config.is_read_only)
                // .custom_flags(if drive_config.odirect { libc::O_DIRECT } else { 0 })
                .open(&drive_config.path_on_host)
                .map_err(StartMicrovmError::OpenBlockDevice)?;

            // let epoll_config = epoll_context.allocate_virtio_block_tokens();
            let (epoll_config, handler_idx) = epoll_context.allocate_virtio_block_tokens();
            self.drive_handler_id_map
                .insert(drive_config.drive_id.clone(), handler_idx);

            let rate_limiter = match drive_config.rate_limiter {
                Some(rlim_cfg) => Some(
                    rlim_cfg
                        .into_rate_limiter()
                        .map_err(StartMicrovmError::CreateRateLimiter)?,
                ),
                None => None,
            };

            let block_box = Box::new(
                devices::virtio::Block::new(
                    block_file,
                    drive_config.is_read_only,
                    epoll_config,
                    rate_limiter,
                )
                .map_err(StartMicrovmError::CreateBlockDevice)?,
            );
            device_manager
                .register_virtio_device(
                    self.vm.get_fd(),
                    block_box,
                    None,
                    TYPE_BLOCK,
                    &drive_config.drive_id,
                )
                .map_err(StartMicrovmError::RegisterBlockDevice)?;
        }

        Ok(())
    }

    // Attaches all block devices from the BlockDevicesConfig.
    fn attach_block_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        if self.block_device_configs.has_root_block_device() {
            // If no PARTUUID was specified for the root device, try with the /dev/vda.
            if !self.block_device_configs.has_partuuid_root() {
                kernel_config
                    .cmdline
                    .insert_str("root=/dev/vda")
                    .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;

                if self.block_device_configs.has_read_only_root() {
                    kernel_config
                        .cmdline
                        .insert_str("ro,norecovery")
                        .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;
                } else {
                    kernel_config
                        .cmdline
                        .insert_str("rw")
                        .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;
                }
            }
        }

        let epoll_context = &mut self.epoll_context;
        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for drive_config in self.block_device_configs.config_list.iter_mut() {
            // Add the block device from file.
            let block_file = OpenOptions::new()
                .read(true)
                .write(!drive_config.is_read_only)
                .open(&drive_config.path_on_host)
                .map_err(StartMicrovmError::OpenBlockDevice)?;

            if drive_config.is_root_device && drive_config.get_partuuid().is_some() {
                kernel_config
                    .cmdline
                    .insert_str(format!(
                        "root=PARTUUID={}",
                        //The unwrap is safe as we are firstly checking that partuuid is_some().
                        drive_config.get_partuuid().unwrap()
                    ))
                    .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;
                if drive_config.is_read_only {
                    kernel_config
                        .cmdline
                        .insert_str("ro")
                        .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;
                } else {
                    kernel_config
                        .cmdline
                        .insert_str("rw")
                        .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;
                }
            }

            let (epoll_config, handler_idx) = epoll_context.allocate_virtio_block_tokens();

            self.drive_handler_id_map
                .insert(drive_config.drive_id.clone(), handler_idx);
            let rate_limiter = match drive_config.rate_limiter {
                Some(rlim_cfg) => Some(
                    rlim_cfg
                        .into_rate_limiter()
                        .map_err(StartMicrovmError::CreateRateLimiter)?,
                ),
                None => None,
            };

            let block_box = Box::new(
                devices::virtio::Block::new(
                    block_file,
                    drive_config.is_read_only,
                    epoll_config,
                    rate_limiter,
                )
                .map_err(StartMicrovmError::CreateBlockDevice)?,
            );
            device_manager
                .register_virtio_device(
                    self.vm.get_fd(),
                    block_box,
                    Some(&mut kernel_config.cmdline),
                    TYPE_BLOCK,
                    &drive_config.drive_id,
                )
                .map_err(StartMicrovmError::RegisterBlockDevice)?;
        }

        Ok(())
    }

    fn attach_net_devices_snapshot(
        &mut self,
    ) -> std::result::Result<(), StartMicrovmError> {

        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for cfg in self.network_interface_configs.iter_mut() {

            // let kernel_config = self
            //     .kernel_config
            //     .as_mut()
            //     .ok_or(StartMicrovmError::MissingKernelConfig)?;

            let (epoll_config, handler_idx) = self.epoll_context.allocate_virtio_net_tokens();
            self.net_handler_id_map
                .insert(cfg.iface_id.clone(), handler_idx);

            let allow_mmds_requests = cfg.allow_mmds_requests();
            let rx_rate_limiter = match cfg.rx_rate_limiter {
                Some(rlim) => Some(
                    rlim.into_rate_limiter()
                        .map_err(StartMicrovmError::CreateRateLimiter)?,
                ),
                None => None,
            };
            let tx_rate_limiter = match cfg.tx_rate_limiter {
                Some(rlim) => Some(
                    rlim.into_rate_limiter()
                        .map_err(StartMicrovmError::CreateRateLimiter)?,
                ),
                None => None,
            };

            if let Some(tap) = cfg.take_tap() {
                let net_box = Box::new(
                    devices::virtio::Net::new_with_tap(
                        tap,
                        cfg.guest_mac(),
                        epoll_config,
                        rx_rate_limiter,
                        tx_rate_limiter,
                        allow_mmds_requests,
                    )
                    .map_err(StartMicrovmError::CreateNetDevice)?,
                );

                device_manager
                    .register_virtio_device(
                        self.vm.get_fd(),
                        net_box,
                        None,
                        TYPE_NET,
                        &cfg.iface_id,
                    )
                    .map_err(StartMicrovmError::RegisterNetDevice)?;

                // device_manager
                    // .register_virtio_device(self.vm.get_fd(), net_box, None, None)
                    // .map_err(StartMicrovmError::RegisterNetDevice)?;
            } else {
                return Err(StartMicrovmError::NetDeviceNotConfigured)?;
            }
        }
        Ok(())
    }

    fn attach_net_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for cfg in self.network_interface_configs.iter_mut() {

            let (epoll_config, handler_idx) = self.epoll_context.allocate_virtio_net_tokens();

            self.net_handler_id_map
                .insert(cfg.iface_id.clone(), handler_idx);

            let allow_mmds_requests = cfg.allow_mmds_requests();

            let rx_rate_limiter = match cfg.rx_rate_limiter {
                Some(rlim) => Some(
                    rlim.into_rate_limiter()
                        .map_err(StartMicrovmError::CreateRateLimiter)?,
                ),
                None => None,
            };

            // let rx_rate_limiter = cfg
                // .rx_rate_limiter
                // .map(vmm_config::RateLimiterConfig::into_rate_limiter)
                // .transpose()
                // .map_err(StartMicrovmError::CreateRateLimiter)?;

            let tx_rate_limiter = match cfg.tx_rate_limiter {
                Some(rlim) => Some(
                    rlim.into_rate_limiter()
                        .map_err(StartMicrovmError::CreateRateLimiter)?,
                ),
                None => None,
            };

            // let tx_rate_limiter = cfg
            //     .tx_rate_limiter
            //     .map(vmm_config::RateLimiterConfig::into_rate_limiter)
            //     .transpose()
            //     .map_err(StartMicrovmError::CreateRateLimiter)?;

            if let Some(tap) = cfg.take_tap() {
                let net_box = Box::new(
                    devices::virtio::Net::new_with_tap(
                        tap,
                        cfg.guest_mac(),
                        epoll_config,
                        rx_rate_limiter,
                        tx_rate_limiter,
                        allow_mmds_requests,
                    )
                    .map_err(StartMicrovmError::CreateNetDevice)?,
                );

                device_manager
                    .register_virtio_device(
                        self.vm.get_fd(),
                        net_box,
                        Some(&mut kernel_config.cmdline),
                        TYPE_NET,
                        &cfg.iface_id,
                    )
                    .map_err(StartMicrovmError::RegisterNetDevice)?;
            } else {
                return Err(StartMicrovmError::NetDeviceNotConfigured)?;
            }
        }
        Ok(())
    }

    // #[cfg(feature = "vsock")]
    fn attach_vsock_devices_snapshot(
        &mut self,
    ) -> std::result::Result<(), StartMicrovmError> {

        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for cfg in self.vsock_device_configs.iter() {

            // let kernel_config = self
            //     .kernel_config
            //     .as_mut()
            //     .ok_or(StartMicrovmError::MissingKernelConfig)?;

            let backend = devices::virtio::vsock::VsockUnixBackend::new(
                u64::from(cfg.guest_cid),
                cfg.uds_path.clone(),
            )
            .map_err(StartMicrovmError::CreateVsockBackend)?;

            let epoll_config = self.epoll_context.allocate_virtio_vsock_tokens();

            let vsock_box = Box::new(
                devices::virtio::vsock::Vsock::new(u64::from(cfg.guest_cid), epoll_config, backend)
                    .map_err(StartMicrovmError::CreateVsockDevice)?,
            );

            device_manager
                .register_virtio_device(
                    self.vm.get_fd(),
                    vsock_box,
                    None,
                    virtio::TYPE_VSOCK,
                    &cfg.vsock_id,
                )
                .map_err(StartMicrovmError::RegisterVsockDevice)?;
        }
        Ok(())
    }

    // #[cfg(feature = "vsock")]
    fn attach_vsock_devices(
        &mut self,
        // device_manager: &mut MMIODeviceManager,
    ) -> std::result::Result<(), StartMicrovmError> {

        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        // println!("Pirame kernel_config");
        
        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        // println!("Pirame kernel_config");

        for cfg in self.vsock_device_configs.iter() {

            let backend = devices::virtio::vsock::VsockUnixBackend::new(
                u64::from(cfg.guest_cid),
                cfg.uds_path.clone(),
            )
            .map_err(StartMicrovmError::CreateVsockBackend)?;

            let epoll_config = self.epoll_context.allocate_virtio_vsock_tokens();

            // println!("Pirame epoll_config");

            let vsock_box = Box::new(
                devices::virtio::Vsock::new(u64::from(cfg.guest_cid), epoll_config, backend)
                    .map_err(StartMicrovmError::CreateVsockDevice)?,
            );

            // println!("Prin tin register_virtio_device");

            device_manager
                .register_virtio_device(
                    self.vm.get_fd(),
                    vsock_box,
                    Some(&mut kernel_config.cmdline),
                    virtio::TYPE_VSOCK,
                    &cfg.vsock_id,
                )
                .map_err(StartMicrovmError::RegisterVsockDevice)?;

            // println!("Meta tin register_virtio_device");
        }
        Ok(())
    }


    fn configure_kernel(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    fn flush_metrics(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        if let Err(e) = self.write_metrics() {
            if let LoggerError::NeverInitialized(s) = e {
                return Err(VmmActionError::Logger(
                    ErrorKind::User,
                    LoggerConfigError::FlushMetrics(s),
                ));
            } else {
                return Err(VmmActionError::Logger(
                    ErrorKind::Internal,
                    LoggerConfigError::FlushMetrics(e.to_string()),
                ));
            }
        }
        Ok(VmmData::Empty)
    }

    // #[cfg(target_arch = "x86_64")]
    fn log_dirty_pages(&mut self) {
        // If we're logging dirty pages, post the metrics on how many dirty pages there are.
        if LOGGER.flags() | LogOption::LogDirtyPages as usize > 0 {
            METRICS.memory.dirty_pages.add(self.get_dirty_page_count());
        }
    }

    fn write_metrics(&mut self) -> result::Result<(), LoggerError> {
        // The dirty pages are only available on x86_64.
        // #[cfg(target_arch = "x86_64")]
        self.log_dirty_pages();
        LOGGER.log_metrics()
    }

    fn init_guest_memory(&mut self) -> std::result::Result<(), StartMicrovmError> {
        let mem_size = self
            .vm_config
            .mem_size_mib
            .ok_or(StartMicrovmError::GuestMemory(
                memory_model::GuestMemoryError::MemoryNotInitialized,
            ))?
            << 20;
        let arch_mem_regions = arch::aarch64::arch_memory_regions(mem_size);

        println!("arch_mem_regions: {:?}", arch_mem_regions);

        if !self.load_dir.is_empty() {
            self.guest_memory =
                Some(GuestMemory::new_from_snapshot(
                        &arch_mem_regions,
                        &self.load_dir,
                        &self.snap_to_load.as_ref().unwrap().memory_meta,
                        self.load_ws, // only eagerly load the working set
                        self.huge_page,
                        self.base, // a base snapshot should always be provided
                        self.diff, // only valid when a diff snapshot is provided
                        !self.load_dir.is_empty() && self.dump_dir.is_some(), // only clear soft dirty bits when generating diff snapshots
                    ).map_err(StartMicrovmError::GuestMemory)?);
        } else {
            self.guest_memory =
                Some(GuestMemory::new(&arch_mem_regions, self.dump_dir.is_some())
                    .map_err(StartMicrovmError::GuestMemory)?);
        }
        self.vm
            .memory_init(
                self.guest_memory
                    .clone()
                    .ok_or(StartMicrovmError::GuestMemory(
                        memory_model::GuestMemoryError::MemoryNotInitialized,
                    ))?,
                &self.kvm,
            )
            .map_err(StartMicrovmError::ConfigureVm)?;
        Ok(())
    }

    fn check_health(&self) -> std::result::Result<(), StartMicrovmError> {
        if self.kernel_config.is_none() {
            return Err(StartMicrovmError::MissingKernelConfig)?;
        }
        Ok(())
    }

    fn init_mmio_device_manager(&mut self) -> std::result::Result<(), StartMicrovmError> {

        if self.mmio_device_manager.is_some() {
            return Ok(());
        }

        let guest_mem = self
            .guest_memory
            .clone()
            .ok_or(StartMicrovmError::GuestMemory(
                memory_model::GuestMemoryError::MemoryNotInitialized,
            ))?;

        // Instantiate the MMIO device manager.
        // 'mmio_base' address has to be an address which is protected by the kernel
        // and is architectural specific.
        let device_manager = MMIODeviceManager::new(
            guest_mem.clone(),
            &mut (arch::aarch64::MMIO_MEM_START as u64),
            (arch::aarch64::layout::IRQ_BASE, arch::aarch64::layout::IRQ_MAX),
        );
        self.mmio_device_manager = Some(device_manager);

        Ok(())
    }

    fn attach_virtio_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {

        self.init_mmio_device_manager()?;

        // let mut device_manager = self.mmio_device_manager.clone().unwrap();

        if !self.load_dir.is_empty() {
            // let mut device_manager = self.mmio_device_manager.as_mut().unwrap();
            println!("Prin tin attach_block_devices_snapshot");
            self.attach_block_devices_snapshot()?;
            println!("Perasa attach_block_devices_snapshot");
            self.attach_net_devices_snapshot()?;
            println!("Perasa attach_net_devices_snapshot");
            // #[cfg(feature = "vsock")]
            self.attach_vsock_devices_snapshot()?;
            println!("Perasa attach_vsock_devices_snapshot");
        } else {
            self.attach_block_devices()?;
            // println!("Perasame attach_block_devices");
            self.attach_net_devices()?;
            // println!("Perasame attach_net_devices");
            self.attach_vsock_devices()?;
            // println!("Perasame attach_vsock_devices");
            // #[cfg(feature = "vsock")]
            // {
                // let guest_mem = self
                    // .guest_memory
                    // .clone()
                    // .ok_or(StartMicrovmError::GuestMemory(
                        // memory_model::GuestMemoryError::MemoryNotInitialized,
                    // ))?;
                // self.attach_vsock_devices()?;
                // println!("Perasame attach_vsock_devices");
            // }
        }

        // self.mmio_device_manager = Some(device_manager);
        Ok(())
    }

    fn setup_interrupt_controller(&mut self) -> std::result::Result<(), StartMicrovmError> {

        let vcpu_count = self
            .vm_config
            .vcpu_count
            .ok_or(StartMicrovmError::VcpusNotConfigured)?;

        self.vm
            .setup_irqchip(
                vcpu_count,
                self.snap_to_load.as_ref(),
            )
            .map_err(StartMicrovmError::ConfigureVm)?;
        // #[cfg(target_arch = "x86_64")]
        // self.vm
            // .create_pit()
            // .map_err(StartMicrovmError::ConfigureVm)?;
        Ok(())
    }

    // fn attach_legacy_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
    //     self.legacy_device_manager
    //         .register_devices()
    //         .map_err(StartMicrovmError::LegacyIOBus)?;

    //     Ok(())
    //

    fn attach_legacy_devices_aarch64(&mut self) -> std::result::Result<(), StartMicrovmError> {

        self.init_mmio_device_manager()?;

        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        if self.load_dir.is_empty() {
            let kernel_config = self
                .kernel_config
                .as_mut()
                .ok_or(StartMicrovmError::MissingKernelConfig)?;

            if kernel_config.cmdline.as_str().contains("console=") {
                device_manager
                    .register_mmio_serial(self.vm.get_fd(), &mut kernel_config.cmdline)
                    .map_err(StartMicrovmError::RegisterMMIODevice)?;
            }
        }

        device_manager
            .register_mmio_rtc(self.vm.get_fd())
            .map_err(StartMicrovmError::RegisterMMIODevice)?;

        Ok(())
    }



    fn get_mmio_device_info(&self) -> Option<&HashMap<(DeviceType, String), MMIODeviceInfo>> {
        if let Some(ref device_manager) = self.mmio_device_manager {
            Some(device_manager.get_device_info())
        } else {
            None
        }
    }

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) and configured before
    // setting up the IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    fn create_vcpus(
        &mut self,
        entry_addr: GuestAddress,
        request_ts: TimestampUs,
    ) -> std::result::Result<Vec<Vcpu>, StartMicrovmError> {

        // println!("Bika create_vcpu");

        let vcpu_count = self
            .vm_config
            .vcpu_count
            .ok_or(StartMicrovmError::VcpusNotConfigured)?;
        
        let mut vcpus = Vec::with_capacity(vcpu_count as usize);

        let vm_memory = self
            .vm
            .get_memory()
            .expect("Cannot create vCPUs before guest memory initialization!");

        for cpu_id in 0..vcpu_count {
            
            let mut vcpu = Vcpu::new(cpu_id, &self.vm, request_ts.clone())
                .map_err(StartMicrovmError::Vcpu)?;

            // WE NEED TO ADD VCPU LOAD STATE FUNCTIONALITY
            
            // let maybe_vcpu_state = match self.snap_to_load.as_ref() {
                // Some(snap) => Some(&snap.vcpu_states[cpu_id as usize]),
                // None => None,
            // };

            // vcpu.fd.init(&self.vm.fd).unwrap();
        
            // #[cfg(target_arch = "x86_64")]
            // vcpu.configure(&self.vm_config, entry_addr, &self.vm, maybe_vcpu_state)
                // .map_err(StartMicrovmError::VcpuConfigure)?;

            vcpu.fd.init(&self.vm.fd).unwrap();

            // Check that configure_aarch64() is in the right place (propably move it outside create_vcpus()?)
            vcpu.configure_aarch64(vm_memory, entry_addr)
                .map_err(StartMicrovmError::VcpuConfigure)?;

            // println!("Prin tin push vcpu");
    
            vcpus.push(vcpu);
        }
        Ok(vcpus)
    }

    fn start_vcpus(&mut self, mut vcpus: Vec<Vcpu>) -> std::result::Result<(), StartMicrovmError> {
        // vm_config has a default value for vcpu_count.
        let vcpu_count = self
            .vm_config
            .vcpu_count
            .ok_or(StartMicrovmError::VcpusNotConfigured)?;
        assert_eq!(
            vcpus.len(),
            vcpu_count as usize,
            "The number of vCPU fds is corrupted!"
        );

        self.vcpus_handles.reserve(vcpu_count as usize);

        let vcpus_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
        let vcpus_snap_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        // We're going in reverse so we can `.pop()` on the vec and still maintain order.
        for cpu_id in (0..vcpu_count).rev() {
            let vcpu_thread_barrier = vcpus_thread_barrier.clone();
            let vcpu_snap_barrier = vcpus_snap_barrier.clone();
            // If the lock is poisoned, it's OK to panic.

            // let vcpu_exit_evt = self
                // .legacy_device_manager
                // .i8042
                // .lock()
                // .expect("Failed to start VCPUs due to poisoned i8042 lock")
                // .get_reset_evt_clone()
                // .map_err(|_| StartMicrovmError::EventFd)?;

            // let vcpu_exit_evt = EventFd::new().expect("Cannot create snap event fd");
                // .map_err(Error::EventFd)
                // .map_err(Internal)?;

            let vcpu_exit_evt =
                EventFd::new().map_err(|_| StartMicrovmError::EventFd)?;

            let vcpu_snap_evt = self.snap_evt.try_clone().map_err(|_| StartMicrovmError::EventFd)?;

            // `unwrap` is safe since we are asserting that the `vcpu_count` is equal to the number
            // of items of `vcpus` vector.
            let mut vcpu = vcpus.pop().unwrap();

            // HERE WE HAVE TO SET MMIO_BUS

            // let device_manager = self
            //     .mmio_device_manager
            //     .as_ref()
            //     .ok_or(StartMicrovmError::DeviceManager)?;

            // let mmio_bus = device_manager.bus.clone();

            // vcpu.set_mmio_bus(mmio_bus);

            if let Some(ref mmio_device_manager) = self.mmio_device_manager {
                vcpu.set_mmio_bus(mmio_device_manager.bus.clone());
            }

            let seccomp_level = self.seccomp_level;
            //let from_snapshot = self.load_dir.is_some();
            let sender = self.snap_sender.clone();
            self.vcpus_handles.push(
                thread::Builder::new()
                    .name(format!("fc_vcpu{}", cpu_id))
                    .spawn(move || {
                        vcpu.run(vcpu_thread_barrier,
                                 vcpu_snap_barrier,
                                 seccomp_level,
                                 vcpu_exit_evt,
                                 vcpu_snap_evt,
                                 sender,
                                 //from_snapshot,
                                 );
                    })
                    .map_err(StartMicrovmError::VcpuSpawn)?,
            );
        }

        // Load seccomp filters for the VMM thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        default_syscalls::set_seccomp_level(self.seccomp_level)
            .map_err(StartMicrovmError::SeccompFilters)?;

        vcpus_thread_barrier.wait();

        Ok(())
    }

    fn load_kernel(&mut self) -> std::result::Result<GuestAddress, StartMicrovmError> {
        // This is the easy way out of consuming the value of the kernel_cmdline.
        // TODO: refactor the kernel_cmdline struct in order to have a CString instead of a String.

        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;
        
        // let cmdline_cstring = CString::new(kernel_config.cmdline.clone()).map_err(|_| {
            // StartMicrovmError::KernelCmdline(kernel_cmdline::Error::InvalidAscii.to_string())
        // })?;

        // It is safe to unwrap because the VM memory was initialized before in vm.memory_init().
        let vm_memory = self.vm.get_memory().ok_or(StartMicrovmError::GuestMemory(
            memory_model::GuestMemoryError::MemoryNotInitialized,
        ))?;

        // println!("Prin tin kernel_loader::load_kernel");

        let entry_addr = kernel_loader::load_kernel(
            vm_memory,
            &mut kernel_config.kernel_file,
            arch::aarch64::get_kernel_start().try_into().unwrap(),
        )
        .map_err(StartMicrovmError::KernelLoader)?;

        // This is x86_64 specific since on aarch64 the commandline will be specified through the FDT.
        // #[cfg(target_arch = "x86_64")]
        // kernel_loader::load_cmdline(vm_memory, kernel_config.cmdline_addr, &cmdline_cstring)
            // .map_err(StartMicrovmError::LoadCommandline)?;

        Ok(entry_addr)
    }

    fn configure_system(&mut self, vcpus: &mut [Vcpu], mut entry_addr: GuestAddress) -> std::result::Result<(), StartMicrovmError> {

        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        // It is safe to unwrap because the VM memory was initialized before in vm.memory_init().
        let vm_memory = self.vm.get_memory().ok_or(StartMicrovmError::GuestMemory(
            memory_model::GuestMemoryError::MemoryNotInitialized,
        ))?;

        // The vcpu_count has a default value. We shouldn't have gotten to this point without
        // having set the vcpu count.
        // let vcpu_count = self
            // .vm_config
            // .vcpu_count
            // .ok_or(StartMicrovmError::VcpusNotConfigured)?;

        // println!("Prin tin aarch64 configure_system");

        let vcpu_mpidr = vcpus.into_iter().map(|cpu| cpu.get_mpidr()).collect();

        arch::aarch64::configure_system(
            vm_memory,
            &kernel_config
                .cmdline
                .as_cstring()
                .unwrap(),
                // .map_err(StartMicrovmError::LoadCommandline)?,
            vcpu_mpidr,
            self.get_mmio_device_info(),
            self.vm.get_irqchip(),
        )
        .map_err(StartMicrovmError::ConfigureSystem)?;

        // println!("Meta tin aarch64 configure_system");

        self.configure_stdin();

        Ok(())
    }

    fn configure_stdin(&self) -> std::result::Result<(), StartMicrovmError> {
        // Set raw mode for stdin.
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(StartMicrovmError::CreateRateLimiter)
    }



    fn register_events(&mut self) -> std::result::Result<(), StartMicrovmError> {
        // If the lock is poisoned, it's OK to panic.
        
        // let event_fd = self
            // .legacy_device_manager
            // .i8042
            // .lock()
            // .expect("Failed to register events on the event fd due to poisoned lock")
            // .get_reset_evt_clone()
            // .map_err(|_| StartMicrovmError::EventFd)?;
        // let exit_epoll_evt = self
            // .epoll_context
            // .add_event(event_fd, EpollDispatch::Exit)
            // .map_err(|_| StartMicrovmError::RegisterEvent)?;
        // self.exit_evt = Some(exit_epoll_evt);

        self.epoll_context
            .enable_stdin_event()
            .map_err(|_| StartMicrovmError::RegisterEvent)?;

        Ok(())
    }

    fn restore_block_device(&mut self, index: u64) {
        //manually replay writes to mmio device
        // let device_manager = self.mmio_device_manager.as_mut().unwrap();
        // let temp = device_manager.get_device_base();
        // let base = temp + index*4096; // index: rootfs=0, appfs=1
        // the addr of the first of the block devs (base)
        let base = 1073745920 + index*4096; // index: rootfs=0, appfs=1
        let bus = self.mmio_device_manager.as_ref().unwrap().bus.clone();
        let mut data = [0u8; 4];
        let zero = [0u8; 4];

        // 0x70: update_driver_status
        // Reading from this register returns the current device status flags. 
        // Writing non-zero values to this register sets the status flags, indicating the driver progress. 
        // Writing zero (0x0) to this register triggers a device reset
        // 0x14: features_select
        // Writing to this register selects a set of 32 device feature bits accessible by reading from DeviceFeatures
        // 0x20: ack_features
        // Writing to this register sets 32 consecutive flag bits, 
        // the least significant bit depending on the last value written to DriverFeaturesSel.
        // 0x24: acked_features_select
        // Writing to this register selects a set of 32 activated feature bits accessible by writing to DriverFeatures
        // 0x30: queue_select
        // Writing to this register selects the virtual queue that the following operations on QueueNumMax, QueueNum, 
        // QueueReady, QueueDescLow, QueueDescHigh, QueueAvailLow, QueueAvailHigh, QueueUsedLow and QueueUsedHigh apply to. 
        // The index number of the first queue is zero (0x0)

        bus.write(base+0x70, &zero);
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x70, &data);
        LittleEndian::write_u32(data.as_mut(), 3);
        bus.write(base+0x70, &data);

        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x14, &data);
        bus.write(base+0x14, &zero);

        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x24, &data);
        bus.write(base+0x20, &data);

        bus.write(base+0x24, &zero);
        LittleEndian::write_u32(data.as_mut(), 512);
        bus.write(base+0x20, &data);

        LittleEndian::write_u32(data.as_mut(), 11);
        bus.write(base+0x70, &data);

        bus.write(base+0x30, &zero);

        // states checked by device activation operation
        // queue size and queue ready
        LittleEndian::write_u32(data.as_mut(), 256);
        bus.write(base+0x38, &data);
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x44, &data);
        // At this step, the mmio device is activated and EpollHandler is sent to the epoll_context
        // Activation requires all queues in a valid state:
        //     1. must be marked as ready
        //     2. size must not be zero and cannot exceed max_size
        //     3. descriptor table/available ring/used ring must completely reside in guest memory
        //     4. alignment constraints must be satisfied
        LittleEndian::write_u32(data.as_mut(), 15);
        bus.write(base+0x70, &data);

        let queues =
            &self.snap_to_load.as_ref().unwrap().block_states[index as usize].queues;
        println!("TA BLOCK QUEUES: {:?}", queues);

        // Sleep so we can attach strace
        // println!("TO PID: {:?}", std::process::id());
        // thread::sleep_ms(20000);

        self.epoll_context.get_device_handler(index as usize).unwrap().set_queues(&queues);
        println!("Perasa restore_block_device");
        // ERROR --> called `Result::unwrap()` on an `Err` value: Device event handler not found. This might point to a guest device driver issue.
        // caused when calling get_device_handler(). The 'device_handlers' field is not initialized properly(?). 
        // device_handlers --> Vec::with_capacity(6)
    }

    fn restore_net_device(&mut self, index: u64) {
        //manually replay writes to mmio device
        // index: network devices come after block devices
        let base = 1073745920 + (index + self.drive_handler_id_map.len() as u64)*4096;
        let bus = self.mmio_device_manager.as_ref().unwrap().bus.clone();
        let mut data = [0u8; 4];
        let zero = [0u8; 4];

        // 0x70: update_driver_status
        // 0x14: features_select
        // 0x20: ack_features
        // 0x24: acked_features_select
        // 0x30: queue_select
        bus.write(base+0x70, &zero);
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x70, &data);
        LittleEndian::write_u32(data.as_mut(), 3);
        bus.write(base+0x70, &data);

        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x14, &data);
        bus.write(base+0x14, &zero);

        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x24, &data);
        bus.write(base+0x20, &data);

        bus.write(base+0x24, &zero);
        LittleEndian::write_u32(data.as_mut(), 19619);
        bus.write(base+0x20, &data);

        LittleEndian::write_u32(data.as_mut(), 11);
        bus.write(base+0x70, &data);

        // select queue 0
        bus.write(base+0x30, &zero);
        // states checked by device activation operation
        // queue size and queue ready
        LittleEndian::write_u32(data.as_mut(), 256);
        bus.write(base+0x38, &data);
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x44, &data);

        // select queue 1
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x30, &data);
        LittleEndian::write_u32(data.as_mut(), 256);
        bus.write(base+0x38, &data);
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x44, &data);

        // At this step, the mmio device is activated and EpollHandler is sent to the epoll_context
        // Activation requires all queues in a valid state:
        //     1. must be marked as ready
        //     2. size must not be zero and cannot exceed max_size
        //     3. descriptor table/available ring/used ring must completely reside in guest memory
        //     4. alignment constraints must be satisfied
        LittleEndian::write_u32(data.as_mut(), 15);
        bus.write(base+0x70, &data);

        let queues =
            &self.snap_to_load.as_ref().unwrap().net_states[index as usize].queues;
        self.epoll_context.get_device_handler(index as usize + self.drive_handler_id_map.len())
            .unwrap().set_queues(&queues);
    }

    fn restore_vsock(&mut self) {
        let mmio_offset = self.drive_handler_id_map.len() + self.net_handler_id_map.len();
        let base = 1073745920 + 4096 * mmio_offset as u64;
        let bus = self.mmio_device_manager.as_ref().unwrap().bus.clone();
        let mut data = [0u8; 4];
        let zero = [0u8; 4];

        bus.write(base+0x70, &zero);
        LittleEndian::write_u32(data.as_mut(), 1);
        bus.write(base+0x70, &data);
        LittleEndian::write_u32(data.as_mut(), 3);
        bus.write(base+0x70, &data);
        LittleEndian::write_u32(data.as_mut(), 11);
        bus.write(base+0x70, &data);

        for idx in 0..=2usize {
            LittleEndian::write_u32(data.as_mut(), idx as u32);
            bus.write(base+0x30, &data);
            // states checked by device activation operation
            // queue size, queue location, queue ready
            LittleEndian::write_u32(data.as_mut(), 256);
            bus.write(base+0x38, &data);
            LittleEndian::write_u32(data.as_mut(), 1);
            bus.write(base+0x44, &data);
        }

        // At this step, the mmio device is activated and EpollHandler is sent to the epoll_context
        // Activation requires all queues in a valid state:
        //     1. must be marked as ready
        //     2. size must not be zero and cannot exceed max_size
        //     3. descriptor table/available ring/used ring must completely reside in guest memory
        //     4. alignment constraints must be satisfied
        LittleEndian::write_u32(data.as_mut(), 15);
        bus.write(base+0x70, &data);

        let queues = &self.snap_to_load.as_ref().unwrap().vsock_state.queues;
        self.epoll_context.get_device_handler(mmio_offset).unwrap().set_queues(&queues);
    }

    fn start_microvm(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        info!("VMM received instance start command");
        // println!("VMM received instance start command");
        let mut ts_vec = Vec::new();
        ts_vec.push(Instant::now());
        //let t00 = now_monotime_us();
        if self.is_instance_initialized() {
            return Err(VmmActionError::StartMicrovm(
                ErrorKind::User,
                StartMicrovmError::MicroVMAlreadyRunning,
            ));
        }

        // println!("Perasa is_instance_initialized");

        let request_ts = TimestampUs {
            time_us: now_monotime_us(),
            cputime_us: now_cputime_us(),
        };

        if self.load_dir.is_empty() {
            self.check_health()
                .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::User, e))?;
        }
        // Use expect() to crash if the other thread poisoned this lock.
        self.shared_info
            .write()
            .expect("Failed to start microVM because shared info couldn't be written due to poisoned lock")
            .state = InstanceState::Starting;

        self.init_guest_memory()
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;

        

        println!("Perasa init_guest_memory");

        // let entry_addr = self
            // .load_kernel()
            // .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;

        // We need to check if this is the right addr in the aarch64 case
        // let mut entry_addr = GuestAddress(0);
        let mut entry_addr = GuestAddress(2148007936);
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if self.load_dir.is_empty() {
            entry_addr = self
                .load_kernel()
                .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;
            println!("To entry_addr: {:?}", entry_addr);
        }

        println!("Meta tin load_kernel");        

        let mut vcpus = self
            .create_vcpus(entry_addr, request_ts)
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;
        ts_vec.push(Instant::now());
        let t2 = now_monotime_us();

        println!("Perasa tin create_vcpu");

        let t0 = now_monotime_us();
        ts_vec.push(Instant::now());
        self.setup_interrupt_controller()
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;

        println!("Perasa setup_interrupt_controller");

        self.attach_virtio_devices()
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;

        println!("Perasa attach_virtio");

        self.attach_legacy_devices_aarch64()
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;


        println!("Ta addresses twn mmio devices");
        let mut mmio_devs = self.get_mmio_device_info();
        println!("{:?}", mmio_devs);
        println!("Till here");

        // let temp;
        // temp = self.epoll_context.get_device_handler(0 as usize).unwrap();
        // println!("To device handler toy rootfs: {:?}", temp);
    
        println!("Perasa attach_legacy_devices_aarch64");

        if self.load_dir.is_empty(){
            self.configure_system(vcpus.as_mut(), entry_addr)
                .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;
        } else {
            println!("Prin tin restore_block_device");
            for i in 0..self.drive_handler_id_map.len() {
                self.restore_block_device(i as u64);
            }
            println!("Prin tin restore_net_device");
            for i in 0..self.net_handler_id_map.len() {
                self.restore_net_device(i as u64);
            }
            self.restore_vsock();
        }
            
        // println!("Meta tin configure system");
        
        self.register_events()
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;

        if self.dump_dir.is_some() {
            self.snap_to_dump = Some(Snapshot {
                // TODO: currently only block devices
                block_states: vec![Default::default(); self.drive_handler_id_map.len()],
                net_states: vec![Default::default(); self.net_handler_id_map.len()],
                vcpu_states: vec![Default::default(); self.vm_config.vcpu_count.unwrap() as usize],
                ..Default::default()
            });
        }

        ts_vec.push(Instant::now());
        let t1 = now_monotime_us();

        // println!("Meta tin register events");

        self.start_vcpus(vcpus)
            .map_err(|e| VmmActionError::StartMicrovm(ErrorKind::Internal, e))?;

        ts_vec.push(Instant::now());
        //let t3 = now_monotime_us();
        // fast (28us) and does not affect total boot latency measurement
        println!("VMM: restore memory: {} us", ts_vec[1].duration_since(ts_vec[0]).as_micros());
        // Use expect() to crash if the other thread poisoned this lock.
        self.shared_info
            .write()
            .expect("Failed to start microVM because shared info couldn't be written due to poisoned lock")
            .state = InstanceState::Running;

        // Arm the log write timer.
        // TODO: the timer does not stop on InstanceStop.
        let timer_state = TimerState::Periodic {
            current: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
            interval: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
        };
        self.write_metrics_event
            .fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Log the metrics straight away to check the process startup time.
        if LOGGER.log_metrics().is_err() {
            METRICS.logger.missed_metrics_count.inc();
        }

        // let vm_memory = self.vm.get_memory().unwrap();

        // let (gfns_to_pfns, _) = memory_model::GuestMemory::get_pagemap(vm_memory, true);

        // println!("{:?}", gfns_to_pfns);

        Ok(VmmData::Empty)
    }


    /// Process the content of the MPIDR_EL1 register in order to be able to pass it to KVM
    ///
    /// The kernel expects to find the four affinity levels of the MPIDR in the first 32 bits of the
    /// VGIC register attribute:
    /// https://elixir.free-electrons.com/linux/v4.14.203/source/virt/kvm/arm/vgic/vgic-kvm-device.c#L445.
    ///
    /// The format of the MPIDR_EL1 register is:
    /// | 39 .... 32 | 31 .... 24 | 23 .... 16 | 15 .... 8 | 7 .... 0 |
    /// |    Aff3    |    Other   |    Aff2    |    Aff1   |   Aff0   |
    ///
    /// The KVM mpidr format is:
    /// | 63 .... 56 | 55 .... 48 | 47 .... 40 | 39 .... 32 |
    /// |    Aff3    |    Aff2    |    Aff1    |    Aff0    |
    /// As specified in the linux kernel: Documentation/virt/kvm/devices/arm-vgic-v3.rst
    fn construct_gicr_typer(vcpu_state: &vstate::VcpuState) -> Vec<u64> {
        /* Pre-construct the GICR_TYPER:
         * For our implementation:
         *  Top 32 bits are the affinity value of the associated CPU
         *  CommonLPIAff == 01 (redistributors with same Aff3 share LPI table)
         *  Processor_Number == CPU index starting from 0
         *  DPGS == 0 (GICR_CTLR.DPG* not supported)
         *  Last == 1 if this is the last redistributor in a series of
         *            contiguous redistributor pages
         *  DirectLPI == 0 (direct injection of LPIs not supported)
         *  VLPIS == 0 (virtual LPIs not supported)
         *  PLPIS == 0 (physical LPIs not supported)
         */
        let mut mpidrs: Vec<u64> = Vec::new();
        
        // let index = 0;
        // let last = 1;
        // let mut cpu_affid = vcpu_state.mpidr & 1_0952_3343_7695;
        // cpu_affid = ((cpu_affid & 0xFF_0000_0000) >> 8) | (cpu_affid & 0xFF_FFFF);
        // mpidrs.push((cpu_affid << 32) | (1 << 24) | (index as u64) << 8 | (last << 4));

        let mut cpu_affid = ((vcpu_state.mpidr & 0xFF_0000_0000) >> 8) | (vcpu_state.mpidr & 0xFF_FFFF);
        mpidrs.push(cpu_affid << 32);

        // for (index, state) in vcpu_states.iter().enumerate() {
            // let last = {
                // if index == vcpu_states.len() - 1 {
                    // 1
                // } else {
                    // 0
                // }
            // };
            //calculate affinity
            // let mut cpu_affid = state.mpidr & 1_0952_3343_7695;
            // cpu_affid = ((cpu_affid & 0xFF_0000_0000) >> 8) | (cpu_affid & 0xFF_FFFF);
            // mpidrs.push((cpu_affid << 32) | (1 << 24) | (index as u64) << 8 | (last << 4));
        // }

        mpidrs
    }

    // fn load_initrd_from_config(
    //     boot_cfg: &BootConfig,
    //     vm_memory: &GuestMemoryMmap,
    // ) -> std::result::Result<Option<InitrdConfig>, StartMicrovmError> {
    //     use self::StartMicrovmError::InitrdRead;
    
    //     Ok(match &boot_cfg.initrd_file {
    //         Some(f) => Some(load_initrd(
    //             vm_memory,
    //             &mut f.try_clone().map_err(InitrdRead)?,
    //         )?),
    //         None => None,
    //     })
    // }

    fn send_ctrl_alt_del(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        self.legacy_device_manager
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(|e| VmmActionError::SendCtrlAltDel(ErrorKind::Internal, e))?;
        Ok(VmmData::Empty)
    }

    /// Waits for all vCPUs to exit and terminates the Firecracker process.
    fn stop(&mut self, exit_code: i32) {
        info!("Vmm is stopping.");

        if let Err(e) = self.epoll_context.disable_stdin_event() {
            warn!("Cannot disable the STDIN event. {:?}", e);
        }

        if let Err(e) = self
            .legacy_device_manager
            .stdin_handle
            .lock()
            .set_canon_mode()
        {
            warn!("Cannot set canonical mode for the terminal. {:?}", e);
        }

        // Log the metrics before exiting.
        if let Err(e) = LOGGER.log_metrics() {
            error!("Failed to log metrics while stopping: {}", e);
        }

        // Exit from Firecracker using the provided exit code. Safe because we're terminating
        // the process anyway.
        unsafe {
            libc::_exit(exit_code);
        }
    }

    fn is_instance_initialized(&self) -> bool {
        let instance_state = {
            // Use expect() to crash if the other thread poisoned this lock.
            let shared_info = self.shared_info.read()
                .expect("Failed to determine if instance is initialized because shared info couldn't be read due to poisoned lock");
            shared_info.state.clone()
        };
        match instance_state {
            InstanceState::Uninitialized => false,
            _ => true,
        }
    }

    fn update_memory_meta(meta: &MemorySnapshotMeta, dirty_pages: &BTreeSet<usize>) -> MemorySnapshotMeta {
        let mut new_meta = MemorySnapshotMeta::new();
        for layer in meta {
            let mut pages = BTreeSet::new();
            for (start_gfn, count) in &layer.dirty_regions {
                let mut i = *count;
                let mut gfn = *start_gfn;
                while i > 0 {
                    pages.insert(gfn);
                    i -= 1;
                    gfn += 1;
                }
            }
            let new_pages = pages.difference(&dirty_pages).cloned().collect();
            let new_layer = MemorySnapshotLayer {
                dirty_regions: GuestMemory::convert_to_regionlist(new_pages),
                ..Default::default()
            };
            new_meta.push(new_layer);
        }
        new_meta
    }

    #[allow(clippy::unused_label)]
    fn run_control(&mut self) -> Result<()> {

        println!("Bika run_control");

        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        let epoll_raw_fd = self.epoll_context.epoll_raw_fd;
        let mut exit_on_dump = false;
        let mut vcpu_snap_cnt = 0usize;
        // TODO: try handling of errors/failures without breaking this main loop.
        loop {

            // println!("Bika stin loopa");

            let num_events = epoll::wait(epoll_raw_fd, -1, &mut events[..]).map_err(Error::Poll)?;

            // println!("Ta num_events:");
            // println!("{}", num_events);

            for event in events.iter().take(num_events) {
                let dispatch_idx = event.data as usize;
                let evset = match epoll::Events::from_bits(event.events) {
                    Some(evset) => evset,
                    None => {
                        let evbits = event.events;
                        println!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                        warn!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                        continue;
                    },
                };

                // println!("Meta tin evset");
                // println!("To dispatch_idx");
                // println!("{}", dispatch_idx);

                if let Some(dispatch_type) = self.epoll_context.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Exit => {

                            println!("Bika stin EpollDispatch::Exit");

                            match self.exit_evt {
                                Some(ref ev) => {
                                    ev.fd.read().map_err(Error::EventFd)?;
                                }
                                None => warn!("leftover exit-evt in epollcontext!"),
                            }
                            self.stop(i32::from(FC_EXIT_CODE_OK));

                            println!("Meta tin EpollDispatch::Exit");
                        }
                        EpollDispatch::Stdin => {

                            println!("Bika stin EpollDispatch::Stdin");

                            let mut out = [0u8; 64];
                            let stdin_lock = self.legacy_device_manager.stdin_handle.lock();
                            match stdin_lock.read_raw(&mut out[..]) {
                                Ok(0) => {
                                    // Zero-length read indicates EOF. Remove from pollables.
                                    self.epoll_context.disable_stdin_event()?;
                                }
                                Err(e) => {
                                    println!("error while reading stdin: {:?}", e);
                                    warn!("error while reading stdin: {:?}", e);
                                    self.epoll_context.disable_stdin_event()?;
                                }
                                Ok(count) => {
                                    // Use expect() to panic if another thread panicked
                                    // while holding the lock.
                                    self.legacy_device_manager
                                        .stdio_serial
                                        .lock()
                                        .expect(
                                            "Failed to process stdin event due to poisoned lock",
                                        )
                                        .queue_input_bytes(&out[..count])
                                        .map_err(Error::Serial)?;
                                }
                            }

                            println!("Prin vgw apo tin EpollDispatch::Stdin");

                        }
                        EpollDispatch::DeviceHandler(device_idx, device_token) => {
                        
                            // println!("Bika stin EpollDispatch::DeviceHandler");

                            METRICS.vmm.device_events.inc();
                            match self.epoll_context.get_device_handler(device_idx) {
                                Ok(handler) => {
                                    match handler.handle_event(
                                        device_token,
                                        event.events,
                                        EpollHandlerPayload::Empty,
                                        evset,
                                    ) {
                                        Err(devices::Error::PayloadExpected) => panic!(
                                            "Received update disk image event with empty payload."
                                        ),
                                        Err(devices::Error::UnknownEvent { device, event }) => {
                                            panic!("Unknown event: {:?} {:?}", device, event)
                                        }
                                        _ => (),
                                    }
                                }
                                Err(e) => {
                                    println!("invalid handler for device {}: {:?}", device_idx, e);
                                    warn!("invalid handler for device {}: {:?}", device_idx, e)
                                }
                            }

                            // println!("Vgika apo tin EpollDispatch::DeviceHandler");

                        }
                        EpollDispatch::VmmActionRequest => {
                            self.api_event.fd.read().map_err(Error::EventFd)?;
                            self.run_vmm_action().unwrap_or_else(|_| {
                                warn!("got spurious notification from api thread");
                            });
                        }
                        EpollDispatch::WriteMetrics => {
                            self.write_metrics_event.fd.read();
                            // Please note that, since LOGGER has no output file configured yet, it will write to
                            // stdout, so logging will interfere with console output.
                            if let Err(e) = self.write_metrics() {
                                error!("Failed to log metrics: {}", e);
                            }
                        }
                        EpollDispatch::Snap => {
                            println!("Egine trigger to snap event");
                            self.snap_evt.read().map_err(Error::EventFd)?;
                            vcpu_snap_cnt += 1;
                            let info = self.snap_receiver.as_ref().unwrap().recv().unwrap();
                            self.snap_to_dump.as_mut().unwrap().vcpu_states[info.id as usize]
                                = info.state;
                            if vcpu_snap_cnt == self.vcpus_handles.len() {
                                exit_on_dump = true;
                            }
                        }
                    }
                }
            }
            if exit_on_dump {
                println!("Bikame exit_on_dump");
                let snapshot = self.snap_to_dump.as_mut().unwrap();
                // dump block device state, assume all block devices are attached first
                for i in 0..self.drive_handler_id_map.len() {

                    snapshot.block_states[i].queues =
                        self.epoll_context.get_device_handler(i).unwrap().get_queues();

                }
                println!("Kaname save ta block states");

                // dump network device state, assume network devices are attached after all block
                // devices
                for i in 0..self.net_handler_id_map.len() {
                    
                    snapshot.net_states[i].queues =
                        self.epoll_context.get_device_handler(i + self.drive_handler_id_map.len())
                            .unwrap().get_queues();

                }
                println!("Kaname save ta net states");

                // dump vsock state, assume vsock is the last attached virtio device

                snapshot.vsock_state.queues = self.epoll_context.get_device_handler(
                    self.drive_handler_id_map.len() + self.net_handler_id_map.len())
                    .unwrap().get_queues();
                println!("Kaname save ta Vsock states");

                // dump irqchip state
                // We need to get access to vcpus and through them to mpidrs
                // let vcpus = self.vcpus_handles;
                // let vcpu_mpidrs = vcpus.into_iter().map(|cpu| cpu.get_mpidr()).collect();
                // self.vm.dump_irqchip(snapshot, vcpu_mpidrs).map_err(|e| Error::SaveSnapshot(e))?;

                let vcpu_state = &snapshot.vcpu_states[0 as usize];
                let mpidrs = Vmm::construct_gicr_typer(&vcpu_state);
                println!("Ftiaxame mpidrs");
                self.vm.dump_irqchip(snapshot, &mpidrs).unwrap();
                // self.vm.dump_irqchip(snapshot, &mpidrs).map_err(|e| Error::SaveSnapshot(e))?;
                println!("Dumped the irqchip state");

                println!("snapshotting memory...");
                if let Some(dirty_pages_set) = self.vm.dump_initialized_memory_to_file(
                    self.dump_dir.as_ref().unwrap().clone()) {
                    let mut new_memory_meta = if self.load_dir.is_empty() {
                        MemorySnapshotMeta::new()
                    } else {
                        // generate a diff snapshot
                        Vmm::update_memory_meta(&self.snap_to_load.as_ref().unwrap().memory_meta, &dirty_pages_set)
                    };
                    new_memory_meta.push(MemorySnapshotLayer{
                        dirty_regions: GuestMemory::convert_to_regionlist(dirty_pages_set),
                        ..Default::default()
                    });
                    snapshot.memory_meta = new_memory_meta;

                    let snap_str = serde_json::to_string(self.snap_to_dump.as_ref().unwrap()).unwrap();
                    self.dump_dir.as_mut().unwrap().push("snapshot.json");

                    println!("writing meta to {:?}", self.dump_dir);

                    std::fs::write(self.dump_dir.as_ref().unwrap(), snap_str)
                        .map_err(|e| Error::SaveSnapshot(e))?;

                    println!("VMM: Snapshot creation succeeds");
                } else {
                    println!("Snapshot creation failed.");
                }


                self.stop(i32::from(FC_EXIT_CODE_OK));
            }
        }
    }

    // Count the number of pages dirtied since the last call to this function.
    // Because this is used for metrics, it swallows most errors and simply doesn't count dirty
    // pages if the KVM operation fails.
    // #[cfg(target_arch = "x86_64")]
    fn get_dirty_page_count(&mut self) -> usize {
        if let Some(ref mem) = self.guest_memory {
            let dirty_pages = mem.map_and_fold(
                0,
                |(slot, memory_region)| {
                    let bitmap = self
                        .vm
                        .get_fd()
                        .get_dirty_log(slot as u32, memory_region.size());
                    match bitmap {
                        Ok(v) => v
                            .iter()
                            .fold(0, |init, page| init + page.count_ones() as usize),
                        Err(_) => 0,
                    }
                },
                |dirty_pages, region_dirty_pages| dirty_pages + region_dirty_pages,
            );
            return dirty_pages;
        }
        0
    }

    //pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap> {
    //    let mut bitmap: DirtyBitmap = HashMap::new();
    //    self.guest_memory.with_regions_mut(
    //        |slot: usize, region: &GuestRegionMmap| -> Result<()> {
    //            let bitmap_region = self
    //                .vm
    //                .fd()
    //                .get_dirty_log(slot as u32, region.len() as usize)
    //                .map_err(Error::DirtyBitmap)?;
    //            bitmap.insert(slot, bitmap_region);
    //            Ok(())
    //        },
    //    )?;
    //    Ok(bitmap)
    //}


    // Count the list of pages dirtied since the last call to this function.
    // Intended for diff snapshot generation
    //#[cfg(target_arch = "x86_64")]
    //fn get_dirty_page_list(&mut self) -> Vec<usize> {
    //    if let Some(ref mem) = self.guest_memory {
    //        let dirty_pages = mem.map_and_fold(
    //            Vec::new(),
    //            |(slot, memory_region)| {
    //                let bitmap = self
    //                    .vm
    //                    .get_fd()
    //                    .get_dirty_log(slot as u32, memory_region.size());
    //                let base_gfn = memory_region.end_addr() - memory_region.size();
    //                match bitmap {
    //                    Ok(v) => v
    //                        .iter()
    //                        .fold(Vec::new(), |init, page| init.append(page.count_ones()) ),
    //                    Err(_) => Vec::new(),
    //                }
    //            },
    //            |mut dirty_pages, mut region_dirty_pages| dirty_pages.append(&mut region_dirty_pages),
    //        );
    //        return dirty_pages;
    //    }
    //    Vec::new()
    //}

    fn configure_boot_source(
        &mut self,
        kernel_image_path: String,
        kernel_cmdline: Option<String>,
    ) -> std::result::Result<VmmData, VmmActionError> {

        // println!("Bika stin configure_boot_source");

        if !self.load_dir.is_empty() {
            return Ok(VmmData::Empty);
        }
        if self.is_instance_initialized() {
            return Err(VmmActionError::BootSource(
                ErrorKind::User,
                BootSourceConfigError::UpdateNotAllowedPostBoot,
            ));
        }

        // println!("Perasa tin is_instance_initialized");


        let kernel_file = File::open(kernel_image_path).map_err(|_| {
            VmmActionError::BootSource(ErrorKind::User, BootSourceConfigError::InvalidKernelPath)
        })?;

        // println!("Anoiksa to kernel");

        let mut cmdline = kernel_cmdline::Cmdline::new(2048 as usize);
        // println!("Meta to settarisma");
        cmdline
            .insert_str(kernel_cmdline.unwrap_or_else(|| String::from(DEFAULT_KERNEL_CMDLINE)))
            .map_err(|_| {
                VmmActionError::BootSource(
                    ErrorKind::User,
                    BootSourceConfigError::InvalidKernelCommandLine,
                )
            })?;

        // println!("Pira commandline");

        let kernel_config = KernelConfig {
            kernel_file,
            cmdline,
            // cmdline_addr: GuestAddress(arch::aarch64::layout::CMDLINE_START),   //doesn't matter
        };

        // println!("Pira kernel configuration");

        self.configure_kernel(kernel_config);

        // println!("Ekana configure to kernel");

        Ok(VmmData::Empty)
    }

    fn set_vm_configuration(
        &mut self,
        machine_config: VmConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {

        if self.is_instance_initialized() {
            return Err(VmmActionError::MachineConfig(
                ErrorKind::User,
                VmConfigError::UpdateNotAllowedPostBoot,
            ));
        }

        if let Some(vcpu_count_value) = machine_config.vcpu_count {
            // Check that the vcpu_count value is >=1.
            if vcpu_count_value == 0 {
                return Err(VmmActionError::MachineConfig(
                    ErrorKind::User,
                    VmConfigError::InvalidVcpuCount,
                ));
            }
        }

        if let Some(mem_size_mib_value) = machine_config.mem_size_mib {
            // TODO: add other memory checks
            if mem_size_mib_value == 0 {
                return Err(VmmActionError::MachineConfig(
                    ErrorKind::User,
                    VmConfigError::InvalidMemorySize,
                ));
            }
        }

        let ht_enabled = match machine_config.ht_enabled {
            Some(value) => value,
            None => self.vm_config.ht_enabled.unwrap(),
        };

        let vcpu_count_value = match machine_config.vcpu_count {
            Some(value) => value,
            None => self.vm_config.vcpu_count.unwrap(),
        };

        // If hyperthreading is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if ht_enabled && vcpu_count_value > 1 && vcpu_count_value % 2 == 1 {
            return Err(VmmActionError::MachineConfig(
                ErrorKind::User,
                VmConfigError::InvalidVcpuCount,
            ));
        }

        // Update all the fields that have a new value.
        self.vm_config.vcpu_count = Some(vcpu_count_value);
        self.vm_config.ht_enabled = Some(ht_enabled);

        if machine_config.mem_size_mib.is_some() {
            self.vm_config.mem_size_mib = machine_config.mem_size_mib;
        }

        if machine_config.cpu_template.is_some() {
            self.vm_config.cpu_template = machine_config.cpu_template;
        }

        Ok(VmmData::Empty)
    }

    fn insert_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            return Err(VmmActionError::NetworkConfig(
                ErrorKind::User,
                NetworkInterfaceError::UpdateNotAllowedPostBoot,
            ));
        }
        self.network_interface_configs
            .insert(body)
            .map(|_| VmmData::Empty)
            .map_err(|e| VmmActionError::NetworkConfig(ErrorKind::User, e))
    }

    fn update_net_device(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if !self.is_instance_initialized() {
            // VM not started yet, so we only need to update the device configs, not the actual
            // live device.
            let old_cfg = self
                .network_interface_configs
                .iter_mut()
                .find(|&&mut ref c| c.iface_id == new_cfg.iface_id)
                .ok_or(VmmActionError::NetworkConfig(
                    ErrorKind::User,
                    NetworkInterfaceError::DeviceIdNotFound,
                ))?;

            // Check if we need to update the RX rate limiter.
            if let Some(new_rlim_cfg) = new_cfg.rx_rate_limiter {
                if let Some(ref mut old_rlim_cfg) = old_cfg.rx_rate_limiter {
                    // We already have an RX rate limiter set, so we'll update it.
                    old_rlim_cfg.update(&new_rlim_cfg);
                } else {
                    // No old RX rate limiter; create one now.
                    old_cfg.rx_rate_limiter = Some(new_rlim_cfg);
                }
            }

            // Check if we need to update the TX rate limiter.
            if let Some(new_rlim_cfg) = new_cfg.tx_rate_limiter {
                if let Some(ref mut old_rlim_cfg) = old_cfg.tx_rate_limiter {
                    // We already have a TX rate limiter set, so we'll update it.
                    old_rlim_cfg.update(&new_rlim_cfg);
                } else {
                    // No old TX rate limiter; create one now.
                    old_cfg.tx_rate_limiter = Some(new_rlim_cfg);
                }
            }

            return Ok(VmmData::Empty);
        }

        // If we got to here, the VM is running. We need to update the live device.
        //

        let handler_id = *self.net_handler_id_map.get(&new_cfg.iface_id).ok_or(
            VmmActionError::NetworkConfig(ErrorKind::User, NetworkInterfaceError::DeviceIdNotFound),
        )?;

        let handler = self
            .epoll_context
            .get_device_handler(handler_id)
            .map_err(|e| {
                VmmActionError::NetworkConfig(
                    ErrorKind::User,
                    NetworkInterfaceError::EpollHandlerNotFound(e),
                )
            })?;

        // Hack because velocity (my new favorite phrase): fake an epoll event, because we can only
        // contact a live device via its `EpollHandler`.
        handler
            .handle_event(
                virtio::net::PATCH_RATE_LIMITERS_FAKE_EVENT,
                handler_id as u32,
                EpollHandlerPayload::NetRateLimiterPayload {
                    rx_bytes: new_cfg
                        .rx_rate_limiter
                        .map(|rl| rl.bandwidth.map(|b| b.into_token_bucket()))
                        .unwrap_or(None),
                    rx_ops: new_cfg
                        .rx_rate_limiter
                        .map(|rl| rl.ops.map(|b| b.into_token_bucket()))
                        .unwrap_or(None),
                    tx_bytes: new_cfg
                        .tx_rate_limiter
                        .map(|rl| rl.bandwidth.map(|b| b.into_token_bucket()))
                        .unwrap_or(None),
                    tx_ops: new_cfg
                        .tx_rate_limiter
                        .map(|rl| rl.ops.map(|b| b.into_token_bucket()))
                        .unwrap_or(None),
                },
                epoll::Events::empty(),
            )
            .map_err(|e| {
                VmmActionError::NetworkConfig(
                    ErrorKind::Internal,
                    NetworkInterfaceError::RateLimiterUpdateFailed(e),
                )
            })?;

        Ok(VmmData::Empty)
    }

    #[cfg(feature = "vsock")]
    fn insert_vsock_device(
        &mut self,
        body: VsockDeviceConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            return Err(VmmActionError::VsockConfig(
                ErrorKind::User,
                VsockError::UpdateNotAllowedPostBoot,
            ));
        }
        self.vsock_device_configs
            .add(body)
            .map(|_| VmmData::Empty)
            .map_err(|e| VmmActionError::VsockConfig(ErrorKind::User, e))
    }

    fn set_block_device_path(
        &mut self,
        drive_id: String,
        path_on_host: String,
    ) -> std::result::Result<VmmData, VmmActionError> {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .block_device_configs
            .get_index_of_drive_id(&drive_id)
            .ok_or(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::InvalidBlockDeviceID,
            ))?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let disk_file = OpenOptions::new()
            .read(true)
            .write(!self.block_device_configs.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(|_| {
                VmmActionError::DriveConfig(ErrorKind::User, DriveError::CannotOpenBlockDevice)
            })?;

        // Update the path of the block device with the specified path_on_host.
        self.block_device_configs.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the drive handler and send a
        // rescan command to the drive.
        if self.is_instance_initialized() {
            self.update_drive_handler(&drive_id, disk_file)
                .map_err(|e| VmmActionError::DriveConfig(ErrorKind::User, e))?;
            self.rescan_block_device(&drive_id)?;
        }
        Ok(VmmData::Empty)
    }

    fn rescan_block_device(
        &mut self,
        drive_id: &str,
    ) -> std::result::Result<VmmData, VmmActionError> {
        // Rescan can only happen after the guest is booted.
        if !self.is_instance_initialized() {
            return Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::OperationNotAllowedPreBoot,
            ));
        }

        // Safe to unwrap() because mmio_device_manager is initialized in init_devices(), which is
        // called before the guest boots, and this function is called after boot.
        let device_manager = self.mmio_device_manager.as_ref().unwrap();
        match device_manager.get_address(drive_id) {
            Some(address) => {
                for drive_config in self.block_device_configs.config_list.iter() {
                    if drive_config.drive_id == *drive_id {
                        let metadata = metadata(&drive_config.path_on_host).map_err(|_| {
                            VmmActionError::DriveConfig(
                                ErrorKind::User,
                                DriveError::BlockDeviceUpdateFailed,
                            )
                        })?;
                        let new_size = metadata.len();
                        if new_size % virtio::block::SECTOR_SIZE != 0 {
                            warn!(
                                "Disk size {} is not a multiple of sector size {}; \
                                 the remainder will not be visible to the guest.",
                                new_size,
                                virtio::block::SECTOR_SIZE
                            );
                        }
                        return device_manager
                            .update_drive(address, new_size)
                            .map(|_| VmmData::Empty)
                            .map_err(|_| {
                                VmmActionError::DriveConfig(
                                    ErrorKind::User,
                                    DriveError::BlockDeviceUpdateFailed,
                                )
                            });
                    }
                }
                Err(VmmActionError::DriveConfig(
                    ErrorKind::User,
                    DriveError::BlockDeviceUpdateFailed,
                ))
            }
            _ => Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::InvalidBlockDeviceID,
            )),
        }
    }

    // Only call this function as part of the API.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    fn insert_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            return Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::UpdateNotAllowedPostBoot,
            ));
        }

        self.block_device_configs
            .insert(block_device_config)
            .map(|_| VmmData::Empty)
            .map_err(|e| VmmActionError::DriveConfig(ErrorKind::User, e))
    }

    fn init_logger(
        &self,
        api_logger: LoggerConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            return Err(VmmActionError::Logger(
                ErrorKind::User,
                LoggerConfigError::InitializationFailure(
                    "Cannot initialize logger after boot.".to_string(),
                ),
            ));
        }

        let instance_id;
        let firecracker_version;
        {
            let guard = self.shared_info.read().unwrap();
            instance_id = guard.id.clone();
            firecracker_version = guard.vmm_version.clone();
        }

        match api_logger.level {
            LoggerLevel::Error => LOGGER.set_level(Level::Error),
            LoggerLevel::Warning => LOGGER.set_level(Level::Warn),
            LoggerLevel::Info => LOGGER.set_level(Level::Info),
            LoggerLevel::Debug => LOGGER.set_level(Level::Debug),
        }

        LOGGER.set_include_origin(api_logger.show_log_origin, api_logger.show_log_origin);
        LOGGER.set_include_level(api_logger.show_level);

        #[cfg(target_arch = "aarch64")]
        let options: &Vec<Value> = &vec![];
        #[cfg(target_arch = "x86_64")]
        let options = api_logger.options.as_array().unwrap();

        LOGGER
            .init(
                &AppInfo::new("Firecracker", &firecracker_version),
                &instance_id,
                api_logger.log_fifo,
                api_logger.metrics_fifo,
                options,
            )
            .map(|_| VmmData::Empty)
            .map_err(|e| {
                VmmActionError::Logger(
                    ErrorKind::User,
                    LoggerConfigError::InitializationFailure(e.to_string()),
                )
            })
    }

    // If load_dir is provided and diff_dirs is empty, the working set is off the full function
    // snapshot.
    // If diff_dirs size is exactly one, the working set if off the diff snapshot.
    // All the other cases, the function is a noop
    // When the function is not a noop, it generates a metadata file to the directory given by the
    // input parameter.
    fn dump_working_set(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        if let Some(snapshot) = self.snap_to_load.as_mut() {
            // we are sure this is a valid snapshot
            let base_layer = snapshot.memory_meta.last_mut().unwrap();
            let mut dir = self.load_dir.last().unwrap().clone();
            self.vm.dump_working_set(dir.clone(), base_layer)
                .map(|_| VmmData::Empty)
                .map_err(|e| VmmActionError::DumpWorkingSet(ErrorKind::User, e))?;
            
            let snap_str = serde_json::to_string(snapshot).unwrap();
            dir.push("snapshot.json");
            //println!("writing meta to {:?}", dir);
            std::fs::write(dir, snap_str).map(|_| VmmData::Empty)
                .map_err(|e| VmmActionError::DumpWorkingSet(ErrorKind::Internal,
                                                            memory_model::GuestMemoryError::IoError(e)))
        } else {
            let custom_io_error = std::io::Error::new(io::ErrorKind::Other, "invalid snapshot");
            Err(VmmActionError::DumpWorkingSet(ErrorKind::User,
                                               memory_model::GuestMemoryError::IoError(custom_io_error)))
        }
    }

    fn send_response(outcome: VmmRequestOutcome, sender: OutcomeSender) {
        sender
            .send(outcome)
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn run_vmm_action(&mut self) -> Result<()> {

        let request = match self.from_api.try_recv() {
            Ok(t) => *t,
            Err(TryRecvError::Empty) => {
                return Err(Error::ApiChannel)?;
            }
            Err(TryRecvError::Disconnected) => {
                panic!("The channel's sending half was disconnected. Cannot receive data.");
            }
        };

        match request {
            VmmAction::ConfigureBootSource(boot_source_body, sender) => {
                Vmm::send_response(
                    self.configure_boot_source(
                        boot_source_body.kernel_image_path,
                        boot_source_body.boot_args,
                    ),
                    sender,
                );
            }
            VmmAction::ConfigureLogger(logger_description, sender) => {
                Vmm::send_response(self.init_logger(logger_description), sender);
            }
            VmmAction::FlushMetrics(sender) => {
                Vmm::send_response(self.flush_metrics(), sender);
            }
            VmmAction::GetVmConfiguration(sender) => {
                Vmm::send_response(
                    Ok(VmmData::MachineConfiguration(self.vm_config.clone())),
                    sender,
                );
            }
            VmmAction::InsertBlockDevice(block_device_config, sender) => {
                Vmm::send_response(self.insert_block_device(block_device_config), sender);
            }
            VmmAction::InsertNetworkDevice(netif_body, sender) => {
                Vmm::send_response(self.insert_net_device(netif_body), sender);
            }
            #[cfg(feature = "vsock")]
            VmmAction::InsertVsockDevice(vsock_cfg, sender) => {
                Vmm::send_response(self.insert_vsock_device(vsock_cfg), sender);
            }
            VmmAction::RescanBlockDevice(drive_id, sender) => {
                Vmm::send_response(self.rescan_block_device(&drive_id), sender);
            }
            VmmAction::StartMicroVm(sender) => {
                Vmm::send_response(self.start_microvm(), sender);
            }
            VmmAction::SendCtrlAltDel(sender) => {
                Vmm::send_response(self.send_ctrl_alt_del(), sender);
            }
            VmmAction::SetVmConfiguration(machine_config_body, sender) => {
                Vmm::send_response(self.set_vm_configuration(machine_config_body), sender);
            }
            VmmAction::UpdateBlockDevicePath(drive_id, path_on_host, sender) => {
                Vmm::send_response(self.set_block_device_path(drive_id, path_on_host), sender);
            }
            VmmAction::UpdateNetworkInterface(netif_update, sender) => {
                Vmm::send_response(self.update_net_device(netif_update), sender);
            }
            VmmAction::DumpWorkingSet(sender) => {
                Vmm::send_response(self.dump_working_set(), sender);
            }
        };
        Ok(())
    }

    fn log_boot_time(t0_ts: &TimestampUs) {
        let now_cpu_us = now_cputime_us();
        let now_us = now_monotime_us();

        let boot_time_us = now_us - t0_ts.time_us;
        let boot_time_cpu_us = now_cpu_us - t0_ts.cputime_us;

        println!("VMM: boot time: {} us", boot_time_us);

        fc_util::fc_log!(
            "firecracker: Guest-boot-time: {:>6} us, {:>6} CPU us",
            boot_time_us,
            boot_time_cpu_us,
        );
    }
}

// Can't derive PartialEq directly because the sender members can't be compared.
// This implementation is only used in tests, but cannot be moved to mod tests,
// because it is used in tests outside of the vmm crate (api_server).
impl PartialEq for VmmAction {
    fn eq(&self, other: &VmmAction) -> bool {
        match (self, other) {
            (
                &VmmAction::UpdateBlockDevicePath(ref drive_id, ref path_on_host, _),
                &VmmAction::UpdateBlockDevicePath(ref other_drive_id, ref other_path_on_host, _),
            ) => drive_id == other_drive_id && path_on_host == other_path_on_host,
            (
                &VmmAction::ConfigureBootSource(ref boot_source, _),
                &VmmAction::ConfigureBootSource(ref other_boot_source, _),
            ) => boot_source == other_boot_source,
            (
                &VmmAction::InsertBlockDevice(ref block_device, _),
                &VmmAction::InsertBlockDevice(ref other_other_block_device, _),
            ) => block_device == other_other_block_device,
            (
                &VmmAction::ConfigureLogger(ref log, _),
                &VmmAction::ConfigureLogger(ref other_log, _),
            ) => log == other_log,
            (
                &VmmAction::SetVmConfiguration(ref vm_config, _),
                &VmmAction::SetVmConfiguration(ref other_vm_config, _),
            ) => vm_config == other_vm_config,
            (
                &VmmAction::InsertNetworkDevice(ref net_dev, _),
                &VmmAction::InsertNetworkDevice(ref other_net_dev, _),
            ) => net_dev == other_net_dev,
            (
                &VmmAction::UpdateNetworkInterface(ref net_dev, _),
                &VmmAction::UpdateNetworkInterface(ref other_net_dev, _),
            ) => net_dev == other_net_dev,
            (
                &VmmAction::RescanBlockDevice(ref req, _),
                &VmmAction::RescanBlockDevice(ref other_req, _),
            ) => req == other_req,
            (&VmmAction::StartMicroVm(_), &VmmAction::StartMicroVm(_)) => true,
            (&VmmAction::SendCtrlAltDel(_), &VmmAction::SendCtrlAltDel(_)) => true,
            (&VmmAction::FlushMetrics(_), &VmmAction::FlushMetrics(_)) => true,
            _ => false,
        }
    }
}

/// Starts a new vmm thread that can service API requests.
///
/// # Arguments
///
/// * `api_shared_info` - A parameter for storing information on the VMM (e.g the current state).
/// * `api_event_fd` - An event fd used for receiving API associated events.
/// * `from_api` - The receiver end point of the communication channel.
/// * `seccomp_level` - The level of seccomp filtering used. Filters are loaded before executing
///                     guest code. Can be one of 0 (seccomp disabled), 1 (filter by syscall
///                     number) or 2 (filter by syscall number and argument values).
/// * `kvm_fd` - Provides the option of supplying an already existing raw file descriptor
///              associated with `/dev/kvm`.
pub fn start_vmm_thread(
    api_shared_info: Arc<RwLock<InstanceInfo>>,
    api_event_fd: EventFd,
    from_api: Receiver<Box<VmmAction>>,
    seccomp_level: u32,
    snapfaas_config: SnapFaaSConfig,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("fc_vmm".to_string())
        .spawn(move || {
            // If this fails, consider it fatal. Use expect().
            let mut vmm = Vmm::new(api_shared_info, api_event_fd, from_api, seccomp_level, snapfaas_config)
                .expect("Cannot create VMM");
            match vmm.run_control() {
                Ok(()) => {
                    info!("Gracefully terminated VMM control loop");
                    vmm.stop(i32::from(FC_EXIT_CODE_OK))
                }
                Err(e) => {
                    error!("Abruptly exited VMM control loop: {:?}", e);
                    vmm.stop(i32::from(FC_EXIT_CODE_GENERIC_ERROR));
                }
            }
        })
        .expect("VMM thread spawn failed.")
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use super::*;

    use serde_json::Value;
    use std::env;
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::sync::atomic::AtomicUsize;

    use self::tempfile::NamedTempFile;
    use devices::virtio::ActivateResult;
    use net_util::MacAddr;
    use vmm_config::machine_config::CpuFeaturesTemplate;
    use vmm_config::{RateLimiterConfig, TokenBucketConfig};

    fn good_kernel_file() -> PathBuf {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = path.parent().unwrap();

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return [parent.to_str().unwrap(), "kernel/src/loader/test_elf.bin"]
            .iter()
            .collect();
        #[cfg(target_arch = "aarch64")]
        return [parent.to_str().unwrap(), "kernel/src/loader/test_pe.bin"]
            .iter()
            .collect();
    }

    impl Vmm {
        fn get_kernel_cmdline_str(&self) -> &str {
            if let Some(ref k) = self.kernel_config {
                k.cmdline.as_str()
            } else {
                ""
            }
        }

        fn remove_addr(&mut self, id: &str) {
            self.mmio_device_manager
                .as_mut()
                .unwrap()
                .remove_address(id);
        }

        fn default_kernel_config(&mut self, cust_kernel_path: Option<PathBuf>) {
            let kernel_temp_file =
                NamedTempFile::new().expect("Failed to create temporary kernel file.");
            let mut kernel_path = kernel_temp_file.path().to_path_buf();

            if cust_kernel_path.is_some() {
                kernel_path = cust_kernel_path.unwrap();
            }
            let kernel_file = File::open(kernel_path).expect("Cannot open kernel file");
            let mut cmdline = kernel_cmdline::Cmdline::new(arch::arch64::CMDLINE_MAX_SIZE);
            assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
            let kernel_cfg = KernelConfig {
                cmdline,
                kernel_file,
                // cmdline_addr: GuestAddress(arch::arch64::CMDLINE_START),
            };
            self.configure_kernel(kernel_cfg);
        }

        fn set_instance_state(&mut self, instance_state: InstanceState) {
            self.shared_info.write().unwrap().state = instance_state;
        }

        fn update_block_device_path(&mut self, block_device_id: &str, new_path: PathBuf) {
            for config in self.block_device_configs.config_list.iter_mut() {
                if config.drive_id == block_device_id {
                    config.path_on_host = new_path;
                    break;
                }
            }
        }

        fn change_id(&mut self, prev_id: &str, new_id: &str) {
            for config in self.block_device_configs.config_list.iter_mut() {
                if config.drive_id == prev_id {
                    config.drive_id = new_id.to_string();
                    break;
                }
            }
        }
    }

    struct DummyEpollHandler {
        evt: Option<DeviceEventT>,
        flags: Option<u32>,
        payload: Option<EpollHandlerPayload>,
    }

    impl EpollHandler for DummyEpollHandler {
        fn handle_event(
            &mut self,
            device_event: DeviceEventT,
            event_flags: u32,
            payload: EpollHandlerPayload,
        ) -> std::result::Result<(), devices::Error> {
            self.evt = Some(device_event);
            self.flags = Some(event_flags);
            self.payload = Some(payload);
            Ok(())
        }
    }

    #[allow(dead_code)]
    #[derive(Clone)]
    struct DummyDevice {
        dummy: u32,
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            0
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &[10]
        }

        fn ack_features(&mut self, page: u32, value: u32) {
            let _ = page;
            let _ = value;
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

        #[allow(unused_variables)]
        #[allow(unused_mut)]
        fn activate(
            &mut self,
            mem: GuestMemory,
            interrupt_evt: EventFd,
            status: Arc<AtomicUsize>,
            queues: Vec<devices::virtio::Queue>,
            mut queue_evts: Vec<EventFd>,
        ) -> ActivateResult {
            Ok(())
        }
    }

    fn create_vmm_object(state: InstanceState) -> Vmm {
        let shared_info = Arc::new(RwLock::new(InstanceInfo {
            state,
            id: "TEST_ID".to_string(),
            vmm_version: "1.0".to_string(),
        }));

        let (_to_vmm, from_api) = channel();
        // Vmm::new(
            // shared_info,
            // EventFd::new().expect("cannot create eventFD"),
            // from_api,
            // seccomp::SECCOMP_LEVEL_ADVANCED,
        // )
        // .expect("Cannot Create VMM")
    }

    #[test]
    fn test_device_handler() {
        let mut ep = EpollContext::new().unwrap();
        let (base, sender) = ep.allocate_tokens(1);
        assert_eq!(ep.device_handlers.len(), 1);
        assert_eq!(base, 1);

        let handler = DummyEpollHandler {
            evt: None,
            flags: None,
            payload: None,
        };
        assert!(sender.send(Box::new(handler)).is_ok());
        assert!(ep.get_device_handler(0).is_ok());
    }

    #[test]
    fn test_insert_block_device() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let f = NamedTempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("root"),
        //     path_on_host: f.path().to_path_buf(),
        //     is_root_device: true,
        //     partuuid: None,
        //     is_read_only: false,
        //     rate_limiter: None,
        // };
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm
            .block_device_configs
            .config_list
            .contains(&root_block_device));

        // Test that updating a block device returns the correct output.
        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("root"),
        //     path_on_host: f.path().to_path_buf(),
        //     is_root_device: true,
        //     partuuid: None,
        //     is_read_only: true,
        //     rate_limiter: None,
        // };
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm
            .block_device_configs
            .config_list
            .contains(&root_block_device));

        // Test insert second drive with the same path fails.
        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("dummy_dev"),
        //     path_on_host: f.path().to_path_buf(),
        //     is_root_device: false,
        //     partuuid: None,
        //     is_read_only: true,
        //     rate_limiter: None,
        // };
        // assert!(vmm.insert_block_device(root_block_device.clone()).is_err());

        // // Test inserting a second drive is ok.
        // let f = NamedTempFile::new().unwrap();
        // // Test that creating a new block device returns the correct output.
        // let non_root = BlockDeviceConfig {
        //     drive_id: String::from("non_root"),
        //     path_on_host: f.path().to_path_buf(),
        //     is_root_device: false,
        //     partuuid: None,
        //     is_read_only: false,
        //     rate_limiter: None,
        // };
        // assert!(vmm.insert_block_device(non_root).is_ok());

        // // Test that making the second device root fails (it would result in 2 root block
        // // devices.
        // let non_root = BlockDeviceConfig {
        //     drive_id: String::from("non_root"),
        //     path_on_host: f.path().to_path_buf(),
        //     is_root_device: true,
        //     partuuid: None,
        //     is_read_only: false,
        //     rate_limiter: None,
        // };
        // assert!(vmm.insert_block_device(non_root).is_err());

        // // Test update after boot.
        // vmm.set_instance_state(InstanceState::Running);
        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("root"),
        //     path_on_host: f.path().to_path_buf(),
        //     is_root_device: false,
        //     partuuid: None,
        //     is_read_only: true,
        //     rate_limiter: None,
        // };
        assert!(vmm.insert_block_device(root_block_device).is_err())
    }

    #[test]
    fn test_insert_net_device() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // test create network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };
        assert!(vmm.insert_net_device(network_interface).is_ok());

        let mac = MacAddr::parse_str("01:23:45:67:89:0A").unwrap();
        // test update network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname2"),
            guest_mac: Some(mac),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };
        assert!(vmm.insert_net_device(network_interface).is_ok());

        // Test insert new net device with same mac fails.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif2"),
            host_dev_name: String::from("hostname3"),
            guest_mac: Some(mac),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };
        assert!(vmm.insert_net_device(network_interface).is_err());

        // Test that update post-boot fails.
        vmm.set_instance_state(InstanceState::Running);
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname2"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };
        assert!(vmm.insert_net_device(network_interface).is_err());
    }

    #[test]
    fn test_update_net_device() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        let tbc_1mtps = TokenBucketConfig {
            size: 1024 * 1024,
            one_time_burst: None,
            refill_time: 1000,
        };
        let tbc_2mtps = TokenBucketConfig {
            size: 2 * 1024 * 1024,
            one_time_burst: None,
            refill_time: 1000,
        };

        vmm.insert_net_device(NetworkInterfaceConfig {
            iface_id: String::from("1"),
            host_dev_name: String::from("hostname5"),
            guest_mac: None,
            rx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: Some(tbc_1mtps),
                ops: None,
            }),
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        })
        .unwrap();

        vmm.update_net_device(NetworkInterfaceUpdateConfig {
            iface_id: "1".to_string(),
            rx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: None,
                ops: Some(tbc_2mtps),
            }),
            tx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: None,
                ops: Some(tbc_2mtps),
            }),
        })
        .unwrap();

        {
            let nic_1: &mut NetworkInterfaceConfig =
                vmm.network_interface_configs.iter_mut().next().unwrap();
            // The RX bandwidth should be unaffected.
            assert_eq!(nic_1.rx_rate_limiter.unwrap().bandwidth.unwrap(), tbc_1mtps);
            // The RX ops should be set to 2mtps.
            assert_eq!(nic_1.rx_rate_limiter.unwrap().ops.unwrap(), tbc_2mtps);
            // The TX bandwith should be unlimited (unaffected).
            assert_eq!(nic_1.tx_rate_limiter.unwrap().bandwidth, None);
            // The TX ops should be set to 2mtps.
            assert_eq!(nic_1.tx_rate_limiter.unwrap().ops.unwrap(), tbc_2mtps);
        }

        vmm.init_guest_memory().unwrap();
        vmm.default_kernel_config(None);
        let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );
        // vmm.attach_net_devices(&mut device_manager).unwrap();
        vmm.set_instance_state(InstanceState::Running);

        // The update should fail before device activation.
        assert!(vmm
            .update_net_device(NetworkInterfaceUpdateConfig {
                iface_id: "1".to_string(),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            })
            .is_err());

        // Fake device activation by explicitly setting a dummy epoll handler.
        vmm.epoll_context.device_handlers[0].handler = Some(Box::new(DummyEpollHandler {
            evt: None,
            flags: None,
            payload: None,
        }));
        vmm.update_net_device(NetworkInterfaceUpdateConfig {
            iface_id: "1".to_string(),
            rx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: Some(tbc_2mtps),
                ops: None,
            }),
            tx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: Some(tbc_1mtps),
                ops: None,
            }),
        })
        .unwrap();
    }

    #[test]
    #[allow(clippy::cyclomatic_complexity)]
    fn test_machine_configuration() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // test the default values of machine config
        // vcpu_count = 1
        assert_eq!(vmm.vm_config.vcpu_count, Some(1));
        // mem_size = 128
        assert_eq!(vmm.vm_config.mem_size_mib, Some(128));
        // ht_enabled = false
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        // no cpu template
        assert!(vmm.vm_config.cpu_template.is_none());

        // 1. Tests with no hyperthreading
        // test put machine configuration for vcpu count with valid value
        let machine_config = VmConfig {
            vcpu_count: Some(3),
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_ok());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(128));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));

        // test put machine configuration for mem size with valid value
        let machine_config = VmConfig {
            vcpu_count: None,
            mem_size_mib: Some(256),
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_ok());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(256));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));

        // Test Error cases for put_machine_configuration with invalid value for vcpu_count
        // Test that the put method return error & that the vcpu value is not changed
        let machine_config = VmConfig {
            vcpu_count: Some(0),
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));

        // Test Error cases for put_machine_configuration with invalid value for the mem_size_mib
        // Test that the put method return error & that the mem_size_mib value is not changed
        let machine_config = VmConfig {
            vcpu_count: Some(1),
            mem_size_mib: Some(0),
            ht_enabled: Some(false),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(256));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        assert!(vmm.vm_config.cpu_template.is_none());

        // 2. Test with hyperthreading enabled
        // Test that you can't change the hyperthreading value to false when the vcpu count
        // is odd
        let machine_config = VmConfig {
            vcpu_count: None,
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        // Test that you can change the ht flag when you have a valid vcpu count
        // Also set the CPU Template since we are here
        let machine_config = VmConfig {
            vcpu_count: Some(2),
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(vmm.set_vm_configuration(machine_config).is_ok());
        assert_eq!(vmm.vm_config.vcpu_count, Some(2));
        assert_eq!(vmm.vm_config.ht_enabled, Some(true));
        assert_eq!(vmm.vm_config.cpu_template, Some(CpuFeaturesTemplate::T2));

        // 3. Test update vm configuration after boot.
        vmm.set_instance_state(InstanceState::Running);
        let machine_config = VmConfig {
            vcpu_count: Some(2),
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
    }

    #[test]
    fn new_epoll_context_test() {
        assert!(EpollContext::new().is_ok());
    }

    #[test]
    fn enable_disable_stdin_test() {
        let mut ep = EpollContext::new().unwrap();
        // enabling stdin should work
        assert!(ep.enable_stdin_event().is_ok());

        // doing it again should fail
        // TODO: commented out because stdin & /dev/null related issues, as mentioned in another
        // comment from enable_stdin_event().
        // assert!(ep.enable_stdin_event().is_err());

        // disabling stdin should work
        assert!(ep.disable_stdin_event().is_ok());

        // enabling stdin should work now
        assert!(ep.enable_stdin_event().is_ok());
        // disabling it again should work
        assert!(ep.disable_stdin_event().is_ok());
    }

    #[test]
    fn add_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        let epev = ep.add_event(evfd, EpollDispatch::Exit);
        assert!(epev.is_ok());
    }

    #[test]
    fn epoll_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        let epev = ep.add_event(evfd, EpollDispatch::Exit);
        assert!(epev.is_ok());
        let epev = epev.unwrap();

        let evpoll_events_len = 10;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); evpoll_events_len];

        // epoll should have no pending events
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 0);

        // raise the event
        assert!(epev.fd.write(1).is_ok());

        // epoll should report one event
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 1);

        // reported event should be the one we raised
        let idx = events[0].data as usize;
        assert!(ep.dispatch_table[idx].is_some());
        assert_eq!(
            *ep.dispatch_table[idx].as_ref().unwrap(),
            EpollDispatch::Exit
        );
    }

    #[test]
    fn test_kvm_context() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::FromRawFd;

        let c = KvmContext::new().unwrap();

        assert!(c.max_memslots >= 32);

        let kvm = Kvm::new().unwrap();
        let f = unsafe { File::from_raw_fd(kvm.as_raw_fd()) };
        let m1 = f.metadata().unwrap();
        let m2 = File::open("/dev/kvm").unwrap().metadata().unwrap();

        assert_eq!(m1.dev(), m2.dev());
        assert_eq!(m1.ino(), m2.ino());
    }

    #[test]
    fn test_check_health() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.check_health().is_err());

        let dummy_addr = GuestAddress(0x1000);
        // vmm.configure_kernel(KernelConfig {
        //     cmdline_addr: dummy_addr,
        //     cmdline: kernel_cmdline::Cmdline::new(10),
        //     kernel_file: tempfile::tempfile().unwrap(),
        // });
        assert!(vmm.check_health().is_ok());
    }

    #[test]
    fn test_is_instance_initialized() {
        let vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(vmm.is_instance_initialized(), false);

        let vmm = create_vmm_object(InstanceState::Starting);
        assert_eq!(vmm.is_instance_initialized(), true);

        let vmm = create_vmm_object(InstanceState::Halting);
        assert_eq!(vmm.is_instance_initialized(), true);

        let vmm = create_vmm_object(InstanceState::Halted);
        assert_eq!(vmm.is_instance_initialized(), true);

        let vmm = create_vmm_object(InstanceState::Running);
        assert_eq!(vmm.is_instance_initialized(), true);
    }

    #[test]
    fn test_attach_block_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let block_file = NamedTempFile::new().unwrap();

        // Use Case 1: Root Block Device is not specified through PARTUUID.
        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("root"),
        //     path_on_host: block_file.path().to_path_buf(),
        //     is_root_device: true,
        //     partuuid: None,
        //     is_read_only: false,
        //     rate_limiter: None,
        // };
        // // Test that creating a new block device returns the correct output.
        // assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        // assert!(vmm.init_guest_memory().is_ok());
        // assert!(vmm.guest_memory.is_some());

        // vmm.default_kernel_config(None);

        // let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );
        // assert!(vmm.attach_block_devices(&mut device_manager).is_ok());
        // assert!(vmm.get_kernel_cmdline_str().contains("root=/dev/vda"));

        // // Use Case 2: Root Block Device is specified through PARTUUID.
        // let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("root"),
        //     path_on_host: block_file.path().to_path_buf(),
        //     is_root_device: true,
        //     partuuid: Some("0eaa91a0-01".to_string()),
        //     is_read_only: false,
        //     rate_limiter: None,
        // };

        // // Test that creating a new block device returns the correct output.
        // assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        // assert!(vmm.init_guest_memory().is_ok());
        // assert!(vmm.guest_memory.is_some());

        // vmm.default_kernel_config(None);

        // let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );
        // assert!(vmm.attach_block_devices(&mut device_manager).is_ok());
        // assert!(vmm
        //     .get_kernel_cmdline_str()
        //     .contains("root=PARTUUID=0eaa91a0-01"));

        // // Use Case 3: Root Block Device is not added at all.
        // let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        // let non_root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("not_root"),
        //     path_on_host: block_file.path().to_path_buf(),
        //     is_root_device: false,
        //     partuuid: Some("0eaa91a0-01".to_string()),
        //     is_read_only: false,
        //     rate_limiter: None,
        // };

        // // Test that creating a new block device returns the correct output.
        // assert!(vmm
        //     .insert_block_device(non_root_block_device.clone())
        //     .is_ok());
        // assert!(vmm.init_guest_memory().is_ok());
        // assert!(vmm.guest_memory.is_some());

        // vmm.default_kernel_config(None);

        // let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );
        // assert!(vmm.attach_block_devices(&mut device_manager).is_ok());
        // Test that kernel commandline does not contain either /dev/vda or PARTUUID.
        assert!(!vmm.get_kernel_cmdline_str().contains("root=PARTUUID="));
        assert!(!vmm.get_kernel_cmdline_str().contains("root=/dev/vda"));

        // Test that the non root device is attached.
        assert!(device_manager
            .get_address(&non_root_block_device.drive_id)
            .is_some());

        // Test partial update of block devices.
        let new_block = NamedTempFile::new().unwrap();
        let path = String::from(new_block.path().to_path_buf().to_str().unwrap());
        assert!(vmm
            .set_block_device_path("not_root".to_string(), path)
            .is_ok());

        // Test partial update of block device fails due to invalid file.
        assert!(vmm
            .set_block_device_path("not_root".to_string(), String::from("dummy_path"))
            .is_err());
    }

    #[test]
    fn test_attach_net_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory.is_some());

        vmm.default_kernel_config(None);

        let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     // arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );

        // test create network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname3"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };

        assert!(vmm.insert_net_device(network_interface).is_ok());

        // assert!(vmm.attach_net_devices(&mut device_manager).is_ok());
        // a second call to attach_net_devices should fail because when
        // we are creating the virtio::Net object, we are taking the tap.
        // assert!(vmm.attach_net_devices(&mut device_manager).is_err());
    }

    #[test]
    fn test_init_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);
        assert!(vmm.init_guest_memory().is_ok());

        assert!(vmm.attach_virtio_devices().is_ok());
    }

    #[test]
    fn test_configure_boot_source() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // Test invalid kernel path.
        assert!(vmm
            .configure_boot_source(String::from("dummy-path"), None)
            .is_err());

        // Test valid kernel path and invalid cmdline.
        let kernel_file = NamedTempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file.path().to_path_buf().to_str().unwrap());
        let invalid_cmdline = String::from_utf8(vec![b'X'; arch::CMDLINE_MAX_SIZE + 1]).unwrap();
        assert!(vmm
            .configure_boot_source(kernel_path.clone(), Some(invalid_cmdline))
            .is_err());

        // Test valid configuration.
        assert!(vmm.configure_boot_source(kernel_path.clone(), None).is_ok());
        assert!(vmm
            .configure_boot_source(kernel_path.clone(), Some(String::from("reboot=k")))
            .is_ok());

        // Test valid configuration after boot (should fail).
        vmm.set_instance_state(InstanceState::Running);
        assert!(vmm
            .configure_boot_source(kernel_path.clone(), None)
            .is_err());
    }

    #[test]
    fn test_rescan() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        let root_file = NamedTempFile::new().unwrap();
        let scratch_file = NamedTempFile::new().unwrap();
        let scratch_id = "not_root".to_string();

        // let root_block_device = BlockDeviceConfig {
        //     drive_id: String::from("root"),
        //     path_on_host: root_file.path().to_path_buf(),
        //     is_root_device: true,
        //     partuuid: None,
        //     is_read_only: false,
        //     rate_limiter: None,
        // };
        // let non_root_block_device = BlockDeviceConfig {
        //     drive_id: scratch_id.clone(),
        //     path_on_host: scratch_file.path().to_path_buf(),
        //     is_root_device: false,
        //     partuuid: None,
        //     is_read_only: true,
        //     rate_limiter: None,
        // };

        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm
            .insert_block_device(non_root_block_device.clone())
            .is_ok());

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory.is_some());

        let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );

        let dummy_box = Box::new(DummyDevice { dummy: 0 });
        // Use a dummy command line as it is not used in this test.
        let _addr = device_manager
            .register_device(
                vmm.vm.get_fd(),
                dummy_box,
                &mut kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE),
                Some(scratch_id.clone()),
            )
            .unwrap();

        vmm.mmio_device_manager = Some(device_manager);
        vmm.set_instance_state(InstanceState::Running);

        // Test valid rescan_block_device.
        assert!(vmm.rescan_block_device(&scratch_id).is_ok());

        // Test rescan block device with size not a multiple of sector size.
        let new_size = 10 * virtio::block::SECTOR_SIZE + 1;
        scratch_file.as_file().set_len(new_size).unwrap();
        assert!(vmm.rescan_block_device(&scratch_id).is_ok());

        // Test rescan block device with invalid path.
        let prev_path = non_root_block_device.path_on_host().clone();
        vmm.update_block_device_path(&scratch_id, PathBuf::from("foo"));
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::BlockDeviceUpdateFailed,
            )) => (),
            _ => assert!(false),
        }
        vmm.update_block_device_path(&scratch_id, prev_path);

        // Test rescan_block_device with invalid ID.
        match vmm.rescan_block_device(&"foo".to_string()) {
            Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDeviceID)) => {
            }
            _ => assert!(false),
        }
        vmm.change_id(&scratch_id, "scratch");
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::BlockDeviceUpdateFailed,
            )) => (),
            _ => assert!(false),
        }

        // Test rescan_block_device with invalid device address.
        vmm.remove_addr(&scratch_id);
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDeviceID)) => {
            }
            _ => assert!(false),
        }

        // Test rescan not allowed.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm
            .insert_block_device(non_root_block_device.clone())
            .is_ok());
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::OperationNotAllowedPreBoot,
            )) => (),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_init_logger_from_api() {
        // Error case: update after instance is running
        let log_file = NamedTempFile::new().unwrap();
        let metrics_file = NamedTempFile::new().unwrap();
        let desc = LoggerConfig {
            log_fifo: log_file.path().to_str().unwrap().to_string(),
            metrics_fifo: metrics_file.path().to_str().unwrap().to_string(),
            level: LoggerLevel::Warning,
            show_level: true,
            show_log_origin: true,
            options: Value::Array(vec![]),
        };

        let mut vmm = create_vmm_object(InstanceState::Running);
        assert!(vmm.init_logger(desc).is_err());

        // Reset vmm state to test the other scenarios.
        vmm.set_instance_state(InstanceState::Uninitialized);

        // Error case: initializing logger with invalid pipes returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
            options: Value::Array(vec![]),
        };
        assert!(vmm.init_logger(desc).is_err());

        // Error case: initializing logger with invalid option flags returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
            options: Value::Array(vec![Value::String("foobar".to_string())]),
        };
        assert!(vmm.init_logger(desc).is_err());

        // Initializing logger with valid pipes is ok.
        let log_file = NamedTempFile::new().unwrap();
        let metrics_file = NamedTempFile::new().unwrap();
        let desc = LoggerConfig {
            log_fifo: log_file.path().to_str().unwrap().to_string(),
            metrics_fifo: metrics_file.path().to_str().unwrap().to_string(),
            level: LoggerLevel::Info,
            show_level: true,
            show_log_origin: true,
            options: Value::Array(vec![Value::String("LogDirtyPages".to_string())]),
        };
        // Flushing metrics before initializing logger is erroneous.
        let err = vmm.flush_metrics();
        assert!(err.is_err());
        assert_eq!(
            format!("{:?}", err.unwrap_err()),
            "Logger(Internal, FlushMetrics(\"Logger was not initialized.\"))"
        );

        assert!(vmm.init_logger(desc).is_ok());

        assert!(vmm.flush_metrics().is_ok());

        let f = File::open(metrics_file).unwrap();
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("utc_timestamp_ms"));

        // It is safe to do that because the tests are run sequentially (so no other test may be
        // writing to the same file.
        assert!(vmm.flush_metrics().is_ok());
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("utc_timestamp_ms"));

        // Validate logfile works.
        warn!("this is a test");

        let f = File::open(log_file).unwrap();
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        loop {
            if line.contains("this is a test") {
                break;
            }
            if reader.read_line(&mut line).unwrap() == 0 {
                // If it ever gets here, this assert will fail.
                assert!(line.contains("this is a test"));
            }
        }

        // Validate logging the boot time works.
        Vmm::log_boot_time(&TimestampUs::default());
        let mut line = String::new();
        loop {
            if line.contains("Guest-boot-time =") {
                break;
            }
            if reader.read_line(&mut line).unwrap() == 0 {
                // If it ever gets here, this assert will fail.
                assert!(line.contains("Guest-boot-time ="));
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_dirty_page_count() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(vmm.get_dirty_page_count(), 0);
        // Booting an actual guest and getting real data is covered by `kvm::tests::run_code_test`.
    }

    #[test]
    fn test_create_vcpus() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.get_memory().is_some());

        // #[cfg(target_arch = "x86_64")]
        // `KVM_CREATE_VCPU` fails if the irqchip is not created beforehand. This is x86_64 speciifc.
        // vmm.vm
        //     .setup_irqchip(
        //         &vmm.legacy_device_manager.com_evt_1_3,
        //         &vmm.legacy_device_manager.com_evt_2_4,
        //         &vmm.legacy_device_manager.kbd_evt,
        //     )
        //     .expect("Cannot create IRQCHIP");

        // let guest_mem = vmm.guest_memory.clone().unwrap();
        // let mut device_manager = MMIODeviceManager::new(
        //     guest_mem.clone(),
        //     arch::get_reserved_mem_addr() as u64,
        //     (arch::IRQ_BASE, arch::IRQ_MAX),
        // );

        let dummy_box = Box::new(DummyDevice { dummy: 0 });
        // Use a dummy command line as it is not used in this test.
        let _addr = device_manager
            .register_device(
                vmm.vm.get_fd(),
                dummy_box,
                &mut kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE),
                Some("bogus".to_string()),
            )
            .unwrap();

        vmm.mmio_device_manager = Some(device_manager);
        assert!(vmm
            .create_vcpus(GuestAddress(0x0), TimestampUs::default())
            .is_ok());
    }

    #[test]
    fn test_setup_interrupt_controller() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.setup_interrupt_controller().is_ok());
    }

    #[test]
    fn test_load_kernel() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Cannot start microvm without kernel configuration."
        );

        vmm.default_kernel_config(None);

        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Invalid Memory Configuration: MemoryNotInitialized"
        );

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.get_memory().is_some());

        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Cannot load kernel due to invalid memory configuration or invalid kernel image. Failed to read ELF header"
        );

        vmm.default_kernel_config(Some(good_kernel_file()));
        assert!(vmm.load_kernel().is_ok());
    }

    // #[test]
    // fn test_configure_system() {
    //     let mut vmm = create_vmm_object(InstanceState::Uninitialized);
    //     assert_eq!(
    //         vmm.configure_system().unwrap_err().to_string(),
    //         "Cannot start microvm without kernel configuration."
    //     );

    //     vmm.default_kernel_config(None);

    //     assert_eq!(
    //         vmm.configure_system().unwrap_err().to_string(),
    //         "Invalid Memory Configuration: MemoryNotInitialized"
    //     );

    //     assert!(vmm.init_guest_memory().is_ok());
    //     assert!(vmm.vm.get_memory().is_some());

    //     assert!(vmm.configure_system().is_ok());
    // }

    #[test]
    fn test_attach_virtio_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.get_memory().is_some());

        // Create test network interface.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };

        assert!(vmm.insert_net_device(network_interface).is_ok());
        assert!(vmm.attach_virtio_devices().is_ok());
        assert!(vmm.mmio_device_manager.is_some());
    }

    #[test]
    fn test_attach_legacy_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        assert!(vmm.attach_legacy_devices().is_ok());
        assert!(vmm.legacy_device_manager.io_bus.get_device(0x3f8).is_some());
        assert!(vmm.legacy_device_manager.io_bus.get_device(0x2f8).is_some());
        assert!(vmm.legacy_device_manager.io_bus.get_device(0x3e8).is_some());
        assert!(vmm.legacy_device_manager.io_bus.get_device(0x2e8).is_some());
        assert!(vmm.legacy_device_manager.io_bus.get_device(0x060).is_some());
        let stdin_handle = io::stdin();
        stdin_handle.lock().set_canon_mode().unwrap();
    }

    #[test]
    fn test_error_messages() {
        // Enum `Error`

        assert_eq!(
            format!("{:?}", Error::ApiChannel),
            "ApiChannel: error receiving data from the API server"
        );
        assert_eq!(
            format!(
                "{:?}",
                Error::CreateLegacyDevice(device_manager::legacy::Error::EventFd(
                    io::Error::from_raw_os_error(42)
                ))
            ),
            format!(
                "Error creating legacy device: EventFd({:?})",
                io::Error::from_raw_os_error(42)
            )
        );
        assert_eq!(
            format!("{:?}", Error::EpollFd(io::Error::from_raw_os_error(42))),
            "Epoll fd error: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::EventFd(io::Error::from_raw_os_error(42))),
            "Event fd error: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::DeviceEventHandlerNotFound),
            "Device event handler not found. This might point to a guest device driver issue."
        );
        assert_eq!(
            format!("{:?}", Error::Kvm(io::Error::from_raw_os_error(42))),
            "Cannot open /dev/kvm. Error: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::KvmApiVersion(42)),
            "Bad KVM API version: 42"
        );
        assert_eq!(
            format!("{:?}", Error::KvmCap(Cap::Hlt)),
            "Missing KVM capability: Hlt"
        );
        assert_eq!(
            format!("{:?}", Error::Poll(io::Error::from_raw_os_error(42))),
            "Epoll wait failed: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::Serial(io::Error::from_raw_os_error(42))),
            format!(
                "Error writing to the serial console: {:?}",
                io::Error::from_raw_os_error(42)
            )
        );
        assert_eq!(
            format!("{:?}", Error::TimerFd(io::Error::from_raw_os_error(42))),
            "Error creating timer fd: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::Vm(vstate::Error::HTNotInitialized)),
            "Error opening VM fd: HTNotInitialized"
        );

        // Enum `ErrorKind`

        assert_eq!(format!("{:?}", ErrorKind::User), "User");
        assert_eq!(format!("{:?}", ErrorKind::Internal), "Internal");

        // Enum VmmActionError

        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::BootSource(
                    ErrorKind::User,
                    BootSourceConfigError::InvalidKernelCommandLine
                )
            ),
            "BootSource(User, InvalidKernelCommandLine)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::DriveConfig(
                    ErrorKind::User,
                    DriveError::BlockDevicePathAlreadyExists
                )
            ),
            "DriveConfig(User, BlockDevicePathAlreadyExists)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::Logger(
                    ErrorKind::User,
                    LoggerConfigError::InitializationFailure(String::from("foobar"))
                )
            ),
            "Logger(User, InitializationFailure(\"foobar\"))"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::InvalidMemorySize)
            ),
            "MachineConfig(User, InvalidMemorySize)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::NetworkConfig(
                    ErrorKind::User,
                    NetworkInterfaceError::DeviceIdNotFound
                )
            ),
            "NetworkConfig(User, DeviceIdNotFound)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::StartMicrovm(ErrorKind::User, StartMicrovmError::EventFd)
            ),
            "StartMicrovm(User, EventFd)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::SendCtrlAltDel(
                    ErrorKind::User,
                    I8042DeviceError::InternalBufferFull
                )
            ),
            "SendCtrlAltDel(User, InternalBufferFull)"
        );
        #[cfg(feature = "vsock")]
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::VsockConfig(ErrorKind::User, VsockError::UpdateNotAllowedPostBoot)
            ),
            "VsockConfig(User, UpdateNotAllowedPostBoot)"
        );
    }
}
