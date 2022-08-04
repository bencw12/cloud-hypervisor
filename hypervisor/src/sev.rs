use kvm_bindings::kvm_sev_cmd;
use kvm_bindings::kvm_sev_guest_status;
use kvm_bindings::kvm_sev_launch_measure;
use kvm_bindings::kvm_sev_launch_start;
use kvm_bindings::kvm_sev_launch_update_data;
use kvm_bindings::sev_cmd_id_KVM_SEV_INIT;
use kvm_bindings::sev_cmd_id_KVM_SEV_LAUNCH_START;
use kvm_bindings::sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA;
use kvm_bindings::{
    kvm_enc_region, sev_cmd_id_KVM_SEV_GUEST_STATUS, sev_cmd_id_KVM_SEV_LAUNCH_FINISH,
    sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
};
use kvm_ioctls::VmFd;
use linux_loader::loader::KernelLoader;
use std::fmt::Display;
use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::{arch::x86_64::__cpuid, fs::OpenOptions, os::unix::prelude::AsRawFd, sync::Arc, u64};
use thiserror::Error;
use vm_memory::Bytes;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

const MEASUREMENT_LEN: u32 = 48;
const FIRMWARE_ADDR: GuestAddress = GuestAddress(0x100000);
const KERNEL_ADDR: u64 = 0x2000000;

//This excludes SUCCESS=0 and ACTIVE=18
#[derive(Debug, Error)]
pub enum SevError {
    /// The platform state is invalid for this command
    InvalidPlatformState,
    /// The guest state is invalid for this command
    InvalidGuestState,
    /// The platform configuration is invalid
    InvalidConfig,
    /// A memory buffer is too small
    InvalidLength,
    /// The platform is already owned
    AlreadyOwned,
    /// The certificate is invalid
    InvalidCertificate,
    /// Request is not allowed by guest policy
    PolicyFailure,
    /// The guest is inactive
    Inactive,
    /// The address provided is inactive
    InvalidAddress,
    /// The provided signature is invalid
    BadSignature,
    /// The provided measurement is invalid
    BadMeasurement,
    /// The ASID is already owned
    AsidOwned,
    /// The ASID is invalid
    InvalidAsid,
    /// WBINVD instruction required
    WBINVDRequired,
    ///DF_FLUSH invocation required
    DfFlushRequired,
    /// The guest handle is invalid
    InvalidGuest,
    /// The command issued is invalid
    InvalidCommand,
    /// The error code returned by the SEV device is not valid
    InvalidErrorCode,
    Errno(i32),
}
#[derive(Debug)]
pub enum Error {
    FirmwareLoad,
}

impl Display for SevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u32> for SevError {
    fn from(code: u32) -> Self {
        match code {
            1 => Self::InvalidPlatformState,
            2 => Self::InvalidGuestState,
            3 => Self::InvalidConfig,
            4 => Self::InvalidLength,
            5 => Self::AlreadyOwned,
            6 => Self::InvalidCertificate,
            7 => Self::PolicyFailure,
            8 => Self::Inactive,
            9 => Self::InvalidAddress,
            10 => Self::BadSignature,
            11 => Self::BadMeasurement,
            12 => Self::AsidOwned,
            13 => Self::InvalidAsid,
            14 => Self::WBINVDRequired,
            15 => Self::DfFlushRequired,
            16 => Self::InvalidGuest,
            17 => Self::InvalidCommand,
            _ => Self::InvalidErrorCode,
        }
    }
}

pub type SevResult<T> = std::result::Result<T, SevError>;

/// SEV Guest states
#[derive(PartialEq)]
pub enum State {
    /// The guest is uninitialized
    UnInit,
    /// The SEV platform has been initialized
    Init,
    /// The guest is currently beign launched and plaintext data and VMCB save areas are being imported
    LaunchUpdate,
    /// The guest is currently being launched and ciphertext data are being imported
    LaunchSecret,
    /// The guest is fully launched or migrated in, and not being migrated out to another machine
    Running,
    /// The guest is currently being migrated out to another machine
    SendUpdate,
    /// The guest is currently being migrated from another machine
    RecieveUpdate,
    /// The guest has been sent to another machine
    Sent,
}
pub struct Sev {
    vm_fd: Arc<VmFd>,
    fd: File,
    handle: u32,
    policy: u32,
    state: State,
    measure: Vec<u8>,
    _cbitpos: u32,
    entry_point: GuestAddress,
    encryption: bool,
}

impl Sev {
    pub fn new(vm_fd: Arc<VmFd>, encryption: bool) -> Sev {
        //Open /dev/sev
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev")
            .unwrap();

        let ebx;

        //Get position of the C-bit
        unsafe {
            ebx = __cpuid(0x8000001F).ebx & 0x3f;
        }

        Sev {
            vm_fd,
            fd: fd,
            handle: 0,
            policy: 0,
            state: State::UnInit,
            measure: Vec::with_capacity(48),
            _cbitpos: ebx,
            entry_point: GuestAddress(0),
            encryption
        }
    }

    // load kernel unencrypted
    pub fn load_kernel<M: GuestMemory>(
        &mut self,
        mem: &M,
        kernel_path: &PathBuf,
    ) -> SevResult<u32> {
        let mut f = File::open(kernel_path.as_path()).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let len = f.seek(SeekFrom::End(0)).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();

        mem.read_exact_from(GuestAddress(KERNEL_ADDR), &mut f, len.try_into().unwrap())
            .unwrap();
        Ok(len as u32)
    }
    // Load the SEV firmware and encrypt
    pub fn load_firmware<M: GuestMemory>(
        &mut self,
        mem: &M,
        firmware_path: &PathBuf,
    ) -> Result<bool, Error> {
        use linux_loader::loader::{elf::Error::InvalidElfMagicNumber, Error::Elf};
        let mut f = File::open(firmware_path.as_path()).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let len = f.seek(SeekFrom::End(0)).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();

        //Check if firmware is pvh elf
        match linux_loader::loader::elf::Elf::load(
            mem, 
            None, 
            &mut f, 
            Some(GuestAddress(0x100000)),
        ) {
            Ok(entry_addr) => {
                //Need to encrypt ovmf here
                let addr = mem.get_host_address(FIRMWARE_ADDR).unwrap() as u64;
                let len = entry_addr.kernel_end - FIRMWARE_ADDR.0;
                let len = len - (len % 16) + 16;
                self.launch_update_data(addr, len as u32).unwrap();
                self.entry_point = entry_addr.kernel_load;
                entry_addr
            },
            Err(e) => match e {
                Elf(InvalidElfMagicNumber) => {
                    f.seek(SeekFrom::Start(0)).unwrap();
                    //If not an elf try flat binary firmware
                    mem.read_exact_from(FIRMWARE_ADDR, &mut f, len.try_into().unwrap())
                        .unwrap();
                    let addr = mem.get_host_address(FIRMWARE_ADDR).unwrap() as u64;
                    let len = len - (len % 16) + 16;
                    self.launch_update_data(addr, len as u32).unwrap();
                    self.entry_point = FIRMWARE_ADDR;
                    //also need a kernel if we loaded sev-fw
                    return Ok(true);
                }
                _ => {
                    return Err(Error::FirmwareLoad);
                }
            },
        };

        Ok(false)
    }

    fn sev_ioctl(&mut self, cmd: &mut kvm_sev_cmd) -> SevResult<()> {
        match self.vm_fd.encrypt_op_sev(cmd) {
            Err(err) => {
                if cmd.error > 0 {
                    return Err(SevError::from(cmd.error));
                } else {
                    return Err(SevError::Errno(err.errno()));
                }
            }
            _ => Ok(()),
        }
    }

    pub fn entry_point(&self) -> GuestAddress {
        self.entry_point
    }

    pub fn sev_init(&mut self) -> SevResult<()> {
        if self.state != State::UnInit {
            return Err(SevError::InvalidPlatformState);
        }
        let mut init = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_INIT,
            data: 0,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut init).unwrap();

        self.state = State::Init;

        self.sev_launch_start()
    }

    fn sev_launch_start(&mut self) -> SevResult<()> {
        if self.state != State::Init {
            return Err(SevError::InvalidPlatformState);
        }

        let start = kvm_sev_launch_start {
            handle: 0,
            policy: self.policy,
            //The remaining 4 fields are optional but should be explored later
            ..Default::default()
        };

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_START,
            data: &start as *const kvm_sev_launch_start as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.handle = start.handle;
        self.state = State::LaunchUpdate;
        Ok(())
    }

    pub fn launch_update_data(&mut self, addr: u64, len: u32) -> SevResult<()> {
        if !self.encryption {
            return Ok(())
        }


        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let region = kvm_sev_launch_update_data {
            uaddr: addr,
            len: len,
        };

        let mem_region = kvm_enc_region {
            addr: addr,
            size: len as u64,
        };

        //Tell kvm this memory region might contain encrypted data
        match self.vm_fd.register_enc_memory_region(&mem_region) {
            Ok(()) => {}
            Err(e) => return Err(SevError::Errno(e.errno())),
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
            data: &region as *const kvm_sev_launch_update_data as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        Ok(())
    }

    pub fn get_launch_measurement(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let len = MEASUREMENT_LEN;

        for _x in 0..len as usize {
            self.measure.push(0);
        }

        let mut measure: kvm_sev_launch_measure = Default::default();

        measure.uaddr = self.measure.as_ptr() as _;
        measure.len = len;

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
            data: &measure as *const kvm_sev_launch_measure as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::LaunchSecret;
        Ok(())
    }

    pub fn sev_launch_secret(&self) -> SevResult<()> {
        if self.state != State::LaunchSecret {
            return Err(SevError::InvalidPlatformState);
        }
        todo!()
    }

    pub fn sev_guest_state(&mut self) -> SevResult<State> {
        let state = kvm_sev_guest_status {
            handle: self.handle,
            policy: self.policy,
            state: 0,
        };

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_GUEST_STATUS,
            sev_fd: self.fd.as_raw_fd() as _,
            data: &state as *const kvm_sev_guest_status as u64,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        match state.state {
            0 => Ok(State::UnInit),
            1 => Ok(State::LaunchUpdate),
            2 => Ok(State::LaunchSecret),
            3 => Ok(State::Running),
            4 => Ok(State::SendUpdate),
            5 => Ok(State::RecieveUpdate),
            6 => Ok(State::Sent),
            _ => Err(SevError::InvalidGuestState),
        }
    }

    pub fn sev_launch_finish(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        if self.state != State::LaunchSecret {
            return Err(SevError::InvalidPlatformState);
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_FINISH,
            sev_fd: self.fd.as_raw_fd() as _,
            data: self.handle as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::Running;

        Ok(())
    }
}
