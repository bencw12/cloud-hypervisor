use std::{path::PathBuf, fs::File, io::{Seek, SeekFrom, Read}, mem, fmt, sync::{Arc, Mutex}};

use hypervisor::sev::{self, Sev};
use linux_loader::{bootparam::setup_header, elf::{elf64_phdr, elf64_hdr}, elf};
use vm_device::BusDevice;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap, bitmap::AtomicBitmap, Bytes, ByteValued, GuestAddressSpace, GuestAddress, GuestMemory};

//Constants for partial loading the kernel
const BZIMAGE_HEADER_OFFSET: u64 = 0x1f1;
const BZIMAGE_HEADER_MAGIC: u32 = 0x53726448;

const BZIMAGE_CODE: u32 = 0x0;
const DIRECT_CODE: u32 = 0x1;
const DATA_REGION_SIZE: u64 = 0x200000;  
const DATA_REGION_ADDR: u64 = 0x200000; 
pub const FW_CFG_REG: u64 = 0x81;

#[derive(PartialEq, Copy, Clone)]
enum KernelType {
    BzImage,
    Direct,
}

#[derive(PartialEq)]
enum State {
    WriteKernelType,
    WriteElfHdr,
    WritePhdrs,
    WriteSegs,
    WriteBzImageLen,
    WriteBzImageData,
}

enum Command {
    ///Get the type of kernel to load, should be the first command issued 
    ///(this is probably unsafe and there should be a 
    /// better way for the firmware to determine which type of kernel its loading)
    KernelType,
    ///Get the length of the bzImage
    BzImageLen,
    ///Start reading the bzImage in chunks
    BzimageData,
    ///For a direct boot, send the ELF header
    ElfHdr,
    ///For a direct boot, get the next phdr
    PhdrData,
    ///Start reading loadable segment data
    SegData,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    InvalidElfMagicNumber,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    ReadKernelDataStruct(&'static str),
    SeekKernelStart,
    SeekKernelImage,
    SeekProgramHeader,
    InvalidCommand,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::BigEndianElfOnLittle => "Unsupported ELF File byte order",
                Error::InvalidElfMagicNumber => "Invalid ELF magic number",
                Error::InvalidProgramHeaderSize => "Invalid ELF program header size",
                Error::InvalidProgramHeaderOffset => "Invalid ELF program header offset",
                Error::ReadKernelDataStruct(ref e) => e,
                Error::SeekKernelStart => {
                    "Failed to seek to file offset as pointed by the ELF program header"
                }
                Error::SeekKernelImage => "Failed to seek to offset of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
                Error::InvalidCommand => "Invalid command",
            }
        )
    }
}

impl TryFrom<u32> for Command {
    type Error = Error;

    fn try_from(code: u32) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::KernelType),
            1 => Ok(Self::BzImageLen),
            2 => Ok(Self::BzimageData),
            3 => Ok(Self::ElfHdr),
            4 => Ok(Self::PhdrData),
            5 => Ok(Self::SegData),
            _ => Err(Error::InvalidCommand)
        }
    }
}

impl Into<u32> for Command {
    fn into(self) -> u32 {
        match self {
            Self::KernelType => 0, 
            Self::BzImageLen => 1,
            Self::BzimageData => 2,
            Self::ElfHdr => 3,
            Self::PhdrData => 4,
            Self::SegData => 5,
        }
    }
}

impl KernelType {
    fn value(&self) -> u32 {
        match *self {
            Self::BzImage => BZIMAGE_CODE,
            Self::Direct => DIRECT_CODE,
        }
    }
}

pub struct FwCfg {
    _id: String,
    mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    kernel: File,
    kernel_type: KernelType,
    kernel_len: u64,
    ehdr: Option<elf64_hdr>,
    phdrs: Option<Vec<elf64_phdr>>,
    cur_phdr: usize,
    seg_pos: u64,
    cmd: Option<Command>,
    state: State,
}

impl FwCfg {
    pub fn new(
        kernel_path: PathBuf, 
        hashes_path: &PathBuf, 
        mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>, 
        sev: Arc<Mutex<Option<Sev>>>,
        _id: String) -> Self {
        info!("Creating fw_cfg device");

        let mut kernel = File::open(kernel_path).unwrap();
        let kernel_type = get_kernel_type(&mut kernel);

        let mut fw_cfg = FwCfg{
            _id,
            mem,
            kernel,
            kernel_len: 0,
            kernel_type,
            ehdr: None,
            phdrs: None,
            cmd: None,
            cur_phdr: 0,
            seg_pos: 0,
            state: State::WriteKernelType,
        };

        //Try to parallelize this somehow in the future
        if kernel_type == KernelType::Direct {
            fw_cfg.setup_direct_boot().unwrap();
            assert!(fw_cfg.phdrs.is_some());
            assert!(!fw_cfg.phdrs.as_ref().unwrap().is_empty());
        } else {
            fw_cfg.get_bzimage_size().unwrap();
        }

        fw_cfg.add_kernel_hashes(hashes_path, sev);

        fw_cfg
    }

    fn add_kernel_hashes(&self, hashes_path: &PathBuf, sev: Arc<Mutex<Option<Sev>>>) {
        let num_hashes = match self.kernel_type {
            KernelType::BzImage => 1,
            KernelType::Direct => 3,
        };

        let hashes_base_addr = GuestAddress(sev::FIRMWARE_ADDR.0 - (num_hashes * 32));

        let mut hashes = File::open(hashes_path).unwrap();
        self.mem.memory()
            .read_exact_from(hashes_base_addr, &mut hashes, num_hashes as usize * 32).unwrap();

        let addr = 
            self.mem.memory().get_host_address(hashes_base_addr).unwrap() as u64;
        
        if let Some(sev) = sev.lock().unwrap().as_mut() {
            sev.launch_update_data(addr, (num_hashes * 32).try_into().unwrap()).unwrap();
        }
    }

    ///Parse uncompressed kernel ELF and save loadable phdrs/entry point 
    fn setup_direct_boot(&mut self) -> Result<(), Error>{
        self.kernel
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::SeekKernelStart)?;

        let mut ehdr = elf::Elf64_Ehdr::default();
        ehdr.as_bytes()
            .read_from(
                0,
                &mut self.kernel, 
                mem::size_of::<elf::Elf64_Ehdr>())
            .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF header"))?;
            

        // Sanity checks
        if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
        {
            return Err(Error::InvalidElfMagicNumber);
        }
        if ehdr.e_ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
            return Err(Error::BigEndianElfOnLittle);
        }
        if ehdr.e_phentsize as usize != mem::size_of::<elf::Elf64_Phdr>() {
            return Err(Error::InvalidProgramHeaderSize);
        }
        if (ehdr.e_phoff as usize) < mem::size_of::<elf::Elf64_Ehdr>() {
            // If the program header is backwards, bail.
            return Err(Error::InvalidProgramHeaderOffset);
        }

        self.kernel
            .seek(SeekFrom::Start(ehdr.e_phoff))
            .map_err(|_| Error::SeekProgramHeader)?;

        let mut phdrs = Vec::new();

        let phdr_sz = mem::size_of::<elf::Elf64_Phdr>();
        for _ in 0usize..ehdr.e_phnum as usize {
            let mut phdr = elf::Elf64_Phdr::default();
            phdr.as_bytes()
                .read_from(0, &mut self.kernel, phdr_sz)
                .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF program header"))?;
            
            phdrs.push(phdr);
        }

        self.ehdr = Some(ehdr.clone());
        self.phdrs = Some(phdrs.clone());        

        Ok(())
    }

    fn get_bzimage_size(&mut self) -> Result<(), Error>{
        self.kernel
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::SeekKernelStart)?;
        self.kernel_len = 
            self.kernel
                .seek(SeekFrom::End(0))
                .map_err(|_| Error::SeekKernelImage)?;
        self.kernel
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::SeekKernelStart)?;

        Ok(())
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {

        if offset != 0 || data.len() < 4 {
            info!("fw_cfg invalid read address");
        } else {
            match self.cmd {
                Some(Command::KernelType) => {
                    if self.state == State::WriteKernelType {
                        let type_buf = u32::to_le_bytes(self.kernel_type.value());
                        data.copy_from_slice(&type_buf);
                        if self.kernel_type == KernelType::Direct {
                            self.state = State::WriteElfHdr;
                        } else {
                            self.state = State::WriteBzImageLen;
                        }
                    } else {
                        warn!("Invalid state");
                    }
                },
                Some(Command::ElfHdr) => {
                    if self.state == State::WriteElfHdr {
                        //Elf header is small so it can all be written in one chunk
                        self.mem
                            .memory()
                            .write_slice(
                                &self.ehdr.unwrap().as_slice(), 
                                GuestAddress(DATA_REGION_ADDR)).unwrap();
                        self.state = State::WritePhdrs;
                    } else {
                        warn!("Invalid state")
                    }
                },
                Some(Command::PhdrData) => {
                    if self.state == State::WritePhdrs {
                        if let Some(phdrs) = &mut self.phdrs {
                            let phdr = phdrs.get(self.cur_phdr).unwrap();
                            self.mem
                                .memory()
                                .write_slice(
                                    phdr.as_slice(),
                                    GuestAddress(DATA_REGION_ADDR)).unwrap();
                            
                            self.cur_phdr += 1;

                            if self.cur_phdr == self.ehdr.unwrap().e_phnum as usize {
                                self.cur_phdr = 0;
                                self.state = State::WriteSegs;
                            } 
                        } else {
                            warn!("phdrs is empty");
                        }
                    } else {
                        warn!("Invalid state");
                    }
                },
                Some(Command::SegData) => {
                    if self.state == State::WriteSegs {
                        if let Some(phdrs) = &mut self.phdrs {
                            //Get phdr for segment to write
                            let mut phdr = phdrs.get(self.cur_phdr).unwrap();
                            if phdr.p_type & elf::PT_LOAD == 0 || phdr.p_filesz == 0 {
                                self.cur_phdr += 1;
                                if self.cur_phdr >= phdrs.len() {
                                    return;
                                }
                                phdr = phdrs.get(self.cur_phdr).unwrap();
                            }
                            let bytes_left = phdr.p_filesz - self.seg_pos;
                            let mut write_len = DATA_REGION_SIZE;
                            if bytes_left < DATA_REGION_SIZE {
                                write_len = bytes_left;
                            }
                            //Offset is kernel file offset plus last position in segment
                            // let pos = phdr.p_offset + self.seg_pos;
                            //Seek to offset in segment
                            if self.seg_pos == 0 {
                                self.kernel
                                .seek(
                                    SeekFrom::Start(phdr.p_offset)
                                ).unwrap();
                            }
                           
                            //Write segment bytes to data region
                            self.mem
                                .memory()
                                .read_exact_from(
                                    GuestAddress(DATA_REGION_ADDR), 
                                    &mut self.kernel, 
                                    write_len as usize)
                                    .unwrap();
                            //Update position in current segment
                            self.seg_pos += write_len;
    
                            //If we finished writing the segment, move to the next one
                            if self.seg_pos >= phdr.p_filesz {
                                self.cur_phdr += 1;
                                self.seg_pos = 0;
                            }
                        } else {
                            warn!("No program headers");
                        }
                    } else {
                        warn!("Invalid state");
                    }
                },
                Some(Command::BzImageLen) => {
                    if self.state == State::WriteBzImageLen {
                        let len_buf = u32::to_le_bytes(self.kernel_len as u32);
                        data.copy_from_slice(&len_buf);
                        self.state = State::WriteBzImageData;
                    } else {
                        warn!("Invalid state");
                    }
                },
                Some(Command::BzimageData) => {
                    if self.state == State::WriteBzImageData {
                        let pos = self.kernel.stream_position().unwrap();
                        let mut chunk_sz = DATA_REGION_SIZE;
                        //check if the last chunk of file is less than a page
                        if self.kernel_len - pos < DATA_REGION_SIZE {
                            chunk_sz = self.kernel_len - pos;
                        }
        
                        self.mem
                            .memory()
                            .read_exact_from(
                                GuestAddress(DATA_REGION_ADDR), &mut self.kernel, chunk_sz as usize).unwrap();
                    }
                },
                _ => warn!("Invalid read for command")
            }
        }
    }

    fn write(
        &mut self,
        _base: u64,
        offset: u64,
        data: &[u8],
    ) -> Option<std::sync::Arc<std::sync::Barrier>> {

        //Only allow writes to 8 bytes before the page to load data
        if offset != 0 || data.len() < 4 {
            info!("fw_cfg invalid write");
            return None;
        } else {
            let mut buf: [u8; 4] = Default::default();
            buf.copy_from_slice(&data[0..4]);
            let code = u32::from_le_bytes(buf);
            let result = Command::try_from(code);
            match result {
                Ok(cmd) => self.cmd = Some(cmd),
                _ => warn!("FwCfg invalid command")
            }
        }        

        None
    }
}

fn get_kernel_type<F>(kernel_image: &mut F) -> KernelType
where
    F: Read + Seek,
{
    
    let mut kernel_type = KernelType::Direct;
    //determine if kernel file is bzImage or uncompressed
    //Assume bzImage first
    let mut bz_header = setup_header::default();
    kernel_image 
        .seek(SeekFrom::Start(BZIMAGE_HEADER_OFFSET))
        .unwrap();

    bz_header.as_bytes()
        .read_from(
            0,
            kernel_image,
            mem::size_of::<setup_header>() )
        .unwrap();

    if bz_header.header == BZIMAGE_HEADER_MAGIC {
        kernel_type = KernelType::BzImage;
    }

    kernel_type
}
