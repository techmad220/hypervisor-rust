// UEFIDriverInjector.c ported to Rust
use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileInfo};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use core::ptr;
use alloc::vec::Vec;

/// Map a driver into memory without using LoadImage
pub fn map_driver(
    image_handle: Handle,
    system_table: &SystemTable<Boot>,
    driver_path: &CStr16,
) -> Result<usize, Status> {
    // 1. Locate the file system protocol
    let mut fs_handle = system_table
        .boot_services()
        .get_handle_for_protocol::<SimpleFileSystem>()?;
    
    let mut fs = system_table
        .boot_services()
        .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)?;
    
    // 2. Open the root directory
    let mut root_dir = fs.open_volume()?;
    
    // 3. Open the driver file
    let mut driver_file = root_dir.open(
        driver_path,
        FileMode::Read,
        FileAttribute::empty(),
    )?;
    
    // 4. Get the file size
    let mut info_buffer = [0u8; 512];
    let file_info = driver_file.get_info::<FileInfo>(&mut info_buffer)?;
    let driver_size = file_info.file_size() as usize;
    
    // 5. Allocate memory for the driver file
    let driver_buffer = system_table
        .boot_services()
        .allocate_pool(MemoryType::LOADER_DATA, driver_size)?;
    
    // 6. Read the driver into memory
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(driver_buffer, driver_size)
    };
    driver_file.read(buffer)?;
    
    // 7. Parse PE headers and perform manual mapping
    let loaded_driver = manual_map_pe(driver_buffer, driver_size, system_table)?;
    
    log::info!("Driver mapped at {:#x}", loaded_driver);
    Ok(loaded_driver)
}

/// Manually map a PE file into memory
fn manual_map_pe(
    pe_buffer: *mut u8,
    size: usize,
    system_table: &SystemTable<Boot>,
) -> Result<usize, Status> {
    unsafe {
        // Check DOS header
        let dos_header = pe_buffer as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(Status::LOAD_ERROR);
        }
        
        // Get NT headers
        let nt_headers = pe_buffer.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return Err(Status::LOAD_ERROR);
        }
        
        // Allocate memory for the image
        let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
        let image_base = system_table
            .boot_services()
            .allocate_pages(
                AllocateType::AnyPages,
                MemoryType::LOADER_CODE,
                (image_size + 0xFFF) / 0x1000,
            )? as *mut u8;
        
        // Copy headers
        let headers_size = (*nt_headers).OptionalHeader.SizeOfHeaders as usize;
        ptr::copy_nonoverlapping(pe_buffer, image_base, headers_size);
        
        // Copy sections
        let sections = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS64>()) 
            as *const IMAGE_SECTION_HEADER;
        let num_sections = (*nt_headers).FileHeader.NumberOfSections as usize;
        
        for i in 0..num_sections {
            let section = &*sections.add(i);
            let dest = image_base.add(section.VirtualAddress as usize);
            let src = pe_buffer.add(section.PointerToRawData as usize);
            let size = section.SizeOfRawData as usize;
            
            if size > 0 {
                ptr::copy_nonoverlapping(src, dest, size);
            }
        }
        
        // Process relocations
        process_relocations(image_base, nt_headers)?;
        
        // Resolve imports
        resolve_imports(image_base, nt_headers, system_table)?;
        
        // Get entry point
        let entry_point = image_base.add((*nt_headers).OptionalHeader.AddressOfEntryPoint as usize);
        
        // Call driver entry point
        let driver_entry: extern "efiapi" fn(Handle, *const core::ffi::c_void) -> Status =
            core::mem::transmute(entry_point);
        
        let status = driver_entry(
            system_table.boot_services().image_handle(),
            system_table as *const _ as *const core::ffi::c_void,
        );
        
        if status != Status::SUCCESS {
            return Err(status);
        }
        
        Ok(image_base as usize)
    }
}

/// Process PE relocations
fn process_relocations(
    image_base: *mut u8,
    nt_headers: *const IMAGE_NT_HEADERS64,
) -> Result<(), Status> {
    unsafe {
        let opt_header = &(*nt_headers).OptionalHeader;
        
        // Check if relocations exist
        if opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 {
            return Ok(());
        }
        
        let delta = image_base as i64 - opt_header.ImageBase as i64;
        if delta == 0 {
            return Ok(()); // No relocation needed
        }
        
        let mut reloc = image_base.add(
            opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress as usize
        ) as *const IMAGE_BASE_RELOCATION;
        
        let reloc_end = (reloc as *const u8).add(
            opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size as usize
        );
        
        while (reloc as *const u8) < reloc_end && (*reloc).SizeOfBlock != 0 {
            let entries = ((*reloc).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / 2;
            let reloc_data = (reloc as *const u8).add(size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
            
            for i in 0..entries {
                let data = *reloc_data.add(i);
                let reloc_type = (data >> 12) & 0xF;
                let offset = (data & 0xFFF) as usize;
                
                if reloc_type == IMAGE_REL_BASED_DIR64 {
                    let addr = image_base.add((*reloc).VirtualAddress as usize + offset) as *mut i64;
                    *addr += delta;
                }
            }
            
            reloc = (reloc as *const u8).add((*reloc).SizeOfBlock as usize) as *const IMAGE_BASE_RELOCATION;
        }
        
        Ok(())
    }
}

/// Resolve PE imports
fn resolve_imports(
    image_base: *mut u8,
    nt_headers: *const IMAGE_NT_HEADERS64,
    system_table: &SystemTable<Boot>,
) -> Result<(), Status> {
    unsafe {
        let opt_header = &(*nt_headers).OptionalHeader;
        
        // Check if imports exist
        if opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 {
            return Ok(());
        }
        
        let mut import = image_base.add(
            opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress as usize
        ) as *const IMAGE_IMPORT_DESCRIPTOR;
        
        while (*import).Name != 0 {
            let dll_name = image_base.add((*import).Name as usize) as *const i8;
            
            // Get import address table
            let mut iat = if (*import).FirstThunk != 0 {
                image_base.add((*import).FirstThunk as usize) as *mut usize
            } else {
                image_base.add((*import).OriginalFirstThunk as usize) as *mut usize
            };
            
            let mut thunk = image_base.add((*import).OriginalFirstThunk as usize) as *const usize;
            
            while *thunk != 0 {
                // For UEFI, we'd resolve against boot services
                // For now, stub the imports
                *iat = 0xDEADC0DE; // Placeholder
                
                iat = iat.add(1);
                thunk = thunk.add(1);
            }
            
            import = import.add(1);
        }
        
        Ok(())
    }
}

// PE structures
#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
struct IMAGE_SECTION_HEADER {
    Name: [u8; 8],
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

#[repr(C)]
struct IMAGE_BASE_RELOCATION {
    VirtualAddress: u32,
    SizeOfBlock: u32,
}

#[repr(C)]
struct IMAGE_IMPORT_DESCRIPTOR {
    OriginalFirstThunk: u32,
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,
    FirstThunk: u32,
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_DIR64: u16 = 10;

use core::mem::size_of;