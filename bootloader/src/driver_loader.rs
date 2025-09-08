//! Driver loading and PE image processing

use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileInfo};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::MemoryType;
use uefi::CStr16;
use alloc::vec::Vec;
use core::mem;

/// PE/COFF header structures
#[repr(C)]
struct DosHeader {
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
    e_lfanew: u32,
}

#[repr(C)]
struct NtHeaders64 {
    signature: u32,
    file_header: FileHeader,
    optional_header: OptionalHeader64,
}

#[repr(C)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [DataDirectory; 16],
}

#[repr(C)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct BaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

#[repr(C)]
struct ImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Load a driver from the ESP
pub fn load_driver(
    image: Handle,
    st: &SystemTable<Boot>,
    driver_name: &CStr16,
) -> Result<Handle, Status> {
    // Open root filesystem
    let mut fs_handle = st.boot_services()
        .get_handle_for_protocol::<SimpleFileSystem>()?;
    
    let mut fs = st.boot_services()
        .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)?;
    
    let mut root = fs.open_volume()?;
    
    // Open driver file
    let mut driver_file = root.open(
        driver_name,
        FileMode::Read,
        FileAttribute::empty(),
    )?;
    
    // Get file size
    let mut info_buffer = [0u8; 512];
    let file_info = driver_file.get_info::<FileInfo>(&mut info_buffer)?;
    let file_size = file_info.file_size() as usize;
    
    // Allocate memory for driver
    let pages = (file_size + 4095) / 4096;
    let driver_base = st.boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::BOOT_SERVICES_CODE,
            pages,
        )?;
    
    // Read driver into memory
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(driver_base as *mut u8, file_size)
    };
    driver_file.read(buffer)?;
    
    // Process PE image
    unsafe {
        process_pe_image(driver_base)?;
    }
    
    // Create loaded image protocol
    let driver_handle = st.boot_services()
        .install_protocol_interface(
            None,
            &LOADED_IMAGE_PROTOCOL_GUID,
            driver_base as *mut _,
        )?;
    
    info!("Driver {} loaded at {:#x}", driver_name, driver_base);
    
    Ok(driver_handle)
}

/// Process PE image (relocations and imports)
unsafe fn process_pe_image(base: u64) -> Result<(), Status> {
    let dos_header = base as *const DosHeader;
    if (*dos_header).e_magic != 0x5A4D {
        return Err(Status::INVALID_PARAMETER);
    }
    
    let nt_headers = (base + (*dos_header).e_lfanew as u64) as *const NtHeaders64;
    if (*nt_headers).signature != 0x00004550 {
        return Err(Status::INVALID_PARAMETER);
    }
    
    // Apply relocations
    apply_relocations(base, &*nt_headers)?;
    
    // Resolve imports
    resolve_imports(base, &*nt_headers)?;
    
    Ok(())
}

/// Apply PE relocations
unsafe fn apply_relocations(base: u64, nt_headers: &NtHeaders64) -> Result<(), Status> {
    let reloc_dir = &nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        return Ok(()); // No relocations
    }
    
    let relocation_delta = base - nt_headers.optional_header.image_base;
    if relocation_delta == 0 {
        return Ok(()); // No adjustment needed
    }
    
    let mut reloc = (base + reloc_dir.virtual_address as u64) as *const BaseRelocation;
    let reloc_end = (base + reloc_dir.virtual_address as u64 + reloc_dir.size as u64) as *const BaseRelocation;
    
    while reloc < reloc_end && (*reloc).virtual_address != 0 {
        let entries = ((*reloc).size_of_block as usize - mem::size_of::<BaseRelocation>()) / 2;
        let reloc_data = (reloc as *const u8).add(mem::size_of::<BaseRelocation>()) as *const u16;
        
        for i in 0..entries {
            let type_offset = *reloc_data.add(i);
            let reloc_type = (type_offset >> 12) & 0xF;
            let offset = (type_offset & 0xFFF) as u64;
            
            if reloc_type == IMAGE_REL_BASED_DIR64 {
                let patch_addr = (base + (*reloc).virtual_address as u64 + offset) as *mut u64;
                *patch_addr = (*patch_addr as i64 + relocation_delta as i64) as u64;
            }
        }
        
        reloc = (reloc as *const u8).add((*reloc).size_of_block as usize) as *const BaseRelocation;
    }
    
    Ok(())
}

/// Resolve PE imports
unsafe fn resolve_imports(base: u64, nt_headers: &NtHeaders64) -> Result<(), Status> {
    let import_dir = &nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return Ok(()); // No imports
    }
    
    let mut import_desc = (base + import_dir.virtual_address as u64) as *const ImportDescriptor;
    
    while (*import_desc).name != 0 {
        let lib_name = (base + (*import_desc).name as u64) as *const u8;
        
        // For UEFI drivers, we need to resolve against UEFI protocols
        // This is simplified - real implementation would lookup protocols
        
        let mut thunk = (base + (*import_desc).first_thunk as u64) as *mut u64;
        let mut orig_thunk = if (*import_desc).original_first_thunk != 0 {
            (base + (*import_desc).original_first_thunk as u64) as *const u64
        } else {
            (base + (*import_desc).first_thunk as u64) as *const u64
        };
        
        while *orig_thunk != 0 {
            // In a real implementation, we'd resolve the function here
            // For now, we'll stub it
            *thunk = 0xDEADBEEF; // Placeholder
            
            thunk = thunk.add(1);
            orig_thunk = orig_thunk.add(1);
        }
        
        import_desc = import_desc.add(1);
    }
    
    Ok(())
}

/// Chain-load Windows Boot Manager
pub fn chainload_windows_bootmgr(
    image: Handle,
    st: &SystemTable<Boot>,
) -> Result<(), Status> {
    const WINDOWS_BOOTMGR: &CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    
    // Find ESP
    let mut fs_handle = st.boot_services()
        .get_handle_for_protocol::<SimpleFileSystem>()?;
    
    let mut fs = st.boot_services()
        .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)?;
    
    // Create device path for Windows Boot Manager
    let mut root = fs.open_volume()?;
    
    // Check if Windows Boot Manager exists
    match root.open(
        WINDOWS_BOOTMGR,
        FileMode::Read,
        FileAttribute::empty(),
    ) {
        Ok(mut file) => {
            file.close();
            
            // Load and start Windows Boot Manager
            info!("Chain-loading Windows Boot Manager...");
            
            let bootmgr_handle = st.boot_services()
                .load_image(
                    image,
                    WINDOWS_BOOTMGR,
                    None,
                    None,
                )?;
            
            st.boot_services()
                .start_image(bootmgr_handle)?;
            
            Ok(())
        }
        Err(_) => {
            info!("Windows Boot Manager not found, continuing with hypervisor only");
            Ok(())
        }
    }
}

// UEFI Protocol GUIDs
const LOADED_IMAGE_PROTOCOL_GUID: uefi::Guid = uefi::Guid::from_values(
    0x5B1B31A1,
    0x9562,
    0x11d2,
    [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);

extern crate alloc;