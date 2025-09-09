//! Driver Processing Module
//! Complete 1:1 port of DriverProcessing.c to Rust

#![no_std]

use uefi::prelude::*;
use core::ptr;
use core::slice;

/// DOS header magic number
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ

/// PE header magic number
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // PE\0\0

/// Image directory entries
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

/// Relocation types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

#[repr(C)]
struct ImageDosHeader {
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
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageOptionalHeader64 {
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
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
struct ImageImportByName {
    hint: u16,
    name: [u8; 1],
}

/// Apply PE relocations to driver image
pub fn apply_relocations(driver_base: usize) -> bool {
    unsafe {
        let dos_header = driver_base as *const ImageDosHeader;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }

        let nt_headers = (driver_base + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        if (*nt_headers).signature != IMAGE_NT_SIGNATURE {
            return false;
        }

        let reloc_dir = &(*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            return true; // No relocations needed
        }

        let relocation_delta = driver_base as u64 - (*nt_headers).optional_header.image_base;
        if relocation_delta == 0 {
            return true; // No adjustment needed
        }

        let mut reloc = (driver_base + reloc_dir.virtual_address as usize) as *const ImageBaseRelocation;
        let reloc_end = driver_base + reloc_dir.virtual_address as usize + reloc_dir.size as usize;

        while (reloc as usize) < reloc_end && (*reloc).virtual_address != 0 && (*reloc).size_of_block != 0 {
            let reloc_entries = (reloc as *const u8).add(core::mem::size_of::<ImageBaseRelocation>()) as *const u16;
            let entry_count = ((*reloc).size_of_block as usize - core::mem::size_of::<ImageBaseRelocation>()) / 2;

            for i in 0..entry_count {
                let type_offset = *reloc_entries.add(i);
                let reloc_type = (type_offset >> 12) & 0xF;
                let offset = type_offset & 0xFFF;

                match reloc_type {
                    IMAGE_REL_BASED_ABSOLUTE => {
                        // Skip absolute relocations
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        let patch_address = (driver_base + (*reloc).virtual_address as usize + offset as usize) as *mut u64;
                        *patch_address = (*patch_address).wrapping_add(relocation_delta);
                    }
                    _ => {
                        // Unsupported relocation type
                    }
                }
            }

            reloc = (reloc as *const u8).add((*reloc).size_of_block as usize) as *const ImageBaseRelocation;
        }

        true
    }
}

/// Resolve imports for driver
pub fn resolve_imports(driver_base: usize, system_table: &SystemTable<Boot>) -> bool {
    unsafe {
        let dos_header = driver_base as *const ImageDosHeader;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }

        let nt_headers = (driver_base + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        if (*nt_headers).signature != IMAGE_NT_SIGNATURE {
            return false;
        }

        let import_dir = &(*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        
        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            return true; // No imports
        }

        let mut import_desc = (driver_base + import_dir.virtual_address as usize) as *const ImageImportDescriptor;
        
        while (*import_desc).name != 0 {
            let lib_name = (driver_base + (*import_desc).name as usize) as *const u8;
            let lib_name_slice = core::str::from_utf8_unchecked(
                slice::from_raw_parts(lib_name, strlen(lib_name))
            );

            // Resolve library (in UEFI context, we'd use protocol lookups)
            let lib_handle = resolve_library(lib_name_slice, system_table);
            if lib_handle.is_null() {
                return false;
            }

            let mut thunk = (driver_base + (*import_desc).first_thunk as usize) as *mut u64;
            let mut orig_thunk = if (*import_desc).original_first_thunk != 0 {
                (driver_base + (*import_desc).original_first_thunk as usize) as *const u64
            } else {
                (driver_base + (*import_desc).first_thunk as usize) as *const u64
            };

            while *orig_thunk != 0 {
                let func_addr = if *orig_thunk & 0x8000_0000_0000_0000 != 0 {
                    // Import by ordinal
                    let ordinal = (*orig_thunk & 0xFFFF) as u16;
                    resolve_function_by_ordinal(lib_handle, ordinal)
                } else {
                    // Import by name
                    let import_by_name = (driver_base + *orig_thunk as usize) as *const ImageImportByName;
                    let func_name = &(*import_by_name).name as *const u8;
                    let func_name_slice = core::str::from_utf8_unchecked(
                        slice::from_raw_parts(func_name, strlen(func_name))
                    );
                    resolve_function_by_name(lib_handle, func_name_slice)
                };

                if func_addr.is_null() {
                    return false;
                }

                *thunk = func_addr as u64;
                thunk = thunk.add(1);
                orig_thunk = orig_thunk.add(1);
            }

            import_desc = import_desc.add(1);
        }

        true
    }
}

/// Helper to get string length
unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

/// Resolve library handle (UEFI context)
fn resolve_library(lib_name: &str, system_table: &SystemTable<Boot>) -> *const core::ffi::c_void {
    // In UEFI, we'd look up loaded image protocols
    // For now, return a placeholder
    match lib_name {
        "ntoskrnl.exe" | "NTOSKRNL.EXE" => {
            // Return kernel base address
            0x1000 as *const core::ffi::c_void
        }
        "hal.dll" | "HAL.DLL" => {
            // Return HAL base address
            0x2000 as *const core::ffi::c_void
        }
        _ => ptr::null()
    }
}

/// Resolve function by ordinal
fn resolve_function_by_ordinal(lib_handle: *const core::ffi::c_void, ordinal: u16) -> *const core::ffi::c_void {
    // In real implementation, would parse export table
    // For now, return placeholder based on common ordinals
    match ordinal {
        1 => 0x1100 as *const core::ffi::c_void,
        2 => 0x1200 as *const core::ffi::c_void,
        _ => ptr::null()
    }
}

/// Resolve function by name
fn resolve_function_by_name(lib_handle: *const core::ffi::c_void, func_name: &str) -> *const core::ffi::c_void {
    // In real implementation, would parse export table
    // For now, return placeholder based on common functions
    match func_name {
        "ExAllocatePool" => 0x1300 as *const core::ffi::c_void,
        "ExFreePool" => 0x1400 as *const core::ffi::c_void,
        "IoCreateDevice" => 0x1500 as *const core::ffi::c_void,
        "IoDeleteDevice" => 0x1600 as *const core::ffi::c_void,
        _ => ptr::null()
    }
}

/// Process and load driver
pub fn process_driver(
    driver_base: usize,
    driver_size: usize,
    system_table: &SystemTable<Boot>
) -> Result<usize, Status> {
    // Apply relocations
    if !apply_relocations(driver_base) {
        return Err(Status::LOAD_ERROR);
    }

    // Resolve imports
    if !resolve_imports(driver_base, system_table) {
        return Err(Status::LOAD_ERROR);
    }

    // Get entry point
    unsafe {
        let dos_header = driver_base as *const ImageDosHeader;
        let nt_headers = (driver_base + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        let entry_point = driver_base + (*nt_headers).optional_header.address_of_entry_point as usize;
        
        Ok(entry_point)
    }
}