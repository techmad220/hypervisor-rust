//! PE Image Loader - Relocation and Import Resolution
//! 1:1 port of PE loading functionality from MmTechmad.c

use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use core::mem;

// PE structures
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub signature: u32,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub hint: u16,
    pub name: [u8; 1],
}

// Directory indices
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

// Relocation types
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// Relocate PE image to new base address
pub unsafe fn relocate_image(image_base: *mut u8, load_addr: u64) -> Result<(), NTSTATUS> {
    let dos_hdr = image_base as *const IMAGE_DOS_HEADER;
    if (*dos_hdr).e_magic != 0x5A4D {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    
    let nt_hdr = image_base.offset((*dos_hdr).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    if (*nt_hdr).signature != 0x00004550 {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    
    let delta = load_addr - (*nt_hdr).optional_header.image_base;
    if delta == 0 {
        return Ok(());
    }
    
    let reloc_dir = &(*nt_hdr).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if reloc_dir.size == 0 {
        return Ok(());
    }
    
    let mut reloc = image_base.offset(reloc_dir.virtual_address as isize) as *const IMAGE_BASE_RELOCATION;
    let reloc_end = image_base.offset((reloc_dir.virtual_address + reloc_dir.size) as isize);
    
    while (reloc as *const u8) < reloc_end {
        let count = ((*reloc).size_of_block as usize - mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
        let entries = (reloc as *const u8).offset(mem::size_of::<IMAGE_BASE_RELOCATION>() as isize) as *const u16;
        
        for i in 0..count {
            let entry = *entries.offset(i as isize);
            let reloc_type = entry >> 12;
            let offset = entry & 0xFFF;
            
            if reloc_type == IMAGE_REL_BASED_DIR64 {
                let patch_addr = image_base.offset(((*reloc).virtual_address + offset as u32) as isize) as *mut u64;
                *patch_addr = (*patch_addr as i64 + delta as i64) as u64;
            }
        }
        
        reloc = (reloc as *const u8).offset((*reloc).size_of_block as isize) as *const IMAGE_BASE_RELOCATION;
    }
    
    DbgPrint(b"[PELoader] Image relocated with delta: 0x%llX\n\0".as_ptr() as *const i8, delta);
    
    Ok(())
}

/// Resolve imports for PE image
pub unsafe fn resolve_imports(image_base: *mut u8) -> Result<(), NTSTATUS> {
    let dos_hdr = image_base as *const IMAGE_DOS_HEADER;
    let nt_hdr = image_base.offset((*dos_hdr).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    
    let import_dir = &(*nt_hdr).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.size == 0 {
        return Ok(());
    }
    
    let mut import_desc = image_base.offset(import_dir.virtual_address as isize) as *const IMAGE_IMPORT_DESCRIPTOR;
    
    while (*import_desc).name != 0 {
        let dll_name = image_base.offset((*import_desc).name as isize) as *const u8;
        
        DbgPrint(
            b"[PELoader] Resolving imports from: %s\n\0".as_ptr() as *const i8,
            dll_name
        );
        
        let mut thunk = image_base.offset((*import_desc).first_thunk as isize) as *mut u64;
        let mut orig_thunk = if (*import_desc).original_first_thunk != 0 {
            image_base.offset((*import_desc).original_first_thunk as isize) as *const u64
        } else {
            image_base.offset((*import_desc).first_thunk as isize) as *const u64
        };
        
        while *orig_thunk != 0 {
            if (*orig_thunk & IMAGE_ORDINAL_FLAG64) == 0 {
                let import_name = image_base.offset(*orig_thunk as isize) as *const IMAGE_IMPORT_BY_NAME;
                let func_name = &(*import_name).name as *const u8;
                
                // Convert to UNICODE_STRING and resolve
                let addr = resolve_kernel_function(func_name)?;
                *thunk = addr as u64;
                
                DbgPrint(
                    b"[PELoader] Resolved %s -> 0x%p\n\0".as_ptr() as *const i8,
                    func_name,
                    addr
                );
            }
            
            thunk = thunk.offset(1);
            orig_thunk = orig_thunk.offset(1);
        }
        
        import_desc = import_desc.offset(1);
    }
    
    Ok(())
}

/// Resolve kernel function by name
unsafe fn resolve_kernel_function(name: *const u8) -> Result<*mut u8, NTSTATUS> {
    // Convert ASCII to UNICODE
    let name_len = strlen(name);
    let mut unicode_name: UNICODE_STRING = core::mem::zeroed();
    let mut buffer = [0u16; 256];
    
    for i in 0..name_len.min(255) {
        buffer[i] = *name.offset(i as isize) as u16;
    }
    
    unicode_name.Length = (name_len * 2) as u16;
    unicode_name.MaximumLength = 512;
    unicode_name.Buffer = buffer.as_mut_ptr();
    
    let addr = MmGetSystemRoutineAddress(&mut unicode_name);
    if addr.is_null() {
        return Err(STATUS_PROCEDURE_NOT_FOUND);
    }
    
    Ok(addr as *mut u8)
}

/// Get string length
unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while *s.offset(len as isize) != 0 {
        len += 1;
    }
    len
}

/// Execute plugin entry point
pub unsafe fn execute_plugin(image_base: *mut u8) -> Result<NTSTATUS, NTSTATUS> {
    let dos_hdr = image_base as *const IMAGE_DOS_HEADER;
    let nt_hdr = image_base.offset((*dos_hdr).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    
    let entry_point = (*nt_hdr).optional_header.address_of_entry_point;
    if entry_point == 0 {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    
    type PluginEntry = unsafe extern "system" fn() -> NTSTATUS;
    let plugin_main: PluginEntry = mem::transmute(image_base.offset(entry_point as isize));
    
    DbgPrint(b"[PELoader] Executing plugin entry at: 0x%p\n\0".as_ptr() as *const i8, plugin_main);
    
    Ok(plugin_main())
}

extern "system" {
    fn MmGetSystemRoutineAddress(SystemRoutineName: *mut UNICODE_STRING) -> PVOID;
    fn DbgPrint(Format: *const i8, ...) -> NTSTATUS;
}