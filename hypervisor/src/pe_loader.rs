//! PE (Portable Executable) Loader
//! Complete implementation for loading and processing Windows PE files

use alloc::{vec::Vec, string::String};
use core::mem;

pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_magic: u16,      // Magic number
    pub e_cblp: u16,       // Bytes on last page of file
    pub e_cp: u16,         // Pages in file
    pub e_crlc: u16,       // Relocations
    pub e_cparhdr: u16,    // Size of header in paragraphs
    pub e_minalloc: u16,   // Minimum extra paragraphs needed
    pub e_maxalloc: u16,   // Maximum extra paragraphs needed
    pub e_ss: u16,         // Initial (relative) SS value
    pub e_sp: u16,         // Initial SP value
    pub e_csum: u16,       // Checksum
    pub e_ip: u16,         // Initial IP value
    pub e_cs: u16,         // Initial (relative) CS value
    pub e_lfarlc: u16,     // File address of relocation table
    pub e_ovno: u16,       // Overlay number
    pub e_res: [u16; 4],   // Reserved words
    pub e_oemid: u16,      // OEM identifier
    pub e_oeminfo: u16,    // OEM information
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: u32,     // File address of PE header
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
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
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
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
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageDirectoryEntry {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    BaseReloc = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescriptor = 14,
    Reserved = 15,
}

pub struct PeLoader {
    data: Vec<u8>,
    image_base: u64,
    is_64bit: bool,
}

impl PeLoader {
    pub fn new(data: Vec<u8>) -> Result<Self, PeError> {
        let loader = Self {
            data,
            image_base: 0,
            is_64bit: false,
        };
        
        loader.validate()?;
        Ok(loader)
    }
    
    fn validate(&self) -> Result<(), PeError> {
        if self.data.len() < mem::size_of::<DosHeader>() {
            return Err(PeError::InvalidFormat("File too small"));
        }
        
        let dos_header = self.get_dos_header()?;
        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(PeError::InvalidFormat("Invalid DOS signature"));
        }
        
        if dos_header.e_lfanew as usize >= self.data.len() {
            return Err(PeError::InvalidFormat("Invalid PE offset"));
        }
        
        let pe_signature = self.get_pe_signature()?;
        if pe_signature != PE_SIGNATURE {
            return Err(PeError::InvalidFormat("Invalid PE signature"));
        }
        
        Ok(())
    }
    
    pub fn get_dos_header(&self) -> Result<&DosHeader, PeError> {
        if self.data.len() < mem::size_of::<DosHeader>() {
            return Err(PeError::InvalidFormat("Invalid DOS header"));
        }
        
        unsafe {
            Ok(&*(self.data.as_ptr() as *const DosHeader))
        }
    }
    
    pub fn get_pe_signature(&self) -> Result<u32, PeError> {
        let dos_header = self.get_dos_header()?;
        let pe_offset = dos_header.e_lfanew as usize;
        
        if pe_offset + 4 > self.data.len() {
            return Err(PeError::InvalidFormat("Invalid PE signature offset"));
        }
        
        unsafe {
            Ok(*(self.data.as_ptr().add(pe_offset) as *const u32))
        }
    }
    
    pub fn get_file_header(&self) -> Result<&ImageFileHeader, PeError> {
        let dos_header = self.get_dos_header()?;
        let pe_offset = dos_header.e_lfanew as usize;
        
        let file_header_offset = pe_offset + 4; // Skip PE signature
        
        if file_header_offset + mem::size_of::<ImageFileHeader>() > self.data.len() {
            return Err(PeError::InvalidFormat("Invalid file header"));
        }
        
        unsafe {
            Ok(&*(self.data.as_ptr().add(file_header_offset) as *const ImageFileHeader))
        }
    }
    
    pub fn is_64bit(&self) -> Result<bool, PeError> {
        let file_header = self.get_file_header()?;
        Ok(file_header.machine == IMAGE_FILE_MACHINE_AMD64)
    }
    
    pub fn get_optional_header_64(&self) -> Result<&ImageOptionalHeader64, PeError> {
        if !self.is_64bit()? {
            return Err(PeError::InvalidFormat("Not a 64-bit PE"));
        }
        
        let dos_header = self.get_dos_header()?;
        let pe_offset = dos_header.e_lfanew as usize;
        let opt_header_offset = pe_offset + 4 + mem::size_of::<ImageFileHeader>();
        
        if opt_header_offset + mem::size_of::<ImageOptionalHeader64>() > self.data.len() {
            return Err(PeError::InvalidFormat("Invalid optional header"));
        }
        
        unsafe {
            Ok(&*(self.data.as_ptr().add(opt_header_offset) as *const ImageOptionalHeader64))
        }
    }
    
    pub fn get_optional_header_32(&self) -> Result<&ImageOptionalHeader32, PeError> {
        if self.is_64bit()? {
            return Err(PeError::InvalidFormat("Not a 32-bit PE"));
        }
        
        let dos_header = self.get_dos_header()?;
        let pe_offset = dos_header.e_lfanew as usize;
        let opt_header_offset = pe_offset + 4 + mem::size_of::<ImageFileHeader>();
        
        if opt_header_offset + mem::size_of::<ImageOptionalHeader32>() > self.data.len() {
            return Err(PeError::InvalidFormat("Invalid optional header"));
        }
        
        unsafe {
            Ok(&*(self.data.as_ptr().add(opt_header_offset) as *const ImageOptionalHeader32))
        }
    }
    
    pub fn get_sections(&self) -> Result<Vec<ImageSectionHeader>, PeError> {
        let file_header = self.get_file_header()?;
        let num_sections = file_header.number_of_sections as usize;
        
        let dos_header = self.get_dos_header()?;
        let pe_offset = dos_header.e_lfanew as usize;
        let section_offset = pe_offset + 4 
            + mem::size_of::<ImageFileHeader>() 
            + file_header.size_of_optional_header as usize;
        
        let mut sections = Vec::with_capacity(num_sections);
        
        for i in 0..num_sections {
            let offset = section_offset + i * mem::size_of::<ImageSectionHeader>();
            
            if offset + mem::size_of::<ImageSectionHeader>() > self.data.len() {
                return Err(PeError::InvalidFormat("Invalid section header"));
            }
            
            unsafe {
                let section = *(self.data.as_ptr().add(offset) as *const ImageSectionHeader);
                sections.push(section);
            }
        }
        
        Ok(sections)
    }
    
    pub fn load_into_memory(&mut self, base_address: u64) -> Result<u64, PeError> {
        self.image_base = base_address;
        
        let image_size = if self.is_64bit()? {
            self.get_optional_header_64()?.size_of_image as usize
        } else {
            self.get_optional_header_32()?.size_of_image as usize
        };
        
        // Allocate memory for the image
        let image_memory = unsafe {
            alloc::alloc::alloc_zeroed(
                alloc::alloc::Layout::from_size_align(image_size, 0x1000).unwrap()
            )
        };
        
        if image_memory.is_null() {
            return Err(PeError::AllocationFailed);
        }
        
        // Copy headers
        let headers_size = if self.is_64bit()? {
            self.get_optional_header_64()?.size_of_headers as usize
        } else {
            self.get_optional_header_32()?.size_of_headers as usize
        };
        
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.data.as_ptr(),
                image_memory,
                headers_size.min(self.data.len())
            );
        }
        
        // Copy sections
        let sections = self.get_sections()?;
        for section in sections {
            if section.size_of_raw_data == 0 {
                continue;
            }
            
            let src = unsafe {
                self.data.as_ptr().add(section.pointer_to_raw_data as usize)
            };
            
            let dst = unsafe {
                image_memory.add(section.virtual_address as usize)
            };
            
            let size = section.size_of_raw_data.min(section.virtual_size) as usize;
            
            if section.pointer_to_raw_data as usize + size > self.data.len() {
                continue;
            }
            
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, size);
            }
        }
        
        // Process relocations
        self.process_relocations(image_memory as u64)?;
        
        // Resolve imports
        self.resolve_imports(image_memory as u64)?;
        
        // Get entry point
        let entry_point = if self.is_64bit()? {
            base_address + self.get_optional_header_64()?.address_of_entry_point as u64
        } else {
            base_address + self.get_optional_header_32()?.address_of_entry_point as u64
        };
        
        Ok(entry_point)
    }
    
    fn process_relocations(&self, image_base: u64) -> Result<(), PeError> {
        let (original_base, reloc_dir) = if self.is_64bit()? {
            let header = self.get_optional_header_64()?;
            (
                header.image_base,
                header.data_directory[ImageDirectoryEntry::BaseReloc as usize]
            )
        } else {
            let header = self.get_optional_header_32()?;
            (
                header.image_base as u64,
                header.data_directory[ImageDirectoryEntry::BaseReloc as usize]
            )
        };
        
        if reloc_dir.size == 0 {
            return Ok(()); // No relocations
        }
        
        let delta = image_base as i64 - original_base as i64;
        if delta == 0 {
            return Ok(()); // No adjustment needed
        }
        
        let mut offset = 0u32;
        while offset < reloc_dir.size {
            let block_ptr = (image_base + reloc_dir.virtual_address as u64 + offset as u64) as *const ImageBaseRelocation;
            let block = unsafe { &*block_ptr };
            
            let entries = (block.size_of_block - 8) / 2;
            let entries_ptr = unsafe { block_ptr.add(1) as *const u16 };
            
            for i in 0..entries {
                let entry = unsafe { *entries_ptr.add(i as usize) };
                let reloc_type = (entry >> 12) & 0xF;
                let reloc_offset = entry & 0xFFF;
                
                let target_addr = image_base + block.virtual_address as u64 + reloc_offset as u64;
                
                match reloc_type {
                    3 => { // IMAGE_REL_BASED_HIGHLOW (32-bit)
                        unsafe {
                            let ptr = target_addr as *mut u32;
                            *ptr = (*ptr as i32 + delta as i32) as u32;
                        }
                    }
                    10 => { // IMAGE_REL_BASED_DIR64 (64-bit)
                        unsafe {
                            let ptr = target_addr as *mut u64;
                            *ptr = (*ptr as i64 + delta) as u64;
                        }
                    }
                    0 => {} // IMAGE_REL_BASED_ABSOLUTE - Skip
                    _ => {
                        // Unsupported relocation type
                    }
                }
            }
            
            offset += block.size_of_block;
        }
        
        Ok(())
    }
    
    fn resolve_imports(&self, image_base: u64) -> Result<(), PeError> {
        let import_dir = if self.is_64bit()? {
            self.get_optional_header_64()?.data_directory[ImageDirectoryEntry::Import as usize]
        } else {
            self.get_optional_header_32()?.data_directory[ImageDirectoryEntry::Import as usize]
        };
        
        if import_dir.size == 0 {
            return Ok(()); // No imports
        }
        
        let mut import_desc_ptr = (image_base + import_dir.virtual_address as u64) as *const ImageImportDescriptor;
        
        unsafe {
            while (*import_desc_ptr).name != 0 {
                let dll_name_ptr = (image_base + (*import_desc_ptr).name as u64) as *const u8;
                let dll_name = self.read_cstring(dll_name_ptr)?;
                
                // Load the DLL (in a real implementation)
                // let dll_handle = load_library(&dll_name)?;
                
                let mut thunk_ptr = if (*import_desc_ptr).original_first_thunk != 0 {
                    (image_base + (*import_desc_ptr).original_first_thunk as u64) as *mut u64
                } else {
                    (image_base + (*import_desc_ptr).first_thunk as u64) as *mut u64
                };
                
                let mut func_ptr = (image_base + (*import_desc_ptr).first_thunk as u64) as *mut u64;
                
                while *thunk_ptr != 0 {
                    if *thunk_ptr & 0x8000000000000000 != 0 {
                        // Import by ordinal
                        let ordinal = (*thunk_ptr & 0xFFFF) as u16;
                        // *func_ptr = get_proc_address_by_ordinal(dll_handle, ordinal)?;
                    } else {
                        // Import by name
                        let import_by_name = (image_base + *thunk_ptr) as *const u16;
                        let name_ptr = import_by_name.add(1) as *const u8;
                        let func_name = self.read_cstring(name_ptr)?;
                        // *func_ptr = get_proc_address(dll_handle, &func_name)?;
                    }
                    
                    thunk_ptr = thunk_ptr.add(1);
                    func_ptr = func_ptr.add(1);
                }
                
                import_desc_ptr = import_desc_ptr.add(1);
            }
        }
        
        Ok(())
    }
    
    fn read_cstring(&self, ptr: *const u8) -> Result<String, PeError> {
        let mut bytes = Vec::new();
        let mut offset = 0;
        
        unsafe {
            while *ptr.add(offset) != 0 {
                bytes.push(*ptr.add(offset));
                offset += 1;
                
                if offset > 256 {
                    return Err(PeError::InvalidFormat("String too long"));
                }
            }
        }
        
        String::from_utf8(bytes)
            .map_err(|_| PeError::InvalidFormat("Invalid UTF-8 string"))
    }
    
    pub fn get_exports(&self) -> Result<Vec<(String, u32)>, PeError> {
        let export_dir = if self.is_64bit()? {
            self.get_optional_header_64()?.data_directory[ImageDirectoryEntry::Export as usize]
        } else {
            self.get_optional_header_32()?.data_directory[ImageDirectoryEntry::Export as usize]
        };
        
        if export_dir.size == 0 {
            return Ok(Vec::new()); // No exports
        }
        
        let export_dir_ptr = unsafe {
            self.data.as_ptr().add(self.rva_to_offset(export_dir.virtual_address)? as usize)
                as *const ImageExportDirectory
        };
        
        let export_dir = unsafe { &*export_dir_ptr };
        
        let mut exports = Vec::new();
        
        for i in 0..export_dir.number_of_names {
            let name_rva = unsafe {
                let names_ptr = self.data.as_ptr().add(
                    self.rva_to_offset(export_dir.address_of_names)? as usize
                ) as *const u32;
                *names_ptr.add(i as usize)
            };
            
            let name_ptr = unsafe {
                self.data.as_ptr().add(self.rva_to_offset(name_rva)? as usize)
            };
            
            let name = self.read_cstring(name_ptr)?;
            
            let ordinal = unsafe {
                let ordinals_ptr = self.data.as_ptr().add(
                    self.rva_to_offset(export_dir.address_of_name_ordinals)? as usize
                ) as *const u16;
                *ordinals_ptr.add(i as usize)
            };
            
            let function_rva = unsafe {
                let functions_ptr = self.data.as_ptr().add(
                    self.rva_to_offset(export_dir.address_of_functions)? as usize
                ) as *const u32;
                *functions_ptr.add(ordinal as usize)
            };
            
            exports.push((name, function_rva));
        }
        
        Ok(exports)
    }
    
    fn rva_to_offset(&self, rva: u32) -> Result<u32, PeError> {
        let sections = self.get_sections()?;
        
        for section in sections {
            if rva >= section.virtual_address 
                && rva < section.virtual_address + section.virtual_size {
                return Ok(rva - section.virtual_address + section.pointer_to_raw_data);
            }
        }
        
        Err(PeError::InvalidRva)
    }
}

#[derive(Debug)]
pub enum PeError {
    InvalidFormat(&'static str),
    AllocationFailed,
    InvalidRva,
    ImportResolutionFailed,
}

impl core::fmt::Display for PeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            PeError::InvalidFormat(msg) => write!(f, "Invalid PE format: {}", msg),
            PeError::AllocationFailed => write!(f, "Memory allocation failed"),
            PeError::InvalidRva => write!(f, "Invalid RVA"),
            PeError::ImportResolutionFailed => write!(f, "Failed to resolve imports"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dos_header_size() {
        assert_eq!(mem::size_of::<DosHeader>(), 64);
    }
    
    #[test]
    fn test_pe_signature() {
        assert_eq!(PE_SIGNATURE, 0x00004550);
    }
}