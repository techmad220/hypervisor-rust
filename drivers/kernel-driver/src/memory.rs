//! Memory management and shared memory support

use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::km::wdm::*;
use core::ptr;

const SHARED_MEMORY_SIZE: usize = 4096;

pub struct SharedMemory {
    base: *mut u8,
    section_handle: HANDLE,
    user_base: *mut u8,
}

impl SharedMemory {
    pub fn new() -> Self {
        Self {
            base: ptr::null_mut(),
            section_handle: ptr::null_mut(),
            user_base: ptr::null_mut(),
        }
    }
    
    /// Create shared memory section
    pub unsafe fn create(&mut self) -> Result<(), NTSTATUS> {
        let mut size: LARGE_INTEGER = core::mem::zeroed();
        size.QuadPart = SHARED_MEMORY_SIZE as i64;
        
        let mut obj_attr: OBJECT_ATTRIBUTES = core::mem::zeroed();
        InitializeObjectAttributes(
            &mut obj_attr,
            ptr::null_mut(),
            OBJ_KERNEL_HANDLE,
            ptr::null_mut(),
            ptr::null_mut()
        );
        
        let status = ZwCreateSection(
            &mut self.section_handle,
            SECTION_ALL_ACCESS,
            &mut obj_attr,
            &mut size,
            PAGE_READWRITE,
            SEC_COMMIT,
            ptr::null_mut()
        );
        
        if !NT_SUCCESS(status) {
            return Err(status);
        }
        
        // Map to kernel space
        let mut view_size = SHARED_MEMORY_SIZE;
        let status = ZwMapViewOfSection(
            self.section_handle,
            ZwCurrentProcess(),
            &mut self.base as *mut _ as *mut PVOID,
            0,
            SHARED_MEMORY_SIZE,
            ptr::null_mut(),
            &mut view_size,
            ViewUnmap,
            0,
            PAGE_READWRITE
        );
        
        if !NT_SUCCESS(status) {
            ZwClose(self.section_handle);
            return Err(status);
        }
        
        DbgPrint(
            b"[Memory] Shared memory created at: 0x%p\n\0".as_ptr() as *const i8,
            self.base
        );
        
        Ok(())
    }
    
    /// Map shared memory to user process
    pub unsafe fn map_to_user(&mut self, process: PEPROCESS) -> Result<*mut u8, NTSTATUS> {
        let mut view_size = SHARED_MEMORY_SIZE;
        let process_handle = process as HANDLE;
        
        let status = ZwMapViewOfSection(
            self.section_handle,
            process_handle,
            &mut self.user_base as *mut _ as *mut PVOID,
            0,
            SHARED_MEMORY_SIZE,
            ptr::null_mut(),
            &mut view_size,
            ViewUnmap,
            0,
            PAGE_READWRITE
        );
        
        if !NT_SUCCESS(status) {
            return Err(status);
        }
        
        DbgPrint(
            b"[Memory] Shared memory mapped to user: 0x%p\n\0".as_ptr() as *const i8,
            self.user_base
        );
        
        Ok(self.user_base)
    }
    
    /// Write to shared memory
    pub unsafe fn write(&self, data: &[u8]) -> Result<(), NTSTATUS> {
        if self.base.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        
        let copy_size = data.len().min(SHARED_MEMORY_SIZE);
        ptr::copy_nonoverlapping(data.as_ptr(), self.base, copy_size);
        
        Ok(())
    }
    
    /// Read from shared memory
    pub unsafe fn read(&self, buffer: &mut [u8]) -> Result<usize, NTSTATUS> {
        if self.base.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        
        let copy_size = buffer.len().min(SHARED_MEMORY_SIZE);
        ptr::copy_nonoverlapping(self.base, buffer.as_mut_ptr(), copy_size);
        
        Ok(copy_size)
    }
    
    /// Cleanup shared memory
    pub unsafe fn cleanup(&mut self) {
        if !self.base.is_null() {
            ZwUnmapViewOfSection(ZwCurrentProcess(), self.base as PVOID);
            self.base = ptr::null_mut();
        }
        
        if !self.section_handle.is_null() {
            ZwClose(self.section_handle);
            self.section_handle = ptr::null_mut();
        }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            self.cleanup();
        }
    }
}

// Memory scanning functions
pub unsafe fn scan_memory_pattern(
    start: *const u8,
    size: usize,
    pattern: &[u8],
    mask: &[u8]
) -> Option<*const u8> {
    if pattern.len() != mask.len() {
        return None;
    }
    
    for i in 0..size {
        let mut found = true;
        
        for j in 0..pattern.len() {
            if mask[j] == b'x' {
                if *start.offset((i + j) as isize) != pattern[j] {
                    found = false;
                    break;
                }
            }
        }
        
        if found {
            return Some(start.offset(i as isize));
        }
    }
    
    None
}

// Helper constants
const OBJ_KERNEL_HANDLE: u32 = 0x00000200;
const SECTION_ALL_ACCESS: u32 = 0x000F001F;
const PAGE_READWRITE: u32 = 0x04;
const SEC_COMMIT: u32 = 0x8000000;
const ViewUnmap: u32 = 2;

type PEPROCESS = *mut u8;

extern "system" {
    fn InitializeObjectAttributes(
        p: *mut OBJECT_ATTRIBUTES,
        n: *mut UNICODE_STRING,
        a: u32,
        r: HANDLE,
        s: *mut SECURITY_DESCRIPTOR
    );
    fn ZwCreateSection(
        SectionHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        MaximumSize: *mut LARGE_INTEGER,
        SectionPageProtection: u32,
        AllocationAttributes: u32,
        FileHandle: HANDLE
    ) -> NTSTATUS;
    fn ZwMapViewOfSection(
        SectionHandle: HANDLE,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        CommitSize: SIZE_T,
        SectionOffset: *mut LARGE_INTEGER,
        ViewSize: *mut SIZE_T,
        InheritDisposition: u32,
        AllocationType: u32,
        Win32Protect: u32
    ) -> NTSTATUS;
    fn ZwUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> NTSTATUS;
    fn ZwClose(Handle: HANDLE) -> NTSTATUS;
    fn ZwCurrentProcess() -> HANDLE;
    fn DbgPrint(Format: *const i8, ...) -> NTSTATUS;
}