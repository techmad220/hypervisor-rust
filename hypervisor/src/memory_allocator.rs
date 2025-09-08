//! Memory allocator matching C implementation's AllocatePageAlignedMemory pattern

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use alloc::vec::Vec;
use crate::HypervisorError;

pub const PAGE_SIZE: usize = 4096;
pub const PAGES_TO_SIZE: fn(usize) -> usize = |pages| pages * PAGE_SIZE;

/// Page-aligned memory allocator (from C: AllocatePageAlignedMemory)
pub struct PageAlignedAllocator {
    allocated_regions: Vec<(*mut u8, usize)>,
}

impl PageAlignedAllocator {
    pub const fn new() -> Self {
        Self {
            allocated_regions: Vec::new(),
        }
    }
    
    /// Allocate page-aligned memory (matching C's AllocatePageAlignedMemory)
    pub fn allocate_pages(&mut self, pages: usize) -> Result<*mut u8, HypervisorError> {
        let size = PAGES_TO_SIZE(pages);
        let layout = Layout::from_size_align(size, PAGE_SIZE)
            .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
        
        unsafe {
            let ptr = alloc::alloc::alloc_zeroed(layout);
            if ptr.is_null() {
                return Err(HypervisorError::MemoryAllocationFailed);
            }
            
            // Track allocation
            self.allocated_regions.push((ptr, size));
            
            // Clear memory (like C's SetMem)
            ptr::write_bytes(ptr, 0, size);
            
            log::debug!("[Memory] Allocated {} pages at {:p}", pages, ptr);
            Ok(ptr)
        }
    }
    
    /// Free pages (matching C's FreePages)
    pub fn free_pages(&mut self, addr: *mut u8, pages: usize) -> Result<(), HypervisorError> {
        let size = PAGES_TO_SIZE(pages);
        
        // Find and remove from tracking
        if let Some(pos) = self.allocated_regions.iter()
            .position(|(ptr, sz)| *ptr == addr && *sz == size) {
            self.allocated_regions.remove(pos);
            
            let layout = Layout::from_size_align(size, PAGE_SIZE)
                .map_err(|_| HypervisorError::MemoryError)?;
            
            unsafe {
                alloc::alloc::dealloc(addr, layout);
            }
            
            log::debug!("[Memory] Freed {} pages at {:p}", pages, addr);
            Ok(())
        } else {
            Err(HypervisorError::InvalidParameter)
        }
    }
    
    /// Get total allocated memory
    pub fn get_allocated_size(&self) -> usize {
        self.allocated_regions.iter().map(|(_, size)| size).sum()
    }
}

/// Global page allocator instance
pub static mut PAGE_ALLOCATOR: PageAlignedAllocator = PageAlignedAllocator::new();

/// Allocate page-aligned memory (C-compatible interface)
pub fn allocate_page_aligned_memory(pages: usize) -> Result<*mut u8, HypervisorError> {
    unsafe {
        PAGE_ALLOCATOR.allocate_pages(pages)
    }
}

/// Setup NPT (Nested Page Tables) - Direct port from C
pub fn setup_npt() -> Result<u64, HypervisorError> {
    log::info!("[SetupNPT] Initializing Nested Page Tables.");
    
    unsafe {
        // Allocate PML4 table (matching C)
        let pml4_addr = allocate_page_aligned_memory(1)?;
        if pml4_addr.is_null() {
            log::error!("[-] Failed to allocate PML4 table.");
            return Err(HypervisorError::MemoryAllocationFailed);
        }
        
        // Allocate PDPT table
        let pdpt_addr = allocate_page_aligned_memory(1)?;
        if pdpt_addr.is_null() {
            log::error!("[-] Failed to allocate PDPT table.");
            PAGE_ALLOCATOR.free_pages(pml4_addr, 1)?;
            return Err(HypervisorError::MemoryAllocationFailed);
        }
        
        // Allocate PD table
        let pd_addr = allocate_page_aligned_memory(1)?;
        if pd_addr.is_null() {
            log::error!("[-] Failed to allocate PD table.");
            PAGE_ALLOCATOR.free_pages(pml4_addr, 1)?;
            PAGE_ALLOCATOR.free_pages(pdpt_addr, 1)?;
            return Err(HypervisorError::MemoryAllocationFailed);
        }
        
        // Setup page tables (exact match to C code)
        let pml4 = pml4_addr as *mut u64;
        let pdpt = pdpt_addr as *mut u64;
        let pd = pd_addr as *mut u64;
        
        // PML4[0] = PDPT | Present, RW, User (matching C: PdptAddr | 7)
        *pml4.offset(0) = (pdpt_addr as u64) | 7;
        
        // PDPT[0] = PD | Present, RW, User
        *pdpt.offset(0) = (pd_addr as u64) | 7;
        
        // Setup 512 * 2MB pages (1GB total) - exact match to C loop
        for i in 0..512 {
            *pd.offset(i) = (i as u64 * 0x200000) | 0x87; // 2MB pages with flags
        }
        
        log::info!("[SetupNPT] Nested page tables configured.");
        
        // Return PML4 physical address for NCR3
        Ok(pml4_addr as u64)
    }
}

/// Mask CPUID features (from C: MaskCpuidFeatures)
pub fn mask_cpuid_features() -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    
    unsafe {
        // Get CPUID leaf 1
        asm!(
            "mov eax, 1",
            "cpuid",
            out("eax") eax,
            out("ebx") ebx,
            out("ecx") ecx,
            out("edx") edx,
        );
        
        // Clear hypervisor-present bit (ECX[31]) - exact match to C
        ecx &= !(1u32 << 31);
        
        log::info!("[CPUID] Hypervisor-present bit cleared (requires VMEXIT CPUID handler).");
    }
    
    (eax, ebx, ecx, edx)
}

/// Host Save Area setup (from C patterns)
pub fn setup_host_save_area() -> Result<u64, HypervisorError> {
    unsafe {
        // Allocate host save area
        let host_save_area = allocate_page_aligned_memory(1)?;
        if host_save_area.is_null() {
            return Err(HypervisorError::MemoryAllocationFailed);
        }
        
        // Write to VM_HSAVE_PA MSR
        const MSR_VM_HSAVE_PA: u32 = 0xC0010117;
        asm!(
            "wrmsr",
            in("ecx") MSR_VM_HSAVE_PA,
            in("eax") host_save_area as u32,
            in("edx") (host_save_area as u64 >> 32) as u32,
        );
        
        log::info!("[SVM] Host save area configured at {:p}", host_save_area);
        Ok(host_save_area as u64)
    }
}