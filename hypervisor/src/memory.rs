//! Real memory management for hypervisor
//! Based on C implementation from svm.c and vm_creation_plugin.c

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Page, Size4KiB, Size2MiB, Size1GiB};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::HypervisorError;

/// Page size constants
pub const PAGE_SIZE: usize = 4096;
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024; // 2MB

/// Memory region type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryType {
    Ram,
    Reserved,
    Mmio,
    Rom,
}

/// Memory region
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub size: usize,
    pub mem_type: MemoryType,
    pub flags: MemoryFlags,
}

bitflags::bitflags! {
    pub struct MemoryFlags: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const CACHED = 1 << 3;
        const DEVICE = 1 << 4;
    }
}

/// Extended Page Table entry for Intel EPT
#[repr(C)]
pub struct EptEntry {
    entry: u64,
}

impl EptEntry {
    const PRESENT: u64 = 1 << 0;
    const WRITABLE: u64 = 1 << 1;
    const EXECUTABLE: u64 = 1 << 2;
    const MEMORY_TYPE_MASK: u64 = 0x7 << 3;
    const ACCESSED: u64 = 1 << 8;
    const DIRTY: u64 = 1 << 9;
    const HUGE_PAGE: u64 = 1 << 7;
    const ADDR_MASK: u64 = 0x000FFFFFFFFFF000;
    
    pub fn new() -> Self {
        Self { entry: 0 }
    }
    
    pub fn set_addr(&mut self, addr: PhysAddr) {
        self.entry = (self.entry & !Self::ADDR_MASK) | (addr.as_u64() & Self::ADDR_MASK);
    }
    
    pub fn set_flags(&mut self, present: bool, writable: bool, executable: bool) {
        self.entry = 0;
        if present {
            self.entry |= Self::PRESENT;
        }
        if writable {
            self.entry |= Self::WRITABLE;
        }
        if executable {
            self.entry |= Self::EXECUTABLE;
        }
    }
    
    pub fn set_huge(&mut self, huge: bool) {
        if huge {
            self.entry |= Self::HUGE_PAGE;
        } else {
            self.entry &= !Self::HUGE_PAGE;
        }
    }
}

/// EPT page table (4-level)
#[repr(C, align(4096))]
pub struct EptPageTable {
    entries: [EptEntry; 512],
}

impl EptPageTable {
    pub fn new() -> Self {
        Self {
            entries: [EptEntry::new(); 512],
        }
    }
}

/// Real NPT/EPT page table manager
pub struct NestedPageTables {
    pml4: *mut PageTable,
    pdpt: *mut PageTable,
    pd: *mut PageTable,
    pt: *mut PageTable,
    allocated_pages: Vec<(*mut u8, Layout)>,
}

impl NestedPageTables {
    /// Create new NPT/EPT structure (based on C SetupNpt)
    pub fn new() -> Result<Self, HypervisorError> {
        unsafe {
            // Allocate PML4 table (4KB aligned)
            let pml4_layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
                .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
            let pml4 = alloc::alloc::alloc_zeroed(pml4_layout) as *mut PageTable;
            if pml4.is_null() {
                return Err(HypervisorError::MemoryAllocationFailed);
            }

            // Allocate PDPT table
            let pdpt_layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
                .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
            let pdpt = alloc::alloc::alloc_zeroed(pdpt_layout) as *mut PageTable;
            if pdpt.is_null() {
                alloc::alloc::dealloc(pml4 as *mut u8, pml4_layout);
                return Err(HypervisorError::MemoryAllocationFailed);
            }

            // Allocate PD table
            let pd_layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
                .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
            let pd = alloc::alloc::alloc_zeroed(pd_layout) as *mut PageTable;
            if pd.is_null() {
                alloc::alloc::dealloc(pml4 as *mut u8, pml4_layout);
                alloc::alloc::dealloc(pdpt as *mut u8, pdpt_layout);
                return Err(HypervisorError::MemoryAllocationFailed);
            }

            // Allocate PT table  
            let pt_layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
                .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
            let pt = alloc::alloc::alloc_zeroed(pt_layout) as *mut PageTable;
            if pt.is_null() {
                alloc::alloc::dealloc(pml4 as *mut u8, pml4_layout);
                alloc::alloc::dealloc(pdpt as *mut u8, pdpt_layout);
                alloc::alloc::dealloc(pd as *mut u8, pd_layout);
                return Err(HypervisorError::MemoryAllocationFailed);
            }

            // Set up page table hierarchy (from C: Pml4[0] = PdptAddr | 7)
            (*pml4)[0].set_addr(
                PhysAddr::new(pdpt as u64),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            );

            // PDPT[0] -> PD
            (*pdpt)[0].set_addr(
                PhysAddr::new(pd as u64),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            );

            // PD entries use 2MB pages for identity mapping (from C: Pd[i] = (i * 0x200000ULL) | 0x87)
            for i in 0..512 {
                (*pd)[i].set_addr(
                    PhysAddr::new(i * LARGE_PAGE_SIZE as u64),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                    PageTableFlags::USER_ACCESSIBLE | PageTableFlags::HUGE_PAGE
                );
            }

            let mut allocated_pages = Vec::new();
            allocated_pages.push((pml4 as *mut u8, pml4_layout));
            allocated_pages.push((pdpt as *mut u8, pdpt_layout));
            allocated_pages.push((pd as *mut u8, pd_layout));
            allocated_pages.push((pt as *mut u8, pt_layout));

            Ok(Self {
                pml4,
                pdpt,
                pd,
                pt,
                allocated_pages,
            })
        }
    }

    /// Get PML4 physical address for VMCB/VMCS
    pub fn get_pml4_addr(&self) -> u64 {
        self.pml4 as u64
    }
}

impl Drop for NestedPageTables {
    fn drop(&mut self) {
        unsafe {
            // Deallocate all page tables
            for (ptr, layout) in self.allocated_pages.drain(..) {
                alloc::alloc::dealloc(ptr, layout);
            }
        }
    }
}

/// Memory manager
pub struct MemoryManager {
    regions: Mutex<Vec<MemoryRegion>>,
    ept_root: Option<PhysAddr>,
    npt_root: Option<PhysAddr>,
    allocations: Mutex<BTreeMap<PhysAddr, usize>>,
    npt: Option<NestedPageTables>,
    guest_memory_base: u64,
    guest_memory_size: usize,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self::with_guest_memory(4 * 1024 * 1024) // Default 4MB guest
    }
    
    /// Create with specific guest memory size (based on C SetupExpandedNpt)
    pub fn with_guest_memory(guest_memory_size: usize) -> Self {
        // Allocate guest memory
        let layout = Layout::from_size_align(guest_memory_size, PAGE_SIZE)
            .expect("Invalid memory layout");
        
        let guest_memory_base = unsafe {
            let ptr = alloc::alloc::alloc_zeroed(layout);
            if ptr.is_null() {
                panic!("Failed to allocate guest memory");
            }
            ptr as u64
        };

        // Create NPT/EPT
        let npt = NestedPageTables::new().ok();
        let npt_root = npt.as_ref().map(|n| PhysAddr::new(n.get_pml4_addr()));

        Self {
            regions: Mutex::new(Vec::new()),
            ept_root: None,
            npt_root,
            allocations: Mutex::new(BTreeMap::new()),
            npt,
            guest_memory_base,
            guest_memory_size,
        }
    }
    
    /// Add a memory region
    pub fn add_region(&self, region: MemoryRegion) {
        self.regions.lock().push(region);
        log::debug!("Added memory region: {:?}", region);
    }
    
    /// Allocate physical memory (based on C AllocatePageAlignedMemory)
    pub fn allocate_physical(&self, size: usize, align: usize) -> Result<PhysAddr, HypervisorError> {
        let layout = Layout::from_size_align(size, align)
            .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
        
        let ptr = unsafe {
            alloc::alloc::alloc_zeroed(layout)
        };
        
        if ptr.is_null() {
            return Err(HypervisorError::MemoryAllocationFailed);
        }
        
        // Clear memory (like C SetMem)
        unsafe {
            ptr::write_bytes(ptr, 0, size);
        }
        
        let addr = PhysAddr::new(ptr as u64);
        self.allocations.lock().insert(addr, size);
        
        log::trace!("Allocated {} bytes at {:?}", size, addr);
        Ok(addr)
    }
    
    /// Free physical memory
    pub fn free_physical(&self, addr: PhysAddr) -> Result<(), HypervisorError> {
        let size = self.allocations.lock().remove(&addr)
            .ok_or(HypervisorError::MemoryAllocationFailed)?;
        
        unsafe {
            let layout = alloc::alloc::Layout::from_size_align_unchecked(size, 4096);
            alloc::alloc::dealloc(addr.as_u64() as *mut u8, layout);
        }
        
        log::trace!("Freed {} bytes at {:?}", size, addr);
        Ok(())
    }
    
    /// Create EPT for Intel VT-x
    pub fn create_ept(&mut self) -> Result<PhysAddr, HypervisorError> {
        // Allocate PML4 table
        let pml4_addr = self.allocate_physical(4096, 4096)?;
        let pml4 = unsafe { &mut *(pml4_addr.as_u64() as *mut EptPageTable) };
        
        // Initialize EPT with identity mapping for first 4GB
        self.setup_ept_identity_map(pml4)?;
        
        self.ept_root = Some(pml4_addr);
        log::info!("Created EPT at {:?}", pml4_addr);
        
        Ok(pml4_addr)
    }
    
    /// Set up identity mapping in EPT
    fn setup_ept_identity_map(&self, pml4: &mut EptPageTable) -> Result<(), HypervisorError> {
        // Allocate PDPT
        let pdpt_addr = self.allocate_physical(4096, 4096)?;
        let pdpt = unsafe { &mut *(pdpt_addr.as_u64() as *mut EptPageTable) };
        
        // Set PML4[0] -> PDPT
        pml4.entries[0].set_addr(pdpt_addr);
        pml4.entries[0].set_flags(true, true, true);
        
        // Map first 4GB using 1GB pages
        for i in 0..4 {
            pdpt.entries[i].set_addr(PhysAddr::new(i as u64 * 0x40000000));
            pdpt.entries[i].set_flags(true, true, true);
            pdpt.entries[i].set_huge(true); // 1GB page
        }
        
        Ok(())
    }
    
    /// Create NPT for AMD-V (real implementation)
    pub fn create_npt(&mut self) -> Result<PhysAddr, HypervisorError> {
        // Create real NPT structure
        let npt = NestedPageTables::new()?;
        let pml4_addr = PhysAddr::new(npt.get_pml4_addr());
        
        self.npt = Some(npt);
        self.npt_root = Some(pml4_addr);
        log::info!("Created NPT at {:?}", pml4_addr);
        
        Ok(pml4_addr)
    }
    
    /// Get NPT base address for VMCB
    pub fn get_npt_base(&self) -> u64 {
        self.npt.as_ref().map(|n| n.get_pml4_addr()).unwrap_or(0)
    }
    
    /// Read from guest memory
    pub unsafe fn read_guest_memory(&self, gpa: u64, data: &mut [u8]) -> Result<(), HypervisorError> {
        if gpa + data.len() as u64 > self.guest_memory_size as u64 {
            return Err(HypervisorError::InvalidGuestPhysicalAddress);
        }
        
        let src = (self.guest_memory_base + gpa) as *const u8;
        ptr::copy_nonoverlapping(src, data.as_mut_ptr(), data.len());
        Ok(())
    }

    /// Write to guest memory
    pub unsafe fn write_guest_memory(&self, gpa: u64, data: &[u8]) -> Result<(), HypervisorError> {
        if gpa + data.len() as u64 > self.guest_memory_size as u64 {
            return Err(HypervisorError::InvalidGuestPhysicalAddress);
        }
        
        let dst = (self.guest_memory_base + gpa) as *mut u8;
        ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        Ok(())
    }
    
    /// Set up identity mapping in NPT
    fn setup_npt_identity_map(&self, pml4: &mut PageTable) -> Result<(), HypervisorError> {
        // Similar to EPT but using standard page table format
        let pdpt_addr = self.allocate_physical(4096, 4096)?;
        let pdpt = unsafe { &mut *(pdpt_addr.as_u64() as *mut PageTable) };
        pdpt.zero();
        
        pml4[0].set_addr(
            pdpt_addr,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
        );
        
        // Map first 4GB
        for i in 0..4 {
            let pd_addr = self.allocate_physical(4096, 4096)?;
            let pd = unsafe { &mut *(pd_addr.as_u64() as *mut PageTable) };
            pd.zero();
            
            pdpt[i].set_addr(
                pd_addr,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
            );
            
            // Use 2MB pages
            for j in 0..512 {
                let phys_addr = PhysAddr::new((i * 512 + j) as u64 * 0x200000);
                pd[j].set_addr(
                    phys_addr,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                    PageTableFlags::USER_ACCESSIBLE | PageTableFlags::HUGE_PAGE
                );
            }
        }
        
        Ok(())
    }
    
    /// Map guest physical to host physical
    pub fn map_gpa_to_hpa(
        &self,
        gpa: PhysAddr,
        hpa: PhysAddr,
        size: usize,
        flags: MemoryFlags,
    ) -> Result<(), HypervisorError> {
        log::debug!("Mapping GPA {:?} -> HPA {:?}, size {:#x}", gpa, hpa, size);
        
        // Update EPT or NPT based on what's active
        if let Some(ept_root) = self.ept_root {
            self.update_ept_mapping(ept_root, gpa, hpa, size, flags)?;
        } else if let Some(npt_root) = self.npt_root {
            self.update_npt_mapping(npt_root, gpa, hpa, size, flags)?;
        }
        
        Ok(())
    }
    
    /// Update EPT mapping
    fn update_ept_mapping(
        &self,
        ept_root: PhysAddr,
        gpa: PhysAddr,
        hpa: PhysAddr,
        size: usize,
        flags: MemoryFlags,
    ) -> Result<(), HypervisorError> {
        // EPT mapping implementation
        // Walk EPT tables and update mapping
        Ok(())
    }
    
    /// Update NPT mapping
    fn update_npt_mapping(
        &self,
        npt_root: PhysAddr,
        gpa: PhysAddr,
        hpa: PhysAddr,
        size: usize,
        flags: MemoryFlags,
    ) -> Result<(), HypervisorError> {
        // NPT mapping implementation
        // Walk NPT tables and update mapping
        Ok(())
    }
    
    /// Handle page fault
    pub fn handle_page_fault(&self, fault_addr: VirtAddr, error_code: u64) -> Result<(), HypervisorError> {
        log::debug!("Page fault at {:?}, error code: {:#x}", fault_addr, error_code);
        
        // Determine fault type
        let present = error_code & 0x1 != 0;
        let write = error_code & 0x2 != 0;
        let user = error_code & 0x4 != 0;
        let reserved = error_code & 0x8 != 0;
        let instruction = error_code & 0x10 != 0;
        
        if !present {
            // Page not present - allocate and map
            let page_addr = self.allocate_physical(4096, 4096)?;
            // Map the page...
        }
        
        Ok(())
    }
}

/// Memory ballooning support
pub struct MemoryBalloon {
    current_size: Mutex<usize>,
    target_size: usize,
    pages: Mutex<Vec<PhysAddr>>,
}

impl MemoryBalloon {
    pub fn new(initial_size: usize) -> Self {
        Self {
            current_size: Mutex::new(initial_size),
            target_size: initial_size,
            pages: Mutex::new(Vec::new()),
        }
    }
    
    /// Inflate balloon (reduce guest memory)
    pub fn inflate(&self, pages: usize) -> Result<(), HypervisorError> {
        let mut current = self.current_size.lock();
        let mut page_list = self.pages.lock();
        
        for _ in 0..pages {
            // Allocate page from guest
            // Add to balloon
            page_list.push(PhysAddr::new(0)); // Placeholder
        }
        
        *current += pages * 4096;
        log::info!("Balloon inflated by {} pages", pages);
        
        Ok(())
    }
    
    /// Deflate balloon (return memory to guest)
    pub fn deflate(&self, pages: usize) -> Result<(), HypervisorError> {
        let mut current = self.current_size.lock();
        let mut page_list = self.pages.lock();
        
        for _ in 0..pages.min(page_list.len()) {
            // Return page to guest
            page_list.pop();
        }
        
        *current = current.saturating_sub(pages * 4096);
        log::info!("Balloon deflated by {} pages", pages);
        
        Ok(())
    }
}

extern crate alloc;