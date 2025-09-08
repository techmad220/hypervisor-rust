//! Memory management for hypervisor

use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Page, Size4KiB, Size2MiB, Size1GiB};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::HypervisorError;

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

/// Memory manager
pub struct MemoryManager {
    regions: Mutex<Vec<MemoryRegion>>,
    ept_root: Option<PhysAddr>,
    npt_root: Option<PhysAddr>,
    allocations: Mutex<BTreeMap<PhysAddr, usize>>,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
            ept_root: None,
            npt_root: None,
            allocations: Mutex::new(BTreeMap::new()),
        }
    }
    
    /// Add a memory region
    pub fn add_region(&self, region: MemoryRegion) {
        self.regions.lock().push(region);
        log::debug!("Added memory region: {:?}", region);
    }
    
    /// Allocate physical memory
    pub fn allocate_physical(&self, size: usize, align: usize) -> Result<PhysAddr, HypervisorError> {
        let layout = alloc::alloc::Layout::from_size_align(size, align)
            .map_err(|_| HypervisorError::MemoryAllocationFailed)?;
        
        let ptr = unsafe {
            alloc::alloc::alloc_zeroed(layout)
        };
        
        if ptr.is_null() {
            return Err(HypervisorError::MemoryAllocationFailed);
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
    
    /// Create NPT for AMD-V
    pub fn create_npt(&mut self) -> Result<PhysAddr, HypervisorError> {
        // NPT uses same format as regular x86-64 page tables
        let pml4_addr = self.allocate_physical(4096, 4096)?;
        let pml4 = unsafe { &mut *(pml4_addr.as_u64() as *mut PageTable) };
        pml4.zero();
        
        // Set up identity mapping
        self.setup_npt_identity_map(pml4)?;
        
        self.npt_root = Some(pml4_addr);
        log::info!("Created NPT at {:?}", pml4_addr);
        
        Ok(pml4_addr)
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