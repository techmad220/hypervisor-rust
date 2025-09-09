//! Extended Page Tables (Intel EPT) and Nested Page Tables (AMD NPT) Implementation
//! Complete production-ready nested paging for both Intel and AMD

#![no_std]
#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::mem;
use crate::HypervisorError;

/// EPT/NPT page table entry flags
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum PageTableFlags {
    Present = 1 << 0,
    Writable = 1 << 1,
    Executable = 1 << 2,
    MemoryType = 0x7 << 3,  // Bits 3-5
    IgnorePat = 1 << 6,
    LargePage = 1 << 7,
    Accessed = 1 << 8,
    Dirty = 1 << 9,
    ExecuteForUserMode = 1 << 10,
    VerifyGuestPaging = 1 << 57,
    PagingWriteAccess = 1 << 58,
    SupervisorShadowStack = 1 << 60,
    SubPageWritePerm = 1 << 61,
    SuppressVE = 1 << 63,
}

/// Memory types for EPT
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

/// EPT violation exit qualification
#[derive(Debug)]
pub struct EptViolationInfo {
    pub read_access: bool,
    pub write_access: bool,
    pub execute_access: bool,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub user_mode_executable: bool,
    pub gpa_valid: bool,
    pub caused_by_translation: bool,
    pub user_mode_linear_address: bool,
    pub readable_writable: bool,
    pub executable_user: bool,
    pub verify_guest_paging: bool,
    pub paging_write: bool,
    pub shadow_stack: bool,
    pub supervisor_shadow_stack: bool,
    pub guest_physical_address: u64,
}

/// 4-Level EPT/NPT page table structure
pub struct NestedPageTable {
    /// PML4 (Page Map Level 4) base address
    pml4_base: u64,
    /// Allocated pages for page tables
    allocated_pages: Vec<u64>,
    /// Guest physical to host physical mappings
    gpa_to_hpa: BTreeMap<u64, u64>,
    /// Memory type mappings for MMIO regions
    mmio_regions: BTreeMap<(u64, u64), MemoryType>,
    /// Dirty page tracking bitmap
    dirty_bitmap: Vec<u64>,
    /// Access tracking bitmap
    access_bitmap: Vec<u64>,
    /// Maximum guest physical address
    max_gpa: u64,
    /// Use 2MB large pages
    use_large_pages: bool,
    /// Use 1GB huge pages
    use_huge_pages: bool,
}

impl NestedPageTable {
    /// Create new EPT/NPT structure
    pub fn new(max_gpa: u64) -> Result<Self, HypervisorError> {
        use alloc::alloc::{alloc, Layout};
        
        // Allocate PML4 table
        let pml4_base = unsafe {
            let ptr = alloc(Layout::from_size_align(4096, 4096).unwrap());
            if ptr.is_null() {
                return Err(HypervisorError::InsufficientMemory);
            }
            core::ptr::write_bytes(ptr, 0, 4096);
            ptr as u64
        };
        
        // Calculate bitmap sizes (1 bit per 4KB page)
        let num_pages = (max_gpa + 0xFFF) / 0x1000;
        let bitmap_size = (num_pages + 63) / 64;
        
        Ok(Self {
            pml4_base,
            allocated_pages: Vec::new(),
            gpa_to_hpa: BTreeMap::new(),
            mmio_regions: BTreeMap::new(),
            dirty_bitmap: vec![0; bitmap_size as usize],
            access_bitmap: vec![0; bitmap_size as usize],
            max_gpa,
            use_large_pages: true,
            use_huge_pages: true,
        })
    }
    
    /// Map guest physical address to host physical address
    pub fn map_gpa_to_hpa(&mut self, gpa: u64, hpa: u64, size: u64, 
                          writable: bool, executable: bool) -> Result<(), HypervisorError> {
        // Validate addresses
        if gpa >= self.max_gpa || (gpa + size) > self.max_gpa {
            return Err(HypervisorError::InvalidGuestPhysicalAddress);
        }
        
        // Align addresses to page boundary
        let gpa_aligned = gpa & !0xFFF;
        let hpa_aligned = hpa & !0xFFF;
        let size_aligned = ((size + 0xFFF) & !0xFFF) as usize;
        
        // Map each page
        for offset in (0..size_aligned).step_by(4096) {
            let cur_gpa = gpa_aligned + offset as u64;
            let cur_hpa = hpa_aligned + offset as u64;
            
            self.map_single_page(cur_gpa, cur_hpa, writable, executable)?;
            self.gpa_to_hpa.insert(cur_gpa, cur_hpa);
        }
        
        Ok(())
    }
    
    /// Map a single 4KB page
    fn map_single_page(&mut self, gpa: u64, hpa: u64, writable: bool, 
                      executable: bool) -> Result<(), HypervisorError> {
        // Extract indices for each level
        let pml4_index = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pt_index = ((gpa >> 12) & 0x1FF) as usize;
        
        // Walk/create page tables
        let pml4_table = unsafe { &mut *(self.pml4_base as *mut [u64; 512]) };
        
        // Get or create PDPT
        let pdpt_base = if pml4_table[pml4_index] & PageTableFlags::Present as u64 != 0 {
            pml4_table[pml4_index] & 0x000FFFFFFFFFF000
        } else {
            let pdpt = self.allocate_page_table()?;
            pml4_table[pml4_index] = pdpt | 
                PageTableFlags::Present as u64 |
                PageTableFlags::Writable as u64 |
                PageTableFlags::Executable as u64;
            pdpt
        };
        
        let pdpt_table = unsafe { &mut *(pdpt_base as *mut [u64; 512]) };
        
        // Check for 1GB huge page opportunity
        if self.use_huge_pages && (gpa & 0x3FFFFFFF) == 0 && (hpa & 0x3FFFFFFF) == 0 {
            // Map 1GB huge page
            pdpt_table[pdpt_index] = hpa |
                PageTableFlags::Present as u64 |
                PageTableFlags::LargePage as u64 |
                (if writable { PageTableFlags::Writable as u64 } else { 0 }) |
                (if executable { PageTableFlags::Executable as u64 } else { 0 }) |
                ((MemoryType::WriteBack as u64) << 3);
            return Ok(());
        }
        
        // Get or create PD
        let pd_base = if pdpt_table[pdpt_index] & PageTableFlags::Present as u64 != 0 {
            pdpt_table[pdpt_index] & 0x000FFFFFFFFFF000
        } else {
            let pd = self.allocate_page_table()?;
            pdpt_table[pdpt_index] = pd |
                PageTableFlags::Present as u64 |
                PageTableFlags::Writable as u64 |
                PageTableFlags::Executable as u64;
            pd
        };
        
        let pd_table = unsafe { &mut *(pd_base as *mut [u64; 512]) };
        
        // Check for 2MB large page opportunity
        if self.use_large_pages && (gpa & 0x1FFFFF) == 0 && (hpa & 0x1FFFFF) == 0 {
            // Map 2MB large page
            pd_table[pd_index] = hpa |
                PageTableFlags::Present as u64 |
                PageTableFlags::LargePage as u64 |
                (if writable { PageTableFlags::Writable as u64 } else { 0 }) |
                (if executable { PageTableFlags::Executable as u64 } else { 0 }) |
                ((MemoryType::WriteBack as u64) << 3);
            return Ok(());
        }
        
        // Get or create PT
        let pt_base = if pd_table[pd_index] & PageTableFlags::Present as u64 != 0 {
            pd_table[pd_index] & 0x000FFFFFFFFFF000
        } else {
            let pt = self.allocate_page_table()?;
            pd_table[pd_index] = pt |
                PageTableFlags::Present as u64 |
                PageTableFlags::Writable as u64 |
                PageTableFlags::Executable as u64;
            pt
        };
        
        let pt_table = unsafe { &mut *(pt_base as *mut [u64; 512]) };
        
        // Map 4KB page
        pt_table[pt_index] = hpa |
            PageTableFlags::Present as u64 |
            (if writable { PageTableFlags::Writable as u64 } else { 0 }) |
            (if executable { PageTableFlags::Executable as u64 } else { 0 }) |
            ((MemoryType::WriteBack as u64) << 3);
        
        Ok(())
    }
    
    /// Map MMIO region with specific memory type
    pub fn map_mmio_region(&mut self, gpa_start: u64, size: u64, 
                           memory_type: MemoryType) -> Result<(), HypervisorError> {
        // MMIO regions are mapped on-demand during EPT violations
        self.mmio_regions.insert((gpa_start, gpa_start + size), memory_type);
        
        // Pre-map with uncacheable memory type
        for gpa in (gpa_start..gpa_start + size).step_by(4096) {
            self.map_mmio_page(gpa, memory_type)?;
        }
        
        Ok(())
    }
    
    /// Map a single MMIO page
    fn map_mmio_page(&mut self, gpa: u64, memory_type: MemoryType) -> Result<(), HypervisorError> {
        let pml4_index = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pt_index = ((gpa >> 12) & 0x1FF) as usize;
        
        // Walk/create page tables
        let pml4_table = unsafe { &mut *(self.pml4_base as *mut [u64; 512]) };
        
        // Ensure PDPT exists
        let pdpt_base = if pml4_table[pml4_index] & PageTableFlags::Present as u64 != 0 {
            pml4_table[pml4_index] & 0x000FFFFFFFFFF000
        } else {
            let pdpt = self.allocate_page_table()?;
            pml4_table[pml4_index] = pdpt | 0x7; // Present, Writable, Executable
            pdpt
        };
        
        let pdpt_table = unsafe { &mut *(pdpt_base as *mut [u64; 512]) };
        
        // Ensure PD exists
        let pd_base = if pdpt_table[pdpt_index] & PageTableFlags::Present as u64 != 0 {
            pdpt_table[pdpt_index] & 0x000FFFFFFFFFF000
        } else {
            let pd = self.allocate_page_table()?;
            pdpt_table[pdpt_index] = pd | 0x7;
            pd
        };
        
        let pd_table = unsafe { &mut *(pd_base as *mut [u64; 512]) };
        
        // Ensure PT exists
        let pt_base = if pd_table[pd_index] & PageTableFlags::Present as u64 != 0 {
            pd_table[pd_index] & 0x000FFFFFFFFFF000
        } else {
            let pt = self.allocate_page_table()?;
            pd_table[pd_index] = pt | 0x7;
            pt
        };
        
        let pt_table = unsafe { &mut *(pt_base as *mut [u64; 512]) };
        
        // Map MMIO page with specified memory type, no host backing
        pt_table[pt_index] = PageTableFlags::Present as u64 |
            PageTableFlags::Writable as u64 |
            ((memory_type as u64) << 3);
        
        Ok(())
    }
    
    /// Handle EPT violation
    pub fn handle_ept_violation(&mut self, info: EptViolationInfo) -> Result<EptAction, HypervisorError> {
        let gpa = info.guest_physical_address;
        
        // Check if this is an MMIO region
        for ((start, end), mem_type) in &self.mmio_regions {
            if gpa >= *start && gpa < *end {
                return Ok(EptAction::EmulateMMIO);
            }
        }
        
        // Check if we need to allocate backing memory
        if !self.gpa_to_hpa.contains_key(&(gpa & !0xFFF)) {
            // Allocate new page
            let hpa = self.allocate_backing_page()?;
            self.map_gpa_to_hpa(gpa & !0xFFF, hpa, 4096, true, true)?;
            
            // Mark page as accessed
            self.mark_accessed(gpa);
            
            return Ok(EptAction::Retry);
        }
        
        // Check if this is a write to a read-only page
        if info.write_access && !info.writable {
            // Check if we're tracking dirty pages
            if self.is_dirty_tracking_enabled() {
                self.mark_dirty(gpa);
                // Make page writable
                self.update_page_permissions(gpa, true, info.executable)?;
                return Ok(EptAction::Retry);
            }
            
            // Otherwise, inject page fault
            return Ok(EptAction::InjectPageFault);
        }
        
        // Check if this is execution of non-executable page
        if info.execute_access && !info.executable {
            return Ok(EptAction::InjectPageFault);
        }
        
        // Unknown violation
        log::error!("Unhandled EPT violation at GPA {:#x}", gpa);
        Ok(EptAction::InjectPageFault)
    }
    
    /// Update page permissions
    fn update_page_permissions(&mut self, gpa: u64, writable: bool, 
                              executable: bool) -> Result<(), HypervisorError> {
        let pml4_index = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pt_index = ((gpa >> 12) & 0x1FF) as usize;
        
        // Walk page tables
        let pml4_table = unsafe { &mut *(self.pml4_base as *mut [u64; 512]) };
        if pml4_table[pml4_index] & PageTableFlags::Present as u64 == 0 {
            return Err(HypervisorError::InvalidGuestPhysicalAddress);
        }
        
        let pdpt_base = pml4_table[pml4_index] & 0x000FFFFFFFFFF000;
        let pdpt_table = unsafe { &mut *(pdpt_base as *mut [u64; 512]) };
        if pdpt_table[pdpt_index] & PageTableFlags::Present as u64 == 0 {
            return Err(HypervisorError::InvalidGuestPhysicalAddress);
        }
        
        // Check for 1GB page
        if pdpt_table[pdpt_index] & PageTableFlags::LargePage as u64 != 0 {
            // Update 1GB page permissions
            pdpt_table[pdpt_index] = (pdpt_table[pdpt_index] & !0x6) |
                (if writable { PageTableFlags::Writable as u64 } else { 0 }) |
                (if executable { PageTableFlags::Executable as u64 } else { 0 });
            self.invalidate_ept_entry(gpa);
            return Ok(());
        }
        
        let pd_base = pdpt_table[pdpt_index] & 0x000FFFFFFFFFF000;
        let pd_table = unsafe { &mut *(pd_base as *mut [u64; 512]) };
        if pd_table[pd_index] & PageTableFlags::Present as u64 == 0 {
            return Err(HypervisorError::InvalidGuestPhysicalAddress);
        }
        
        // Check for 2MB page
        if pd_table[pd_index] & PageTableFlags::LargePage as u64 != 0 {
            // Update 2MB page permissions
            pd_table[pd_index] = (pd_table[pd_index] & !0x6) |
                (if writable { PageTableFlags::Writable as u64 } else { 0 }) |
                (if executable { PageTableFlags::Executable as u64 } else { 0 });
            self.invalidate_ept_entry(gpa);
            return Ok(());
        }
        
        let pt_base = pd_table[pd_index] & 0x000FFFFFFFFFF000;
        let pt_table = unsafe { &mut *(pt_base as *mut [u64; 512]) };
        
        // Update 4KB page permissions
        pt_table[pt_index] = (pt_table[pt_index] & !0x6) |
            (if writable { PageTableFlags::Writable as u64 } else { 0 }) |
            (if executable { PageTableFlags::Executable as u64 } else { 0 });
        
        self.invalidate_ept_entry(gpa);
        Ok(())
    }
    
    /// Mark page as dirty
    fn mark_dirty(&mut self, gpa: u64) {
        let page_num = gpa / 0x1000;
        let bitmap_index = (page_num / 64) as usize;
        let bit_offset = (page_num % 64) as u64;
        
        if bitmap_index < self.dirty_bitmap.len() {
            self.dirty_bitmap[bitmap_index] |= 1 << bit_offset;
        }
    }
    
    /// Mark page as accessed
    fn mark_accessed(&mut self, gpa: u64) {
        let page_num = gpa / 0x1000;
        let bitmap_index = (page_num / 64) as usize;
        let bit_offset = (page_num % 64) as u64;
        
        if bitmap_index < self.access_bitmap.len() {
            self.access_bitmap[bitmap_index] |= 1 << bit_offset;
        }
    }
    
    /// Check if dirty tracking is enabled
    fn is_dirty_tracking_enabled(&self) -> bool {
        true // Can be made configurable
    }
    
    /// Get dirty pages since last check
    pub fn get_dirty_pages(&mut self) -> Vec<u64> {
        let mut dirty_pages = Vec::new();
        
        for (i, &bitmap_word) in self.dirty_bitmap.iter().enumerate() {
            if bitmap_word != 0 {
                for bit in 0..64 {
                    if bitmap_word & (1 << bit) != 0 {
                        let page_num = (i * 64 + bit) as u64;
                        dirty_pages.push(page_num * 0x1000);
                    }
                }
            }
        }
        
        // Clear dirty bitmap
        for word in &mut self.dirty_bitmap {
            *word = 0;
        }
        
        dirty_pages
    }
    
    /// Allocate a new page table
    fn allocate_page_table(&mut self) -> Result<u64, HypervisorError> {
        use alloc::alloc::{alloc, Layout};
        
        let ptr = unsafe {
            let p = alloc(Layout::from_size_align(4096, 4096).unwrap());
            if p.is_null() {
                return Err(HypervisorError::InsufficientMemory);
            }
            core::ptr::write_bytes(p, 0, 4096);
            p as u64
        };
        
        self.allocated_pages.push(ptr);
        Ok(ptr)
    }
    
    /// Allocate backing page for guest memory
    fn allocate_backing_page(&mut self) -> Result<u64, HypervisorError> {
        use alloc::alloc::{alloc, Layout};
        
        let ptr = unsafe {
            let p = alloc(Layout::from_size_align(4096, 4096).unwrap());
            if p.is_null() {
                return Err(HypervisorError::InsufficientMemory);
            }
            core::ptr::write_bytes(p, 0, 4096);
            p as u64
        };
        
        Ok(ptr)
    }
    
    /// Invalidate EPT entry in TLB
    fn invalidate_ept_entry(&self, gpa: u64) {
        unsafe {
            // INVEPT instruction
            let descriptor = [1u64, gpa]; // Type 1: Single-context invalidation
            core::arch::asm!(
                "invept {}, [{}]",
                in(reg) 1u64,  // Type: single-context
                in(reg) descriptor.as_ptr(),
                options(nostack)
            );
        }
    }
    
    /// Get EPT pointer for VMCS
    pub fn get_ept_pointer(&self) -> u64 {
        self.pml4_base |
            (3 << 3) |  // 4-level page walk
            (6 << 0)    // Write-back memory type
    }
    
    /// Create identity mapping for low memory
    pub fn create_identity_map(&mut self, size: u64) -> Result<(), HypervisorError> {
        // Map first 'size' bytes as identity (GPA = HPA)
        for gpa in (0..size).step_by(0x200000) { // Use 2MB pages
            let size_to_map = core::cmp::min(0x200000, size - gpa);
            self.map_gpa_to_hpa(gpa, gpa, size_to_map, true, true)?;
        }
        Ok(())
    }
    
    /// Set up MMIO regions for standard devices
    pub fn setup_standard_mmio(&mut self) -> Result<(), HypervisorError> {
        // Local APIC
        self.map_mmio_region(0xFEE00000, 0x100000, MemoryType::Uncacheable)?;
        
        // I/O APIC
        self.map_mmio_region(0xFEC00000, 0x1000, MemoryType::Uncacheable)?;
        
        // HPET
        self.map_mmio_region(0xFED00000, 0x400, MemoryType::Uncacheable)?;
        
        // PCI MMCONFIG
        self.map_mmio_region(0xE0000000, 0x10000000, MemoryType::Uncacheable)?;
        
        Ok(())
    }
    
    /// Walk EPT and dump structure (for debugging)
    pub fn dump_ept_structure(&self, gpa: u64) {
        let pml4_index = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_index = ((gpa >> 30) & 0x1FF) as usize;
        let pd_index = ((gpa >> 21) & 0x1FF) as usize;
        let pt_index = ((gpa >> 12) & 0x1FF) as usize;
        
        log::debug!("EPT walk for GPA {:#x}:", gpa);
        log::debug!("  PML4[{}] -> PDPT[{}] -> PD[{}] -> PT[{}]",
                   pml4_index, pdpt_index, pd_index, pt_index);
        
        let pml4_table = unsafe { &*(self.pml4_base as *const [u64; 512]) };
        if pml4_table[pml4_index] & PageTableFlags::Present as u64 == 0 {
            log::debug!("  PML4 entry not present");
            return;
        }
        
        let pdpt_base = pml4_table[pml4_index] & 0x000FFFFFFFFFF000;
        let pdpt_table = unsafe { &*(pdpt_base as *const [u64; 512]) };
        if pdpt_table[pdpt_index] & PageTableFlags::Present as u64 == 0 {
            log::debug!("  PDPT entry not present");
            return;
        }
        
        if pdpt_table[pdpt_index] & PageTableFlags::LargePage as u64 != 0 {
            log::debug!("  1GB page at HPA {:#x}", pdpt_table[pdpt_index] & 0x000FFFFFFFFFF000);
            return;
        }
        
        let pd_base = pdpt_table[pdpt_index] & 0x000FFFFFFFFFF000;
        let pd_table = unsafe { &*(pd_base as *const [u64; 512]) };
        if pd_table[pd_index] & PageTableFlags::Present as u64 == 0 {
            log::debug!("  PD entry not present");
            return;
        }
        
        if pd_table[pd_index] & PageTableFlags::LargePage as u64 != 0 {
            log::debug!("  2MB page at HPA {:#x}", pd_table[pd_index] & 0x000FFFFFFFFFF000);
            return;
        }
        
        let pt_base = pd_table[pd_index] & 0x000FFFFFFFFFF000;
        let pt_table = unsafe { &*(pt_base as *const [u64; 512]) };
        if pt_table[pt_index] & PageTableFlags::Present as u64 == 0 {
            log::debug!("  PT entry not present");
        } else {
            log::debug!("  4KB page at HPA {:#x}", pt_table[pt_index] & 0x000FFFFFFFFFF000);
        }
    }
}

/// NPT (AMD Nested Page Tables) specific implementation
pub struct NestedPageTableAMD {
    base: NestedPageTable,
    ncr3: u64,  // Nested CR3
    asid: u32,  // Address Space ID
}

impl NestedPageTableAMD {
    pub fn new(max_gpa: u64, asid: u32) -> Result<Self, HypervisorError> {
        let base = NestedPageTable::new(max_gpa)?;
        let ncr3 = base.pml4_base;
        
        Ok(Self {
            base,
            ncr3,
            asid,
        })
    }
    
    /// Get NCR3 value for VMCB
    pub fn get_ncr3(&self) -> u64 {
        self.ncr3
    }
    
    /// Get ASID
    pub fn get_asid(&self) -> u32 {
        self.asid
    }
    
    /// Invalidate NPT entries
    pub fn invalidate_npt(&self) {
        unsafe {
            // Use INVLPGA instruction for AMD
            core::arch::asm!(
                "invlpga [rax], ecx",
                in("rax") 0u64,
                in("ecx") self.asid,
                options(nostack)
            );
        }
    }
}

/// Action to take after EPT violation
#[derive(Debug)]
pub enum EptAction {
    Retry,              // Retry the instruction
    EmulateMMIO,        // Emulate MMIO access
    InjectPageFault,    // Inject #PF into guest
    Shutdown,           // Shutdown VM
}

/// Parse EPT violation exit qualification
pub fn parse_ept_violation(qualification: u64, gpa: u64) -> EptViolationInfo {
    EptViolationInfo {
        read_access: (qualification & 0x1) != 0,
        write_access: (qualification & 0x2) != 0,
        execute_access: (qualification & 0x4) != 0,
        readable: (qualification & 0x8) != 0,
        writable: (qualification & 0x10) != 0,
        executable: (qualification & 0x20) != 0,
        user_mode_executable: (qualification & 0x40) != 0,
        gpa_valid: (qualification & 0x80) != 0,
        caused_by_translation: (qualification & 0x100) != 0,
        user_mode_linear_address: (qualification & 0x200) != 0,
        readable_writable: (qualification & 0x400) != 0,
        executable_user: (qualification & 0x800) != 0,
        verify_guest_paging: (qualification & 0x1000) != 0,
        paging_write: (qualification & 0x2000) != 0,
        shadow_stack: (qualification & 0x4000) != 0,
        supervisor_shadow_stack: (qualification & 0x10000) != 0,
        guest_physical_address: gpa,
    }
}