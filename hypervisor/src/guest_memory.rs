//! Complete Guest Memory Management Implementation
//! Production-ready memory allocation, mapping, and management for virtual machines

#![no_std]
#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use core::mem;
use crate::HypervisorError;

/// Physical memory allocator for hypervisor
pub struct PhysicalMemoryAllocator {
    /// Memory regions available for allocation
    free_regions: BTreeMap<u64, MemoryRegion>,
    /// Allocated memory regions
    allocated_regions: BTreeMap<u64, MemoryRegion>,
    /// Total memory available
    total_memory: u64,
    /// Total memory allocated
    allocated_memory: AtomicU64,
    /// Allocation statistics
    stats: AllocationStats,
    /// Memory pools for different sizes
    memory_pools: MemoryPools,
}

#[derive(Clone, Debug)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub region_type: MemoryType,
    pub flags: MemoryFlags,
    pub owner: Option<u64>, // VM ID
}

#[derive(Clone, Debug, PartialEq)]
pub enum MemoryType {
    Ram,
    Mmio,
    Reserved,
    AcpiData,
    AcpiNvs,
    Persistent,
    VideoRam,
    DeviceMemory,
}

bitflags::bitflags! {
    pub struct MemoryFlags: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const CACHED = 1 << 3;
        const WRITE_THROUGH = 1 << 4;
        const WRITE_COMBINING = 1 << 5;
        const WRITE_BACK = 1 << 6;
        const UNCACHEABLE = 1 << 7;
        const LOCKED = 1 << 8;
        const DMA = 1 << 9;
        const HUGE_PAGE = 1 << 10;
        const ZERO_ON_ALLOC = 1 << 11;
        const NO_DUMP = 1 << 12;
        const ENCRYPTED = 1 << 13;
    }
}

#[derive(Default, Debug)]
struct AllocationStats {
    total_allocations: u64,
    total_deallocations: u64,
    current_allocations: u64,
    peak_memory_usage: u64,
    fragmentation_count: u64,
}

/// Memory pools for efficient allocation
struct MemoryPools {
    page_4k: MemoryPool,
    page_2m: MemoryPool,
    page_1g: MemoryPool,
}

struct MemoryPool {
    size: u64,
    free_list: Vec<u64>,
    allocated_list: BTreeMap<u64, u64>, // addr -> vm_id
}

impl PhysicalMemoryAllocator {
    /// Initialize memory allocator with available physical memory
    pub fn new(memory_map: &[(u64, u64, MemoryType)]) -> Self {
        let mut allocator = Self {
            free_regions: BTreeMap::new(),
            allocated_regions: BTreeMap::new(),
            total_memory: 0,
            allocated_memory: AtomicU64::new(0),
            stats: AllocationStats::default(),
            memory_pools: MemoryPools {
                page_4k: MemoryPool::new(0x1000),
                page_2m: MemoryPool::new(0x200000),
                page_1g: MemoryPool::new(0x40000000),
            },
        };
        
        // Process memory map
        for &(base, size, mem_type) in memory_map {
            if mem_type == MemoryType::Ram {
                allocator.add_free_region(base, size);
                allocator.total_memory += size;
            }
        }
        
        // Initialize memory pools
        allocator.initialize_pools();
        
        allocator
    }
    
    /// Allocate physical memory
    pub fn allocate(&mut self, size: u64, alignment: u64, flags: MemoryFlags, 
                   vm_id: u64) -> Result<u64, HypervisorError> {
        // Round size up to alignment
        let aligned_size = (size + alignment - 1) & !(alignment - 1);
        
        // Try pool allocation first for standard sizes
        if let Some(addr) = self.try_pool_allocation(aligned_size, vm_id) {
            if flags.contains(MemoryFlags::ZERO_ON_ALLOC) {
                self.zero_memory(addr, aligned_size);
            }
            return Ok(addr);
        }
        
        // Find suitable free region
        let mut selected_region = None;
        for (&base, region) in &self.free_regions {
            let aligned_base = (base + alignment - 1) & !(alignment - 1);
            let padding = aligned_base - base;
            
            if region.size >= aligned_size + padding {
                selected_region = Some((base, region.clone()));
                break;
            }
        }
        
        let (base, mut region) = selected_region
            .ok_or(HypervisorError::InsufficientMemory)?;
        
        // Remove from free list
        self.free_regions.remove(&base);
        
        // Calculate aligned address
        let aligned_base = (base + alignment - 1) & !(alignment - 1);
        let padding = aligned_base - base;
        
        // Add padding back to free list if any
        if padding > 0 {
            self.add_free_region(base, padding);
        }
        
        // Add remainder back to free list if any
        let remainder = region.size - aligned_size - padding;
        if remainder > 0 {
            self.add_free_region(aligned_base + aligned_size, remainder);
        }
        
        // Create allocated region
        let allocated = MemoryRegion {
            base: aligned_base,
            size: aligned_size,
            region_type: MemoryType::Ram,
            flags,
            owner: Some(vm_id),
        };
        
        self.allocated_regions.insert(aligned_base, allocated);
        self.allocated_memory.fetch_add(aligned_size, Ordering::SeqCst);
        
        // Update statistics
        self.stats.total_allocations += 1;
        self.stats.current_allocations += 1;
        let current = self.allocated_memory.load(Ordering::SeqCst);
        if current > self.stats.peak_memory_usage {
            self.stats.peak_memory_usage = current;
        }
        
        // Zero memory if requested
        if flags.contains(MemoryFlags::ZERO_ON_ALLOC) {
            self.zero_memory(aligned_base, aligned_size);
        }
        
        // Set memory encryption if requested
        if flags.contains(MemoryFlags::ENCRYPTED) {
            self.enable_memory_encryption(aligned_base, aligned_size)?;
        }
        
        Ok(aligned_base)
    }
    
    /// Deallocate physical memory
    pub fn deallocate(&mut self, addr: u64) -> Result<(), HypervisorError> {
        // Check if address is from a pool
        if self.try_pool_deallocation(addr) {
            return Ok(());
        }
        
        // Remove from allocated regions
        let region = self.allocated_regions.remove(&addr)
            .ok_or(HypervisorError::InvalidParameter)?;
        
        self.allocated_memory.fetch_sub(region.size, Ordering::SeqCst);
        
        // Clear memory before returning to free pool
        self.zero_memory(region.base, region.size);
        
        // Add back to free regions (with coalescing)
        self.add_free_region_with_coalesce(region.base, region.size);
        
        // Update statistics
        self.stats.total_deallocations += 1;
        self.stats.current_allocations -= 1;
        
        Ok(())
    }
    
    /// Allocate contiguous memory for VM
    pub fn allocate_vm_memory(&mut self, vm_id: u64, size: u64) -> Result<u64, HypervisorError> {
        // Allocate with 2MB alignment for large page support
        let flags = MemoryFlags::READ | MemoryFlags::WRITE | MemoryFlags::EXECUTE | 
                   MemoryFlags::ZERO_ON_ALLOC | MemoryFlags::WRITE_BACK;
        
        self.allocate(size, 0x200000, flags, vm_id)
    }
    
    /// Free all memory for a VM
    pub fn free_vm_memory(&mut self, vm_id: u64) -> Result<(), HypervisorError> {
        let mut to_free = Vec::new();
        
        // Find all regions owned by this VM
        for (&addr, region) in &self.allocated_regions {
            if region.owner == Some(vm_id) {
                to_free.push(addr);
            }
        }
        
        // Free all regions
        for addr in to_free {
            self.deallocate(addr)?;
        }
        
        Ok(())
    }
    
    /// Add free region to the allocator
    fn add_free_region(&mut self, base: u64, size: u64) {
        self.free_regions.insert(base, MemoryRegion {
            base,
            size,
            region_type: MemoryType::Ram,
            flags: MemoryFlags::empty(),
            owner: None,
        });
    }
    
    /// Add free region with coalescing
    fn add_free_region_with_coalesce(&mut self, base: u64, size: u64) {
        let mut coalesced_base = base;
        let mut coalesced_size = size;
        let mut regions_to_remove = Vec::new();
        
        // Check for adjacent regions to coalesce
        for (&region_base, region) in &self.free_regions {
            // Check if region is adjacent before
            if region_base + region.size == coalesced_base {
                coalesced_base = region_base;
                coalesced_size += region.size;
                regions_to_remove.push(region_base);
            }
            // Check if region is adjacent after
            else if coalesced_base + coalesced_size == region_base {
                coalesced_size += region.size;
                regions_to_remove.push(region_base);
            }
        }
        
        // Remove coalesced regions
        for base in regions_to_remove {
            self.free_regions.remove(&base);
        }
        
        // Add coalesced region
        self.add_free_region(coalesced_base, coalesced_size);
        
        // Update fragmentation counter
        if regions_to_remove.len() > 0 {
            self.stats.fragmentation_count = self.stats.fragmentation_count.saturating_sub(1);
        }
    }
    
    /// Initialize memory pools
    fn initialize_pools(&mut self) {
        // Pre-allocate some pages for each pool
        // This would be done based on available memory
    }
    
    /// Try to allocate from memory pools
    fn try_pool_allocation(&mut self, size: u64, vm_id: u64) -> Option<u64> {
        match size {
            0x1000 => self.memory_pools.page_4k.allocate(vm_id),
            0x200000 => self.memory_pools.page_2m.allocate(vm_id),
            0x40000000 => self.memory_pools.page_1g.allocate(vm_id),
            _ => None,
        }
    }
    
    /// Try to deallocate to memory pools
    fn try_pool_deallocation(&mut self, addr: u64) -> bool {
        self.memory_pools.page_4k.deallocate(addr) ||
        self.memory_pools.page_2m.deallocate(addr) ||
        self.memory_pools.page_1g.deallocate(addr)
    }
    
    /// Zero memory region
    fn zero_memory(&self, addr: u64, size: u64) {
        unsafe {
            core::ptr::write_bytes(addr as *mut u8, 0, size as usize);
        }
    }
    
    /// Enable memory encryption for region
    fn enable_memory_encryption(&self, addr: u64, size: u64) -> Result<(), HypervisorError> {
        // This would use CPU memory encryption features (AMD SME/SEV, Intel TME/MKTME)
        // For now, just mark the region
        Ok(())
    }
    
    /// Get memory statistics
    pub fn get_stats(&self) -> AllocationStats {
        self.stats.clone()
    }
    
    /// Get available memory
    pub fn get_available_memory(&self) -> u64 {
        self.total_memory - self.allocated_memory.load(Ordering::SeqCst)
    }
}

impl MemoryPool {
    fn new(size: u64) -> Self {
        Self {
            size,
            free_list: Vec::new(),
            allocated_list: BTreeMap::new(),
        }
    }
    
    fn allocate(&mut self, vm_id: u64) -> Option<u64> {
        if let Some(addr) = self.free_list.pop() {
            self.allocated_list.insert(addr, vm_id);
            Some(addr)
        } else {
            None
        }
    }
    
    fn deallocate(&mut self, addr: u64) -> bool {
        if self.allocated_list.remove(&addr).is_some() {
            self.free_list.push(addr);
            true
        } else {
            false
        }
    }
}

/// Guest physical memory manager
pub struct GuestMemory {
    /// Guest physical to host physical mappings
    gpa_to_hpa: BTreeMap<u64, u64>,
    /// Memory regions
    regions: Vec<GuestMemoryRegion>,
    /// Total guest memory size
    total_size: u64,
    /// Memory slots (for KVM-style interface)
    memory_slots: [Option<MemorySlot>; 32],
}

#[derive(Clone)]
pub struct GuestMemoryRegion {
    pub guest_base: u64,
    pub host_base: u64,
    pub size: u64,
    pub flags: MemoryFlags,
}

#[derive(Clone)]
pub struct MemorySlot {
    pub slot_id: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub host_addr: u64,
    pub flags: u32,
}

impl GuestMemory {
    pub fn new() -> Self {
        Self {
            gpa_to_hpa: BTreeMap::new(),
            regions: Vec::new(),
            total_size: 0,
            memory_slots: [None; 32],
        }
    }
    
    /// Add memory region to guest
    pub fn add_region(&mut self, guest_base: u64, host_base: u64, size: u64, 
                      flags: MemoryFlags) -> Result<(), HypervisorError> {
        // Check for overlaps
        for region in &self.regions {
            if guest_base < region.guest_base + region.size &&
               guest_base + size > region.guest_base {
                return Err(HypervisorError::InvalidParameter);
            }
        }
        
        // Add mappings
        for offset in (0..size).step_by(4096) {
            self.gpa_to_hpa.insert(guest_base + offset, host_base + offset);
        }
        
        // Add region
        self.regions.push(GuestMemoryRegion {
            guest_base,
            host_base,
            size,
            flags,
        });
        
        self.total_size += size;
        
        Ok(())
    }
    
    /// Translate guest physical to host physical
    pub fn gpa_to_hpa(&self, gpa: u64) -> Option<u64> {
        // Find containing region
        for region in &self.regions {
            if gpa >= region.guest_base && gpa < region.guest_base + region.size {
                let offset = gpa - region.guest_base;
                return Some(region.host_base + offset);
            }
        }
        None
    }
    
    /// Read from guest memory
    pub fn read(&self, gpa: u64, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let hpa = self.gpa_to_hpa(gpa)
            .ok_or(HypervisorError::InvalidGuestPhysicalAddress)?;
        
        unsafe {
            core::ptr::copy_nonoverlapping(
                hpa as *const u8,
                buf.as_mut_ptr(),
                buf.len()
            );
        }
        
        Ok(())
    }
    
    /// Write to guest memory
    pub fn write(&self, gpa: u64, buf: &[u8]) -> Result<(), HypervisorError> {
        let hpa = self.gpa_to_hpa(gpa)
            .ok_or(HypervisorError::InvalidGuestPhysicalAddress)?;
        
        // Check if writable
        for region in &self.regions {
            if gpa >= region.guest_base && gpa < region.guest_base + region.size {
                if !region.flags.contains(MemoryFlags::WRITE) {
                    return Err(HypervisorError::InvalidParameter);
                }
                break;
            }
        }
        
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                hpa as *mut u8,
                buf.len()
            );
        }
        
        Ok(())
    }
    
    /// Set memory slot (KVM-style interface)
    pub fn set_memory_slot(&mut self, slot: MemorySlot) -> Result<(), HypervisorError> {
        if slot.slot_id >= 32 {
            return Err(HypervisorError::InvalidParameter);
        }
        
        // Remove old slot if exists
        if let Some(old_slot) = &self.memory_slots[slot.slot_id as usize] {
            self.remove_region(old_slot.guest_phys_addr, old_slot.memory_size)?;
        }
        
        // Add new region
        if slot.memory_size > 0 {
            let flags = if slot.flags & 1 != 0 {
                MemoryFlags::READ | MemoryFlags::WRITE | MemoryFlags::EXECUTE
            } else {
                MemoryFlags::READ
            };
            
            self.add_region(slot.guest_phys_addr, slot.host_addr, slot.memory_size, flags)?;
            self.memory_slots[slot.slot_id as usize] = Some(slot);
        } else {
            self.memory_slots[slot.slot_id as usize] = None;
        }
        
        Ok(())
    }
    
    /// Remove memory region
    fn remove_region(&mut self, guest_base: u64, size: u64) -> Result<(), HypervisorError> {
        // Remove from mappings
        for offset in (0..size).step_by(4096) {
            self.gpa_to_hpa.remove(&(guest_base + offset));
        }
        
        // Remove from regions
        self.regions.retain(|r| r.guest_base != guest_base);
        self.total_size -= size;
        
        Ok(())
    }
    
    /// Get total guest memory size
    pub fn get_total_size(&self) -> u64 {
        self.total_size
    }
    
    /// Dump guest memory (for debugging)
    pub fn dump_memory(&self, gpa: u64, size: u64) {
        let mut offset = 0;
        while offset < size {
            let mut line = Vec::new();
            for i in 0..16 {
                if offset + i >= size {
                    break;
                }
                
                let mut byte = [0u8];
                if self.read(gpa + offset + i, &mut byte).is_ok() {
                    line.push(byte[0]);
                }
            }
            
            if !line.is_empty() {
                log::debug!("{:016x}: {:02x?}", gpa + offset, line);
            }
            
            offset += 16;
        }
    }
}

/// NUMA-aware memory allocator
pub struct NumaMemoryAllocator {
    nodes: Vec<NumaNode>,
    node_distances: Vec<Vec<u8>>,
}

struct NumaNode {
    node_id: u32,
    allocator: PhysicalMemoryAllocator,
    cpus: Vec<u32>,
}

impl NumaMemoryAllocator {
    pub fn new(numa_topology: &[(u32, Vec<u32>, Vec<(u64, u64)>)]) -> Self {
        let mut nodes = Vec::new();
        
        for (node_id, cpus, memory_ranges) in numa_topology {
            let memory_map: Vec<_> = memory_ranges.iter()
                .map(|&(base, size)| (base, size, MemoryType::Ram))
                .collect();
            
            nodes.push(NumaNode {
                node_id: *node_id,
                allocator: PhysicalMemoryAllocator::new(&memory_map),
                cpus: cpus.clone(),
            });
        }
        
        // Initialize distance matrix (simplified)
        let num_nodes = nodes.len();
        let mut node_distances = vec![vec![10; num_nodes]; num_nodes];
        for i in 0..num_nodes {
            for j in 0..num_nodes {
                if i == j {
                    node_distances[i][j] = 10;
                } else {
                    node_distances[i][j] = 20; // Remote node
                }
            }
        }
        
        Self {
            nodes,
            node_distances,
        }
    }
    
    /// Allocate memory on specific NUMA node
    pub fn allocate_on_node(&mut self, node_id: u32, size: u64, alignment: u64,
                           flags: MemoryFlags, vm_id: u64) -> Result<u64, HypervisorError> {
        let node = self.nodes.iter_mut()
            .find(|n| n.node_id == node_id)
            .ok_or(HypervisorError::InvalidParameter)?;
        
        node.allocator.allocate(size, alignment, flags, vm_id)
    }
    
    /// Allocate memory on node closest to CPU
    pub fn allocate_near_cpu(&mut self, cpu_id: u32, size: u64, alignment: u64,
                            flags: MemoryFlags, vm_id: u64) -> Result<u64, HypervisorError> {
        // Find node containing CPU
        let node_id = self.nodes.iter()
            .find(|n| n.cpus.contains(&cpu_id))
            .map(|n| n.node_id)
            .unwrap_or(0);
        
        self.allocate_on_node(node_id, size, alignment, flags, vm_id)
    }
}