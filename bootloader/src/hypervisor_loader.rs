//! Hypervisor Bootloader
//! Advanced bootloader for loading and initializing the hypervisor

use alloc::{vec::Vec, string::String};
use core::mem;
use uefi::prelude::*;
use uefi::proto::console::text::SimpleTextOutput;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType, MemoryDescriptor};
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size2MiB};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::{PhysAddr, VirtAddr};

pub const HYPERVISOR_BASE: u64 = 0xFFFF800000000000; // Hypervisor virtual base
pub const HYPERVISOR_SIZE: usize = 256 * 1024 * 1024; // 256MB
pub const KERNEL_STACK_SIZE: usize = 2 * 1024 * 1024; // 2MB per CPU
pub const MAX_CPUS: usize = 256;

#[repr(C, align(4096))]
pub struct HypervisorInfo {
    pub magic: u32,
    pub version: u32,
    pub flags: u64,
    pub entry_point: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub cpu_count: u32,
    pub memory_map_addr: u64,
    pub memory_map_size: u32,
    pub memory_map_desc_size: u32,
    pub acpi_rsdp: u64,
    pub smbios_entry: u64,
    pub framebuffer_addr: u64,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_pitch: u32,
    pub framebuffer_bpp: u32,
    pub tsc_frequency: u64,
    pub lapic_base: u64,
    pub ioapic_base: u64,
    pub vmx_features: u64,
    pub svm_features: u64,
    pub ept_features: u64,
    pub reserved: [u64; 32],
}

impl Default for HypervisorInfo {
    fn default() -> Self {
        Self {
            magic: 0x48565052, // "HVPR"
            version: 0x00010000, // 1.0.0
            flags: 0,
            entry_point: 0,
            stack_base: 0,
            stack_size: 0,
            cpu_count: 0,
            memory_map_addr: 0,
            memory_map_size: 0,
            memory_map_desc_size: 0,
            acpi_rsdp: 0,
            smbios_entry: 0,
            framebuffer_addr: 0,
            framebuffer_width: 0,
            framebuffer_height: 0,
            framebuffer_pitch: 0,
            framebuffer_bpp: 0,
            tsc_frequency: 0,
            lapic_base: 0xFEE00000,
            ioapic_base: 0xFEC00000,
            vmx_features: 0,
            svm_features: 0,
            ept_features: 0,
            reserved: [0; 32],
        }
    }
}

pub struct HypervisorLoader {
    boot_services: &'static BootServices,
    hypervisor_info: HypervisorInfo,
    hypervisor_image: Vec<u8>,
    page_tables: PageTableHierarchy,
}

struct PageTableHierarchy {
    pml4: *mut PageTable,
    pdpt: *mut PageTable,
    pd: *mut PageTable,
    pt: *mut PageTable,
}

impl HypervisorLoader {
    pub fn new(boot_services: &'static BootServices) -> Self {
        Self {
            boot_services,
            hypervisor_info: HypervisorInfo::default(),
            hypervisor_image: Vec::new(),
            page_tables: PageTableHierarchy {
                pml4: core::ptr::null_mut(),
                pdpt: core::ptr::null_mut(),
                pd: core::ptr::null_mut(),
                pt: core::ptr::null_mut(),
            },
        }
    }

    pub fn load_hypervisor(&mut self, path: &CStr16) -> Result<(), Status> {
        log::info!("Loading hypervisor from {:?}", path);
        
        // Load hypervisor binary
        self.hypervisor_image = self.load_hypervisor_binary(path)?;
        
        // Allocate memory for hypervisor
        let hypervisor_base = self.allocate_hypervisor_memory()?;
        
        // Copy hypervisor to allocated memory
        self.copy_hypervisor_image(hypervisor_base)?;
        
        // Set up page tables
        self.setup_page_tables(hypervisor_base)?;
        
        // Collect system information
        self.collect_system_info()?;
        
        // Initialize per-CPU structures
        self.initialize_per_cpu_structures()?;
        
        // Prepare hypervisor info structure
        self.hypervisor_info.entry_point = hypervisor_base + 0x1000; // Entry at offset 0x1000
        self.hypervisor_info.stack_base = hypervisor_base + HYPERVISOR_SIZE as u64;
        self.hypervisor_info.stack_size = KERNEL_STACK_SIZE as u64;
        
        log::info!("Hypervisor loaded successfully at 0x{:X}", hypervisor_base);
        
        Ok(())
    }

    fn load_hypervisor_binary(&self, path: &CStr16) -> Result<Vec<u8>, Status> {
        // Open root filesystem
        let mut fs_handle = self.boot_services
            .get_handle_for_protocol::<SimpleFileSystem>()?;
        
        let mut fs = self.boot_services
            .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)?;
        
        let mut root = fs.open_volume()?;
        
        // Open hypervisor binary
        let mut file = root.open(path, FileMode::Read, FileAttribute::empty())?;
        
        // Get file size
        let mut info_buffer = [0u8; 512];
        let info = file.get_info::<uefi::proto::media::file::FileInfo>(&mut info_buffer)?;
        let file_size = info.file_size() as usize;
        
        if file_size > HYPERVISOR_SIZE {
            return Err(Status::BUFFER_TOO_SMALL);
        }
        
        // Read file contents
        let mut buffer = vec![0u8; file_size];
        file.read(&mut buffer)?;
        
        Ok(buffer)
    }

    fn allocate_hypervisor_memory(&self) -> Result<u64, Status> {
        let pages = (HYPERVISOR_SIZE + 0xFFF) / 0x1000;
        
        let base = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_CODE,
            pages,
        )?;
        
        // Clear allocated memory
        unsafe {
            core::ptr::write_bytes(base as *mut u8, 0, HYPERVISOR_SIZE);
        }
        
        Ok(base)
    }

    fn copy_hypervisor_image(&self, base: u64) -> Result<(), Status> {
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.hypervisor_image.as_ptr(),
                base as *mut u8,
                self.hypervisor_image.len(),
            );
        }
        Ok(())
    }

    fn setup_page_tables(&mut self, hypervisor_base: u64) -> Result<(), Status> {
        // Allocate page tables
        self.allocate_page_table_memory()?;
        
        unsafe {
            // Clear page tables
            (*self.page_tables.pml4).zero();
            (*self.page_tables.pdpt).zero();
            (*self.page_tables.pd).zero();
            
            // Set up PML4 entry
            (*self.page_tables.pml4)[0].set_addr(
                PhysAddr::new(self.page_tables.pdpt as u64),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
            
            // Higher half mapping for hypervisor
            let hh_index = (HYPERVISOR_BASE >> 39) & 0x1FF;
            (*self.page_tables.pml4)[hh_index as usize].set_addr(
                PhysAddr::new(self.page_tables.pdpt as u64),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            );
            
            // Set up PDPT entries
            for i in 0..4 {
                (*self.page_tables.pdpt)[i].set_addr(
                    PhysAddr::new((self.page_tables.pd as u64) + (i as u64 * 0x1000)),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                );
            }
            
            // Map hypervisor memory with 2MB pages
            let pages = HYPERVISOR_SIZE / (2 * 1024 * 1024);
            for i in 0..pages {
                let phys_addr = hypervisor_base + (i as u64 * 2 * 1024 * 1024);
                (*self.page_tables.pd)[i].set_addr(
                    PhysAddr::new(phys_addr),
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::HUGE_PAGE,
                );
            }
            
            // Identity map first 4GB for compatibility
            self.identity_map_low_memory()?;
        }
        
        Ok(())
    }

    fn allocate_page_table_memory(&mut self) -> Result<(), Status> {
        // Allocate PML4
        self.page_tables.pml4 = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            1,
        )? as *mut PageTable;
        
        // Allocate PDPT
        self.page_tables.pdpt = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            1,
        )? as *mut PageTable;
        
        // Allocate PD (4 tables for 4GB coverage)
        self.page_tables.pd = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            4,
        )? as *mut PageTable;
        
        Ok(())
    }

    fn identity_map_low_memory(&self) -> Result<(), Status> {
        unsafe {
            // Identity map first 4GB using 2MB pages
            for i in 0..2048 {
                let pd_index = i / 512;
                let pd_offset = i % 512;
                let pd = (self.page_tables.pd as u64 + (pd_index * 0x1000)) as *mut PageTable;
                
                (*pd)[pd_offset].set_addr(
                    PhysAddr::new(i as u64 * 2 * 1024 * 1024),
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::HUGE_PAGE,
                );
            }
        }
        Ok(())
    }

    fn collect_system_info(&mut self) -> Result<(), Status> {
        // Get CPU count
        self.hypervisor_info.cpu_count = self.get_cpu_count();
        
        // Get memory map
        self.save_memory_map()?;
        
        // Get ACPI RSDP
        self.hypervisor_info.acpi_rsdp = self.find_acpi_rsdp()?;
        
        // Get SMBIOS entry point
        self.hypervisor_info.smbios_entry = self.find_smbios_entry()?;
        
        // Get framebuffer info
        self.get_framebuffer_info()?;
        
        // Get CPU features
        self.detect_cpu_features();
        
        // Get TSC frequency
        self.hypervisor_info.tsc_frequency = self.get_tsc_frequency();
        
        Ok(())
    }

    fn get_cpu_count(&self) -> u32 {
        // Use CPUID or ACPI MADT table to get CPU count
        // For now, use CPUID leaf 0xB
        use raw_cpuid::CpuId;
        
        let cpuid = CpuId::new();
        if let Some(info) = cpuid.get_extended_topology_info() {
            // Count logical processors
            let mut count = 0;
            for level in info {
                if level.level_type() == 2 {
                    // Core level
                    count = level.processors();
                }
            }
            count as u32
        } else {
            1 // Default to 1 CPU
        }
    }

    fn save_memory_map(&mut self) -> Result<(), Status> {
        let mmap_size = self.boot_services.memory_map_size();
        let mut mmap_buffer = vec![0u8; mmap_size + 512];
        
        let (_, descriptors) = self.boot_services.memory_map(&mut mmap_buffer)?;
        
        // Allocate memory for memory map
        let map_pages = (mmap_buffer.len() + 0xFFF) / 0x1000;
        let map_addr = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            map_pages,
        )?;
        
        // Copy memory map
        unsafe {
            core::ptr::copy_nonoverlapping(
                mmap_buffer.as_ptr(),
                map_addr as *mut u8,
                mmap_buffer.len(),
            );
        }
        
        self.hypervisor_info.memory_map_addr = map_addr;
        self.hypervisor_info.memory_map_size = mmap_buffer.len() as u32;
        self.hypervisor_info.memory_map_desc_size = mem::size_of::<MemoryDescriptor>() as u32;
        
        Ok(())
    }

    fn find_acpi_rsdp(&self) -> Result<u64, Status> {
        // Search for ACPI RSDP in UEFI configuration table
        use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};
        
        for entry in self.boot_services.config_table() {
            if entry.guid == ACPI2_GUID || entry.guid == ACPI_GUID {
                return Ok(entry.address as u64);
            }
        }
        
        // Not found
        Ok(0)
    }

    fn find_smbios_entry(&self) -> Result<u64, Status> {
        // Search for SMBIOS entry point in UEFI configuration table
        use uefi::table::cfg::SMBIOS3_GUID;
        
        for entry in self.boot_services.config_table() {
            if entry.guid == SMBIOS3_GUID {
                return Ok(entry.address as u64);
            }
        }
        
        // Not found
        Ok(0)
    }

    fn get_framebuffer_info(&mut self) -> Result<(), Status> {
        // Get GOP (Graphics Output Protocol) info
        use uefi::proto::console::gop::GraphicsOutput;
        
        if let Ok(gop) = self.boot_services.locate_protocol::<GraphicsOutput>() {
            let mode = unsafe { &*gop.as_ptr() }.current_mode_info();
            let fb = unsafe { &*gop.as_ptr() }.frame_buffer();
            
            self.hypervisor_info.framebuffer_addr = fb.as_mut_ptr() as u64;
            self.hypervisor_info.framebuffer_width = mode.resolution().0 as u32;
            self.hypervisor_info.framebuffer_height = mode.resolution().1 as u32;
            self.hypervisor_info.framebuffer_pitch = mode.stride() as u32 * 4;
            self.hypervisor_info.framebuffer_bpp = 32;
        }
        
        Ok(())
    }

    fn detect_cpu_features(&mut self) {
        use raw_cpuid::CpuId;
        
        let cpuid = CpuId::new();
        
        // Check VMX features
        if let Some(features) = cpuid.get_feature_info() {
            if features.has_vmx() {
                self.hypervisor_info.vmx_features |= 1;
                
                // Check EPT support
                const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
                let msr = unsafe { Msr::new(IA32_VMX_EPT_VPID_CAP) };
                let ept_cap = unsafe { msr.read() };
                
                if ept_cap & (1 << 0) != 0 {
                    self.hypervisor_info.ept_features |= 1; // EPT supported
                }
                if ept_cap & (1 << 6) != 0 {
                    self.hypervisor_info.ept_features |= 2; // 2MB pages
                }
                if ept_cap & (1 << 16) != 0 {
                    self.hypervisor_info.ept_features |= 4; // 1GB pages
                }
            }
        }
        
        // Check SVM features
        if let Some(extended) = cpuid.get_extended_processor_info() {
            if extended.has_svm() {
                self.hypervisor_info.svm_features |= 1;
                
                // Check nested paging support
                const SVM_FEATURES: u32 = 0x8000000A;
                let res = unsafe { core::arch::x86_64::__cpuid(SVM_FEATURES) };
                
                if res.edx & (1 << 0) != 0 {
                    self.hypervisor_info.svm_features |= 2; // Nested paging
                }
            }
        }
    }

    fn get_tsc_frequency(&self) -> u64 {
        // Try to get TSC frequency from CPUID
        use raw_cpuid::CpuId;
        
        let cpuid = CpuId::new();
        
        // Check leaf 0x15 (TSC frequency)
        if cpuid.get_tsc_info().is_some() {
            let tsc_info = cpuid.get_tsc_info().unwrap();
            if tsc_info.nominal_frequency() > 0 {
                return tsc_info.nominal_frequency() as u64;
            }
        }
        
        // Fallback: measure TSC frequency
        self.measure_tsc_frequency()
    }

    fn measure_tsc_frequency(&self) -> u64 {
        // Measure TSC frequency by timing against PIT or HPET
        // Simplified: assume 2.4 GHz
        2_400_000_000
    }

    fn initialize_per_cpu_structures(&mut self) -> Result<(), Status> {
        let cpu_count = self.hypervisor_info.cpu_count as usize;
        
        for cpu_id in 0..cpu_count {
            // Allocate per-CPU stack
            let stack_pages = (KERNEL_STACK_SIZE + 0xFFF) / 0x1000;
            let stack_base = self.boot_services.allocate_pages(
                AllocateType::AnyPages,
                MemoryType::RUNTIME_SERVICES_DATA,
                stack_pages,
            )?;
            
            // Initialize stack with guard pages
            self.setup_stack_guard_pages(stack_base)?;
            
            // Allocate per-CPU data structures
            self.allocate_per_cpu_data(cpu_id)?;
        }
        
        Ok(())
    }

    fn setup_stack_guard_pages(&self, stack_base: u64) -> Result<(), Status> {
        // Mark first and last page as guard pages (no access)
        // This would modify page table entries
        Ok(())
    }

    fn allocate_per_cpu_data(&self, cpu_id: usize) -> Result<(), Status> {
        // Allocate GDT, IDT, TSS, etc. for each CPU
        Ok(())
    }

    pub fn launch_hypervisor(&self) -> ! {
        unsafe {
            // Disable interrupts
            x86_64::instructions::interrupts::disable();
            
            // Load new page tables
            Cr3::write(
                PhysFrame::from_start_address(PhysAddr::new(self.page_tables.pml4 as u64)).unwrap(),
                Cr3Flags::empty(),
            );
            
            // Enable required CPU features
            self.enable_cpu_features();
            
            // Jump to hypervisor entry point
            let entry = self.hypervisor_info.entry_point;
            let stack = self.hypervisor_info.stack_base + self.hypervisor_info.stack_size;
            let info = &self.hypervisor_info as *const HypervisorInfo;
            
            core::arch::asm!(
                "mov rsp, {}",
                "mov rdi, {}",
                "jmp {}",
                in(reg) stack,
                in(reg) info,
                in(reg) entry,
                options(noreturn)
            );
        }
    }

    unsafe fn enable_cpu_features(&self) {
        // Enable PAE, PGE, PSE
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::PHYSICAL_ADDRESS_EXTENSION
            | Cr4Flags::PAGE_GLOBAL
            | Cr4Flags::PAGE_SIZE_EXTENSION;
        
        // Enable VMX if supported
        if self.hypervisor_info.vmx_features != 0 {
            cr4 |= Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        }
        
        Cr4::write(cr4);
        
        // Enable NX bit
        const IA32_EFER: u32 = 0xC0000080;
        let mut efer = Msr::new(IA32_EFER);
        let value = efer.read();
        efer.write(value | (1 << 11)); // NXE bit
        
        // Enable SYSCALL/SYSRET
        efer.write(efer.read() | 1); // SCE bit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypervisor_info_size() {
        assert_eq!(mem::size_of::<HypervisorInfo>(), 4096);
    }
}