#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use core::mem;
use log::info;
use uefi::prelude::*;
use uefi::proto::console::text::{Color, SimpleTextOutput};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::runtime::ResetType;
use x86_64::instructions::interrupts;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
use x86_64::structures::paging::{PageTable, PageTableFlags};

// Entry point for UEFI application
#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize UEFI services
    uefi_services::init(&mut system_table).unwrap();
    
    // Clear screen and set colors
    let stdout = system_table.stdout();
    stdout.clear().unwrap();
    stdout.set_color(Color::Yellow, Color::Black).unwrap();
    
    info!("Hypervisor-Rust UEFI Bootloader v0.1.0");
    info!("Initializing Type-1 Bare Metal Hypervisor...");
    
    // Check CPU features
    if !check_virtualization_support() {
        error!("CPU does not support virtualization!");
        return Status::UNSUPPORTED;
    }
    
    // Get memory map
    let mmap_size = system_table.boot_services().memory_map_size();
    let mut mmap_buffer = vec![0u8; mmap_size + 512];
    let (_key, mmap) = system_table
        .boot_services()
        .memory_map(&mut mmap_buffer)
        .unwrap();
    
    info!("Memory map obtained, {} entries", mmap.len());
    
    // Allocate memory for hypervisor
    let hypervisor_size = 16 * 1024 * 1024; // 16MB for hypervisor
    let hypervisor_pages = hypervisor_size / 4096;
    
    let hypervisor_base = system_table
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            hypervisor_pages,
        )
        .unwrap();
    
    info!("Allocated {} MB at {:#x} for hypervisor", 
          hypervisor_size / (1024 * 1024), hypervisor_base);
    
    // Load hypervisor binary
    load_hypervisor(image_handle, &system_table, hypervisor_base)?;
    
    // Set up initial page tables
    setup_page_tables(hypervisor_base)?;
    
    // Enable virtualization extensions
    enable_vmx_or_svm()?;
    
    // Exit boot services and jump to hypervisor
    info!("Exiting UEFI boot services...");
    
    let (_runtime, _mmap) = system_table
        .exit_boot_services(image_handle, &mut mmap_buffer)
        .unwrap();
    
    // Jump to hypervisor entry point
    unsafe {
        jump_to_hypervisor(hypervisor_base);
    }
    
    Status::SUCCESS
}

// Check if CPU supports Intel VT-x or AMD-V
fn check_virtualization_support() -> bool {
    use raw_cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // Check for Intel VT-x
    if let Some(features) = cpuid.get_feature_info() {
        if features.has_vmx() {
            info!("Intel VT-x supported");
            return true;
        }
    }
    
    // Check for AMD-V (SVM)
    if let Some(extended) = cpuid.get_extended_feature_info() {
        if extended.has_svm() {
            info!("AMD-V (SVM) supported");
            return true;
        }
    }
    
    false
}

// Load hypervisor binary from disk
fn load_hypervisor(
    image: Handle,
    st: &SystemTable<Boot>,
    base_address: u64,
) -> Result<(), Status> {
    // Open root filesystem
    let mut fs_handle = st.boot_services()
        .get_handle_for_protocol::<SimpleFileSystem>()?;
    
    let mut fs = st.boot_services()
        .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)?;
    
    let mut root = fs.open_volume()?;
    
    // Open hypervisor binary
    let mut hypervisor_file = root.open(
        cstr16!("\\EFI\\hypervisor\\hypervisor.bin"),
        FileMode::Read,
        FileAttribute::empty(),
    )?;
    
    // Get file size
    let file_info = hypervisor_file.get_info::<FileInfo>(&mut [0u8; 512])?;
    let file_size = file_info.file_size();
    
    // Read hypervisor into memory
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(base_address as *mut u8, file_size as usize)
    };
    
    hypervisor_file.read(buffer)?;
    
    info!("Loaded hypervisor binary ({} bytes)", file_size);
    
    Ok(())
}

// Set up 4-level page tables for long mode
fn setup_page_tables(base: u64) -> Result<(), Status> {
    unsafe {
        // Create PML4 table
        let pml4 = (base + 0x1000) as *mut PageTable;
        (*pml4).zero();
        
        // Create PDPT
        let pdpt = (base + 0x2000) as *mut PageTable;
        (*pdpt).zero();
        
        // Create PD
        let pd = (base + 0x3000) as *mut PageTable;
        (*pd).zero();
        
        // Create PT
        let pt = (base + 0x4000) as *mut PageTable;
        (*pt).zero();
        
        // Set up identity mapping for first 2MB
        (*pml4)[0].set_addr(
            x86_64::PhysAddr::new(pdpt as u64),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        
        (*pdpt)[0].set_addr(
            x86_64::PhysAddr::new(pd as u64),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        
        (*pd)[0].set_addr(
            x86_64::PhysAddr::new(pt as u64),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        
        // Identity map first 2MB
        for i in 0..512 {
            (*pt)[i].set_addr(
                x86_64::PhysAddr::new(i as u64 * 0x1000),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }
        
        // Load CR3 with PML4 address
        x86_64::registers::control::Cr3::write(
            x86_64::PhysFrame::from_start_address(x86_64::PhysAddr::new(pml4 as u64)).unwrap(),
            x86_64::registers::control::Cr3Flags::empty(),
        );
    }
    
    info!("Page tables configured");
    Ok(())
}

// Enable Intel VT-x or AMD-V
fn enable_vmx_or_svm() -> Result<(), Status> {
    use x86_64::registers::model_specific::Msr;
    
    // Check which virtualization extension is available
    let cpuid = raw_cpuid::CpuId::new();
    
    if let Some(features) = cpuid.get_feature_info() {
        if features.has_vmx() {
            // Enable Intel VT-x
            unsafe {
                // Set CR4.VMXE
                let mut cr4 = Cr4::read();
                cr4.insert(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
                Cr4::write(cr4);
                
                // Enable VMX in IA32_FEATURE_CONTROL MSR
                const IA32_FEATURE_CONTROL: u32 = 0x3A;
                let mut msr = Msr::new(IA32_FEATURE_CONTROL);
                let value = msr.read();
                
                if value & 1 == 0 {
                    // MSR not locked, enable VMX
                    msr.write(value | 0x5); // Lock bit + VMX enable
                }
                
                info!("Intel VT-x enabled");
            }
        } else if features.has_svm() {
            // Enable AMD-V
            unsafe {
                const MSR_VM_CR: u32 = 0xC0010114;
                const MSR_EFER: u32 = 0xC0000080;
                
                // Enable SVM in EFER
                let mut efer = Msr::new(MSR_EFER);
                let value = efer.read();
                efer.write(value | (1 << 12)); // SVME bit
                
                info!("AMD-V enabled");
            }
        }
    }
    
    Ok(())
}

// Jump to hypervisor entry point
unsafe fn jump_to_hypervisor(base: u64) -> ! {
    // Disable interrupts
    interrupts::disable();
    
    // Set up stack for hypervisor
    let stack_top = base + 0x100000; // 1MB stack
    
    // Jump to hypervisor entry
    let entry_point = base + 0x10000; // Hypervisor entry at offset 0x10000
    
    asm!(
        "mov rsp, {stack}",
        "jmp {entry}",
        stack = in(reg) stack_top,
        entry = in(reg) entry_point,
        options(noreturn)
    );
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("PANIC: {}", info);
    
    // Reset system
    unsafe {
        uefi::runtime::reset(ResetType::COLD, Status::ABORTED, None);
    }
}