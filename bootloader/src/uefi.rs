//! UEFI Bootloader for Hypervisor
//! 
//! This module implements a UEFI bootloader that:
//! 1. Loads the hypervisor before the OS
//! 2. Sets up early virtualization
//! 3. Chainloads the original OS bootloader

#![no_std]
#![no_main]

extern crate alloc;

use uefi::prelude::*;
use uefi::proto::console::text::Output;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileType, FileInfo};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{LoadImageSource, MemoryType};
use uefi::table::runtime::ResetType;
use uefi::{Handle, Status};
use uefi::CStr16;
use core::mem;
use alloc::vec::Vec;

const HYPERVISOR_FILENAME: &CStr16 = cstr16!("\\EFI\\hypervisor\\hypervisor.efi");
const WINDOWS_BOOTMGR: &CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
const LINUX_GRUB: &CStr16 = cstr16!("\\EFI\\grub\\grubx64.efi");

/// UEFI entry point
#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize UEFI services
    uefi::helpers::init(&mut system_table).unwrap();
    
    let boot_services = system_table.boot_services();
    
    // Clear screen and print banner
    if let Ok(stdout) = system_table.stdout() {
        stdout.clear().ok();
        info!("[+] UEFI Hypervisor Bootloader v1.0");
        info!("[+] Initializing...");
    }
    
    // Small delay for debugging
    boot_services.stall(1_000_000);
    
    // Load hypervisor
    match load_hypervisor(image_handle, boot_services) {
        Ok(_) => info!("[+] Hypervisor loaded successfully"),
        Err(e) => {
            error!("[-] Failed to load hypervisor: {:?}", e);
            // Continue booting even if hypervisor fails
        }
    }
    
    // Setup early virtualization hooks
    if let Err(e) = setup_early_hooks(boot_services) {
        error!("[-] Failed to setup hooks: {:?}", e);
    }
    
    // Chainload original OS bootloader
    match chainload_os(image_handle, boot_services) {
        Ok(_) => info!("[+] Chainloading OS bootloader..."),
        Err(e) => {
            error!("[-] Failed to chainload OS: {:?}", e);
            // Fatal error - cannot continue
            boot_services.stall(5_000_000);
            system_table.runtime_services().reset(
                ResetType::SHUTDOWN,
                Status::LOAD_ERROR,
                None
            );
        }
    }
    
    Status::SUCCESS
}

/// Load the hypervisor EFI binary
fn load_hypervisor(
    image_handle: Handle,
    boot_services: &BootServices
) -> uefi::Result<Handle> {
    info!("[*] Loading hypervisor...");
    
    // Find ESP (EFI System Partition)
    let esp_handle = find_esp(boot_services)?;
    
    // Open filesystem protocol
    let mut fs = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(esp_handle)?;
    
    // Open root directory
    let mut root = fs.open_volume()?;
    
    // Try to open hypervisor file
    let hypervisor_file = root.open(
        HYPERVISOR_FILENAME,
        FileMode::Read,
        FileAttribute::empty()
    )?;
    
    // Get file info to determine size
    let mut info_buffer = [0u8; 512];
    let info = hypervisor_file
        .into_regular_file()
        .ok_or(Status::INVALID_PARAMETER)?
        .get_info::<FileInfo>(&mut info_buffer)?;
    
    let file_size = info.file_size() as usize;
    
    // Allocate memory for hypervisor
    let hypervisor_data = boot_services.allocate_pool(
        MemoryType::BOOT_SERVICES_CODE,
        file_size
    )?;
    
    // Read hypervisor into memory
    let mut hypervisor_file = root.open(
        HYPERVISOR_FILENAME,
        FileMode::Read,
        FileAttribute::empty()
    )?;
    
    let mut regular_file = hypervisor_file
        .into_regular_file()
        .ok_or(Status::INVALID_PARAMETER)?;
    
    let data_slice = unsafe {
        core::slice::from_raw_parts_mut(hypervisor_data, file_size)
    };
    
    regular_file.read(data_slice)?;
    
    // Load image from memory
    let hypervisor_handle = boot_services.load_image(
        image_handle,
        LoadImageSource::FromBuffer {
            buffer: data_slice,
            file_path: None,
        }
    )?;
    
    // Start the hypervisor
    boot_services.start_image(hypervisor_handle)?;
    
    // Free temporary buffer
    boot_services.free_pool(hypervisor_data)?;
    
    Ok(hypervisor_handle)
}

/// Setup early virtualization hooks
fn setup_early_hooks(boot_services: &BootServices) -> uefi::Result<()> {
    info!("[*] Setting up early virtualization hooks...");
    
    // Check CPU features
    let (vmx_supported, svm_supported) = check_virt_support();
    
    if !vmx_supported && !svm_supported {
        warn!("[-] No virtualization support detected");
        return Err(Status::UNSUPPORTED.into());
    }
    
    if vmx_supported {
        info!("[+] Intel VMX detected");
        setup_vmx_early()?;
    }
    
    if svm_supported {
        info!("[+] AMD SVM detected");
        setup_svm_early()?;
    }
    
    // Hook ExitBootServices to maintain control
    hook_exit_boot_services(boot_services)?;
    
    Ok(())
}

/// Check for virtualization support
fn check_virt_support() -> (bool, bool) {
    let mut vmx = false;
    let mut svm = false;
    
    unsafe {
        // Check Intel VMX
        let result = core::arch::x86_64::__cpuid(0x1);
        if result.ecx & (1 << 5) != 0 {
            vmx = true;
        }
        
        // Check AMD SVM
        let result = core::arch::x86_64::__cpuid(0x80000001);
        if result.ecx & (1 << 2) != 0 {
            svm = true;
        }
    }
    
    (vmx, svm)
}

/// Setup early VMX initialization
fn setup_vmx_early() -> uefi::Result<()> {
    unsafe {
        // Enable VMX in CR4
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 1 << 13; // CR4.VMXE
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
        
        // Set up MSRs
        const IA32_FEATURE_CONTROL: u32 = 0x3A;
        let feature_control = core::arch::x86_64::_rdmsr(IA32_FEATURE_CONTROL);
        
        if feature_control & 1 == 0 {
            // Feature control not locked, enable VMX
            core::arch::x86_64::_wrmsr(IA32_FEATURE_CONTROL, feature_control | 0x5);
        }
    }
    
    Ok(())
}

/// Setup early SVM initialization  
fn setup_svm_early() -> uefi::Result<()> {
    unsafe {
        // Enable SVM in EFER
        const MSR_EFER: u32 = 0xC0000080;
        let mut efer = core::arch::x86_64::_rdmsr(MSR_EFER);
        efer |= 1 << 12; // EFER.SVME
        core::arch::x86_64::_wrmsr(MSR_EFER, efer);
    }
    
    Ok(())
}

/// Hook ExitBootServices to maintain hypervisor control
fn hook_exit_boot_services(boot_services: &BootServices) -> uefi::Result<()> {
    // This would involve hooking the boot services table
    // For now, just log that we would do this
    info!("[*] ExitBootServices hook would be installed here");
    Ok(())
}

/// Find the EFI System Partition
fn find_esp(boot_services: &BootServices) -> uefi::Result<Handle> {
    let handles = boot_services
        .find_handles::<SimpleFileSystem>()?;
    
    // For simplicity, use the first filesystem found
    // In production, you'd verify this is actually the ESP
    handles.first()
        .copied()
        .ok_or(Status::NOT_FOUND.into())
}

/// Chainload the original OS bootloader
fn chainload_os(
    image_handle: Handle,
    boot_services: &BootServices
) -> uefi::Result<()> {
    info!("[*] Chainloading OS bootloader...");
    
    let esp_handle = find_esp(boot_services)?;
    
    // Try Windows first, then Linux
    let bootloaders = [WINDOWS_BOOTMGR, LINUX_GRUB];
    
    for bootloader_path in &bootloaders {
        match load_and_start_image(image_handle, boot_services, esp_handle, bootloader_path) {
            Ok(handle) => {
                info!("[+] Starting OS bootloader: {:?}", bootloader_path);
                boot_services.start_image(handle)?;
                return Ok(());
            }
            Err(_) => continue,
        }
    }
    
    Err(Status::NOT_FOUND.into())
}

/// Load and prepare an image for execution
fn load_and_start_image(
    parent_image: Handle,
    boot_services: &BootServices,
    device_handle: Handle,
    file_path: &CStr16,
) -> uefi::Result<Handle> {
    // Open filesystem
    let mut fs = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(device_handle)?;
    
    let mut root = fs.open_volume()?;
    
    // Open the bootloader file
    let file = root.open(
        file_path,
        FileMode::Read,
        FileAttribute::empty()
    )?;
    
    // Get file size
    let mut info_buffer = [0u8; 512];
    let info = file
        .into_regular_file()
        .ok_or(Status::INVALID_PARAMETER)?
        .get_info::<FileInfo>(&mut info_buffer)?;
    
    let file_size = info.file_size() as usize;
    
    // Allocate memory
    let file_data = boot_services.allocate_pool(
        MemoryType::BOOT_SERVICES_CODE,
        file_size
    )?;
    
    // Read file
    let mut file = root.open(
        file_path,
        FileMode::Read,
        FileAttribute::empty()
    )?;
    
    let mut regular_file = file
        .into_regular_file()
        .ok_or(Status::INVALID_PARAMETER)?;
    
    let data_slice = unsafe {
        core::slice::from_raw_parts_mut(file_data, file_size)
    };
    
    regular_file.read(data_slice)?;
    
    // Load image
    let image_handle = boot_services.load_image(
        parent_image,
        LoadImageSource::FromBuffer {
            buffer: data_slice,
            file_path: None,
        }
    )?;
    
    // Free temporary buffer
    boot_services.free_pool(file_data)?;
    
    Ok(image_handle)
}

/// Panic handler
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    error!("PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

// Helper macros for logging
macro_rules! info {
    ($($arg:tt)*) => {
        if let Ok(stdout) = unsafe { uefi::helpers::system_table().stdout() } {
            let _ = stdout.output_string(cstr16!("[INFO] "));
            // Note: Real implementation would format the arguments
        }
    };
}

macro_rules! warn {
    ($($arg:tt)*) => {
        if let Ok(stdout) = unsafe { uefi::helpers::system_table().stdout() } {
            let _ = stdout.output_string(cstr16!("[WARN] "));
        }
    };
}

macro_rules! error {
    ($($arg:tt)*) => {
        if let Ok(stdout) = unsafe { uefi::helpers::system_table().stdout() } {
            let _ = stdout.output_string(cstr16!("[ERROR] "));
        }
    };
}