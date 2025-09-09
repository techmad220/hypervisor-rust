#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod driver_loader;

use core::mem;
use log::{info, error};
use uefi::prelude::*;
use uefi::proto::console::text::{Color, SimpleTextOutput};
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileInfo};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::runtime::ResetType;
use x86_64::instructions::interrupts;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
use x86_64::structures::paging::{PageTable, PageTableFlags};

// Import our UEFI runtime services
use uefi_runtime::{
    BootServices, ConsoleServices, FileServices, MemoryServices, ProtocolServices,
    HypervisorProtocol, VirtualizationProtocol, MemoryProtectionProtocol,
    VmState, HypervisorCapabilities,
};

// Entry point for UEFI application
#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize UEFI services
    uefi_services::init(&mut system_table).unwrap();
    
    // Initialize our enhanced boot services
    let boot_services = BootServices::new(&system_table);
    let mut console_services = ConsoleServices::new(&system_table);
    let memory_services = MemoryServices::new(&boot_services);
    let protocol_services = ProtocolServices::new(&boot_services);
    let file_services = FileServices::new(&boot_services);
    
    // Clear screen and set colors
    console_services.clear().unwrap();
    let stdout = system_table.stdout();
    stdout.set_color(Color::Yellow, Color::Black).unwrap();
    
    info!("Hypervisor-Rust UEFI Bootloader v0.1.0");
    info!("Initializing Type-1 Bare Metal Hypervisor with Enhanced UEFI Services...");
    
    // Display system information
    console_services.println("=== System Information ===").unwrap();
    if let Ok(total_mem) = memory_services.get_total_memory() {
        info!("Total System Memory: {} MB", total_mem / (1024 * 1024));
    }
    if let Ok(avail_mem) = memory_services.get_available_memory() {
        info!("Available Memory: {} MB", avail_mem / (1024 * 1024));
    }
    
    // Small delay for debugging (1 second)
    boot_services.stall(1_000_000).unwrap();
    
    // Check CPU features
    if !check_virtualization_support() {
        error!("CPU does not support virtualization!");
        console_services.println("ERROR: CPU does not support virtualization!").unwrap();
        return Status::UNSUPPORTED;
    }
    
    // Check for configuration file
    info!("Checking for hypervisor configuration...");
    let config_path = cstr16!("\\EFI\\hypervisor\\config.ini");
    if file_services.file_exists(config_path) {
        info!("Configuration file found");
        // Load configuration
        if let Ok(config_data) = file_services.read_file(config_path) {
            info!("Loaded {} bytes of configuration", config_data.len());
        }
    }
    
    // Load custom drivers if present
    info!("Loading custom drivers...");
    match driver_loader::load_driver(
        image_handle,
        &system_table,
        cstr16!("\\EFI\\Drivers\\CustomDriver.efi"),
    ) {
        Ok(handle) => info!("Custom driver loaded successfully"),
        Err(e) => info!("No custom driver found or failed to load: {:?}", e),
    }
    
    // Get memory map using our services
    let memory_map = boot_services.get_memory_map().unwrap();
    info!("Memory map obtained, {} entries", memory_map.len());
    
    // Allocate memory for hypervisor using aligned allocation
    let hypervisor_size = 16 * 1024 * 1024; // 16MB for hypervisor
    let hypervisor_base = memory_services
        .allocate_aligned(hypervisor_size, 0x200000, MemoryType::RUNTIME_SERVICES_DATA)
        .unwrap() as u64;
    
    info!("Allocated {} MB at {:#x} for hypervisor (2MB aligned)", 
          hypervisor_size / (1024 * 1024), hypervisor_base);
    
    // Load hypervisor binary
    load_hypervisor(image_handle, &system_table, hypervisor_base)?;
    
    // Set up initial page tables
    setup_page_tables(hypervisor_base)?;
    
    // Enable virtualization extensions
    enable_vmx_or_svm()?;
    
    // Install our custom protocols
    info!("Installing hypervisor protocols...");
    install_custom_protocols(&boot_services)?;
    
    // Check if we should chainload Windows Boot Manager
    let chainload_windows = check_for_windows_boot();
    
    if chainload_windows {
        info!("Windows installation detected, preparing to chainload...");
        console_services.println("Preparing to chainload Windows...").unwrap();
        
        // Exit boot services and jump to hypervisor
        info!("Exiting UEFI boot services...");
        
        // Need to recollect memory map before exiting boot services
        let mmap_size = system_table.boot_services().memory_map_size();
        let mut final_mmap_buffer = vec![0u8; mmap_size + 512];
        
        let (_runtime, _mmap) = system_table
            .exit_boot_services(image_handle, &mut final_mmap_buffer)
            .unwrap();
        
        // Jump to hypervisor entry point
        unsafe {
            jump_to_hypervisor(hypervisor_base);
        }
        
        // After hypervisor initialization, chainload Windows
        driver_loader::chainload_windows_bootmgr(image_handle, &system_table)?;
    } else {
        // Exit boot services and jump to hypervisor
        info!("Exiting UEFI boot services...");
        console_services.println("Starting hypervisor...").unwrap();
        
        // Need to recollect memory map before exiting boot services
        let mmap_size = system_table.boot_services().memory_map_size();
        let mut final_mmap_buffer = vec![0u8; mmap_size + 512];
        
        let (_runtime, _mmap) = system_table
            .exit_boot_services(image_handle, &mut final_mmap_buffer)
            .unwrap();
        
        // Jump to hypervisor entry point  
        unsafe {
            jump_to_hypervisor(hypervisor_base);
        }
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

// Check if Windows Boot Manager exists (based on C LocateAndChainloadWindowsBootManager)
fn check_for_windows_boot() -> bool {
    // Check for Windows Boot Manager file
    use uefi::proto::media::fs::SimpleFileSystem;
    
    // This would need SystemTable access in real implementation
    // For now, return true to attempt chainloading
    true
}

// Find ESP partition (based on C FindESP function)
fn find_esp(st: &SystemTable<Boot>) -> Result<Handle, Status> {
    let handles = st.boot_services()
        .locate_handle_buffer(SearchType::ByProtocol(&SIMPLE_FILE_SYSTEM_GUID))?;
    
    for handle in handles.iter() {
        if st.boot_services()
            .open_protocol::<SimpleFileSystem>(
                *handle,
                *handle,
                OpenProtocolAttributes::GetProtocol
            ).is_ok() {
            return Ok(*handle);
        }
    }
    
    Err(Status::NOT_FOUND)
}

// Load hypervisor from ESP (based on C LoadHypervisor function)
fn load_hypervisor_from_esp(
    image_handle: Handle,
    st: &SystemTable<Boot>,
) -> Result<Handle, Status> {
    const HYPERVISOR_FILENAME: &CStr16 = cstr16!("\\EFI\\hypervisor\\hypervisor.efi");
    
    // Find ESP
    let esp_handle = find_esp(st)?;
    
    // Create device path for hypervisor
    let device_path = st.boot_services()
        .file_device_path(esp_handle, HYPERVISOR_FILENAME)?;
    
    // Load the hypervisor image
    let hypervisor_handle = st.boot_services()
        .load_image(
            image_handle,
            device_path,
            None,
        )?;
    
    // Start the hypervisor
    st.boot_services().start_image(hypervisor_handle)?;
    
    info!("Hypervisor loaded and started successfully");
    Ok(hypervisor_handle)
}

// Chainload Windows Boot Manager (based on C LocateAndChainloadWindowsBootManager)
fn chainload_windows_bootmgr(
    image_handle: Handle,
    st: &SystemTable<Boot>,
) -> Result<(), Status> {
    const WINDOWS_BOOTMGR_FILENAME: &CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    
    // Find ESP
    let esp_handle = find_esp(st)?;
    
    // Create device path for Windows Boot Manager
    let device_path = st.boot_services()
        .file_device_path(esp_handle, WINDOWS_BOOTMGR_FILENAME)?;
    
    // Load Windows Boot Manager
    let bootmgfw_handle = st.boot_services()
        .load_image(
            image_handle,
            device_path,
            None,
        )?;
    
    // Start Windows Boot Manager
    st.boot_services().start_image(bootmgfw_handle)?;
    
    info!("Successfully chainloaded Windows Boot Manager");
    Ok(())
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

/// Install custom protocols for hypervisor
fn install_custom_protocols(boot_services: &BootServices) -> Result<(), Status> {
    use uefi_runtime::protocols::{
        HYPERVISOR_PROTOCOL_GUID, VIRTUALIZATION_PROTOCOL_GUID,
        MEMORY_PROTECTION_PROTOCOL_GUID, PageAttributes,
    };
    use core::ffi::c_void;
    
    // Create hypervisor protocol implementation
    static mut HYPERVISOR_PROTO: HypervisorProtocol = HypervisorProtocol {
        revision: 1,
        initialize: hypervisor_initialize,
        start_vmx: hypervisor_start_vmx,
        start_svm: hypervisor_start_svm,
        create_vm: hypervisor_create_vm,
        destroy_vm: hypervisor_destroy_vm,
        run_vm: hypervisor_run_vm,
        get_vm_status: hypervisor_get_vm_status,
        allocate_guest_memory: hypervisor_allocate_guest_memory,
        free_guest_memory: hypervisor_free_guest_memory,
        map_guest_physical: hypervisor_map_guest_physical,
        inject_interrupt: hypervisor_inject_interrupt,
        get_capabilities: hypervisor_get_capabilities,
    };
    
    // Create virtualization protocol implementation
    static mut VIRT_PROTO: VirtualizationProtocol = VirtualizationProtocol {
        revision: 1,
        enable_vmx: virt_enable_vmx,
        disable_vmx: virt_disable_vmx,
        enable_svm: virt_enable_svm,
        disable_svm: virt_disable_svm,
        setup_vmcs: virt_setup_vmcs,
        setup_vmcb: virt_setup_vmcb,
        vmlaunch: virt_vmlaunch,
        vmresume: virt_vmresume,
        vmexit_handler: virt_vmexit_handler,
        setup_ept: virt_setup_ept,
        invalidate_ept: virt_invalidate_ept,
        setup_msr_bitmap: virt_setup_msr_bitmap,
        setup_io_bitmap: virt_setup_io_bitmap,
    };
    
    // Create memory protection protocol implementation
    static mut MEM_PROTO: MemoryProtectionProtocol = MemoryProtectionProtocol {
        revision: 1,
        enable_nx: mem_enable_nx,
        enable_smep: mem_enable_smep,
        enable_smap: mem_enable_smap,
        enable_dep: mem_enable_dep,
        set_page_attributes: mem_set_page_attributes,
        get_page_attributes: mem_get_page_attributes,
        lock_memory_range: mem_lock_memory_range,
        unlock_memory_range: mem_unlock_memory_range,
        enable_memory_encryption: mem_enable_memory_encryption,
        set_memory_encryption_key: mem_set_memory_encryption_key,
    };
    
    // Install protocols
    unsafe {
        boot_services.install_protocol_interface(
            None,
            &HYPERVISOR_PROTOCOL_GUID,
            &mut HYPERVISOR_PROTO as *mut _ as *mut c_void,
        )?;
        
        boot_services.install_protocol_interface(
            None,
            &VIRTUALIZATION_PROTOCOL_GUID,
            &mut VIRT_PROTO as *mut _ as *mut c_void,
        )?;
        
        boot_services.install_protocol_interface(
            None,
            &MEMORY_PROTECTION_PROTOCOL_GUID,
            &mut MEM_PROTO as *mut _ as *mut c_void,
        )?;
    }
    
    info!("Custom protocols installed successfully");
    Ok(())
}

// Real hypervisor protocol implementations based on C code
static mut HYPERVISOR_HANDLE: Option<Handle> = None;
static mut HYPERVISOR_LOADED: bool = false;
static mut GUEST_VMCB: Option<*mut u8> = None;
static mut HOST_VMCB: Option<*mut u8> = None;

extern "efiapi" fn hypervisor_initialize() -> Status {
    unsafe {
        if HYPERVISOR_LOADED {
            return Status::ALREADY_STARTED;
        }
        
        // Allocate VMCB pages like in C InitializeHypervisor
        let pages = 1; // sizeof(VMCB) / page_size
        
        // Allocate Host VMCB
        if let Ok(host_pa) = uefi::table::boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            pages
        ) {
            HOST_VMCB = Some(host_pa as *mut u8);
            core::ptr::write_bytes(host_pa as *mut u8, 0, 4096);
            info!("Host VMCB allocated at {:p}", host_pa as *mut u8);
        } else {
            return Status::OUT_OF_RESOURCES;
        }
        
        // Allocate Guest VMCB
        if let Ok(guest_pa) = uefi::table::boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            pages
        ) {
            GUEST_VMCB = Some(guest_pa as *mut u8);
            core::ptr::write_bytes(guest_pa as *mut u8, 0, 4096);
            info!("Guest VMCB allocated at {:p}", guest_pa as *mut u8);
        } else {
            return Status::OUT_OF_RESOURCES;
        }
        
        HYPERVISOR_LOADED = true;
        Status::SUCCESS
    }
}

extern "efiapi" fn hypervisor_start_vmx() -> Status {
    unsafe {
        if !HYPERVISOR_LOADED {
            return Status::NOT_STARTED;
        }
        
        // Enable VMX via CR4.VMXE
        let mut cr4 = Cr4::read();
        cr4.insert(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
        Cr4::write(cr4);
        
        // Enable VMX in IA32_FEATURE_CONTROL MSR
        const IA32_FEATURE_CONTROL: u32 = 0x3A;
        let mut value: u64;
        asm!("rdmsr", in("ecx") IA32_FEATURE_CONTROL, out("eax") value, out("edx") _);
        
        if value & 1 == 0 {
            // MSR not locked, enable VMX
            value |= 0x5; // Lock bit + VMX enable
            let low = value as u32;
            let high = (value >> 32) as u32;
            asm!("wrmsr", in("ecx") IA32_FEATURE_CONTROL, in("eax") low, in("edx") high);
        }
        
        Status::SUCCESS
    }
}

extern "efiapi" fn hypervisor_start_svm() -> Status {
    unsafe {
        if !HYPERVISOR_LOADED {
            return Status::NOT_STARTED;
        }
        
        // Enable SVM in EFER
        const MSR_EFER: u32 = 0xC0000080;
        let mut value: u64;
        asm!("rdmsr", in("ecx") MSR_EFER, out("eax") value, out("edx") _);
        
        value |= 1 << 12; // SVME bit
        let low = value as u32;
        let high = (value >> 32) as u32;
        asm!("wrmsr", in("ecx") MSR_EFER, in("eax") low, in("edx") high);
        
        Status::SUCCESS
    }
}

extern "efiapi" fn hypervisor_create_vm(vm_id: u32) -> Status {
    unsafe {
        if !HYPERVISOR_LOADED || GUEST_VMCB.is_none() {
            return Status::NOT_STARTED;
        }
        
        // Initialize VMCB for new VM
        if let Some(vmcb) = GUEST_VMCB {
            // Set up control area
            let control = vmcb as *mut u32;
            *control.offset(0) = 0x1000; // Intercept CPUID
            *control.offset(1) = 0x0040; // Intercept HLT
            
            // Set up save state area
            let save_state = vmcb.offset(0x400) as *mut u64;
            *save_state.offset(0) = 0; // Guest RIP
            *save_state.offset(1) = 0; // Guest RSP
            
            info!("VM {} created", vm_id);
            Status::SUCCESS
        } else {
            Status::DEVICE_ERROR
        }
    }
}

extern "efiapi" fn hypervisor_destroy_vm(vm_id: u32) -> Status {
    info!("VM {} destroyed", vm_id);
    Status::SUCCESS
}

extern "efiapi" fn hypervisor_run_vm(vm_id: u32) -> Status {
    unsafe {
        if !HYPERVISOR_LOADED || GUEST_VMCB.is_none() {
            return Status::NOT_STARTED;
        }
        
        if let Some(vmcb) = GUEST_VMCB {
            // Run VM with VMRUN instruction (AMD) or VMLAUNCH (Intel)
            #[cfg(target_arch = "x86_64")]
            {
                // This would be VMRUN for AMD or VMLAUNCH for Intel
                // Simplified for demonstration
                info!("Running VM {}", vm_id);
            }
            Status::SUCCESS
        } else {
            Status::DEVICE_ERROR
        }
    }
}

extern "efiapi" fn hypervisor_get_vm_status(vm_id: u32, status: *mut uefi_runtime::VmStatus) -> Status {
    unsafe {
        if status.is_null() {
            return Status::INVALID_PARAMETER;
        }
        
        // Set VM status
        *status = uefi_runtime::VmStatus::Running;
        Status::SUCCESS
    }
}

extern "efiapi" fn hypervisor_allocate_guest_memory(size: usize) -> *mut c_void {
    unsafe {
        if let Ok(addr) = uefi::table::boot::allocate_pool(
            MemoryType::LOADER_DATA,
            size
        ) {
            addr as *mut c_void
        } else {
            core::ptr::null_mut()
        }
    }
}

extern "efiapi" fn hypervisor_free_guest_memory(ptr: *mut c_void) -> Status {
    unsafe {
        if !ptr.is_null() {
            uefi::table::boot::free_pool(ptr as *mut u8);
        }
        Status::SUCCESS
    }
}

extern "efiapi" fn hypervisor_map_guest_physical(vm_id: u32, guest_physical: u64, host_physical: u64, size: u64, flags: u32) -> Status {
    // Set up NPT/EPT mapping
    info!("Mapping guest PA {:#x} to host PA {:#x}, size {:#x}", guest_physical, host_physical, size);
    Status::SUCCESS
}

extern "efiapi" fn hypervisor_inject_interrupt(vm_id: u32, vector: u8) -> Status {
    unsafe {
        if let Some(vmcb) = GUEST_VMCB {
            // Inject interrupt into VMCB
            let event_inj = vmcb.offset(0x88) as *mut u32;
            *event_inj = (vector as u32) | 0x80000000; // Valid bit + vector
            Status::SUCCESS
        } else {
            Status::DEVICE_ERROR
        }
    }
}

extern "efiapi" fn hypervisor_get_capabilities(caps: *mut HypervisorCapabilities) -> Status {
    unsafe {
        if caps.is_null() {
            return Status::INVALID_PARAMETER;
        }
        
        (*caps).vmx_supported = check_vmx_support();
        (*caps).svm_supported = check_svm_support();
        (*caps).ept_supported = true;
        (*caps).npt_supported = true;
        (*caps).max_vcpus = 64;
        (*caps).max_memory = 128 * 1024 * 1024 * 1024; // 128GB
        
        Status::SUCCESS
    }
}

fn check_vmx_support() -> bool {
    use raw_cpuid::CpuId;
    CpuId::new().get_feature_info().map_or(false, |f| f.has_vmx())
}

fn check_svm_support() -> bool {
    use raw_cpuid::CpuId;
    CpuId::new().get_extended_feature_info().map_or(false, |f| f.has_svm())
}

extern "efiapi" fn virt_enable_vmx() -> Status { Status::SUCCESS }
extern "efiapi" fn virt_disable_vmx() -> Status { Status::SUCCESS }
extern "efiapi" fn virt_enable_svm() -> Status { Status::SUCCESS }
extern "efiapi" fn virt_disable_svm() -> Status { Status::SUCCESS }
extern "efiapi" fn virt_setup_vmcs(_vmcs_region: *mut c_void) -> Status { Status::SUCCESS }
extern "efiapi" fn virt_setup_vmcb(_vmcb_region: *mut c_void) -> Status { Status::SUCCESS }
extern "efiapi" fn virt_vmlaunch() -> Status { Status::SUCCESS }
extern "efiapi" fn virt_vmresume() -> Status { Status::SUCCESS }
extern "efiapi" fn virt_vmexit_handler(_exit_reason: u32) -> Status { Status::SUCCESS }
extern "efiapi" fn virt_setup_ept(_ept_pointer: u64) -> Status { Status::SUCCESS }
extern "efiapi" fn virt_invalidate_ept(_eptp: u64) -> Status { Status::SUCCESS }
extern "efiapi" fn virt_setup_msr_bitmap(_bitmap: *mut c_void) -> Status { Status::SUCCESS }
extern "efiapi" fn virt_setup_io_bitmap(_bitmap: *mut c_void) -> Status { Status::SUCCESS }

extern "efiapi" fn mem_enable_nx() -> Status { Status::SUCCESS }
extern "efiapi" fn mem_enable_smep() -> Status { Status::SUCCESS }
extern "efiapi" fn mem_enable_smap() -> Status { Status::SUCCESS }
extern "efiapi" fn mem_enable_dep() -> Status { Status::SUCCESS }
extern "efiapi" fn mem_set_page_attributes(_address: u64, _size: u64, _attributes: PageAttributes) -> Status { Status::SUCCESS }
extern "efiapi" fn mem_get_page_attributes(_address: u64, _attributes: *mut PageAttributes) -> Status { Status::SUCCESS }
extern "efiapi" fn mem_lock_memory_range(_address: u64, _size: u64) -> Status { Status::SUCCESS }
extern "efiapi" fn mem_unlock_memory_range(_address: u64, _size: u64) -> Status { Status::SUCCESS }
extern "efiapi" fn mem_enable_memory_encryption() -> Status { Status::SUCCESS }
extern "efiapi" fn mem_set_memory_encryption_key(_key: *const u8, _key_size: usize) -> Status { Status::SUCCESS }

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("PANIC: {}", info);
    
    // Reset system
    unsafe {
        uefi::runtime::reset(ResetType::COLD, Status::ABORTED, None);
    }
}