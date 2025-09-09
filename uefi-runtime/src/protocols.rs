//! UEFI Protocol Definitions
//! Custom protocol implementations for hypervisor integration

#![no_std]

use uefi::prelude::*;
use uefi::{Guid, Handle};
use core::ffi::c_void;
use core::mem;

/// Hypervisor Protocol GUID
pub const HYPERVISOR_PROTOCOL_GUID: Guid = Guid::from_values(
    0x12345678,
    0x9ABC,
    0xDEF0,
    [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
);

/// VMX/SVM Protocol GUID
pub const VIRTUALIZATION_PROTOCOL_GUID: Guid = Guid::from_values(
    0x87654321,
    0xFEDC,
    0xBA98,
    [0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98],
);

/// Memory Protection Protocol GUID
pub const MEMORY_PROTECTION_PROTOCOL_GUID: Guid = Guid::from_values(
    0xABCDEF01,
    0x2345,
    0x6789,
    [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89],
);

/// Driver Loader Protocol GUID
pub const DRIVER_LOADER_PROTOCOL_GUID: Guid = Guid::from_values(
    0x11223344,
    0x5566,
    0x7788,
    [0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00],
);

/// Hypervisor Protocol
#[repr(C)]
pub struct HypervisorProtocol {
    pub revision: u64,
    pub initialize: extern "efiapi" fn() -> Status,
    pub start_vmx: extern "efiapi" fn() -> Status,
    pub start_svm: extern "efiapi" fn() -> Status,
    pub create_vm: extern "efiapi" fn(vm_id: u32) -> Status,
    pub destroy_vm: extern "efiapi" fn(vm_id: u32) -> Status,
    pub run_vm: extern "efiapi" fn(vm_id: u32) -> Status,
    pub get_vm_status: extern "efiapi" fn(vm_id: u32, status: *mut VmStatus) -> Status,
    pub allocate_guest_memory: extern "efiapi" fn(size: usize) -> *mut c_void,
    pub free_guest_memory: extern "efiapi" fn(ptr: *mut c_void) -> Status,
    pub map_guest_physical: extern "efiapi" fn(
        vm_id: u32,
        guest_physical: u64,
        host_physical: u64,
        size: u64,
        flags: u32,
    ) -> Status,
    pub inject_interrupt: extern "efiapi" fn(vm_id: u32, vector: u8) -> Status,
    pub get_capabilities: extern "efiapi" fn(caps: *mut HypervisorCapabilities) -> Status,
}

/// VM Status structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VmStatus {
    pub state: VmState,
    pub exit_reason: u32,
    pub exit_qualification: u64,
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub interrupt_pending: bool,
    pub cpu_count: u32,
}

/// VM State enum
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VmState {
    Created = 0,
    Running = 1,
    Paused = 2,
    Suspended = 3,
    Terminated = 4,
    Error = 5,
}

/// Hypervisor Capabilities
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HypervisorCapabilities {
    pub vmx_supported: bool,
    pub svm_supported: bool,
    pub nested_virtualization: bool,
    pub ept_supported: bool,
    pub vpid_supported: bool,
    pub unrestricted_guest: bool,
    pub max_vcpus: u32,
    pub max_memory_gb: u32,
}

/// Virtualization Protocol
#[repr(C)]
pub struct VirtualizationProtocol {
    pub revision: u64,
    pub enable_vmx: extern "efiapi" fn() -> Status,
    pub disable_vmx: extern "efiapi" fn() -> Status,
    pub enable_svm: extern "efiapi" fn() -> Status,
    pub disable_svm: extern "efiapi" fn() -> Status,
    pub setup_vmcs: extern "efiapi" fn(vmcs_region: *mut c_void) -> Status,
    pub setup_vmcb: extern "efiapi" fn(vmcb_region: *mut c_void) -> Status,
    pub vmlaunch: extern "efiapi" fn() -> Status,
    pub vmresume: extern "efiapi" fn() -> Status,
    pub vmexit_handler: extern "efiapi" fn(exit_reason: u32) -> Status,
    pub setup_ept: extern "efiapi" fn(ept_pointer: u64) -> Status,
    pub invalidate_ept: extern "efiapi" fn(eptp: u64) -> Status,
    pub setup_msr_bitmap: extern "efiapi" fn(bitmap: *mut c_void) -> Status,
    pub setup_io_bitmap: extern "efiapi" fn(bitmap: *mut c_void) -> Status,
}

/// Memory Protection Protocol
#[repr(C)]
pub struct MemoryProtectionProtocol {
    pub revision: u64,
    pub enable_nx: extern "efiapi" fn() -> Status,
    pub enable_smep: extern "efiapi" fn() -> Status,
    pub enable_smap: extern "efiapi" fn() -> Status,
    pub enable_dep: extern "efiapi" fn() -> Status,
    pub set_page_attributes: extern "efiapi" fn(
        address: u64,
        size: u64,
        attributes: PageAttributes,
    ) -> Status,
    pub get_page_attributes: extern "efiapi" fn(
        address: u64,
        attributes: *mut PageAttributes,
    ) -> Status,
    pub lock_memory_range: extern "efiapi" fn(address: u64, size: u64) -> Status,
    pub unlock_memory_range: extern "efiapi" fn(address: u64, size: u64) -> Status,
    pub enable_memory_encryption: extern "efiapi" fn() -> Status,
    pub set_memory_encryption_key: extern "efiapi" fn(key: *const u8, key_size: usize) -> Status,
}

/// Page Attributes
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PageAttributes {
    pub present: bool,
    pub writable: bool,
    pub executable: bool,
    pub user_accessible: bool,
    pub write_through: bool,
    pub cache_disabled: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub huge_page: bool,
    pub global: bool,
    pub no_execute: bool,
}

/// Driver Loader Protocol
#[repr(C)]
pub struct DriverLoaderProtocol {
    pub revision: u64,
    pub load_driver: extern "efiapi" fn(
        image_handle: Handle,
        driver_path: *const u16,
        driver_size: usize,
    ) -> Status,
    pub unload_driver: extern "efiapi" fn(driver_handle: Handle) -> Status,
    pub verify_driver_signature: extern "efiapi" fn(
        driver_data: *const u8,
        driver_size: usize,
    ) -> Status,
    pub get_driver_info: extern "efiapi" fn(
        driver_handle: Handle,
        info: *mut DriverInfo,
    ) -> Status,
    pub register_driver_callback: extern "efiapi" fn(
        event_type: DriverEventType,
        callback: DriverCallback,
    ) -> Status,
    pub load_kernel_driver: extern "efiapi" fn(
        driver_path: *const u16,
        load_options: *const c_void,
    ) -> Status,
    pub chainload_os: extern "efiapi" fn(
        os_loader_path: *const u16,
        boot_options: *const c_void,
    ) -> Status,
}

/// Driver Information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DriverInfo {
    pub name: [u16; 256],
    pub version: u32,
    pub vendor: [u16; 256],
    pub driver_type: DriverType,
    pub load_address: u64,
    pub image_size: usize,
    pub entry_point: u64,
}

/// Driver Type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DriverType {
    BootService = 0,
    RuntimeService = 1,
    SystemManagement = 2,
    Hypervisor = 3,
    Security = 4,
}

/// Driver Event Type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DriverEventType {
    PreLoad = 0,
    PostLoad = 1,
    PreUnload = 2,
    PostUnload = 3,
    Error = 4,
}

/// Driver Callback function type
pub type DriverCallback = extern "efiapi" fn(
    event_type: DriverEventType,
    driver_handle: Handle,
    context: *mut c_void,
) -> Status;

/// Advanced Configuration Protocol
#[repr(C)]
pub struct AdvancedConfigProtocol {
    pub revision: u64,
    pub get_config_table: extern "efiapi" fn(
        guid: *const Guid,
        table: *mut *mut c_void,
    ) -> Status,
    pub install_config_table: extern "efiapi" fn(
        guid: *const Guid,
        table: *mut c_void,
    ) -> Status,
    pub get_acpi_table: extern "efiapi" fn(
        signature: u32,
        table: *mut *mut c_void,
    ) -> Status,
    pub get_smbios_table: extern "efiapi" fn(table: *mut *mut c_void) -> Status,
    pub configure_pci_device: extern "efiapi" fn(
        bus: u8,
        device: u8,
        function: u8,
        config: *const PciConfig,
    ) -> Status,
    pub get_pci_device_info: extern "efiapi" fn(
        bus: u8,
        device: u8,
        function: u8,
        info: *mut PciDeviceInfo,
    ) -> Status,
}

/// PCI Configuration
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PciConfig {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision_id: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class_code: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
    pub bar: [u32; 6],
}

/// PCI Device Information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PciDeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bars: [u64; 6],
    pub rom_base: u64,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

/// Security Protocol
#[repr(C)]
pub struct SecurityProtocol {
    pub revision: u64,
    pub measure_boot: extern "efiapi" fn(
        pcr_index: u32,
        event_type: u32,
        event_data: *const u8,
        event_size: usize,
    ) -> Status,
    pub verify_signature: extern "efiapi" fn(
        data: *const u8,
        data_size: usize,
        signature: *const u8,
        signature_size: usize,
        key: *const u8,
        key_size: usize,
    ) -> Status,
    pub get_random: extern "efiapi" fn(buffer: *mut u8, size: usize) -> Status,
    pub hash_data: extern "efiapi" fn(
        algorithm: HashAlgorithm,
        data: *const u8,
        data_size: usize,
        hash: *mut u8,
        hash_size: *mut usize,
    ) -> Status,
    pub encrypt_data: extern "efiapi" fn(
        algorithm: CryptoAlgorithm,
        key: *const u8,
        key_size: usize,
        iv: *const u8,
        plaintext: *const u8,
        plaintext_size: usize,
        ciphertext: *mut u8,
        ciphertext_size: *mut usize,
    ) -> Status,
    pub decrypt_data: extern "efiapi" fn(
        algorithm: CryptoAlgorithm,
        key: *const u8,
        key_size: usize,
        iv: *const u8,
        ciphertext: *const u8,
        ciphertext_size: usize,
        plaintext: *mut u8,
        plaintext_size: *mut usize,
    ) -> Status,
}

/// Hash Algorithm
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashAlgorithm {
    Sha1 = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
    Blake2b = 4,
    Blake3 = 5,
}

/// Crypto Algorithm
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CryptoAlgorithm {
    Aes128Cbc = 0,
    Aes256Cbc = 1,
    Aes128Gcm = 2,
    Aes256Gcm = 3,
    ChaCha20Poly1305 = 4,
}

/// Protocol installation helper
pub fn install_hypervisor_protocols(
    boot_services: &uefi::table::boot::BootServices,
    hypervisor_protocol: *mut HypervisorProtocol,
    virtualization_protocol: *mut VirtualizationProtocol,
    memory_protection_protocol: *mut MemoryProtectionProtocol,
    driver_loader_protocol: *mut DriverLoaderProtocol,
) -> Result<Vec<Handle>, Status> {
    let mut handles = Vec::new();

    // Install Hypervisor Protocol
    let h1 = boot_services.install_protocol_interface(
        None,
        &HYPERVISOR_PROTOCOL_GUID,
        hypervisor_protocol as *mut c_void,
    )?;
    handles.push(h1);

    // Install Virtualization Protocol
    let h2 = boot_services.install_protocol_interface(
        None,
        &VIRTUALIZATION_PROTOCOL_GUID,
        virtualization_protocol as *mut c_void,
    )?;
    handles.push(h2);

    // Install Memory Protection Protocol
    let h3 = boot_services.install_protocol_interface(
        None,
        &MEMORY_PROTECTION_PROTOCOL_GUID,
        memory_protection_protocol as *mut c_void,
    )?;
    handles.push(h3);

    // Install Driver Loader Protocol
    let h4 = boot_services.install_protocol_interface(
        None,
        &DRIVER_LOADER_PROTOCOL_GUID,
        driver_loader_protocol as *mut c_void,
    )?;
    handles.push(h4);

    Ok(handles)
}

extern crate alloc;
use alloc::vec::Vec;