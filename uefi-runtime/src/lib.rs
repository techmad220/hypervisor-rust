//! UEFI Runtime Services support
//! Comprehensive UEFI boot and runtime services integration

#![no_std]
#![feature(abi_efiapi)]

extern crate alloc;

pub mod boot_services;
pub mod protocols;
pub mod runtime_services;

use uefi::prelude::*;
use uefi::table::{Boot, Runtime, SystemTable};

/// Initialize UEFI services
pub fn init_boot_services(system_table: &SystemTable<Boot>) -> boot_services::BootServices {
    boot_services::BootServices::new(system_table)
}

/// Initialize runtime services
pub fn init_runtime_services(system_table: &SystemTable<Runtime>) -> runtime_services::RuntimeServices {
    runtime_services::RuntimeServices::new(system_table)
}

/// Re-export commonly used types
pub use boot_services::{BootServices, ConsoleServices, FileServices, MemoryServices, ProtocolServices};
pub use protocols::{
    HypervisorProtocol, VirtualizationProtocol, MemoryProtectionProtocol, 
    DriverLoaderProtocol, SecurityProtocol, AdvancedConfigProtocol,
    VmStatus, VmState, HypervisorCapabilities, PageAttributes,
    DriverInfo, DriverType, PciDeviceInfo,
    HYPERVISOR_PROTOCOL_GUID, VIRTUALIZATION_PROTOCOL_GUID,
    MEMORY_PROTECTION_PROTOCOL_GUID, DRIVER_LOADER_PROTOCOL_GUID,
};
pub use runtime_services::{RuntimeServices, VariableServices, TimeServices, HypervisorConfig};