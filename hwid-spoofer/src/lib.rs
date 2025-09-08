#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod smbios;
mod pci;
mod network;
mod disk;
mod usb;
mod nvme;
mod acpi;
mod tpm;
mod variables;

use uefi::prelude::*;
use uefi::proto::console::text::SimpleTextOutput;
use uefi::table::boot::EventType;
use uefi::Event;
use log::info;
use spin::Mutex;
use x86_64::instructions::random::RdRand;
use alloc::vec::Vec;

/// Global spoof seed for consistent randomization
static SPOOF_SEED: Mutex<u64> = Mutex::new(0);

/// Global runtime services pointer for hooks
static mut ORIGINAL_RT: Option<*const uefi::table::runtime::RuntimeServices> = None;

/// UEFI Driver entry point
#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize UEFI services
    uefi_services::init(&mut system_table).unwrap();
    
    info!("[HWID Spoofer] Initializing...");
    
    // Create ReadyToBoot event
    let event = unsafe {
        system_table
            .boot_services()
            .create_event(
                EventType::NOTIFY_SIGNAL,
                uefi::table::boot::Tpl::CALLBACK,
                Some(on_ready_to_boot),
                None,
            )?
    };
    
    // Register for ReadyToBoot notification
    system_table
        .boot_services()
        .register_protocol_notify(
            &uefi::proto::loaded_image::LOADED_IMAGE_PROTOCOL_GUID,
            event,
        )?;
    
    info!("[HWID Spoofer] Driver loaded successfully");
    Status::SUCCESS
}

/// Called when system is ready to boot
unsafe extern "efiapi" fn on_ready_to_boot(_event: Event, _context: Option<*mut core::ffi::c_void>) {
    static mut EXECUTED: bool = false;
    
    // Only execute once
    if EXECUTED {
        return;
    }
    EXECUTED = true;
    
    info!("[HWID Spoofer] ReadyToBoot event triggered, starting spoofing...");
    
    // Initialize spoof seed
    initialize_spoof_seed();
    
    // Execute all spoofing operations
    smbios::spoof_all_smbios();
    pci::patch_all_pci_devices();
    network::override_all_network_macs();
    disk::override_all_disk_serials();
    disk::spoof_gpt_partition_guids();
    disk::override_mbr_signatures();
    usb::hook_usb_descriptors();
    nvme::hook_nvme_identify();
    acpi::spoof_acpi_tables();
    tpm::hook_tpm_protocol();
    variables::hook_variable_protocol();
    
    info!("[HWID Spoofer] All spoofing operations completed");
}

/// Initialize the spoof seed using hardware RNG or timestamp
fn initialize_spoof_seed() {
    let seed = if let Some(rdrand) = RdRand::new() {
        // Use hardware RNG if available
        rdrand.get_u64().unwrap_or_else(|| {
            // Fallback to timestamp
            let time = uefi::table::runtime::Time::invalid();
            (time.nanosecond() as u64) << 32 | time.second() as u64
        })
    } else {
        // Fallback to timestamp
        let time = uefi::table::runtime::Time::invalid();
        (time.nanosecond() as u64) << 32 | time.second() as u64
    };
    
    *SPOOF_SEED.lock() = seed;
    info!("[HWID Spoofer] Spoof seed initialized: {:#x}", seed);
}

/// Generate random ASCII string
pub fn random_ascii_string(len: usize) -> Vec<u8> {
    let seed = *SPOOF_SEED.lock();
    let mut result = Vec::with_capacity(len);
    let mut rng = seed;
    
    for _ in 0..len {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        let ch = b'A' + ((rng >> 16) % 26) as u8;
        result.push(ch);
    }
    
    result
}

/// Generate random GUID
pub fn random_guid() -> uefi::Guid {
    let seed = *SPOOF_SEED.lock();
    let mut rng = seed;
    
    let mut bytes = [0u8; 16];
    for byte in &mut bytes {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (rng >> 16) as u8;
    }
    
    // Set version (4) and variant bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    
    uefi::Guid::from_bytes(bytes)
}

/// Generate random MAC address
pub fn generate_random_mac() -> [u8; 6] {
    let seed = *SPOOF_SEED.lock();
    let mut rng = seed;
    let mut mac = [0u8; 6];
    
    // First byte: locally administered, unicast
    rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
    mac[0] = ((rng >> 16) & 0xFE) as u8 | 0x02;
    
    // Remaining bytes
    for i in 1..6 {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        mac[i] = (rng >> 16) as u8;
    }
    
    mac
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("[HWID Spoofer] PANIC: {}", info);
    loop {
        x86_64::instructions::hlt();
    }
}