//! PCI device spoofing

use uefi::prelude::*;
use uefi::proto::pci_io::{PciIo, PciIoProtocol};
use log::info;
use alloc::vec::Vec;

const VENDOR_WHITELIST: &[u16] = &[
    0x8086, // Intel
    0x10DE, // NVIDIA  
    0x1002, // AMD
];

/// Patch all PCI devices
pub fn patch_all_pci_devices() {
    info!("[PCI] Starting PCI device spoofing...");
    
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    // Locate all PCI I/O protocol handles
    let handles = match bt.locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(&PciIoProtocol::GUID)) {
        Ok(h) => h,
        Err(_) => {
            info!("[PCI] No PCI devices found");
            return;
        }
    };
    
    for handle in handles.handles() {
        if let Ok(pci_io) = bt.open_protocol_exclusive::<PciIo>(*handle) {
            unsafe {
                spoof_pci_device(&pci_io);
            }
        }
    }
    
    patch_gpu_pci_devices();
    patch_network_pci_devices();
    patch_storage_pci_devices();
    patch_audio_pci_devices();
    patch_bluetooth_pci_devices();
    
    info!("[PCI] PCI device spoofing completed");
}

unsafe fn spoof_pci_device(pci_io: &PciIo) {
    // Read vendor ID
    let mut vendor_id: u16 = 0;
    if pci_io.pci_read(
        uefi::proto::pci_io::PciIoWidth::U16,
        0, // Vendor ID offset
        1,
        &mut vendor_id as *mut _ as *mut u8,
    ).is_err() {
        return;
    }
    
    // Only spoof whitelisted vendors
    if !VENDOR_WHITELIST.contains(&vendor_id) {
        return;
    }
    
    // Generate fake device ID based on seed
    let seed = *crate::SPOOF_SEED.lock();
    let fake_device_id = ((seed >> 16) & 0xFFFF) as u16;
    
    // Write fake device ID
    let _ = pci_io.pci_write(
        uefi::proto::pci_io::PciIoWidth::U16,
        2, // Device ID offset
        1,
        &fake_device_id as *const _ as *const u8,
    );
}

fn patch_gpu_pci_devices() {
    patch_pci_by_class(0x03, 0x3D3D); // Display Controller
}

fn patch_network_pci_devices() {
    patch_pci_by_class(0x02, 0xD00D); // Network Controller
}

fn patch_storage_pci_devices() {
    patch_pci_by_class(0x01, 0x5A5A); // Storage Controller
}

fn patch_audio_pci_devices() {
    patch_pci_by_class(0x04, 0xC0DE); // Multimedia Controller
}

fn patch_bluetooth_pci_devices() {
    // Serial Bus Controllers (Bluetooth, USB, etc)
    patch_pci_by_subclass(0x0C, &[0x0F, 0x03, 0x01, 0x00], 0xB1E1);
}

fn patch_pci_by_class(class_code: u8, fake_id: u16) {
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    if let Ok(handles) = bt.locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(&PciIoProtocol::GUID)) {
        for handle in handles.handles() {
            if let Ok(pci_io) = bt.open_protocol_exclusive::<PciIo>(*handle) {
                let mut class: u32 = 0;
                
                unsafe {
                    if pci_io.pci_read(
                        uefi::proto::pci_io::PciIoWidth::U32,
                        8, // Class code offset
                        1,
                        &mut class as *mut _ as *mut u8,
                    ).is_ok() {
                        if ((class >> 16) & 0xFF) as u8 == class_code {
                            // Write fake device ID
                            let _ = pci_io.pci_write(
                                uefi::proto::pci_io::PciIoWidth::U16,
                                2, // Device ID offset
                                1,
                                &fake_id as *const _ as *const u8,
                            );
                            
                            info!("[PCI] Spoofed class {:#x} device to ID {:#x}", class_code, fake_id);
                        }
                    }
                }
            }
        }
    }
}

fn patch_pci_by_subclass(base_class: u8, subclasses: &[u8], base_fake_id: u16) {
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    if let Ok(handles) = bt.locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(&PciIoProtocol::GUID)) {
        for handle in handles.handles() {
            if let Ok(pci_io) = bt.open_protocol_exclusive::<PciIo>(*handle) {
                let mut class: u32 = 0;
                
                unsafe {
                    if pci_io.pci_read(
                        uefi::proto::pci_io::PciIoWidth::U32,
                        8, // Class code offset
                        1,
                        &mut class as *mut _ as *mut u8,
                    ).is_ok() {
                        let base = ((class >> 16) & 0xFF) as u8;
                        let sub = ((class >> 8) & 0xFF) as u8;
                        
                        if base == base_class && subclasses.contains(&sub) {
                            let fake_id = base_fake_id + sub as u16;
                            
                            // Write fake device ID
                            let _ = pci_io.pci_write(
                                uefi::proto::pci_io::PciIoWidth::U16,
                                2, // Device ID offset
                                1,
                                &fake_id as *const _ as *const u8,
                            );
                            
                            info!("[PCI] Spoofed class {:#x}:{:#x} device to ID {:#x}", base_class, sub, fake_id);
                        }
                    }
                }
            }
        }
    }
}