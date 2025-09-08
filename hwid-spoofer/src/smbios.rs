//! SMBIOS table spoofing

use uefi::prelude::*;
use uefi::table::cfg::{ConfigTableEntry, SMBIOS_GUID, SMBIOS3_GUID};
use core::mem;
use alloc::string::String;
use log::info;

#[repr(C, packed)]
struct SmbiosEntryPoint {
    anchor: [u8; 4],           // "_SM_"
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    max_structure_size: u16,
    revision: u8,
    formatted_area: [u8; 5],
    intermediate_anchor: [u8; 5], // "_DMI_"
    intermediate_checksum: u8,
    table_length: u16,
    table_address: u32,
    structure_count: u16,
    bcd_revision: u8,
}

#[repr(C, packed)]
struct SmbiosHeader {
    stype: u8,
    length: u8,
    handle: u16,
}

// SMBIOS structure types
const SMBIOS_TYPE_BIOS: u8 = 0;
const SMBIOS_TYPE_SYSTEM: u8 = 1;
const SMBIOS_TYPE_BASEBOARD: u8 = 2;
const SMBIOS_TYPE_CHASSIS: u8 = 3;
const SMBIOS_TYPE_PROCESSOR: u8 = 4;
const SMBIOS_TYPE_MEMORY_DEVICE: u8 = 17;
const SMBIOS_TYPE_BATTERY: u8 = 22;
const SMBIOS_TYPE_POWER_SUPPLY: u8 = 39;
const SMBIOS_TYPE_ONBOARD_DEVICES: u8 = 41;

/// Spoof all SMBIOS tables
pub fn spoof_all_smbios() {
    info!("[SMBIOS] Starting SMBIOS spoofing...");
    
    let st = unsafe { uefi::table::system::SystemTable::<uefi::table::Boot>::unsafe_clone() };
    
    // Find SMBIOS table in configuration table
    let mut smbios_entry: Option<*mut SmbiosEntryPoint> = None;
    
    for entry in st.config_table() {
        if entry.guid == SMBIOS_GUID || entry.guid == SMBIOS3_GUID {
            smbios_entry = Some(entry.address as *mut SmbiosEntryPoint);
            break;
        }
    }
    
    if let Some(entry_ptr) = smbios_entry {
        unsafe {
            spoof_smbios_structures(entry_ptr);
            recalculate_smbios_checksum(entry_ptr);
        }
        info!("[SMBIOS] SMBIOS spoofing completed");
    } else {
        info!("[SMBIOS] No SMBIOS table found");
    }
}

unsafe fn spoof_smbios_structures(entry: *mut SmbiosEntryPoint) {
    let table_addr = (*entry).table_address as *mut u8;
    let table_length = (*entry).table_length as usize;
    
    let mut ptr = table_addr;
    let end = table_addr.add(table_length);
    
    while ptr < end {
        let header = ptr as *mut SmbiosHeader;
        let header_type = (*header).stype;
        let header_length = (*header).length as usize;
        
        // Process based on structure type
        match header_type {
            SMBIOS_TYPE_SYSTEM => {
                spoof_system_info(ptr, header_length);
            }
            SMBIOS_TYPE_BASEBOARD => {
                spoof_baseboard_info(ptr, header_length);
            }
            SMBIOS_TYPE_CHASSIS => {
                spoof_chassis_info(ptr, header_length);
            }
            SMBIOS_TYPE_MEMORY_DEVICE => {
                spoof_memory_device(ptr, header_length);
            }
            SMBIOS_TYPE_BATTERY | SMBIOS_TYPE_POWER_SUPPLY | SMBIOS_TYPE_ONBOARD_DEVICES => {
                spoof_generic_strings(ptr, header_length);
            }
            127 => break, // End of table
            _ => {}
        }
        
        // Move to next structure
        ptr = ptr.add(header_length);
        
        // Skip strings section (double null terminated)
        while ptr < end && (*ptr != 0 || *ptr.add(1) != 0) {
            ptr = ptr.add(1);
        }
        ptr = ptr.add(2); // Skip double null
    }
}

unsafe fn spoof_system_info(ptr: *mut u8, header_len: usize) {
    // System Information (Type 1) structure
    #[repr(C, packed)]
    struct SystemInfo {
        header: SmbiosHeader,
        manufacturer: u8,
        product_name: u8,
        version: u8,
        serial_number: u8,
        uuid: [u8; 16],
        wake_up_type: u8,
        sku_number: u8,
        family: u8,
    }
    
    if header_len >= mem::size_of::<SystemInfo>() {
        let sys_info = ptr as *mut SystemInfo;
        
        // Randomize UUID
        let guid = crate::random_guid();
        (*sys_info).uuid.copy_from_slice(guid.as_bytes());
        
        // Spoof strings
        spoof_smbios_strings(ptr.add(header_len));
    }
}

unsafe fn spoof_baseboard_info(ptr: *mut u8, header_len: usize) {
    // Spoof baseboard strings
    spoof_smbios_strings(ptr.add(header_len));
}

unsafe fn spoof_chassis_info(ptr: *mut u8, header_len: usize) {
    #[repr(C, packed)]
    struct ChassisInfo {
        header: SmbiosHeader,
        manufacturer: u8,
        chassis_type: u8,
        version: u8,
        serial_number: u8,
        asset_tag: u8,
        // More fields...
    }
    
    if header_len >= 9 {
        // Spoof chassis serial and asset tag strings
        spoof_smbios_strings(ptr.add(header_len));
    }
}

unsafe fn spoof_memory_device(ptr: *mut u8, header_len: usize) {
    #[repr(C, packed)]
    struct MemoryDevice {
        header: SmbiosHeader,
        physical_memory_array_handle: u16,
        memory_error_info_handle: u16,
        total_width: u16,
        data_width: u16,
        size: u16,
        form_factor: u8,
        device_set: u8,
        device_locator: u8,
        bank_locator: u8,
        memory_type: u8,
        type_detail: u16,
        speed: u16,
        manufacturer: u8,
        serial_number: u8,
        asset_tag: u8,
        part_number: u8,
        // More fields...
    }
    
    // Spoof memory device strings (manufacturer, serial, part number)
    spoof_smbios_strings(ptr.add(header_len));
}

unsafe fn spoof_generic_strings(ptr: *mut u8, header_len: usize) {
    spoof_smbios_strings(ptr.add(header_len));
}

unsafe fn spoof_smbios_strings(mut string_ptr: *mut u8) {
    // SMBIOS strings are located after the structure
    // They are indexed starting from 1, terminated by null, 
    // and the string section ends with double null
    
    while *string_ptr != 0 || *string_ptr.add(1) != 0 {
        if *string_ptr != 0 {
            // Found a string, spoof it
            let mut len = 0;
            let start = string_ptr;
            
            // Find string length
            while *string_ptr != 0 {
                len += 1;
                string_ptr = string_ptr.add(1);
            }
            
            // Generate random string
            let random = crate::random_ascii_string(len);
            core::ptr::copy_nonoverlapping(random.as_ptr(), start, len);
        } else {
            string_ptr = string_ptr.add(1);
        }
    }
}

unsafe fn recalculate_smbios_checksum(entry: *mut SmbiosEntryPoint) {
    // Recalculate entry point checksum
    let bytes = core::slice::from_raw_parts(entry as *const u8, (*entry).length as usize);
    let mut sum: u8 = 0;
    
    for i in 0..bytes.len() {
        if i != 4 { // Skip checksum field itself
            sum = sum.wrapping_add(bytes[i]);
        }
    }
    
    (*entry).checksum = (!sum).wrapping_add(1);
    
    // Recalculate intermediate checksum
    let intermediate_start = 0x10;
    let intermediate_len = 0x0F;
    sum = 0;
    
    for i in intermediate_start..(intermediate_start + intermediate_len) {
        if i != 0x1C { // Skip intermediate checksum field
            sum = sum.wrapping_add(bytes[i]);
        }
    }
    
    (*entry).intermediate_checksum = (!sum).wrapping_add(1);
    
    info!("[SMBIOS] Checksums recalculated");
}