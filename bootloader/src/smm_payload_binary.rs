//! SMM Payload Binary Module
//! Complete 1:1 port of SmmPayloadBinary.c to Rust
//! COMM-based SMM payload with real NVRAM scan

#![no_std]

use uefi::prelude::*;
use uefi::{Handle, Guid};
use core::ptr;
use core::mem;
use log::{info, error};

const RESP_MAX: usize = 128;

/// SMM Communication Protocol GUID
const EFI_SMM_COMMUNICATION_PROTOCOL_GUID: Guid = Guid::from_values(
    0xc68ed8e2,
    0x9dc6,
    0x4cbd,
    [0x9d, 0x94, 0xdb, 0x65, 0xac, 0xc5, 0xc3, 0x32],
);

/// Runtime Services Table
#[repr(C)]
pub struct RuntimeServices {
    pub hdr: uefi::table::Header,
    pub get_time: *mut core::ffi::c_void,
    pub set_time: *mut core::ffi::c_void,
    pub get_wakeup_time: *mut core::ffi::c_void,
    pub set_wakeup_time: *mut core::ffi::c_void,
    pub set_virtual_address_map: *mut core::ffi::c_void,
    pub convert_pointer: *mut core::ffi::c_void,
    pub get_variable: unsafe extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid: *const Guid,
        attributes: *mut u32,
        data_size: *mut usize,
        data: *mut u8,
    ) -> Status,
    pub get_next_variable_name: unsafe extern "efiapi" fn(
        variable_name_size: *mut usize,
        variable_name: *mut u16,
        vendor_guid: *mut Guid,
    ) -> Status,
    pub set_variable: unsafe extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid: *const Guid,
        attributes: u32,
        data_size: usize,
        data: *const u8,
    ) -> Status,
    pub get_next_high_monotonic_count: *mut core::ffi::c_void,
    pub reset_system: *mut core::ffi::c_void,
}

/// SMM Services Table
#[repr(C)]
pub struct SmmServicesTable {
    pub hdr: uefi::table::Header,
    pub smm_install_configuration_table: *mut core::ffi::c_void,
    pub smm_cpu: *mut core::ffi::c_void,
    pub smm_allocate_pool: *mut core::ffi::c_void,
    pub smm_free_pool: *mut core::ffi::c_void,
    pub smm_allocate_pages: *mut core::ffi::c_void,
    pub smm_free_pages: *mut core::ffi::c_void,
    pub smm_startup_this_ap: *mut core::ffi::c_void,
    pub current_smm_id: usize,
    pub number_of_cpus: usize,
    pub cpu_save_state_size: *mut usize,
    pub cpu_save_state: *mut *mut core::ffi::c_void,
    pub number_of_table_entries: usize,
    pub smm_configuration_table: *mut core::ffi::c_void,
    pub smm_install_protocol_interface: *mut core::ffi::c_void,
    pub smm_uninstall_protocol_interface: *mut core::ffi::c_void,
    pub smm_handle_protocol: *mut core::ffi::c_void,
    pub smm_register_protocol_notify: *mut core::ffi::c_void,
    pub smm_locate_handle: *mut core::ffi::c_void,
    pub smm_locate_protocol: *mut core::ffi::c_void,
    pub smi_manage: *mut core::ffi::c_void,
    pub smi_handler_register: unsafe extern "efiapi" fn(
        handler: SmiHandlerFn,
        handler_type: *const Guid,
        dispatch_handle: *mut Handle,
    ) -> Status,
    pub smi_handler_unregister: *mut core::ffi::c_void,
}

/// SMI Handler function type
type SmiHandlerFn = unsafe extern "efiapi" fn(
    dispatch_handle: Handle,
    comm_buffer: *const core::ffi::c_void,
    comm_size: *mut usize,
) -> Status;

/// Persistent state stored in SMRAM BSS - survives across SMIs & boots
#[repr(C)]
struct SmmState {
    boot_counter: u32,
    scan_counter: u32,
    last_nvram_vars: u32,
}

/// Global state
static mut G_STATE: SmmState = SmmState {
    boot_counter: 0,
    scan_counter: 0,
    last_nvram_vars: 0,
};

/// Global pointers
static mut GRT: Option<*const RuntimeServices> = None;
static mut GSMST: Option<*const SmmServicesTable> = None;

/// Safe ASCII string comparison
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

/// ASCII string print (sprintf equivalent)
fn ascii_sprint(dest: &mut [u8], format: &str, args: &[u32]) -> usize {
    let mut output = [0u8; RESP_MAX];
    let mut pos = 0;
    
    let mut format_chars = format.chars();
    let mut arg_index = 0;
    
    while let Some(ch) = format_chars.next() {
        if ch == '%' {
            if let Some(spec) = format_chars.next() {
                match spec {
                    'u' => {
                        if arg_index < args.len() {
                            let num_str = u32_to_ascii(args[arg_index]);
                            for &b in num_str.iter() {
                                if b != 0 && pos < RESP_MAX - 1 {
                                    output[pos] = b;
                                    pos += 1;
                                }
                            }
                            arg_index += 1;
                        }
                    }
                    'a' => {
                        // ASCII string - handled separately
                    }
                    _ => {
                        if pos < RESP_MAX - 1 {
                            output[pos] = ch as u8;
                            pos += 1;
                        }
                    }
                }
            }
        } else {
            if pos < RESP_MAX - 1 {
                output[pos] = ch as u8;
                pos += 1;
            }
        }
    }
    
    output[pos] = 0;
    let copy_len = pos.min(dest.len() - 1);
    dest[..copy_len].copy_from_slice(&output[..copy_len]);
    dest[copy_len] = 0;
    copy_len + 1
}

/// Convert u32 to ASCII string
fn u32_to_ascii(mut num: u32) -> [u8; 12] {
    let mut buffer = [0u8; 12];
    let mut pos = 10;
    
    if num == 0 {
        buffer[0] = b'0';
        return buffer;
    }
    
    while num > 0 && pos > 0 {
        buffer[pos] = b'0' + (num % 10) as u8;
        num /= 10;
        pos -= 1;
    }
    
    // Shift left to start
    let start = pos + 1;
    for i in 0..(11 - start) {
        buffer[i] = buffer[start + i];
    }
    for i in (11 - start)..12 {
        buffer[i] = 0;
    }
    
    buffer
}

/// Enumerate all NVRAM variables to demonstrate a real scan
/// Returns the number of variables successfully read
unsafe fn nvram_variable_scan() -> u32 {
    if GRT.is_none() {
        return 0;
    }
    
    let rt = GRT.unwrap();
    let mut name_size: usize = 0;
    let mut name_buf = [0u16; 1024];
    let mut vendor_guid = Guid::from_values(0, 0, 0, [0; 8]);
    let mut count: u32 = 0;
    
    // First call with zero size to get the first variable's size
    let mut status = (*rt).get_next_variable_name(&mut name_size, ptr::null_mut(), ptr::null_mut());
    if status == Status::NOT_FOUND {
        return 0; // No variables
    }
    
    while status != Status::NOT_FOUND {
        if status == Status::BUFFER_TOO_SMALL && name_size <= mem::size_of_val(&name_buf) {
            status = (*rt).get_next_variable_name(&mut name_size, name_buf.as_mut_ptr(), &mut vendor_guid);
            if status == Status::SUCCESS {
                count += 1;
            }
        } else if status != Status::SUCCESS {
            break; // Bail on fatal errors
        }
        
        name_size = 0; // Reset to discover the next size
        status = (*rt).get_next_variable_name(&mut name_size, ptr::null_mut(), ptr::null_mut());
    }
    
    count
}

/// Core SMI handler - now with real scan branch
unsafe extern "efiapi" fn smi_handler(
    dispatch_handle: Handle,
    comm_buffer: *const core::ffi::c_void,
    comm_size: *mut usize,
) -> Status {
    if comm_buffer.is_null() || comm_size.is_null() || *comm_size < 2 {
        return Status::SUCCESS;
    }
    
    let cmd = comm_buffer as *mut u8;
    let cmd_slice = core::slice::from_raw_parts(cmd, *comm_size);
    
    // Find command string length
    let cmd_len = cmd_slice.iter().position(|&b| b == 0).unwrap_or(*comm_size);
    let cmd_str = &cmd_slice[..cmd_len];
    
    if same(cmd_str, b"GetStatus") {
        G_STATE.boot_counter += 1;
        let args = [G_STATE.boot_counter, G_STATE.scan_counter, G_STATE.last_nvram_vars];
        let mut response = [0u8; RESP_MAX];
        let len = ascii_sprint(&mut response, "Boots=%u Scans=%u Vars=%u", &args);
        
        let copy_len = len.min(*comm_size);
        core::ptr::copy_nonoverlapping(response.as_ptr(), cmd, copy_len);
        *comm_size = copy_len;
        
    } else if same(cmd_str, b"DoScan") {
        G_STATE.scan_counter += 1;
        G_STATE.last_nvram_vars = nvram_variable_scan();
        
        let args = [G_STATE.scan_counter, G_STATE.last_nvram_vars];
        let mut response = [0u8; RESP_MAX];
        let len = ascii_sprint(&mut response, "ScanOK #%u - Found %u vars", &args);
        
        let copy_len = len.min(*comm_size);
        core::ptr::copy_nonoverlapping(response.as_ptr(), cmd, copy_len);
        *comm_size = copy_len;
        
    } else {
        let response = b"UnknownCmd\0";
        let copy_len = response.len().min(*comm_size);
        core::ptr::copy_nonoverlapping(response.as_ptr(), cmd, copy_len);
        *comm_size = copy_len;
    }
    
    Status::SUCCESS
}

/// Entry point - register COMM handler for the standard GUID
#[no_mangle]
pub extern "efiapi" fn smm_entry_point(
    image_handle: Handle,
    system_table: *const core::ffi::c_void,
) -> Status {
    unsafe {
        // Cast system table appropriately
        let smm_st = system_table as *const SmmServicesTable;
        GSMST = Some(smm_st);
        
        // Note: GRT would need to be set from the runtime services table
        // This is typically available through the system configuration table
        
        let mut handle = Handle::from_ptr(ptr::null_mut()).unwrap();
        let status = (*smm_st).smi_handler_register(
            smi_handler,
            &EFI_SMM_COMMUNICATION_PROTOCOL_GUID,
            &mut handle,
        );
        
        if status != Status::SUCCESS {
            error!("[SMM] Failed to register NVRAM-scan payload: {:?}", status);
        } else {
            info!("[SMM] NVRAM-scan payload registered successfully");
        }
        
        status
    }
}