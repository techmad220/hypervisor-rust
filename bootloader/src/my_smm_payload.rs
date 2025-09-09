//! SMM Payload Module
//! Complete 1:1 port of MySmmPayload.c to Rust

#![no_std]

use uefi::prelude::*;
use uefi::proto::console::text::SimpleTextOutput;
use uefi::{Handle, Guid};
use core::ptr;
use core::slice;
use log::info;

/// SMM SW Dispatch Protocol GUID
const EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID: Guid = Guid::from_values(
    0x18a3c6dc,
    0x5eea,
    0x48c8,
    [0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99],
);

/// SMM System Table
#[repr(C)]
pub struct SmmSystemTable {
    pub hdr: uefi::table::Header,
    pub vendor: *const u16,
    pub revision: u32,
    pub smm_io: *mut core::ffi::c_void,
    pub smm_allocate_pool: unsafe extern "efiapi" fn(
        pool_type: uefi::table::boot::MemoryType,
        size: usize,
        buffer: *mut *mut u8,
    ) -> Status,
    pub smm_free_pool: unsafe extern "efiapi" fn(buffer: *mut u8) -> Status,
    pub smm_allocate_pages: unsafe extern "efiapi" fn(
        alloc_type: uefi::table::boot::AllocateType,
        memory_type: uefi::table::boot::MemoryType,
        pages: usize,
        memory: *mut u64,
    ) -> Status,
    pub smm_free_pages: unsafe extern "efiapi" fn(memory: u64, pages: usize) -> Status,
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
    pub smm_locate_protocol: unsafe extern "efiapi" fn(
        protocol: *const Guid,
        registration: *mut core::ffi::c_void,
        interface: *mut *mut core::ffi::c_void,
    ) -> Status,
}

/// SMM SW Dispatch Context
#[repr(C)]
pub struct SmmSwRegisterContext {
    pub sw_smi_input_value: u64,
}

/// SMM SW Dispatch Protocol
#[repr(C)]
pub struct SmmSwDispatch2Protocol {
    pub register: unsafe extern "efiapi" fn(
        this: *const SmmSwDispatch2Protocol,
        handler: SmiHandlerFn,
        context: *const SmmSwRegisterContext,
        handle: *mut Handle,
    ) -> Status,
    pub unregister: unsafe extern "efiapi" fn(
        this: *const SmmSwDispatch2Protocol,
        handle: Handle,
    ) -> Status,
    pub maximum_sw_smi_value: u64,
}

/// SMI Handler function type
type SmiHandlerFn = unsafe extern "efiapi" fn(
    dispatch_handle: Handle,
    context: *const core::ffi::c_void,
    comm_buffer: *mut core::ffi::c_void,
    comm_buffer_size: *mut usize,
) -> Status;

/// Global SMM System Table pointer
static mut GSMST: Option<*const SmmSystemTable> = None;

/// SMI Handler implementation
unsafe extern "efiapi" fn smi_handler(
    dispatch_handle: Handle,
    context: *const core::ffi::c_void,
    comm_buffer: *mut core::ffi::c_void,
    comm_buffer_size: *mut usize,
) -> Status {
    info!("SMI Triggered!");

    if !comm_buffer.is_null() && !comm_buffer_size.is_null() {
        let buffer_size = *comm_buffer_size;
        let cmd_bytes = slice::from_raw_parts_mut(comm_buffer as *mut u8, buffer_size);
        
        // Find null terminator to get command string
        let cmd_len = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(buffer_size);
        let cmd_str = core::str::from_utf8_unchecked(&cmd_bytes[..cmd_len]);
        
        info!("SMM Command Received: {}", cmd_str);

        let response = match cmd_str {
            "GetStatus" => b"Status OK\0",
            "DoScan" => b"Scan Done\0",
            _ => b"Unknown Command\0",
        };

        // Copy response back to buffer
        let response_len = response.len().min(buffer_size);
        cmd_bytes[..response_len].copy_from_slice(&response[..response_len]);
    }

    Status::SUCCESS
}

/// SMM Entry Point
#[no_mangle]
pub extern "efiapi" fn smm_entry_point(
    image_handle: Handle,
    system_table: *const SmmSystemTable,
) -> Status {
    unsafe {
        // Store global SMM system table
        GSMST = Some(system_table);
        
        // Locate SMM SW Dispatch Protocol
        let mut sw_dispatch: *mut SmmSwDispatch2Protocol = ptr::null_mut();
        let status = (*system_table).smm_locate_protocol(
            &EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID,
            ptr::null_mut(),
            &mut sw_dispatch as *mut _ as *mut *mut core::ffi::c_void,
        );
        
        if status != Status::SUCCESS {
            return status;
        }

        // Register SMI handler
        let sw_context = SmmSwRegisterContext {
            sw_smi_input_value: 0x42, // Custom SMI value
        };
        
        let mut handle = Handle::from_ptr(ptr::null_mut()).unwrap();
        let status = (*sw_dispatch).register(
            sw_dispatch,
            smi_handler,
            &sw_context,
            &mut handle,
        );
        
        if status != Status::SUCCESS {
            return status;
        }

        info!("SMM Payload Loaded and Handler Registered!");
        Status::SUCCESS
    }
}

/// ASCII string comparison
fn ascii_strcmp(s1: &[u8], s2: &[u8]) -> bool {
    if s1.len() != s2.len() {
        return false;
    }
    s1.iter().zip(s2.iter()).all(|(a, b)| a == b)
}

/// Copy ASCII string safely
fn ascii_strcpy_s(dest: &mut [u8], src: &[u8]) {
    let copy_len = src.len().min(dest.len() - 1);
    dest[..copy_len].copy_from_slice(&src[..copy_len]);
    dest[copy_len] = 0;
}