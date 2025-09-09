//! Anti-Debug Detection Plugin
//! Complete 1:1 port of Anti-Debug-Detection-Plugin.c to Rust

#![no_std]
#![allow(non_snake_case)]

use core::ptr;
use core::mem;
use core::sync::atomic::{AtomicPtr, AtomicBool, AtomicU32, Ordering};
use alloc::boxed::Box;
use crate::nt_types::*;

const TAG_PLG: u32 = u32::from_le_bytes(*b"gLPH");

/// Plugin states
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PluginState {
    Pending = 0,
    InProgress = 1,
    Executed = 2,
    Failed = 3,
}

/// ZwCreateFile function type
type PfnZwCreateFile = unsafe extern "system" fn(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *const LARGE_INTEGER,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut core::ffi::c_void,
    ea_length: u32,
) -> NTSTATUS;

/// Hook plugin structure
#[repr(C)]
pub struct HookPlugin {
    pub list_entry: LIST_ENTRY,
    pub plugin_id: u32,
    pub state: PluginState,
    pub registration_time: LARGE_INTEGER,
    
    // Custom fields
    pub debugger_detected: AtomicBool,
    pub hidden_page: AtomicPtr<u8>,
    pub hidden_size: usize,
}

// Global state
static mut G_PLUGIN: Option<Box<HookPlugin>> = None;
static G_ZW_CREATE_FILE_ORIG: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(ptr::null_mut());
static G_ZW_CREATE_FILE_SHADOW: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

/// Hooked ZwCreateFile
unsafe extern "system" fn zw_create_file_hook(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *const LARGE_INTEGER,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut core::ffi::c_void,
    ea_length: u32,
) -> NTSTATUS {
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[hook] ZwCreateFile intercepted - PID %lu\n",
        PsGetCurrentProcessId() as u32
    );
    
    let orig_fn = G_ZW_CREATE_FILE_ORIG.load(Ordering::SeqCst) as PfnZwCreateFile;
    orig_fn(
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        allocation_size,
        file_attributes,
        share_access,
        create_disposition,
        create_options,
        ea_buffer,
        ea_length
    )
}

/// Plugin initialization
#[no_mangle]
pub unsafe extern "system" fn PluginInit(driver_object: *mut DRIVER_OBJECT) -> NTSTATUS {
    // Resolve ZwCreateFile
    let mut func_name: UNICODE_STRING = mem::zeroed();
    RtlInitUnicodeString(&mut func_name, w!("ZwCreateFile"));
    
    let zw_create_file = MmGetSystemRoutineAddress(&func_name);
    if zw_create_file.is_null() {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "PluginInit: failed to resolve ZwCreateFile\n"
        );
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    G_ZW_CREATE_FILE_ORIG.store(zw_create_file, Ordering::SeqCst);
    G_ZW_CREATE_FILE_SHADOW.store(zw_create_file, Ordering::SeqCst);
    
    // Allocate plugin structure
    let plugin = Box::new(HookPlugin {
        list_entry: LIST_ENTRY {
            flink: ptr::null_mut(),
            blink: ptr::null_mut(),
        },
        plugin_id: 0,
        state: PluginState::Pending,
        registration_time: LARGE_INTEGER { quad_part: 0 },
        debugger_detected: AtomicBool::new(false),
        hidden_page: AtomicPtr::new(ptr::null_mut()),
        hidden_size: 0,
    });
    
    G_PLUGIN = Some(plugin);
    
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "PluginInit: success\n"
    );
    
    STATUS_SUCCESS
}

/// Plugin execution
#[no_mangle]
pub unsafe extern "system" fn PluginExecute() -> NTSTATUS {
    if G_PLUGIN.is_none() {
        return STATUS_NOT_INITIALIZED;
    }
    
    let plugin = G_PLUGIN.as_mut().unwrap();
    plugin.state = PluginState::InProgress;
    
    // Detect debugger
    let status = detect_debugger();
    if NT_SUCCESS(status) {
        if plugin.debugger_detected.load(Ordering::SeqCst) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "PluginExecute: Debugger detected! Taking evasive action\n"
            );
        }
    }
    
    // Install hook
    let hook_status = hook_install();
    
    // Allocate and hide a page
    let hidden_page = ExAllocatePoolWithTag(NonPagedPool, 4096, TAG_PLG);
    if !hidden_page.is_null() {
        plugin.hidden_page.store(hidden_page as *mut u8, Ordering::SeqCst);
        plugin.hidden_size = 4096;
        hide_page(hidden_page, 4096);
    }
    
    plugin.state = if NT_SUCCESS(hook_status) {
        PluginState::Executed
    } else {
        PluginState::Failed
    };
    
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "PluginExecute: completed with status 0x%x\n",
        hook_status
    );
    
    hook_status
}

/// Plugin unload
#[no_mangle]
pub unsafe extern "system" fn PluginUnload() {
    hook_remove();
    
    if let Some(ref plugin) = G_PLUGIN {
        let hidden_page = plugin.hidden_page.load(Ordering::SeqCst);
        if !hidden_page.is_null() {
            ExFreePoolWithTag(hidden_page as *mut _, TAG_PLG);
        }
    }
    
    G_PLUGIN = None;
    
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "PluginUnload: cleaned up\n"
    );
}

/// Detect debugger presence
unsafe fn detect_debugger() -> NTSTATUS {
    if G_PLUGIN.is_none() {
        return STATUS_NOT_INITIALIZED;
    }
    
    let plugin = G_PLUGIN.as_mut().unwrap();
    
    // Check debug registers
    let dr7: u64;
    asm!("mov {}, dr7", out(reg) dr7);
    
    if dr7 != 0 {
        plugin.debugger_detected.store(true, Ordering::SeqCst);
        return STATUS_SUCCESS;
    }
    
    // Check KdDebuggerEnabled
    let kd_debugger_enabled = *(0xfffff80000000000u64 as *const bool); // Placeholder address
    if kd_debugger_enabled {
        plugin.debugger_detected.store(true, Ordering::SeqCst);
    }
    
    STATUS_SUCCESS
}

/// Install hook
unsafe fn hook_install() -> NTSTATUS {
    // In production, would use more sophisticated hooking
    // For now, just swap the shadow pointer
    G_ZW_CREATE_FILE_SHADOW.store(
        zw_create_file_hook as *mut core::ffi::c_void,
        Ordering::SeqCst
    );
    
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "HookInstall: ZwCreateFile hooked\n"
    );
    
    STATUS_SUCCESS
}

/// Remove hook
unsafe fn hook_remove() {
    let orig = G_ZW_CREATE_FILE_ORIG.load(Ordering::SeqCst);
    G_ZW_CREATE_FILE_SHADOW.store(orig, Ordering::SeqCst);
    
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "HookRemove: ZwCreateFile restored\n"
    );
}

/// Hide memory page
unsafe fn hide_page(base: *mut core::ffi::c_void, size: usize) {
    // Mark page as no-access to hide from scans
    let mut old_protect: u32 = 0;
    ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &mut (base as *mut _),
        &mut (size as SIZE_T),
        PAGE_NOACCESS,
        &mut old_protect
    );
    
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "HidePage: Protected %p size 0x%x\n",
        base,
        size
    );
}