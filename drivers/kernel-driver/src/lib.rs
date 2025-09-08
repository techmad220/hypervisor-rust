//! Windows Kernel Driver - Main Entry Point
//! 1:1 port of Techmad.c and MmTechmad.c

#![no_std]
#![feature(lang_items)]

extern crate alloc;

mod plugin_system;
mod pe_loader;
mod ioctl;
mod memory;

use winapi::km::wdm::*;
use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use core::mem;
use spin::Mutex;
use lazy_static::lazy_static;

// Device names
const DEVICE_NAME: &[u16] = w!("\\Device\\MemoryScanner");
const SYMBOLIC_LINK: &[u16] = w!("\\??\\MemoryScanner");

// Global driver state
lazy_static! {
    static ref DEVICE_OBJECT: Mutex<Option<*mut DEVICE_OBJECT>> = Mutex::new(None);
    static ref PLUGIN_MANAGER: Mutex<plugin_system::PluginManager> = 
        Mutex::new(plugin_system::PluginManager::new());
}

/// Driver entry point
#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        // Set up dispatch routines
        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_close);
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_ioctl);
        (*driver_object).DriverUnload = Some(driver_unload);
        
        // Create device
        let mut device_name = UNICODE_STRING::from_slice(DEVICE_NAME);
        let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
        
        let status = IoCreateDevice(
            driver_object,
            0,
            &mut device_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &mut device_object,
        );
        
        if !NT_SUCCESS(status) {
            return status;
        }
        
        // Create symbolic link
        let mut symbolic_link = UNICODE_STRING::from_slice(SYMBOLIC_LINK);
        let status = IoCreateSymbolicLink(&mut symbolic_link, &mut device_name);
        
        if !NT_SUCCESS(status) {
            IoDeleteDevice(device_object);
            return status;
        }
        
        // Store device object
        *DEVICE_OBJECT.lock() = Some(device_object);
        
        // Initialize plugin system
        PLUGIN_MANAGER.lock().initialize();
        
        DbgPrint(b"[HypervisorDriver] Driver loaded successfully\n\0".as_ptr() as *const i8);
        
        STATUS_SUCCESS
    }
}

/// Driver unload routine
unsafe extern "system" fn driver_unload(driver_object: *mut DRIVER_OBJECT) {
    DbgPrint(b"[HypervisorDriver] Unloading driver\n\0".as_ptr() as *const i8);
    
    // Cleanup plugin system
    PLUGIN_MANAGER.lock().cleanup();
    
    // Delete symbolic link
    let mut symbolic_link = UNICODE_STRING::from_slice(SYMBOLIC_LINK);
    IoDeleteSymbolicLink(&mut symbolic_link);
    
    // Delete device
    if let Some(device) = *DEVICE_OBJECT.lock() {
        IoDeleteDevice(device);
    }
}

/// IRP_MJ_CREATE handler
unsafe extern "system" fn dispatch_create(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    (*irp).IoStatus.Status = STATUS_SUCCESS;
    (*irp).IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    STATUS_SUCCESS
}

/// IRP_MJ_CLOSE handler
unsafe extern "system" fn dispatch_close(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    (*irp).IoStatus.Status = STATUS_SUCCESS;
    (*irp).IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    STATUS_SUCCESS
}

/// IRP_MJ_DEVICE_CONTROL handler
unsafe extern "system" fn dispatch_ioctl(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;
    
    DbgPrint(
        b"[HypervisorDriver] IOCTL: 0x%X\n\0".as_ptr() as *const i8,
        control_code
    );
    
    let status = ioctl::handle_ioctl(irp, control_code);
    
    (*irp).IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    status
}

// Helper functions
impl UNICODE_STRING {
    fn from_slice(s: &[u16]) -> Self {
        UNICODE_STRING {
            Length: ((s.len() - 1) * 2) as u16,
            MaximumLength: (s.len() * 2) as u16,
            Buffer: s.as_ptr() as *mut u16,
        }
    }
}

// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        DbgPrint(b"[HypervisorDriver] PANIC!\n\0".as_ptr() as *const i8);
    }
    loop {}
}

// Language items
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

// Wide string literal macro
macro_rules! w {
    ($s:expr) => {{
        concat!($s, "\0").encode_utf16().collect::<Vec<u16>>().as_slice()
    }};
}