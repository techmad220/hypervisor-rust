//! IOCTL Handler - 1:1 port of DeviceIoControl handling

use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::km::wdm::*;
use crate::PLUGIN_MANAGER;

// IOCTL definitions
pub const IOCTL_REGISTER_PLUGIN: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_EXECUTE_PLUGINS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_UNREGISTER_PLUGIN: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_GET_NEXT_PLUGIN: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_WAIT_FOR_EXECUTION: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_EXECUTION_ACK: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Handle IOCTL requests
pub unsafe fn handle_ioctl(irp: *mut IRP, control_code: u32) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let input_buffer = (*irp).AssociatedIrp.SystemBuffer;
    let input_size = (*stack).Parameters.DeviceIoControl.InputBufferLength;
    let output_size = (*stack).Parameters.DeviceIoControl.OutputBufferLength;
    
    match control_code {
        IOCTL_REGISTER_PLUGIN => {
            if output_size < core::mem::size_of::<u32>() as u32 {
                (*irp).IoStatus.Information = 0;
                return STATUS_BUFFER_TOO_SMALL;
            }
            
            match PLUGIN_MANAGER.lock().register_plugin() {
                Ok(plugin_id) => {
                    *(input_buffer as *mut u32) = plugin_id;
                    (*irp).IoStatus.Information = core::mem::size_of::<u32>();
                    
                    DbgPrint(
                        b"[IOCTL] Registered plugin ID: %u\n\0".as_ptr() as *const i8,
                        plugin_id
                    );
                    
                    STATUS_SUCCESS
                }
                Err(status) => {
                    (*irp).IoStatus.Information = 0;
                    status
                }
            }
        }
        
        IOCTL_EXECUTE_PLUGINS => {
            PLUGIN_MANAGER.lock().execute_all();
            (*irp).IoStatus.Information = 0;
            
            DbgPrint(b"[IOCTL] Executing all plugins\n\0".as_ptr() as *const i8);
            
            STATUS_SUCCESS
        }
        
        IOCTL_GET_NEXT_PLUGIN => {
            if output_size < core::mem::size_of::<u32>() as u32 {
                (*irp).IoStatus.Information = 0;
                return STATUS_BUFFER_TOO_SMALL;
            }
            
            if let Some(plugin_id) = PLUGIN_MANAGER.lock().get_next_pending() {
                *(input_buffer as *mut u32) = plugin_id;
                (*irp).IoStatus.Information = core::mem::size_of::<u32>();
                
                DbgPrint(
                    b"[IOCTL] Next pending plugin: %u\n\0".as_ptr() as *const i8,
                    plugin_id
                );
                
                STATUS_SUCCESS
            } else {
                *(input_buffer as *mut u32) = 0;
                (*irp).IoStatus.Information = core::mem::size_of::<u32>();
                STATUS_NO_MORE_ENTRIES
            }
        }
        
        IOCTL_EXECUTION_ACK => {
            if input_size < core::mem::size_of::<u32>() as u32 {
                (*irp).IoStatus.Information = 0;
                return STATUS_INVALID_PARAMETER;
            }
            
            let plugin_id = *(input_buffer as *const u32);
            
            match PLUGIN_MANAGER.lock().mark_executed(plugin_id) {
                Ok(()) => {
                    (*irp).IoStatus.Information = 0;
                    
                    DbgPrint(
                        b"[IOCTL] Plugin %u acknowledged\n\0".as_ptr() as *const i8,
                        plugin_id
                    );
                    
                    STATUS_SUCCESS
                }
                Err(status) => {
                    (*irp).IoStatus.Information = 0;
                    status
                }
            }
        }
        
        IOCTL_WAIT_FOR_EXECUTION => {
            // This would block waiting for execution event
            // For now, return immediately
            (*irp).IoStatus.Information = 0;
            STATUS_SUCCESS
        }
        
        IOCTL_UNREGISTER_PLUGIN => {
            // TODO: Implement plugin unregistration
            (*irp).IoStatus.Information = 0;
            STATUS_NOT_IMPLEMENTED
        }
        
        _ => {
            DbgPrint(
                b"[IOCTL] Unknown control code: 0x%X\n\0".as_ptr() as *const i8,
                control_code
            );
            
            (*irp).IoStatus.Information = 0;
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

extern "system" {
    fn IoGetCurrentIrpStackLocation(Irp: *mut IRP) -> *mut IO_STACK_LOCATION;
    fn DbgPrint(Format: *const i8, ...) -> NTSTATUS;
}