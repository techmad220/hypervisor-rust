// Complete 1:1 port of Techmad.c to Rust
#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::mem;
use core::ptr;
use winapi::km::*;
use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::um::winioctl::*;

// IOCTL definitions - exact match to C
const IOCTL_REGISTER_PLUGIN: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
const IOCTL_EXECUTE_PLUGINS: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
const IOCTL_UNREGISTER_PLUGIN: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
const IOCTL_GET_NEXT_PLUGIN: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
const IOCTL_WAIT_FOR_EXECUTION: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
const IOCTL_EXECUTION_ACK: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

// Plugin state definitions - exact match to C
const PLUGIN_STATE_PENDING: u32 = 0;      // Not yet executed, waiting for execution
const PLUGIN_STATE_EXECUTED: u32 = 1;     // Execution completed (or initially executed)
const PLUGIN_STATE_IN_PROGRESS: u32 = 2;  // In the process of being executed

// Plugin structure - matches C _PLUGIN
#[repr(C)]
struct PLUGIN {
    ListEntry: LIST_ENTRY,
    PluginId: u32,
    State: u32,  // 0: pending, 1: executed, 2: in progress
}

type PPLUGIN = *mut PLUGIN;

// Global variables matching C exactly
static mut DeviceObject: PDEVICE_OBJECT = ptr::null_mut();
static mut DeviceName: UNICODE_STRING = UNICODE_STRING {
    Length: 50,
    MaximumLength: 50,
    Buffer: w!("\\Device\\MemoryScanner").as_ptr() as *mut u16,
};
static mut SymbolicLink: UNICODE_STRING = UNICODE_STRING {
    Length: 44,
    MaximumLength: 44,
    Buffer: w!("\\??\\MemoryScanner").as_ptr() as *mut u16,
};
static mut PluginList: LIST_ENTRY = LIST_ENTRY {
    Flink: ptr::null_mut(),
    Blink: ptr::null_mut(),
};
static mut PluginMutex: FAST_MUTEX = FAST_MUTEX {
    Count: 0,
    Owner: ptr::null_mut(),
    Contention: 0,
    Event: KEVENT {
        Header: DISPATCHER_HEADER {
            Type: 0,
            Signalling: 0,
            Size: 0,
            Reserved1: 0,
            SignalState: 0,
            WaitListHead: LIST_ENTRY {
                Flink: ptr::null_mut(),
                Blink: ptr::null_mut(),
            },
        },
    },
    OldIrql: 0,
};
static mut PluginExecutionEvent: KEVENT = KEVENT {
    Header: DISPATCHER_HEADER {
        Type: 0,
        Signalling: 0,
        Size: 0,
        Reserved1: 0,
        SignalState: 0,
        WaitListHead: LIST_ENTRY {
            Flink: ptr::null_mut(),
            Blink: ptr::null_mut(),
        },
    },
};
static mut NextPluginId: u32 = 1; // Unique ID generator

// ExecutePlugins - exact match to C
unsafe fn ExecutePlugins() {
    ExAcquireFastMutex(&mut PluginMutex);
    
    let mut entry = PluginList.Flink;
    while entry != &mut PluginList as *mut _ {
        let plugin = CONTAINING_RECORD!(entry, PLUGIN, ListEntry);
        (*plugin).State = PLUGIN_STATE_PENDING; // Mark as pending
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "ExecutePlugins: Plugin %lu marked pending\n\0".as_ptr(),
            (*plugin).PluginId
        );
        entry = (*entry).Flink;
    }
    
    ExReleaseFastMutex(&mut PluginMutex);
    KeSetEvent(&mut PluginExecutionEvent, 0, FALSE);
}

// DeviceIoControlHandler - exact match to C
extern "system" fn DeviceIoControlHandler(
    DeviceObject: PDEVICE_OBJECT,
    Irp: PIRP,
) -> NTSTATUS {
    unsafe {
        let stack = IoGetCurrentIrpStackLocation(Irp);
        let mut status = STATUS_UNSUCCESSFUL;
        let outputSize = (*stack).Parameters.DeviceIoControl.OutputBufferLength;
        
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "IOCTL Code: 0x%X\n\0".as_ptr(),
            (*stack).Parameters.DeviceIoControl.IoControlCode
        );
        
        match (*stack).Parameters.DeviceIoControl.IoControlCode {
            IOCTL_REGISTER_PLUGIN => {
                if (*stack).Parameters.DeviceIoControl.InputBufferLength == mem::size_of::<u32>() as u32 {
                    if outputSize < mem::size_of::<u32>() as u32 {
                        status = STATUS_BUFFER_TOO_SMALL;
                    } else {
                        let newPlugin = ExAllocatePoolWithTag(
                            NonPagedPool,
                            mem::size_of::<PLUGIN>() as u64,
                            'plgM' as u32
                        ) as PPLUGIN;
                        
                        if !newPlugin.is_null() {
                            (*newPlugin).PluginId = NextPluginId;
                            NextPluginId += 1;
                            (*newPlugin).State = PLUGIN_STATE_EXECUTED; // Initially considered executed
                            
                            ExAcquireFastMutex(&mut PluginMutex);
                            InsertTailList(&mut PluginList, &mut (*newPlugin).ListEntry);
                            ExReleaseFastMutex(&mut PluginMutex);
                            
                            *((*Irp).AssociatedIrp.SystemBuffer as *mut u32) = (*newPlugin).PluginId;
                            status = STATUS_SUCCESS;
                            
                            DbgPrintEx(
                                DPFLTR_IHVDRIVER_ID,
                                DPFLTR_INFO_LEVEL,
                                "Registered plugin with ID: %lu\n\0".as_ptr(),
                                (*newPlugin).PluginId
                            );
                        } else {
                            status = STATUS_INSUFFICIENT_RESOURCES;
                        }
                    }
                }
            },
            
            IOCTL_EXECUTE_PLUGINS => {
                ExecutePlugins();
                status = STATUS_SUCCESS;
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_INFO_LEVEL,
                    "Executed plugins: all marked pending\n\0".as_ptr()
                );
            },
            
            IOCTL_GET_NEXT_PLUGIN => {
                if outputSize < mem::size_of::<u32>() as u32 {
                    status = STATUS_BUFFER_TOO_SMALL;
                } else {
                    ExAcquireFastMutex(&mut PluginMutex);
                    
                    let mut entry = PluginList.Flink;
                    let mut pluginId: u32 = 0;
                    
                    while entry != &mut PluginList as *mut _ {
                        let plugin = CONTAINING_RECORD!(entry, PLUGIN, ListEntry);
                        if (*plugin).State == PLUGIN_STATE_PENDING {
                            pluginId = (*plugin).PluginId;
                            (*plugin).State = PLUGIN_STATE_IN_PROGRESS;
                            DbgPrintEx(
                                DPFLTR_IHVDRIVER_ID,
                                DPFLTR_INFO_LEVEL,
                                "GetNextPlugin: Returning plugin %lu (now in progress)\n\0".as_ptr(),
                                pluginId
                            );
                            break;
                        }
                        entry = (*entry).Flink;
                    }
                    
                    *((*Irp).AssociatedIrp.SystemBuffer as *mut u32) = pluginId;
                    (*Irp).IoStatus.Information = mem::size_of::<u32>() as ULONG_PTR;
                    
                    ExReleaseFastMutex(&mut PluginMutex);
                    status = STATUS_SUCCESS;
                }
            },
            
            IOCTL_WAIT_FOR_EXECUTION => {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_INFO_LEVEL,
                    "WaitForExecution: Waiting for event signal\n\0".as_ptr()
                );
                
                let waitStatus = KeWaitForSingleObject(
                    &mut PluginExecutionEvent as *mut _ as PVOID,
                    Executive,
                    KernelMode,
                    FALSE,
                    ptr::null_mut()
                );
                
                if waitStatus == STATUS_SUCCESS {
                    KeClearEvent(&mut PluginExecutionEvent);
                    status = STATUS_SUCCESS;
                    DbgPrintEx(
                        DPFLTR_IHVDRIVER_ID,
                        DPFLTR_INFO_LEVEL,
                        "WaitForExecution: Event signaled, returning\n\0".as_ptr()
                    );
                } else {
                    status = STATUS_UNSUCCESSFUL;
                }
            },
            
            IOCTL_EXECUTION_ACK => {
                if (*stack).Parameters.DeviceIoControl.InputBufferLength == mem::size_of::<u32>() as u32 {
                    let pluginId = *((*Irp).AssociatedIrp.SystemBuffer as *const u32);
                    
                    ExAcquireFastMutex(&mut PluginMutex);
                    
                    let mut entry = PluginList.Flink;
                    while entry != &mut PluginList as *mut _ {
                        let plugin = CONTAINING_RECORD!(entry, PLUGIN, ListEntry);
                        if (*plugin).PluginId == pluginId {
                            (*plugin).State = PLUGIN_STATE_EXECUTED;
                            status = STATUS_SUCCESS;
                            DbgPrintEx(
                                DPFLTR_IHVDRIVER_ID,
                                DPFLTR_INFO_LEVEL,
                                "ExecutionAck: Plugin %lu acknowledged\n\0".as_ptr(),
                                pluginId
                            );
                            break;
                        }
                        entry = (*entry).Flink;
                    }
                    
                    ExReleaseFastMutex(&mut PluginMutex);
                }
            },
            
            IOCTL_UNREGISTER_PLUGIN => {
                if (*stack).Parameters.DeviceIoControl.InputBufferLength == mem::size_of::<u32>() as u32 {
                    let pluginId = *((*Irp).AssociatedIrp.SystemBuffer as *const u32);
                    
                    ExAcquireFastMutex(&mut PluginMutex);
                    
                    let mut entry = PluginList.Flink;
                    while entry != &mut PluginList as *mut _ {
                        let plugin = CONTAINING_RECORD!(entry, PLUGIN, ListEntry);
                        if (*plugin).PluginId == pluginId {
                            let nextEntry = (*entry).Flink;
                            RemoveEntryList(entry);
                            ExFreePoolWithTag(plugin as PVOID, 'plgM' as u32);
                            status = STATUS_SUCCESS;
                            DbgPrintEx(
                                DPFLTR_IHVDRIVER_ID,
                                DPFLTR_INFO_LEVEL,
                                "Unregistered plugin with ID: %lu\n\0".as_ptr(),
                                pluginId
                            );
                            entry = nextEntry;
                        } else {
                            entry = (*entry).Flink;
                        }
                    }
                    
                    ExReleaseFastMutex(&mut PluginMutex);
                }
            },
            
            _ => {
                status = STATUS_INVALID_DEVICE_REQUEST;
            }
        }
        
        (*Irp).IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        status
    }
}

// CreateFileHandler - exact match to C
extern "system" fn CreateFileHandler(
    DeviceObject: PDEVICE_OBJECT,
    Irp: PIRP,
) -> NTSTATUS {
    unsafe {
        (*Irp).IoStatus.Status = STATUS_SUCCESS;
        (*Irp).IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        STATUS_SUCCESS
    }
}

// CloseFileHandler - exact match to C
extern "system" fn CloseFileHandler(
    DeviceObject: PDEVICE_OBJECT,
    Irp: PIRP,
) -> NTSTATUS {
    unsafe {
        (*Irp).IoStatus.Status = STATUS_SUCCESS;
        (*Irp).IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        STATUS_SUCCESS
    }
}

// DriverUnload - exact match to C
extern "system" fn DriverUnload(DriverObject: PDRIVER_OBJECT) {
    unsafe {
        // Clean up plugins
        ExAcquireFastMutex(&mut PluginMutex);
        
        let mut entry = PluginList.Flink;
        while entry != &mut PluginList as *mut _ {
            let plugin = CONTAINING_RECORD!(entry, PLUGIN, ListEntry);
            let nextEntry = (*entry).Flink;
            RemoveEntryList(entry);
            ExFreePoolWithTag(plugin as PVOID, 'plgM' as u32);
            entry = nextEntry;
        }
        
        ExReleaseFastMutex(&mut PluginMutex);
        
        // Delete symbolic link and device
        IoDeleteSymbolicLink(&mut SymbolicLink);
        IoDeleteDevice(DeviceObject);
        
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "MemoryScanner Driver Unloaded\n\0".as_ptr()
        );
    }
}

// DriverEntry - exact match to C
#[no_mangle]
pub extern "system" fn DriverEntry(
    DriverObject: PDRIVER_OBJECT,
    RegistryPath: PUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "MemoryScanner Driver Loading...\n\0".as_ptr()
        );
        
        // Initialize global structures
        InitializeListHead(&mut PluginList);
        ExInitializeFastMutex(&mut PluginMutex);
        KeInitializeEvent(&mut PluginExecutionEvent, NotificationEvent, FALSE);
        
        // Set dispatch routines
        (*DriverObject).DriverUnload = Some(DriverUnload);
        (*DriverObject).MajorFunction[IRP_MJ_CREATE] = Some(CreateFileHandler);
        (*DriverObject).MajorFunction[IRP_MJ_CLOSE] = Some(CloseFileHandler);
        (*DriverObject).MajorFunction[IRP_MJ_DEVICE_CONTROL] = Some(DeviceIoControlHandler);
        
        // Create device
        let mut status = IoCreateDevice(
            DriverObject,
            0,
            &mut DeviceName,
            FILE_DEVICE_UNKNOWN,
            0,
            FALSE,
            &mut DeviceObject
        );
        
        if !NT_SUCCESS(status) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "Failed to create device: 0x%08X\n\0".as_ptr(),
                status
            );
            return status;
        }
        
        // Create symbolic link
        status = IoCreateSymbolicLink(&mut SymbolicLink, &mut DeviceName);
        
        if !NT_SUCCESS(status) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "Failed to create symbolic link: 0x%08X\n\0".as_ptr(),
                status
            );
            IoDeleteDevice(DeviceObject);
            return status;
        }
        
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "MemoryScanner Driver Loaded Successfully\n\0".as_ptr()
        );
        
        STATUS_SUCCESS
    }
}

// Helper macros matching C
macro_rules! CTL_CODE {
    ($DeviceType:expr, $Function:expr, $Method:expr, $Access:expr) => {
        (($DeviceType) << 16) | (($Access) << 14) | (($Function) << 2) | ($Method)
    };
}

macro_rules! CONTAINING_RECORD {
    ($address:expr, $type:ty, $field:ident) => {
        (($address as usize - offset_of!($type, $field)) as *mut $type)
    };
}

macro_rules! offset_of {
    ($type:ty, $field:ident) => {
        unsafe { &(*(ptr::null::<$type>())).$field as *const _ as usize }
    };
}

macro_rules! w {
    ($s:expr) => {
        {
            const S: &[u16] = &wchar::wch!($s);
            S
        }
    };
}

// Constants matching C
const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 0x0001;
const FILE_WRITE_ACCESS: u32 = 0x0002;

const DPFLTR_IHVDRIVER_ID: u32 = 77;
const DPFLTR_INFO_LEVEL: u32 = 3;
const DPFLTR_ERROR_LEVEL: u32 = 0;

const IRP_MJ_CREATE: usize = 0x00;
const IRP_MJ_CLOSE: usize = 0x02;
const IRP_MJ_DEVICE_CONTROL: usize = 0x0e;

const NonPagedPool: POOL_TYPE = 0;
const Executive: KWAIT_REASON = 0;
const KernelMode: KPROCESSOR_MODE = 0;
const NotificationEvent: EVENT_TYPE = 0;
const FALSE: BOOLEAN = 0;
const IO_NO_INCREMENT: u8 = 0;

// Additional type definitions
type POOL_TYPE = u32;
type KWAIT_REASON = u32;
type KPROCESSOR_MODE = u8;
type EVENT_TYPE = u32;
type BOOLEAN = u8;
type ULONG_PTR = usize;

// Function declarations (would be imported from Windows DDK)
extern "system" {
    fn IoCreateDevice(
        DriverObject: PDRIVER_OBJECT,
        DeviceExtensionSize: u32,
        DeviceName: PUNICODE_STRING,
        DeviceType: u32,
        DeviceCharacteristics: u32,
        Exclusive: BOOLEAN,
        DeviceObject: *mut PDEVICE_OBJECT,
    ) -> NTSTATUS;
    
    fn IoCreateSymbolicLink(
        SymbolicLinkName: PUNICODE_STRING,
        DeviceName: PUNICODE_STRING,
    ) -> NTSTATUS;
    
    fn IoDeleteDevice(DeviceObject: PDEVICE_OBJECT);
    
    fn IoDeleteSymbolicLink(SymbolicLinkName: PUNICODE_STRING) -> NTSTATUS;
    
    fn IoGetCurrentIrpStackLocation(Irp: PIRP) -> PIO_STACK_LOCATION;
    
    fn IoCompleteRequest(Irp: PIRP, PriorityBoost: u8);
    
    fn ExAllocatePoolWithTag(PoolType: POOL_TYPE, NumberOfBytes: u64, Tag: u32) -> PVOID;
    
    fn ExFreePoolWithTag(P: PVOID, Tag: u32);
    
    fn ExAcquireFastMutex(FastMutex: PFAST_MUTEX);
    
    fn ExReleaseFastMutex(FastMutex: PFAST_MUTEX);
    
    fn ExInitializeFastMutex(FastMutex: PFAST_MUTEX);
    
    fn InitializeListHead(ListHead: PLIST_ENTRY);
    
    fn InsertTailList(ListHead: PLIST_ENTRY, Entry: PLIST_ENTRY);
    
    fn RemoveEntryList(Entry: PLIST_ENTRY) -> BOOLEAN;
    
    fn KeInitializeEvent(Event: PKEVENT, Type: EVENT_TYPE, State: BOOLEAN);
    
    fn KeSetEvent(Event: PKEVENT, Increment: i32, Wait: BOOLEAN) -> i32;
    
    fn KeClearEvent(Event: PKEVENT);
    
    fn KeWaitForSingleObject(
        Object: PVOID,
        WaitReason: KWAIT_REASON,
        WaitMode: KPROCESSOR_MODE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    
    fn DbgPrintEx(ComponentId: u32, Level: u32, Format: *const u8, ...);
    
    fn NT_SUCCESS(Status: NTSTATUS) -> bool;
}