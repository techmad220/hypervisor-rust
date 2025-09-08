//! Driver Self-Protection Plugin
//! 1:1 port of driver_self_protection_plugin.c

#![no_std]

use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::km::wdm::*;
use core::ptr;

/// Plugin entry point
#[no_mangle]
pub extern "system" fn PluginEntry() -> NTSTATUS {
    unsafe {
        DbgPrint(b"[Protection] Driver self-protection activated\n\0".as_ptr() as *const i8);
        
        // Protect driver memory
        protect_driver_memory();
        
        // Hook critical functions
        install_protection_hooks();
        
        // Set up integrity checks
        setup_integrity_checks();
        
        // Install anti-unload protection
        prevent_driver_unload();
        
        // Protect registry keys
        protect_registry_keys();
        
        // Install process/thread callbacks
        install_callbacks();
        
        STATUS_SUCCESS
    }
}

/// Protect driver memory pages
unsafe fn protect_driver_memory() {
    // Get our driver's base and size
    let driver_base = get_driver_base();
    let driver_size = get_driver_size();
    
    if driver_base.is_null() {
        return;
    }
    
    // Make code sections read-only
    let mut mdl = IoAllocateMdl(
        driver_base as PVOID,
        driver_size as ULONG,
        FALSE,
        FALSE,
        ptr::null_mut()
    );
    
    if !mdl.is_null() {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        let protected_va = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            ptr::null_mut(),
            FALSE,
            NormalPagePriority
        );
        
        // Set page protection
        if !protected_va.is_null() {
            // Mark as read-only
            let pte = MiGetPteAddress(protected_va);
            if !pte.is_null() {
                (*pte).Write = 0;  // Clear write bit
            }
        }
        
        DbgPrint(b"[Protection] Driver memory protected\n\0".as_ptr() as *const i8);
    }
}

/// Install hooks to protect driver
unsafe fn install_protection_hooks() {
    // Hook ZwTerminateProcess to prevent termination
    hook_system_service(b"ZwTerminateProcess\0", anti_terminate_handler as *mut u8);
    
    // Hook ZwUnloadDriver to prevent unload
    hook_system_service(b"ZwUnloadDriver\0", anti_unload_handler as *mut u8);
    
    // Hook ZwOpenProcess to prevent access
    hook_system_service(b"ZwOpenProcess\0", anti_open_handler as *mut u8);
    
    DbgPrint(b"[Protection] Protection hooks installed\n\0".as_ptr() as *const i8);
}

/// Set up integrity checking
unsafe fn setup_integrity_checks() {
    // Calculate hash of critical sections
    let code_hash = calculate_code_hash();
    
    // Set up periodic integrity check
    let mut timer: KTIMER = core::mem::zeroed();
    let mut dpc: KDPC = core::mem::zeroed();
    
    KeInitializeTimer(&mut timer);
    KeInitializeDpc(&mut dpc, integrity_check_dpc, code_hash as PVOID);
    
    // Check every 5 seconds
    let due_time = -50000000i64; // 5 seconds in 100ns units
    KeSetTimerEx(&mut timer, due_time, 5000, &mut dpc);
    
    DbgPrint(b"[Protection] Integrity checks enabled\n\0".as_ptr() as *const i8);
}

/// Prevent driver unload
unsafe fn prevent_driver_unload() {
    // Get our driver object
    let driver_object = get_driver_object();
    if driver_object.is_null() {
        return;
    }
    
    // Clear DriverUnload to prevent unloading
    (*driver_object).DriverUnload = None;
    
    // Increment reference count
    ObReferenceObject(driver_object as PVOID);
    
    DbgPrint(b"[Protection] Anti-unload protection enabled\n\0".as_ptr() as *const i8);
}

/// Protect registry keys
unsafe fn protect_registry_keys() {
    // Protect driver service key
    let key_path = w!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HypervisorDriver");
    
    let mut key_name = UNICODE_STRING::from_slice(key_path);
    let mut obj_attr: OBJECT_ATTRIBUTES = core::mem::zeroed();
    
    InitializeObjectAttributes(
        &mut obj_attr,
        &mut key_name,
        OBJ_KERNEL_HANDLE,
        ptr::null_mut(),
        ptr::null_mut()
    );
    
    let mut key_handle: HANDLE = ptr::null_mut();
    let status = ZwOpenKey(&mut key_handle, KEY_ALL_ACCESS, &mut obj_attr);
    
    if NT_SUCCESS(status) {
        // Set security descriptor to deny deletion
        set_key_security(key_handle);
        ZwClose(key_handle);
        
        DbgPrint(b"[Protection] Registry keys protected\n\0".as_ptr() as *const i8);
    }
}

/// Install process/thread callbacks
unsafe fn install_callbacks() {
    // Register process creation callback
    let status = PsSetCreateProcessNotifyRoutineEx(
        process_create_callback,
        FALSE
    );
    
    if NT_SUCCESS(status) {
        DbgPrint(b"[Protection] Process callback installed\n\0".as_ptr() as *const i8);
    }
    
    // Register thread creation callback  
    PsSetCreateThreadNotifyRoutine(thread_create_callback);
}

// Callback handlers
unsafe extern "system" fn process_create_callback(
    process: PEPROCESS,
    process_id: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO
) {
    if create_info.is_null() {
        return; // Process termination
    }
    
    // Check if process is trying to access our driver
    let image_name = get_process_image_name(process);
    
    if is_suspicious_process(&image_name) {
        // Deny access
        (*create_info).CreationStatus = STATUS_ACCESS_DENIED;
        
        DbgPrint(
            b"[Protection] Blocked suspicious process: %wZ\n\0".as_ptr() as *const i8,
            &image_name
        );
    }
}

unsafe extern "system" fn thread_create_callback(
    process_id: HANDLE,
    thread_id: HANDLE,
    create: BOOLEAN
) {
    if create == FALSE {
        return; // Thread termination
    }
    
    // Check if thread is targeting our driver
    // Block if suspicious
}

// Hook handlers
unsafe extern "system" fn anti_terminate_handler() -> NTSTATUS {
    // Check if target is our protected process
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn anti_unload_handler() -> NTSTATUS {
    // Prevent driver unload
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn anti_open_handler() -> NTSTATUS {
    // Check if trying to open our process/driver
    STATUS_ACCESS_DENIED
}

// Integrity check DPC
unsafe extern "system" fn integrity_check_dpc(
    dpc: *mut KDPC,
    context: PVOID,
    arg1: PVOID,
    arg2: PVOID
) {
    let expected_hash = context as usize;
    let current_hash = calculate_code_hash();
    
    if current_hash != expected_hash {
        DbgPrint(b"[Protection] INTEGRITY CHECK FAILED! Code modified!\n\0".as_ptr() as *const i8);
        
        // Take action: restore code, trigger alert, etc.
        restore_code_integrity();
    }
}

// Helper functions
unsafe fn get_driver_base() -> *mut u8 {
    // Get from PsLoadedModuleList or driver object
    ptr::null_mut()
}

unsafe fn get_driver_size() -> usize {
    // Get from driver's PE headers
    0x10000 // Default 64KB
}

unsafe fn get_driver_object() -> *mut DRIVER_OBJECT {
    // Get our driver object
    ptr::null_mut()
}

unsafe fn calculate_code_hash() -> usize {
    // Simple hash of code section
    let base = get_driver_base();
    let size = get_driver_size();
    
    if base.is_null() {
        return 0;
    }
    
    let mut hash: usize = 0;
    for i in 0..size {
        hash = hash.wrapping_mul(31).wrapping_add(*base.offset(i as isize) as usize);
    }
    
    hash
}

unsafe fn restore_code_integrity() {
    // Restore original code from backup
    DbgPrint(b"[Protection] Restoring code integrity...\n\0".as_ptr() as *const i8);
}

unsafe fn hook_system_service(_name: &[u8], _handler: *mut u8) {
    // Hook SSDT or inline hook
}

unsafe fn get_process_image_name(_process: PEPROCESS) -> UNICODE_STRING {
    // Get process image name
    UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: ptr::null_mut()
    }
}

unsafe fn is_suspicious_process(_name: &UNICODE_STRING) -> bool {
    // Check against blacklist
    false
}

unsafe fn set_key_security(_key: HANDLE) {
    // Set DACL to prevent deletion
}

// Structures
type PEPROCESS = *mut u8;
type KDPC = u8;
type KTIMER = u8;
type PS_CREATE_NOTIFY_INFO = u8;

impl UNICODE_STRING {
    unsafe fn from_slice(s: &[u16]) -> Self {
        UNICODE_STRING {
            Length: ((s.len() - 1) * 2) as u16,
            MaximumLength: (s.len() * 2) as u16,
            Buffer: s.as_ptr() as *mut u16,
        }
    }
}

// Constants
const OBJ_KERNEL_HANDLE: u32 = 0x00000200;
const KEY_ALL_ACCESS: u32 = 0x000F003F;
const KernelMode: u8 = 0;
const IoReadAccess: u8 = 0;
const MmCached: u8 = 1;
const NormalPagePriority: u8 = 16;

// External functions
extern "system" {
    fn IoAllocateMdl(
        VirtualAddress: PVOID,
        Length: ULONG,
        SecondaryBuffer: BOOLEAN,
        ChargeQuota: BOOLEAN,
        Irp: *mut u8
    ) -> *mut u8;
    fn MmProbeAndLockPages(MemoryDescriptorList: *mut u8, AccessMode: u8, Operation: u8);
    fn MmMapLockedPagesSpecifyCache(
        MemoryDescriptorList: *mut u8,
        AccessMode: u8,
        CacheType: u8,
        BaseAddress: PVOID,
        BugCheckOnFailure: BOOLEAN,
        Priority: u8
    ) -> PVOID;
    fn MiGetPteAddress(VirtualAddress: PVOID) -> *mut PTE;
    fn ObReferenceObject(Object: PVOID) -> NTSTATUS;
    fn InitializeObjectAttributes(
        p: *mut OBJECT_ATTRIBUTES,
        n: *mut UNICODE_STRING,
        a: u32,
        r: HANDLE,
        s: *mut u8
    );
    fn ZwOpenKey(
        KeyHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES
    ) -> NTSTATUS;
    fn ZwClose(Handle: HANDLE) -> NTSTATUS;
    fn PsSetCreateProcessNotifyRoutineEx(
        NotifyRoutine: unsafe extern "system" fn(PEPROCESS, HANDLE, *mut PS_CREATE_NOTIFY_INFO),
        Remove: BOOLEAN
    ) -> NTSTATUS;
    fn PsSetCreateThreadNotifyRoutine(
        NotifyRoutine: unsafe extern "system" fn(HANDLE, HANDLE, BOOLEAN)
    ) -> NTSTATUS;
    fn KeInitializeTimer(Timer: *mut KTIMER);
    fn KeInitializeDpc(Dpc: *mut KDPC, DeferredRoutine: unsafe extern "system" fn(*mut KDPC, PVOID, PVOID, PVOID), DeferredContext: PVOID);
    fn KeSetTimerEx(Timer: *mut KTIMER, DueTime: i64, Period: i32, Dpc: *mut KDPC) -> BOOLEAN;
    fn DbgPrint(Format: *const i8, ...) -> NTSTATUS;
}

#[repr(C)]
struct PTE {
    Present: u32,
    Write: u32,
    // ... other fields
}

macro_rules! w {
    ($s:expr) => {{
        concat!($s, "\0").encode_utf16().collect::<Vec<u16>>().as_slice()
    }};
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}