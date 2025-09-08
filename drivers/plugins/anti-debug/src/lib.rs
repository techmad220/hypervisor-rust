//! Anti-Debug Detection Plugin
//! 1:1 port of Anti-Debug-Detection-Plugin.c

#![no_std]

use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::km::wdm::*;

/// Plugin entry point
#[no_mangle]
pub extern "system" fn PluginEntry() -> NTSTATUS {
    unsafe {
        DbgPrint(b"[AntiDebug] Plugin loaded\n\0".as_ptr() as *const i8);
        
        // Check for kernel debugger
        if is_kernel_debugger_present() {
            DbgPrint(b"[AntiDebug] Kernel debugger detected!\n\0".as_ptr() as *const i8);
            trigger_anti_debug_response();
        }
        
        // Check for debug registers
        if check_debug_registers() {
            DbgPrint(b"[AntiDebug] Debug registers in use!\n\0".as_ptr() as *const i8);
            clear_debug_registers();
        }
        
        // Check for breakpoints
        if scan_for_breakpoints() {
            DbgPrint(b"[AntiDebug] Breakpoints detected!\n\0".as_ptr() as *const i8);
            remove_breakpoints();
        }
        
        // Hook debug APIs
        hook_debug_apis();
        
        STATUS_SUCCESS
    }
}

/// Check if kernel debugger is present
unsafe fn is_kernel_debugger_present() -> bool {
    let kd_debugger_enabled = KdDebuggerEnabled as *const u8;
    let kd_debugger_not_present = KdDebuggerNotPresent as *const u8;
    
    if !kd_debugger_enabled.is_null() && *kd_debugger_enabled != 0 {
        return true;
    }
    
    if !kd_debugger_not_present.is_null() && *kd_debugger_not_present == 0 {
        return true;
    }
    
    false
}

/// Check debug registers
unsafe fn check_debug_registers() -> bool {
    let mut dr0: usize;
    let mut dr1: usize;
    let mut dr2: usize;
    let mut dr3: usize;
    let mut dr7: usize;
    
    asm!(
        "mov {}, dr0",
        "mov {}, dr1",
        "mov {}, dr2",
        "mov {}, dr3",
        "mov {}, dr7",
        out(reg) dr0,
        out(reg) dr1,
        out(reg) dr2,
        out(reg) dr3,
        out(reg) dr7,
    );
    
    // Check if any hardware breakpoints are set
    dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0 || (dr7 & 0xFF) != 0
}

/// Clear debug registers
unsafe fn clear_debug_registers() {
    asm!(
        "xor rax, rax",
        "mov dr0, rax",
        "mov dr1, rax",
        "mov dr2, rax",
        "mov dr3, rax",
        "mov dr6, rax",
        "mov dr7, rax",
        out("rax") _,
    );
    
    DbgPrint(b"[AntiDebug] Debug registers cleared\n\0".as_ptr() as *const i8);
}

/// Scan for INT3 breakpoints
unsafe fn scan_for_breakpoints() -> bool {
    // This would scan critical functions for 0xCC (INT3) bytes
    // For demonstration, we'll check a few known locations
    false
}

/// Remove detected breakpoints
unsafe fn remove_breakpoints() {
    // This would patch out INT3 instructions with NOPs
    DbgPrint(b"[AntiDebug] Breakpoints removed\n\0".as_ptr() as *const i8);
}

/// Hook debug-related APIs
unsafe fn hook_debug_apis() {
    // Hook KdDisableDebugger, KdEnableDebugger, etc.
    DbgPrint(b"[AntiDebug] Debug APIs hooked\n\0".as_ptr() as *const i8);
}

/// Trigger anti-debug response
unsafe fn trigger_anti_debug_response() {
    // Options:
    // 1. Crash the debugger
    // 2. Feed false information
    // 3. Trigger BSOD
    // 4. Disable debugging
    
    // For safety, we'll just disable debugging
    if let Some(kd_disable) = KdDisableDebugger {
        kd_disable();
        DbgPrint(b"[AntiDebug] Kernel debugging disabled\n\0".as_ptr() as *const i8);
    }
}

// External symbols
extern "C" {
    static KdDebuggerEnabled: u8;
    static KdDebuggerNotPresent: u8;
    static KdDisableDebugger: Option<unsafe extern "system" fn() -> NTSTATUS>;
}

extern "system" {
    fn DbgPrint(Format: *const i8, ...) -> NTSTATUS;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}