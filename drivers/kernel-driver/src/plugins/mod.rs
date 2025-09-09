//! Driver Plugins Module
//! Complete 1:1 ports of all driver plugin C files

pub mod anti_debug_detection;
pub mod callback_obfuscation;
pub mod file_system_stealth;
pub mod kernel_memory_access;
pub mod log_offset_values;
pub mod memory_forensics_evasion;
pub mod pg_safe_patching;
pub mod stealth_process_dump;
pub mod driver_self_protection;
pub mod hypervisor_hijack;
pub mod memory_scan;
pub mod screenshot_detector;
pub mod uefi_variable;

// Re-export main plugin interface
pub use anti_debug_detection::*;