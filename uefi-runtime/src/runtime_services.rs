//! UEFI Runtime Services
//! Services available after ExitBootServices()

#![no_std]

use uefi::prelude::*;
use uefi::table::runtime::{Daylight, Time, TimeCapabilities, VariableAttributes, ResetType};
use uefi::table::{Runtime, SystemTable};
use uefi::{CStr16, Guid};
use core::mem;

/// Runtime Services Manager
pub struct RuntimeServices<'a> {
    system_table: &'a SystemTable<Runtime>,
}

impl<'a> RuntimeServices<'a> {
    /// Create new runtime services wrapper
    pub fn new(system_table: &'a SystemTable<Runtime>) -> Self {
        Self { system_table }
    }

    /// Get time and date
    pub fn get_time(&self) -> Result<(Time, TimeCapabilities), Status> {
        let mut time = Time::invalid();
        let mut capabilities = TimeCapabilities::default();
        
        let status = (self.system_table.runtime_services().get_time)(
            &mut time,
            &mut capabilities,
        );
        
        if status == Status::SUCCESS {
            Ok((time, capabilities))
        } else {
            Err(status)
        }
    }

    /// Set time and date
    pub fn set_time(&mut self, time: &Time) -> Result<(), Status> {
        let status = (self.system_table.runtime_services().set_time)(time);
        
        if status == Status::SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Get wakeup time
    pub fn get_wakeup_time(&self) -> Result<(bool, bool, Time), Status> {
        let mut enabled = false;
        let mut pending = false;
        let mut time = Time::invalid();
        
        let status = (self.system_table.runtime_services().get_wakeup_time)(
            &mut enabled,
            &mut pending,
            &mut time,
        );
        
        if status == Status::SUCCESS {
            Ok((enabled, pending, time))
        } else {
            Err(status)
        }
    }

    /// Set wakeup time
    pub fn set_wakeup_time(&mut self, enable: bool, time: Option<&Time>) -> Result<(), Status> {
        let time_ptr = time.map(|t| t as *const Time).unwrap_or(core::ptr::null());
        
        let status = (self.system_table.runtime_services().set_wakeup_time)(enable, time_ptr);
        
        if status == Status::SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Get variable
    pub fn get_variable(
        &self,
        name: &CStr16,
        vendor: &Guid,
        attributes: Option<&mut VariableAttributes>,
        data: &mut [u8],
        data_size: &mut usize,
    ) -> Result<(), Status> {
        let attr_ptr = attributes
            .map(|a| a as *mut VariableAttributes)
            .unwrap_or(core::ptr::null_mut());
        
        let status = (self.system_table.runtime_services().get_variable)(
            name.as_ptr(),
            vendor,
            attr_ptr,
            data_size,
            data.as_mut_ptr(),
        );
        
        if status == Status::SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Set variable
    pub fn set_variable(
        &mut self,
        name: &CStr16,
        vendor: &Guid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<(), Status> {
        let status = (self.system_table.runtime_services().set_variable)(
            name.as_ptr(),
            vendor,
            attributes,
            data.len(),
            data.as_ptr(),
        );
        
        if status == Status::SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Get next variable name
    pub fn get_next_variable_name(
        &self,
        name_size: &mut usize,
        name: &mut [u16],
        vendor: &mut Guid,
    ) -> Result<(), Status> {
        let status = (self.system_table.runtime_services().get_next_variable_name)(
            name_size,
            name.as_mut_ptr(),
            vendor,
        );
        
        if status == Status::SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Query variable info
    pub fn query_variable_info(
        &self,
        attributes: VariableAttributes,
    ) -> Result<(u64, u64, u64), Status> {
        let mut max_storage_size = 0;
        let mut remaining_storage_size = 0;
        let mut max_variable_size = 0;
        
        let status = (self.system_table.runtime_services().query_variable_info)(
            attributes,
            &mut max_storage_size,
            &mut remaining_storage_size,
            &mut max_variable_size,
        );
        
        if status == Status::SUCCESS {
            Ok((max_storage_size, remaining_storage_size, max_variable_size))
        } else {
            Err(status)
        }
    }

    /// Reset system
    pub fn reset(&mut self, reset_type: ResetType, status: Status, data: Option<&[u8]>) -> ! {
        let (data_size, data_ptr) = if let Some(d) = data {
            (d.len(), d.as_ptr())
        } else {
            (0, core::ptr::null())
        };
        
        (self.system_table.runtime_services().reset_system)(
            reset_type,
            status,
            data_size,
            data_ptr,
        );
        
        // Should never reach here
        loop {
            unsafe { core::arch::asm!("hlt") }
        }
    }

    /// Update capsule
    pub fn update_capsule(
        &mut self,
        capsule_headers: &[*const CapsuleHeader],
        scatter_gather_list: Option<u64>,
    ) -> Result<(), Status> {
        let status = (self.system_table.runtime_services().update_capsule)(
            capsule_headers.as_ptr() as *mut *mut CapsuleHeader,
            capsule_headers.len(),
            scatter_gather_list.unwrap_or(0),
        );
        
        if status == Status::SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Query capsule capabilities
    pub fn query_capsule_capabilities(
        &self,
        capsule_headers: &[*const CapsuleHeader],
    ) -> Result<(u64, ResetType), Status> {
        let mut max_capsule_size = 0;
        let mut reset_type = ResetType::COLD;
        
        let status = (self.system_table.runtime_services().query_capsule_capabilities)(
            capsule_headers.as_ptr() as *mut *mut CapsuleHeader,
            capsule_headers.len(),
            &mut max_capsule_size,
            &mut reset_type,
        );
        
        if status == Status::SUCCESS {
            Ok((max_capsule_size, reset_type))
        } else {
            Err(status)
        }
    }
}

/// Capsule Header
#[repr(C)]
pub struct CapsuleHeader {
    pub capsule_guid: Guid,
    pub header_size: u32,
    pub flags: u32,
    pub capsule_image_size: u32,
}

/// Variable Services
pub struct VariableServices<'a> {
    runtime_services: &'a RuntimeServices<'a>,
}

impl<'a> VariableServices<'a> {
    pub fn new(runtime_services: &'a RuntimeServices<'a>) -> Self {
        Self { runtime_services }
    }

    /// Read boot order
    pub fn get_boot_order(&self) -> Result<Vec<u16>, Status> {
        let name = cstr16!("BootOrder");
        let vendor = &EFI_GLOBAL_VARIABLE_GUID;
        let mut data = vec![0u8; 256];
        let mut data_size = data.len();
        
        self.runtime_services.get_variable(
            name,
            vendor,
            None,
            &mut data,
            &mut data_size,
        )?;
        
        // Convert bytes to u16 array
        let boot_order_count = data_size / 2;
        let mut boot_order = Vec::with_capacity(boot_order_count);
        
        for i in 0..boot_order_count {
            let value = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
            boot_order.push(value);
        }
        
        Ok(boot_order)
    }

    /// Set boot order
    pub fn set_boot_order(&mut self, boot_order: &[u16]) -> Result<(), Status> {
        let name = cstr16!("BootOrder");
        let vendor = &EFI_GLOBAL_VARIABLE_GUID;
        let attributes = VariableAttributes::BOOTSERVICE_ACCESS 
            | VariableAttributes::RUNTIME_ACCESS 
            | VariableAttributes::NON_VOLATILE;
        
        // Convert u16 array to bytes
        let mut data = Vec::with_capacity(boot_order.len() * 2);
        for &value in boot_order {
            data.extend_from_slice(&value.to_le_bytes());
        }
        
        self.runtime_services.set_variable(name, vendor, attributes, &data)
    }

    /// Get secure boot status
    pub fn is_secure_boot_enabled(&self) -> Result<bool, Status> {
        let name = cstr16!("SecureBoot");
        let vendor = &EFI_GLOBAL_VARIABLE_GUID;
        let mut data = [0u8; 1];
        let mut data_size = 1;
        
        match self.runtime_services.get_variable(
            name,
            vendor,
            None,
            &mut data,
            &mut data_size,
        ) {
            Ok(()) => Ok(data[0] == 1),
            Err(Status::NOT_FOUND) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get platform language
    pub fn get_platform_language(&self) -> Result<String, Status> {
        let name = cstr16!("PlatformLang");
        let vendor = &EFI_GLOBAL_VARIABLE_GUID;
        let mut data = vec![0u8; 16];
        let mut data_size = data.len();
        
        self.runtime_services.get_variable(
            name,
            vendor,
            None,
            &mut data,
            &mut data_size,
        )?;
        
        // Convert to string (ASCII)
        data.truncate(data_size);
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    /// Store hypervisor configuration
    pub fn store_hypervisor_config(&mut self, config: &HypervisorConfig) -> Result<(), Status> {
        let name = cstr16!("HypervisorConfig");
        let vendor = &HYPERVISOR_VENDOR_GUID;
        let attributes = VariableAttributes::BOOTSERVICE_ACCESS 
            | VariableAttributes::RUNTIME_ACCESS 
            | VariableAttributes::NON_VOLATILE;
        
        let data = unsafe {
            core::slice::from_raw_parts(
                config as *const HypervisorConfig as *const u8,
                mem::size_of::<HypervisorConfig>(),
            )
        };
        
        self.runtime_services.set_variable(name, vendor, attributes, data)
    }

    /// Load hypervisor configuration
    pub fn load_hypervisor_config(&self) -> Result<HypervisorConfig, Status> {
        let name = cstr16!("HypervisorConfig");
        let vendor = &HYPERVISOR_VENDOR_GUID;
        let mut config = HypervisorConfig::default();
        let mut data = unsafe {
            core::slice::from_raw_parts_mut(
                &mut config as *mut HypervisorConfig as *mut u8,
                mem::size_of::<HypervisorConfig>(),
            )
        };
        let mut data_size = data.len();
        
        self.runtime_services.get_variable(
            name,
            vendor,
            None,
            data,
            &mut data_size,
        )?;
        
        Ok(config)
    }
}

/// Hypervisor Configuration
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HypervisorConfig {
    pub enabled: bool,
    pub vmx_enabled: bool,
    pub svm_enabled: bool,
    pub nested_virtualization: bool,
    pub memory_size_mb: u32,
    pub vcpu_count: u32,
    pub ept_enabled: bool,
    pub vpid_enabled: bool,
    pub auto_start: bool,
    pub chainload_windows: bool,
    pub debug_mode: bool,
    pub reserved: [u8; 64],
}

/// Time Services
pub struct TimeServices<'a> {
    runtime_services: &'a RuntimeServices<'a>,
}

impl<'a> TimeServices<'a> {
    pub fn new(runtime_services: &'a RuntimeServices<'a>) -> Self {
        Self { runtime_services }
    }

    /// Get current timestamp
    pub fn get_timestamp(&self) -> Result<u64, Status> {
        let (time, _) = self.runtime_services.get_time()?;
        
        // Convert to Unix timestamp
        let timestamp = time_to_unix_timestamp(&time);
        Ok(timestamp)
    }

    /// Set system time from timestamp
    pub fn set_timestamp(&mut self, timestamp: u64) -> Result<(), Status> {
        let time = unix_timestamp_to_time(timestamp);
        self.runtime_services.set_time(&time)
    }

    /// Schedule wakeup
    pub fn schedule_wakeup(&mut self, timestamp: u64) -> Result<(), Status> {
        let time = unix_timestamp_to_time(timestamp);
        self.runtime_services.set_wakeup_time(true, Some(&time))
    }

    /// Cancel wakeup
    pub fn cancel_wakeup(&mut self) -> Result<(), Status> {
        self.runtime_services.set_wakeup_time(false, None)
    }
}

/// Convert UEFI Time to Unix timestamp
fn time_to_unix_timestamp(time: &Time) -> u64 {
    // Simplified conversion (doesn't handle all edge cases)
    let mut days = 0u64;
    
    // Days from 1970 to year
    for year in 1970..time.year() {
        days += if is_leap_year(year) { 366 } else { 365 };
    }
    
    // Days in current year
    for month in 1..time.month() {
        days += days_in_month(month, time.year());
    }
    days += (time.day() - 1) as u64;
    
    // Convert to seconds
    let seconds = days * 86400
        + (time.hour() as u64) * 3600
        + (time.minute() as u64) * 60
        + time.second() as u64;
    
    seconds
}

/// Convert Unix timestamp to UEFI Time
fn unix_timestamp_to_time(timestamp: u64) -> Time {
    // Simplified conversion
    let mut remaining = timestamp;
    let mut year = 1970u16;
    
    // Find year
    loop {
        let year_seconds = if is_leap_year(year) { 366 * 86400 } else { 365 * 86400 };
        if remaining < year_seconds {
            break;
        }
        remaining -= year_seconds;
        year += 1;
    }
    
    // Find month and day
    let mut month = 1u8;
    let mut day_of_year = (remaining / 86400) as u16 + 1;
    
    while day_of_year > days_in_month(month, year) as u16 {
        day_of_year -= days_in_month(month, year) as u16;
        month += 1;
    }
    
    let day = day_of_year as u8;
    remaining %= 86400;
    
    let hour = (remaining / 3600) as u8;
    remaining %= 3600;
    let minute = (remaining / 60) as u8;
    let second = (remaining % 60) as u8;
    
    Time {
        year: year,
        month: month,
        day: day,
        hour: hour,
        minute: minute,
        second: second,
        nanosecond: 0,
        timezone: 0,
        daylight: Daylight::empty(),
        _pad: 0,
    }
}

/// Check if year is leap year
fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get days in month
fn days_in_month(month: u8, year: u16) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap_year(year) { 29 } else { 28 },
        _ => 0,
    }
}

// GUIDs
const EFI_GLOBAL_VARIABLE_GUID: Guid = Guid::from_values(
    0x8BE4DF61,
    0x93CA,
    0x11d2,
    [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
);

const HYPERVISOR_VENDOR_GUID: Guid = Guid::from_values(
    0x12345678,
    0x1234,
    0x5678,
    [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
);

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;