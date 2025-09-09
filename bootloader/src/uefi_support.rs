//! UEFI Support Module
//! Complete 1:1 port of uefi_support.c to Rust

#![no_std]

use uefi::prelude::*;
use uefi::proto::console::text::SimpleTextOutput;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::device_path::DevicePath;
use uefi::table::boot::{MemoryType, AllocateType};
use uefi::{Handle, Guid};
use core::ptr;
use alloc::vec::Vec;

/// UEFI support functions

/// Initialize UEFI environment
pub fn init_uefi_environment(system_table: &SystemTable<Boot>) -> Result<(), Status> {
    // Clear screen
    if let Ok(stdout) = system_table.stdout() {
        stdout.clear()?;
    }
    
    // Set watchdog timer to 0 (disable)
    system_table.boot_services().set_watchdog_timer(0, 0x10000, None)?;
    
    Ok(())
}

/// Load image from file
pub fn load_image_from_file(
    system_table: &SystemTable<Boot>,
    device_path: &DevicePath,
    parent_image: Handle,
) -> Result<Handle, Status> {
    let mut image_handle = Handle::from_ptr(ptr::null_mut()).unwrap();
    
    unsafe {
        system_table.boot_services().load_image(
            false,
            parent_image,
            Some(device_path),
            ptr::null(),
            0,
            &mut image_handle,
        )?;
    }
    
    Ok(image_handle)
}

/// Start loaded image
pub fn start_image(
    system_table: &SystemTable<Boot>,
    image_handle: Handle,
) -> Result<usize, Status> {
    let mut exit_data_size = 0;
    let mut exit_data: *mut u16 = ptr::null_mut();
    
    let status = unsafe {
        system_table.boot_services().start_image(
            image_handle,
            &mut exit_data_size,
            &mut exit_data,
        )
    };
    
    if !exit_data.is_null() {
        unsafe {
            system_table.boot_services().free_pool(exit_data as *mut u8)?;
        }
    }
    
    status.map(|_| exit_data_size)
}

/// Locate protocol
pub fn locate_protocol<P: uefi::proto::Protocol>(
    system_table: &SystemTable<Boot>,
) -> Result<&P, Status> {
    let mut interface: *mut P = ptr::null_mut();
    
    unsafe {
        system_table.boot_services().locate_protocol::<P>(
            &P::GUID,
            ptr::null_mut(),
            &mut interface,
        )?;
        
        Ok(&*interface)
    }
}

/// Handle protocol
pub fn handle_protocol<P: uefi::proto::Protocol>(
    system_table: &SystemTable<Boot>,
    handle: Handle,
) -> Result<&P, Status> {
    let mut interface: *mut P = ptr::null_mut();
    
    unsafe {
        system_table.boot_services().handle_protocol(
            handle,
            &P::GUID,
            &mut interface as *mut _ as *mut *mut core::ffi::c_void,
        )?;
        
        Ok(&*interface)
    }
}

/// Allocate aligned memory
pub fn allocate_aligned_pages(
    system_table: &SystemTable<Boot>,
    pages: usize,
    alignment: usize,
) -> Result<u64, Status> {
    // Allocate extra pages for alignment
    let total_pages = pages + (alignment / 4096);
    
    let mut memory = 0u64;
    system_table.boot_services().allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        total_pages,
        &mut memory,
    )?;
    
    // Align the address
    let aligned = (memory + alignment as u64 - 1) & !(alignment as u64 - 1);
    
    // Free unused pages before aligned address
    if aligned > memory {
        let unused_pages = ((aligned - memory) / 4096) as usize;
        system_table.boot_services().free_pages(memory, unused_pages)?;
    }
    
    Ok(aligned)
}

/// Get loaded image protocol
pub fn get_loaded_image(
    system_table: &SystemTable<Boot>,
    image_handle: Handle,
) -> Result<&LoadedImage, Status> {
    handle_protocol::<LoadedImage>(system_table, image_handle)
}

/// Exit boot services
pub fn exit_boot_services(
    system_table: SystemTable<Boot>,
    image_handle: Handle,
) -> Result<(SystemTable<Runtime>, MemoryMap), Status> {
    // Get memory map
    let mut memory_map = Vec::with_capacity(256);
    let mut map_key = 0;
    
    loop {
        let mut memory_map_size = memory_map.capacity() * core::mem::size_of::<uefi::table::boot::MemoryDescriptor>();
        let mut descriptor_size = 0;
        let mut descriptor_version = 0;
        
        match system_table.boot_services().memory_map(
            &mut memory_map_size,
            memory_map.as_mut_ptr(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        ) {
            Ok(_) => {
                unsafe {
                    memory_map.set_len(memory_map_size / descriptor_size);
                }
                break;
            }
            Err(Status::BUFFER_TOO_SMALL) => {
                memory_map.reserve(memory_map_size / descriptor_size);
            }
            Err(e) => return Err(e),
        }
    }
    
    // Exit boot services
    let (runtime_table, _) = system_table.exit_boot_services(image_handle, map_key)?;
    
    Ok((runtime_table, MemoryMap { entries: memory_map }))
}

/// Memory map wrapper
pub struct MemoryMap {
    pub entries: Vec<uefi::table::boot::MemoryDescriptor>,
}

impl MemoryMap {
    pub fn iter(&self) -> impl Iterator<Item = &uefi::table::boot::MemoryDescriptor> {
        self.entries.iter()
    }
    
    pub fn total_memory(&self) -> u64 {
        self.entries.iter()
            .filter(|desc| desc.ty == MemoryType::CONVENTIONAL)
            .map(|desc| desc.page_count * 4096)
            .sum()
    }
}