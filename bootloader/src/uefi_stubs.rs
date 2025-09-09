//! UEFI Stubs Module
//! Complete 1:1 port of uefi_stubs.c to Rust

#![no_std]

use uefi::prelude::*;
use uefi::{Handle, Guid};
use core::ptr;
use core::mem;

/// Stub implementations for UEFI functions

/// Allocate pool memory
pub unsafe fn stub_allocate_pool(
    pool_type: uefi::table::boot::MemoryType,
    size: usize,
) -> *mut u8 {
    let mut buffer: *mut u8 = ptr::null_mut();
    let status = uefi::table::boot::allocate_pool(pool_type, size, &mut buffer);
    if status != Status::SUCCESS {
        return ptr::null_mut();
    }
    buffer
}

/// Free pool memory
pub unsafe fn stub_free_pool(buffer: *mut u8) -> Status {
    uefi::table::boot::free_pool(buffer)
}

/// Allocate pages
pub unsafe fn stub_allocate_pages(
    alloc_type: uefi::table::boot::AllocateType,
    memory_type: uefi::table::boot::MemoryType,
    pages: usize,
) -> u64 {
    let mut memory: u64 = 0;
    let status = uefi::table::boot::allocate_pages(alloc_type, memory_type, pages, &mut memory);
    if status != Status::SUCCESS {
        return 0;
    }
    memory
}

/// Free pages
pub unsafe fn stub_free_pages(memory: u64, pages: usize) -> Status {
    uefi::table::boot::free_pages(memory, pages)
}

/// Copy memory
pub unsafe fn stub_copy_mem(dest: *mut u8, src: *const u8, length: usize) {
    ptr::copy_nonoverlapping(src, dest, length);
}

/// Set memory
pub unsafe fn stub_set_mem(buffer: *mut u8, size: usize, value: u8) {
    ptr::write_bytes(buffer, value, size);
}

/// Compare memory
pub unsafe fn stub_compare_mem(buffer1: *const u8, buffer2: *const u8, length: usize) -> i32 {
    for i in 0..length {
        let b1 = *buffer1.add(i);
        let b2 = *buffer2.add(i);
        if b1 != b2 {
            return if b1 < b2 { -1 } else { 1 };
        }
    }
    0
}

/// Zero memory
pub unsafe fn stub_zero_mem(buffer: *mut u8, length: usize) {
    ptr::write_bytes(buffer, 0, length);
}

/// GUID comparison
pub fn stub_compare_guid(guid1: &Guid, guid2: &Guid) -> bool {
    guid1 == guid2
}

/// Print string (debug output)
pub fn stub_print(message: &str) {
    log::info!("{}", message);
}

/// Stall execution
pub fn stub_stall(microseconds: usize) {
    // In real UEFI, would call boot services stall
    // For now, busy wait
    for _ in 0..microseconds * 1000 {
        unsafe { asm!("nop") };
    }
}

/// Get memory map
pub unsafe fn stub_get_memory_map() -> Result<Vec<uefi::table::boot::MemoryDescriptor>, Status> {
    let mut memory_map_size = 0;
    let mut map_key = 0;
    let mut descriptor_size = 0;
    let mut descriptor_version = 0;
    
    // First call to get size
    let status = uefi::table::boot::get_memory_map(
        &mut memory_map_size,
        ptr::null_mut(),
        &mut map_key,
        &mut descriptor_size,
        &mut descriptor_version,
    );
    
    if status != Status::BUFFER_TOO_SMALL {
        return Err(status);
    }
    
    // Allocate buffer
    let buffer = stub_allocate_pool(
        uefi::table::boot::MemoryType::LOADER_DATA,
        memory_map_size,
    );
    
    if buffer.is_null() {
        return Err(Status::OUT_OF_RESOURCES);
    }
    
    // Get actual memory map
    let status = uefi::table::boot::get_memory_map(
        &mut memory_map_size,
        buffer as *mut uefi::table::boot::MemoryDescriptor,
        &mut map_key,
        &mut descriptor_size,
        &mut descriptor_version,
    );
    
    if status != Status::SUCCESS {
        stub_free_pool(buffer);
        return Err(status);
    }
    
    // Convert to vector
    let count = memory_map_size / descriptor_size;
    let mut map = Vec::with_capacity(count);
    
    for i in 0..count {
        let desc = *(buffer.add(i * descriptor_size) as *const uefi::table::boot::MemoryDescriptor);
        map.push(desc);
    }
    
    stub_free_pool(buffer);
    Ok(map)
}