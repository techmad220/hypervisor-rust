//! UEFI Boot Services wrapper
//! Provides safe abstractions over UEFI boot services

#![no_std]

use core::mem;
use core::ptr;
use uefi::prelude::*;
use uefi::proto::console::text::{Key, ScanCode, SimpleTextInput, SimpleTextOutput};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileMode, FileInfo};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryDescriptor, MemoryType, SearchType, TimerTrigger};
use uefi::table::{Boot, SystemTable};
use uefi::{Event, Guid, Handle};
use alloc::vec::Vec;
use alloc::string::String;

/// Boot Services Manager
pub struct BootServices<'a> {
    system_table: &'a SystemTable<Boot>,
}

impl<'a> BootServices<'a> {
    /// Create new boot services wrapper
    pub fn new(system_table: &'a SystemTable<Boot>) -> Self {
        Self { system_table }
    }

    /// Get system table reference
    pub fn system_table(&self) -> &SystemTable<Boot> {
        self.system_table
    }

    /// Allocate pages of memory
    pub fn allocate_pages(
        &self,
        alloc_type: AllocateType,
        memory_type: MemoryType,
        pages: usize,
    ) -> Result<u64, Status> {
        self.system_table
            .boot_services()
            .allocate_pages(alloc_type, memory_type, pages)
    }

    /// Free allocated pages
    pub fn free_pages(&self, address: u64, pages: usize) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .free_pages(address, pages)
    }

    /// Allocate pool memory
    pub fn allocate_pool(
        &self,
        memory_type: MemoryType,
        size: usize,
    ) -> Result<*mut u8, Status> {
        self.system_table
            .boot_services()
            .allocate_pool(memory_type, size)
    }

    /// Free pool memory
    pub fn free_pool(&self, buffer: *mut u8) -> Result<(), Status> {
        self.system_table.boot_services().free_pool(buffer)
    }

    /// Get memory map
    pub fn get_memory_map(&self) -> Result<Vec<MemoryDescriptor>, Status> {
        let map_size = self.system_table.boot_services().memory_map_size();
        let mut buffer = vec![0u8; map_size + 512];
        
        let (_key, descriptors) = self.system_table
            .boot_services()
            .memory_map(&mut buffer)?;
        
        Ok(descriptors.copied().collect())
    }

    /// Create an event
    pub fn create_event(
        &self,
        event_type: u32,
        notify_tpl: usize,
        notify_function: Option<fn(Event)>,
        notify_context: Option<*mut core::ffi::c_void>,
    ) -> Result<Event, Status> {
        self.system_table
            .boot_services()
            .create_event(event_type, notify_tpl, notify_function, notify_context)
    }

    /// Set timer
    pub fn set_timer(
        &self,
        event: Event,
        timer_type: TimerTrigger,
        trigger_time: u64,
    ) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .set_timer(event, timer_type, trigger_time)
    }

    /// Wait for event
    pub fn wait_for_event(&self, events: &mut [Event]) -> Result<usize, Status> {
        self.system_table.boot_services().wait_for_event(events)
    }

    /// Signal event
    pub fn signal_event(&self, event: Event) -> Result<(), Status> {
        self.system_table.boot_services().signal_event(event)
    }

    /// Close event
    pub fn close_event(&self, event: Event) -> Result<(), Status> {
        self.system_table.boot_services().close_event(event)
    }

    /// Check event
    pub fn check_event(&self, event: Event) -> Result<(), Status> {
        self.system_table.boot_services().check_event(event)
    }

    /// Install protocol interface
    pub fn install_protocol_interface(
        &self,
        handle: Option<Handle>,
        guid: &Guid,
        interface: *mut core::ffi::c_void,
    ) -> Result<Handle, Status> {
        self.system_table
            .boot_services()
            .install_protocol_interface(handle, guid, interface)
    }

    /// Uninstall protocol interface
    pub fn uninstall_protocol_interface(
        &self,
        handle: Handle,
        guid: &Guid,
        interface: *mut core::ffi::c_void,
    ) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .uninstall_protocol_interface(handle, guid, interface)
    }

    /// Open protocol
    pub fn open_protocol<P: uefi::proto::Protocol>(
        &self,
        handle: Handle,
        agent_handle: Handle,
        controller_handle: Option<Handle>,
        attributes: u32,
    ) -> Result<&'a mut P, Status> {
        self.system_table
            .boot_services()
            .open_protocol::<P>(handle, agent_handle, controller_handle, attributes)
    }

    /// Close protocol
    pub fn close_protocol(
        &self,
        handle: Handle,
        guid: &Guid,
        agent_handle: Handle,
        controller_handle: Option<Handle>,
    ) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .close_protocol(handle, guid, agent_handle, controller_handle)
    }

    /// Locate handle buffer
    pub fn locate_handle_buffer(
        &self,
        search_type: SearchType,
    ) -> Result<Vec<Handle>, Status> {
        self.system_table
            .boot_services()
            .locate_handle_buffer(search_type)
    }

    /// Locate protocol
    pub fn locate_protocol<P: uefi::proto::Protocol>(&self) -> Result<&'a mut P, Status> {
        self.system_table.boot_services().locate_protocol::<P>()
    }

    /// Load image
    pub fn load_image(
        &self,
        parent_image: Handle,
        device_path: &uefi::proto::device_path::DevicePath,
        source_buffer: Option<&[u8]>,
        source_size: Option<usize>,
    ) -> Result<Handle, Status> {
        self.system_table
            .boot_services()
            .load_image(parent_image, device_path, source_buffer, source_size)
    }

    /// Start image
    pub fn start_image(&self, image_handle: Handle) -> Result<usize, Status> {
        self.system_table.boot_services().start_image(image_handle)
    }

    /// Exit
    pub fn exit(
        &self,
        image_handle: Handle,
        exit_status: Status,
        exit_data_size: usize,
        exit_data: Option<&[u16]>,
    ) -> ! {
        self.system_table
            .boot_services()
            .exit(image_handle, exit_status, exit_data_size, exit_data)
    }

    /// Unload image
    pub fn unload_image(&self, image_handle: Handle) -> Result<(), Status> {
        self.system_table.boot_services().unload_image(image_handle)
    }

    /// Exit boot services
    pub fn exit_boot_services(
        self,
        image_handle: Handle,
        memory_map_buffer: &mut [u8],
    ) -> Result<(SystemTable<uefi::table::Runtime>, impl Iterator<Item = &MemoryDescriptor>), Status> {
        let system_table = unsafe { 
            ptr::read(self.system_table as *const SystemTable<Boot>)
        };
        system_table.exit_boot_services(image_handle, memory_map_buffer)
    }

    /// Stall processor
    pub fn stall(&self, microseconds: usize) -> Result<(), Status> {
        self.system_table.boot_services().stall(microseconds)
    }

    /// Set watchdog timer
    pub fn set_watchdog_timer(
        &self,
        timeout: usize,
        watchdog_code: u64,
        data_size: usize,
        watchdog_data: Option<&[u16]>,
    ) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .set_watchdog_timer(timeout, watchdog_code, data_size, watchdog_data)
    }

    /// Connect controller
    pub fn connect_controller(
        &self,
        controller_handle: Handle,
        driver_image_handle: Option<Handle>,
        remaining_device_path: Option<&uefi::proto::device_path::DevicePath>,
        recursive: bool,
    ) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .connect_controller(
                controller_handle,
                driver_image_handle,
                remaining_device_path,
                recursive,
            )
    }

    /// Disconnect controller
    pub fn disconnect_controller(
        &self,
        controller_handle: Handle,
        driver_image_handle: Option<Handle>,
        child_handle: Option<Handle>,
    ) -> Result<(), Status> {
        self.system_table
            .boot_services()
            .disconnect_controller(controller_handle, driver_image_handle, child_handle)
    }

    /// Get handle for protocol
    pub fn get_handle_for_protocol<P: uefi::proto::Protocol>(&self) -> Result<Handle, Status> {
        self.system_table
            .boot_services()
            .get_handle_for_protocol::<P>()
    }

    /// Register protocol notify
    pub fn register_protocol_notify(
        &self,
        protocol: &Guid,
        event: Event,
    ) -> Result<*mut core::ffi::c_void, Status> {
        self.system_table
            .boot_services()
            .register_protocol_notify(protocol, event)
    }

    /// Locate device path
    pub fn locate_device_path(
        &self,
        protocol: &Guid,
        device_path: &mut &uefi::proto::device_path::DevicePath,
    ) -> Result<Handle, Status> {
        self.system_table
            .boot_services()
            .locate_device_path(protocol, device_path)
    }

    /// Copy memory
    pub fn copy_mem(&self, dest: *mut u8, src: *const u8, length: usize) -> Result<(), Status> {
        self.system_table.boot_services().copy_mem(dest, src, length)
    }

    /// Set memory
    pub fn set_mem(&self, buffer: *mut u8, size: usize, value: u8) -> Result<(), Status> {
        self.system_table.boot_services().set_mem(buffer, size, value)
    }
}

/// Memory services wrapper
pub struct MemoryServices<'a> {
    boot_services: &'a BootServices<'a>,
}

impl<'a> MemoryServices<'a> {
    pub fn new(boot_services: &'a BootServices<'a>) -> Self {
        Self { boot_services }
    }

    /// Allocate aligned memory
    pub fn allocate_aligned(
        &self,
        size: usize,
        alignment: usize,
        memory_type: MemoryType,
    ) -> Result<*mut u8, Status> {
        let aligned_size = (size + alignment - 1) & !(alignment - 1);
        let pages = (aligned_size + 4095) / 4096;
        
        let address = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            memory_type,
            pages,
        )?;
        
        Ok(address as *mut u8)
    }

    /// Allocate executable memory
    pub fn allocate_executable(&self, size: usize) -> Result<*mut u8, Status> {
        let pages = (size + 4095) / 4096;
        let address = self.boot_services.allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_CODE,
            pages,
        )?;
        
        Ok(address as *mut u8)
    }

    /// Allocate DMA buffer
    pub fn allocate_dma_buffer(&self, size: usize) -> Result<*mut u8, Status> {
        let pages = (size + 4095) / 4096;
        
        // Allocate below 4GB for DMA
        let address = self.boot_services.allocate_pages(
            AllocateType::MaxAddress(0xFFFFFFFF),
            MemoryType::BOOT_SERVICES_DATA,
            pages,
        )?;
        
        Ok(address as *mut u8)
    }

    /// Get total memory size
    pub fn get_total_memory(&self) -> Result<u64, Status> {
        let memory_map = self.boot_services.get_memory_map()?;
        let mut total = 0u64;
        
        for descriptor in memory_map {
            if descriptor.ty != MemoryType::RESERVED {
                total += descriptor.page_count * 4096;
            }
        }
        
        Ok(total)
    }

    /// Get available memory size
    pub fn get_available_memory(&self) -> Result<u64, Status> {
        let memory_map = self.boot_services.get_memory_map()?;
        let mut available = 0u64;
        
        for descriptor in memory_map {
            if descriptor.ty == MemoryType::CONVENTIONAL {
                available += descriptor.page_count * 4096;
            }
        }
        
        Ok(available)
    }
}

/// Protocol services wrapper
pub struct ProtocolServices<'a> {
    boot_services: &'a BootServices<'a>,
}

impl<'a> ProtocolServices<'a> {
    pub fn new(boot_services: &'a BootServices<'a>) -> Self {
        Self { boot_services }
    }

    /// Find all handles supporting a protocol
    pub fn find_handles<P: uefi::proto::Protocol>(&self) -> Result<Vec<Handle>, Status> {
        self.boot_services.locate_handle_buffer(SearchType::ByProtocol(&P::GUID))
    }

    /// Open filesystem protocol
    pub fn open_filesystem(&self, handle: Handle) -> Result<&'a mut SimpleFileSystem, Status> {
        self.boot_services.open_protocol::<SimpleFileSystem>(
            handle,
            self.boot_services.system_table().boot_services().image_handle(),
            None,
            0x20, // EXCLUSIVE
        )
    }

    /// Get loaded image protocol
    pub fn get_loaded_image(&self, handle: Handle) -> Result<&'a mut LoadedImage, Status> {
        self.boot_services.open_protocol::<LoadedImage>(
            handle,
            self.boot_services.system_table().boot_services().image_handle(),
            None,
            0x20, // EXCLUSIVE
        )
    }
}

/// Console services wrapper
pub struct ConsoleServices<'a> {
    system_table: &'a SystemTable<Boot>,
}

impl<'a> ConsoleServices<'a> {
    pub fn new(system_table: &'a SystemTable<Boot>) -> Self {
        Self { system_table }
    }

    /// Clear screen
    pub fn clear(&mut self) -> Result<(), Status> {
        self.system_table.stdout().clear()
    }

    /// Print text
    pub fn print(&mut self, text: &str) -> Result<(), Status> {
        for ch in text.chars() {
            let mut buf = [0u16; 2];
            ch.encode_utf16(&mut buf);
            self.system_table.stdout().output_string(&buf)?;
        }
        Ok(())
    }

    /// Print line
    pub fn println(&mut self, text: &str) -> Result<(), Status> {
        self.print(text)?;
        self.print("\r\n")
    }

    /// Read key
    pub fn read_key(&mut self) -> Result<Key, Status> {
        self.system_table.stdin().read_key()
    }

    /// Set cursor position
    pub fn set_cursor_position(&mut self, column: usize, row: usize) -> Result<(), Status> {
        self.system_table.stdout().set_cursor_position(column, row)
    }

    /// Enable cursor
    pub fn enable_cursor(&mut self, visible: bool) -> Result<(), Status> {
        self.system_table.stdout().enable_cursor(visible)
    }
}

/// File services wrapper
pub struct FileServices<'a> {
    boot_services: &'a BootServices<'a>,
}

impl<'a> FileServices<'a> {
    pub fn new(boot_services: &'a BootServices<'a>) -> Self {
        Self { boot_services }
    }

    /// Open ESP (EFI System Partition)
    pub fn open_esp(&self) -> Result<Directory, Status> {
        let fs_handle = self.boot_services.get_handle_for_protocol::<SimpleFileSystem>()?;
        let mut fs = self.boot_services.open_protocol::<SimpleFileSystem>(
            fs_handle,
            self.boot_services.system_table().boot_services().image_handle(),
            None,
            0x20, // EXCLUSIVE
        )?;
        
        fs.open_volume()
    }

    /// Read file from ESP
    pub fn read_file(&self, path: &uefi::CStr16) -> Result<Vec<u8>, Status> {
        let mut root = self.open_esp()?;
        let mut file = root.open(path, FileMode::Read, FileAttribute::empty())?;
        
        // Get file size
        let mut info_buffer = [0u8; 512];
        let file_info = file.get_info::<FileInfo>(&mut info_buffer)?;
        let file_size = file_info.file_size() as usize;
        
        // Read file
        let mut buffer = vec![0u8; file_size];
        file.read(&mut buffer)?;
        
        Ok(buffer)
    }

    /// Write file to ESP
    pub fn write_file(&self, path: &uefi::CStr16, data: &[u8]) -> Result<(), Status> {
        let mut root = self.open_esp()?;
        let mut file = root.open(
            path,
            FileMode::CreateReadWrite,
            FileAttribute::empty(),
        )?;
        
        file.write(data)?;
        file.flush()?;
        
        Ok(())
    }

    /// Check if file exists
    pub fn file_exists(&self, path: &uefi::CStr16) -> bool {
        if let Ok(mut root) = self.open_esp() {
            if let Ok(mut file) = root.open(path, FileMode::Read, FileAttribute::empty()) {
                let _ = file.close();
                return true;
            }
        }
        false
    }

    /// List directory contents
    pub fn list_directory(&self, path: &uefi::CStr16) -> Result<Vec<String>, Status> {
        let mut root = self.open_esp()?;
        let mut dir = if path.is_empty() {
            root
        } else {
            root.open(path, FileMode::Read, FileAttribute::DIRECTORY)?
                .into_directory()
                .ok_or(Status::INVALID_PARAMETER)?
        };
        
        let mut entries = Vec::new();
        let mut buffer = [0u8; 512];
        
        loop {
            match dir.read_entry(&mut buffer) {
                Ok(Some(entry)) => {
                    let name = entry.file_name().to_string();
                    entries.push(name);
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        
        Ok(entries)
    }
}

extern crate alloc;