//! Guest OS loader implementation
//! Supports loading Linux kernel, multiboot, and ELF binaries

use alloc::vec::Vec;
use alloc::string::String;
use core::mem;
use crate::{HypervisorError, memory::MemoryManager, vcpu::VCpu};

/// Boot protocol types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BootProtocol {
    Linux,
    Multiboot,
    Multiboot2,
    Elf,
    Raw,
}

/// Linux boot parameters (based on Linux boot protocol)
#[repr(C, packed)]
pub struct LinuxBootParams {
    // Screen info (0x000)
    pub orig_x: u8,
    pub orig_y: u8,
    pub ext_mem_k: u16,
    pub orig_video_page: u16,
    pub orig_video_mode: u8,
    pub orig_video_cols: u8,
    pub flags: u8,
    pub unused2: u8,
    pub orig_video_ega_bx: u16,
    pub unused3: u16,
    pub orig_video_lines: u8,
    pub orig_video_isVGA: u8,
    pub orig_video_points: u16,
    
    // VESA info (0x010)
    pub vesa_attributes: u16,
    pub vesa_seg: u16,
    pub vesa_off: u16,
    pub vesa_mode: u16,
    pub vesa_width: u16,
    pub vesa_height: u16,
    pub vesa_xres: u16,
    pub vesa_yres: u16,
    
    // APM BIOS info (0x020)
    pub apm_bios_info: [u8; 20],
    
    // Drive info (0x034)
    pub drive_info: [u8; 32],
    
    // Video info (0x054)
    pub video_info: [u8; 64],
    
    // ISA PnP (0x094)
    pub isa_pnp: [u8; 16],
    
    // EFI info (0x0A4)
    pub efi_info: [u8; 32],
    
    // Alt mem info (0x0C4)
    pub alt_mem_k: u32,
    pub scratch: u32,
    pub e820_entries: u8,
    pub eddbuf_entries: u8,
    pub edd_mbr_sig_buf_entries: u8,
    pub kbd_status: u8,
    pub secure_boot: u8,
    pub sentinel: u8,
    pub reserved3: [u8; 2],
    
    // Header (0x1F0)
    pub hdr_pad: [u8; 0x1F0 - 0xD4],
    pub setup_sects: u8,
    pub root_flags: u16,
    pub syssize: u32,
    pub ram_size: u16,
    pub vid_mode: u16,
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: u16,
    pub header: u32,
    pub version: u16,
    pub realmode_swtch: u32,
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub kernel_info_offset: u32,
}

/// E820 memory map entry
#[repr(C, packed)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub entry_type: u32,
}

impl E820Entry {
    pub const TYPE_RAM: u32 = 1;
    pub const TYPE_RESERVED: u32 = 2;
    pub const TYPE_ACPI: u32 = 3;
    pub const TYPE_NVS: u32 = 4;
    pub const TYPE_UNUSABLE: u32 = 5;
}

/// Multiboot information structure
#[repr(C)]
pub struct MultibootInfo {
    pub flags: u32,
    pub mem_lower: u32,
    pub mem_upper: u32,
    pub boot_device: u32,
    pub cmdline: u32,
    pub mods_count: u32,
    pub mods_addr: u32,
    pub syms: [u32; 4],
    pub mmap_length: u32,
    pub mmap_addr: u32,
    pub drives_length: u32,
    pub drives_addr: u32,
    pub config_table: u32,
    pub boot_loader_name: u32,
    pub apm_table: u32,
    pub vbe_control_info: u32,
    pub vbe_mode_info: u32,
    pub vbe_mode: u16,
    pub vbe_interface_seg: u16,
    pub vbe_interface_off: u16,
    pub vbe_interface_len: u16,
}

/// ELF header
#[repr(C)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF program header
#[repr(C)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Guest OS loader
pub struct GuestLoader {
    memory_manager: *mut MemoryManager,
    boot_protocol: BootProtocol,
    entry_point: u64,
    kernel_base: u64,
    kernel_size: usize,
    initrd_base: u64,
    initrd_size: usize,
    cmdline: String,
    e820_map: Vec<E820Entry>,
}

impl GuestLoader {
    pub fn new(memory_manager: &mut MemoryManager) -> Self {
        Self {
            memory_manager: memory_manager as *mut _,
            boot_protocol: BootProtocol::Linux,
            entry_point: 0,
            kernel_base: 0x100000, // Default 1MB
            kernel_size: 0,
            initrd_base: 0x2000000, // Default 32MB
            initrd_size: 0,
            cmdline: String::new(),
            e820_map: Vec::new(),
        }
    }

    /// Load a Linux kernel
    pub fn load_linux(&mut self, kernel_data: &[u8], initrd_data: Option<&[u8]>, cmdline: &str) 
        -> Result<u64, HypervisorError> 
    {
        if kernel_data.len() < 0x202 {
            return Err(HypervisorError::InvalidParameter);
        }

        // Check Linux boot signature
        if kernel_data[0x1FE] != 0x55 || kernel_data[0x1FF] != 0xAA {
            return Err(HypervisorError::InvalidParameter);
        }

        // Check header magic "HdrS"
        if &kernel_data[0x202..0x206] != b"HdrS" {
            return Err(HypervisorError::InvalidParameter);
        }

        // Parse setup header
        let setup_sects = if kernel_data[0x1F1] == 0 { 4 } else { kernel_data[0x1F1] as usize };
        let setup_size = (setup_sects + 1) * 512;
        
        // Get protocol version
        let protocol = u16::from_le_bytes([kernel_data[0x206], kernel_data[0x207]]);
        
        // Allocate memory for boot params
        let boot_params_addr = 0x7000u64;
        let boot_params = unsafe {
            let mm = &mut *self.memory_manager;
            mm.write_guest_memory(boot_params_addr, &vec![0u8; mem::size_of::<LinuxBootParams>()])?;
            
            // Copy setup header
            mm.write_guest_memory(boot_params_addr + 0x1F0, &kernel_data[0x1F0..setup_size.min(kernel_data.len())])?;
            
            boot_params_addr as *mut LinuxBootParams
        };

        // Set up boot parameters
        unsafe {
            (*boot_params).type_of_loader = 0xFF; // Unknown bootloader
            (*boot_params).loadflags |= 0x01; // LOADED_HIGH
            (*boot_params).heap_end_ptr = 0xFE00;
            (*boot_params).ext_loader_ver = 0;
            (*boot_params).cmd_line_ptr = 0x20000; // Command line at 128KB
        }

        // Copy command line
        if !cmdline.is_empty() {
            let cmdline_bytes = cmdline.as_bytes();
            unsafe {
                let mm = &mut *self.memory_manager;
                mm.write_guest_memory(0x20000, cmdline_bytes)?;
                mm.write_guest_memory(0x20000 + cmdline_bytes.len() as u64, &[0u8])?; // Null terminator
            }
        }

        // Load kernel image
        let kernel_load_addr = if protocol >= 0x0200 {
            // Use protected mode entry point
            0x100000u64 // 1MB
        } else {
            // Real mode kernel
            0x10000u64 // 64KB
        };

        unsafe {
            let mm = &mut *self.memory_manager;
            let kernel_image = &kernel_data[setup_size..];
            mm.write_guest_memory(kernel_load_addr, kernel_image)?;
            self.kernel_size = kernel_image.len();
        }

        // Load initrd if provided
        if let Some(initrd) = initrd_data {
            let initrd_addr = 0x2000000u64; // 32MB
            unsafe {
                let mm = &mut *self.memory_manager;
                mm.write_guest_memory(initrd_addr, initrd)?;
                
                (*boot_params).ramdisk_image = initrd_addr as u32;
                (*boot_params).ramdisk_size = initrd.len() as u32;
            }
            self.initrd_base = initrd_addr;
            self.initrd_size = initrd.len();
        }

        // Set up E820 memory map
        self.setup_e820_map()?;
        
        // Write E820 map to boot params
        let e820_addr = boot_params_addr + 0x2D0;
        for (i, entry) in self.e820_map.iter().enumerate() {
            if i >= 128 { break; } // Max 128 entries
            
            unsafe {
                let mm = &mut *self.memory_manager;
                let entry_bytes = core::slice::from_raw_parts(
                    entry as *const _ as *const u8,
                    mem::size_of::<E820Entry>()
                );
                mm.write_guest_memory(e820_addr + (i * mem::size_of::<E820Entry>()) as u64, entry_bytes)?;
            }
        }
        
        unsafe {
            (*boot_params).e820_entries = self.e820_map.len().min(128) as u8;
        }

        // Set entry point
        self.entry_point = kernel_load_addr;
        self.boot_protocol = BootProtocol::Linux;
        
        Ok(self.entry_point)
    }

    /// Load a multiboot kernel
    pub fn load_multiboot(&mut self, kernel_data: &[u8], modules: &[(&str, &[u8])], cmdline: &str) 
        -> Result<u64, HypervisorError> 
    {
        // Check multiboot magic
        if kernel_data.len() < 12 {
            return Err(HypervisorError::InvalidParameter);
        }

        // Search for multiboot header
        let mut header_offset = None;
        for i in 0..8192.min(kernel_data.len() - 12) {
            if u32::from_le_bytes([kernel_data[i], kernel_data[i+1], kernel_data[i+2], kernel_data[i+3]]) == 0x1BADB002 {
                header_offset = Some(i);
                break;
            }
        }

        let header_offset = header_offset.ok_or(HypervisorError::InvalidParameter)?;
        
        // Parse multiboot header
        let flags = u32::from_le_bytes([
            kernel_data[header_offset + 4],
            kernel_data[header_offset + 5],
            kernel_data[header_offset + 6],
            kernel_data[header_offset + 7],
        ]);

        // Load kernel (assume ELF format)
        let entry = self.load_elf(kernel_data)?;
        
        // Set up multiboot info structure
        let mbi_addr = 0x7000u64;
        let mbi = MultibootInfo {
            flags: 0x1247, // Memory info, cmdline, modules, mmap
            mem_lower: 640,
            mem_upper: (128 * 1024) - 1024, // 128MB - 1MB
            boot_device: 0,
            cmdline: 0x8000,
            mods_count: modules.len() as u32,
            mods_addr: 0x9000,
            syms: [0; 4],
            mmap_length: (self.e820_map.len() * 24) as u32,
            mmap_addr: 0xA000,
            drives_length: 0,
            drives_addr: 0,
            config_table: 0,
            boot_loader_name: 0xB000,
            apm_table: 0,
            vbe_control_info: 0,
            vbe_mode_info: 0,
            vbe_mode: 0,
            vbe_interface_seg: 0,
            vbe_interface_off: 0,
            vbe_interface_len: 0,
        };

        unsafe {
            let mm = &mut *self.memory_manager;
            
            // Write multiboot info
            let mbi_bytes = core::slice::from_raw_parts(
                &mbi as *const _ as *const u8,
                mem::size_of::<MultibootInfo>()
            );
            mm.write_guest_memory(mbi_addr, mbi_bytes)?;
            
            // Write command line
            mm.write_guest_memory(0x8000, cmdline.as_bytes())?;
            mm.write_guest_memory(0x8000 + cmdline.len() as u64, &[0u8])?;
            
            // Write bootloader name
            let bootloader_name = b"Hypervisor-Rust\0";
            mm.write_guest_memory(0xB000, bootloader_name)?;
            
            // Load modules
            let mut mod_addr = 0x100000u64;
            for (i, (name, data)) in modules.iter().enumerate() {
                // Align to page boundary
                mod_addr = (mod_addr + 0xFFF) & !0xFFF;
                
                // Write module data
                mm.write_guest_memory(mod_addr, data)?;
                
                // Write module descriptor
                let mod_desc = [
                    mod_addr as u32,
                    (mod_addr + data.len() as u64) as u32,
                    (0xC000 + i * 256) as u32, // Module command line
                    0u32, // Reserved
                ];
                
                let mod_desc_bytes: [u8; 16] = unsafe { mem::transmute(mod_desc) };
                mm.write_guest_memory(0x9000 + (i * 16) as u64, &mod_desc_bytes)?;
                
                // Write module name
                mm.write_guest_memory((0xC000 + i * 256) as u64, name.as_bytes())?;
                mm.write_guest_memory((0xC000 + i * 256 + name.len()) as u64, &[0u8])?;
                
                mod_addr += data.len() as u64;
            }
        }

        self.boot_protocol = BootProtocol::Multiboot;
        self.entry_point = entry;
        
        Ok(self.entry_point)
    }

    /// Load an ELF binary
    pub fn load_elf(&mut self, elf_data: &[u8]) -> Result<u64, HypervisorError> {
        if elf_data.len() < mem::size_of::<Elf64Header>() {
            return Err(HypervisorError::InvalidParameter);
        }

        // Check ELF magic
        if &elf_data[0..4] != b"\x7FELF" {
            return Err(HypervisorError::InvalidParameter);
        }

        // Check 64-bit
        if elf_data[4] != 2 {
            return Err(HypervisorError::InvalidParameter);
        }

        // Parse ELF header
        let header = unsafe {
            &*(elf_data.as_ptr() as *const Elf64Header)
        };

        // Load program segments
        let ph_offset = header.e_phoff as usize;
        let ph_size = header.e_phentsize as usize;
        let ph_count = header.e_phnum as usize;

        for i in 0..ph_count {
            let ph_start = ph_offset + i * ph_size;
            if ph_start + mem::size_of::<Elf64ProgramHeader>() > elf_data.len() {
                break;
            }

            let ph = unsafe {
                &*(elf_data[ph_start..].as_ptr() as *const Elf64ProgramHeader)
            };

            // Only load PT_LOAD segments
            if ph.p_type != 1 {
                continue;
            }

            // Load segment
            let file_offset = ph.p_offset as usize;
            let file_size = ph.p_filesz as usize;
            let mem_size = ph.p_memsz as usize;
            let vaddr = ph.p_vaddr;

            if file_offset + file_size > elf_data.len() {
                return Err(HypervisorError::InvalidParameter);
            }

            unsafe {
                let mm = &mut *self.memory_manager;
                
                // Copy file data
                if file_size > 0 {
                    mm.write_guest_memory(vaddr, &elf_data[file_offset..file_offset + file_size])?;
                }
                
                // Zero BSS
                if mem_size > file_size {
                    let zeros = vec![0u8; mem_size - file_size];
                    mm.write_guest_memory(vaddr + file_size as u64, &zeros)?;
                }
            }
        }

        self.boot_protocol = BootProtocol::Elf;
        self.entry_point = header.e_entry;
        
        Ok(self.entry_point)
    }

    /// Load raw binary
    pub fn load_raw(&mut self, data: &[u8], load_addr: u64, entry_offset: u64) 
        -> Result<u64, HypervisorError> 
    {
        unsafe {
            let mm = &mut *self.memory_manager;
            mm.write_guest_memory(load_addr, data)?;
        }

        self.boot_protocol = BootProtocol::Raw;
        self.entry_point = load_addr + entry_offset;
        self.kernel_base = load_addr;
        self.kernel_size = data.len();
        
        Ok(self.entry_point)
    }

    /// Set up E820 memory map
    fn setup_e820_map(&mut self) -> Result<(), HypervisorError> {
        self.e820_map.clear();
        
        // BIOS area
        self.e820_map.push(E820Entry {
            addr: 0x0,
            size: 0x9FC00,
            entry_type: E820Entry::TYPE_RAM,
        });
        
        // Reserved BIOS area
        self.e820_map.push(E820Entry {
            addr: 0x9FC00,
            size: 0x400,
            entry_type: E820Entry::TYPE_RESERVED,
        });
        
        // Extended BIOS data area
        self.e820_map.push(E820Entry {
            addr: 0xE0000,
            size: 0x20000,
            entry_type: E820Entry::TYPE_RESERVED,
        });
        
        // Main memory (1MB to 128MB)
        self.e820_map.push(E820Entry {
            addr: 0x100000,
            size: 0x7F00000,
            entry_type: E820Entry::TYPE_RAM,
        });
        
        Ok(())
    }

    /// Configure VCPU for guest entry
    pub fn configure_vcpu(&self, vcpu: &mut VCpu) -> Result<(), HypervisorError> {
        match self.boot_protocol {
            BootProtocol::Linux => {
                // Linux boot protocol
                vcpu.set_register("rip", self.entry_point)?;
                vcpu.set_register("rsi", 0x7000)?; // Boot params pointer
                vcpu.set_register("rsp", 0x7FF0)?; // Stack
                
                // Set up segment registers for protected mode
                vcpu.set_segment("cs", 0x10, 0, 0xFFFFFFFF, 0xC09B)?;
                vcpu.set_segment("ds", 0x18, 0, 0xFFFFFFFF, 0xC093)?;
                vcpu.set_segment("es", 0x18, 0, 0xFFFFFFFF, 0xC093)?;
                vcpu.set_segment("fs", 0x18, 0, 0xFFFFFFFF, 0xC093)?;
                vcpu.set_segment("gs", 0x18, 0, 0xFFFFFFFF, 0xC093)?;
                vcpu.set_segment("ss", 0x18, 0, 0xFFFFFFFF, 0xC093)?;
                
                // Enable protected mode and paging
                vcpu.set_control_register("cr0", 0x80000011)?; // PG | WP | PE
                vcpu.set_control_register("cr4", 0x20)?; // PAE
            }
            
            BootProtocol::Multiboot => {
                // Multiboot protocol
                vcpu.set_register("rip", self.entry_point)?;
                vcpu.set_register("eax", 0x2BADB002)?; // Multiboot magic
                vcpu.set_register("ebx", 0x7000)?; // Multiboot info pointer
                vcpu.set_register("rsp", 0x7FF0)?;
            }
            
            BootProtocol::Elf | BootProtocol::Raw => {
                // Simple entry
                vcpu.set_register("rip", self.entry_point)?;
                vcpu.set_register("rsp", 0x7FF0)?;
            }
            
            _ => {}
        }
        
        Ok(())
    }
}

/// BIOS/UEFI emulation for legacy guests
pub struct BiosEmulator {
    interrupt_handlers: Vec<fn(regs: &mut X86Registers)>,
}

#[derive(Default)]
pub struct X86Registers {
    pub ax: u16,
    pub bx: u16,
    pub cx: u16,
    pub dx: u16,
    pub si: u16,
    pub di: u16,
    pub bp: u16,
    pub sp: u16,
    pub ip: u16,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub flags: u16,
}

impl BiosEmulator {
    pub fn new() -> Self {
        let mut handlers = vec![|_: &mut X86Registers| {}; 256];
        
        // INT 10h - Video services
        handlers[0x10] = |regs| {
            match (regs.ax >> 8) as u8 {
                0x00 => {
                    // Set video mode
                    log::debug!("BIOS: Set video mode {:#x}", regs.ax & 0xFF);
                }
                0x0E => {
                    // Teletype output
                    log::debug!("BIOS: Output character '{}'", (regs.ax & 0xFF) as u8 as char);
                }
                _ => {}
            }
        };
        
        // INT 13h - Disk services
        handlers[0x13] = |regs| {
            match (regs.ax >> 8) as u8 {
                0x00 => {
                    // Reset disk
                    regs.ax = 0; // Success
                    regs.flags &= !0x01; // Clear carry
                }
                0x02 => {
                    // Read sectors
                    log::debug!("BIOS: Read {} sectors from CHS {}/{}/{}", 
                        regs.ax & 0xFF, regs.cx >> 8, regs.dx >> 8, regs.cx & 0x3F);
                    regs.ax = (regs.ax & 0xFF00) | ((regs.ax & 0xFF) as u16); // Sectors read
                    regs.flags &= !0x01; // Clear carry
                }
                0x08 => {
                    // Get drive parameters
                    regs.cx = 0x4F12; // 79 cylinders, 18 sectors
                    regs.dx = 0x0101; // 1 head, drive 1
                    regs.ax = 0;
                    regs.flags &= !0x01;
                }
                _ => {}
            }
        };
        
        // INT 15h - System services
        handlers[0x15] = |regs| {
            match (regs.ax >> 8) as u8 {
                0x88 => {
                    // Get extended memory size
                    regs.ax = 0x3C00; // 15MB
                    regs.flags &= !0x01;
                }
                0xE8 => {
                    match regs.ax & 0xFF {
                        0x01 => {
                            // Get memory map (E801)
                            regs.ax = 0x3C00; // 15MB at 1MB
                            regs.bx = 0;
                            regs.cx = 0x3C00;
                            regs.dx = 0;
                            regs.flags &= !0x01;
                        }
                        0x20 => {
                            // Get memory map (E820)
                            // This would need more complex handling
                            regs.flags |= 0x01; // Set carry (not supported)
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        };
        
        // INT 16h - Keyboard services
        handlers[0x16] = |regs| {
            match (regs.ax >> 8) as u8 {
                0x00 => {
                    // Get keystroke
                    regs.ax = 0; // No key available
                }
                0x01 => {
                    // Check keystroke
                    regs.flags |= 0x40; // Set ZF (no key)
                }
                _ => {}
            }
        };
        
        Self {
            interrupt_handlers: handlers,
        }
    }

    pub fn handle_interrupt(&mut self, vector: u8, regs: &mut X86Registers) {
        if (vector as usize) < self.interrupt_handlers.len() {
            (self.interrupt_handlers[vector as usize])(regs);
        }
    }
}

extern crate alloc;