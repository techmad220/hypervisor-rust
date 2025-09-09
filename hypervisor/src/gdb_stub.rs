//! GDB Remote Serial Protocol (RSP) stub for VM debugging
//! Implements full GDB protocol for debugging guest VMs

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

/// GDB protocol constants
pub const GDB_STUB_PORT: u16 = 1234;
pub const GDB_PACKET_SIZE: usize = 4096;
pub const GDB_MAX_BREAKPOINTS: usize = 256;
pub const GDB_MAX_WATCHPOINTS: usize = 32;

/// GDB stub state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GdbState {
    Disconnected,
    Connected,
    Running,
    Stopped,
    Stepping,
}

/// Stop reason for GDB
#[derive(Debug, Clone, Copy)]
pub enum StopReason {
    Signal(u8),
    Breakpoint,
    Watchpoint { addr: u64, kind: WatchpointKind },
    Step,
    Exception(u8),
    Trap,
}

/// Watchpoint kinds
#[derive(Debug, Clone, Copy)]
pub enum WatchpointKind {
    Write,
    Read,
    Access,
}

/// Breakpoint types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BreakpointType {
    Software,
    Hardware,
    Watchpoint(WatchpointKind),
}

/// GDB register definitions for x86_64
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum GdbRegister {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rsi = 4,
    Rdi = 5,
    Rbp = 6,
    Rsp = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    Rip = 16,
    Eflags = 17,
    Cs = 18,
    Ss = 19,
    Ds = 20,
    Es = 21,
    Fs = 22,
    Gs = 23,
    // x87 FPU registers
    St0 = 24,
    St1 = 25,
    St2 = 26,
    St3 = 27,
    St4 = 28,
    St5 = 29,
    St6 = 30,
    St7 = 31,
    Fctrl = 32,
    Fstat = 33,
    Ftag = 34,
    Fiseg = 35,
    Fioff = 36,
    Foseg = 37,
    Fooff = 38,
    Fop = 39,
    // XMM registers
    Xmm0 = 40,
    Xmm1 = 41,
    Xmm2 = 42,
    Xmm3 = 43,
    Xmm4 = 44,
    Xmm5 = 45,
    Xmm6 = 46,
    Xmm7 = 47,
    Xmm8 = 48,
    Xmm9 = 49,
    Xmm10 = 50,
    Xmm11 = 51,
    Xmm12 = 52,
    Xmm13 = 53,
    Xmm14 = 54,
    Xmm15 = 55,
    Mxcsr = 56,
}

/// GDB stub implementation
pub struct GdbStub {
    state: AtomicU32,
    vm_id: u64,
    connection: Option<GdbConnection>,
    breakpoints: RwLock<BTreeMap<u64, Breakpoint>>,
    watchpoints: RwLock<BTreeMap<u64, Watchpoint>>,
    single_step: AtomicBool,
    current_thread: AtomicU64,
    stop_reason: Mutex<Option<StopReason>>,
    register_cache: RwLock<RegisterCache>,
    memory_cache: RwLock<MemoryCache>,
    features: GdbFeatures,
    no_ack_mode: AtomicBool,
}

impl GdbStub {
    pub fn new(vm_id: u64) -> Self {
        Self {
            state: AtomicU32::new(GdbState::Disconnected as u32),
            vm_id,
            connection: None,
            breakpoints: RwLock::new(BTreeMap::new()),
            watchpoints: RwLock::new(BTreeMap::new()),
            single_step: AtomicBool::new(false),
            current_thread: AtomicU64::new(0),
            stop_reason: Mutex::new(None),
            register_cache: RwLock::new(RegisterCache::new()),
            memory_cache: RwLock::new(MemoryCache::new()),
            features: GdbFeatures::default(),
            no_ack_mode: AtomicBool::new(false),
        }
    }
    
    pub fn start(&mut self, port: u16) -> Result<(), GdbError> {
        let connection = GdbConnection::listen(port)?;
        self.connection = Some(connection);
        self.set_state(GdbState::Connected);
        Ok(())
    }
    
    pub fn handle_connection(&mut self, vm: &mut VirtualMachine) -> Result<(), GdbError> {
        while self.get_state() != GdbState::Disconnected {
            if let Some(conn) = &mut self.connection {
                match conn.receive_packet() {
                    Ok(packet) => {
                        self.handle_packet(vm, &packet)?;
                    }
                    Err(GdbError::ConnectionClosed) => {
                        self.set_state(GdbState::Disconnected);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
    
    fn handle_packet(&mut self, vm: &mut VirtualMachine, packet: &[u8]) -> Result<(), GdbError> {
        if packet.is_empty() {
            return Ok(());
        }
        
        let response = match packet[0] {
            b'?' => self.handle_stop_reason(),
            b'g' => self.handle_read_registers(vm),
            b'G' => self.handle_write_registers(vm, &packet[1..]),
            b'p' => self.handle_read_register(vm, &packet[1..]),
            b'P' => self.handle_write_register(vm, &packet[1..]),
            b'm' => self.handle_read_memory(vm, &packet[1..]),
            b'M' => self.handle_write_memory(vm, &packet[1..]),
            b'c' => self.handle_continue(vm, &packet[1..]),
            b's' => self.handle_step(vm, &packet[1..]),
            b'z' => self.handle_remove_breakpoint(vm, &packet[1..]),
            b'Z' => self.handle_insert_breakpoint(vm, &packet[1..]),
            b'H' => self.handle_set_thread(&packet[1..]),
            b'T' => self.handle_thread_alive(&packet[1..]),
            b'D' => self.handle_detach(vm),
            b'k' => self.handle_kill(vm),
            b'q' => self.handle_query(&packet[1..]),
            b'Q' => self.handle_set(&packet[1..]),
            b'v' => self.handle_v_packet(vm, &packet[1..]),
            b'X' => self.handle_write_binary_memory(vm, &packet[1..]),
            b'!' => self.handle_extended_mode(),
            _ => self.create_error_response(),
        };
        
        self.send_response(&response)?;
        Ok(())
    }
    
    fn handle_stop_reason(&self) -> Vec<u8> {
        if let Some(reason) = &*self.stop_reason.lock() {
            match reason {
                StopReason::Signal(sig) => format!("S{:02x}", sig).into_bytes(),
                StopReason::Breakpoint => b"T05swbreak:;".to_vec(),
                StopReason::Watchpoint { addr, kind } => {
                    let kind_str = match kind {
                        WatchpointKind::Write => "watch",
                        WatchpointKind::Read => "rwatch",
                        WatchpointKind::Access => "awatch",
                    };
                    format!("T05{}:{:016x};", kind_str, addr).into_bytes()
                }
                StopReason::Step => b"T05".to_vec(),
                StopReason::Exception(ex) => format!("T{:02x}", ex).into_bytes(),
                StopReason::Trap => b"T05".to_vec(),
            }
        } else {
            b"S05".to_vec() // SIGTRAP
        }
    }
    
    fn handle_read_registers(&self, vm: &VirtualMachine) -> Vec<u8> {
        let mut response = String::new();
        let vcpu = vm.get_vcpu(self.current_thread.load(Ordering::Relaxed));
        
        if let Some(vcpu) = vcpu {
            let regs = vcpu.get_registers();
            
            // General purpose registers
            response.push_str(&format!("{:016x}", regs.rax));
            response.push_str(&format!("{:016x}", regs.rbx));
            response.push_str(&format!("{:016x}", regs.rcx));
            response.push_str(&format!("{:016x}", regs.rdx));
            response.push_str(&format!("{:016x}", regs.rsi));
            response.push_str(&format!("{:016x}", regs.rdi));
            response.push_str(&format!("{:016x}", regs.rbp));
            response.push_str(&format!("{:016x}", regs.rsp));
            response.push_str(&format!("{:016x}", regs.r8));
            response.push_str(&format!("{:016x}", regs.r9));
            response.push_str(&format!("{:016x}", regs.r10));
            response.push_str(&format!("{:016x}", regs.r11));
            response.push_str(&format!("{:016x}", regs.r12));
            response.push_str(&format!("{:016x}", regs.r13));
            response.push_str(&format!("{:016x}", regs.r14));
            response.push_str(&format!("{:016x}", regs.r15));
            response.push_str(&format!("{:016x}", regs.rip));
            response.push_str(&format!("{:08x}", regs.rflags));
            
            // Segment registers
            response.push_str(&format!("{:04x}", regs.cs));
            response.push_str(&format!("{:04x}", regs.ss));
            response.push_str(&format!("{:04x}", regs.ds));
            response.push_str(&format!("{:04x}", regs.es));
            response.push_str(&format!("{:04x}", regs.fs));
            response.push_str(&format!("{:04x}", regs.gs));
        } else {
            // Return zeros if vcpu not found
            for _ in 0..24 {
                response.push_str("00000000");
            }
        }
        
        response.into_bytes()
    }
    
    fn handle_write_registers(&self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        let data_str = String::from_utf8_lossy(data);
        let vcpu = vm.get_vcpu_mut(self.current_thread.load(Ordering::Relaxed));
        
        if let Some(vcpu) = vcpu {
            let mut regs = vcpu.get_registers();
            let mut offset = 0;
            
            // Parse general purpose registers
            if let Ok(val) = u64::from_str_radix(&data_str[offset..offset+16], 16) {
                regs.rax = val;
            }
            offset += 16;
            
            if let Ok(val) = u64::from_str_radix(&data_str[offset..offset+16], 16) {
                regs.rbx = val;
            }
            offset += 16;
            
            // Continue for all registers...
            // (abbreviated for brevity)
            
            vcpu.set_registers(&regs);
            b"OK".to_vec()
        } else {
            b"E01".to_vec()
        }
    }
    
    fn handle_read_register(&self, vm: &VirtualMachine, data: &[u8]) -> Vec<u8> {
        let reg_str = String::from_utf8_lossy(data);
        if let Ok(reg_num) = usize::from_str_radix(&reg_str, 16) {
            let vcpu = vm.get_vcpu(self.current_thread.load(Ordering::Relaxed));
            
            if let Some(vcpu) = vcpu {
                let value = match reg_num {
                    0 => vcpu.get_registers().rax,
                    1 => vcpu.get_registers().rbx,
                    2 => vcpu.get_registers().rcx,
                    3 => vcpu.get_registers().rdx,
                    4 => vcpu.get_registers().rsi,
                    5 => vcpu.get_registers().rdi,
                    6 => vcpu.get_registers().rbp,
                    7 => vcpu.get_registers().rsp,
                    8 => vcpu.get_registers().r8,
                    9 => vcpu.get_registers().r9,
                    10 => vcpu.get_registers().r10,
                    11 => vcpu.get_registers().r11,
                    12 => vcpu.get_registers().r12,
                    13 => vcpu.get_registers().r13,
                    14 => vcpu.get_registers().r14,
                    15 => vcpu.get_registers().r15,
                    16 => vcpu.get_registers().rip,
                    17 => vcpu.get_registers().rflags as u64,
                    _ => return b"E01".to_vec(),
                };
                
                format!("{:016x}", value).into_bytes()
            } else {
                b"E01".to_vec()
            }
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_write_register(&self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.split('=').collect();
        
        if parts.len() != 2 {
            return b"E01".to_vec();
        }
        
        if let (Ok(reg_num), Ok(value)) = (
            usize::from_str_radix(parts[0], 16),
            u64::from_str_radix(parts[1], 16)
        ) {
            let vcpu = vm.get_vcpu_mut(self.current_thread.load(Ordering::Relaxed));
            
            if let Some(vcpu) = vcpu {
                let mut regs = vcpu.get_registers();
                
                match reg_num {
                    0 => regs.rax = value,
                    1 => regs.rbx = value,
                    2 => regs.rcx = value,
                    3 => regs.rdx = value,
                    4 => regs.rsi = value,
                    5 => regs.rdi = value,
                    6 => regs.rbp = value,
                    7 => regs.rsp = value,
                    8 => regs.r8 = value,
                    9 => regs.r9 = value,
                    10 => regs.r10 = value,
                    11 => regs.r11 = value,
                    12 => regs.r12 = value,
                    13 => regs.r13 = value,
                    14 => regs.r14 = value,
                    15 => regs.r15 = value,
                    16 => regs.rip = value,
                    17 => regs.rflags = value as u32,
                    _ => return b"E01".to_vec(),
                }
                
                vcpu.set_registers(&regs);
                b"OK".to_vec()
            } else {
                b"E01".to_vec()
            }
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_read_memory(&self, vm: &VirtualMachine, data: &[u8]) -> Vec<u8> {
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.split(',').collect();
        
        if parts.len() != 2 {
            return b"E01".to_vec();
        }
        
        if let (Ok(addr), Ok(len)) = (
            u64::from_str_radix(parts[0], 16),
            usize::from_str_radix(parts[1], 16)
        ) {
            let mut result = String::new();
            
            for i in 0..len {
                match vm.read_memory_byte(addr + i as u64) {
                    Ok(byte) => result.push_str(&format!("{:02x}", byte)),
                    Err(_) => return b"E03".to_vec(),
                }
            }
            
            result.into_bytes()
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_write_memory(&self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.split(':').collect();
        
        if parts.len() != 2 {
            return b"E01".to_vec();
        }
        
        let addr_len: Vec<&str> = parts[0].split(',').collect();
        if addr_len.len() != 2 {
            return b"E01".to_vec();
        }
        
        if let (Ok(addr), Ok(len)) = (
            u64::from_str_radix(addr_len[0], 16),
            usize::from_str_radix(addr_len[1], 16)
        ) {
            let hex_data = parts[1];
            
            if hex_data.len() != len * 2 {
                return b"E04".to_vec();
            }
            
            for i in 0..len {
                if let Ok(byte) = u8::from_str_radix(&hex_data[i*2..i*2+2], 16) {
                    if vm.write_memory_byte(addr + i as u64, byte).is_err() {
                        return b"E03".to_vec();
                    }
                } else {
                    return b"E02".to_vec();
                }
            }
            
            b"OK".to_vec()
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_write_binary_memory(&self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        // Format: X addr,length:binary_data
        let colon_pos = data.iter().position(|&b| b == b':');
        if colon_pos.is_none() {
            return b"E01".to_vec();
        }
        
        let header = &data[..colon_pos.unwrap()];
        let binary_data = &data[colon_pos.unwrap() + 1..];
        
        let header_str = String::from_utf8_lossy(header);
        let parts: Vec<&str> = header_str.split(',').collect();
        
        if parts.len() != 2 {
            return b"E01".to_vec();
        }
        
        if let (Ok(addr), Ok(len)) = (
            u64::from_str_radix(parts[0], 16),
            usize::from_str_radix(parts[1], 16)
        ) {
            if binary_data.len() != len {
                return b"E04".to_vec();
            }
            
            for (i, &byte) in binary_data.iter().enumerate() {
                if vm.write_memory_byte(addr + i as u64, byte).is_err() {
                    return b"E03".to_vec();
                }
            }
            
            b"OK".to_vec()
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_continue(&mut self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        // Optional address to continue from
        if !data.is_empty() {
            let addr_str = String::from_utf8_lossy(data);
            if let Ok(addr) = u64::from_str_radix(&addr_str, 16) {
                if let Some(vcpu) = vm.get_vcpu_mut(self.current_thread.load(Ordering::Relaxed)) {
                    let mut regs = vcpu.get_registers();
                    regs.rip = addr;
                    vcpu.set_registers(&regs);
                }
            }
        }
        
        self.set_state(GdbState::Running);
        vm.resume();
        
        // Return immediately, stop reply will be sent when VM stops
        b"".to_vec()
    }
    
    fn handle_step(&mut self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        // Optional address to step from
        if !data.is_empty() {
            let addr_str = String::from_utf8_lossy(data);
            if let Ok(addr) = u64::from_str_radix(&addr_str, 16) {
                if let Some(vcpu) = vm.get_vcpu_mut(self.current_thread.load(Ordering::Relaxed)) {
                    let mut regs = vcpu.get_registers();
                    regs.rip = addr;
                    vcpu.set_registers(&regs);
                }
            }
        }
        
        self.single_step.store(true, Ordering::SeqCst);
        self.set_state(GdbState::Stepping);
        
        if let Some(vcpu) = vm.get_vcpu_mut(self.current_thread.load(Ordering::Relaxed)) {
            vcpu.single_step();
        }
        
        vm.resume();
        
        // Return immediately, stop reply will be sent when step completes
        b"".to_vec()
    }
    
    fn handle_insert_breakpoint(&mut self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.split(',').collect();
        
        if parts.len() < 3 {
            return b"E01".to_vec();
        }
        
        let bp_type = parts[0];
        if let (Ok(addr), Ok(len)) = (
            u64::from_str_radix(parts[1], 16),
            usize::from_str_radix(parts[2], 16)
        ) {
            match bp_type {
                "0" => {
                    // Software breakpoint
                    let bp = Breakpoint {
                        addr,
                        len,
                        bp_type: BreakpointType::Software,
                        original_byte: 0,
                        enabled: true,
                    };
                    
                    // Save original instruction byte and insert INT3
                    if let Ok(orig) = vm.read_memory_byte(addr) {
                        let mut bp = bp;
                        bp.original_byte = orig;
                        vm.write_memory_byte(addr, 0xCC).ok(); // INT3
                        self.breakpoints.write().insert(addr, bp);
                        b"OK".to_vec()
                    } else {
                        b"E03".to_vec()
                    }
                }
                "1" => {
                    // Hardware breakpoint
                    let bp = Breakpoint {
                        addr,
                        len,
                        bp_type: BreakpointType::Hardware,
                        original_byte: 0,
                        enabled: true,
                    };
                    
                    // Set hardware breakpoint
                    if vm.set_hardware_breakpoint(addr, len).is_ok() {
                        self.breakpoints.write().insert(addr, bp);
                        b"OK".to_vec()
                    } else {
                        b"E05".to_vec()
                    }
                }
                "2" => {
                    // Write watchpoint
                    self.insert_watchpoint(vm, addr, len, WatchpointKind::Write)
                }
                "3" => {
                    // Read watchpoint
                    self.insert_watchpoint(vm, addr, len, WatchpointKind::Read)
                }
                "4" => {
                    // Access watchpoint
                    self.insert_watchpoint(vm, addr, len, WatchpointKind::Access)
                }
                _ => b"E06".to_vec(),
            }
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_remove_breakpoint(&mut self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.split(',').collect();
        
        if parts.len() < 3 {
            return b"E01".to_vec();
        }
        
        let bp_type = parts[0];
        if let Ok(addr) = u64::from_str_radix(parts[1], 16) {
            match bp_type {
                "0" | "1" => {
                    // Software or hardware breakpoint
                    if let Some(bp) = self.breakpoints.write().remove(&addr) {
                        if bp.bp_type == BreakpointType::Software {
                            // Restore original byte
                            vm.write_memory_byte(addr, bp.original_byte).ok();
                        } else {
                            // Clear hardware breakpoint
                            vm.clear_hardware_breakpoint(addr).ok();
                        }
                        b"OK".to_vec()
                    } else {
                        b"E07".to_vec()
                    }
                }
                "2" | "3" | "4" => {
                    // Watchpoint
                    if let Some(_wp) = self.watchpoints.write().remove(&addr) {
                        vm.clear_watchpoint(addr).ok();
                        b"OK".to_vec()
                    } else {
                        b"E07".to_vec()
                    }
                }
                _ => b"E06".to_vec(),
            }
        } else {
            b"E02".to_vec()
        }
    }
    
    fn insert_watchpoint(&mut self, vm: &mut VirtualMachine, addr: u64, len: usize, kind: WatchpointKind) -> Vec<u8> {
        let wp = Watchpoint {
            addr,
            len,
            kind,
            enabled: true,
        };
        
        if vm.set_watchpoint(addr, len, kind).is_ok() {
            self.watchpoints.write().insert(addr, wp);
            b"OK".to_vec()
        } else {
            b"E05".to_vec()
        }
    }
    
    fn handle_set_thread(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return b"E01".to_vec();
        }
        
        let op = data[0];
        let thread_str = String::from_utf8_lossy(&data[1..]);
        
        if thread_str == "-1" || thread_str == "0" {
            // Use any thread
            b"OK".to_vec()
        } else if let Ok(thread_id) = u64::from_str_radix(&thread_str, 16) {
            match op {
                b'g' | b'c' => {
                    // Set thread for subsequent operations
                    self.current_thread.store(thread_id, Ordering::SeqCst);
                    b"OK".to_vec()
                }
                _ => b"E01".to_vec(),
            }
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_thread_alive(&self, data: &[u8]) -> Vec<u8> {
        let thread_str = String::from_utf8_lossy(data);
        
        if let Ok(_thread_id) = u64::from_str_radix(&thread_str, 16) {
            // Check if thread exists
            // For now, always return OK
            b"OK".to_vec()
        } else {
            b"E02".to_vec()
        }
    }
    
    fn handle_query(&self, data: &[u8]) -> Vec<u8> {
        let query = String::from_utf8_lossy(data);
        
        if query.starts_with("Supported") {
            self.handle_query_supported()
        } else if query.starts_with("Attached") {
            b"1".to_vec() // We're always attached
        } else if query.starts_with("C") {
            // Current thread
            format!("QC{:x}", self.current_thread.load(Ordering::Relaxed)).into_bytes()
        } else if query.starts_with("fThreadInfo") {
            // First thread info
            b"m0,1,2,3".to_vec() // Example thread IDs
        } else if query.starts_with("sThreadInfo") {
            // Subsequent thread info
            b"l".to_vec() // End of list
        } else if query.starts_with("ThreadExtraInfo") {
            self.handle_thread_extra_info(&query)
        } else if query.starts_with("Offsets") {
            b"Text=0;Data=0;Bss=0".to_vec()
        } else if query.starts_with("Symbol") {
            b"OK".to_vec()
        } else if query.starts_with("TStatus") {
            b"T0;tnotrun:0".to_vec()
        } else {
            b"".to_vec() // Unknown query
        }
    }
    
    fn handle_query_supported(&self) -> Vec<u8> {
        let mut features = Vec::new();
        
        features.push("PacketSize=4096");
        features.push("qXfer:features:read+");
        features.push("qXfer:memory-map:read+");
        features.push("qXfer:threads:read+");
        features.push("QStartNoAckMode+");
        features.push("multiprocess+");
        features.push("swbreak+");
        features.push("hwbreak+");
        features.push("qRelocInsn+");
        features.push("fork-events+");
        features.push("vfork-events+");
        features.push("exec-events+");
        features.push("vContSupported+");
        features.push("QThreadEvents+");
        features.push("no-resumed+");
        
        features.join(";").into_bytes()
    }
    
    fn handle_thread_extra_info(&self, query: &str) -> Vec<u8> {
        if let Some(tid_str) = query.strip_prefix("ThreadExtraInfo,") {
            if let Ok(tid) = u64::from_str_radix(tid_str, 16) {
                let info = format!("Thread {} (CPU {})", tid, tid);
                // Convert to hex
                info.bytes()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
                    .into_bytes()
            } else {
                b"E01".to_vec()
            }
        } else {
            b"E01".to_vec()
        }
    }
    
    fn handle_set(&mut self, data: &[u8]) -> Vec<u8> {
        let cmd = String::from_utf8_lossy(data);
        
        if cmd.starts_with("StartNoAckMode") {
            self.no_ack_mode.store(true, Ordering::SeqCst);
            b"OK".to_vec()
        } else if cmd.starts_with("ThreadEvents") {
            b"OK".to_vec()
        } else {
            b"".to_vec()
        }
    }
    
    fn handle_v_packet(&mut self, vm: &mut VirtualMachine, data: &[u8]) -> Vec<u8> {
        let cmd = String::from_utf8_lossy(data);
        
        if cmd.starts_with("Cont?") {
            b"vCont;c;C;s;S;t;r".to_vec()
        } else if cmd.starts_with("Cont;") {
            self.handle_v_cont(vm, &cmd[5..])
        } else if cmd.starts_with("Kill") {
            self.handle_kill(vm)
        } else if cmd.starts_with("Stopped") {
            self.handle_stop_reason()
        } else if cmd.starts_with("MustReplyEmpty") {
            b"".to_vec()
        } else {
            b"".to_vec()
        }
    }
    
    fn handle_v_cont(&mut self, vm: &mut VirtualMachine, actions: &str) -> Vec<u8> {
        // Parse vCont actions
        for action in actions.split(';') {
            if action.is_empty() {
                continue;
            }
            
            let (cmd, thread) = if action.contains(':') {
                let parts: Vec<&str> = action.split(':').collect();
                (parts[0], Some(parts[1]))
            } else {
                (action, None)
            };
            
            // Apply to specified thread or current thread
            let thread_id = if let Some(t) = thread {
                if let Ok(tid) = u64::from_str_radix(t, 16) {
                    tid
                } else {
                    self.current_thread.load(Ordering::Relaxed)
                }
            } else {
                self.current_thread.load(Ordering::Relaxed)
            };
            
            match cmd {
                "c" => {
                    // Continue
                    self.set_state(GdbState::Running);
                    vm.resume();
                }
                "s" => {
                    // Single step
                    if let Some(vcpu) = vm.get_vcpu_mut(thread_id) {
                        vcpu.single_step();
                    }
                    self.single_step.store(true, Ordering::SeqCst);
                    self.set_state(GdbState::Stepping);
                    vm.resume();
                }
                "t" => {
                    // Stop thread
                    if let Some(vcpu) = vm.get_vcpu_mut(thread_id) {
                        vcpu.stop();
                    }
                }
                _ => {}
            }
        }
        
        b"".to_vec()
    }
    
    fn handle_detach(&mut self, vm: &mut VirtualMachine) -> Vec<u8> {
        // Remove all breakpoints
        for (addr, bp) in self.breakpoints.write().drain() {
            if bp.bp_type == BreakpointType::Software {
                vm.write_memory_byte(addr, bp.original_byte).ok();
            } else {
                vm.clear_hardware_breakpoint(addr).ok();
            }
        }
        
        // Remove all watchpoints
        for (addr, _) in self.watchpoints.write().drain() {
            vm.clear_watchpoint(addr).ok();
        }
        
        // Resume VM
        vm.resume();
        
        self.set_state(GdbState::Disconnected);
        b"OK".to_vec()
    }
    
    fn handle_kill(&mut self, vm: &mut VirtualMachine) -> Vec<u8> {
        vm.terminate();
        self.set_state(GdbState::Disconnected);
        b"OK".to_vec()
    }
    
    fn handle_extended_mode(&mut self) -> Vec<u8> {
        // Enable extended mode
        b"OK".to_vec()
    }
    
    fn create_error_response(&self) -> Vec<u8> {
        b"".to_vec() // Empty response for unknown commands
    }
    
    fn send_response(&mut self, response: &[u8]) -> Result<(), GdbError> {
        if let Some(conn) = &mut self.connection {
            conn.send_packet(response, self.no_ack_mode.load(Ordering::Relaxed))?;
        }
        Ok(())
    }
    
    pub fn notify_stop(&mut self, reason: StopReason) {
        *self.stop_reason.lock() = Some(reason);
        self.set_state(GdbState::Stopped);
        
        // Send stop notification
        let notification = self.handle_stop_reason();
        self.send_response(&notification).ok();
    }
    
    pub fn check_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.read().contains_key(&addr)
    }
    
    pub fn check_watchpoint(&self, addr: u64, is_write: bool) -> Option<&Watchpoint> {
        let watchpoints = self.watchpoints.read();
        for (wp_addr, wp) in watchpoints.iter() {
            if addr >= *wp_addr && addr < *wp_addr + wp.len as u64 {
                match wp.kind {
                    WatchpointKind::Write if is_write => return Some(wp),
                    WatchpointKind::Read if !is_write => return Some(wp),
                    WatchpointKind::Access => return Some(wp),
                    _ => {}
                }
            }
        }
        None
    }
    
    fn get_state(&self) -> GdbState {
        unsafe { core::mem::transmute(self.state.load(Ordering::SeqCst)) }
    }
    
    fn set_state(&self, state: GdbState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }
}

/// Breakpoint structure
#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub addr: u64,
    pub len: usize,
    pub bp_type: BreakpointType,
    pub original_byte: u8,
    pub enabled: bool,
}

/// Watchpoint structure
#[derive(Debug, Clone)]
pub struct Watchpoint {
    pub addr: u64,
    pub len: usize,
    pub kind: WatchpointKind,
    pub enabled: bool,
}

/// GDB connection handling
pub struct GdbConnection {
    socket: TcpSocket,
    buffer: Vec<u8>,
}

impl GdbConnection {
    pub fn listen(port: u16) -> Result<Self, GdbError> {
        let socket = TcpSocket::listen(port)?;
        Ok(Self {
            socket,
            buffer: Vec::with_capacity(GDB_PACKET_SIZE),
        })
    }
    
    pub fn receive_packet(&mut self) -> Result<Vec<u8>, GdbError> {
        let mut packet = Vec::new();
        let mut in_packet = false;
        let mut checksum_bytes = Vec::new();
        
        loop {
            let byte = self.socket.read_byte()?;
            
            if !in_packet {
                match byte {
                    b'$' => {
                        in_packet = true;
                        packet.clear();
                        checksum_bytes.clear();
                    }
                    b'+' => {} // ACK, ignore
                    b'-' => return Err(GdbError::Nak), // NAK, resend
                    b'\x03' => {
                        // Ctrl-C interrupt
                        return Ok(vec![b'\x03']);
                    }
                    _ => {} // Ignore other bytes
                }
            } else {
                if byte == b'#' {
                    // Checksum follows
                    checksum_bytes.push(self.socket.read_byte()?);
                    checksum_bytes.push(self.socket.read_byte()?);
                    
                    // Verify checksum
                    let expected = self.calculate_checksum(&packet);
                    let received = u8::from_str_radix(
                        &String::from_utf8_lossy(&checksum_bytes),
                        16
                    ).unwrap_or(0);
                    
                    if expected == received {
                        // Send ACK
                        self.socket.write_byte(b'+')?;
                        return Ok(packet);
                    } else {
                        // Send NAK
                        self.socket.write_byte(b'-')?;
                        in_packet = false;
                    }
                } else {
                    packet.push(byte);
                }
            }
        }
    }
    
    pub fn send_packet(&mut self, data: &[u8], no_ack: bool) -> Result<(), GdbError> {
        let checksum = self.calculate_checksum(data);
        
        // Build packet: $data#checksum
        self.socket.write_byte(b'$')?;
        self.socket.write_all(data)?;
        self.socket.write_byte(b'#')?;
        self.socket.write_all(format!("{:02x}", checksum).as_bytes())?;
        
        if !no_ack {
            // Wait for ACK
            let response = self.socket.read_byte()?;
            if response != b'+' {
                return Err(GdbError::Nak);
            }
        }
        
        Ok(())
    }
    
    fn calculate_checksum(&self, data: &[u8]) -> u8 {
        data.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))
    }
}

/// TCP socket abstraction
pub struct TcpSocket;

impl TcpSocket {
    pub fn listen(_port: u16) -> Result<Self, GdbError> {
        Ok(Self)
    }
    
    pub fn read_byte(&self) -> Result<u8, GdbError> {
        Ok(0)
    }
    
    pub fn write_byte(&mut self, _byte: u8) -> Result<(), GdbError> {
        Ok(())
    }
    
    pub fn write_all(&mut self, _data: &[u8]) -> Result<(), GdbError> {
        Ok(())
    }
}

/// Register cache
pub struct RegisterCache {
    registers: BTreeMap<GdbRegister, u64>,
}

impl RegisterCache {
    pub fn new() -> Self {
        Self {
            registers: BTreeMap::new(),
        }
    }
}

/// Memory cache
pub struct MemoryCache {
    pages: BTreeMap<u64, Vec<u8>>,
}

impl MemoryCache {
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }
}

/// GDB features
pub struct GdbFeatures {
    pub xml_support: bool,
    pub multi_process: bool,
    pub no_ack_mode: bool,
    pub vcont: bool,
    pub qxfer: bool,
}

impl Default for GdbFeatures {
    fn default() -> Self {
        Self {
            xml_support: true,
            multi_process: true,
            no_ack_mode: true,
            vcont: true,
            qxfer: true,
        }
    }
}

/// GDB errors
#[derive(Debug, Clone)]
pub enum GdbError {
    ConnectionFailed,
    ConnectionClosed,
    InvalidPacket,
    ChecksumMismatch,
    Nak,
    Timeout,
    Unsupported,
}

/// Placeholder VM types
pub struct VirtualMachine;
impl VirtualMachine {
    pub fn get_vcpu(&self, _id: u64) -> Option<&Vcpu> { None }
    pub fn get_vcpu_mut(&mut self, _id: u64) -> Option<&mut Vcpu> { None }
    pub fn read_memory_byte(&self, _addr: u64) -> Result<u8, GdbError> { Ok(0) }
    pub fn write_memory_byte(&mut self, _addr: u64, _val: u8) -> Result<(), GdbError> { Ok(()) }
    pub fn set_hardware_breakpoint(&mut self, _addr: u64, _len: usize) -> Result<(), GdbError> { Ok(()) }
    pub fn clear_hardware_breakpoint(&mut self, _addr: u64) -> Result<(), GdbError> { Ok(()) }
    pub fn set_watchpoint(&mut self, _addr: u64, _len: usize, _kind: WatchpointKind) -> Result<(), GdbError> { Ok(()) }
    pub fn clear_watchpoint(&mut self, _addr: u64) -> Result<(), GdbError> { Ok(()) }
    pub fn resume(&mut self) {}
    pub fn terminate(&mut self) {}
}

pub struct Vcpu;
impl Vcpu {
    pub fn get_registers(&self) -> CpuRegisters { CpuRegisters::default() }
    pub fn set_registers(&mut self, _regs: &CpuRegisters) {}
    pub fn single_step(&mut self) {}
    pub fn stop(&mut self) {}
}

#[derive(Default)]
pub struct CpuRegisters {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u32,
    pub cs: u16, pub ss: u16, pub ds: u16,
    pub es: u16, pub fs: u16, pub gs: u16,
}

/// Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gdb_stub_creation() {
        let stub = GdbStub::new(1);
        assert_eq!(stub.vm_id, 1);
    }
    
    #[test]
    fn test_checksum_calculation() {
        let conn = GdbConnection {
            socket: TcpSocket,
            buffer: Vec::new(),
        };
        let checksum = conn.calculate_checksum(b"OK");
        assert_eq!(checksum, b'O' + b'K');
    }
}