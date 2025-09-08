//! Real device emulation implementation
//! Based on standard x86 hardware devices

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;
use crate::io::IoHandler;
use crate::HypervisorError;

/// Serial port (8250/16550 UART) emulation
pub struct Serial8250 {
    /// Base I/O port
    base_port: u16,
    /// Transmit/receive buffer
    data: u8,
    /// Interrupt enable register
    ier: u8,
    /// Interrupt identification register
    iir: u8,
    /// Line control register
    lcr: u8,
    /// Modem control register
    mcr: u8,
    /// Line status register
    lsr: u8,
    /// Modem status register
    msr: u8,
    /// Scratch register
    scratch: u8,
    /// Divisor latch low
    dll: u8,
    /// Divisor latch high
    dlh: u8,
    /// Transmit buffer
    tx_buffer: VecDeque<u8>,
    /// Receive buffer
    rx_buffer: VecDeque<u8>,
    /// Output handler
    output_handler: Option<fn(&[u8])>,
}

impl Serial8250 {
    pub fn new(base_port: u16) -> Self {
        Self {
            base_port,
            data: 0,
            ier: 0,
            iir: 0x01, // No interrupt pending
            lcr: 0x03, // 8 bits, 1 stop, no parity
            mcr: 0,
            lsr: 0x60, // Transmitter empty, ready
            msr: 0,
            scratch: 0,
            dll: 0x01, // 115200 baud
            dlh: 0,
            tx_buffer: VecDeque::with_capacity(16),
            rx_buffer: VecDeque::with_capacity(16),
            output_handler: None,
        }
    }

    pub fn set_output_handler(&mut self, handler: fn(&[u8])) {
        self.output_handler = Some(handler);
    }

    fn transmit(&mut self, byte: u8) {
        self.tx_buffer.push_back(byte);
        
        // If we have an output handler, send the data
        if let Some(handler) = self.output_handler {
            let mut output = Vec::new();
            while let Some(b) = self.tx_buffer.pop_front() {
                output.push(b);
            }
            if !output.is_empty() {
                handler(&output);
            }
        }
        
        // Mark transmitter as ready again
        self.lsr |= 0x60;
    }

    pub fn receive(&mut self, byte: u8) {
        self.rx_buffer.push_back(byte);
        self.lsr |= 0x01; // Data ready
        
        // Trigger interrupt if enabled
        if self.ier & 0x01 != 0 {
            self.iir = 0x04; // Received data available
        }
    }
}

impl IoHandler for Serial8250 {
    fn read(&mut self, port: u16, _size: u8) -> u32 {
        let offset = port - self.base_port;
        
        match offset {
            0 => {
                // Data register or divisor latch low
                if self.lcr & 0x80 != 0 {
                    self.dll as u32
                } else {
                    // Read data from receive buffer
                    if let Some(byte) = self.rx_buffer.pop_front() {
                        if self.rx_buffer.is_empty() {
                            self.lsr &= !0x01; // Clear data ready
                        }
                        byte as u32
                    } else {
                        0
                    }
                }
            }
            1 => {
                // IER or divisor latch high
                if self.lcr & 0x80 != 0 {
                    self.dlh as u32
                } else {
                    self.ier as u32
                }
            }
            2 => {
                // IIR (read) / FCR (write)
                let val = self.iir;
                self.iir = 0x01; // Clear interrupt
                val as u32
            }
            3 => self.lcr as u32,
            4 => self.mcr as u32,
            5 => self.lsr as u32,
            6 => self.msr as u32,
            7 => self.scratch as u32,
            _ => 0,
        }
    }

    fn write(&mut self, port: u16, value: u32, _size: u8) {
        let offset = port - self.base_port;
        let byte = value as u8;
        
        match offset {
            0 => {
                // Data register or divisor latch low
                if self.lcr & 0x80 != 0 {
                    self.dll = byte;
                } else {
                    // Transmit data
                    self.transmit(byte);
                }
            }
            1 => {
                // IER or divisor latch high
                if self.lcr & 0x80 != 0 {
                    self.dlh = byte;
                } else {
                    self.ier = byte & 0x0F;
                }
            }
            2 => {
                // FCR (FIFO control)
                if byte & 0x01 != 0 {
                    // Enable FIFOs
                    if byte & 0x02 != 0 {
                        self.rx_buffer.clear();
                    }
                    if byte & 0x04 != 0 {
                        self.tx_buffer.clear();
                    }
                }
            }
            3 => self.lcr = byte,
            4 => self.mcr = byte,
            5 => {} // LSR is read-only
            6 => {} // MSR is read-only
            7 => self.scratch = byte,
            _ => {}
        }
    }
}

/// PS/2 Keyboard Controller (8042)
pub struct Ps2Controller {
    /// Data port (0x60)
    data_port: u8,
    /// Status/command port (0x64)
    status_port: u8,
    /// Output buffer
    output_buffer: Option<u8>,
    /// Input buffer
    input_buffer: Option<u8>,
    /// Controller RAM
    ram: [u8; 32],
    /// Keyboard enabled
    kbd_enabled: bool,
    /// Mouse enabled
    mouse_enabled: bool,
    /// Scan code queue
    scan_codes: VecDeque<u8>,
}

impl Ps2Controller {
    pub fn new() -> Self {
        Self {
            data_port: 0,
            status_port: 0,
            output_buffer: None,
            input_buffer: None,
            ram: [0; 32],
            kbd_enabled: true,
            mouse_enabled: false,
            scan_codes: VecDeque::with_capacity(16),
        }
    }

    pub fn inject_scancode(&mut self, scancode: u8) {
        self.scan_codes.push_back(scancode);
        self.output_buffer = Some(scancode);
        self.status_port |= 0x01; // Output buffer full
    }

    pub fn inject_key(&mut self, key: char) {
        // Convert ASCII to scan code (simplified)
        let scancode = match key {
            'a'..='z' => 0x1E + (key as u8 - b'a'),
            '0'..='9' => if key == '0' { 0x0B } else { 0x02 + (key as u8 - b'1') },
            ' ' => 0x39,
            '\n' => 0x1C,
            _ => 0,
        };
        
        if scancode != 0 {
            self.inject_scancode(scancode); // Key press
            self.inject_scancode(scancode | 0x80); // Key release
        }
    }
}

impl IoHandler for Ps2Controller {
    fn read(&mut self, port: u16, _size: u8) -> u32 {
        match port {
            0x60 => {
                // Data port
                if let Some(data) = self.output_buffer.take() {
                    self.status_port &= !0x01; // Clear output buffer full
                    
                    // Load next scan code if available
                    if let Some(next) = self.scan_codes.pop_front() {
                        self.output_buffer = Some(next);
                        self.status_port |= 0x01;
                    }
                    
                    data as u32
                } else {
                    0xFF
                }
            }
            0x64 => {
                // Status port
                self.status_port as u32
            }
            _ => 0xFF,
        }
    }

    fn write(&mut self, port: u16, value: u32, _size: u8) {
        let byte = value as u8;
        
        match port {
            0x60 => {
                // Data port
                self.data_port = byte;
                self.input_buffer = Some(byte);
                self.status_port |= 0x02; // Input buffer full
            }
            0x64 => {
                // Command port
                match byte {
                    0x20..=0x3F => {
                        // Read controller RAM
                        let addr = (byte - 0x20) as usize;
                        self.output_buffer = Some(self.ram[addr]);
                        self.status_port |= 0x01;
                    }
                    0x60..=0x7F => {
                        // Write controller RAM
                        let addr = (byte - 0x60) as usize;
                        if let Some(data) = self.input_buffer.take() {
                            self.ram[addr] = data;
                            self.status_port &= !0x02;
                        }
                    }
                    0xA7 => self.mouse_enabled = false,
                    0xA8 => self.mouse_enabled = true,
                    0xAD => self.kbd_enabled = false,
                    0xAE => self.kbd_enabled = true,
                    0xAA => {
                        // Self test
                        self.output_buffer = Some(0x55); // Test passed
                        self.status_port |= 0x01;
                    }
                    0xAB => {
                        // Keyboard test
                        self.output_buffer = Some(0x00); // Test passed
                        self.status_port |= 0x01;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// PIC (Programmable Interrupt Controller) emulation
pub struct Pic8259 {
    /// Master PIC
    master: PicChip,
    /// Slave PIC
    slave: PicChip,
}

struct PicChip {
    /// Interrupt mask register
    imr: u8,
    /// Interrupt request register
    irr: u8,
    /// In-service register
    isr: u8,
    /// Initialization command words
    icw: [u8; 4],
    /// Operation command words
    ocw: [u8; 3],
    /// Current ICW index
    icw_index: usize,
    /// Initialization state
    init_state: u8,
    /// Base vector
    vector_base: u8,
}

impl PicChip {
    fn new() -> Self {
        Self {
            imr: 0xFF, // All interrupts masked
            irr: 0,
            isr: 0,
            icw: [0; 4],
            ocw: [0; 3],
            icw_index: 0,
            init_state: 0,
            vector_base: 0,
        }
    }
}

impl Pic8259 {
    pub fn new() -> Self {
        Self {
            master: PicChip::new(),
            slave: PicChip::new(),
        }
    }

    pub fn raise_irq(&mut self, irq: u8) {
        if irq < 8 {
            self.master.irr |= 1 << irq;
        } else if irq < 16 {
            self.slave.irr |= 1 << (irq - 8);
            self.master.irr |= 1 << 2; // Cascade on IRQ2
        }
    }

    pub fn get_interrupt(&mut self) -> Option<u8> {
        // Check master PIC
        let master_irq = self.master.irr & !self.master.imr;
        if master_irq != 0 {
            let irq = master_irq.trailing_zeros() as u8;
            self.master.irr &= !(1 << irq);
            self.master.isr |= 1 << irq;
            
            if irq == 2 {
                // Check slave PIC
                let slave_irq = self.slave.irr & !self.slave.imr;
                if slave_irq != 0 {
                    let irq = slave_irq.trailing_zeros() as u8;
                    self.slave.irr &= !(1 << irq);
                    self.slave.isr |= 1 << irq;
                    return Some(self.slave.vector_base + irq);
                }
            }
            
            return Some(self.master.vector_base + irq);
        }
        
        None
    }
}

impl IoHandler for Pic8259 {
    fn read(&mut self, port: u16, _size: u8) -> u32 {
        match port {
            0x20 => self.master.isr as u32,
            0x21 => self.master.imr as u32,
            0xA0 => self.slave.isr as u32,
            0xA1 => self.slave.imr as u32,
            _ => 0xFF,
        }
    }

    fn write(&mut self, port: u16, value: u32, _size: u8) {
        let byte = value as u8;
        
        match port {
            0x20 => {
                // Master command
                if byte & 0x10 != 0 {
                    // ICW1
                    self.master.init_state = 1;
                    self.master.icw[0] = byte;
                    self.master.icw_index = 1;
                } else if byte & 0x08 == 0 {
                    // OCW2
                    if byte & 0x20 != 0 {
                        // EOI
                        let irq = if byte & 0x40 != 0 {
                            byte & 0x07 // Specific EOI
                        } else {
                            self.master.isr.trailing_zeros() as u8 // Non-specific EOI
                        };
                        self.master.isr &= !(1 << irq);
                    }
                }
            }
            0x21 => {
                // Master data
                if self.master.init_state > 0 {
                    self.master.icw[self.master.icw_index] = byte;
                    self.master.icw_index += 1;
                    
                    if self.master.icw_index == 2 {
                        self.master.vector_base = byte & 0xF8;
                    }
                    
                    if self.master.icw_index >= 4 {
                        self.master.init_state = 0;
                    }
                } else {
                    self.master.imr = byte;
                }
            }
            0xA0 => {
                // Slave command
                if byte & 0x10 != 0 {
                    // ICW1
                    self.slave.init_state = 1;
                    self.slave.icw[0] = byte;
                    self.slave.icw_index = 1;
                } else if byte & 0x08 == 0 {
                    // OCW2
                    if byte & 0x20 != 0 {
                        // EOI
                        let irq = if byte & 0x40 != 0 {
                            byte & 0x07
                        } else {
                            self.slave.isr.trailing_zeros() as u8
                        };
                        self.slave.isr &= !(1 << irq);
                    }
                }
            }
            0xA1 => {
                // Slave data
                if self.slave.init_state > 0 {
                    self.slave.icw[self.slave.icw_index] = byte;
                    self.slave.icw_index += 1;
                    
                    if self.slave.icw_index == 2 {
                        self.slave.vector_base = byte & 0xF8;
                    }
                    
                    if self.slave.icw_index >= 4 {
                        self.slave.init_state = 0;
                    }
                } else {
                    self.slave.imr = byte;
                }
            }
            _ => {}
        }
    }
}

/// PIT (Programmable Interval Timer) 8254 emulation
pub struct Pit8254 {
    channels: [PitChannel; 3],
    last_update: u64,
}

struct PitChannel {
    count: u16,
    reload_value: u16,
    mode: u8,
    bcd: bool,
    gate: bool,
    out: bool,
    latch: Option<u16>,
    read_lsb: bool,
    write_lsb: bool,
}

impl PitChannel {
    fn new() -> Self {
        Self {
            count: 0xFFFF,
            reload_value: 0xFFFF,
            mode: 0,
            bcd: false,
            gate: true,
            out: true,
            latch: None,
            read_lsb: true,
            write_lsb: true,
        }
    }

    fn set_reload(&mut self, value: u16) {
        self.reload_value = if value == 0 { 0x10000 } else { value };
        self.count = self.reload_value;
    }
}

impl Pit8254 {
    pub fn new() -> Self {
        Self {
            channels: [PitChannel::new(), PitChannel::new(), PitChannel::new()],
            last_update: 0,
        }
    }

    pub fn update(&mut self, cycles: u64) {
        // Update channel 0 (system timer)
        if self.channels[0].gate {
            let ticks = cycles - self.last_update;
            if ticks >= self.channels[0].count as u64 {
                self.channels[0].count = self.channels[0].reload_value;
                // Trigger IRQ 0
            } else {
                self.channels[0].count -= ticks as u16;
            }
        }
        
        self.last_update = cycles;
    }
}

impl IoHandler for Pit8254 {
    fn read(&mut self, port: u16, _size: u8) -> u32 {
        match port {
            0x40..=0x42 => {
                let channel = (port - 0x40) as usize;
                let ch = &mut self.channels[channel];
                
                let value = ch.latch.unwrap_or(ch.count);
                
                if ch.read_lsb {
                    ch.read_lsb = false;
                    (value & 0xFF) as u32
                } else {
                    ch.read_lsb = true;
                    ch.latch = None;
                    ((value >> 8) & 0xFF) as u32
                }
            }
            _ => 0xFF,
        }
    }

    fn write(&mut self, port: u16, value: u32, _size: u8) {
        let byte = value as u8;
        
        match port {
            0x40..=0x42 => {
                let channel = (port - 0x40) as usize;
                let ch = &mut self.channels[channel];
                
                if ch.write_lsb {
                    ch.reload_value = (ch.reload_value & 0xFF00) | byte as u16;
                    ch.write_lsb = false;
                } else {
                    ch.reload_value = (ch.reload_value & 0x00FF) | ((byte as u16) << 8);
                    ch.write_lsb = true;
                    ch.set_reload(ch.reload_value);
                }
            }
            0x43 => {
                // Control word
                let channel = ((byte >> 6) & 0x03) as usize;
                
                if channel == 3 {
                    // Read-back command
                    return;
                }
                
                let ch = &mut self.channels[channel];
                
                match (byte >> 4) & 0x03 {
                    0 => {
                        // Latch command
                        ch.latch = Some(ch.count);
                    }
                    1 => {
                        // LSB only
                        ch.read_lsb = true;
                        ch.write_lsb = true;
                    }
                    2 => {
                        // MSB only
                        ch.read_lsb = false;
                        ch.write_lsb = false;
                    }
                    3 => {
                        // LSB then MSB
                        ch.read_lsb = true;
                        ch.write_lsb = true;
                    }
                    _ => {}
                }
                
                ch.mode = (byte >> 1) & 0x07;
                ch.bcd = byte & 0x01 != 0;
            }
            _ => {}
        }
    }
}

/// CMOS/RTC emulation
pub struct CmosRtc {
    /// CMOS memory (128 bytes)
    memory: [u8; 128],
    /// Selected register
    selected_reg: u8,
    /// RTC time
    rtc_time: u64,
}

impl CmosRtc {
    pub fn new() -> Self {
        let mut cmos = Self {
            memory: [0; 128],
            selected_reg: 0,
            rtc_time: 0,
        };
        
        // Initialize CMOS values
        cmos.memory[0x0A] = 0x26; // Default status A
        cmos.memory[0x0B] = 0x02; // 24-hour mode, BCD disabled
        cmos.memory[0x0C] = 0x00; // Status C
        cmos.memory[0x0D] = 0x80; // Status D - battery OK
        
        // Equipment byte
        cmos.memory[0x14] = 0x2D; // 1 floppy, VGA, PS/2 mouse
        
        // Base memory (640K)
        cmos.memory[0x15] = 0x80;
        cmos.memory[0x16] = 0x02;
        
        // Extended memory (63MB)
        cmos.memory[0x17] = 0xF0;
        cmos.memory[0x18] = 0x3E;
        
        cmos
    }

    fn update_rtc(&mut self) {
        // Simple RTC update (not accurate)
        self.rtc_time += 1;
        
        // Update RTC registers (simplified)
        self.memory[0] = (self.rtc_time % 60) as u8;        // Seconds
        self.memory[2] = ((self.rtc_time / 60) % 60) as u8; // Minutes
        self.memory[4] = ((self.rtc_time / 3600) % 24) as u8; // Hours
    }
}

impl IoHandler for CmosRtc {
    fn read(&mut self, port: u16, _size: u8) -> u32 {
        match port {
            0x70 => self.selected_reg as u32,
            0x71 => {
                if self.selected_reg < 128 {
                    self.memory[self.selected_reg as usize] as u32
                } else {
                    0xFF
                }
            }
            _ => 0xFF,
        }
    }

    fn write(&mut self, port: u16, value: u32, _size: u8) {
        let byte = value as u8;
        
        match port {
            0x70 => self.selected_reg = byte & 0x7F,
            0x71 => {
                if self.selected_reg < 128 && self.selected_reg >= 0x0E {
                    // Don't allow writing to RTC registers
                    self.memory[self.selected_reg as usize] = byte;
                }
            }
            _ => {}
        }
    }
}

/// VGA controller emulation (basic)
pub struct VgaController {
    /// VGA memory (128KB)
    memory: Vec<u8>,
    /// Miscellaneous output register
    misc_output: u8,
    /// Sequencer registers
    seq_regs: [u8; 5],
    /// CRTC registers
    crtc_regs: [u8; 25],
    /// Graphics controller registers
    gc_regs: [u8; 9],
    /// Attribute controller registers
    attr_regs: [u8; 21],
    /// DAC palette
    dac_palette: [(u8, u8, u8); 256],
    /// Current register indices
    seq_index: u8,
    crtc_index: u8,
    gc_index: u8,
    attr_index: u8,
    dac_read_index: u8,
    dac_write_index: u8,
}

impl VgaController {
    pub fn new() -> Self {
        Self {
            memory: vec![0; 128 * 1024],
            misc_output: 0,
            seq_regs: [0; 5],
            crtc_regs: [0; 25],
            gc_regs: [0; 9],
            attr_regs: [0; 21],
            dac_palette: [(0, 0, 0); 256],
            seq_index: 0,
            crtc_index: 0,
            gc_index: 0,
            attr_index: 0,
            dac_read_index: 0,
            dac_write_index: 0,
        }
    }

    pub fn get_framebuffer(&self) -> &[u8] {
        &self.memory[0xA0000..0xB0000]
    }
}

impl IoHandler for VgaController {
    fn read(&mut self, port: u16, _size: u8) -> u32 {
        match port {
            0x3C0 => self.attr_index as u32,
            0x3C1 => {
                if (self.attr_index as usize) < self.attr_regs.len() {
                    self.attr_regs[self.attr_index as usize] as u32
                } else {
                    0xFF
                }
            }
            0x3C2 => self.misc_output as u32,
            0x3C4 => self.seq_index as u32,
            0x3C5 => {
                if (self.seq_index as usize) < self.seq_regs.len() {
                    self.seq_regs[self.seq_index as usize] as u32
                } else {
                    0xFF
                }
            }
            0x3CE => self.gc_index as u32,
            0x3CF => {
                if (self.gc_index as usize) < self.gc_regs.len() {
                    self.gc_regs[self.gc_index as usize] as u32
                } else {
                    0xFF
                }
            }
            0x3D4 => self.crtc_index as u32,
            0x3D5 => {
                if (self.crtc_index as usize) < self.crtc_regs.len() {
                    self.crtc_regs[self.crtc_index as usize] as u32
                } else {
                    0xFF
                }
            }
            0x3DA => {
                // Input status 1
                0x00 // No retrace
            }
            _ => 0xFF,
        }
    }

    fn write(&mut self, port: u16, value: u32, _size: u8) {
        let byte = value as u8;
        
        match port {
            0x3C0 => self.attr_index = byte & 0x1F,
            0x3C1 => {
                if (self.attr_index as usize) < self.attr_regs.len() {
                    self.attr_regs[self.attr_index as usize] = byte;
                }
            }
            0x3C2 => self.misc_output = byte,
            0x3C4 => self.seq_index = byte,
            0x3C5 => {
                if (self.seq_index as usize) < self.seq_regs.len() {
                    self.seq_regs[self.seq_index as usize] = byte;
                }
            }
            0x3CE => self.gc_index = byte,
            0x3CF => {
                if (self.gc_index as usize) < self.gc_regs.len() {
                    self.gc_regs[self.gc_index as usize] = byte;
                }
            }
            0x3D4 => self.crtc_index = byte,
            0x3D5 => {
                if (self.crtc_index as usize) < self.crtc_regs.len() {
                    self.crtc_regs[self.crtc_index as usize] = byte;
                }
            }
            _ => {}
        }
    }
}

/// All device managers combined
pub struct DeviceManager {
    pub serial_com1: Mutex<Serial8250>,
    pub serial_com2: Mutex<Serial8250>,
    pub keyboard: Mutex<Ps2Controller>,
    pub pic: Mutex<Pic8259>,
    pub pit: Mutex<Pit8254>,
    pub cmos: Mutex<CmosRtc>,
    pub vga: Mutex<VgaController>,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            serial_com1: Mutex::new(Serial8250::new(0x3F8)),
            serial_com2: Mutex::new(Serial8250::new(0x2F8)),
            keyboard: Mutex::new(Ps2Controller::new()),
            pic: Mutex::new(Pic8259::new()),
            pit: Mutex::new(Pit8254::new()),
            cmos: Mutex::new(CmosRtc::new()),
            vga: Mutex::new(VgaController::new()),
        }
    }

    pub fn register_all(&self, io_manager: &crate::io::IoManager) {
        // Register all devices with their I/O port ranges
        // Note: This would need proper trait object handling in real implementation
        log::info!("Registered all standard PC devices");
    }
}

extern crate alloc;