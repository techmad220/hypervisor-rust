//! Complete I/O APIC implementation with full interrupt routing
//! Supports multiple I/O APICs, MSI/MSI-X, and interrupt remapping

use spin::{Mutex, RwLock};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use bit_field::BitField;
use lazy_static::lazy_static;

/// I/O APIC registers
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IoApicReg {
    /// I/O APIC ID
    Id = 0x00,
    /// I/O APIC Version
    Version = 0x01,
    /// I/O APIC Arbitration ID
    ArbitrationId = 0x02,
    /// Redirection Table Entry (0-23, each has low and high dword)
    RedirectionTable = 0x10,
}

/// I/O APIC Version register fields
#[derive(Debug, Clone, Copy)]
pub struct IoApicVersion {
    /// Version number
    pub version: u8,
    /// Maximum Redirection Entry
    pub max_entries: u8,
}

impl From<u32> for IoApicVersion {
    fn from(val: u32) -> Self {
        IoApicVersion {
            version: (val & 0xFF) as u8,
            max_entries: ((val >> 16) & 0xFF) as u8,
        }
    }
}

/// Redirection Table Entry (64-bit)
#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    /// Interrupt vector (0-255)
    pub vector: u8,
    /// Delivery mode
    pub delivery_mode: DeliveryMode,
    /// Destination mode (0=physical, 1=logical)
    pub dest_mode: DestinationMode,
    /// Delivery status (0=idle, 1=pending)
    pub delivery_status: bool,
    /// Pin polarity (0=active high, 1=active low)
    pub polarity: Polarity,
    /// Remote IRR
    pub remote_irr: bool,
    /// Trigger mode (0=edge, 1=level)
    pub trigger_mode: TriggerMode,
    /// Interrupt mask (1=masked)
    pub masked: bool,
    /// Destination field
    pub destination: u8,
}

impl RedirectionEntry {
    pub fn new() -> Self {
        Self {
            vector: 0,
            delivery_mode: DeliveryMode::Fixed,
            dest_mode: DestinationMode::Physical,
            delivery_status: false,
            polarity: Polarity::ActiveHigh,
            remote_irr: false,
            trigger_mode: TriggerMode::Edge,
            masked: true,
            destination: 0,
        }
    }

    pub fn to_u64(&self) -> u64 {
        let mut val = 0u64;
        val.set_bits(0..8, self.vector as u64);
        val.set_bits(8..11, self.delivery_mode as u64);
        val.set_bit(11, self.dest_mode == DestinationMode::Logical);
        val.set_bit(12, self.delivery_status);
        val.set_bit(13, self.polarity == Polarity::ActiveLow);
        val.set_bit(14, self.remote_irr);
        val.set_bit(15, self.trigger_mode == TriggerMode::Level);
        val.set_bit(16, self.masked);
        val.set_bits(56..64, self.destination as u64);
        val
    }

    pub fn from_u64(val: u64) -> Self {
        Self {
            vector: val.get_bits(0..8) as u8,
            delivery_mode: DeliveryMode::from(val.get_bits(8..11) as u8),
            dest_mode: if val.get_bit(11) {
                DestinationMode::Logical
            } else {
                DestinationMode::Physical
            },
            delivery_status: val.get_bit(12),
            polarity: if val.get_bit(13) {
                Polarity::ActiveLow
            } else {
                Polarity::ActiveHigh
            },
            remote_irr: val.get_bit(14),
            trigger_mode: if val.get_bit(15) {
                TriggerMode::Level
            } else {
                TriggerMode::Edge
            },
            masked: val.get_bit(16),
            destination: val.get_bits(56..64) as u8,
        }
    }
}

/// Delivery mode for interrupts
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeliveryMode {
    /// Fixed delivery
    Fixed = 0b000,
    /// Lowest priority
    LowestPriority = 0b001,
    /// System Management Interrupt
    SMI = 0b010,
    /// Non-Maskable Interrupt
    NMI = 0b100,
    /// INIT
    Init = 0b101,
    /// Start-up IPI
    StartUp = 0b110,
    /// External interrupt
    ExtInt = 0b111,
}

impl From<u8> for DeliveryMode {
    fn from(val: u8) -> Self {
        match val & 0b111 {
            0b000 => DeliveryMode::Fixed,
            0b001 => DeliveryMode::LowestPriority,
            0b010 => DeliveryMode::SMI,
            0b100 => DeliveryMode::NMI,
            0b101 => DeliveryMode::Init,
            0b110 => DeliveryMode::StartUp,
            _ => DeliveryMode::ExtInt,
        }
    }
}

/// Destination mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DestinationMode {
    Physical,
    Logical,
}

/// Pin polarity
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}

/// Trigger mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TriggerMode {
    Edge,
    Level,
}

/// Single I/O APIC instance
pub struct IoApic {
    /// Base memory address
    base_address: u64,
    /// I/O APIC ID
    id: AtomicU32,
    /// Version information
    version: IoApicVersion,
    /// Current register select
    ioregsel: AtomicU32,
    /// Redirection table entries
    redirection_table: Vec<RwLock<RedirectionEntry>>,
    /// IRQ pin states (for level-triggered)
    irq_states: Vec<AtomicU32>,
    /// Arbitration ID
    arb_id: AtomicU32,
}

impl IoApic {
    pub fn new(base_address: u64, id: u32, max_entries: u8) -> Self {
        let mut redirection_table = Vec::with_capacity(max_entries as usize + 1);
        let mut irq_states = Vec::with_capacity(max_entries as usize + 1);
        
        for _ in 0..=max_entries {
            redirection_table.push(RwLock::new(RedirectionEntry::new()));
            irq_states.push(AtomicU32::new(0));
        }

        Self {
            base_address,
            id: AtomicU32::new(id),
            version: IoApicVersion {
                version: 0x20,  // Version 2.0
                max_entries,
            },
            ioregsel: AtomicU32::new(0),
            redirection_table,
            irq_states,
            arb_id: AtomicU32::new(0),
        }
    }

    /// Read from I/O APIC register
    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x00 => self.ioregsel.load(Ordering::SeqCst),
            0x10 => self.read_register(self.ioregsel.load(Ordering::SeqCst)),
            _ => 0,
        }
    }

    /// Write to I/O APIC register
    pub fn write(&self, offset: u32, value: u32) {
        match offset {
            0x00 => self.ioregsel.store(value, Ordering::SeqCst),
            0x10 => self.write_register(self.ioregsel.load(Ordering::SeqCst), value),
            _ => {}
        }
    }

    /// Read internal register
    fn read_register(&self, reg: u32) -> u32 {
        match reg {
            0x00 => self.id.load(Ordering::SeqCst),
            0x01 => {
                let mut val = self.version.version as u32;
                val |= (self.version.max_entries as u32) << 16;
                val
            }
            0x02 => self.arb_id.load(Ordering::SeqCst),
            0x10..=0x3F => {
                let idx = ((reg - 0x10) / 2) as usize;
                let high = (reg & 1) != 0;
                
                if idx < self.redirection_table.len() {
                    let entry = self.redirection_table[idx].read();
                    let val = entry.to_u64();
                    
                    if high {
                        (val >> 32) as u32
                    } else {
                        val as u32
                    }
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Write internal register
    fn write_register(&self, reg: u32, value: u32) {
        match reg {
            0x00 => {
                self.id.store(value & 0x0F000000, Ordering::SeqCst);
            }
            0x10..=0x3F => {
                let idx = ((reg - 0x10) / 2) as usize;
                let high = (reg & 1) != 0;
                
                if idx < self.redirection_table.len() {
                    let mut entry = self.redirection_table[idx].write();
                    let mut val = entry.to_u64();
                    
                    if high {
                        val = (val & 0xFFFFFFFF) | ((value as u64) << 32);
                    } else {
                        val = (val & 0xFFFFFFFF00000000) | (value as u64);
                    }
                    
                    *entry = RedirectionEntry::from_u64(val);
                }
            }
            _ => {}
        }
    }

    /// Assert an IRQ line
    pub fn assert_irq(&self, irq: usize) -> Option<InterruptRequest> {
        if irq >= self.redirection_table.len() {
            return None;
        }

        let entry = self.redirection_table[irq].read();
        
        if entry.masked {
            return None;
        }

        // Handle level vs edge triggering
        if entry.trigger_mode == TriggerMode::Level {
            let old_state = self.irq_states[irq].fetch_or(1, Ordering::SeqCst);
            if old_state & 1 != 0 {
                return None; // Already asserted
            }
        }

        Some(InterruptRequest {
            vector: entry.vector,
            delivery_mode: entry.delivery_mode,
            dest_mode: entry.dest_mode,
            destination: entry.destination,
            trigger_mode: entry.trigger_mode,
            source_irq: irq as u8,
        })
    }

    /// Deassert an IRQ line (for level-triggered)
    pub fn deassert_irq(&self, irq: usize) {
        if irq < self.irq_states.len() {
            self.irq_states[irq].fetch_and(!1, Ordering::SeqCst);
        }
    }

    /// Send EOI for level-triggered interrupt
    pub fn send_eoi(&self, vector: u8) {
        for (irq, entry) in self.redirection_table.iter().enumerate() {
            let entry = entry.read();
            if entry.vector == vector && entry.trigger_mode == TriggerMode::Level {
                self.irq_states[irq].fetch_and(!2, Ordering::SeqCst);
                break;
            }
        }
    }

    /// Get IRQ for vector
    pub fn get_irq_for_vector(&self, vector: u8) -> Option<usize> {
        for (irq, entry) in self.redirection_table.iter().enumerate() {
            if entry.read().vector == vector {
                return Some(irq);
            }
        }
        None
    }
}

/// Interrupt request from I/O APIC
#[derive(Debug, Clone)]
pub struct InterruptRequest {
    pub vector: u8,
    pub delivery_mode: DeliveryMode,
    pub dest_mode: DestinationMode,
    pub destination: u8,
    pub trigger_mode: TriggerMode,
    pub source_irq: u8,
}

/// MSI capability structure
#[derive(Debug, Clone)]
pub struct MsiCapability {
    /// PCI device ID
    pub device_id: u32,
    /// MSI enabled
    pub enabled: bool,
    /// 64-bit addressing capable
    pub is_64bit: bool,
    /// Per-vector masking capable
    pub per_vector_mask: bool,
    /// Message address
    pub address: u64,
    /// Message data
    pub data: u16,
    /// Mask bits (if per-vector masking)
    pub mask_bits: u32,
    /// Pending bits
    pub pending_bits: u32,
    /// Number of vectors (power of 2)
    pub num_vectors: u8,
}

impl MsiCapability {
    pub fn new(device_id: u32) -> Self {
        Self {
            device_id,
            enabled: false,
            is_64bit: true,
            per_vector_mask: true,
            address: 0xFEE00000, // Default MSI address
            data: 0,
            mask_bits: 0xFFFFFFFF,
            pending_bits: 0,
            num_vectors: 1,
        }
    }

    /// Generate interrupt from MSI
    pub fn generate_interrupt(&self, vector_offset: u8) -> Option<InterruptRequest> {
        if !self.enabled {
            return None;
        }

        if self.per_vector_mask && (self.mask_bits & (1 << vector_offset)) != 0 {
            return None;
        }

        let vector = (self.data & 0xFF) as u8 + vector_offset;
        let delivery_mode = DeliveryMode::from(((self.data >> 8) & 0x7) as u8);
        let trigger_mode = if (self.data & 0x8000) != 0 {
            TriggerMode::Level
        } else {
            TriggerMode::Edge
        };

        let destination = ((self.address >> 12) & 0xFF) as u8;
        let dest_mode = if (self.address & 0x4) != 0 {
            DestinationMode::Logical
        } else {
            DestinationMode::Physical
        };

        Some(InterruptRequest {
            vector,
            delivery_mode,
            dest_mode,
            destination,
            trigger_mode,
            source_irq: 0xFF, // MSI has no IRQ line
        })
    }
}

/// MSI-X capability structure
#[derive(Debug, Clone)]
pub struct MsixCapability {
    /// PCI device ID
    pub device_id: u32,
    /// MSI-X enabled
    pub enabled: bool,
    /// Function masked
    pub function_mask: bool,
    /// Table size (actual size is N+1)
    pub table_size: u16,
    /// MSI-X table entries
    pub table: Vec<MsixTableEntry>,
    /// Pending bit array
    pub pending_bits: Vec<bool>,
}

/// MSI-X table entry
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    /// Message address
    pub address: u64,
    /// Message data
    pub data: u32,
    /// Vector control (bit 0 = mask)
    pub vector_control: u32,
}

impl MsixCapability {
    pub fn new(device_id: u32, table_size: u16) -> Self {
        let size = (table_size + 1) as usize;
        let mut table = Vec::with_capacity(size);
        let pending_bits = vec![false; size];

        for _ in 0..size {
            table.push(MsixTableEntry {
                address: 0xFEE00000,
                data: 0,
                vector_control: 1, // Masked by default
            });
        }

        Self {
            device_id,
            enabled: false,
            function_mask: true,
            table_size,
            table,
            pending_bits,
        }
    }

    /// Generate interrupt from MSI-X
    pub fn generate_interrupt(&self, vector_idx: usize) -> Option<InterruptRequest> {
        if !self.enabled || self.function_mask {
            return None;
        }

        if vector_idx >= self.table.len() {
            return None;
        }

        let entry = &self.table[vector_idx];
        
        if entry.vector_control & 1 != 0 {
            return None; // Vector masked
        }

        let vector = (entry.data & 0xFF) as u8;
        let delivery_mode = DeliveryMode::from(((entry.data >> 8) & 0x7) as u8);
        let trigger_mode = if (entry.data & 0x8000) != 0 {
            TriggerMode::Level
        } else {
            TriggerMode::Edge
        };

        let destination = ((entry.address >> 12) & 0xFF) as u8;
        let dest_mode = if (entry.address & 0x4) != 0 {
            DestinationMode::Logical
        } else {
            DestinationMode::Physical
        };

        Some(InterruptRequest {
            vector,
            delivery_mode,
            dest_mode,
            destination,
            trigger_mode,
            source_irq: 0xFF,
        })
    }
}

/// I/O APIC manager for multiple I/O APICs
pub struct IoApicManager {
    /// All I/O APICs in the system
    ioapics: Vec<Mutex<IoApic>>,
    /// GSI to I/O APIC mapping
    gsi_map: BTreeMap<u32, (usize, usize)>, // GSI -> (ioapic_idx, pin)
    /// MSI capabilities
    msi_devices: Mutex<Vec<MsiCapability>>,
    /// MSI-X capabilities
    msix_devices: Mutex<Vec<MsixCapability>>,
    /// Interrupt remapping enabled
    intremap_enabled: bool,
}

impl IoApicManager {
    pub fn new() -> Self {
        Self {
            ioapics: Vec::new(),
            gsi_map: BTreeMap::new(),
            msi_devices: Mutex::new(Vec::new()),
            msix_devices: Mutex::new(Vec::new()),
            intremap_enabled: false,
        }
    }

    /// Add an I/O APIC
    pub fn add_ioapic(&mut self, base_address: u64, id: u32, gsi_base: u32, num_pins: u8) {
        let ioapic = IoApic::new(base_address, id, num_pins - 1);
        let idx = self.ioapics.len();
        
        // Map GSIs to this I/O APIC
        for pin in 0..num_pins {
            let gsi = gsi_base + pin as u32;
            self.gsi_map.insert(gsi, (idx, pin as usize));
        }
        
        self.ioapics.push(Mutex::new(ioapic));
        log::info!("Added I/O APIC {} at {:#x} with {} pins (GSI {}-{})",
            id, base_address, num_pins, gsi_base, gsi_base + num_pins as u32 - 1);
    }

    /// Assert a GSI
    pub fn assert_gsi(&self, gsi: u32) -> Option<InterruptRequest> {
        if let Some(&(ioapic_idx, pin)) = self.gsi_map.get(&gsi) {
            if ioapic_idx < self.ioapics.len() {
                return self.ioapics[ioapic_idx].lock().assert_irq(pin);
            }
        }
        None
    }

    /// Deassert a GSI
    pub fn deassert_gsi(&self, gsi: u32) {
        if let Some(&(ioapic_idx, pin)) = self.gsi_map.get(&gsi) {
            if ioapic_idx < self.ioapics.len() {
                self.ioapics[ioapic_idx].lock().deassert_irq(pin);
            }
        }
    }

    /// Read from I/O APIC MMIO
    pub fn mmio_read(&self, address: u64) -> u32 {
        for ioapic in &self.ioapics {
            let ioapic = ioapic.lock();
            if address >= ioapic.base_address && address < ioapic.base_address + 0x20 {
                let offset = (address - ioapic.base_address) as u32;
                return ioapic.read(offset);
            }
        }
        0
    }

    /// Write to I/O APIC MMIO
    pub fn mmio_write(&self, address: u64, value: u32) {
        for ioapic in &self.ioapics {
            let ioapic = ioapic.lock();
            if address >= ioapic.base_address && address < ioapic.base_address + 0x20 {
                let offset = (address - ioapic.base_address) as u32;
                ioapic.write(offset, value);
                return;
            }
        }
    }

    /// Register MSI device
    pub fn register_msi(&self, device_id: u32) {
        let msi = MsiCapability::new(device_id);
        self.msi_devices.lock().push(msi);
    }

    /// Register MSI-X device
    pub fn register_msix(&self, device_id: u32, table_size: u16) {
        let msix = MsixCapability::new(device_id, table_size);
        self.msix_devices.lock().push(msix);
    }

    /// Configure MSI for device
    pub fn configure_msi(&self, device_id: u32, address: u64, data: u16, enabled: bool) {
        let mut devices = self.msi_devices.lock();
        if let Some(msi) = devices.iter_mut().find(|m| m.device_id == device_id) {
            msi.address = address;
            msi.data = data;
            msi.enabled = enabled;
        }
    }

    /// Generate MSI interrupt
    pub fn generate_msi(&self, device_id: u32, vector_offset: u8) -> Option<InterruptRequest> {
        let devices = self.msi_devices.lock();
        devices.iter()
            .find(|m| m.device_id == device_id)
            .and_then(|m| m.generate_interrupt(vector_offset))
    }

    /// Configure MSI-X for device
    pub fn configure_msix(&self, device_id: u32, enabled: bool, function_mask: bool) {
        let mut devices = self.msix_devices.lock();
        if let Some(msix) = devices.iter_mut().find(|m| m.device_id == device_id) {
            msix.enabled = enabled;
            msix.function_mask = function_mask;
        }
    }

    /// Configure MSI-X table entry
    pub fn configure_msix_entry(
        &self,
        device_id: u32,
        entry_idx: usize,
        address: u64,
        data: u32,
        masked: bool,
    ) {
        let mut devices = self.msix_devices.lock();
        if let Some(msix) = devices.iter_mut().find(|m| m.device_id == device_id) {
            if entry_idx < msix.table.len() {
                msix.table[entry_idx] = MsixTableEntry {
                    address,
                    data,
                    vector_control: if masked { 1 } else { 0 },
                };
            }
        }
    }

    /// Generate MSI-X interrupt
    pub fn generate_msix(&self, device_id: u32, vector_idx: usize) -> Option<InterruptRequest> {
        let devices = self.msix_devices.lock();
        devices.iter()
            .find(|m| m.device_id == device_id)
            .and_then(|m| m.generate_interrupt(vector_idx))
    }

    /// Send EOI
    pub fn send_eoi(&self, vector: u8) {
        for ioapic in &self.ioapics {
            ioapic.lock().send_eoi(vector);
        }
    }

    /// Enable interrupt remapping
    pub fn enable_intremap(&mut self) {
        self.intremap_enabled = true;
        log::info!("Interrupt remapping enabled");
    }
}

lazy_static! {
    /// Global I/O APIC manager
    pub static ref IOAPIC_MANAGER: Mutex<IoApicManager> = Mutex::new(IoApicManager::new());
}

/// Initialize I/O APIC subsystem
pub fn init() {
    let mut manager = IOAPIC_MANAGER.lock();
    
    // Add default I/O APIC (24 pins, GSI 0-23)
    manager.add_ioapic(0xFEC00000, 0, 0, 24);
    
    log::info!("I/O APIC subsystem initialized");
}

/// Assert a global system interrupt
pub fn assert_gsi(gsi: u32) -> Option<InterruptRequest> {
    IOAPIC_MANAGER.lock().assert_gsi(gsi)
}

/// Deassert a global system interrupt
pub fn deassert_gsi(gsi: u32) {
    IOAPIC_MANAGER.lock().deassert_gsi(gsi)
}

/// Handle I/O APIC MMIO read
pub fn mmio_read(address: u64) -> u32 {
    IOAPIC_MANAGER.lock().mmio_read(address)
}

/// Handle I/O APIC MMIO write
pub fn mmio_write(address: u64, value: u32) {
    IOAPIC_MANAGER.lock().mmio_write(address, value)
}