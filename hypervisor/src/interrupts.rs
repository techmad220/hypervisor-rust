//! Complete interrupt handling infrastructure for the hypervisor
//! Implements all ISRs (Interrupt Service Routines) and exception handlers

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::instructions::port::Port;
use x86_64::registers::control::Cr2;
use x86_64::instructions::interrupts;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::PrivilegeLevel;
use spin::Mutex;
use lazy_static::lazy_static;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;

/// Size of the interrupt stack
pub const STACK_SIZE: usize = 16384; // 16 KB

/// Double fault stack index in TSS
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// NMI stack index in TSS
pub const NMI_IST_INDEX: u16 = 1;

/// Machine check stack index in TSS
pub const MCE_IST_INDEX: u16 = 2;

/// Debug stack index in TSS
pub const DEBUG_IST_INDEX: u16 = 3;

/// Page fault stack index in TSS
pub const PAGE_FAULT_IST_INDEX: u16 = 4;
pub struct InterruptVector {
    pub vector: u8,
    pub int_type: InterruptType,
    pub error_code: Option<u32>,
    pub priority: u8,
    pub has_error_code: bool,
}

impl InterruptVector {
    pub fn new(vector: u8, int_type: InterruptType) -> Self {
        Self {
            vector,
            int_type,
            error_code: None,
            priority: Self::calculate_priority(vector, int_type),
            has_error_code: Self::has_error_code(vector),
        }
    }

    fn calculate_priority(vector: u8, int_type: InterruptType) -> u8 {
        match int_type {
            InterruptType::Nmi => 255,
            InterruptType::Exception => 200 + (32 - vector.min(32)),
            InterruptType::External => 100 + (vector / 16),
            InterruptType::Software => 50,
        }
    }

    fn has_error_code(vector: u8) -> bool {
        matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
    }
}

/// Local APIC emulation
pub struct LocalApic {
    /// APIC ID
    pub id: u32,
    /// Task Priority Register
    pub tpr: u32,
    /// End of Interrupt register
    pub eoi: u32,
    /// Spurious Interrupt Vector
    pub sivr: u32,
    /// Error Status Register
    pub esr: u32,
    /// LVT Timer
    pub lvt_timer: u32,
    /// LVT Thermal
    pub lvt_thermal: u32,
    /// LVT Performance Counter
    pub lvt_perf: u32,
    /// LVT LINT0
    pub lvt_lint0: u32,
    /// LVT LINT1
    pub lvt_lint1: u32,
    /// LVT Error
    pub lvt_error: u32,
    /// Initial Count Register for timer
    pub timer_initial: u32,
    /// Current Count Register for timer
    pub timer_current: u32,
    /// Divide Configuration Register
    pub timer_divide: u32,
    /// Interrupt Request Register (256 bits)
    pub irr: [u32; 8],
    /// In-Service Register (256 bits)
    pub isr: [u32; 8],
    /// Trigger Mode Register (256 bits)
    pub tmr: [u32; 8],
}

impl LocalApic {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            tpr: 0,
            eoi: 0,
            sivr: 0x1FF, // APIC enabled, spurious vector 0xFF
            esr: 0,
            lvt_timer: 0x10000, // Masked
            lvt_thermal: 0x10000,
            lvt_perf: 0x10000,
            lvt_lint0: 0x10000,
            lvt_lint1: 0x10000,
            lvt_error: 0x10000,
            timer_initial: 0,
            timer_current: 0,
            timer_divide: 0,
            irr: [0; 8],
            isr: [0; 8],
            tmr: [0; 8],
        }
    }

    /// Set interrupt request
    pub fn set_irr(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[idx] |= 1 << bit;
    }

    /// Clear interrupt request
    pub fn clear_irr(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[idx] &= !(1 << bit);
    }

    /// Set in-service
    pub fn set_isr(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        self.isr[idx] |= 1 << bit;
    }

    /// Clear in-service (EOI)
    pub fn clear_isr(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        self.isr[idx] &= !(1 << bit);
    }

    /// Get highest priority pending interrupt
    pub fn get_highest_irr(&self) -> Option<u8> {
        for idx in (0..8).rev() {
            if self.irr[idx] != 0 {
                let bit = 31 - self.irr[idx].leading_zeros();
                return Some((idx as u8) * 32 + bit as u8);
            }
        }
        None
    }

    /// Get highest in-service interrupt
    pub fn get_highest_isr(&self) -> Option<u8> {
        for idx in (0..8).rev() {
            if self.isr[idx] != 0 {
                let bit = 31 - self.isr[idx].leading_zeros();
                return Some((idx as u8) * 32 + bit as u8);
            }
        }
        None
    }

    /// Check if interrupt can be delivered
    pub fn can_deliver(&self, vector: u8) -> bool {
        let priority = vector >> 4;
        let tpr_priority = (self.tpr >> 4) & 0xF;
        
        if priority <= tpr_priority {
            return false;
        }

        if let Some(highest_isr) = self.get_highest_isr() {
            if vector <= highest_isr {
                return false;
            }
        }

        true
    }

    /// Process timer tick
    pub fn timer_tick(&mut self) -> bool {
        if self.timer_initial == 0 {
            return false;
        }

        if self.timer_current > 0 {
            self.timer_current -= 1;
            
            if self.timer_current == 0 {
                // Timer expired
                if self.lvt_timer & 0x10000 == 0 { // Not masked
                    let vector = (self.lvt_timer & 0xFF) as u8;
                    self.set_irr(vector);
                    
                    // Reload if periodic
                    if self.lvt_timer & 0x20000 != 0 {
                        self.timer_current = self.timer_initial;
                    }
                    
                    return true;
                }
            }
        }
        
        false
    }

    /// Handle EOI write
    pub fn write_eoi(&mut self) {
        if let Some(vector) = self.get_highest_isr() {
            self.clear_isr(vector);
        }
    }
}

/// I/O APIC emulation
pub struct IoApic {
    /// I/O APIC ID
    pub id: u32,
    /// Redirection table (24 entries)
    pub redirection_table: [u64; 24],
    /// Current register select
    pub ioregsel: u32,
}

impl IoApic {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            redirection_table: [0x10000; 24], // All masked initially
            ioregsel: 0,
        }
    }

    /// Read I/O APIC register
    pub fn read_register(&self, reg: u32) -> u32 {
        match reg {
            0x00 => self.id,
            0x01 => 0x00170020, // Version: 24 entries
            0x02 => 0, // Arbitration ID
            0x10..=0x3F => {
                let idx = ((reg - 0x10) / 2) as usize;
                let high = (reg & 1) != 0;
                
                if idx < 24 {
                    if high {
                        (self.redirection_table[idx] >> 32) as u32
                    } else {
                        self.redirection_table[idx] as u32
                    }
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Write I/O APIC register
    pub fn write_register(&mut self, reg: u32, value: u32) {
        match reg {
            0x00 => self.id = value & 0xFF000000,
            0x10..=0x3F => {
                let idx = ((reg - 0x10) / 2) as usize;
                let high = (reg & 1) != 0;
                
                if idx < 24 {
                    if high {
                        self.redirection_table[idx] = 
                            (self.redirection_table[idx] & 0xFFFFFFFF) | 
                            ((value as u64) << 32);
                    } else {
                        self.redirection_table[idx] = 
                            (self.redirection_table[idx] & 0xFFFFFFFF00000000) | 
                            (value as u64);
                    }
                }
            }
            _ => {}
        }
    }

    /// Deliver interrupt from I/O APIC
    pub fn deliver_interrupt(&self, irq: u8) -> Option<InterruptDelivery> {
        if irq >= 24 {
            return None;
        }

        let entry = self.redirection_table[irq as usize];
        
        // Check if masked
        if entry & 0x10000 != 0 {
            return None;
        }

        let vector = (entry & 0xFF) as u8;
        let delivery_mode = ((entry >> 8) & 0x7) as u8;
        let dest_mode = ((entry >> 11) & 0x1) as u8;
        let dest = ((entry >> 56) & 0xFF) as u8;

        Some(InterruptDelivery {
            vector,
            delivery_mode,
            dest_mode,
            destination: dest,
            level: (entry & 0x8000) != 0,
            trigger_mode: (entry & 0x8000) != 0,
        })
    }
}

/// Interrupt delivery information
#[derive(Debug, Clone, Copy)]
pub struct InterruptDelivery {
    pub vector: u8,
    pub delivery_mode: u8,
    pub dest_mode: u8,
    pub destination: u8,
    pub level: bool,
    pub trigger_mode: bool,
}

/// MSI (Message Signaled Interrupts) support
pub struct MsiController {
    /// MSI capability registers for each device
    msi_caps: Vec<MsiCapability>,
}

#[derive(Debug, Clone)]
pub struct MsiCapability {
    pub device_id: u16,
    pub enabled: bool,
    pub address: u64,
    pub data: u32,
    pub mask_bits: u32,
    pub pending_bits: u32,
    pub num_vectors: u8,
}

impl MsiController {
    pub fn new() -> Self {
        Self {
            msi_caps: Vec::new(),
        }
    }

    pub fn register_device(&mut self, device_id: u16, num_vectors: u8) {
        self.msi_caps.push(MsiCapability {
            device_id,
            enabled: false,
            address: 0,
            data: 0,
            mask_bits: 0,
            pending_bits: 0,
            num_vectors,
        });
    }

    pub fn deliver_msi(&self, device_id: u16) -> Option<InterruptDelivery> {
        self.msi_caps.iter()
            .find(|cap| cap.device_id == device_id && cap.enabled)
            .map(|cap| {
                let vector = (cap.data & 0xFF) as u8;
                let delivery_mode = ((cap.data >> 8) & 0x7) as u8;
                let level = (cap.data & 0x4000) != 0;
                let trigger_mode = (cap.data & 0x8000) != 0;
                let dest = ((cap.address >> 12) & 0xFF) as u8;
                let dest_mode = ((cap.address >> 2) & 0x1) as u8;

                InterruptDelivery {
                    vector,
                    delivery_mode,
                    dest_mode,
                    destination: dest,
                    level,
                    trigger_mode,
                }
            })
    }
}

/// Interrupt controller for the hypervisor
pub struct InterruptController {
    /// Local APICs (one per CPU)
    pub local_apics: Vec<Mutex<LocalApic>>,
    /// I/O APIC
    pub io_apic: Mutex<IoApic>,
    /// MSI controller
    pub msi_controller: Mutex<MsiController>,
    /// Pending interrupts queue
    pub pending_interrupts: Mutex<VecDeque<InterruptVector>>,
    /// Interrupt remapping table (for VT-d)
    pub irte_table: Vec<InterruptRemapEntry>,
    /// Posted interrupt descriptor
    pub posted_interrupts: PostedInterrupts,
}

/// Interrupt Remapping Table Entry (Intel VT-d)
#[repr(C)]
pub struct InterruptRemapEntry {
    pub present: bool,
    pub fault_disable: bool,
    pub dest_mode: u8,
    pub redirection_hint: bool,
    pub trigger_mode: bool,
    pub delivery_mode: u8,
    pub avail: u8,
    pub vector: u8,
    pub destination: u32,
    pub sid: u16,
    pub sq: u8,
    pub svt: u8,
}

/// Posted Interrupts support (Intel VT-x)
pub struct PostedInterrupts {
    /// Posted Interrupt Descriptor
    pub pir: [u64; 4], // 256 bits
    /// Outstanding Notification
    pub on: bool,
    /// Suppress Notification
    pub sn: bool,
    /// Notification Vector
    pub nv: u8,
    /// Notification Destination
    pub ndst: u32,
}

impl InterruptController {
    pub fn new(num_cpus: usize) -> Self {
        let mut local_apics = Vec::with_capacity(num_cpus);
        for i in 0..num_cpus {
            local_apics.push(Mutex::new(LocalApic::new(i as u32)));
        }

        Self {
            local_apics,
            io_apic: Mutex::new(IoApic::new(0)),
            msi_controller: Mutex::new(MsiController::new()),
            pending_interrupts: Mutex::new(VecDeque::new()),
            irte_table: Vec::new(),
            posted_interrupts: PostedInterrupts {
                pir: [0; 4],
                on: false,
                sn: false,
                nv: 0,
                ndst: 0,
            },
        }
    }

    /// Queue an interrupt for delivery
    pub fn queue_interrupt(&self, vector: InterruptVector) {
        let mut pending = self.pending_interrupts.lock();
        
        // Insert sorted by priority
        let pos = pending.iter().position(|v| v.priority < vector.priority)
            .unwrap_or(pending.len());
        pending.insert(pos, vector);
    }

    /// Inject interrupt into VCPU (AMD SVM)
    pub fn inject_interrupt_svm(&self, vcpu: &mut VCpu, vmcb: &mut Vmcb) 
        -> Result<(), HypervisorError> 
    {
        let mut pending = self.pending_interrupts.lock();
        
        // Check if we can inject
        if vmcb.control_area.interrupt_shadow != 0 {
            return Ok(()); // In interrupt shadow
        }

        if vmcb.control_area.event_inject & 0x80000000 != 0 {
            return Ok(()); // Event already pending
        }

        // Get next interrupt
        if let Some(interrupt) = pending.pop_front() {
            let mut event = interrupt.vector as u64;
            
            // Set type
            event |= match interrupt.int_type {
                InterruptType::External => 0 << 8,
                InterruptType::Nmi => 2 << 8,
                InterruptType::Exception => 3 << 8,
                InterruptType::Software => 4 << 8,
            };

            // Set error code if needed
            if let Some(error) = interrupt.error_code {
                event |= 0x800; // Error code valid
                vmcb.control_area.event_inject_err = error;
            }

            // Set valid bit
            event |= 0x80000000;

            vmcb.control_area.event_inject = event;
            
            log::trace!("Injected interrupt {} into VCPU", interrupt.vector);
        }

        Ok(())
    }

    /// Inject interrupt into VCPU (Intel VMX)
    pub fn inject_interrupt_vmx(&self, vcpu: &mut VCpu, vmcs: &mut Vmcs) 
        -> Result<(), HypervisorError> 
    {
        use crate::vmx;
        
        let mut pending = self.pending_interrupts.lock();
        
        unsafe {
            // Check interruptibility state
            let interruptibility = vmx::Vmcs::read_field(vmx::VMCS_GUEST_INTERRUPTIBILITY)?;
            if interruptibility & 0x3 != 0 {
                return Ok(()); // Blocked by STI or MOV SS
            }

            // Check if interrupt window open
            let rflags = vmx::Vmcs::read_field(vmx::VMCS_GUEST_RFLAGS)?;
            if rflags & 0x200 == 0 {
                // IF=0, request interrupt window exit
                let cpu_controls = vmx::Vmcs::read_field(vmx::VMCS_CPU_BASED_CONTROLS)?;
                vmx::Vmcs::write_field(
                    vmx::VMCS_CPU_BASED_CONTROLS, 
                    cpu_controls | (1 << 2)
                )?;
                return Ok(());
            }

            // Get next interrupt
            if let Some(interrupt) = pending.pop_front() {
                let mut info = interrupt.vector as u64;
                
                // Set type
                info |= match interrupt.int_type {
                    InterruptType::External => 0 << 8,
                    InterruptType::Nmi => 2 << 8,
                    InterruptType::Exception => 3 << 8,
                    InterruptType::Software => 4 << 8,
                } << 8;

                // Set deliver error code
                if let Some(error) = interrupt.error_code {
                    info |= 1 << 11;
                    vmx::Vmcs::write_field(
                        vmx::VMCS_VM_ENTRY_EXCEPTION_ERROR, 
                        error as u64
                    )?;
                }

                // Set valid
                info |= 1 << 31;

                vmx::Vmcs::write_field(vmx::VMCS_VM_ENTRY_INTERRUPTION_INFO, info)?;
                
                log::trace!("Injected interrupt {} into VCPU", interrupt.vector);
            }
        }

        Ok(())
    }

    /// Handle APIC access
    pub fn handle_apic_access(&self, vcpu_id: usize, address: u64, data: &mut [u8], is_write: bool) 
        -> Result<(), HypervisorError> 
    {
        if vcpu_id >= self.local_apics.len() {
            return Err(HypervisorError::InvalidParameter);
        }

        let offset = address & 0xFFF;
        let mut apic = self.local_apics[vcpu_id].lock();

        if is_write {
            let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            
            match offset {
                0x80 => apic.tpr = value & 0xFF,
                0xB0 => apic.write_eoi(),
                0xF0 => apic.sivr = value,
                0x320 => apic.lvt_timer = value,
                0x330 => apic.lvt_thermal = value,
                0x340 => apic.lvt_perf = value,
                0x350 => apic.lvt_lint0 = value,
                0x360 => apic.lvt_lint1 = value,
                0x370 => apic.lvt_error = value,
                0x380 => apic.timer_initial = value,
                0x3E0 => apic.timer_divide = value,
                _ => {}
            }
        } else {
            let value = match offset {
                0x20 => apic.id,
                0x30 => 0x00050014, // Version
                0x80 => apic.tpr,
                0xF0 => apic.sivr,
                0x320 => apic.lvt_timer,
                0x330 => apic.lvt_thermal,
                0x340 => apic.lvt_perf,
                0x350 => apic.lvt_lint0,
                0x360 => apic.lvt_lint1,
                0x370 => apic.lvt_error,
                0x380 => apic.timer_initial,
                0x390 => apic.timer_current,
                0x3E0 => apic.timer_divide,
                _ => 0,
            };
            
            data[0..4].copy_from_slice(&value.to_le_bytes());
        }

        Ok(())
    }

    /// Handle I/O APIC access
    pub fn handle_ioapic_access(&self, address: u64, data: &mut [u8], is_write: bool) 
        -> Result<(), HypervisorError> 
    {
        let mut io_apic = self.io_apic.lock();
        let offset = address & 0xFF;

        if is_write {
            let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            
            match offset {
                0x00 => io_apic.ioregsel = value,
                0x10 => {
                    io_apic.write_register(io_apic.ioregsel, value);
                }
                _ => {}
            }
        } else {
            let value = match offset {
                0x00 => io_apic.ioregsel,
                0x10 => io_apic.read_register(io_apic.ioregsel),
                _ => 0,
            };
            
            data[0..4].copy_from_slice(&value.to_le_bytes());
        }

        Ok(())
    }

    /// Process timer tick for all CPUs
    pub fn timer_tick(&self) {
        for apic in &self.local_apics {
            let mut apic = apic.lock();
            if apic.timer_tick() {
                // Timer interrupt fired
                if let Some(vector) = apic.get_highest_irr() {
                    self.queue_interrupt(InterruptVector::new(vector, InterruptType::External));
                }
            }
        }
    }

    /// Handle external interrupt line
    pub fn raise_irq(&self, irq: u8) {
        let io_apic = self.io_apic.lock();
        
        if let Some(delivery) = io_apic.deliver_interrupt(irq) {
            // Route to appropriate LAPIC
            let dest = delivery.destination as usize;
            
            if dest < self.local_apics.len() {
                let mut apic = self.local_apics[dest].lock();
                apic.set_irr(delivery.vector);
                
                self.queue_interrupt(InterruptVector::new(
                    delivery.vector,
                    InterruptType::External
                ));
            }
        }
    }

    /// Handle MSI
    pub fn deliver_msi(&self, device_id: u16) {
        let msi = self.msi_controller.lock();
        
        if let Some(delivery) = msi.deliver_msi(device_id) {
            let dest = delivery.destination as usize;
            
            if dest < self.local_apics.len() {
                let mut apic = self.local_apics[dest].lock();
                apic.set_irr(delivery.vector);
                
                self.queue_interrupt(InterruptVector::new(
                    delivery.vector,
                    InterruptType::External
                ));
            }
        }
    }

    /// Setup interrupt remapping (VT-d)
    pub fn setup_interrupt_remapping(&mut self, num_entries: usize) {
        self.irte_table = Vec::with_capacity(num_entries);
        
        for _ in 0..num_entries {
            self.irte_table.push(InterruptRemapEntry {
                present: false,
                fault_disable: false,
                dest_mode: 0,
                redirection_hint: false,
                trigger_mode: false,
                delivery_mode: 0,
                avail: 0,
                vector: 0,
                destination: 0,
                sid: 0,
                sq: 0,
                svt: 0,
            });
        }
        
        log::info!("Interrupt remapping table initialized with {} entries", num_entries);
    }

    /// Remap interrupt through IRTE
    pub fn remap_interrupt(&self, index: u16) -> Option<InterruptVector> {
        if (index as usize) >= self.irte_table.len() {
            return None;
        }

        let irte = &self.irte_table[index as usize];
        
        if !irte.present {
            return None;
        }

        Some(InterruptVector::new(
            irte.vector,
            match irte.delivery_mode {
                0 => InterruptType::External,
                2 => InterruptType::Nmi,
                _ => InterruptType::Software,
            }
        ))
    }

    /// Post interrupt to descriptor (for posted interrupts)
    pub fn post_interrupt(&mut self, vector: u8) {
        let idx = (vector / 64) as usize;
        let bit = vector % 64;
        
        self.posted_interrupts.pir[idx] |= 1u64 << bit;
        self.posted_interrupts.on = true;
        
        // Send notification if not suppressed
        if !self.posted_interrupts.sn {
            // Would send IPI to notification vector here
            log::trace!("Posted interrupt {} (notification vector {})", 
                vector, self.posted_interrupts.nv);
        }
    }

    /// Process posted interrupts
    pub fn process_posted_interrupts(&mut self, apic_id: usize) {
        if !self.posted_interrupts.on {
            return;
        }

        if apic_id >= self.local_apics.len() {
            return;
        }

        let mut apic = self.local_apics[apic_id].lock();
        
        // Scan PIR and inject into vAPIC
        for i in 0..4 {
            let mut pir = self.posted_interrupts.pir[i];
            while pir != 0 {
                let bit = pir.trailing_zeros();
                let vector = (i * 64 + bit as usize) as u8;
                
                apic.set_irr(vector);
                pir &= !(1u64 << bit);
            }
            self.posted_interrupts.pir[i] = 0;
        }
        
        self.posted_interrupts.on = false;
    }
}

/// Global interrupt controller instance
pub static INTERRUPT_CONTROLLER: Mutex<Option<InterruptController>> = Mutex::new(None);

/// Initialize the interrupt controller
pub fn init(num_cpus: usize) {
    let controller = InterruptController::new(num_cpus);
    *INTERRUPT_CONTROLLER.lock() = Some(controller);
    log::info!("Interrupt controller initialized for {} CPUs", num_cpus);
}

/// Queue an interrupt globally
pub fn queue_interrupt(vector: u8, int_type: InterruptType) {
    if let Some(ref controller) = *INTERRUPT_CONTROLLER.lock() {
        controller.queue_interrupt(InterruptVector::new(vector, int_type));
    }
}

/// Raise an IRQ line
pub fn raise_irq(irq: u8) {
    if let Some(ref controller) = *INTERRUPT_CONTROLLER.lock() {
        controller.raise_irq(irq);
    }
}

extern crate alloc;