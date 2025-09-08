//! Interrupt handling for hypervisor

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::instructions::port::Port;
use x86_64::registers::control::Cr2;
use spin::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref IDT: Mutex<InterruptDescriptorTable> = Mutex::new({
        let mut idt = InterruptDescriptorTable::new();
        
        // CPU exceptions
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.debug.set_handler_fn(debug_handler);
        idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
        idt.alignment_check.set_handler_fn(alignment_check_handler);
        idt.machine_check.set_handler_fn(machine_check_handler);
        idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
        idt.virtualization.set_handler_fn(virtualization_handler);
        
        // Hardware interrupts (PIC)
        idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_usize()].set_handler_fn(keyboard_interrupt_handler);
        
        idt
    });
}

/// Interrupt indices
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = 32,
    Keyboard = 33,
    Cascade = 34,
    Com2 = 35,
    Com1 = 36,
    Lpt2 = 37,
    FloppyDisk = 38,
    Lpt1 = 39,
    RtcTimer = 40,
    Acpi = 41,
    Available1 = 42,
    Available2 = 43,
    Mouse = 44,
    CoProcessor = 45,
    PrimaryAta = 46,
    SecondaryAta = 47,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
    
    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

/// Initialize interrupt handling
pub fn init() {
    IDT.lock().load();
    log::info!("Interrupt descriptor table loaded");
    
    // Initialize PIC
    unsafe {
        init_pic();
    }
}

/// Initialize 8259 PIC
unsafe fn init_pic() {
    const PIC1_CMD: u16 = 0x20;
    const PIC1_DATA: u16 = 0x21;
    const PIC2_CMD: u16 = 0xA0;
    const PIC2_DATA: u16 = 0xA1;
    
    let mut pic1_cmd = Port::<u8>::new(PIC1_CMD);
    let mut pic1_data = Port::<u8>::new(PIC1_DATA);
    let mut pic2_cmd = Port::<u8>::new(PIC2_CMD);
    let mut pic2_data = Port::<u8>::new(PIC2_DATA);
    
    // Start initialization sequence
    pic1_cmd.write(0x11);
    pic2_cmd.write(0x11);
    
    // Set vector offsets
    pic1_data.write(32);
    pic2_data.write(40);
    
    // Configure chaining
    pic1_data.write(4);
    pic2_data.write(2);
    
    // Set mode
    pic1_data.write(0x01);
    pic2_data.write(0x01);
    
    // Mask all interrupts except timer and keyboard
    pic1_data.write(0xFC);
    pic2_data.write(0xFF);
}

// Exception handlers
extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    panic!("DIVIDE ERROR\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    log::debug!("DEBUG EXCEPTION\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn nmi_handler(stack_frame: InterruptStackFrame) {
    log::error!("NON-MASKABLE INTERRUPT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    log::debug!("BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    panic!("OVERFLOW\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn bound_range_handler(stack_frame: InterruptStackFrame) {
    panic!("BOUND RANGE EXCEEDED\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    panic!("INVALID OPCODE\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    panic!("DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    panic!("DOUBLE FAULT (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn invalid_tss_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("INVALID TSS (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("SEGMENT NOT PRESENT (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("STACK SEGMENT FAULT (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn general_protection_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("GENERAL PROTECTION FAULT (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let addr = Cr2::read();
    log::error!("PAGE FAULT at {:?}", addr);
    log::error!("Error code: {:?}", error_code);
    log::error!("{:#?}", stack_frame);
    
    // Try to handle the page fault
    if let Some(ref mut hv) = unsafe { &mut crate::HYPERVISOR } {
        if let Err(e) = hv.memory_manager.handle_page_fault(addr, error_code.bits()) {
            panic!("Failed to handle page fault: {:?}", e);
        }
    } else {
        panic!("Page fault before hypervisor initialization");
    }
}

extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: InterruptStackFrame) {
    panic!("x87 FLOATING POINT ERROR\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn alignment_check_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("ALIGNMENT CHECK (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    panic!("MACHINE CHECK\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    panic!("SIMD FLOATING POINT ERROR\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn virtualization_handler(stack_frame: InterruptStackFrame) {
    log::debug!("VIRTUALIZATION EXCEPTION\n{:#?}", stack_frame);
}

// Hardware interrupt handlers
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Handle timer tick
    unsafe {
        // Send EOI to PIC
        Port::<u8>::new(0x20).write(0x20);
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Read keyboard scancode
    let scancode = unsafe { Port::<u8>::new(0x60).read() };
    log::trace!("Keyboard scancode: {:#x}", scancode);
    
    unsafe {
        // Send EOI to PIC
        Port::<u8>::new(0x20).write(0x20);
    }
}

/// Posted interrupt support for VMX
pub struct PostedInterrupt {
    pir: [u64; 4],  // Posted interrupt request
    on: u32,        // Outstanding notification
}

impl PostedInterrupt {
    pub fn new() -> Self {
        Self {
            pir: [0; 4],
            on: 0,
        }
    }
    
    /// Post an interrupt
    pub fn post(&mut self, vector: u8) {
        let index = (vector / 64) as usize;
        let bit = vector % 64;
        self.pir[index] |= 1 << bit;
        self.on = 1;
    }
    
    /// Clear posted interrupts
    pub fn clear(&mut self) {
        self.pir = [0; 4];
        self.on = 0;
    }
}

/// Interrupt remapping for VT-d
pub struct InterruptRemapping {
    enabled: bool,
    remapping_table: Vec<RemappingEntry>,
}

#[repr(C)]
struct RemappingEntry {
    low: u64,
    high: u64,
}

impl InterruptRemapping {
    pub fn new() -> Self {
        Self {
            enabled: false,
            remapping_table: Vec::new(),
        }
    }
    
    /// Enable interrupt remapping
    pub fn enable(&mut self) -> Result<(), crate::HypervisorError> {
        // Initialize remapping table
        self.remapping_table = Vec::with_capacity(256);
        
        // Configure IOMMU for interrupt remapping
        // ...
        
        self.enabled = true;
        log::info!("Interrupt remapping enabled");
        
        Ok(())
    }
}

extern crate alloc;
use alloc::vec::Vec;