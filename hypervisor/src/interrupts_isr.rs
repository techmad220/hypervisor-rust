//! Complete ISR (Interrupt Service Routine) implementations
//! All hardware interrupt handlers and exception handlers

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::instructions::port::Port;
use x86_64::registers::control::Cr2;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, Segment};
use x86_64::instructions::tables::load_tss;
use spin::Mutex;
use lazy_static::lazy_static;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Stack sizes for different interrupt levels
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const NMI_IST_INDEX: u16 = 1; 
pub const MCE_IST_INDEX: u16 = 2;
pub const DEBUG_IST_INDEX: u16 = 3;
pub const PAGE_FAULT_IST_INDEX: u16 = 4;

lazy_static! {
    /// Global IDT instance
    static ref IDT: Mutex<InterruptDescriptorTable> = Mutex::new({
        let mut idt = InterruptDescriptorTable::new();
        configure_idt(&mut idt);
        idt
    });

    /// GDT with selectors
    static ref GDT: Mutex<(GlobalDescriptorTable, Selectors)> = Mutex::new({
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        let data_selector = gdt.add_entry(Descriptor::kernel_data_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&TSS));
        let user_code_selector = gdt.add_entry(Descriptor::user_code_segment());
        let user_data_selector = gdt.add_entry(Descriptor::user_data_segment());
        
        (gdt, Selectors {
            code_selector,
            data_selector,
            tss_selector,
            user_code_selector,
            user_data_selector,
        })
    });

    /// Task State Segment with interrupt stacks
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        
        // Configure separate stacks for critical interrupts
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 16384;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            stack_start + STACK_SIZE
        };
        
        tss.interrupt_stack_table[NMI_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 16384;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            stack_start + STACK_SIZE
        };
        
        tss.interrupt_stack_table[MCE_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 16384;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            stack_start + STACK_SIZE
        };
        
        tss.interrupt_stack_table[DEBUG_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 16384;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            stack_start + STACK_SIZE
        };
        
        tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 16384;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            stack_start + STACK_SIZE
        };
        
        tss
    };

    /// Interrupt statistics tracking
    static ref INTERRUPT_STATS: Mutex<InterruptStatistics> = Mutex::new(InterruptStatistics::new());

    /// 8259 PIC controllers
    static ref PICS: Mutex<ChainedPics> = Mutex::new(unsafe {
        ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET)
    });

    /// APIC instance
    static ref APIC: Mutex<Option<Apic>> = Mutex::new(None);
}

struct Selectors {
    code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
    user_code_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
}

#[derive(Debug, Default)]
pub struct InterruptStatistics {
    pub exceptions: [AtomicU64; 32],
    pub hardware_interrupts: [AtomicU64; 16],
    pub software_interrupts: AtomicU64,
    pub total_interrupts: AtomicU64,
    pub spurious_interrupts: AtomicU64,
}

impl InterruptStatistics {
    fn new() -> Self {
        Self::default()
    }

    pub fn record_exception(&self, vector: u8) {
        if vector < 32 {
            self.exceptions[vector as usize].fetch_add(1, Ordering::Relaxed);
            self.total_interrupts.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_hardware_interrupt(&self, irq: u8) {
        if irq < 16 {
            self.hardware_interrupts[irq as usize].fetch_add(1, Ordering::Relaxed);
            self.total_interrupts.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// PIC constants
const PIC_1_OFFSET: u8 = 32;
const PIC_2_OFFSET: u8 = 40;

/// 8259 PIC implementation
pub struct ChainedPics {
    pics: [Pic; 2],
}

struct Pic {
    offset: u8,
    command: Port<u8>,
    data: Port<u8>,
}

impl ChainedPics {
    pub const unsafe fn new(offset1: u8, offset2: u8) -> Self {
        ChainedPics {
            pics: [
                Pic {
                    offset: offset1,
                    command: Port::new(0x20),
                    data: Port::new(0x21),
                },
                Pic {
                    offset: offset2,
                    command: Port::new(0xA0),
                    data: Port::new(0xA1),
                },
            ],
        }
    }

    pub unsafe fn initialize(&mut self) {
        let mut wait = Port::<u8>::new(0x80);
        let wait_cycles = || wait.write(0);

        // Start initialization
        self.pics[0].command.write(0x11);
        wait_cycles();
        self.pics[1].command.write(0x11);
        wait_cycles();

        // Set offsets
        self.pics[0].data.write(self.pics[0].offset);
        wait_cycles();
        self.pics[1].data.write(self.pics[1].offset);
        wait_cycles();

        // Configure chaining
        self.pics[0].data.write(4);
        wait_cycles();
        self.pics[1].data.write(2);
        wait_cycles();

        // Set 8086 mode
        self.pics[0].data.write(0x01);
        wait_cycles();
        self.pics[1].data.write(0x01);
        wait_cycles();

        // Mask all interrupts initially
        self.pics[0].data.write(0xff);
        self.pics[1].data.write(0xff);
    }

    pub unsafe fn send_eoi(&mut self, irq: u8) {
        if irq >= 8 {
            self.pics[1].command.write(0x20);
        }
        self.pics[0].command.write(0x20);
    }

    pub unsafe fn disable(&mut self) {
        self.pics[0].data.write(0xff);
        self.pics[1].data.write(0xff);
    }
}

/// APIC implementation
pub struct Apic {
    base_address: u64,
    id: u32,
    version: u32,
    spurious_vector: u8,
}

impl Apic {
    const APIC_ID: u32 = 0x20;
    const APIC_VERSION: u32 = 0x30;
    const APIC_TPR: u32 = 0x80;
    const APIC_EOI: u32 = 0xB0;
    const APIC_SPURIOUS: u32 = 0xF0;
    const APIC_LVT_TIMER: u32 = 0x320;
    const APIC_LVT_ERROR: u32 = 0x370;

    pub unsafe fn new(base: u64) -> Self {
        let mut apic = Self {
            base_address: base,
            id: 0,
            version: 0,
            spurious_vector: 0xFF,
        };
        apic.init();
        apic
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let addr = (self.base_address + reg as u64) as *const u32;
        core::ptr::read_volatile(addr)
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        let addr = (self.base_address + reg as u64) as *mut u32;
        core::ptr::write_volatile(addr, value);
    }

    pub unsafe fn init(&mut self) {
        self.id = self.read(Self::APIC_ID) >> 24;
        self.version = self.read(Self::APIC_VERSION);

        // Enable APIC
        let spurious = self.read(Self::APIC_SPURIOUS);
        self.write(Self::APIC_SPURIOUS, spurious | 0x100 | (self.spurious_vector as u32));

        // Set task priority to accept all interrupts
        self.write(Self::APIC_TPR, 0);

        // Mask all LVT entries
        self.write(Self::APIC_LVT_TIMER, 0x10000);
        self.write(Self::APIC_LVT_ERROR, 0x10000);
    }

    pub unsafe fn send_eoi(&mut self) {
        self.write(Self::APIC_EOI, 0);
    }
}

/// Configure the IDT with all handlers
fn configure_idt(idt: &mut InterruptDescriptorTable) {
    // CPU Exceptions (0-31)
    idt.divide_error.set_handler_fn(divide_error_handler);
    idt.debug.set_handler_fn(debug_handler)
        .set_stack_index(DEBUG_IST_INDEX);
    idt.non_maskable_interrupt.set_handler_fn(nmi_handler)
        .set_stack_index(NMI_IST_INDEX);
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.overflow.set_handler_fn(overflow_handler);
    idt.bound_range_exceeded.set_handler_fn(bound_range_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.device_not_available.set_handler_fn(device_not_available_handler);
    idt.double_fault.set_handler_fn(double_fault_handler)
        .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    idt.invalid_tss.set_handler_fn(invalid_tss_handler);
    idt.segment_not_present.set_handler_fn(segment_not_present_handler);
    idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
    idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
    idt.page_fault.set_handler_fn(page_fault_handler)
        .set_stack_index(PAGE_FAULT_IST_INDEX);
    idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
    idt.alignment_check.set_handler_fn(alignment_check_handler);
    idt.machine_check.set_handler_fn(machine_check_handler)
        .set_stack_index(MCE_IST_INDEX);
    idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
    idt.virtualization.set_handler_fn(virtualization_handler);
    idt.security_exception.set_handler_fn(security_exception_handler);

    // Hardware interrupts (32-255)
    idt[PIC_1_OFFSET as usize].set_handler_fn(timer_interrupt_handler);
    idt[PIC_1_OFFSET as usize + 1].set_handler_fn(keyboard_interrupt_handler);
    idt[PIC_1_OFFSET as usize + 12].set_handler_fn(mouse_interrupt_handler);
    idt[PIC_1_OFFSET as usize + 14].set_handler_fn(primary_ata_interrupt_handler);
    idt[PIC_1_OFFSET as usize + 15].set_handler_fn(secondary_ata_interrupt_handler);
}

// Exception Handlers
extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(0);
    panic!("EXCEPTION: Divide Error\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(1);
    log::debug!("Debug exception at {:?}", stack_frame.instruction_pointer);
}

extern "x86-interrupt" fn nmi_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(2);
    log::error!("NMI received!");
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(3);
    log::debug!("Breakpoint at {:?}", stack_frame.instruction_pointer);
}

extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(4);
    panic!("EXCEPTION: Overflow\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn bound_range_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(5);
    panic!("EXCEPTION: Bound Range Exceeded\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(6);
    panic!("EXCEPTION: Invalid Opcode\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn device_not_available_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(7);
    unsafe {
        core::arch::asm!(
            "clts",
            "mov rax, cr0",
            "and rax, ~8",
            "mov cr0, rax",
            options(nostack, preserves_flags)
        );
    }
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    INTERRUPT_STATS.lock().record_exception(8);
    panic!("EXCEPTION: Double Fault (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn invalid_tss_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().record_exception(10);
    panic!("EXCEPTION: Invalid TSS (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().record_exception(11);
    panic!("EXCEPTION: Segment Not Present (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().record_exception(12);
    panic!("EXCEPTION: Stack Segment Fault (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().record_exception(13);
    panic!("EXCEPTION: General Protection Fault (error: {:#x})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    INTERRUPT_STATS.lock().record_exception(14);
    let cr2 = Cr2::read();
    panic!("EXCEPTION: Page Fault\nAddress: {:?}\nError: {:?}\n{:#?}", 
        cr2, error_code, stack_frame);
}

extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(16);
    panic!("EXCEPTION: x87 Floating Point\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn alignment_check_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().record_exception(17);
    panic!("EXCEPTION: Alignment Check (error: {})\n{:#?}", error_code, stack_frame);
}

extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    INTERRUPT_STATS.lock().record_exception(18);
    panic!("EXCEPTION: Machine Check\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(19);
    panic!("EXCEPTION: SIMD Floating Point\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn virtualization_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_exception(20);
    log::debug!("Virtualization exception");
}

extern "x86-interrupt" fn security_exception_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().record_exception(30);
    panic!("EXCEPTION: Security Exception (error: {})\n{:#?}", error_code, stack_frame);
}

// Hardware Interrupt Handlers
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_hardware_interrupt(0);
    unsafe {
        PICS.lock().send_eoi(0);
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_hardware_interrupt(1);
    let mut port = Port::<u8>::new(0x60);
    let _scancode = unsafe { port.read() };
    unsafe {
        PICS.lock().send_eoi(1);
    }
}

extern "x86-interrupt" fn mouse_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_hardware_interrupt(12);
    let mut port = Port::<u8>::new(0x60);
    let _data = unsafe { port.read() };
    unsafe {
        PICS.lock().send_eoi(12);
    }
}

extern "x86-interrupt" fn primary_ata_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_hardware_interrupt(14);
    unsafe {
        PICS.lock().send_eoi(14);
    }
}

extern "x86-interrupt" fn secondary_ata_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().record_hardware_interrupt(15);
    unsafe {
        PICS.lock().send_eoi(15);
    }
}

/// Initialize the interrupt system
pub fn init() {
    // Load GDT
    let (gdt, selectors) = &*GDT.lock();
    gdt.load();
    
    unsafe {
        CS::set_reg(selectors.code_selector);
        load_tss(selectors.tss_selector);
    }
    
    // Load IDT
    IDT.lock().load();
    
    // Initialize PICs
    unsafe {
        PICS.lock().initialize();
    }
    
    // Enable interrupts
    x86_64::instructions::interrupts::enable();
    
    log::info!("Interrupt system initialized");
}