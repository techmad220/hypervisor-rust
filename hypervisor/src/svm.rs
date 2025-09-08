//! AMD-V (SVM) implementation

use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::PhysAddr;
use crate::HypervisorError;
use core::mem;

// SVM MSRs
const MSR_VM_CR: u32 = 0xC0010114;
const MSR_EFER: u32 = 0xC0000080;
const MSR_VM_HSAVE_PA: u32 = 0xC0010117;

// VMCB fields
const VMCB_CONTROL_AREA_OFFSET: usize = 0;
const VMCB_STATE_SAVE_AREA_OFFSET: usize = 0x400;

/// VMCB Control Area
#[repr(C, packed)]
pub struct VmcbControlArea {
    intercept_cr: u32,
    intercept_dr: u32,
    intercept_exceptions: u32,
    intercept_instructions1: u64,
    intercept_instructions2: u64,
    reserved1: [u8; 0x28],
    pause_filter_threshold: u16,
    pause_filter_count: u16,
    iopm_base_pa: u64,
    msrpm_base_pa: u64,
    tsc_offset: u64,
    guest_asid: u32,
    tlb_control: u8,
    reserved2: [u8; 3],
    v_intr: u64,
    interrupt_shadow: u64,
    exitcode: u64,
    exit_info_1: u64,
    exit_info_2: u64,
    exit_int_info: u64,
    np_enable: u64,
    avic_apic_bar: u64,
    guest_pa_of_ghcb: u64,
    event_inj: u64,
    nested_cr3: u64,
    lbr_virt_enable: u64,
    vmcb_clean: u32,
    reserved3: u32,
    next_rip: u64,
    n_bytes_fetched: u8,
    guest_instr_bytes: [u8; 15],
    avic_backing_page_ptr: u64,
    reserved4: u64,
    avic_logical_table_ptr: u64,
    avic_physical_table_ptr: u64,
    reserved5: u64,
    vmsa_ptr: u64,
    reserved6: [u8; 0x2E0],
}

/// VMCB State Save Area
#[repr(C, packed)]
pub struct VmcbStateSaveArea {
    es_selector: u16,
    es_attrib: u16,
    es_limit: u32,
    es_base: u64,
    
    cs_selector: u16,
    cs_attrib: u16,
    cs_limit: u32,
    cs_base: u64,
    
    ss_selector: u16,
    ss_attrib: u16,
    ss_limit: u32,
    ss_base: u64,
    
    ds_selector: u16,
    ds_attrib: u16,
    ds_limit: u32,
    ds_base: u64,
    
    fs_selector: u16,
    fs_attrib: u16,
    fs_limit: u32,
    fs_base: u64,
    
    gs_selector: u16,
    gs_attrib: u16,
    gs_limit: u32,
    gs_base: u64,
    
    gdtr_selector: u16,
    gdtr_attrib: u16,
    gdtr_limit: u32,
    gdtr_base: u64,
    
    ldtr_selector: u16,
    ldtr_attrib: u16,
    ldtr_limit: u32,
    ldtr_base: u64,
    
    idtr_selector: u16,
    idtr_attrib: u16,
    idtr_limit: u32,
    idtr_base: u64,
    
    tr_selector: u16,
    tr_attrib: u16,
    tr_limit: u32,
    tr_base: u64,
    
    reserved1: [u8; 0x2B],
    cpl: u8,
    reserved2: u32,
    efer: u64,
    reserved3: [u8; 0x70],
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    reserved4: [u8; 0x58],
    rsp: u64,
    reserved5: [u8; 0x18],
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    cr2: u64,
    reserved6: [u8; 0x20],
    g_pat: u64,
    dbgctl: u64,
    br_from: u64,
    br_to: u64,
    last_excp_from: u64,
    last_excp_to: u64,
}

/// VMCB (Virtual Machine Control Block)
#[repr(C, align(4096))]
pub struct Vmcb {
    control_area: VmcbControlArea,
    reserved: [u8; 0x400 - mem::size_of::<VmcbControlArea>()],
    state_save_area: VmcbStateSaveArea,
    padding: [u8; 4096 - 0x400 - mem::size_of::<VmcbStateSaveArea>()],
}

impl Vmcb {
    pub fn new() -> Self {
        unsafe { mem::zeroed() }
    }
    
    /// Initialize VMCB with default values
    pub fn init(&mut self) {
        // Set up control area
        self.control_area.intercept_cr = 0x10; // Intercept CR0 writes
        self.control_area.intercept_exceptions = 0xFFFFFFFF; // Intercept all exceptions initially
        
        // Set up guest state
        self.state_save_area.cs_selector = 0x8;
        self.state_save_area.cs_attrib = 0x9B; // Code segment, present, executable
        self.state_save_area.cs_limit = 0xFFFFFFFF;
        self.state_save_area.cs_base = 0;
        
        self.state_save_area.rip = 0x10000; // Guest entry point
        self.state_save_area.rsp = 0x80000; // Guest stack
        self.state_save_area.rflags = 0x2; // Reserved bit must be 1
        
        // Set up control registers
        self.state_save_area.cr0 = 0x80000001; // PG | PE
        self.state_save_area.cr3 = 0x1000; // Page table base
        self.state_save_area.cr4 = 0x20; // PAE
        
        self.state_save_area.efer = 0x500; // LME | LMA
    }
}

/// Initialize SVM
pub fn init() -> Result<(), HypervisorError> {
    unsafe {
        // Check if SVM is supported
        if !is_svm_supported() {
            return Err(HypervisorError::NoVirtualizationSupport);
        }
        
        // Enable SVM in EFER
        enable_svm_in_efer()?;
        
        // Set up VM_HSAVE_PA MSR
        setup_hsave_area()?;
        
        log::info!("SVM initialized successfully");
        Ok(())
    }
}

/// Check if SVM is supported
fn is_svm_supported() -> bool {
    use raw_cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // Check for SVM feature
    if let Some(info) = cpuid.get_extended_processor_info() {
        if info.has_svm() {
            // Also check if SVM is not disabled in BIOS
            let result = unsafe {
                let mut eax: u32;
                let mut ebx: u32;
                let mut ecx: u32;
                let mut edx: u32;
                
                asm!(
                    "cpuid",
                    inout("eax") 0x8000000A => eax,
                    out("ebx") ebx,
                    out("ecx") ecx,
                    out("edx") edx,
                );
                
                edx
            };
            
            // Check if SVM is locked off
            return result & 0x4 == 0;
        }
    }
    
    false
}

/// Enable SVM in EFER MSR
unsafe fn enable_svm_in_efer() -> Result<(), HypervisorError> {
    let mut efer = Msr::new(MSR_EFER);
    let value = efer.read();
    
    // Set SVME bit (bit 12)
    efer.write(value | (1 << 12));
    
    // Verify it was set
    if efer.read() & (1 << 12) == 0 {
        return Err(HypervisorError::SvmInitFailed);
    }
    
    Ok(())
}

/// Set up host save area
unsafe fn setup_hsave_area() -> Result<(), HypervisorError> {
    // Allocate 4KB aligned page for host save area
    let hsave_area = alloc::alloc::alloc(
        alloc::alloc::Layout::from_size_align(4096, 4096).unwrap()
    ) as u64;
    
    if hsave_area == 0 {
        return Err(HypervisorError::MemoryAllocationFailed);
    }
    
    // Set VM_HSAVE_PA MSR
    let mut msr = Msr::new(MSR_VM_HSAVE_PA);
    msr.write(hsave_area);
    
    Ok(())
}

/// Run guest with VMRUN
pub unsafe fn vmrun(vmcb_pa: u64) {
    asm!(
        "vmload",
        "vmrun",
        "vmsave",
        in("rax") vmcb_pa,
        options(noreturn)
    );
}

/// Exit guest with VMEXIT
pub unsafe fn vmexit() {
    asm!("vmexit");
}

// SVM exit codes
#[repr(u64)]
pub enum SvmExitCode {
    Read_CR0 = 0x000,
    Read_CR3 = 0x003,
    Read_CR4 = 0x004,
    Read_CR8 = 0x008,
    Write_CR0 = 0x010,
    Write_CR3 = 0x013,
    Write_CR4 = 0x014,
    Write_CR8 = 0x018,
    Exception = 0x040,
    Intr = 0x060,
    Nmi = 0x061,
    Smi = 0x062,
    Init = 0x063,
    Vintr = 0x064,
    Pause = 0x077,
    Hlt = 0x078,
    Invlpg = 0x079,
    Invlpga = 0x07A,
    IoIn = 0x07B,
    IoOut = 0x07C,
    Msr = 0x07D,
    Shutdown = 0x07F,
    Vmrun = 0x080,
    Vmmcall = 0x081,
    Vmload = 0x082,
    Vmsave = 0x083,
    Stgi = 0x084,
    Clgi = 0x085,
    Skinit = 0x086,
    Rdtscp = 0x087,
    Icebp = 0x088,
    Wbinvd = 0x089,
    Monitor = 0x08A,
    Mwait = 0x08B,
    Mwait_Conditional = 0x08C,
    Xsetbv = 0x08D,
    Rdpru = 0x08E,
    Efer_Write_Trap = 0x08F,
    NPF = 0x400,
    Invalid = 0xFFFFFFFFFFFFFFFF,
}

extern crate alloc;