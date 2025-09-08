//! AMD-V (SVM) implementation

use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::PhysAddr;
use crate::HypervisorError;
use core::mem;
use core::ptr;
use alloc::vec::Vec;
use alloc::boxed::Box;

// SVM MSRs
const MSR_VM_CR: u32 = 0xC0010114;
const MSR_EFER: u32 = 0xC0000080;
const MSR_VM_HSAVE_PA: u32 = 0xC0010117;

// SVM Intercept bits
const INTERCEPT_INTR: u32 = 1 << 0;
const INTERCEPT_NMI: u32 = 1 << 1;
const INTERCEPT_SMI: u32 = 1 << 2;
const INTERCEPT_INIT: u32 = 1 << 3;
const INTERCEPT_VINTR: u32 = 1 << 4;
const INTERCEPT_CR0_WRITE: u32 = 1 << 16;
const INTERCEPT_CR3_WRITE: u32 = 1 << 19;
const INTERCEPT_CR4_WRITE: u32 = 1 << 20;
const INTERCEPT_CR8_WRITE: u32 = 1 << 24;

// Instruction intercepts
const INTERCEPT_CPUID: u64 = 1 << 18;
const INTERCEPT_HLT: u64 = 1 << 24;
const INTERCEPT_INVLPG: u64 = 1 << 25;
const INTERCEPT_INVLPGA: u64 = 1 << 26;
const INTERCEPT_IOIO: u64 = 1 << 27;
const INTERCEPT_MSR: u64 = 1 << 28;
const INTERCEPT_SHUTDOWN: u64 = 1 << 31;
const INTERCEPT_VMRUN: u64 = 1 << 32;
const INTERCEPT_VMMCALL: u64 = 1 << 33;
const INTERCEPT_VMLOAD: u64 = 1 << 34;
const INTERCEPT_VMSAVE: u64 = 1 << 35;

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
        self.control_area.intercept_cr = INTERCEPT_CR0_WRITE | INTERCEPT_CR3_WRITE | INTERCEPT_CR4_WRITE;
        self.control_area.intercept_exceptions = 0xFFFFFFFF; // Intercept all exceptions initially
        
        // Set up instruction intercepts
        self.control_area.intercept_instructions1 = INTERCEPT_CPUID | INTERCEPT_HLT | 
                                                     INTERCEPT_INVLPG | INTERCEPT_IOIO | 
                                                     INTERCEPT_MSR | INTERCEPT_SHUTDOWN;
        self.control_area.intercept_instructions2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL | 
                                                     INTERCEPT_VMLOAD | INTERCEPT_VMSAVE;
        
        // Set up guest state
        self.state_save_area.cs_selector = 0x8;
        self.state_save_area.cs_attrib = 0x9B; // Code segment, present, executable
        self.state_save_area.cs_limit = 0xFFFFFFFF;
        self.state_save_area.cs_base = 0;
        
        // Set up other segments
        self.state_save_area.ds_selector = 0x10;
        self.state_save_area.ds_attrib = 0x93;
        self.state_save_area.ds_limit = 0xFFFFFFFF;
        self.state_save_area.ds_base = 0;
        
        self.state_save_area.es_selector = 0x10;
        self.state_save_area.es_attrib = 0x93;
        self.state_save_area.es_limit = 0xFFFFFFFF;
        self.state_save_area.es_base = 0;
        
        self.state_save_area.ss_selector = 0x10;
        self.state_save_area.ss_attrib = 0x93;
        self.state_save_area.ss_limit = 0xFFFFFFFF;
        self.state_save_area.ss_base = 0;
        
        self.state_save_area.rip = 0x10000; // Guest entry point
        self.state_save_area.rsp = 0x80000; // Guest stack
        self.state_save_area.rflags = 0x2; // Reserved bit must be 1
        
        // Set up control registers
        self.state_save_area.cr0 = 0x80000001; // PG | PE
        self.state_save_area.cr3 = 0x1000; // Page table base
        self.state_save_area.cr4 = 0x20; // PAE
        
        self.state_save_area.efer = 0x500; // LME | LMA
        
        // Clear TSC offset for accurate timing
        self.control_area.tsc_offset = 0;
        
        // Set ASID (Address Space ID)
        self.control_area.guest_asid = 1;
    }
    
    /// Set up NPT (Nested Page Tables)
    pub fn setup_npt(&mut self, npt_cr3: u64) {
        self.control_area.np_enable = 1;
        self.control_area.nested_cr3 = npt_cr3;
    }
    
    /// Enable specific intercepts
    pub fn enable_intercept(&mut self, intercept: u64) {
        if intercept < 32 {
            self.control_area.intercept_cr |= (1 << intercept) as u32;
        } else if intercept < 64 {
            self.control_area.intercept_instructions1 |= 1 << (intercept - 32);
        } else {
            self.control_area.intercept_instructions2 |= 1 << (intercept - 64);
        }
    }
    
    /// Mask CPUID features to hide hypervisor presence
    pub fn mask_cpuid_features(&mut self) {
        // Enable CPUID intercept to handle in VM exit
        self.control_area.intercept_instructions1 |= INTERCEPT_CPUID;
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
#[derive(Debug)]
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
    Cpuid = 0x072,
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

/// NPT (Nested Page Tables) support
pub mod npt {
    use super::*;
    use x86_64::structures::paging::{PageTable, PageTableFlags};
    
    /// NPT Page Table Entry flags
    const NPT_PRESENT: u64 = 1 << 0;
    const NPT_WRITABLE: u64 = 1 << 1;
    const NPT_USER: u64 = 1 << 2;
    const NPT_ACCESSED: u64 = 1 << 5;
    const NPT_DIRTY: u64 = 1 << 6;
    const NPT_HUGE: u64 = 1 << 7;
    
    /// NPT Context
    pub struct NptContext {
        pml4: Box<PageTable>,
        pdpt_pool: Vec<Box<PageTable>>,
        pd_pool: Vec<Box<PageTable>>,
        pt_pool: Vec<Box<PageTable>>,
    }
    
    impl NptContext {
        /// Create new NPT context
        pub fn new() -> Self {
            let mut pml4 = Box::new(PageTable::new());
            
            // Clear all entries
            for entry in pml4.iter_mut() {
                entry.set_unused();
            }
            
            NptContext {
                pml4,
                pdpt_pool: Vec::new(),
                pd_pool: Vec::new(),
                pt_pool: Vec::new(),
            }
        }
        
        /// Map guest physical to host physical address
        pub fn map_gpa_to_hpa(&mut self, gpa: u64, hpa: u64, size: u64, flags: u64) -> Result<(), HypervisorError> {
            let mut current_gpa = gpa;
            let mut current_hpa = hpa;
            let mut remaining = size;
            
            while remaining > 0 {
                let pml4_idx = ((current_gpa >> 39) & 0x1FF) as usize;
                let pdpt_idx = ((current_gpa >> 30) & 0x1FF) as usize;
                let pd_idx = ((current_gpa >> 21) & 0x1FF) as usize;
                let pt_idx = ((current_gpa >> 12) & 0x1FF) as usize;
                
                // Get or create PDPT
                if !self.pml4[pml4_idx].flags().contains(PageTableFlags::PRESENT) {
                    let mut pdpt = Box::new(PageTable::new());
                    for entry in pdpt.iter_mut() {
                        entry.set_unused();
                    }
                    let pdpt_addr = Box::as_ref(&pdpt) as *const _ as u64;
                    self.pml4[pml4_idx].set_addr(
                        PhysAddr::new(pdpt_addr),
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
                    );
                    self.pdpt_pool.push(pdpt);
                }
                
                // Map 2MB page if aligned and size permits
                if current_gpa & 0x1FFFFF == 0 && remaining >= 0x200000 {
                    // Use 2MB huge page
                    let pdpt = &mut self.pdpt_pool[self.pdpt_pool.len() - 1];
                    pdpt[pdpt_idx].set_addr(
                        PhysAddr::new(current_hpa | NPT_HUGE),
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
                    );
                    
                    current_gpa += 0x200000;
                    current_hpa += 0x200000;
                    remaining = remaining.saturating_sub(0x200000);
                } else {
                    // Use 4KB pages
                    // TODO: Implement 4KB page mapping
                    current_gpa += 0x1000;
                    current_hpa += 0x1000;
                    remaining = remaining.saturating_sub(0x1000);
                }
            }
            
            Ok(())
        }
        
        /// Get NPT CR3 value
        pub fn get_npt_cr3(&self) -> u64 {
            Box::as_ref(&self.pml4) as *const _ as u64
        }
    }
}

/// VM Exit handler
pub fn handle_vmexit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let exit_code = SvmExitCode::from_u64(vmcb.control_area.exitcode);
    
    match exit_code {
        SvmExitCode::Cpuid => handle_cpuid_exit(vmcb),
        SvmExitCode::Hlt => handle_hlt_exit(vmcb),
        SvmExitCode::Msr => handle_msr_exit(vmcb),
        SvmExitCode::IoIn | SvmExitCode::IoOut => handle_io_exit(vmcb),
        SvmExitCode::NPF => handle_npf_exit(vmcb),
        SvmExitCode::Exception => handle_exception_exit(vmcb),
        SvmExitCode::Vmmcall => handle_vmmcall_exit(vmcb),
        _ => {
            log::warn!("Unhandled VM exit: {:?}", exit_code);
            Ok(())
        }
    }
}

/// Handle CPUID exit
fn handle_cpuid_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let leaf = vmcb.state_save_area.rax as u32;
    let subleaf = vmcb.state_save_area.rcx as u32;
    
    unsafe {
        let mut eax: u32 = leaf;
        let mut ebx: u32 = 0;
        let mut ecx: u32 = subleaf;
        let mut edx: u32 = 0;
        
        asm!(
            "cpuid",
            inout("eax") eax,
            inout("ebx") ebx,
            inout("ecx") ecx,
            inout("edx") edx,
        );
        
        // Mask hypervisor present bit (ECX[31]) for leaf 1
        if leaf == 1 {
            ecx &= !(1 << 31);
        }
        
        // Hide hypervisor vendor leaf (0x40000000)
        if leaf >= 0x40000000 && leaf <= 0x400000FF {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        
        vmcb.state_save_area.rax = eax as u64;
        vmcb.state_save_area.rbx = ebx as u64;
        vmcb.state_save_area.rcx = ecx as u64;
        vmcb.state_save_area.rdx = edx as u64;
    }
    
    // Advance RIP
    vmcb.state_save_area.rip = vmcb.control_area.next_rip;
    
    Ok(())
}

/// Handle HLT exit
fn handle_hlt_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    // Advance RIP past HLT instruction
    vmcb.state_save_area.rip = vmcb.control_area.next_rip;
    
    // Optionally yield CPU
    core::hint::spin_loop();
    
    Ok(())
}

/// Handle MSR exit
fn handle_msr_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let is_write = vmcb.control_area.exit_info_1 & 1 == 1;
    let msr = vmcb.state_save_area.rcx as u32;
    
    if is_write {
        let value = (vmcb.state_save_area.rdx << 32) | (vmcb.state_save_area.rax & 0xFFFFFFFF);
        // Handle MSR write
        log::debug!("MSR write: 0x{:x} = 0x{:x}", msr, value);
    } else {
        // Handle MSR read
        let value = match msr {
            // TSC_AUX
            0xC0000103 => 0,
            // Default: read actual MSR
            _ => unsafe {
                let msr_obj = Msr::new(msr);
                msr_obj.read()
            }
        };
        
        vmcb.state_save_area.rax = value & 0xFFFFFFFF;
        vmcb.state_save_area.rdx = value >> 32;
    }
    
    // Advance RIP
    vmcb.state_save_area.rip = vmcb.control_area.next_rip;
    
    Ok(())
}

/// Handle I/O exit
fn handle_io_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let exit_info1 = vmcb.control_area.exit_info_1;
    let is_in = exit_info1 & (1 << 0) != 0;
    let port = (exit_info1 >> 16) as u16;
    
    if is_in {
        // Handle IN instruction
        vmcb.state_save_area.rax = 0xFF; // Return dummy value
    } else {
        // Handle OUT instruction
        let value = vmcb.state_save_area.rax as u8;
        log::debug!("OUT to port 0x{:x}: 0x{:x}", port, value);
    }
    
    // Advance RIP
    vmcb.state_save_area.rip = vmcb.control_area.next_rip;
    
    Ok(())
}

/// Handle NPF (Nested Page Fault) exit
fn handle_npf_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let fault_addr = vmcb.control_area.exit_info_2;
    let error_code = vmcb.control_area.exit_info_1;
    
    log::error!("Nested page fault at GPA 0x{:x}, error: 0x{:x}", fault_addr, error_code);
    
    // This would typically involve updating NPT mappings
    Err(HypervisorError::NestedPageFault)
}

/// Handle exception exit
fn handle_exception_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let vector = (vmcb.control_area.exit_info_1 & 0xFF) as u8;
    let error_code = vmcb.control_area.exit_info_1 >> 32;
    
    log::debug!("Exception {} at RIP 0x{:x}, error: 0x{:x}", vector, vmcb.state_save_area.rip, error_code);
    
    // Re-inject exception to guest
    vmcb.control_area.event_inj = (1 << 31) | // Valid
                                   (3 << 8) |  // Exception type
                                   vector as u64;
    
    if has_error_code(vector) {
        vmcb.control_area.event_inj |= (1 << 11) | (error_code << 32);
    }
    
    Ok(())
}

/// Handle VMMCALL exit
fn handle_vmmcall_exit(vmcb: &mut Vmcb) -> Result<(), HypervisorError> {
    let command = vmcb.state_save_area.rax;
    
    match command {
        0x1000 => {
            // Custom hypercall: get hypervisor version
            vmcb.state_save_area.rax = 0x01000000; // Version 1.0.0
        }
        _ => {
            log::warn!("Unknown VMMCALL command: 0x{:x}", command);
            vmcb.state_save_area.rax = u64::MAX; // Error
        }
    }
    
    // Advance RIP
    vmcb.state_save_area.rip = vmcb.control_area.next_rip;
    
    Ok(())
}

/// Check if exception has error code
fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

impl SvmExitCode {
    fn from_u64(code: u64) -> Self {
        match code {
            0x000 => SvmExitCode::Read_CR0,
            0x003 => SvmExitCode::Read_CR3,
            0x004 => SvmExitCode::Read_CR4,
            0x008 => SvmExitCode::Read_CR8,
            0x010 => SvmExitCode::Write_CR0,
            0x013 => SvmExitCode::Write_CR3,
            0x014 => SvmExitCode::Write_CR4,
            0x018 => SvmExitCode::Write_CR8,
            0x040 => SvmExitCode::Exception,
            0x060 => SvmExitCode::Intr,
            0x061 => SvmExitCode::Nmi,
            0x062 => SvmExitCode::Smi,
            0x063 => SvmExitCode::Init,
            0x064 => SvmExitCode::Vintr,
            0x072 => SvmExitCode::Cpuid,
            0x077 => SvmExitCode::Pause,
            0x078 => SvmExitCode::Hlt,
            0x079 => SvmExitCode::Invlpg,
            0x07A => SvmExitCode::Invlpga,
            0x07B => SvmExitCode::IoIn,
            0x07C => SvmExitCode::IoOut,
            0x07D => SvmExitCode::Msr,
            0x07F => SvmExitCode::Shutdown,
            0x080 => SvmExitCode::Vmrun,
            0x081 => SvmExitCode::Vmmcall,
            0x082 => SvmExitCode::Vmload,
            0x083 => SvmExitCode::Vmsave,
            0x084 => SvmExitCode::Stgi,
            0x085 => SvmExitCode::Clgi,
            0x086 => SvmExitCode::Skinit,
            0x087 => SvmExitCode::Rdtscp,
            0x088 => SvmExitCode::Icebp,
            0x089 => SvmExitCode::Wbinvd,
            0x08A => SvmExitCode::Monitor,
            0x08B => SvmExitCode::Mwait,
            0x08C => SvmExitCode::Mwait_Conditional,
            0x08D => SvmExitCode::Xsetbv,
            0x08E => SvmExitCode::Rdpru,
            0x08F => SvmExitCode::Efer_Write_Trap,
            0x400 => SvmExitCode::NPF,
            _ => SvmExitCode::Invalid,
        }
    }
}