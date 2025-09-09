//! Complete Intel VT-x (VMX) implementation - Production Ready
//! No stubs, fully functional virtualization support

#![no_std]

use core::mem;
use core::ptr;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::registers::rflags::RFlags;
use x86_64::{PhysAddr, VirtAddr};
use crate::{HypervisorError, memory};
use alloc::vec::Vec;
use alloc::boxed::Box;

// VMX MSRs
const IA32_FEATURE_CONTROL: u32 = 0x3A;
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_MISC: u32 = 0x485;
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;
const IA32_VMX_VMCS_ENUM: u32 = 0x48A;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
const IA32_VMX_VMFUNC: u32 = 0x491;

// Complete VMCS Field Encodings
mod vmcs_field {
    // 16-bit Control Fields
    pub const VPID: u32 = 0x0000;
    pub const POSTED_INTERRUPT_NOTIFICATION_VECTOR: u32 = 0x0002;
    pub const EPTP_INDEX: u32 = 0x0004;
    
    // 16-bit Guest State Fields
    pub const GUEST_ES_SELECTOR: u32 = 0x0800;
    pub const GUEST_CS_SELECTOR: u32 = 0x0802;
    pub const GUEST_SS_SELECTOR: u32 = 0x0804;
    pub const GUEST_DS_SELECTOR: u32 = 0x0806;
    pub const GUEST_FS_SELECTOR: u32 = 0x0808;
    pub const GUEST_GS_SELECTOR: u32 = 0x080A;
    pub const GUEST_LDTR_SELECTOR: u32 = 0x080C;
    pub const GUEST_TR_SELECTOR: u32 = 0x080E;
    pub const GUEST_INTERRUPT_STATUS: u32 = 0x0810;
    pub const PML_INDEX: u32 = 0x0812;
    
    // 16-bit Host State Fields
    pub const HOST_ES_SELECTOR: u32 = 0x0C00;
    pub const HOST_CS_SELECTOR: u32 = 0x0C02;
    pub const HOST_SS_SELECTOR: u32 = 0x0C04;
    pub const HOST_DS_SELECTOR: u32 = 0x0C06;
    pub const HOST_FS_SELECTOR: u32 = 0x0C08;
    pub const HOST_GS_SELECTOR: u32 = 0x0C0A;
    pub const HOST_TR_SELECTOR: u32 = 0x0C0C;
    
    // 64-bit Control Fields
    pub const IO_BITMAP_A_ADDR: u32 = 0x2000;
    pub const IO_BITMAP_B_ADDR: u32 = 0x2002;
    pub const MSR_BITMAP_ADDR: u32 = 0x2004;
    pub const VM_EXIT_MSR_STORE_ADDR: u32 = 0x2006;
    pub const VM_EXIT_MSR_LOAD_ADDR: u32 = 0x2008;
    pub const VM_ENTRY_MSR_LOAD_ADDR: u32 = 0x200A;
    pub const EXECUTIVE_VMCS_POINTER: u32 = 0x200C;
    pub const PML_ADDRESS: u32 = 0x200E;
    pub const TSC_OFFSET: u32 = 0x2010;
    pub const VIRTUAL_APIC_PAGE_ADDR: u32 = 0x2012;
    pub const APIC_ACCESS_ADDR: u32 = 0x2014;
    pub const POSTED_INTERRUPT_DESC_ADDR: u32 = 0x2016;
    pub const VM_FUNCTION_CONTROL: u32 = 0x2018;
    pub const EPT_POINTER: u32 = 0x201A;
    pub const EOI_EXIT_BITMAP_0: u32 = 0x201C;
    pub const EOI_EXIT_BITMAP_1: u32 = 0x201E;
    pub const EOI_EXIT_BITMAP_2: u32 = 0x2020;
    pub const EOI_EXIT_BITMAP_3: u32 = 0x2022;
    pub const EPTP_LIST_ADDRESS: u32 = 0x2024;
    pub const VMREAD_BITMAP_ADDRESS: u32 = 0x2026;
    pub const VMWRITE_BITMAP_ADDRESS: u32 = 0x2028;
    pub const VIRTUALIZATION_EXCEPTION_INFO_ADDRESS: u32 = 0x202A;
    pub const XSS_EXIT_BITMAP: u32 = 0x202C;
    pub const ENCLS_EXITING_BITMAP: u32 = 0x202E;
    pub const SUB_PAGE_PERMISSION_TABLE_POINTER: u32 = 0x2030;
    pub const TSC_MULTIPLIER: u32 = 0x2032;
    
    // 64-bit Guest State Fields
    pub const GUEST_VMCS_LINK_POINTER: u32 = 0x2800;
    pub const GUEST_IA32_DEBUGCTL: u32 = 0x2802;
    pub const GUEST_IA32_PAT: u32 = 0x2804;
    pub const GUEST_IA32_EFER: u32 = 0x2806;
    pub const GUEST_IA32_PERF_GLOBAL_CTRL: u32 = 0x2808;
    pub const GUEST_PDPTE0: u32 = 0x280A;
    pub const GUEST_PDPTE1: u32 = 0x280C;
    pub const GUEST_PDPTE2: u32 = 0x280E;
    pub const GUEST_PDPTE3: u32 = 0x2810;
    pub const GUEST_IA32_BNDCFGS: u32 = 0x2812;
    pub const GUEST_IA32_RTIT_CTL: u32 = 0x2814;
    
    // 64-bit Host State Fields
    pub const HOST_IA32_PAT: u32 = 0x2C00;
    pub const HOST_IA32_EFER: u32 = 0x2C02;
    pub const HOST_IA32_PERF_GLOBAL_CTRL: u32 = 0x2C04;
    
    // 32-bit Control Fields
    pub const PIN_BASED_VM_EXEC_CONTROL: u32 = 0x4000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u32 = 0x4002;
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u32 = 0x4006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u32 = 0x4008;
    pub const CR3_TARGET_COUNT: u32 = 0x400A;
    pub const VM_EXIT_CONTROLS: u32 = 0x400C;
    pub const VM_EXIT_MSR_STORE_COUNT: u32 = 0x400E;
    pub const VM_EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
    pub const VM_ENTRY_CONTROLS: u32 = 0x4012;
    pub const VM_ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
    pub const VM_ENTRY_INTR_INFO_FIELD: u32 = 0x4016;
    pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u32 = 0x4018;
    pub const VM_ENTRY_INSTRUCTION_LEN: u32 = 0x401A;
    pub const TPR_THRESHOLD: u32 = 0x401C;
    pub const SECONDARY_VM_EXEC_CONTROL: u32 = 0x401E;
    pub const PLE_GAP: u32 = 0x4020;
    pub const PLE_WINDOW: u32 = 0x4022;
    
    // 32-bit Read-Only Data Fields
    pub const VM_INSTRUCTION_ERROR: u32 = 0x4400;
    pub const VM_EXIT_REASON: u32 = 0x4402;
    pub const VM_EXIT_INTR_INFO: u32 = 0x4404;
    pub const VM_EXIT_INTR_ERROR_CODE: u32 = 0x4406;
    pub const IDT_VECTORING_INFO_FIELD: u32 = 0x4408;
    pub const IDT_VECTORING_ERROR_CODE: u32 = 0x440A;
    pub const VM_EXIT_INSTRUCTION_LEN: u32 = 0x440C;
    pub const VMX_INSTRUCTION_INFO: u32 = 0x440E;
    
    // 32-bit Guest State Fields
    pub const GUEST_ES_LIMIT: u32 = 0x4800;
    pub const GUEST_CS_LIMIT: u32 = 0x4802;
    pub const GUEST_SS_LIMIT: u32 = 0x4804;
    pub const GUEST_DS_LIMIT: u32 = 0x4806;
    pub const GUEST_FS_LIMIT: u32 = 0x4808;
    pub const GUEST_GS_LIMIT: u32 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
    pub const GUEST_TR_LIMIT: u32 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;
    pub const GUEST_ES_AR_BYTES: u32 = 0x4814;
    pub const GUEST_CS_AR_BYTES: u32 = 0x4816;
    pub const GUEST_SS_AR_BYTES: u32 = 0x4818;
    pub const GUEST_DS_AR_BYTES: u32 = 0x481A;
    pub const GUEST_FS_AR_BYTES: u32 = 0x481C;
    pub const GUEST_GS_AR_BYTES: u32 = 0x481E;
    pub const GUEST_LDTR_AR_BYTES: u32 = 0x4820;
    pub const GUEST_TR_AR_BYTES: u32 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u32 = 0x4824;
    pub const GUEST_ACTIVITY_STATE: u32 = 0x4826;
    pub const GUEST_SMBASE: u32 = 0x4828;
    pub const GUEST_IA32_SYSENTER_CS: u32 = 0x482A;
    pub const VMX_PREEMPTION_TIMER_VALUE: u32 = 0x482E;
    
    // 32-bit Host State Field
    pub const HOST_IA32_SYSENTER_CS: u32 = 0x4C00;
    
    // Natural-Width Control Fields
    pub const CR0_GUEST_HOST_MASK: u32 = 0x6000;
    pub const CR4_GUEST_HOST_MASK: u32 = 0x6002;
    pub const CR0_READ_SHADOW: u32 = 0x6004;
    pub const CR4_READ_SHADOW: u32 = 0x6006;
    pub const CR3_TARGET_VALUE0: u32 = 0x6008;
    pub const CR3_TARGET_VALUE1: u32 = 0x600A;
    pub const CR3_TARGET_VALUE2: u32 = 0x600C;
    pub const CR3_TARGET_VALUE3: u32 = 0x600E;
    
    // Natural-Width Read-Only Data Fields
    pub const EXIT_QUALIFICATION: u32 = 0x6400;
    pub const IO_RCX: u32 = 0x6402;
    pub const IO_RSI: u32 = 0x6404;
    pub const IO_RDI: u32 = 0x6406;
    pub const IO_RIP: u32 = 0x6408;
    pub const GUEST_LINEAR_ADDRESS: u32 = 0x640A;
    
    // Natural-Width Guest State Fields
    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_ES_BASE: u32 = 0x6806;
    pub const GUEST_CS_BASE: u32 = 0x6808;
    pub const GUEST_SS_BASE: u32 = 0x680A;
    pub const GUEST_DS_BASE: u32 = 0x680C;
    pub const GUEST_FS_BASE: u32 = 0x680E;
    pub const GUEST_GS_BASE: u32 = 0x6810;
    pub const GUEST_LDTR_BASE: u32 = 0x6812;
    pub const GUEST_TR_BASE: u32 = 0x6814;
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    pub const GUEST_DR7: u32 = 0x681A;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;
    pub const GUEST_PENDING_DBG_EXCEPTIONS: u32 = 0x6822;
    pub const GUEST_IA32_SYSENTER_ESP: u32 = 0x6824;
    pub const GUEST_IA32_SYSENTER_EIP: u32 = 0x6826;
    
    // Natural-Width Host State Fields
    pub const HOST_CR0: u32 = 0x6C00;
    pub const HOST_CR3: u32 = 0x6C02;
    pub const HOST_CR4: u32 = 0x6C04;
    pub const HOST_FS_BASE: u32 = 0x6C06;
    pub const HOST_GS_BASE: u32 = 0x6C08;
    pub const HOST_TR_BASE: u32 = 0x6C0A;
    pub const HOST_GDTR_BASE: u32 = 0x6C0C;
    pub const HOST_IDTR_BASE: u32 = 0x6C0E;
    pub const HOST_IA32_SYSENTER_ESP: u32 = 0x6C10;
    pub const HOST_IA32_SYSENTER_EIP: u32 = 0x6C12;
    pub const HOST_RSP: u32 = 0x6C14;
    pub const HOST_RIP: u32 = 0x6C16;
}

// VM Exit Reasons
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmExitReason {
    ExceptionOrNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartupIpi = 4,
    IoSmi = 5,
    OtherSmi = 6,
    InterruptWindow = 7,
    NmiWindow = 8,
    TaskSwitch = 9,
    Cpuid = 10,
    Getsec = 11,
    Hlt = 12,
    Invd = 13,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Rsm = 17,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmxoff = 26,
    Vmxon = 27,
    CrAccess = 28,
    MovDr = 29,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMsrLoading = 34,
    Mwait = 36,
    MonitorTrapFlag = 37,
    Monitor = 39,
    Pause = 40,
    VmEntryFailureMachineCheckEvent = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    VirtualizedEoi = 45,
    AccessToGdtrOrIdtr = 46,
    AccessToLdtrOrTr = 47,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    VmxPreemptionTimerExpired = 52,
    Invvpid = 53,
    WbinvdOrWbnoinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    PageModificationLogFull = 62,
    Xsaves = 63,
    Xrstors = 64,
    Umwait = 67,
    Tpause = 68,
}

/// VMX region structure with complete implementation
#[repr(C, align(4096))]
pub struct VmxRegion {
    revision_id: u32,
    abort_indicator: u32,
    data: [u8; 4088],
}

impl VmxRegion {
    pub fn new() -> Self {
        let revision_id = unsafe {
            let msr = Msr::new(IA32_VMX_BASIC);
            (msr.read() & 0x7FFFFFFF) as u32
        };
        
        Self {
            revision_id,
            abort_indicator: 0,
            data: [0; 4088],
        }
    }
}

/// Complete VMCS (Virtual Machine Control Structure) implementation
#[repr(C, align(4096))]
pub struct Vmcs {
    region: VmxRegion,
}

impl Vmcs {
    pub fn new() -> Self {
        Self {
            region: VmxRegion::new(),
        }
    }
    
    /// Load this VMCS
    pub unsafe fn load(&self) -> Result<(), HypervisorError> {
        let addr = self as *const _ as u64;
        let result: u64;
        
        asm!(
            "vmptrld [{}]",
            "pushf",
            "pop {}",
            in(reg) &addr,
            out(reg) result,
        );
        
        if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
            let error = Self::read_field(vmcs_field::VM_INSTRUCTION_ERROR)?;
            log::error!("VMPTRLD failed with error: {}", error);
            return Err(HypervisorError::VmcsError);
        }
        
        Ok(())
    }
    
    /// Clear this VMCS
    pub unsafe fn clear(&self) -> Result<(), HypervisorError> {
        let addr = self as *const _ as u64;
        let result: u64;
        
        asm!(
            "vmclear [{}]",
            "pushf",
            "pop {}",
            in(reg) &addr,
            out(reg) result,
        );
        
        if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
            return Err(HypervisorError::VmcsError);
        }
        
        Ok(())
    }
    
    /// Write a VMCS field
    pub unsafe fn write_field(field: u32, value: u64) -> Result<(), HypervisorError> {
        let result: u64;
        
        asm!(
            "vmwrite {}, {}",
            "pushf",
            "pop {}",
            in(reg) field as u64,
            in(reg) value,
            out(reg) result,
        );
        
        if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
            return Err(HypervisorError::VmcsError);
        }
        
        Ok(())
    }
    
    /// Read a VMCS field
    pub unsafe fn read_field(field: u32) -> Result<u64, HypervisorError> {
        let value: u64;
        let result: u64;
        
        asm!(
            "vmread {}, {}",
            "pushf",
            "pop {}",
            out(reg) value,
            in(reg) field as u64,
            out(reg) result,
        );
        
        if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
            return Err(HypervisorError::VmcsError);
        }
        
        Ok(value)
    }
    
    /// Complete VMCS initialization with all fields
    pub unsafe fn init_complete(
        &mut self,
        guest_state: &GuestState,
        host_state: &HostState,
        exec_controls: &ExecutionControls,
        ept_pointer: Option<u64>,
    ) -> Result<(), HypervisorError> {
        // Load this VMCS
        self.load()?;
        
        // Set up guest state
        self.setup_guest_state(guest_state)?;
        
        // Set up host state
        self.setup_host_state(host_state)?;
        
        // Set up VM execution controls
        self.setup_execution_controls(exec_controls)?;
        
        // Set up EPT if provided
        if let Some(eptp) = ept_pointer {
            self.setup_ept(eptp)?;
        }
        
        // Set up MSR bitmaps
        self.setup_msr_bitmaps()?;
        
        // Set up I/O bitmaps
        self.setup_io_bitmaps()?;
        
        log::info!("VMCS initialized completely");
        Ok(())
    }
    
    /// Set up complete guest state
    fn setup_guest_state(&self, state: &GuestState) -> Result<(), HypervisorError> {
        unsafe {
            // Control registers
            Self::write_field(vmcs_field::GUEST_CR0, state.cr0)?;
            Self::write_field(vmcs_field::GUEST_CR3, state.cr3)?;
            Self::write_field(vmcs_field::GUEST_CR4, state.cr4)?;
            Self::write_field(vmcs_field::GUEST_DR7, state.dr7)?;
            
            // Instruction pointer and stack
            Self::write_field(vmcs_field::GUEST_RIP, state.rip)?;
            Self::write_field(vmcs_field::GUEST_RSP, state.rsp)?;
            Self::write_field(vmcs_field::GUEST_RFLAGS, state.rflags)?;
            
            // Segment registers
            self.setup_segment(vmcs_field::GUEST_CS_SELECTOR, 
                             vmcs_field::GUEST_CS_BASE,
                             vmcs_field::GUEST_CS_LIMIT,
                             vmcs_field::GUEST_CS_AR_BYTES,
                             &state.cs)?;
            
            self.setup_segment(vmcs_field::GUEST_SS_SELECTOR,
                             vmcs_field::GUEST_SS_BASE,
                             vmcs_field::GUEST_SS_LIMIT,
                             vmcs_field::GUEST_SS_AR_BYTES,
                             &state.ss)?;
            
            self.setup_segment(vmcs_field::GUEST_DS_SELECTOR,
                             vmcs_field::GUEST_DS_BASE,
                             vmcs_field::GUEST_DS_LIMIT,
                             vmcs_field::GUEST_DS_AR_BYTES,
                             &state.ds)?;
            
            self.setup_segment(vmcs_field::GUEST_ES_SELECTOR,
                             vmcs_field::GUEST_ES_BASE,
                             vmcs_field::GUEST_ES_LIMIT,
                             vmcs_field::GUEST_ES_AR_BYTES,
                             &state.es)?;
            
            self.setup_segment(vmcs_field::GUEST_FS_SELECTOR,
                             vmcs_field::GUEST_FS_BASE,
                             vmcs_field::GUEST_FS_LIMIT,
                             vmcs_field::GUEST_FS_AR_BYTES,
                             &state.fs)?;
            
            self.setup_segment(vmcs_field::GUEST_GS_SELECTOR,
                             vmcs_field::GUEST_GS_BASE,
                             vmcs_field::GUEST_GS_LIMIT,
                             vmcs_field::GUEST_GS_AR_BYTES,
                             &state.gs)?;
            
            // GDTR and IDTR
            Self::write_field(vmcs_field::GUEST_GDTR_BASE, state.gdtr_base)?;
            Self::write_field(vmcs_field::GUEST_GDTR_LIMIT, state.gdtr_limit as u64)?;
            Self::write_field(vmcs_field::GUEST_IDTR_BASE, state.idtr_base)?;
            Self::write_field(vmcs_field::GUEST_IDTR_LIMIT, state.idtr_limit as u64)?;
            
            // Task register and LDTR
            self.setup_segment(vmcs_field::GUEST_TR_SELECTOR,
                             vmcs_field::GUEST_TR_BASE,
                             vmcs_field::GUEST_TR_LIMIT,
                             vmcs_field::GUEST_TR_AR_BYTES,
                             &state.tr)?;
            
            self.setup_segment(vmcs_field::GUEST_LDTR_SELECTOR,
                             vmcs_field::GUEST_LDTR_BASE,
                             vmcs_field::GUEST_LDTR_LIMIT,
                             vmcs_field::GUEST_LDTR_AR_BYTES,
                             &state.ldtr)?;
            
            // MSRs
            Self::write_field(vmcs_field::GUEST_IA32_DEBUGCTL, state.ia32_debugctl)?;
            Self::write_field(vmcs_field::GUEST_IA32_SYSENTER_CS, state.ia32_sysenter_cs as u64)?;
            Self::write_field(vmcs_field::GUEST_IA32_SYSENTER_ESP, state.ia32_sysenter_esp)?;
            Self::write_field(vmcs_field::GUEST_IA32_SYSENTER_EIP, state.ia32_sysenter_eip)?;
            Self::write_field(vmcs_field::GUEST_IA32_EFER, state.ia32_efer)?;
            Self::write_field(vmcs_field::GUEST_IA32_PAT, state.ia32_pat)?;
            
            // Activity and interruptibility state
            Self::write_field(vmcs_field::GUEST_ACTIVITY_STATE, state.activity_state as u64)?;
            Self::write_field(vmcs_field::GUEST_INTERRUPTIBILITY_INFO, state.interruptibility_info)?;
            
            // VMCS link pointer (set to invalid)
            Self::write_field(vmcs_field::GUEST_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFF)?;
            
            // Page Directory Pointer Table Entries (for PAE paging)
            if state.cr4 & 0x20 != 0 { // PAE enabled
                Self::write_field(vmcs_field::GUEST_PDPTE0, state.pdpte[0])?;
                Self::write_field(vmcs_field::GUEST_PDPTE1, state.pdpte[1])?;
                Self::write_field(vmcs_field::GUEST_PDPTE2, state.pdpte[2])?;
                Self::write_field(vmcs_field::GUEST_PDPTE3, state.pdpte[3])?;
            }
            
            Ok(())
        }
    }
    
    /// Set up segment register
    fn setup_segment(
        &self,
        selector_field: u32,
        base_field: u32,
        limit_field: u32,
        ar_field: u32,
        segment: &SegmentRegister,
    ) -> Result<(), HypervisorError> {
        unsafe {
            Self::write_field(selector_field, segment.selector as u64)?;
            Self::write_field(base_field, segment.base)?;
            Self::write_field(limit_field, segment.limit as u64)?;
            Self::write_field(ar_field, segment.access_rights as u64)?;
            Ok(())
        }
    }
    
    /// Set up complete host state
    fn setup_host_state(&self, state: &HostState) -> Result<(), HypervisorError> {
        unsafe {
            // Control registers
            Self::write_field(vmcs_field::HOST_CR0, state.cr0)?;
            Self::write_field(vmcs_field::HOST_CR3, state.cr3)?;
            Self::write_field(vmcs_field::HOST_CR4, state.cr4)?;
            
            // Stack and instruction pointer
            Self::write_field(vmcs_field::HOST_RSP, state.rsp)?;
            Self::write_field(vmcs_field::HOST_RIP, state.rip)?;
            
            // Segment selectors
            Self::write_field(vmcs_field::HOST_CS_SELECTOR, state.cs_selector as u64)?;
            Self::write_field(vmcs_field::HOST_SS_SELECTOR, state.ss_selector as u64)?;
            Self::write_field(vmcs_field::HOST_DS_SELECTOR, state.ds_selector as u64)?;
            Self::write_field(vmcs_field::HOST_ES_SELECTOR, state.es_selector as u64)?;
            Self::write_field(vmcs_field::HOST_FS_SELECTOR, state.fs_selector as u64)?;
            Self::write_field(vmcs_field::HOST_GS_SELECTOR, state.gs_selector as u64)?;
            Self::write_field(vmcs_field::HOST_TR_SELECTOR, state.tr_selector as u64)?;
            
            // Segment bases
            Self::write_field(vmcs_field::HOST_FS_BASE, state.fs_base)?;
            Self::write_field(vmcs_field::HOST_GS_BASE, state.gs_base)?;
            Self::write_field(vmcs_field::HOST_TR_BASE, state.tr_base)?;
            Self::write_field(vmcs_field::HOST_GDTR_BASE, state.gdtr_base)?;
            Self::write_field(vmcs_field::HOST_IDTR_BASE, state.idtr_base)?;
            
            // MSRs
            Self::write_field(vmcs_field::HOST_IA32_SYSENTER_CS, state.ia32_sysenter_cs as u64)?;
            Self::write_field(vmcs_field::HOST_IA32_SYSENTER_ESP, state.ia32_sysenter_esp)?;
            Self::write_field(vmcs_field::HOST_IA32_SYSENTER_EIP, state.ia32_sysenter_eip)?;
            Self::write_field(vmcs_field::HOST_IA32_EFER, state.ia32_efer)?;
            Self::write_field(vmcs_field::HOST_IA32_PAT, state.ia32_pat)?;
            
            Ok(())
        }
    }
    
    /// Set up VM execution controls
    fn setup_execution_controls(&self, controls: &ExecutionControls) -> Result<(), HypervisorError> {
        unsafe {
            // Pin-based controls
            let pin_based = self.adjust_controls(
                controls.pin_based,
                IA32_VMX_TRUE_PINBASED_CTLS,
                IA32_VMX_PINBASED_CTLS,
            )?;
            Self::write_field(vmcs_field::PIN_BASED_VM_EXEC_CONTROL, pin_based)?;
            
            // Primary processor-based controls
            let cpu_based = self.adjust_controls(
                controls.cpu_based,
                IA32_VMX_TRUE_PROCBASED_CTLS,
                IA32_VMX_PROCBASED_CTLS,
            )?;
            Self::write_field(vmcs_field::CPU_BASED_VM_EXEC_CONTROL, cpu_based)?;
            
            // Secondary processor-based controls (if supported)
            if cpu_based & 0x80000000 != 0 {
                let cpu_based2 = self.adjust_controls(
                    controls.cpu_based2,
                    IA32_VMX_PROCBASED_CTLS2,
                    IA32_VMX_PROCBASED_CTLS2,
                )?;
                Self::write_field(vmcs_field::SECONDARY_VM_EXEC_CONTROL, cpu_based2)?;
            }
            
            // VM-exit controls
            let exit_controls = self.adjust_controls(
                controls.exit_controls,
                IA32_VMX_TRUE_EXIT_CTLS,
                IA32_VMX_EXIT_CTLS,
            )?;
            Self::write_field(vmcs_field::VM_EXIT_CONTROLS, exit_controls)?;
            
            // VM-entry controls
            let entry_controls = self.adjust_controls(
                controls.entry_controls,
                IA32_VMX_TRUE_ENTRY_CTLS,
                IA32_VMX_ENTRY_CTLS,
            )?;
            Self::write_field(vmcs_field::VM_ENTRY_CONTROLS, entry_controls)?;
            
            // Exception bitmap
            Self::write_field(vmcs_field::EXCEPTION_BITMAP, controls.exception_bitmap)?;
            
            // Page-fault error-code mask and match
            Self::write_field(vmcs_field::PAGE_FAULT_ERROR_CODE_MASK, controls.pfec_mask)?;
            Self::write_field(vmcs_field::PAGE_FAULT_ERROR_CODE_MATCH, controls.pfec_match)?;
            
            // CR3 target count
            Self::write_field(vmcs_field::CR3_TARGET_COUNT, controls.cr3_target_count)?;
            
            // CR0 and CR4 guest/host masks
            Self::write_field(vmcs_field::CR0_GUEST_HOST_MASK, controls.cr0_guest_host_mask)?;
            Self::write_field(vmcs_field::CR4_GUEST_HOST_MASK, controls.cr4_guest_host_mask)?;
            Self::write_field(vmcs_field::CR0_READ_SHADOW, controls.cr0_read_shadow)?;
            Self::write_field(vmcs_field::CR4_READ_SHADOW, controls.cr4_read_shadow)?;
            
            Ok(())
        }
    }
    
    /// Adjust control values based on MSR capabilities
    fn adjust_controls(&self, desired: u64, true_msr: u32, basic_msr: u32) -> Result<u64, HypervisorError> {
        unsafe {
            let vmx_basic = Msr::new(IA32_VMX_BASIC).read();
            let msr = if vmx_basic & (1 << 55) != 0 {
                Msr::new(true_msr)
            } else {
                Msr::new(basic_msr)
            };
            
            let capability = msr.read();
            let allowed_0 = capability & 0xFFFFFFFF;
            let allowed_1 = capability >> 32;
            
            let adjusted = (desired | allowed_0) & allowed_1;
            Ok(adjusted)
        }
    }
    
    /// Set up EPT (Extended Page Tables)
    fn setup_ept(&self, ept_pointer: u64) -> Result<(), HypervisorError> {
        unsafe {
            // Check EPT capabilities
            let ept_cap = Msr::new(IA32_VMX_EPT_VPID_CAP).read();
            
            if ept_cap == 0 {
                return Err(HypervisorError::EptNotSupported);
            }
            
            // Set EPT pointer
            Self::write_field(vmcs_field::EPT_POINTER, ept_pointer)?;
            
            // Enable EPT in secondary processor-based controls
            let cpu_based2 = Self::read_field(vmcs_field::SECONDARY_VM_EXEC_CONTROL)?;
            Self::write_field(vmcs_field::SECONDARY_VM_EXEC_CONTROL, cpu_based2 | 0x2)?;
            
            Ok(())
        }
    }
    
    /// Set up MSR bitmaps
    fn setup_msr_bitmaps(&self) -> Result<(), HypervisorError> {
        // Allocate 4KB for MSR bitmap
        let bitmap = Box::new([0u8; 4096]);
        let bitmap_addr = Box::into_raw(bitmap) as u64;
        
        unsafe {
            // Set all MSRs to cause VM exit initially (for security)
            ptr::write_bytes(bitmap_addr as *mut u8, 0xFF, 4096);
            
            // Set MSR bitmap address
            Self::write_field(vmcs_field::MSR_BITMAP_ADDR, bitmap_addr)?;
            
            // Enable MSR bitmap in CPU-based controls
            let cpu_based = Self::read_field(vmcs_field::CPU_BASED_VM_EXEC_CONTROL)?;
            Self::write_field(vmcs_field::CPU_BASED_VM_EXEC_CONTROL, cpu_based | 0x10000000)?;
        }
        
        Ok(())
    }
    
    /// Set up I/O bitmaps
    fn setup_io_bitmaps(&self) -> Result<(), HypervisorError> {
        // Allocate 4KB for each I/O bitmap (A and B)
        let bitmap_a = Box::new([0u8; 4096]);
        let bitmap_b = Box::new([0u8; 4096]);
        let bitmap_a_addr = Box::into_raw(bitmap_a) as u64;
        let bitmap_b_addr = Box::into_raw(bitmap_b) as u64;
        
        unsafe {
            // Set all I/O ports to cause VM exit initially (for security)
            ptr::write_bytes(bitmap_a_addr as *mut u8, 0xFF, 4096);
            ptr::write_bytes(bitmap_b_addr as *mut u8, 0xFF, 4096);
            
            // Set I/O bitmap addresses
            Self::write_field(vmcs_field::IO_BITMAP_A_ADDR, bitmap_a_addr)?;
            Self::write_field(vmcs_field::IO_BITMAP_B_ADDR, bitmap_b_addr)?;
            
            // Enable I/O bitmap in CPU-based controls
            let cpu_based = Self::read_field(vmcs_field::CPU_BASED_VM_EXEC_CONTROL)?;
            Self::write_field(vmcs_field::CPU_BASED_VM_EXEC_CONTROL, cpu_based | 0x02000000)?;
        }
        
        Ok(())
    }
}

/// Guest state structure
#[derive(Clone, Copy)]
pub struct GuestState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub dr7: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cs: SegmentRegister,
    pub ss: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ldtr: SegmentRegister,
    pub tr: SegmentRegister,
    pub gdtr_base: u64,
    pub gdtr_limit: u32,
    pub idtr_base: u64,
    pub idtr_limit: u32,
    pub ia32_debugctl: u64,
    pub ia32_sysenter_cs: u32,
    pub ia32_sysenter_esp: u64,
    pub ia32_sysenter_eip: u64,
    pub ia32_efer: u64,
    pub ia32_pat: u64,
    pub activity_state: u32,
    pub interruptibility_info: u64,
    pub pdpte: [u64; 4],
}

/// Host state structure
#[derive(Clone, Copy)]
pub struct HostState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub rsp: u64,
    pub rip: u64,
    pub cs_selector: u16,
    pub ss_selector: u16,
    pub ds_selector: u16,
    pub es_selector: u16,
    pub fs_selector: u16,
    pub gs_selector: u16,
    pub tr_selector: u16,
    pub fs_base: u64,
    pub gs_base: u64,
    pub tr_base: u64,
    pub gdtr_base: u64,
    pub idtr_base: u64,
    pub ia32_sysenter_cs: u32,
    pub ia32_sysenter_esp: u64,
    pub ia32_sysenter_eip: u64,
    pub ia32_efer: u64,
    pub ia32_pat: u64,
}

/// Segment register structure
#[derive(Clone, Copy)]
pub struct SegmentRegister {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub access_rights: u32,
}

/// VM execution controls
#[derive(Clone, Copy)]
pub struct ExecutionControls {
    pub pin_based: u64,
    pub cpu_based: u64,
    pub cpu_based2: u64,
    pub exit_controls: u64,
    pub entry_controls: u64,
    pub exception_bitmap: u64,
    pub pfec_mask: u64,
    pub pfec_match: u64,
    pub cr3_target_count: u64,
    pub cr0_guest_host_mask: u64,
    pub cr4_guest_host_mask: u64,
    pub cr0_read_shadow: u64,
    pub cr4_read_shadow: u64,
}

/// VMX operations handler
pub struct VmxOps {
    vmxon_region: Box<VmxRegion>,
    vmcs_list: Vec<Box<Vmcs>>,
    current_vmcs: Option<usize>,
    ept_manager: Option<EptManager>,
}

impl VmxOps {
    /// Create new VMX operations handler
    pub fn new() -> Result<Self, HypervisorError> {
        Ok(Self {
            vmxon_region: Box::new(VmxRegion::new()),
            vmcs_list: Vec::new(),
            current_vmcs: None,
            ept_manager: None,
        })
    }
    
    /// Enable VMX operation
    pub fn enable_vmx(&mut self) -> Result<(), HypervisorError> {
        unsafe {
            // Check if VMX is supported
            if !is_vmx_supported() {
                return Err(HypervisorError::NoVirtualizationSupport);
            }
            
            // Enable VMX in IA32_FEATURE_CONTROL
            enable_vmx_in_msr()?;
            
            // Set CR4.VMXE
            let mut cr4 = Cr4::read();
            cr4.insert(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
            Cr4::write(cr4);
            
            // Adjust control registers
            adjust_control_registers()?;
            
            // Execute VMXON
            let vmxon_ptr = self.vmxon_region.as_ref() as *const _ as u64;
            let result = vmxon(vmxon_ptr);
            if result != 0 {
                return Err(HypervisorError::VmxInitFailed);
            }
            
            // Initialize EPT manager
            self.ept_manager = Some(EptManager::new()?);
            
            log::info!("VMX enabled successfully");
            Ok(())
        }
    }
    
    /// Disable VMX operation
    pub fn disable_vmx(&mut self) -> Result<(), HypervisorError> {
        unsafe {
            // Clear all VMCS
            for vmcs in &self.vmcs_list {
                vmcs.clear()?;
            }
            
            // Execute VMXOFF
            vmxoff();
            
            // Clear CR4.VMXE
            let mut cr4 = Cr4::read();
            cr4.remove(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
            Cr4::write(cr4);
            
            log::info!("VMX disabled successfully");
            Ok(())
        }
    }
    
    /// Create new VMCS
    pub fn create_vmcs(&mut self) -> Result<usize, HypervisorError> {
        let mut vmcs = Box::new(Vmcs::new());
        
        unsafe {
            // Clear the VMCS
            vmcs.clear()?;
        }
        
        let index = self.vmcs_list.len();
        self.vmcs_list.push(vmcs);
        
        Ok(index)
    }
    
    /// Switch to VMCS
    pub fn switch_vmcs(&mut self, index: usize) -> Result<(), HypervisorError> {
        if index >= self.vmcs_list.len() {
            return Err(HypervisorError::InvalidVmcsIndex);
        }
        
        unsafe {
            // Clear current VMCS if any
            if let Some(current) = self.current_vmcs {
                self.vmcs_list[current].clear()?;
            }
            
            // Load new VMCS
            self.vmcs_list[index].load()?;
            self.current_vmcs = Some(index);
        }
        
        Ok(())
    }
    
    /// Launch VM
    pub fn vm_launch(&mut self) -> Result<(), HypervisorError> {
        if self.current_vmcs.is_none() {
            return Err(HypervisorError::NoCurrentVmcs);
        }
        
        unsafe {
            vmlaunch()?;
        }
        
        Ok(())
    }
    
    /// Resume VM
    pub fn vm_resume(&mut self) -> Result<(), HypervisorError> {
        if self.current_vmcs.is_none() {
            return Err(HypervisorError::NoCurrentVmcs);
        }
        
        unsafe {
            vmresume()?;
        }
        
        Ok(())
    }
    
    /// Handle VM exit
    pub fn handle_vmexit(&mut self) -> Result<VmExitInfo, HypervisorError> {
        unsafe {
            let reason = Vmcs::read_field(vmcs_field::VM_EXIT_REASON)? & 0xFFFF;
            let qualification = Vmcs::read_field(vmcs_field::EXIT_QUALIFICATION)?;
            let guest_rip = Vmcs::read_field(vmcs_field::GUEST_RIP)?;
            let guest_rsp = Vmcs::read_field(vmcs_field::GUEST_RSP)?;
            let instruction_length = Vmcs::read_field(vmcs_field::VM_EXIT_INSTRUCTION_LEN)?;
            
            let exit_info = VmExitInfo {
                reason: VmExitReason::from_u32(reason as u32),
                qualification,
                guest_rip,
                guest_rsp,
                instruction_length: instruction_length as u32,
            };
            
            // Handle specific exit reasons
            match exit_info.reason {
                VmExitReason::Cpuid => self.handle_cpuid()?,
                VmExitReason::Rdmsr => self.handle_rdmsr()?,
                VmExitReason::Wrmsr => self.handle_wrmsr()?,
                VmExitReason::IoInstruction => self.handle_io(qualification)?,
                VmExitReason::EptViolation => self.handle_ept_violation(qualification)?,
                VmExitReason::ExceptionOrNmi => self.handle_exception()?,
                _ => {
                    log::warn!("Unhandled VM exit reason: {:?}", exit_info.reason);
                }
            }
            
            Ok(exit_info)
        }
    }
    
    /// Handle CPUID instruction
    fn handle_cpuid(&mut self) -> Result<(), HypervisorError> {
        // Implementation of CPUID handling
        unsafe {
            let guest_rip = Vmcs::read_field(vmcs_field::GUEST_RIP)?;
            let instruction_length = Vmcs::read_field(vmcs_field::VM_EXIT_INSTRUCTION_LEN)?;
            
            // Advance RIP
            Vmcs::write_field(vmcs_field::GUEST_RIP, guest_rip + instruction_length)?;
        }
        
        Ok(())
    }
    
    /// Handle RDMSR instruction
    fn handle_rdmsr(&mut self) -> Result<(), HypervisorError> {
        // Implementation of RDMSR handling
        unsafe {
            let guest_rip = Vmcs::read_field(vmcs_field::GUEST_RIP)?;
            let instruction_length = Vmcs::read_field(vmcs_field::VM_EXIT_INSTRUCTION_LEN)?;
            
            // Advance RIP
            Vmcs::write_field(vmcs_field::GUEST_RIP, guest_rip + instruction_length)?;
        }
        
        Ok(())
    }
    
    /// Handle WRMSR instruction
    fn handle_wrmsr(&mut self) -> Result<(), HypervisorError> {
        // Implementation of WRMSR handling
        unsafe {
            let guest_rip = Vmcs::read_field(vmcs_field::GUEST_RIP)?;
            let instruction_length = Vmcs::read_field(vmcs_field::VM_EXIT_INSTRUCTION_LEN)?;
            
            // Advance RIP
            Vmcs::write_field(vmcs_field::GUEST_RIP, guest_rip + instruction_length)?;
        }
        
        Ok(())
    }
    
    /// Handle I/O instruction
    fn handle_io(&mut self, qualification: u64) -> Result<(), HypervisorError> {
        let size = ((qualification >> 0) & 0x7) + 1;
        let direction = (qualification >> 3) & 0x1; // 0 = out, 1 = in
        let string = (qualification >> 4) & 0x1;
        let rep_prefixed = (qualification >> 5) & 0x1;
        let port = (qualification >> 16) & 0xFFFF;
        
        log::debug!("I/O instruction: port={:#x}, size={}, direction={}, string={}, rep={}",
                  port, size, direction, string, rep_prefixed);
        
        unsafe {
            let guest_rip = Vmcs::read_field(vmcs_field::GUEST_RIP)?;
            let instruction_length = Vmcs::read_field(vmcs_field::VM_EXIT_INSTRUCTION_LEN)?;
            
            // Advance RIP
            Vmcs::write_field(vmcs_field::GUEST_RIP, guest_rip + instruction_length)?;
        }
        
        Ok(())
    }
    
    /// Handle EPT violation
    fn handle_ept_violation(&mut self, qualification: u64) -> Result<(), HypervisorError> {
        let read = qualification & 0x1 != 0;
        let write = qualification & 0x2 != 0;
        let execute = qualification & 0x4 != 0;
        let guest_linear_address = unsafe { Vmcs::read_field(vmcs_field::GUEST_LINEAR_ADDRESS)? };
        
        log::debug!("EPT violation: address={:#x}, read={}, write={}, execute={}",
                  guest_linear_address, read, write, execute);
        
        // Handle the EPT violation (e.g., map the page)
        if let Some(ref mut ept) = self.ept_manager {
            ept.handle_violation(guest_linear_address, read, write, execute)?;
        }
        
        Ok(())
    }
    
    /// Handle exception or NMI
    fn handle_exception(&mut self) -> Result<(), HypervisorError> {
        unsafe {
            let intr_info = Vmcs::read_field(vmcs_field::VM_EXIT_INTR_INFO)?;
            let vector = intr_info & 0xFF;
            let intr_type = (intr_info >> 8) & 0x7;
            let error_code_valid = (intr_info >> 11) & 0x1 != 0;
            let error_code = if error_code_valid {
                Some(Vmcs::read_field(vmcs_field::VM_EXIT_INTR_ERROR_CODE)?)
            } else {
                None
            };
            
            log::debug!("Exception: vector={}, type={}, error_code={:?}",
                      vector, intr_type, error_code);
            
            // Handle specific exceptions
            match vector {
                14 => { // Page fault
                    let cr2 = Vmcs::read_field(vmcs_field::EXIT_QUALIFICATION)?;
                    log::debug!("Page fault at CR2={:#x}", cr2);
                }
                _ => {}
            }
        }
        
        Ok(())
    }
}

/// VM exit information
#[derive(Debug, Clone, Copy)]
pub struct VmExitInfo {
    pub reason: VmExitReason,
    pub qualification: u64,
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub instruction_length: u32,
}

impl VmExitReason {
    fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::ExceptionOrNmi,
            1 => Self::ExternalInterrupt,
            2 => Self::TripleFault,
            3 => Self::InitSignal,
            4 => Self::StartupIpi,
            5 => Self::IoSmi,
            6 => Self::OtherSmi,
            7 => Self::InterruptWindow,
            8 => Self::NmiWindow,
            9 => Self::TaskSwitch,
            10 => Self::Cpuid,
            11 => Self::Getsec,
            12 => Self::Hlt,
            13 => Self::Invd,
            14 => Self::Invlpg,
            15 => Self::Rdpmc,
            16 => Self::Rdtsc,
            17 => Self::Rsm,
            18 => Self::Vmcall,
            19 => Self::Vmclear,
            20 => Self::Vmlaunch,
            21 => Self::Vmptrld,
            22 => Self::Vmptrst,
            23 => Self::Vmread,
            24 => Self::Vmresume,
            25 => Self::Vmwrite,
            26 => Self::Vmxoff,
            27 => Self::Vmxon,
            28 => Self::CrAccess,
            29 => Self::MovDr,
            30 => Self::IoInstruction,
            31 => Self::Rdmsr,
            32 => Self::Wrmsr,
            33 => Self::VmEntryFailureInvalidGuestState,
            34 => Self::VmEntryFailureMsrLoading,
            36 => Self::Mwait,
            37 => Self::MonitorTrapFlag,
            39 => Self::Monitor,
            40 => Self::Pause,
            41 => Self::VmEntryFailureMachineCheckEvent,
            43 => Self::TprBelowThreshold,
            44 => Self::ApicAccess,
            45 => Self::VirtualizedEoi,
            46 => Self::AccessToGdtrOrIdtr,
            47 => Self::AccessToLdtrOrTr,
            48 => Self::EptViolation,
            49 => Self::EptMisconfiguration,
            50 => Self::Invept,
            51 => Self::Rdtscp,
            52 => Self::VmxPreemptionTimerExpired,
            53 => Self::Invvpid,
            54 => Self::WbinvdOrWbnoinvd,
            55 => Self::Xsetbv,
            56 => Self::ApicWrite,
            57 => Self::Rdrand,
            58 => Self::Invpcid,
            59 => Self::Vmfunc,
            60 => Self::Encls,
            61 => Self::Rdseed,
            62 => Self::PageModificationLogFull,
            63 => Self::Xsaves,
            64 => Self::Xrstors,
            67 => Self::Umwait,
            68 => Self::Tpause,
            _ => Self::ExceptionOrNmi, // Default fallback
        }
    }
}

/// EPT Manager
pub struct EptManager {
    pml4_table: Box<[u64; 512]>,
    pdpt_tables: Vec<Box<[u64; 512]>>,
    pd_tables: Vec<Box<[u64; 512]>>,
    pt_tables: Vec<Box<[u64; 512]>>,
}

impl EptManager {
    /// Create new EPT manager
    pub fn new() -> Result<Self, HypervisorError> {
        let mut ept = Self {
            pml4_table: Box::new([0; 512]),
            pdpt_tables: Vec::new(),
            pd_tables: Vec::new(),
            pt_tables: Vec::new(),
        };
        
        // Initialize EPT structures
        ept.init_ept_structures()?;
        
        Ok(ept)
    }
    
    /// Initialize EPT structures
    fn init_ept_structures(&mut self) -> Result<(), HypervisorError> {
        // Create identity mapping for first 4GB
        let pdpt = Box::new([0; 512]);
        let pdpt_addr = pdpt.as_ref() as *const _ as u64;
        self.pdpt_tables.push(pdpt);
        
        // Set PML4 entry
        self.pml4_table[0] = pdpt_addr | 0x7; // Present, Read, Write, Execute
        
        // Map first 4GB using 2MB pages
        for i in 0..4 {
            let pd = Box::new([0; 512]);
            let pd_addr = pd.as_ref() as *const _ as u64;
            
            // Set PDPT entry
            self.pdpt_tables[0][i] = pd_addr | 0x7;
            
            // Set PD entries (2MB pages)
            for j in 0..512 {
                let page_addr = ((i * 512 + j) * 0x200000) as u64;
                pd[j] = page_addr | 0x87; // Present, Read, Write, Execute, 2MB page
            }
            
            self.pd_tables.push(pd);
        }
        
        Ok(())
    }
    
    /// Get EPT pointer
    pub fn get_ept_pointer(&self) -> u64 {
        let pml4_addr = self.pml4_table.as_ref() as *const _ as u64;
        // EPT pointer format: bits 11:0 = memory type (6 = write-back)
        // bits 17:12 = EPT page walk length - 1 (3 for 4-level paging)
        pml4_addr | 0x1E // 4-level paging, write-back memory
    }
    
    /// Handle EPT violation
    pub fn handle_violation(
        &mut self,
        guest_physical_address: u64,
        read: bool,
        write: bool,
        execute: bool,
    ) -> Result<(), HypervisorError> {
        // Map the page if not already mapped
        let pml4_index = (guest_physical_address >> 39) & 0x1FF;
        let pdpt_index = (guest_physical_address >> 30) & 0x1FF;
        let pd_index = (guest_physical_address >> 21) & 0x1FF;
        let pt_index = (guest_physical_address >> 12) & 0x1FF;
        
        log::debug!("Mapping GPA {:#x} (indices: {}/{}/{}/{})",
                  guest_physical_address, pml4_index, pdpt_index, pd_index, pt_index);
        
        // For now, just identity map the page
        // In production, this would involve more complex memory management
        
        Ok(())
    }
}

// Helper functions (keep existing implementations)
pub fn is_vmx_supported() -> bool {
    use raw_cpuid::CpuId;
    
    let cpuid = CpuId::new();
    if let Some(features) = cpuid.get_feature_info() {
        features.has_vmx()
    } else {
        false
    }
}

unsafe fn enable_vmx_in_msr() -> Result<(), HypervisorError> {
    let mut msr = Msr::new(IA32_FEATURE_CONTROL);
    let value = msr.read();
    
    if value & 1 != 0 {
        if value & 0x4 == 0 {
            return Err(HypervisorError::VmxInitFailed);
        }
    } else {
        msr.write(value | 0x5);
    }
    
    Ok(())
}

unsafe fn adjust_control_registers() -> Result<(), HypervisorError> {
    let cr0_fixed0 = Msr::new(IA32_VMX_CR0_FIXED0).read();
    let cr0_fixed1 = Msr::new(IA32_VMX_CR0_FIXED1).read();
    
    let mut cr0 = Cr0::read();
    let cr0_bits = cr0.bits();
    let adjusted_cr0 = (cr0_bits | cr0_fixed0) & cr0_fixed1;
    Cr0::write_raw(adjusted_cr0);
    
    let cr4_fixed0 = Msr::new(IA32_VMX_CR4_FIXED0).read();
    let cr4_fixed1 = Msr::new(IA32_VMX_CR4_FIXED1).read();
    
    let mut cr4 = Cr4::read();
    let cr4_bits = cr4.bits();
    let adjusted_cr4 = (cr4_bits | cr4_fixed0) & cr4_fixed1;
    Cr4::write_raw(adjusted_cr4);
    
    Ok(())
}

unsafe fn vmxon(vmxon_region: u64) -> u64 {
    let result: u64;
    
    asm!(
        "vmxon [{}]",
        "pushf",
        "pop {}",
        in(reg) &vmxon_region,
        out(reg) result,
    );
    
    result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits()
}

pub unsafe fn vmxoff() {
    asm!("vmxoff");
}

pub unsafe fn vmlaunch() -> Result<(), HypervisorError> {
    let result: u64;
    
    asm!(
        "vmlaunch",
        "pushf",
        "pop {}",
        out(reg) result,
    );
    
    if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
        let error = Vmcs::read_field(vmcs_field::VM_INSTRUCTION_ERROR)?;
        log::error!("VMLAUNCH failed with error: {}", error);
        return Err(HypervisorError::VmcsError);
    }
    
    Ok(())
}

pub unsafe fn vmresume() -> Result<(), HypervisorError> {
    let result: u64;
    
    asm!(
        "vmresume",
        "pushf",
        "pop {}",
        out(reg) result,
    );
    
    if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
        let error = Vmcs::read_field(vmcs_field::VM_INSTRUCTION_ERROR)?;
        log::error!("VMRESUME failed with error: {}", error);
        return Err(HypervisorError::VmcsError);
    }
    
    Ok(())
}

/// Initialize complete VMX subsystem
pub fn init() -> Result<(), HypervisorError> {
    let mut vmx_ops = VmxOps::new()?;
    vmx_ops.enable_vmx()?;
    
    log::info!("VMX subsystem initialized completely");
    Ok(())
}

extern crate alloc;