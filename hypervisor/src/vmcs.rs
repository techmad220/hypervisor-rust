//! VMCS field definitions and management

// VMCS field encodings
pub mod fields {
    // 16-bit control fields
    pub const VIRTUAL_PROCESSOR_ID: u32 = 0x00000000;
    pub const POSTED_INTR_NV: u32 = 0x00000002;
    pub const EPTP_INDEX: u32 = 0x00000004;
    
    // 16-bit guest state fields
    pub const GUEST_ES_SELECTOR: u32 = 0x00000800;
    pub const GUEST_CS_SELECTOR: u32 = 0x00000802;
    pub const GUEST_SS_SELECTOR: u32 = 0x00000804;
    pub const GUEST_DS_SELECTOR: u32 = 0x00000806;
    pub const GUEST_FS_SELECTOR: u32 = 0x00000808;
    pub const GUEST_GS_SELECTOR: u32 = 0x0000080A;
    pub const GUEST_LDTR_SELECTOR: u32 = 0x0000080C;
    pub const GUEST_TR_SELECTOR: u32 = 0x0000080E;
    pub const GUEST_INTR_STATUS: u32 = 0x00000810;
    pub const GUEST_PML_INDEX: u32 = 0x00000812;
    
    // 16-bit host state fields
    pub const HOST_ES_SELECTOR: u32 = 0x00000C00;
    pub const HOST_CS_SELECTOR: u32 = 0x00000C02;
    pub const HOST_SS_SELECTOR: u32 = 0x00000C04;
    pub const HOST_DS_SELECTOR: u32 = 0x00000C06;
    pub const HOST_FS_SELECTOR: u32 = 0x00000C08;
    pub const HOST_GS_SELECTOR: u32 = 0x00000C0A;
    pub const HOST_TR_SELECTOR: u32 = 0x00000C0C;
    
    // 64-bit control fields
    pub const IO_BITMAP_A: u32 = 0x00002000;
    pub const IO_BITMAP_B: u32 = 0x00002002;
    pub const MSR_BITMAP: u32 = 0x00002004;
    pub const VM_EXIT_MSR_STORE_ADDR: u32 = 0x00002006;
    pub const VM_EXIT_MSR_LOAD_ADDR: u32 = 0x00002008;
    pub const VM_ENTRY_MSR_LOAD_ADDR: u32 = 0x0000200A;
    pub const PML_ADDRESS: u32 = 0x0000200E;
    pub const TSC_OFFSET: u32 = 0x00002010;
    pub const VIRTUAL_APIC_PAGE_ADDR: u32 = 0x00002012;
    pub const APIC_ACCESS_ADDR: u32 = 0x00002014;
    pub const POSTED_INTR_DESC_ADDR: u32 = 0x00002016;
    pub const VM_FUNCTION_CONTROL: u32 = 0x00002018;
    pub const EPT_POINTER: u32 = 0x0000201A;
    pub const EOI_EXIT_BITMAP0: u32 = 0x0000201C;
    pub const EOI_EXIT_BITMAP1: u32 = 0x0000201E;
    pub const EOI_EXIT_BITMAP2: u32 = 0x00002020;
    pub const EOI_EXIT_BITMAP3: u32 = 0x00002022;
    pub const EPTP_LIST_ADDRESS: u32 = 0x00002024;
    pub const VMREAD_BITMAP: u32 = 0x00002026;
    pub const VMWRITE_BITMAP: u32 = 0x00002028;
    
    // 64-bit guest state fields
    pub const VMCS_LINK_POINTER: u32 = 0x00002800;
    pub const GUEST_IA32_DEBUGCTL: u32 = 0x00002802;
    pub const GUEST_IA32_PAT: u32 = 0x00002804;
    pub const GUEST_IA32_EFER: u32 = 0x00002806;
    pub const GUEST_IA32_PERF_GLOBAL_CTRL: u32 = 0x00002808;
    pub const GUEST_PDPTR0: u32 = 0x0000280A;
    pub const GUEST_PDPTR1: u32 = 0x0000280C;
    pub const GUEST_PDPTR2: u32 = 0x0000280E;
    pub const GUEST_PDPTR3: u32 = 0x00002810;
    pub const GUEST_BNDCFGS: u32 = 0x00002812;
    pub const GUEST_IA32_RTIT_CTL: u32 = 0x00002814;
    
    // 64-bit host state fields
    pub const HOST_IA32_PAT: u32 = 0x00002C00;
    pub const HOST_IA32_EFER: u32 = 0x00002C02;
    pub const HOST_IA32_PERF_GLOBAL_CTRL: u32 = 0x00002C04;
    
    // 32-bit control fields
    pub const PIN_BASED_VM_EXEC_CONTROL: u32 = 0x00004000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u32 = 0x00004002;
    pub const EXCEPTION_BITMAP: u32 = 0x00004004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u32 = 0x00004006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u32 = 0x00004008;
    pub const CR3_TARGET_COUNT: u32 = 0x0000400A;
    pub const VM_EXIT_CONTROLS: u32 = 0x0000400C;
    pub const VM_EXIT_MSR_STORE_COUNT: u32 = 0x0000400E;
    pub const VM_EXIT_MSR_LOAD_COUNT: u32 = 0x00004010;
    pub const VM_ENTRY_CONTROLS: u32 = 0x00004012;
    pub const VM_ENTRY_MSR_LOAD_COUNT: u32 = 0x00004014;
    pub const VM_ENTRY_INTR_INFO_FIELD: u32 = 0x00004016;
    pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u32 = 0x00004018;
    pub const VM_ENTRY_INSTRUCTION_LEN: u32 = 0x0000401A;
    pub const TPR_THRESHOLD: u32 = 0x0000401C;
    pub const SECONDARY_VM_EXEC_CONTROL: u32 = 0x0000401E;
    pub const PLE_GAP: u32 = 0x00004020;
    pub const PLE_WINDOW: u32 = 0x00004022;
    
    // 32-bit read-only fields
    pub const VM_INSTRUCTION_ERROR: u32 = 0x00004400;
    pub const VM_EXIT_REASON: u32 = 0x00004402;
    pub const VM_EXIT_INTR_INFO: u32 = 0x00004404;
    pub const VM_EXIT_INTR_ERROR_CODE: u32 = 0x00004406;
    pub const IDT_VECTORING_INFO_FIELD: u32 = 0x00004408;
    pub const IDT_VECTORING_ERROR_CODE: u32 = 0x0000440A;
    pub const VM_EXIT_INSTRUCTION_LEN: u32 = 0x0000440C;
    pub const VMX_INSTRUCTION_INFO: u32 = 0x0000440E;
    
    // 32-bit guest state fields
    pub const GUEST_ES_LIMIT: u32 = 0x00004800;
    pub const GUEST_CS_LIMIT: u32 = 0x00004802;
    pub const GUEST_SS_LIMIT: u32 = 0x00004804;
    pub const GUEST_DS_LIMIT: u32 = 0x00004806;
    pub const GUEST_FS_LIMIT: u32 = 0x00004808;
    pub const GUEST_GS_LIMIT: u32 = 0x0000480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x0000480C;
    pub const GUEST_TR_LIMIT: u32 = 0x0000480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x00004810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x00004812;
    pub const GUEST_ES_AR_BYTES: u32 = 0x00004814;
    pub const GUEST_CS_AR_BYTES: u32 = 0x00004816;
    pub const GUEST_SS_AR_BYTES: u32 = 0x00004818;
    pub const GUEST_DS_AR_BYTES: u32 = 0x0000481A;
    pub const GUEST_FS_AR_BYTES: u32 = 0x0000481C;
    pub const GUEST_GS_AR_BYTES: u32 = 0x0000481E;
    pub const GUEST_LDTR_AR_BYTES: u32 = 0x00004820;
    pub const GUEST_TR_AR_BYTES: u32 = 0x00004822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u32 = 0x00004824;
    pub const GUEST_ACTIVITY_STATE: u32 = 0x00004826;
    pub const GUEST_SYSENTER_CS: u32 = 0x0000482A;
    pub const VMX_PREEMPTION_TIMER_VALUE: u32 = 0x0000482E;
    
    // 32-bit host state fields
    pub const HOST_IA32_SYSENTER_CS: u32 = 0x00004C00;
    
    // Natural-width control fields
    pub const CR0_GUEST_HOST_MASK: u32 = 0x00006000;
    pub const CR4_GUEST_HOST_MASK: u32 = 0x00006002;
    pub const CR0_READ_SHADOW: u32 = 0x00006004;
    pub const CR4_READ_SHADOW: u32 = 0x00006006;
    pub const CR3_TARGET_VALUE0: u32 = 0x00006008;
    pub const CR3_TARGET_VALUE1: u32 = 0x0000600A;
    pub const CR3_TARGET_VALUE2: u32 = 0x0000600C;
    pub const CR3_TARGET_VALUE3: u32 = 0x0000600E;
    
    // Natural-width read-only fields
    pub const EXIT_QUALIFICATION: u32 = 0x00006400;
    pub const IO_RCX: u32 = 0x00006402;
    pub const IO_RSI: u32 = 0x00006404;
    pub const IO_RDI: u32 = 0x00006406;
    pub const IO_RIP: u32 = 0x00006408;
    pub const GUEST_LINEAR_ADDRESS: u32 = 0x0000640A;
    
    // Natural-width guest state fields
    pub const GUEST_CR0: u32 = 0x00006800;
    pub const GUEST_CR3: u32 = 0x00006802;
    pub const GUEST_CR4: u32 = 0x00006804;
    pub const GUEST_ES_BASE: u32 = 0x00006806;
    pub const GUEST_CS_BASE: u32 = 0x00006808;
    pub const GUEST_SS_BASE: u32 = 0x0000680A;
    pub const GUEST_DS_BASE: u32 = 0x0000680C;
    pub const GUEST_FS_BASE: u32 = 0x0000680E;
    pub const GUEST_GS_BASE: u32 = 0x00006810;
    pub const GUEST_LDTR_BASE: u32 = 0x00006812;
    pub const GUEST_TR_BASE: u32 = 0x00006814;
    pub const GUEST_GDTR_BASE: u32 = 0x00006816;
    pub const GUEST_IDTR_BASE: u32 = 0x00006818;
    pub const GUEST_DR7: u32 = 0x0000681A;
    pub const GUEST_RSP: u32 = 0x0000681C;
    pub const GUEST_RIP: u32 = 0x0000681E;
    pub const GUEST_RFLAGS: u32 = 0x00006820;
    pub const GUEST_PENDING_DBG_EXCEPTIONS: u32 = 0x00006822;
    pub const GUEST_SYSENTER_ESP: u32 = 0x00006824;
    pub const GUEST_SYSENTER_EIP: u32 = 0x00006826;
    
    // Natural-width host state fields
    pub const HOST_CR0: u32 = 0x00006C00;
    pub const HOST_CR3: u32 = 0x00006C02;
    pub const HOST_CR4: u32 = 0x00006C04;
    pub const HOST_FS_BASE: u32 = 0x00006C06;
    pub const HOST_GS_BASE: u32 = 0x00006C08;
    pub const HOST_TR_BASE: u32 = 0x00006C0A;
    pub const HOST_GDTR_BASE: u32 = 0x00006C0C;
    pub const HOST_IDTR_BASE: u32 = 0x00006C0E;
    pub const HOST_IA32_SYSENTER_ESP: u32 = 0x00006C10;
    pub const HOST_IA32_SYSENTER_EIP: u32 = 0x00006C12;
    pub const HOST_RSP: u32 = 0x00006C14;
    pub const HOST_RIP: u32 = 0x00006C16;
}

// VM exit reasons
pub mod exit_reasons {
    pub const EXCEPTION_NMI: u32 = 0;
    pub const EXTERNAL_INTERRUPT: u32 = 1;
    pub const TRIPLE_FAULT: u32 = 2;
    pub const INIT: u32 = 3;
    pub const SIPI: u32 = 4;
    pub const IO_SMI: u32 = 5;
    pub const OTHER_SMI: u32 = 6;
    pub const PENDING_VIRT_INTR: u32 = 7;
    pub const PENDING_VIRT_NMI: u32 = 8;
    pub const TASK_SWITCH: u32 = 9;
    pub const CPUID: u32 = 10;
    pub const GETSEC: u32 = 11;
    pub const HLT: u32 = 12;
    pub const INVD: u32 = 13;
    pub const INVLPG: u32 = 14;
    pub const RDPMC: u32 = 15;
    pub const RDTSC: u32 = 16;
    pub const RSM: u32 = 17;
    pub const VMCALL: u32 = 18;
    pub const VMCLEAR: u32 = 19;
    pub const VMLAUNCH: u32 = 20;
    pub const VMPTRLD: u32 = 21;
    pub const VMPTRST: u32 = 22;
    pub const VMREAD: u32 = 23;
    pub const VMRESUME: u32 = 24;
    pub const VMWRITE: u32 = 25;
    pub const VMXOFF: u32 = 26;
    pub const VMXON: u32 = 27;
    pub const CR_ACCESS: u32 = 28;
    pub const DR_ACCESS: u32 = 29;
    pub const IO_INSTRUCTION: u32 = 30;
    pub const MSR_READ: u32 = 31;
    pub const MSR_WRITE: u32 = 32;
    pub const INVALID_GUEST_STATE: u32 = 33;
    pub const MSR_LOADING: u32 = 34;
    pub const MWAIT_INSTRUCTION: u32 = 36;
    pub const MONITOR_TRAP_FLAG: u32 = 37;
    pub const MONITOR_INSTRUCTION: u32 = 39;
    pub const PAUSE_INSTRUCTION: u32 = 40;
    pub const MCE_DURING_VMENTRY: u32 = 41;
    pub const TPR_BELOW_THRESHOLD: u32 = 43;
    pub const APIC_ACCESS: u32 = 44;
    pub const VIRTUALIZED_EOI: u32 = 45;
    pub const ACCESS_GDTR_OR_IDTR: u32 = 46;
    pub const ACCESS_LDTR_OR_TR: u32 = 47;
    pub const EPT_VIOLATION: u32 = 48;
    pub const EPT_MISCONFIG: u32 = 49;
    pub const INVEPT: u32 = 50;
    pub const RDTSCP: u32 = 51;
    pub const VMX_PREEMPTION_TIMER_EXPIRED: u32 = 52;
    pub const INVVPID: u32 = 53;
    pub const WBINVD: u32 = 54;
    pub const XSETBV: u32 = 55;
    pub const APIC_WRITE: u32 = 56;
    pub const RDRAND: u32 = 57;
    pub const INVPCID: u32 = 58;
    pub const VMFUNC: u32 = 59;
    pub const ENCLS: u32 = 60;
    pub const RDSEED: u32 = 61;
    pub const PML_FULL: u32 = 62;
    pub const XSAVES: u32 = 63;
    pub const XRSTORS: u32 = 64;
}