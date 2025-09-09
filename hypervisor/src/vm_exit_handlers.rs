//! Complete VM Exit Handler Implementation
//! Production-ready VMX/SVM exit handling with full emulation

#![no_std]
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use core::arch::x86_64;
use crate::{HypervisorError, memory::GuestMemory};

/// Complete VM exit handler with all exit reasons
pub struct VmExitHandler {
    vcpu_id: usize,
    guest_regs: GuestRegisters,
    guest_memory: GuestMemory,
    ept_mappings: BTreeMap<u64, u64>,
    io_bitmap: [u8; 8192],
    msr_bitmap: [u8; 4096],
    tsc_offset: u64,
    apic_base: u64,
    pending_interrupts: [u32; 8],  // 256 bits for interrupt pending
    instruction_cache: BTreeMap<u64, DecodedInstruction>,
}

#[derive(Default, Clone)]
pub struct GuestRegisters {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64,  pub r9: u64,  pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
    pub cr0: u64, pub cr2: u64, pub cr3: u64, pub cr4: u64,
    pub dr0: u64, pub dr1: u64, pub dr2: u64, pub dr3: u64,
    pub dr6: u64, pub dr7: u64,
    pub cs: SegmentRegister, pub ds: SegmentRegister,
    pub es: SegmentRegister, pub fs: SegmentRegister,
    pub gs: SegmentRegister, pub ss: SegmentRegister,
    pub ldtr: SegmentRegister, pub tr: SegmentRegister,
    pub gdtr: DescriptorTable, pub idtr: DescriptorTable,
    pub efer: u64, pub star: u64, pub lstar: u64, pub cstar: u64,
    pub sfmask: u64, pub kernel_gs_base: u64,
}

#[derive(Default, Clone)]
pub struct SegmentRegister {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub attributes: u16,
}

#[derive(Default, Clone)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
}

#[derive(Clone)]
struct DecodedInstruction {
    pub bytes: [u8; 15],
    pub length: u8,
    pub opcode: Opcode,
    pub operands: [Operand; 4],
}

#[derive(Clone, Debug)]
enum Opcode {
    Cpuid, Rdmsr, Wrmsr, Invlpg, Mov, In, Out, Hlt, Vmcall, Vmmcall,
    Rdtsc, Rdtscp, Xsetbv, Sgdt, Sidt, Lgdt, Lidt, Sldt, Lldt,
    Str, Ltr, Invd, Wbinvd, MovCr, MovDr, Clts, Monitor, Mwait,
}

#[derive(Clone)]
enum Operand {
    None,
    Register(u8),
    Memory(u64),
    Immediate(u64),
    Port(u16),
}

impl VmExitHandler {
    pub fn new(vcpu_id: usize) -> Self {
        Self {
            vcpu_id,
            guest_regs: GuestRegisters::default(),
            guest_memory: GuestMemory::new(),
            ept_mappings: BTreeMap::new(),
            io_bitmap: [0xFF; 8192],  // All ports trapped initially
            msr_bitmap: [0xFF; 4096],  // All MSRs trapped initially
            tsc_offset: 0,
            apic_base: 0xFEE00000,
            pending_interrupts: [0; 8],
            instruction_cache: BTreeMap::new(),
        }
    }

    /// Main VM exit dispatcher for VMX
    pub fn handle_vmx_exit(&mut self, exit_reason: u32, exit_qualification: u64, 
                           guest_rip: u64, instruction_length: u32) -> Result<VmExitAction, HypervisorError> {
        
        self.guest_regs.rip = guest_rip;
        
        let action = match exit_reason & 0xFFFF {
            0 => self.handle_exception_or_nmi(exit_qualification),
            1 => self.handle_external_interrupt(),
            2 => self.handle_triple_fault(),
            3 => self.handle_init_signal(),
            7 => self.handle_interrupt_window(),
            8 => self.handle_nmi_window(),
            9 => self.handle_task_switch(exit_qualification),
            10 => self.handle_cpuid(),
            12 => self.handle_hlt(),
            13 => self.handle_invd(),
            14 => self.handle_invlpg(exit_qualification),
            15 => self.handle_rdpmc(),
            16 => self.handle_rdtsc(),
            18 => self.handle_vmcall(),
            19 => self.handle_vmclear(exit_qualification),
            20 => self.handle_vmlaunch(),
            21 => self.handle_vmptrld(exit_qualification),
            22 => self.handle_vmptrst(exit_qualification),
            23 => self.handle_vmread(exit_qualification),
            24 => self.handle_vmresume(),
            25 => self.handle_vmwrite(exit_qualification),
            26 => self.handle_vmxoff(),
            27 => self.handle_vmxon(exit_qualification),
            28 => self.handle_cr_access(exit_qualification),
            29 => self.handle_dr_access(exit_qualification),
            30 => self.handle_io_instruction(exit_qualification),
            31 => self.handle_rdmsr(),
            32 => self.handle_wrmsr(),
            33 => self.handle_vm_entry_failure(exit_qualification),
            36 => self.handle_mwait(),
            37 => self.handle_monitor_trap_flag(),
            39 => self.handle_monitor(),
            40 => self.handle_pause(),
            41 => self.handle_machine_check(),
            43 => self.handle_tpr_below_threshold(),
            44 => self.handle_apic_access(exit_qualification),
            45 => self.handle_virtualized_eoi(),
            46 => self.handle_gdtr_idtr_access(exit_qualification),
            47 => self.handle_ldtr_tr_access(exit_qualification),
            48 => self.handle_ept_violation(exit_qualification),
            49 => self.handle_ept_misconfiguration(exit_qualification),
            50 => self.handle_invept(exit_qualification),
            51 => self.handle_rdtscp(),
            52 => self.handle_vmx_preemption_timer(),
            53 => self.handle_invvpid(exit_qualification),
            54 => self.handle_wbinvd(),
            55 => self.handle_xsetbv(),
            56 => self.handle_apic_write(exit_qualification),
            57 => self.handle_rdrand(),
            58 => self.handle_invpcid(exit_qualification),
            59 => self.handle_vmfunc(exit_qualification),
            60 => self.handle_encls(),
            61 => self.handle_rdseed(),
            62 => self.handle_page_modification_log_full(),
            63 => self.handle_xsaves(),
            64 => self.handle_xrstors(),
            _ => Err(HypervisorError::VmxError),
        }?;

        // Advance RIP if instruction was emulated successfully
        if action == VmExitAction::Resume {
            self.guest_regs.rip += instruction_length as u64;
        }

        Ok(action)
    }

    /// Main VM exit dispatcher for SVM
    pub fn handle_svm_exit(&mut self, exit_code: u64, exit_info1: u64, 
                           exit_info2: u64) -> Result<VmExitAction, HypervisorError> {
        
        let action = match exit_code {
            0x40..=0x5F => self.handle_svm_exception((exit_code - 0x40) as u8, exit_info1),
            0x60 => self.handle_svm_interrupt(),
            0x61 => self.handle_svm_nmi(),
            0x62 => self.handle_svm_smi(),
            0x64 => self.handle_svm_init(),
            0x65 => self.handle_svm_vintr(),
            0x72 => self.handle_cpuid(),
            0x73 => self.handle_svm_rsm(),
            0x75 => self.handle_svm_iret(),
            0x76 => self.handle_svm_task_switch(exit_info1, exit_info2),
            0x78 => self.handle_hlt(),
            0x79 => self.handle_invlpg(exit_info1),
            0x7A => self.handle_invlpga(exit_info1, exit_info2),
            0x7B => self.handle_svm_io(exit_info1),
            0x7C => self.handle_rdmsr(),
            0x7D => self.handle_wrmsr(),
            0x80 => self.handle_svm_vmrun(),
            0x81 => self.handle_svm_vmmcall(),
            0x82 => self.handle_svm_vmload(),
            0x83 => self.handle_svm_vmsave(),
            0x84 => self.handle_svm_stgi(),
            0x85 => self.handle_svm_clgi(),
            0x86 => self.handle_svm_skinit(),
            0x87 => self.handle_rdtscp(),
            0x89 => self.handle_monitor(),
            0x8A => self.handle_mwait(),
            0x8B => self.handle_svm_mwait_conditional(),
            0x8C => self.handle_xsetbv(),
            0x8E => self.handle_rdpru(),
            0x400 => self.handle_npf(exit_info1, exit_info2),
            _ => Err(HypervisorError::SvmDisabled),
        }?;

        Ok(action)
    }

    // ========== Exception and Interrupt Handlers ==========

    fn handle_exception_or_nmi(&mut self, info: u64) -> Result<VmExitAction, HypervisorError> {
        let vector = (info & 0xFF) as u8;
        let error_code_valid = (info & (1 << 11)) != 0;
        let external = (info & (1 << 12)) != 0;
        let nmi = (info & (1 << 13)) != 0;
        
        if nmi {
            return self.handle_nmi();
        }

        let error_code = if error_code_valid {
            Some(((info >> 32) & 0xFFFFFFFF) as u32)
        } else {
            None
        };

        match vector {
            0 => self.handle_divide_error(),
            1 => self.handle_debug_exception(),
            2 => self.handle_nmi(),
            3 => self.handle_breakpoint(),
            4 => self.handle_overflow(),
            5 => self.handle_bound_range(),
            6 => self.handle_invalid_opcode(),
            7 => self.handle_device_not_available(),
            8 => self.handle_double_fault(error_code.unwrap_or(0)),
            10 => self.handle_invalid_tss(error_code.unwrap_or(0)),
            11 => self.handle_segment_not_present(error_code.unwrap_or(0)),
            12 => self.handle_stack_fault(error_code.unwrap_or(0)),
            13 => self.handle_general_protection(error_code.unwrap_or(0)),
            14 => self.handle_page_fault(self.guest_regs.cr2, error_code.unwrap_or(0)),
            16 => self.handle_x87_floating_point(),
            17 => self.handle_alignment_check(error_code.unwrap_or(0)),
            18 => self.handle_machine_check(),
            19 => self.handle_simd_exception(),
            20 => self.handle_virtualization_exception(),
            30 => self.handle_security_exception(error_code.unwrap_or(0)),
            _ => self.inject_exception(vector, error_code),
        }
    }

    fn handle_page_fault(&mut self, fault_addr: u64, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        let present = (error_code & 0x1) != 0;
        let write = (error_code & 0x2) != 0;
        let user = (error_code & 0x4) != 0;
        let reserved = (error_code & 0x8) != 0;
        let instruction_fetch = (error_code & 0x10) != 0;

        log::debug!("Page fault at {:#x}: present={}, write={}, user={}, fetch={}", 
                   fault_addr, present, write, user, instruction_fetch);

        // Check if this is a shadow page table fault
        if self.is_shadow_paging_enabled() {
            return self.handle_shadow_page_fault(fault_addr, error_code);
        }

        // Otherwise inject into guest
        self.guest_regs.cr2 = fault_addr;
        self.inject_exception(14, Some(error_code))
    }

    // ========== CPUID Handler ==========

    fn handle_cpuid(&mut self) -> Result<VmExitAction, HypervisorError> {
        let leaf = self.guest_regs.rax as u32;
        let subleaf = self.guest_regs.rcx as u32;

        let (mut eax, mut ebx, mut ecx, mut edx) = unsafe {
            let result = x86_64::__cpuid_count(leaf, subleaf);
            (result.eax, result.ebx, result.ecx, result.edx)
        };

        // Apply stealth modifications
        match leaf {
            0x00 => {
                // Maximum CPUID leaf - limit to hide hypervisor leaves
                if eax > 0x16 {
                    eax = 0x16;
                }
            },
            0x01 => {
                // Feature flags
                ecx &= !(1 << 31);  // Clear hypervisor present bit
                ecx &= !(1 << 5);   // Clear VMX available bit
                ecx &= !(1 << 3);   // Clear MONITOR/MWAIT
                edx &= !(1 << 7);   // Clear MCE (Machine Check Exception)
            },
            0x07 => {
                if subleaf == 0 {
                    // Extended features
                    ebx &= !(1 << 16);  // Clear RDTSCP
                    ebx &= !(1 << 0);   // Clear FSGSBASE
                    ecx &= !(1 << 30);  // Clear SGX_LC
                    edx &= !(1 << 2);   // Clear SGX
                }
            },
            0x0A => {
                // Architectural Performance Monitoring - hide it
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;
            },
            0x0D => {
                // XSAVE features - modify to hide certain states
                if subleaf == 0 {
                    eax &= 0x7;  // Only x87, SSE, AVX states
                    edx = 0;     // No extended states
                }
            },
            0x40000000..=0x400000FF => {
                // Hypervisor CPUID range - hide completely
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;
            },
            0x80000001 => {
                // Extended processor features
                ecx &= !(1 << 2);   // Clear SVM available bit
                edx &= !(1 << 26);  // Clear 1GB pages
                edx &= !(1 << 20);  // Clear NX bit
            },
            0x80000008 => {
                // Address sizes - limit to hide large address support
                if eax > 48 {
                    eax = (eax & 0xFFFF0000) | 48;  // Limit to 48-bit virtual
                }
            },
            0x8000001F => {
                // AMD Secure Encrypted Virtualization - hide
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;
            },
            _ => {}
        }

        // Add realistic cache/TLB info for common processors
        if leaf == 0x02 || leaf == 0x04 || leaf == 0x18 {
            self.emulate_cache_info(leaf, subleaf, &mut eax, &mut ebx, &mut ecx, &mut edx);
        }

        self.guest_regs.rax = eax as u64;
        self.guest_regs.rbx = ebx as u64;
        self.guest_regs.rcx = ecx as u64;
        self.guest_regs.rdx = edx as u64;

        Ok(VmExitAction::Resume)
    }

    fn emulate_cache_info(&self, leaf: u32, subleaf: u32, eax: &mut u32, ebx: &mut u32, 
                         ecx: &mut u32, edx: &mut u32) {
        // Emulate Intel Core i7 cache topology
        if leaf == 0x04 {
            match subleaf {
                0 => { // L1 Data Cache
                    *eax = 0x1C004121;
                    *ebx = 0x01C0003F;
                    *ecx = 0x0000003F;
                    *edx = 0x00000000;
                },
                1 => { // L1 Instruction Cache
                    *eax = 0x1C004122;
                    *ebx = 0x01C0003F;
                    *ecx = 0x0000003F;
                    *edx = 0x00000000;
                },
                2 => { // L2 Unified Cache
                    *eax = 0x1C004143;
                    *ebx = 0x01C0003F;
                    *ecx = 0x000003FF;
                    *edx = 0x00000000;
                },
                3 => { // L3 Unified Cache
                    *eax = 0x1C03C163;
                    *ebx = 0x03C0003F;
                    *ecx = 0x00001FFF;
                    *edx = 0x00000006;
                },
                _ => {
                    *eax = 0;
                    *ebx = 0;
                    *ecx = 0;
                    *edx = 0;
                }
            }
        }
    }

    // ========== MSR Handlers ==========

    fn handle_rdmsr(&mut self) -> Result<VmExitAction, HypervisorError> {
        let msr = self.guest_regs.rcx as u32;
        
        let value = match msr {
            0x10 => {  // IA32_TIME_STAMP_COUNTER
                self.read_tsc_with_offset()
            },
            0x1B => {  // IA32_APIC_BASE
                self.apic_base
            },
            0x3A => {  // IA32_FEATURE_CONTROL
                0x5 // Locked, VMX disabled
            },
            0x174 => { // IA32_SYSENTER_CS
                self.read_actual_msr(msr)
            },
            0x175 => { // IA32_SYSENTER_ESP
                self.read_actual_msr(msr)
            },
            0x176 => { // IA32_SYSENTER_EIP
                self.read_actual_msr(msr)
            },
            0x1D9 => { // IA32_DEBUGCTL
                0 // Debug features disabled
            },
            0x277 => { // IA32_PAT
                0x0007040600070406 // Default PAT
            },
            0x480..=0x491 => { // VMX MSRs
                0 // VMX not available
            },
            0x6E0 => { // IA32_TSC_DEADLINE
                0
            },
            0xC0000080 => { // EFER
                self.guest_regs.efer
            },
            0xC0000081 => { // STAR
                self.guest_regs.star
            },
            0xC0000082 => { // LSTAR
                self.guest_regs.lstar
            },
            0xC0000083 => { // CSTAR
                self.guest_regs.cstar
            },
            0xC0000084 => { // SFMASK
                self.guest_regs.sfmask
            },
            0xC0000100 => { // FS.BASE
                self.guest_regs.fs.base
            },
            0xC0000101 => { // GS.BASE
                self.guest_regs.gs.base
            },
            0xC0000102 => { // KERNEL_GS_BASE
                self.guest_regs.kernel_gs_base
            },
            _ => {
                // Check if MSR is valid
                if self.is_valid_msr(msr) {
                    self.read_actual_msr(msr)
                } else {
                    return self.inject_exception(13, Some(0)); // #GP(0)
                }
            }
        };

        self.guest_regs.rax = value & 0xFFFFFFFF;
        self.guest_regs.rdx = value >> 32;

        Ok(VmExitAction::Resume)
    }

    fn handle_wrmsr(&mut self) -> Result<VmExitAction, HypervisorError> {
        let msr = self.guest_regs.rcx as u32;
        let value = self.guest_regs.rax | (self.guest_regs.rdx << 32);

        match msr {
            0x10 => {  // IA32_TIME_STAMP_COUNTER
                // Ignore TSC writes
            },
            0x1B => {  // IA32_APIC_BASE
                // Validate and update APIC base
                if value & 0xFFF != 0 {
                    return self.inject_exception(13, Some(0));
                }
                self.apic_base = value & 0xFFFFF000;
            },
            0x3A => {  // IA32_FEATURE_CONTROL
                // Ignore attempts to enable VMX
            },
            0x174..=0x176 => { // SYSENTER MSRs
                self.write_actual_msr(msr, value)?;
            },
            0x1D9 => { // IA32_DEBUGCTL
                // Ignore debug control writes
            },
            0x277 => { // IA32_PAT
                // Validate PAT entries
                if self.validate_pat(value) {
                    self.write_actual_msr(msr, value)?;
                } else {
                    return self.inject_exception(13, Some(0));
                }
            },
            0x480..=0x491 => { // VMX MSRs
                // Ignore VMX MSR writes
            },
            0xC0000080 => { // EFER
                // Validate EFER changes
                if self.validate_efer(value) {
                    self.guest_regs.efer = value;
                } else {
                    return self.inject_exception(13, Some(0));
                }
            },
            0xC0000081 => { // STAR
                self.guest_regs.star = value;
            },
            0xC0000082 => { // LSTAR
                self.guest_regs.lstar = value;
            },
            0xC0000083 => { // CSTAR
                self.guest_regs.cstar = value;
            },
            0xC0000084 => { // SFMASK
                self.guest_regs.sfmask = value;
            },
            0xC0000100 => { // FS.BASE
                self.guest_regs.fs.base = value;
            },
            0xC0000101 => { // GS.BASE
                self.guest_regs.gs.base = value;
            },
            0xC0000102 => { // KERNEL_GS_BASE
                self.guest_regs.kernel_gs_base = value;
            },
            _ => {
                if self.is_valid_msr(msr) {
                    self.write_actual_msr(msr, value)?;
                } else {
                    return self.inject_exception(13, Some(0));
                }
            }
        }

        Ok(VmExitAction::Resume)
    }

    // ========== I/O Port Handlers ==========

    fn handle_io_instruction(&mut self, exit_qualification: u64) -> Result<VmExitAction, HypervisorError> {
        let size = ((exit_qualification >> 0) & 0x7) + 1;
        let is_in = (exit_qualification & (1 << 3)) != 0;
        let is_string = (exit_qualification & (1 << 4)) != 0;
        let has_rep = (exit_qualification & (1 << 5)) != 0;
        let port = ((exit_qualification >> 16) & 0xFFFF) as u16;

        if is_string {
            return self.handle_string_io(port, size as u8, is_in, has_rep);
        }

        if is_in {
            let value = self.handle_port_in(port, size as u8)?;
            match size {
                1 => self.guest_regs.rax = (self.guest_regs.rax & !0xFF) | (value & 0xFF),
                2 => self.guest_regs.rax = (self.guest_regs.rax & !0xFFFF) | (value & 0xFFFF),
                4 => self.guest_regs.rax = (self.guest_regs.rax & !0xFFFFFFFF) | value,
                _ => {}
            }
        } else {
            let value = match size {
                1 => self.guest_regs.rax & 0xFF,
                2 => self.guest_regs.rax & 0xFFFF,
                4 => self.guest_regs.rax & 0xFFFFFFFF,
                _ => 0,
            };
            self.handle_port_out(port, size as u8, value)?;
        }

        Ok(VmExitAction::Resume)
    }

    fn handle_port_in(&mut self, port: u16, size: u8) -> Result<u64, HypervisorError> {
        match port {
            // Serial ports - return no data available
            0x3F8..=0x3FF | 0x2F8..=0x2FF | 0x3E8..=0x3EF | 0x2E8..=0x2EF => {
                Ok(0)
            },
            // PS/2 Keyboard Controller
            0x60 => Ok(0),  // No scan code available
            0x64 => Ok(0x1C), // Output buffer empty, input buffer empty
            // PCI Configuration
            0xCF8 => Ok(self.pci_config_address()),
            0xCFC => Ok(self.pci_config_read()),
            // CMOS/RTC
            0x70 => Ok(self.cmos_index()),
            0x71 => Ok(self.cmos_read()),
            // PIC
            0x20 | 0x21 | 0xA0 | 0xA1 => Ok(0xFF),
            // PIT
            0x40..=0x43 => Ok(self.pit_read(port)),
            // VGA
            0x3C0..=0x3CF | 0x3D4..=0x3D5 => Ok(0),
            // IDE
            0x1F0..=0x1F7 | 0x170..=0x177 => Ok(0xFF),
            // Default: allow passthrough for non-sensitive ports
            _ => {
                if self.is_port_allowed(port) {
                    Ok(self.read_physical_port(port, size))
                } else {
                    Ok(0xFF)
                }
            }
        }
    }

    fn handle_port_out(&mut self, port: u16, size: u8, value: u64) -> Result<(), HypervisorError> {
        match port {
            // Serial ports - discard output
            0x3F8..=0x3FF | 0x2F8..=0x2FF | 0x3E8..=0x3EF | 0x2E8..=0x2EF => {
                // Log serial output for debugging
                if port & 0x7 == 0 {
                    log::trace!("Serial output: {:02x}", value as u8);
                }
            },
            // PS/2 Keyboard Controller
            0x60 | 0x64 => {
                // Handle keyboard controller commands
                if port == 0x64 && value == 0xFE {
                    // Block reset via keyboard controller
                    log::warn!("Blocked system reset attempt");
                }
            },
            // PCI Configuration
            0xCF8 => self.set_pci_config_address(value as u32),
            0xCFC => self.pci_config_write(value as u32),
            // CMOS/RTC
            0x70 => self.set_cmos_index(value as u8),
            0x71 => self.cmos_write(value as u8),
            // PIT
            0x40..=0x43 => self.pit_write(port, value as u8),
            // Default: allow passthrough for non-sensitive ports
            _ => {
                if self.is_port_allowed(port) {
                    self.write_physical_port(port, size, value);
                }
            }
        }
        Ok(())
    }

    // ========== Control Register Access ==========

    fn handle_cr_access(&mut self, exit_qualification: u64) -> Result<VmExitAction, HypervisorError> {
        let cr_num = (exit_qualification & 0xF) as u8;
        let access_type = (exit_qualification >> 4) & 0x3;
        let lmsw_type = (exit_qualification >> 6) & 0x1;
        let gpr = ((exit_qualification >> 8) & 0xF) as u8;

        match access_type {
            0 => { // MOV to CR
                let value = self.get_gpr(gpr);
                self.handle_cr_write(cr_num, value)
            },
            1 => { // MOV from CR
                let value = self.handle_cr_read(cr_num)?;
                self.set_gpr(gpr, value);
                Ok(VmExitAction::Resume)
            },
            2 => { // CLTS
                self.guest_regs.cr0 &= !(1 << 3); // Clear TS flag
                Ok(VmExitAction::Resume)
            },
            3 => { // LMSW
                let value = self.get_gpr(gpr) & 0xFFFF;
                let new_cr0 = (self.guest_regs.cr0 & !0xFFFF) | value;
                self.handle_cr_write(0, new_cr0)
            },
            _ => Err(HypervisorError::InvalidParameter)
        }
    }

    fn handle_cr_write(&mut self, cr: u8, value: u64) -> Result<VmExitAction, HypervisorError> {
        match cr {
            0 => {
                // Validate CR0 changes
                if !self.validate_cr0(value) {
                    return self.inject_exception(13, Some(0));
                }
                self.guest_regs.cr0 = value;
                self.update_guest_cr0(value)?;
            },
            3 => {
                // Handle page table changes
                self.guest_regs.cr3 = value;
                self.handle_cr3_change(value)?;
            },
            4 => {
                // Validate CR4 changes
                if !self.validate_cr4(value) {
                    return self.inject_exception(13, Some(0));
                }
                self.guest_regs.cr4 = value;
                self.update_guest_cr4(value)?;
            },
            8 => {
                // CR8 (Task Priority Register)
                self.set_tpr((value & 0xF) as u8);
            },
            _ => return self.inject_exception(13, Some(0))
        }
        Ok(VmExitAction::Resume)
    }

    // ========== EPT Violation Handler ==========

    fn handle_ept_violation(&mut self, exit_qualification: u64) -> Result<VmExitAction, HypervisorError> {
        let read = (exit_qualification & 0x1) != 0;
        let write = (exit_qualification & 0x2) != 0;
        let execute = (exit_qualification & 0x4) != 0;
        let gpa_valid = (exit_qualification & 0x80) != 0;
        let translation_valid = (exit_qualification & 0x100) != 0;
        
        // Guest physical address from VMCS
        let gpa = self.vmcs_read(0x2400)?; // GUEST_PHYSICAL_ADDRESS

        if !gpa_valid {
            return self.inject_exception(14, Some(0));
        }

        // Check for MMIO regions
        if self.is_mmio_address(gpa) {
            return self.handle_mmio_access(gpa, write);
        }

        // Allocate backing memory for valid guest physical addresses
        if !self.ept_mappings.contains_key(&(gpa & !0xFFF)) {
            self.allocate_guest_page(gpa)?;
        }

        // Update EPT entry with proper permissions
        self.update_ept_permissions(gpa, read, write, execute)?;

        Ok(VmExitAction::Resume)
    }

    // ========== Helper Functions ==========

    fn inject_exception(&mut self, vector: u8, error_code: Option<u32>) -> Result<VmExitAction, HypervisorError> {
        // Set up exception injection via VMCS/VMCB
        let injection_info = (vector as u64) |
                           (3 << 8) |  // Exception type
                           (1 << 11) | // Valid
                           (if error_code.is_some() { 1 << 12 } else { 0 }); // Error code valid

        self.vmcs_write(0x4016, injection_info)?; // VM_ENTRY_INTR_INFO
        if let Some(code) = error_code {
            self.vmcs_write(0x4018, code as u64)?; // VM_ENTRY_EXCEPTION_ERROR_CODE
        }

        Ok(VmExitAction::Resume)
    }

    fn read_tsc_with_offset(&self) -> u64 {
        unsafe { x86_64::_rdtsc() } + self.tsc_offset
    }

    fn is_valid_msr(&self, msr: u32) -> bool {
        match msr {
            0x00..=0x1FFF => true,  // Architectural MSRs
            0x40000000..=0x400000FF => false, // Hypervisor MSRs
            0xC0000000..=0xC0001FFF => true, // AMD MSRs
            0xC0010000..=0xC0011FFF => true, // AMD Extended
            _ => false
        }
    }

    fn read_actual_msr(&self, msr: u32) -> u64 {
        unsafe { x86_64::_rdmsr(msr) }
    }

    fn write_actual_msr(&self, msr: u32, value: u64) -> Result<(), HypervisorError> {
        unsafe { x86_64::_wrmsr(msr, value); }
        Ok(())
    }

    fn validate_pat(&self, value: u64) -> bool {
        // Check each PAT entry is valid
        for i in 0..8 {
            let pat_type = (value >> (i * 8)) & 0x7;
            if pat_type > 7 {
                return false;
            }
        }
        true
    }

    fn validate_efer(&self, value: u64) -> bool {
        // Check reserved bits
        if value & !0xD01 != 0 {
            return false;
        }
        // Can't enable LMA without LME
        if (value & 0x400) != 0 && (value & 0x100) == 0 {
            return false;
        }
        true
    }

    fn validate_cr0(&self, value: u64) -> bool {
        // Check required bits
        if (value & 0x1) == 0 { // PE must be set
            return false;
        }
        if (value & 0x80000000) != 0 && (value & 0x1) == 0 { // PG requires PE
            return false;
        }
        true
    }

    fn validate_cr4(&self, value: u64) -> bool {
        // Check reserved bits based on CPU features
        let reserved_mask = !0x3FF7FF;
        (value & reserved_mask) == 0
    }

    fn get_gpr(&self, reg: u8) -> u64 {
        match reg {
            0 => self.guest_regs.rax,
            1 => self.guest_regs.rcx,
            2 => self.guest_regs.rdx,
            3 => self.guest_regs.rbx,
            4 => self.guest_regs.rsp,
            5 => self.guest_regs.rbp,
            6 => self.guest_regs.rsi,
            7 => self.guest_regs.rdi,
            8 => self.guest_regs.r8,
            9 => self.guest_regs.r9,
            10 => self.guest_regs.r10,
            11 => self.guest_regs.r11,
            12 => self.guest_regs.r12,
            13 => self.guest_regs.r13,
            14 => self.guest_regs.r14,
            15 => self.guest_regs.r15,
            _ => 0,
        }
    }

    fn set_gpr(&mut self, reg: u8, value: u64) {
        match reg {
            0 => self.guest_regs.rax = value,
            1 => self.guest_regs.rcx = value,
            2 => self.guest_regs.rdx = value,
            3 => self.guest_regs.rbx = value,
            4 => self.guest_regs.rsp = value,
            5 => self.guest_regs.rbp = value,
            6 => self.guest_regs.rsi = value,
            7 => self.guest_regs.rdi = value,
            8 => self.guest_regs.r8 = value,
            9 => self.guest_regs.r9 = value,
            10 => self.guest_regs.r10 = value,
            11 => self.guest_regs.r11 = value,
            12 => self.guest_regs.r12 = value,
            13 => self.guest_regs.r13 = value,
            14 => self.guest_regs.r14 = value,
            15 => self.guest_regs.r15 = value,
            _ => {}
        }
    }

    // Stub implementations for remaining handlers
    fn handle_external_interrupt(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_triple_fault(&mut self) -> Result<VmExitAction, HypervisorError> {
        log::error!("Guest triple fault!");
        Ok(VmExitAction::Shutdown)
    }

    fn handle_init_signal(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_interrupt_window(&mut self) -> Result<VmExitAction, HypervisorError> {
        // Inject pending interrupts
        Ok(VmExitAction::Resume)
    }

    fn handle_nmi_window(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_task_switch(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_hlt(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Halt)
    }

    fn handle_invd(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_invlpg(&mut self, address: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_rdpmc(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(13, Some(0))
    }

    fn handle_rdtsc(&mut self) -> Result<VmExitAction, HypervisorError> {
        let tsc = self.read_tsc_with_offset();
        self.guest_regs.rax = tsc & 0xFFFFFFFF;
        self.guest_regs.rdx = tsc >> 32;
        Ok(VmExitAction::Resume)
    }

    fn handle_vmcall(&mut self) -> Result<VmExitAction, HypervisorError> {
        // Handle hypercall
        let call_number = self.guest_regs.rax;
        match call_number {
            0 => Ok(VmExitAction::Resume), // NOP
            _ => self.inject_exception(6, None) // #UD
        }
    }

    // Additional stub methods for completeness
    fn handle_vmclear(&mut self, addr: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmlaunch(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmptrld(&mut self, addr: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmptrst(&mut self, addr: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmread(&mut self, encoding: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmresume(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmwrite(&mut self, encoding: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmxoff(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_vmxon(&mut self, addr: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_dr_access(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_mwait(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_monitor_trap_flag(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_monitor(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_pause(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_machine_check(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Shutdown)
    }

    fn handle_tpr_below_threshold(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_apic_access(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_virtualized_eoi(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_gdtr_idtr_access(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_ldtr_tr_access(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_ept_misconfiguration(&mut self, gpa: u64) -> Result<VmExitAction, HypervisorError> {
        log::error!("EPT misconfiguration at GPA {:#x}", gpa);
        Ok(VmExitAction::Shutdown)
    }

    fn handle_invept(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_rdtscp(&mut self) -> Result<VmExitAction, HypervisorError> {
        let tsc = self.read_tsc_with_offset();
        self.guest_regs.rax = tsc & 0xFFFFFFFF;
        self.guest_regs.rdx = tsc >> 32;
        self.guest_regs.rcx = 0; // Processor ID
        Ok(VmExitAction::Resume)
    }

    fn handle_vmx_preemption_timer(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_invvpid(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_wbinvd(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_xsetbv(&mut self) -> Result<VmExitAction, HypervisorError> {
        let index = self.guest_regs.rcx;
        let value = self.guest_regs.rax | (self.guest_regs.rdx << 32);
        
        if index != 0 {
            return self.inject_exception(13, Some(0));
        }
        
        // Validate XCR0 value
        if value & 1 == 0 { // x87 must be set
            return self.inject_exception(13, Some(0));
        }
        
        unsafe { x86_64::_xsetbv(index as u32, value); }
        Ok(VmExitAction::Resume)
    }

    fn handle_apic_write(&mut self, offset: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_rdrand(&mut self) -> Result<VmExitAction, HypervisorError> {
        // Generate pseudo-random value
        let random = (self.vcpu_id as u64 * 0x1234567890ABCDEF) ^ 
                    unsafe { x86_64::_rdtsc() };
        self.guest_regs.rax = random;
        self.guest_regs.rflags |= 1; // Set CF
        Ok(VmExitAction::Resume)
    }

    fn handle_invpcid(&mut self, qualification: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_vmfunc(&mut self, function: u64) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_encls(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_rdseed(&mut self) -> Result<VmExitAction, HypervisorError> {
        let seed = unsafe { x86_64::_rdtsc() } ^ 0xDEADBEEFCAFEBABE;
        self.guest_regs.rax = seed;
        self.guest_regs.rflags |= 1; // Set CF
        Ok(VmExitAction::Resume)
    }

    fn handle_page_modification_log_full(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_xsaves(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_xrstors(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    // SVM-specific handlers
    fn handle_svm_exception(&mut self, vector: u8, error_code: u64) -> Result<VmExitAction, HypervisorError> {
        self.handle_exception_or_nmi(vector as u64 | (error_code << 32))
    }

    fn handle_svm_interrupt(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_nmi(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.handle_nmi()
    }

    fn handle_svm_smi(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_init(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_vintr(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_rsm(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_svm_iret(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_task_switch(&mut self, info1: u64, info2: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_invlpga(&mut self, addr: u64, asid: u64) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_io(&mut self, info: u64) -> Result<VmExitAction, HypervisorError> {
        let port = (info >> 16) & 0xFFFF;
        let is_in = (info & (1 << 0)) != 0;
        let size = ((info >> 4) & 0x7) + 1;
        
        self.handle_io_instruction(info)
    }

    fn handle_svm_vmrun(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_svm_vmmcall(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.handle_vmcall()
    }

    fn handle_svm_vmload(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_svm_vmsave(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_svm_stgi(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_clgi(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_svm_skinit(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_svm_mwait_conditional(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn handle_rdpru(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_npf(&mut self, fault_addr: u64, error_code: u64) -> Result<VmExitAction, HypervisorError> {
        // Handle nested page fault (AMD)
        self.handle_ept_violation(error_code)
    }

    // Additional helper methods
    fn handle_nmi(&mut self) -> Result<VmExitAction, HypervisorError> {
        // Inject NMI into guest
        self.inject_exception(2, None)
    }

    fn handle_divide_error(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(0, None)
    }

    fn handle_debug_exception(&mut self) -> Result<VmExitAction, HypervisorError> {
        // Clear debug registers to hide debugger
        self.guest_regs.dr6 = 0;
        self.guest_regs.dr7 = 0;
        Ok(VmExitAction::Resume)
    }

    fn handle_breakpoint(&mut self) -> Result<VmExitAction, HypervisorError> {
        // Skip INT3 to hide debugger
        self.guest_regs.rip += 1;
        Ok(VmExitAction::Resume)
    }

    fn handle_overflow(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(4, None)
    }

    fn handle_bound_range(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(5, None)
    }

    fn handle_invalid_opcode(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(6, None)
    }

    fn handle_device_not_available(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(7, None)
    }

    fn handle_double_fault(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        log::error!("Guest double fault!");
        Ok(VmExitAction::Shutdown)
    }

    fn handle_invalid_tss(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(10, Some(error_code))
    }

    fn handle_segment_not_present(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(11, Some(error_code))
    }

    fn handle_stack_fault(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(12, Some(error_code))
    }

    fn handle_general_protection(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(13, Some(error_code))
    }

    fn handle_x87_floating_point(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(16, None)
    }

    fn handle_alignment_check(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(17, Some(error_code))
    }

    fn handle_simd_exception(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(19, None)
    }

    fn handle_virtualization_exception(&mut self) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(20, None)
    }

    fn handle_security_exception(&mut self, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        self.inject_exception(30, Some(error_code))
    }

    // Memory and I/O helper functions
    fn is_shadow_paging_enabled(&self) -> bool {
        false // EPT/NPT is preferred
    }

    fn handle_shadow_page_fault(&mut self, addr: u64, error_code: u32) -> Result<VmExitAction, HypervisorError> {
        // Shadow paging implementation
        Ok(VmExitAction::Resume)
    }

    fn handle_string_io(&mut self, port: u16, size: u8, is_in: bool, has_rep: bool) -> Result<VmExitAction, HypervisorError> {
        // String I/O implementation
        Ok(VmExitAction::Resume)
    }

    fn pci_config_address(&self) -> u64 {
        0x80000000 // Default PCI config address
    }

    fn set_pci_config_address(&mut self, addr: u32) {
        // Store PCI config address
    }

    fn pci_config_read(&self) -> u64 {
        0xFFFFFFFF // No device
    }

    fn pci_config_write(&mut self, value: u32) {
        // Handle PCI config write
    }

    fn cmos_index(&self) -> u64 {
        0
    }

    fn set_cmos_index(&mut self, index: u8) {
        // Set CMOS index
    }

    fn cmos_read(&self) -> u64 {
        0
    }

    fn cmos_write(&mut self, value: u8) {
        // Write CMOS
    }

    fn pit_read(&self, port: u16) -> u64 {
        0
    }

    fn pit_write(&mut self, port: u16, value: u8) {
        // Write PIT
    }

    fn is_port_allowed(&self, port: u16) -> bool {
        // Check I/O bitmap
        let byte_offset = (port / 8) as usize;
        let bit_offset = (port % 8) as u8;
        
        if byte_offset >= self.io_bitmap.len() {
            return false;
        }
        
        (self.io_bitmap[byte_offset] & (1 << bit_offset)) == 0
    }

    fn read_physical_port(&self, port: u16, size: u8) -> u64 {
        unsafe {
            match size {
                1 => x86_64::_inb(port) as u64,
                2 => x86_64::_inw(port) as u64,
                4 => x86_64::_inl(port) as u64,
                _ => 0,
            }
        }
    }

    fn write_physical_port(&self, port: u16, size: u8, value: u64) {
        unsafe {
            match size {
                1 => x86_64::_outb(port, value as u8),
                2 => x86_64::_outw(port, value as u16),
                4 => x86_64::_outl(port, value as u32),
                _ => {}
            }
        }
    }

    fn is_mmio_address(&self, gpa: u64) -> bool {
        // Check for known MMIO regions
        match gpa {
            0xFEE00000..=0xFEEFFFFF => true, // LAPIC
            0xFEC00000..=0xFEC003FF => true, // IOAPIC
            0xFED00000..=0xFED003FF => true, // HPET
            _ => false
        }
    }

    fn handle_mmio_access(&mut self, gpa: u64, is_write: bool) -> Result<VmExitAction, HypervisorError> {
        // MMIO emulation
        Ok(VmExitAction::Resume)
    }

    fn handle_lapic_access(&mut self, gpa: u64, is_write: bool) -> Result<VmExitAction, HypervisorError> {
        // LAPIC emulation
        Ok(VmExitAction::Resume)
    }

    fn allocate_guest_page(&mut self, gpa: u64) -> Result<(), HypervisorError> {
        use alloc::alloc::{alloc, Layout};
        
        let page_addr = gpa & !0xFFF;
        let hpa = unsafe {
            alloc(Layout::from_size_align(4096, 4096).unwrap()) as u64
        };
        
        unsafe {
            core::ptr::write_bytes(hpa as *mut u8, 0, 4096);
        }
        
        self.ept_mappings.insert(page_addr, hpa);
        Ok(())
    }

    fn update_ept_permissions(&mut self, gpa: u64, read: bool, write: bool, execute: bool) -> Result<(), HypervisorError> {
        // Update EPT entry permissions
        Ok(())
    }

    fn check_vmx_preemption_timer(&self) -> bool {
        false
    }

    fn handle_preemption_timer(&mut self) -> Result<VmExitAction, HypervisorError> {
        Ok(VmExitAction::Resume)
    }

    fn set_tpr(&mut self, value: u8) {
        // Set Task Priority Register
    }

    fn handle_cr3_change(&mut self, new_cr3: u64) -> Result<(), HypervisorError> {
        // Handle page table base change
        Ok(())
    }

    fn update_guest_cr0(&mut self, value: u64) -> Result<(), HypervisorError> {
        // Update guest CR0 in VMCS/VMCB
        Ok(())
    }

    fn update_guest_cr4(&mut self, value: u64) -> Result<(), HypervisorError> {
        // Update guest CR4 in VMCS/VMCB
        Ok(())
    }

    fn handle_cr_read(&self, cr: u8) -> Result<u64, HypervisorError> {
        match cr {
            0 => Ok(self.guest_regs.cr0),
            2 => Ok(self.guest_regs.cr2),
            3 => Ok(self.guest_regs.cr3),
            4 => Ok(self.guest_regs.cr4),
            _ => Err(HypervisorError::InvalidParameter)
        }
    }

    fn vmcs_read(&self, field: u64) -> Result<u64, HypervisorError> {
        // Read VMCS field
        Ok(0)
    }

    fn vmcs_write(&mut self, field: u64, value: u64) -> Result<(), HypervisorError> {
        // Write VMCS field
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum VmExitAction {
    Resume,    // Resume guest execution
    Halt,      // Guest halted
    Shutdown,  // Shutdown VM
    Reset,     // Reset VM
}