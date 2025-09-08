//! Intel VT-x (VMX) implementation

use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::registers::rflags::RFlags;
use x86_64::PhysAddr;
use x86_64::VirtAddr;
use crate::HypervisorError;
use core::mem;

// VMX MSRs
const IA32_FEATURE_CONTROL: u32 = 0x3A;
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;

// VMCS fields
pub const VMCS_GUEST_CR0: u32 = 0x6800;
pub const VMCS_GUEST_CR3: u32 = 0x6802;
pub const VMCS_GUEST_CR4: u32 = 0x6804;
pub const VMCS_GUEST_RSP: u32 = 0x681C;
pub const VMCS_GUEST_RIP: u32 = 0x681E;
pub const VMCS_GUEST_RFLAGS: u32 = 0x6820;

/// VMX region structure
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

/// VMCS (Virtual Machine Control Structure)
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
}

/// Initialize VMX
pub fn init() -> Result<(), HypervisorError> {
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
        
        // Adjust CR0 and CR4 according to VMX requirements
        adjust_control_registers()?;
        
        // Allocate VMXON region
        let vmxon_region = Box::new(VmxRegion::new());
        let vmxon_ptr = Box::into_raw(vmxon_region) as u64;
        
        // Execute VMXON
        let result = vmxon(vmxon_ptr);
        if result != 0 {
            return Err(HypervisorError::VmxInitFailed);
        }
        
        log::info!("VMX initialized successfully");
        Ok(())
    }
}

/// Check if VMX is supported
fn is_vmx_supported() -> bool {
    use raw_cpuid::CpuId;
    
    let cpuid = CpuId::new();
    if let Some(features) = cpuid.get_feature_info() {
        features.has_vmx()
    } else {
        false
    }
}

/// Enable VMX in IA32_FEATURE_CONTROL MSR
unsafe fn enable_vmx_in_msr() -> Result<(), HypervisorError> {
    let mut msr = Msr::new(IA32_FEATURE_CONTROL);
    let value = msr.read();
    
    // Check if locked
    if value & 1 != 0 {
        // Already locked, check if VMX is enabled
        if value & 0x4 == 0 {
            return Err(HypervisorError::VmxInitFailed);
        }
    } else {
        // Not locked, enable VMX and lock
        msr.write(value | 0x5);
    }
    
    Ok(())
}

/// Adjust CR0 and CR4 according to VMX requirements
unsafe fn adjust_control_registers() -> Result<(), HypervisorError> {
    // Read fixed CR0 bits
    let cr0_fixed0 = Msr::new(IA32_VMX_CR0_FIXED0).read();
    let cr0_fixed1 = Msr::new(IA32_VMX_CR0_FIXED1).read();
    
    // Adjust CR0
    let mut cr0 = Cr0::read();
    let cr0_bits = cr0.bits();
    let adjusted_cr0 = (cr0_bits | cr0_fixed0) & cr0_fixed1;
    Cr0::write_raw(adjusted_cr0);
    
    // Read fixed CR4 bits
    let cr4_fixed0 = Msr::new(IA32_VMX_CR4_FIXED0).read();
    let cr4_fixed1 = Msr::new(IA32_VMX_CR4_FIXED1).read();
    
    // Adjust CR4
    let mut cr4 = Cr4::read();
    let cr4_bits = cr4.bits();
    let adjusted_cr4 = (cr4_bits | cr4_fixed0) & cr4_fixed1;
    Cr4::write_raw(adjusted_cr4);
    
    Ok(())
}

/// Execute VMXON instruction
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

/// Execute VMXOFF instruction
pub unsafe fn vmxoff() {
    asm!("vmxoff");
}

/// VM entry
pub unsafe fn vmlaunch() -> Result<(), HypervisorError> {
    let result: u64;
    
    asm!(
        "vmlaunch",
        "pushf",
        "pop {}",
        out(reg) result,
    );
    
    if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
        return Err(HypervisorError::VmcsError);
    }
    
    Ok(())
}

/// VM resume
pub unsafe fn vmresume() -> Result<(), HypervisorError> {
    let result: u64;
    
    asm!(
        "vmresume",
        "pushf",
        "pop {}",
        out(reg) result,
    );
    
    if result & (RFlags::CARRY_FLAG | RFlags::ZERO_FLAG).bits() != 0 {
        return Err(HypervisorError::VmcsError);
    }
    
    Ok(())
}