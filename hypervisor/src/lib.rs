#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(const_mut_refs)]

pub mod vmx;
pub mod svm;
pub mod memory;
pub mod vcpu;
pub mod vmcs;
pub mod interrupts;
pub mod io;

use core::panic::PanicInfo;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

// Global hypervisor state
pub static mut HYPERVISOR: Option<Hypervisor> = None;

/// Main hypervisor structure
pub struct Hypervisor {
    pub vmx_enabled: bool,
    pub svm_enabled: bool,
    pub vcpus: [Option<vcpu::VCpu>; 256],
    pub memory_manager: memory::MemoryManager,
    pub io_manager: io::IoManager,
}

impl Hypervisor {
    /// Initialize the hypervisor
    pub fn init() -> Result<(), HypervisorError> {
        log::info!("Initializing Hypervisor Core...");
        
        // Detect virtualization technology
        let (vmx, svm) = detect_virt_tech();
        
        let mut hypervisor = Self {
            vmx_enabled: vmx,
            svm_enabled: svm,
            vcpus: [const { None }; 256],
            memory_manager: memory::MemoryManager::new(),
            io_manager: io::IoManager::new(),
        };
        
        // Initialize virtualization extensions
        if vmx {
            vmx::init()?;
        } else if svm {
            svm::init()?;
        } else {
            return Err(HypervisorError::NoVirtualizationSupport);
        }
        
        // Set up interrupt handlers
        interrupts::init();
        
        // Store global instance
        unsafe {
            HYPERVISOR = Some(hypervisor);
        }
        
        log::info!("Hypervisor initialized successfully");
        Ok(())
    }
    
    /// Create a new virtual CPU
    pub fn create_vcpu(&mut self, vcpu_id: usize) -> Result<&mut vcpu::VCpu, HypervisorError> {
        if vcpu_id >= 256 {
            return Err(HypervisorError::InvalidVcpuId);
        }
        
        if self.vcpus[vcpu_id].is_some() {
            return Err(HypervisorError::VcpuAlreadyExists);
        }
        
        let vcpu = if self.vmx_enabled {
            vcpu::VCpu::new_vmx(vcpu_id)?
        } else {
            vcpu::VCpu::new_svm(vcpu_id)?
        };
        
        self.vcpus[vcpu_id] = Some(vcpu);
        Ok(self.vcpus[vcpu_id].as_mut().unwrap())
    }
    
    /// Run a virtual CPU
    pub fn run_vcpu(&mut self, vcpu_id: usize) -> Result<(), HypervisorError> {
        let vcpu = self.vcpus[vcpu_id]
            .as_mut()
            .ok_or(HypervisorError::VcpuNotFound)?;
        
        vcpu.run()
    }
}

/// Detect available virtualization technology
fn detect_virt_tech() -> (bool, bool) {
    use raw_cpuid::CpuId;
    
    let cpuid = CpuId::new();
    let mut vmx = false;
    let mut svm = false;
    
    if let Some(features) = cpuid.get_feature_info() {
        vmx = features.has_vmx();
    }
    
    if let Some(extended) = cpuid.get_extended_processor_info() {
        svm = extended.has_svm();
    }
    
    (vmx, svm)
}

#[derive(Debug)]
pub enum HypervisorError {
    NoVirtualizationSupport,
    VmxInitFailed,
    SvmInitFailed,
    InvalidVcpuId,
    VcpuAlreadyExists,
    VcpuNotFound,
    MemoryAllocationFailed,
    VmcsError,
    VmcbError,
}

/// Entry point from bootloader
#[no_mangle]
pub extern "C" fn hypervisor_main() -> ! {
    // Initialize hypervisor
    if let Err(e) = Hypervisor::init() {
        log::error!("Failed to initialize hypervisor: {:?}", e);
        halt();
    }
    
    // Main hypervisor loop
    loop {
        unsafe {
            if let Some(ref mut hv) = HYPERVISOR {
                // Handle pending operations
                hv.io_manager.process_pending();
                
                // Schedule VCPUs
                for i in 0..256 {
                    if hv.vcpus[i].is_some() {
                        let _ = hv.run_vcpu(i);
                    }
                }
            }
        }
        
        // Yield CPU
        x86_64::instructions::hlt();
    }
}

fn halt() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("Hypervisor panic: {}", info);
    halt()
}