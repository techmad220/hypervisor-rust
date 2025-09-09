// hypervisor_core.rs - Core SVM/VMX hypervisor initialization based on Hypervisor.c
use alloc::vec::Vec;
use core::mem;
use x86_64::PhysAddr;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame};

// VMCB structure for AMD SVM
#[repr(C, align(4096))]
pub struct Vmcb {
    pub control_area: VmcbControlArea,
    pub state_save_area: VmcbStateSaveArea,
}

#[repr(C)]
pub struct VmcbControlArea {
    pub intercept_cr: u32,
    pub intercept_dr: u32,
    pub intercept_exceptions: u32,
    pub intercept1: u64,
    pub intercept2: u64,
    pub reserved1: [u8; 40],
    pub pause_filter_threshold: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub reserved2: [u8; 24],
    pub guest_asid: u32,
    pub tlb_control: u8,
    pub reserved3: [u8; 3],
    pub v_intr: u64,
    pub interrupt_shadow: u64,
    pub exitcode: u64,
    pub exitinfo1: u64,
    pub exitinfo2: u64,
    pub exit_int_info: u64,
    pub np_enable: u64,
    pub avic_apic_bar: u64,
    pub guest_pa_of_ghcb: u64,
    pub event_inj: u64,
    pub n_cr3: u64,
    pub lbr_virtualization_enable: u64,
    pub vmcb_clean: u64,
    pub nrip: u64,
    pub num_of_bytes_fetched: u8,
    pub guest_instruction_bytes: [u8; 15],
    pub avic_backing_page_ptr: u64,
    pub reserved4: [u8; 8],
    pub avic_logical_table_ptr: u64,
    pub avic_physical_table_ptr: u64,
    pub reserved5: [u8; 8],
    pub vmsa_ptr: u64,
    pub reserved6: [u8; 752],
}

#[repr(C)]
pub struct VmcbStateSaveArea {
    pub es: SegmentRegister,
    pub cs: SegmentRegister,
    pub ss: SegmentRegister,
    pub ds: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub gdtr: SegmentRegister,
    pub ldtr: SegmentRegister,
    pub idtr: SegmentRegister,
    pub tr: SegmentRegister,
    pub reserved1: [u8; 43],
    pub cpl: u8,
    pub reserved2: [u8; 4],
    pub efer: u64,
    pub reserved3: [u8; 112],
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub reserved4: [u8; 88],
    pub rsp: u64,
    pub reserved5: [u8; 24],
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    pub reserved6: [u8; 32],
    pub g_pat: u64,
    pub dbgctl: u64,
    pub br_from: u64,
    pub br_to: u64,
    pub last_excp_from: u64,
    pub last_excp_to: u64,
}

#[repr(C)]
pub struct SegmentRegister {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

// Hypervisor context structure
pub struct HypervisorContext {
    pub guest_vmcb: Option<*mut Vmcb>,
    pub host_vmcb: Option<*mut Vmcb>,
    pub npt_base: Option<*mut PageTable>,
    pub ctx_buf: Option<*mut u8>,
    pub cpu_id: u32,
    pub active_vcpu_count: u32,
    pub vm_exit_count: u64,
}

// Error codes matching C implementation
#[derive(Debug, Clone, Copy)]
pub enum HypervisorError {
    HostVmcbAllocFailed,
    GuestVmcbAllocFailed,
    NptSetupFailed,
    CtxBufAllocFailed,
    NotInitialized,
}

// Global hypervisor context
static mut GLOBAL_HYPERVISOR_CONTEXT: Option<HypervisorContext> = None;
static mut HOST_VMCB: Option<*mut Vmcb> = None;
static mut GUEST_VMCB: Option<*mut Vmcb> = None;

// Initialize hypervisor - based on C InitializeHypervisor
pub fn initialize_hypervisor() -> Result<(), HypervisorError> {
    unsafe {
        println!("InitializeHypervisor: allocating host VMCB");
        
        // Allocate host VMCB (4KB aligned)
        let host_vmcb = allocate_vmcb_page()?;
        HOST_VMCB = Some(host_vmcb);
        core::ptr::write_bytes(host_vmcb as *mut u8, 0, mem::size_of::<Vmcb>());
        println!("InitializeHypervisor: host VMCB allocated at {:p}", host_vmcb);
        
        // Allocate guest VMCB
        println!("InitializeHypervisor: allocating guest VMCB");
        let guest_vmcb = allocate_vmcb_page()?;
        GUEST_VMCB = Some(guest_vmcb);
        core::ptr::write_bytes(guest_vmcb as *mut u8, 0, mem::size_of::<Vmcb>());
        println!("InitializeHypervisor: guest VMCB allocated at {:p}", guest_vmcb);
        
        // Initialize global context
        let mut context = HypervisorContext {
            guest_vmcb: Some(guest_vmcb),
            host_vmcb: Some(host_vmcb),
            npt_base: None,
            ctx_buf: None,
            cpu_id: 0,
            active_vcpu_count: 0,
            vm_exit_count: 0,
        };
        
        // Setup NPT
        println!("InitializeHypervisor: setting up NPT");
        setup_npt(&mut context)?;
        
        // Allocate context buffer (4KB)
        println!("InitializeHypervisor: allocating context buffer");
        let ctx_buf = allocate_page()?;
        core::ptr::write_bytes(ctx_buf, 0, 4096);
        context.ctx_buf = Some(ctx_buf);
        println!("InitializeHypervisor: context buffer allocated at {:p}", ctx_buf);
        
        GLOBAL_HYPERVISOR_CONTEXT = Some(context);
        
        Ok(())
    }
}

// Cleanup hypervisor - based on C CleanupHypervisor
pub fn cleanup_hypervisor() {
    unsafe {
        println!("CleanupHypervisor: starting cleanup");
        
        if let Some(host_vmcb) = HOST_VMCB {
            println!("CleanupHypervisor: freeing host VMCB");
            free_vmcb_page(host_vmcb);
            HOST_VMCB = None;
        }
        
        if let Some(guest_vmcb) = GUEST_VMCB {
            println!("CleanupHypervisor: freeing guest VMCB");
            free_vmcb_page(guest_vmcb);
            GUEST_VMCB = None;
        }
        
        if let Some(ref mut context) = GLOBAL_HYPERVISOR_CONTEXT {
            if let Some(npt_base) = context.npt_base {
                println!("CleanupHypervisor: freeing NPT structures");
                cleanup_npt(npt_base);
                context.npt_base = None;
            }
            
            if let Some(ctx_buf) = context.ctx_buf {
                println!("CleanupHypervisor: freeing context buffer");
                free_page(ctx_buf);
                context.ctx_buf = None;
            }
        }
        
        GLOBAL_HYPERVISOR_CONTEXT = None;
    }
}

// Get guest VMCB - based on C GetGuestVmcb
pub fn get_guest_vmcb() -> Option<*mut Vmcb> {
    unsafe { GUEST_VMCB }
}

// Setup NPT (Nested Page Tables) - based on C SetupNpt
fn setup_npt(ctx: &mut HypervisorContext) -> Result<(), HypervisorError> {
    unsafe {
        // Allocate PML4 table
        let pml4 = allocate_page()? as *mut PageTable;
        core::ptr::write_bytes(pml4 as *mut u8, 0, 4096);
        
        // Allocate PDPT
        let pdpt = allocate_page()? as *mut PageTable;
        core::ptr::write_bytes(pdpt as *mut u8, 0, 4096);
        
        // Allocate PD
        let pd = allocate_page()? as *mut PageTable;
        core::ptr::write_bytes(pd as *mut u8, 0, 4096);
        
        // Set up page table hierarchy
        // PML4[0] -> PDPT
        (*pml4)[0].set_addr(
            PhysAddr::new(pdpt as u64),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        
        // PDPT[0] -> PD
        (*pdpt)[0].set_addr(
            PhysAddr::new(pd as u64),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        
        // PD entries - map first 512GB with 2MB pages
        for i in 0..512 {
            let addr = i as u64 * 0x200000; // 2MB pages
            (*pd)[i].set_addr(
                PhysAddr::new(addr),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                PageTableFlags::USER_ACCESSIBLE | PageTableFlags::HUGE_PAGE,
            );
        }
        
        ctx.npt_base = Some(pml4);
        
        // Set NPT in guest VMCB if available
        if let Some(guest_vmcb) = ctx.guest_vmcb {
            (*guest_vmcb).control_area.n_cr3 = pml4 as u64;
            (*guest_vmcb).control_area.np_enable = 1;
        }
        
        Ok(())
    }
}

// Cleanup NPT structures
fn cleanup_npt(pml4: *mut PageTable) {
    unsafe {
        // Get PDPT from PML4[0]
        let pdpt_pa = (*pml4)[0].addr().as_u64() & !0xFFF;
        if pdpt_pa != 0 {
            let pdpt = pdpt_pa as *mut PageTable;
            
            // Get PD from PDPT[0]
            let pd_pa = (*pdpt)[0].addr().as_u64() & !0xFFF;
            if pd_pa != 0 {
                free_page(pd_pa as *mut u8);
            }
            
            free_page(pdpt as *mut u8);
        }
        
        free_page(pml4 as *mut u8);
    }
}

// Helper functions for memory allocation
fn allocate_vmcb_page() -> Result<*mut Vmcb, HypervisorError> {
    // In real implementation, this would use UEFI AllocatePages
    // For now, use a simple aligned allocation
    let ptr = allocate_aligned_page(4096)?;
    Ok(ptr as *mut Vmcb)
}

fn free_vmcb_page(vmcb: *mut Vmcb) {
    // In real implementation, this would use UEFI FreePages
    free_page(vmcb as *mut u8);
}

fn allocate_page() -> Result<*mut u8, HypervisorError> {
    // Simplified page allocation
    // In real implementation, use UEFI boot services
    let layout = alloc::alloc::Layout::from_size_align(4096, 4096)
        .map_err(|_| HypervisorError::CtxBufAllocFailed)?;
    
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        Err(HypervisorError::CtxBufAllocFailed)
    } else {
        Ok(ptr)
    }
}

fn allocate_aligned_page(align: usize) -> Result<*mut u8, HypervisorError> {
    let layout = alloc::alloc::Layout::from_size_align(4096, align)
        .map_err(|_| HypervisorError::CtxBufAllocFailed)?;
    
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        Err(HypervisorError::CtxBufAllocFailed)
    } else {
        Ok(ptr)
    }
}

fn free_page(ptr: *mut u8) {
    if !ptr.is_null() {
        let layout = alloc::alloc::Layout::from_size_align(4096, 4096).unwrap();
        unsafe { alloc::alloc::dealloc(ptr, layout) };
    }
}

// Configure guest VMCB for initial VM entry
pub fn configure_guest_vmcb(vmcb: *mut Vmcb) {
    unsafe {
        // Set up control area intercepts
        (*vmcb).control_area.intercept_cr = 0x00000010; // Intercept CR4
        (*vmcb).control_area.intercept_exceptions = 0x00004000; // Intercept #PF
        (*vmcb).control_area.intercept1 = 
            (1 << 28) | // CPUID
            (1 << 30) | // RDMSR
            (1 << 31);  // WRMSR
        
        // Set up state save area
        (*vmcb).state_save_area.efer = 0x1501; // LME | LMA | SCE | NXE
        (*vmcb).state_save_area.cr0 = 0x80050033; // PG | AM | WP | NE | PE | MP
        (*vmcb).state_save_area.cr4 = 0x000406F8; // Common CR4 flags
        (*vmcb).state_save_area.rflags = 0x2; // Reserved bit 1
        
        // Set up segments
        setup_segment(&mut (*vmcb).state_save_area.cs, 0x10, 0xFFFFFFFF, 0x29B);
        setup_segment(&mut (*vmcb).state_save_area.ds, 0x18, 0xFFFFFFFF, 0x293);
        setup_segment(&mut (*vmcb).state_save_area.es, 0x18, 0xFFFFFFFF, 0x293);
        setup_segment(&mut (*vmcb).state_save_area.fs, 0x18, 0xFFFFFFFF, 0x293);
        setup_segment(&mut (*vmcb).state_save_area.gs, 0x18, 0xFFFFFFFF, 0x293);
        setup_segment(&mut (*vmcb).state_save_area.ss, 0x18, 0xFFFFFFFF, 0x293);
    }
}

fn setup_segment(seg: &mut SegmentRegister, selector: u16, limit: u32, attrib: u16) {
    seg.selector = selector;
    seg.limit = limit;
    seg.attrib = attrib;
    seg.base = 0;
}

// Get global hypervisor context
pub fn get_hypervisor_context() -> Option<&'static mut HypervisorContext> {
    unsafe { GLOBAL_HYPERVISOR_CONTEXT.as_mut() }
}

// Check if hypervisor is initialized
pub fn is_hypervisor_initialized() -> bool {
    unsafe { GLOBAL_HYPERVISOR_CONTEXT.is_some() }
}

// Handle VM exit
pub fn handle_vmexit(vmcb: *mut Vmcb) -> Result<(), HypervisorError> {
    unsafe {
        let exit_code = (*vmcb).control_area.exitcode;
        let exit_info1 = (*vmcb).control_area.exitinfo1;
        let exit_info2 = (*vmcb).control_area.exitinfo2;
        
        match exit_code {
            0x72 => { // CPUID
                handle_cpuid_exit(vmcb);
            },
            0x7C => { // MSR read
                handle_msr_read_exit(vmcb);
            },
            0x7D => { // MSR write
                handle_msr_write_exit(vmcb);
            },
            _ => {
                println!("Unhandled VM exit: {:#x}", exit_code);
            }
        }
        
        // Update VM exit count
        if let Some(ref mut ctx) = GLOBAL_HYPERVISOR_CONTEXT {
            ctx.vm_exit_count += 1;
        }
        
        Ok(())
    }
}

fn handle_cpuid_exit(vmcb: *mut Vmcb) {
    unsafe {
        // Handle CPUID instruction
        let rax = (*vmcb).state_save_area.rax;
        
        // Spoof CPUID results as needed
        match rax {
            0x1 => {
                // Mask hypervisor presence
                (*vmcb).state_save_area.rax &= !0x80000000;
            },
            _ => {}
        }
        
        // Advance RIP
        (*vmcb).state_save_area.rip = (*vmcb).control_area.nrip;
    }
}

fn handle_msr_read_exit(vmcb: *mut Vmcb) {
    unsafe {
        // Handle RDMSR
        (*vmcb).state_save_area.rip = (*vmcb).control_area.nrip;
    }
}

fn handle_msr_write_exit(vmcb: *mut Vmcb) {
    unsafe {
        // Handle WRMSR
        (*vmcb).state_save_area.rip = (*vmcb).control_area.nrip;
    }
}

// Print helper for no_std environment
fn println(s: &str) {
    // In real implementation, use UEFI console output
    // For now, this is a placeholder
}