//! Plugin architecture for extensible hypervisor functionality

use core::any::Any;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::string::String;
use crate::{HypervisorError, Vmcb};

/// Plugin priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PluginPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Plugin capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCapability {
    VmExit,
    MemoryManagement,
    CpuidIntercept,
    MsrIntercept,
    IoIntercept,
    ExceptionHandler,
    NetworkFilter,
    DiskFilter,
    ProcessMonitor,
    AntiDetection,
}

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<PluginCapability>,
    pub priority: PluginPriority,
}

/// Core plugin trait
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;
    
    /// Initialize the plugin
    fn init(&mut self) -> Result<(), HypervisorError>;
    
    /// Cleanup plugin resources
    fn cleanup(&mut self) -> Result<(), HypervisorError>;
    
    /// Handle VM exit if this plugin processes exits
    fn handle_vmexit(&mut self, vmcb: &mut Vmcb, exit_code: u64) -> Result<bool, HypervisorError> {
        Ok(false) // Default: don't handle
    }
    
    /// Filter CPUID results
    fn filter_cpuid(&mut self, leaf: u32, subleaf: u32, eax: &mut u32, ebx: &mut u32, ecx: &mut u32, edx: &mut u32) -> Result<bool, HypervisorError> {
        Ok(false) // Default: don't modify
    }
    
    /// Filter MSR access
    fn filter_msr(&mut self, msr: u32, value: &mut u64, is_write: bool) -> Result<bool, HypervisorError> {
        Ok(false) // Default: don't modify
    }
    
    /// Filter I/O port access
    fn filter_io(&mut self, port: u16, value: &mut u32, is_write: bool) -> Result<bool, HypervisorError> {
        Ok(false) // Default: don't modify
    }
    
    /// Get plugin as Any for downcasting
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Plugin manager
pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
    enabled: Vec<bool>,
}

impl PluginManager {
    /// Create new plugin manager
    pub fn new() -> Self {
        PluginManager {
            plugins: Vec::new(),
            enabled: Vec::new(),
        }
    }
    
    /// Register a plugin
    pub fn register(&mut self, plugin: Box<dyn Plugin>) -> Result<usize, HypervisorError> {
        let id = self.plugins.len();
        self.plugins.push(plugin);
        self.enabled.push(true);
        Ok(id)
    }
    
    /// Enable/disable a plugin
    pub fn set_enabled(&mut self, id: usize, enabled: bool) -> Result<(), HypervisorError> {
        if id >= self.enabled.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        self.enabled[id] = enabled;
        Ok(())
    }
    
    /// Initialize all plugins
    pub fn init_all(&mut self) -> Result<(), HypervisorError> {
        for (i, plugin) in self.plugins.iter_mut().enumerate() {
            if self.enabled[i] {
                plugin.init()?;
                log::info!("Initialized plugin: {}", plugin.metadata().name);
            }
        }
        Ok(())
    }
    
    /// Process VM exit through plugins
    pub fn handle_vmexit(&mut self, vmcb: &mut Vmcb, exit_code: u64) -> Result<bool, HypervisorError> {
        // Sort by priority and process
        let mut handled = false;
        
        for (i, plugin) in self.plugins.iter_mut().enumerate() {
            if self.enabled[i] && plugin.metadata().capabilities.contains(&PluginCapability::VmExit) {
                if plugin.handle_vmexit(vmcb, exit_code)? {
                    handled = true;
                    break; // Stop if plugin handled the exit
                }
            }
        }
        
        Ok(handled)
    }
    
    /// Filter CPUID through plugins
    pub fn filter_cpuid(&mut self, leaf: u32, subleaf: u32, eax: &mut u32, ebx: &mut u32, ecx: &mut u32, edx: &mut u32) -> Result<(), HypervisorError> {
        for (i, plugin) in self.plugins.iter_mut().enumerate() {
            if self.enabled[i] && plugin.metadata().capabilities.contains(&PluginCapability::CpuidIntercept) {
                plugin.filter_cpuid(leaf, subleaf, eax, ebx, ecx, edx)?;
            }
        }
        Ok(())
    }
    
    /// Filter MSR access through plugins
    pub fn filter_msr(&mut self, msr: u32, value: &mut u64, is_write: bool) -> Result<(), HypervisorError> {
        for (i, plugin) in self.plugins.iter_mut().enumerate() {
            if self.enabled[i] && plugin.metadata().capabilities.contains(&PluginCapability::MsrIntercept) {
                plugin.filter_msr(msr, value, is_write)?;
            }
        }
        Ok(())
    }
    
    /// Cleanup all plugins
    pub fn cleanup_all(&mut self) -> Result<(), HypervisorError> {
        for (i, plugin) in self.plugins.iter_mut().enumerate() {
            if self.enabled[i] {
                plugin.cleanup()?;
            }
        }
        Ok(())
    }
}

// Example plugins

/// Anti-detection plugin
pub struct AntiDetectionPlugin {
    metadata: PluginMetadata,
    hide_hypervisor_bit: bool,
    spoof_rdtsc: bool,
}

impl AntiDetectionPlugin {
    pub fn new() -> Self {
        AntiDetectionPlugin {
            metadata: PluginMetadata {
                name: String::from("Anti-Detection Plugin"),
                version: String::from("1.0.0"),
                author: String::from("Hypervisor Team"),
                description: String::from("Hides hypervisor presence from guest"),
                capabilities: vec![
                    PluginCapability::CpuidIntercept,
                    PluginCapability::MsrIntercept,
                    PluginCapability::AntiDetection,
                ],
                priority: PluginPriority::High,
            },
            hide_hypervisor_bit: true,
            spoof_rdtsc: true,
        }
    }
}

impl Plugin for AntiDetectionPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    fn init(&mut self) -> Result<(), HypervisorError> {
        log::debug!("Anti-detection plugin initialized");
        Ok(())
    }
    
    fn cleanup(&mut self) -> Result<(), HypervisorError> {
        Ok(())
    }
    
    fn filter_cpuid(&mut self, leaf: u32, _subleaf: u32, _eax: &mut u32, _ebx: &mut u32, ecx: &mut u32, _edx: &mut u32) -> Result<bool, HypervisorError> {
        if self.hide_hypervisor_bit && leaf == 1 {
            // Clear hypervisor present bit (ECX[31])
            *ecx &= !(1 << 31);
            return Ok(true);
        }
        
        // Hide hypervisor vendor leaves
        if leaf >= 0x40000000 && leaf <= 0x400000FF {
            *_eax = 0;
            *_ebx = 0;
            *ecx = 0;
            *_edx = 0;
            return Ok(true);
        }
        
        Ok(false)
    }
    
    fn filter_msr(&mut self, msr: u32, value: &mut u64, is_write: bool) -> Result<bool, HypervisorError> {
        if !is_write && self.spoof_rdtsc {
            match msr {
                // TSC_AUX MSR
                0xC0000103 => {
                    *value = 0;
                    return Ok(true);
                }
                _ => {}
            }
        }
        Ok(false)
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Memory protection plugin
pub struct MemoryProtectionPlugin {
    metadata: PluginMetadata,
    protected_regions: Vec<(u64, u64)>, // (start, end) pairs
}

impl MemoryProtectionPlugin {
    pub fn new() -> Self {
        MemoryProtectionPlugin {
            metadata: PluginMetadata {
                name: String::from("Memory Protection Plugin"),
                version: String::from("1.0.0"),
                author: String::from("Hypervisor Team"),
                description: String::from("Protects critical memory regions"),
                capabilities: vec![
                    PluginCapability::MemoryManagement,
                    PluginCapability::VmExit,
                ],
                priority: PluginPriority::Critical,
            },
            protected_regions: Vec::new(),
        }
    }
    
    pub fn add_protected_region(&mut self, start: u64, end: u64) {
        self.protected_regions.push((start, end));
    }
}

impl Plugin for MemoryProtectionPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    fn init(&mut self) -> Result<(), HypervisorError> {
        log::debug!("Memory protection plugin initialized with {} regions", self.protected_regions.len());
        Ok(())
    }
    
    fn cleanup(&mut self) -> Result<(), HypervisorError> {
        self.protected_regions.clear();
        Ok(())
    }
    
    fn handle_vmexit(&mut self, vmcb: &mut Vmcb, exit_code: u64) -> Result<bool, HypervisorError> {
        // Handle NPF (Nested Page Fault) for protected regions
        if exit_code == 0x400 { // NPF exit code
            let fault_addr = vmcb.control_area.exit_info_2;
            
            for (start, end) in &self.protected_regions {
                if fault_addr >= *start && fault_addr < *end {
                    log::warn!("Blocked access to protected memory region: 0x{:x}", fault_addr);
                    // Inject general protection fault
                    vmcb.control_area.event_inj = (1 << 31) | (3 << 8) | 13; // GP fault
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Network filter plugin
pub struct NetworkFilterPlugin {
    metadata: PluginMetadata,
    blocked_ports: Vec<u16>,
}

impl NetworkFilterPlugin {
    pub fn new() -> Self {
        NetworkFilterPlugin {
            metadata: PluginMetadata {
                name: String::from("Network Filter Plugin"),
                version: String::from("1.0.0"),
                author: String::from("Hypervisor Team"),
                description: String::from("Filters network traffic"),
                capabilities: vec![
                    PluginCapability::IoIntercept,
                    PluginCapability::NetworkFilter,
                ],
                priority: PluginPriority::Normal,
            },
            blocked_ports: vec![445, 139, 135], // Block SMB/NetBIOS by default
        }
    }
}

impl Plugin for NetworkFilterPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    fn init(&mut self) -> Result<(), HypervisorError> {
        log::debug!("Network filter plugin initialized");
        Ok(())
    }
    
    fn cleanup(&mut self) -> Result<(), HypervisorError> {
        Ok(())
    }
    
    fn filter_io(&mut self, port: u16, value: &mut u32, is_write: bool) -> Result<bool, HypervisorError> {
        // Check if this is a network-related I/O port
        if self.blocked_ports.contains(&port) {
            log::warn!("Blocked I/O access to port 0x{:x}", port);
            if !is_write {
                *value = 0xFF; // Return dummy value for reads
            }
            return Ok(true);
        }
        Ok(false)
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

extern crate alloc;
use crate::svm::Vmcb;