//! Complete plugin collection - 77+ plugins ported from C

pub mod all_plugins;
pub mod real_plugins;
pub mod anti_detection;
pub mod memory;
pub mod network;
pub mod process;
pub mod hardware;
pub mod stealth;
pub mod integrity;
pub mod forensics;

use crate::{HypervisorError, svm::Vmcb};
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::string::String;
use core::any::Any;

// Re-export main plugin trait and types
pub use crate::plugin::{Plugin, PluginMetadata, PluginCapability, PluginPriority, PluginManager};

/// Collection of all 77+ plugins
pub struct PluginCollection {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginCollection {
    pub fn new() -> Self {
        PluginCollection {
            plugins: Vec::new(),
        }
    }
    
    /// Load all default plugins
    pub fn load_all_plugins(&mut self) -> Result<(), HypervisorError> {
        // Anti-Detection Plugins (15 plugins)
        self.plugins.push(Box::new(anti_detection::AntiVmDetectionPlugin::new()));
        self.plugins.push(Box::new(anti_detection::CpuidSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::MsrSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::TscSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::HypervisorHidingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::AntiDebugDetectionPlugin::new()));
        self.plugins.push(Box::new(anti_detection::TimingAttackMitigationPlugin::new()));
        self.plugins.push(Box::new(anti_detection::RdtscpSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::VmExitSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::BrandStringSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::HypervisorVendorHidingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::VirtualizationFlagHidingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::PerformanceCounterSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::CacheTimingSpoofingPlugin::new()));
        self.plugins.push(Box::new(anti_detection::InstructionRetirementSpoofingPlugin::new()));
        
        // Memory Management Plugins (12 plugins)
        self.plugins.push(Box::new(memory::MemoryProtectionPlugin::new()));
        self.plugins.push(Box::new(memory::KernelMemoryAccessPlugin::new()));
        self.plugins.push(Box::new(memory::MemoryScannerPlugin::new()));
        self.plugins.push(Box::new(memory::ProcessMemScanPlugin::new()));
        self.plugins.push(Box::new(memory::MemoryForensicsEvasionPlugin::new()));
        self.plugins.push(Box::new(memory::MemoryIntegrityPlugin::new()));
        self.plugins.push(Box::new(memory::NptManagementPlugin::new()));
        self.plugins.push(Box::new(memory::EptManagementPlugin::new()));
        self.plugins.push(Box::new(memory::MemoryStealthPlugin::new()));
        self.plugins.push(Box::new(memory::PageGuardPlugin::new()));
        self.plugins.push(Box::new(memory::ShadowMemoryPlugin::new()));
        self.plugins.push(Box::new(memory::MemoryEncryptionPlugin::new()));
        
        // Process Monitoring Plugins (10 plugins)
        self.plugins.push(Box::new(process::ProcessMonitorPlugin::new()));
        self.plugins.push(Box::new(process::ProcessCreationPlugin::new()));
        self.plugins.push(Box::new(process::ProcessDestructionPlugin::new()));
        self.plugins.push(Box::new(process::ProcessIntegrityPlugin::new()));
        self.plugins.push(Box::new(process::ThreadMonitorPlugin::new()));
        self.plugins.push(Box::new(process::DllInjectionDetectorPlugin::new()));
        self.plugins.push(Box::new(process::ProcessHollowingDetectorPlugin::new()));
        self.plugins.push(Box::new(process::ProcessDoppelgangingPlugin::new()));
        self.plugins.push(Box::new(process::AtomBombingDetectorPlugin::new()));
        self.plugins.push(Box::new(process::ProcessGhostingPlugin::new()));
        
        // Hardware Spoofing Plugins (10 plugins)
        self.plugins.push(Box::new(hardware::HwidSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::CpuidSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::SmBiosSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::AcpiSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::PciSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::UsbSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::NetworkMacSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::DiskSerialSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::TpmSpoofingPlugin::new()));
        self.plugins.push(Box::new(hardware::GpuSpoofingPlugin::new()));
        
        // Stealth & Evasion Plugins (10 plugins)
        self.plugins.push(Box::new(stealth::FileSystemStealthPlugin::new()));
        self.plugins.push(Box::new(stealth::RegistryStealthPlugin::new()));
        self.plugins.push(Box::new(stealth::NetworkStealthPlugin::new()));
        self.plugins.push(Box::new(stealth::CallbackObfuscationPlugin::new()));
        self.plugins.push(Box::new(stealth::DriverSelfProtectionPlugin::new()));
        self.plugins.push(Box::new(stealth::HypervisorHijackPlugin::new()));
        self.plugins.push(Box::new(stealth::ScreenshotDetectorPlugin::new()));
        self.plugins.push(Box::new(stealth::KeyloggerDetectorPlugin::new()));
        self.plugins.push(Box::new(stealth::RecordingDetectorPlugin::new()));
        self.plugins.push(Box::new(stealth::RemoteAccessDetectorPlugin::new()));
        
        // Integrity & Security Plugins (10 plugins)
        self.plugins.push(Box::new(integrity::KernelIntegrityPlugin::new()));
        self.plugins.push(Box::new(integrity::PatchGuardBypassPlugin::new()));
        self.plugins.push(Box::new(integrity::DseBypassPlugin::new()));
        self.plugins.push(Box::new(integrity::KppBypassPlugin::new()));
        self.plugins.push(Box::new(integrity::IntegrityCheckPlugin::new()));
        self.plugins.push(Box::new(integrity::SecureBootBypassPlugin::new()));
        self.plugins.push(Box::new(integrity::UefiVariablePlugin::new()));
        self.plugins.push(Box::new(integrity::BootOrderHijackerPlugin::new()));
        self.plugins.push(Box::new(integrity::MeasuredBootPlugin::new()));
        self.plugins.push(Box::new(integrity::AttestationPlugin::new()));
        
        // Network & I/O Plugins (10 plugins)
        self.plugins.push(Box::new(network::NetworkFilterPlugin::new()));
        self.plugins.push(Box::new(network::PacketFilterPlugin::new()));
        self.plugins.push(Box::new(network::DnsFilterPlugin::new()));
        self.plugins.push(Box::new(network::FirewallPlugin::new()));
        self.plugins.push(Box::new(network::ProxyPlugin::new()));
        self.plugins.push(Box::new(network::VpnPlugin::new()));
        self.plugins.push(Box::new(network::TlsInterceptionPlugin::new()));
        self.plugins.push(Box::new(network::NetworkMonitorPlugin::new()));
        self.plugins.push(Box::new(network::BandwidthControlPlugin::new()));
        self.plugins.push(Box::new(network::NetworkIsolationPlugin::new()));
        
        log::info!("Loaded {} plugins", self.plugins.len());
        Ok(())
    }
    
    /// Register all plugins with a manager
    pub fn register_all(&mut self, manager: &mut PluginManager) -> Result<(), HypervisorError> {
        for plugin in self.plugins.drain(..) {
            manager.register(plugin)?;
        }
        Ok(())
    }
    
    /// Get plugin count
    pub fn count(&self) -> usize {
        self.plugins.len()
    }
}