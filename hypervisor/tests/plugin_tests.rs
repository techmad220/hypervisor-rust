//! Integration tests for all 77+ plugins

#![cfg(test)]

use hypervisor::plugin::{Plugin, PluginManager, PluginPriority};
use hypervisor::plugins::*;

#[test]
fn test_plugin_count() {
    let mut collection = mod::PluginCollection::new();
    collection.load_all_plugins().unwrap();
    assert_eq!(collection.count(), 77, "Should have exactly 77 plugins");
}

#[test]
fn test_anti_detection_plugins() {
    use anti_detection::*;
    
    let plugins = vec![
        Box::new(AntiVmDetectionPlugin::new()) as Box<dyn Plugin>,
        Box::new(CpuidSpoofingPlugin::new()),
        Box::new(MsrSpoofingPlugin::new()),
        Box::new(TscSpoofingPlugin::new()),
        Box::new(HypervisorHidingPlugin::new()),
    ];
    
    for plugin in plugins {
        assert_eq!(plugin.metadata().priority, PluginPriority::High);
        assert!(plugin.metadata().capabilities.contains(&PluginCapability::AntiDetection));
    }
}

#[test]
fn test_memory_plugins() {
    use memory::*;
    
    let mut mem_plugin = MemoryProtectionPlugin::new();
    mem_plugin.add_protected_region(0x1000, 0x2000, 0x7); // RWX
    
    assert!(mem_plugin.init().is_ok());
    assert_eq!(mem_plugin.metadata().priority, PluginPriority::Critical);
}

#[test]
fn test_process_plugins() {
    use all_plugins::process::*;
    
    let plugins = vec![
        Box::new(ProcessMonitorPlugin::new()) as Box<dyn Plugin>,
        Box::new(DllInjectionDetectorPlugin::new()),
        Box::new(ProcessHollowingDetectorPlugin::new()),
    ];
    
    for plugin in plugins {
        assert!(plugin.init().is_ok());
    }
}

#[test]
fn test_hardware_spoofing_plugins() {
    use all_plugins::hardware::*;
    
    let mut hwid_plugin = HwidSpoofingPlugin::new();
    hwid_plugin.set_spoof_value("CPU".to_string(), "Intel Core i9-13900K".to_string());
    
    assert!(hwid_plugin.init().is_ok());
}

#[test]
fn test_stealth_plugins() {
    use all_plugins::stealth::*;
    
    let mut fs_stealth = FileSystemStealthPlugin::new();
    fs_stealth.hide_item("C:\\Windows\\System32\\malware.exe".to_string());
    
    assert!(fs_stealth.init().is_ok());
}

#[test]
fn test_integrity_plugins() {
    use all_plugins::integrity::*;
    
    let mut kernel_integrity = KernelIntegrityPlugin::new();
    kernel_integrity.add_checksum(0xFFFFF800_00000000, 0x12345678);
    
    assert!(kernel_integrity.init().is_ok());
    assert_eq!(kernel_integrity.metadata().priority, PluginPriority::Critical);
}

#[test]
fn test_network_plugins() {
    use all_plugins::network::*;
    
    let mut firewall = FirewallPlugin::new();
    firewall.add_rule(NetworkRule {
        protocol: 6, // TCP
        port: 445,   // SMB
        action: NetworkAction::Block,
    });
    
    assert!(firewall.init().is_ok());
}

#[test]
fn test_forensics_plugins() {
    use all_plugins::forensics::*;
    
    let plugins = vec![
        Box::new(ForensicsEvasionPlugin::new()) as Box<dyn Plugin>,
        Box::new(ArtifactCleanerPlugin::new()),
        Box::new(LogCleanerPlugin::new()),
        Box::new(TimestampSpoofingPlugin::new()),
    ];
    
    for plugin in plugins {
        assert!(plugin.init().is_ok());
    }
}

#[test]
fn test_plugin_manager() {
    let mut manager = PluginManager::new();
    
    // Register multiple plugins
    let plugin1 = Box::new(anti_detection::AntiVmDetectionPlugin::new());
    let plugin2 = Box::new(memory::MemoryProtectionPlugin::new());
    let plugin3 = Box::new(all_plugins::network::NetworkFilterPlugin::new());
    
    assert!(manager.register(plugin1).is_ok());
    assert!(manager.register(plugin2).is_ok());
    assert!(manager.register(plugin3).is_ok());
    
    // Initialize all plugins
    assert!(manager.init_all().is_ok());
}

#[test]
fn test_plugin_priority_ordering() {
    let critical = all_plugins::integrity::KernelIntegrityPlugin::new();
    let high = anti_detection::AntiVmDetectionPlugin::new();
    let normal = all_plugins::network::NetworkFilterPlugin::new();
    
    assert_eq!(critical.metadata().priority, PluginPriority::Critical);
    assert_eq!(high.metadata().priority, PluginPriority::High);
    assert_eq!(normal.metadata().priority, PluginPriority::Normal);
    
    // Verify priority ordering
    assert!(PluginPriority::Critical > PluginPriority::High);
    assert!(PluginPriority::High > PluginPriority::Normal);
    assert!(PluginPriority::Normal > PluginPriority::Low);
}

#[test]
fn test_cpuid_filtering() {
    let mut plugin = anti_detection::AntiVmDetectionPlugin::new();
    
    let mut eax = 0u32;
    let mut ebx = 0u32;
    let mut ecx = 1u32 << 31; // Hypervisor bit set
    let mut edx = 0u32;
    
    // Filter CPUID leaf 1
    plugin.filter_cpuid(1, 0, &mut eax, &mut ebx, &mut ecx, &mut edx).unwrap();
    
    // Hypervisor bit should be cleared
    assert_eq!(ecx & (1 << 31), 0);
}

#[test]
fn test_all_plugin_categories() {
    // Verify all 8 categories have plugins
    assert!(anti_detection::AntiVmDetectionPlugin::new().init().is_ok());
    assert!(memory::MemoryProtectionPlugin::new().init().is_ok());
    assert!(all_plugins::process::ProcessMonitorPlugin::new().init().is_ok());
    assert!(all_plugins::hardware::HwidSpoofingPlugin::new().init().is_ok());
    assert!(all_plugins::stealth::FileSystemStealthPlugin::new().init().is_ok());
    assert!(all_plugins::integrity::KernelIntegrityPlugin::new().init().is_ok());
    assert!(all_plugins::network::NetworkFilterPlugin::new().init().is_ok());
    assert!(all_plugins::forensics::ForensicsEvasionPlugin::new().init().is_ok());
}

// Benchmark test for plugin initialization
#[test]
fn test_plugin_init_performance() {
    use std::time::Instant;
    
    let start = Instant::now();
    
    let mut collection = mod::PluginCollection::new();
    collection.load_all_plugins().unwrap();
    
    let mut manager = PluginManager::new();
    collection.register_all(&mut manager).unwrap();
    manager.init_all().unwrap();
    
    let duration = start.elapsed();
    
    // All 77 plugins should initialize in under 100ms
    assert!(duration.as_millis() < 100, "Plugin initialization took too long: {:?}", duration);
}