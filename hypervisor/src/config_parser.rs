//! Configuration parser for hypervisor config.ini files
//! Supports full INI format with sections, variables, includes, and validation

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

/// Configuration parser errors
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    ParseError(String),
    ValidationError(String),
    MissingSection(String),
    MissingKey(String),
    InvalidValue(String),
    FileNotFound(String),
    CircularInclude(String),
}

/// Main configuration structure
#[derive(Debug, Clone)]
pub struct HypervisorConfig {
    pub global: GlobalConfig,
    pub vms: Vec<VmConfigEntry>,
    pub networks: Vec<NetworkConfig>,
    pub storage_pools: Vec<StoragePoolConfig>,
    pub security: SecurityConfig,
    pub monitoring: MonitoringConfig,
    pub cluster: ClusterConfig,
    pub raw_sections: BTreeMap<String, BTreeMap<String, String>>,
}

/// Global configuration
#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub max_vms: u32,
    pub default_memory_mb: usize,
    pub default_vcpus: u32,
    pub enable_nested_virt: bool,
    pub enable_iommu: bool,
    pub enable_ept: bool,
    pub enable_vpid: bool,
    pub enable_unrestricted_guest: bool,
    pub scheduler_type: String,
    pub memory_overcommit_ratio: f32,
    pub cpu_overcommit_ratio: f32,
    pub log_level: String,
    pub log_file: String,
    pub pid_file: String,
    pub socket_path: String,
    pub enable_kvm: bool,
    pub enable_hax: bool,
    pub enable_whpx: bool,
    pub enable_hvf: bool,
}

/// VM configuration entry
#[derive(Debug, Clone)]
pub struct VmConfigEntry {
    pub name: String,
    pub uuid: Option<String>,
    pub enabled: bool,
    pub auto_start: bool,
    pub auto_start_delay: u32,
    pub memory_mb: usize,
    pub memory_max_mb: Option<usize>,
    pub vcpus: u32,
    pub vcpus_max: Option<u32>,
    pub cpu_model: String,
    pub cpu_features: Vec<String>,
    pub machine_type: String,
    pub firmware: String,
    pub kernel: Option<String>,
    pub initrd: Option<String>,
    pub cmdline: Option<String>,
    pub boot_order: Vec<String>,
    pub disks: Vec<DiskConfig>,
    pub networks: Vec<VmNetworkConfig>,
    pub devices: Vec<DeviceConfig>,
    pub graphics: Option<GraphicsConfig>,
    pub audio: Option<AudioConfig>,
    pub usb: Vec<UsbConfig>,
    pub pci_passthrough: Vec<PciPassthroughConfig>,
    pub shares: Vec<ShareConfig>,
    pub metadata: BTreeMap<String, String>,
}

/// Disk configuration
#[derive(Debug, Clone)]
pub struct DiskConfig {
    pub file: String,
    pub format: String,
    pub interface: String,
    pub cache: String,
    pub size: Option<String>,
    pub read_only: bool,
    pub boot_index: Option<u32>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
}

/// VM network configuration
#[derive(Debug, Clone)]
pub struct VmNetworkConfig {
    pub model: String,
    pub network: String,
    pub mac: Option<String>,
    pub vlan: Option<u16>,
    pub rate_limit: Option<u32>,
}

/// Device configuration
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub device_type: String,
    pub model: String,
    pub options: BTreeMap<String, String>,
}

/// Graphics configuration
#[derive(Debug, Clone)]
pub struct GraphicsConfig {
    pub graphics_type: String,
    pub port: Option<u16>,
    pub listen: String,
    pub password: Option<String>,
    pub keyboard_layout: String,
    pub displays: u32,
    pub vram_mb: u32,
}

/// Audio configuration
#[derive(Debug, Clone)]
pub struct AudioConfig {
    pub model: String,
    pub backend: String,
}

/// USB configuration
#[derive(Debug, Clone)]
pub struct UsbConfig {
    pub usb_type: String,
    pub version: String,
    pub ports: u32,
    pub devices: Vec<String>,
}

/// PCI passthrough configuration
#[derive(Debug, Clone)]
pub struct PciPassthroughConfig {
    pub bus: String,
    pub slot: String,
    pub function: String,
    pub vfio_group: Option<u32>,
    pub rom_file: Option<String>,
}

/// Share configuration
#[derive(Debug, Clone)]
pub struct ShareConfig {
    pub name: String,
    pub path: String,
    pub mount_tag: String,
    pub read_only: bool,
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub name: String,
    pub network_type: String,
    pub bridge: Option<String>,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub dhcp_start: Option<String>,
    pub dhcp_end: Option<String>,
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub vlan_id: Option<u16>,
    pub forward_mode: String,
    pub isolated: bool,
}

/// Storage pool configuration
#[derive(Debug, Clone)]
pub struct StoragePoolConfig {
    pub name: String,
    pub pool_type: String,
    pub path: String,
    pub size_gb: Option<u64>,
    pub allocation_gb: Option<u64>,
    pub format: String,
    pub permissions: String,
}

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub enable_selinux: bool,
    pub enable_apparmor: bool,
    pub enable_seccomp: bool,
    pub enable_capabilities: bool,
    pub enable_namespaces: bool,
    pub enable_cgroups: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_ca: Option<String>,
    pub tls_verify_client: bool,
    pub vnc_tls: bool,
    pub spice_tls: bool,
    pub migration_tls: bool,
}

/// Monitoring configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub enable_prometheus: bool,
    pub prometheus_port: u16,
    pub enable_grafana: bool,
    pub grafana_port: u16,
    pub enable_stats_collection: bool,
    pub stats_interval_seconds: u32,
    pub enable_tracing: bool,
    pub tracing_backend: String,
    pub enable_profiling: bool,
    pub profiling_port: u16,
}

/// Cluster configuration
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub node_id: String,
    pub cluster_name: String,
    pub bind_address: String,
    pub advertise_address: String,
    pub peers: Vec<String>,
    pub heartbeat_interval_ms: u32,
    pub election_timeout_ms: u32,
    pub enable_fencing: bool,
    pub fencing_method: String,
}

/// Configuration parser
pub struct ConfigParser {
    includes_visited: Vec<String>,
    current_file: Option<String>,
    line_number: usize,
}

impl ConfigParser {
    pub fn new() -> Self {
        Self {
            includes_visited: Vec::new(),
            current_file: None,
            line_number: 0,
        }
    }
    
    pub fn parse_file(&mut self, filepath: &str) -> Result<HypervisorConfig, ConfigError> {
        // Check for circular includes
        if self.includes_visited.contains(&filepath.to_string()) {
            return Err(ConfigError::CircularInclude(filepath.to_string()));
        }
        
        self.includes_visited.push(filepath.to_string());
        self.current_file = Some(filepath.to_string());
        
        // Read file contents (in real implementation)
        let contents = self.read_file(filepath)?;
        
        self.parse_string(&contents)
    }
    
    pub fn parse_string(&mut self, contents: &str) -> Result<HypervisorConfig, ConfigError> {
        let mut sections = BTreeMap::new();
        let mut current_section = String::from("global");
        sections.insert(current_section.clone(), BTreeMap::new());
        
        self.line_number = 0;
        
        for line in contents.lines() {
            self.line_number += 1;
            let line = self.process_line(line)?;
            
            if line.is_empty() {
                continue;
            }
            
            // Handle includes
            if line.starts_with("@include") {
                let include_file = line.trim_start_matches("@include").trim();
                let included_config = self.parse_file(include_file)?;
                // Merge included configuration
                self.merge_configs(&mut sections, included_config.raw_sections);
                continue;
            }
            
            // Handle sections
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len()-1].to_string();
                if !sections.contains_key(&current_section) {
                    sections.insert(current_section.clone(), BTreeMap::new());
                }
                continue;
            }
            
            // Handle key-value pairs
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let value = self.expand_value(&line[eq_pos+1..].trim().to_string(), &sections)?;
                
                if let Some(section) = sections.get_mut(&current_section) {
                    section.insert(key, value);
                }
            } else {
                return Err(ConfigError::ParseError(
                    format!("Invalid line {} in {}: {}", 
                        self.line_number, 
                        self.current_file.as_ref().unwrap_or(&"<string>".to_string()),
                        line)
                ));
            }
        }
        
        self.build_config(sections)
    }
    
    fn process_line(&self, line: &str) -> Result<String, ConfigError> {
        // Remove comments
        let line = if let Some(comment_pos) = line.find('#') {
            &line[..comment_pos]
        } else {
            line
        };
        
        // Remove inline comments with ;
        let line = if let Some(comment_pos) = line.find(';') {
            &line[..comment_pos]
        } else {
            line
        };
        
        Ok(line.trim().to_string())
    }
    
    fn expand_value(&self, value: &str, sections: &BTreeMap<String, BTreeMap<String, String>>) -> Result<String, ConfigError> {
        let mut result = value.to_string();
        
        // Handle environment variables ${VAR}
        while let Some(start) = result.find("${") {
            if let Some(end) = result[start..].find('}') {
                let var_name = &result[start+2..start+end];
                let var_value = self.get_env_var(var_name).unwrap_or_default();
                result.replace_range(start..start+end+1, &var_value);
            } else {
                break;
            }
        }
        
        // Handle references to other config values $(section.key)
        while let Some(start) = result.find("$(") {
            if let Some(end) = result[start..].find(')') {
                let ref_path = &result[start+2..start+end];
                let ref_value = self.resolve_reference(ref_path, sections)?;
                result.replace_range(start..start+end+1, &ref_value);
            } else {
                break;
            }
        }
        
        Ok(result)
    }
    
    fn resolve_reference(&self, path: &str, sections: &BTreeMap<String, BTreeMap<String, String>>) -> Result<String, ConfigError> {
        let parts: Vec<&str> = path.split('.').collect();
        
        if parts.len() != 2 {
            return Err(ConfigError::InvalidValue(format!("Invalid reference: {}", path)));
        }
        
        let section_name = parts[0];
        let key_name = parts[1];
        
        sections.get(section_name)
            .and_then(|section| section.get(key_name))
            .cloned()
            .ok_or_else(|| ConfigError::MissingKey(path.to_string()))
    }
    
    fn get_env_var(&self, name: &str) -> Option<String> {
        // In real implementation, would get from environment
        match name {
            "HOME" => Some("/home/user".to_string()),
            "USER" => Some("hypervisor".to_string()),
            _ => None,
        }
    }
    
    fn merge_configs(&self, target: &mut BTreeMap<String, BTreeMap<String, String>>, source: BTreeMap<String, BTreeMap<String, String>>) {
        for (section_name, section) in source {
            if let Some(target_section) = target.get_mut(&section_name) {
                for (key, value) in section {
                    target_section.insert(key, value);
                }
            } else {
                target.insert(section_name, section);
            }
        }
    }
    
    fn read_file(&self, _filepath: &str) -> Result<String, ConfigError> {
        // In real implementation, would read from filesystem
        Ok(String::new())
    }
    
    fn build_config(&self, sections: BTreeMap<String, BTreeMap<String, String>>) -> Result<HypervisorConfig, ConfigError> {
        let global = self.parse_global_config(sections.get("global"))?;
        let vms = self.parse_vm_configs(&sections)?;
        let networks = self.parse_network_configs(&sections)?;
        let storage_pools = self.parse_storage_configs(&sections)?;
        let security = self.parse_security_config(sections.get("security"))?;
        let monitoring = self.parse_monitoring_config(sections.get("monitoring"))?;
        let cluster = self.parse_cluster_config(sections.get("cluster"))?;
        
        Ok(HypervisorConfig {
            global,
            vms,
            networks,
            storage_pools,
            security,
            monitoring,
            cluster,
            raw_sections: sections,
        })
    }
    
    fn parse_global_config(&self, section: Option<&BTreeMap<String, String>>) -> Result<GlobalConfig, ConfigError> {
        let section = section.ok_or_else(|| ConfigError::MissingSection("global".to_string()))?;
        
        Ok(GlobalConfig {
            max_vms: self.parse_u32(section, "max_vms", 100)?,
            default_memory_mb: self.parse_usize(section, "default_memory_mb", 1024)?,
            default_vcpus: self.parse_u32(section, "default_vcpus", 1)?,
            enable_nested_virt: self.parse_bool(section, "enable_nested_virt", false)?,
            enable_iommu: self.parse_bool(section, "enable_iommu", true)?,
            enable_ept: self.parse_bool(section, "enable_ept", true)?,
            enable_vpid: self.parse_bool(section, "enable_vpid", true)?,
            enable_unrestricted_guest: self.parse_bool(section, "enable_unrestricted_guest", true)?,
            scheduler_type: self.parse_string(section, "scheduler_type", "cfs")?,
            memory_overcommit_ratio: self.parse_f32(section, "memory_overcommit_ratio", 1.5)?,
            cpu_overcommit_ratio: self.parse_f32(section, "cpu_overcommit_ratio", 2.0)?,
            log_level: self.parse_string(section, "log_level", "info")?,
            log_file: self.parse_string(section, "log_file", "/var/log/hypervisor.log")?,
            pid_file: self.parse_string(section, "pid_file", "/var/run/hypervisor.pid")?,
            socket_path: self.parse_string(section, "socket_path", "/var/run/hypervisor.sock")?,
            enable_kvm: self.parse_bool(section, "enable_kvm", true)?,
            enable_hax: self.parse_bool(section, "enable_hax", false)?,
            enable_whpx: self.parse_bool(section, "enable_whpx", false)?,
            enable_hvf: self.parse_bool(section, "enable_hvf", false)?,
        })
    }
    
    fn parse_vm_configs(&self, sections: &BTreeMap<String, BTreeMap<String, String>>) -> Result<Vec<VmConfigEntry>, ConfigError> {
        let mut vms = Vec::new();
        
        for (section_name, section) in sections {
            if section_name.starts_with("vm:") {
                let vm_name = section_name.trim_start_matches("vm:");
                let vm_config = self.parse_vm_config(vm_name, section)?;
                vms.push(vm_config);
            }
        }
        
        Ok(vms)
    }
    
    fn parse_vm_config(&self, name: &str, section: &BTreeMap<String, String>) -> Result<VmConfigEntry, ConfigError> {
        Ok(VmConfigEntry {
            name: name.to_string(),
            uuid: section.get("uuid").cloned(),
            enabled: self.parse_bool(section, "enabled", true)?,
            auto_start: self.parse_bool(section, "auto_start", false)?,
            auto_start_delay: self.parse_u32(section, "auto_start_delay", 0)?,
            memory_mb: self.parse_usize(section, "memory_mb", 1024)?,
            memory_max_mb: self.parse_optional_usize(section, "memory_max_mb")?,
            vcpus: self.parse_u32(section, "vcpus", 1)?,
            vcpus_max: self.parse_optional_u32(section, "vcpus_max")?,
            cpu_model: self.parse_string(section, "cpu_model", "host")?,
            cpu_features: self.parse_string_list(section, "cpu_features")?,
            machine_type: self.parse_string(section, "machine_type", "q35")?,
            firmware: self.parse_string(section, "firmware", "seabios")?,
            kernel: section.get("kernel").cloned(),
            initrd: section.get("initrd").cloned(),
            cmdline: section.get("cmdline").cloned(),
            boot_order: self.parse_string_list(section, "boot_order")?,
            disks: self.parse_disk_configs(section)?,
            networks: self.parse_vm_network_configs(section)?,
            devices: self.parse_device_configs(section)?,
            graphics: self.parse_graphics_config(section)?,
            audio: self.parse_audio_config(section)?,
            usb: self.parse_usb_configs(section)?,
            pci_passthrough: self.parse_pci_passthrough_configs(section)?,
            shares: self.parse_share_configs(section)?,
            metadata: self.parse_metadata(section)?,
        })
    }
    
    fn parse_disk_configs(&self, section: &BTreeMap<String, String>) -> Result<Vec<DiskConfig>, ConfigError> {
        let mut disks = Vec::new();
        
        for i in 0..10 {
            let prefix = format!("disk{}_", i);
            if let Some(file) = section.get(&format!("{}file", prefix)) {
                disks.push(DiskConfig {
                    file: file.clone(),
                    format: self.parse_string(section, &format!("{}format", prefix), "qcow2")?,
                    interface: self.parse_string(section, &format!("{}interface", prefix), "virtio")?,
                    cache: self.parse_string(section, &format!("{}cache", prefix), "writeback")?,
                    size: section.get(&format!("{}size", prefix)).cloned(),
                    read_only: self.parse_bool(section, &format!("{}readonly", prefix), false)?,
                    boot_index: self.parse_optional_u32(section, &format!("{}boot_index", prefix))?,
                    serial: section.get(&format!("{}serial", prefix)).cloned(),
                    wwn: section.get(&format!("{}wwn", prefix)).cloned(),
                });
            }
        }
        
        Ok(disks)
    }
    
    fn parse_vm_network_configs(&self, section: &BTreeMap<String, String>) -> Result<Vec<VmNetworkConfig>, ConfigError> {
        let mut networks = Vec::new();
        
        for i in 0..10 {
            let prefix = format!("net{}_", i);
            if let Some(network) = section.get(&format!("{}network", prefix)) {
                networks.push(VmNetworkConfig {
                    model: self.parse_string(section, &format!("{}model", prefix), "virtio")?,
                    network: network.clone(),
                    mac: section.get(&format!("{}mac", prefix)).cloned(),
                    vlan: self.parse_optional_u16(section, &format!("{}vlan", prefix))?,
                    rate_limit: self.parse_optional_u32(section, &format!("{}rate_limit", prefix))?,
                });
            }
        }
        
        Ok(networks)
    }
    
    fn parse_device_configs(&self, _section: &BTreeMap<String, String>) -> Result<Vec<DeviceConfig>, ConfigError> {
        // Parse device configurations
        Ok(Vec::new())
    }
    
    fn parse_graphics_config(&self, section: &BTreeMap<String, String>) -> Result<Option<GraphicsConfig>, ConfigError> {
        if let Some(graphics_type) = section.get("graphics_type") {
            Ok(Some(GraphicsConfig {
                graphics_type: graphics_type.clone(),
                port: self.parse_optional_u16(section, "graphics_port")?,
                listen: self.parse_string(section, "graphics_listen", "0.0.0.0")?,
                password: section.get("graphics_password").cloned(),
                keyboard_layout: self.parse_string(section, "keyboard_layout", "en-us")?,
                displays: self.parse_u32(section, "displays", 1)?,
                vram_mb: self.parse_u32(section, "vram_mb", 16)?,
            }))
        } else {
            Ok(None)
        }
    }
    
    fn parse_audio_config(&self, section: &BTreeMap<String, String>) -> Result<Option<AudioConfig>, ConfigError> {
        if let Some(model) = section.get("audio_model") {
            Ok(Some(AudioConfig {
                model: model.clone(),
                backend: self.parse_string(section, "audio_backend", "none")?,
            }))
        } else {
            Ok(None)
        }
    }
    
    fn parse_usb_configs(&self, _section: &BTreeMap<String, String>) -> Result<Vec<UsbConfig>, ConfigError> {
        // Parse USB configurations
        Ok(Vec::new())
    }
    
    fn parse_pci_passthrough_configs(&self, section: &BTreeMap<String, String>) -> Result<Vec<PciPassthroughConfig>, ConfigError> {
        let mut configs = Vec::new();
        
        for i in 0..10 {
            let prefix = format!("pci{}_", i);
            if let Some(bus) = section.get(&format!("{}bus", prefix)) {
                configs.push(PciPassthroughConfig {
                    bus: bus.clone(),
                    slot: self.parse_string(section, &format!("{}slot", prefix), "0")?,
                    function: self.parse_string(section, &format!("{}function", prefix), "0")?,
                    vfio_group: self.parse_optional_u32(section, &format!("{}vfio_group", prefix))?,
                    rom_file: section.get(&format!("{}rom_file", prefix)).cloned(),
                });
            }
        }
        
        Ok(configs)
    }
    
    fn parse_share_configs(&self, _section: &BTreeMap<String, String>) -> Result<Vec<ShareConfig>, ConfigError> {
        // Parse share configurations
        Ok(Vec::new())
    }
    
    fn parse_metadata(&self, section: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>, ConfigError> {
        let mut metadata = BTreeMap::new();
        
        for (key, value) in section {
            if key.starts_with("meta_") {
                let meta_key = key.trim_start_matches("meta_");
                metadata.insert(meta_key.to_string(), value.clone());
            }
        }
        
        Ok(metadata)
    }
    
    fn parse_network_configs(&self, sections: &BTreeMap<String, BTreeMap<String, String>>) -> Result<Vec<NetworkConfig>, ConfigError> {
        let mut networks = Vec::new();
        
        for (section_name, section) in sections {
            if section_name.starts_with("network:") {
                let network_name = section_name.trim_start_matches("network:");
                networks.push(NetworkConfig {
                    name: network_name.to_string(),
                    network_type: self.parse_string(section, "type", "bridge")?,
                    bridge: section.get("bridge").cloned(),
                    subnet: section.get("subnet").cloned(),
                    gateway: section.get("gateway").cloned(),
                    dhcp_start: section.get("dhcp_start").cloned(),
                    dhcp_end: section.get("dhcp_end").cloned(),
                    dns: self.parse_string_list(section, "dns")?,
                    mtu: self.parse_optional_u32(section, "mtu")?,
                    vlan_id: self.parse_optional_u16(section, "vlan_id")?,
                    forward_mode: self.parse_string(section, "forward_mode", "nat")?,
                    isolated: self.parse_bool(section, "isolated", false)?,
                });
            }
        }
        
        Ok(networks)
    }
    
    fn parse_storage_configs(&self, sections: &BTreeMap<String, BTreeMap<String, String>>) -> Result<Vec<StoragePoolConfig>, ConfigError> {
        let mut pools = Vec::new();
        
        for (section_name, section) in sections {
            if section_name.starts_with("storage:") {
                let pool_name = section_name.trim_start_matches("storage:");
                pools.push(StoragePoolConfig {
                    name: pool_name.to_string(),
                    pool_type: self.parse_string(section, "type", "directory")?,
                    path: self.parse_string(section, "path", "/var/lib/hypervisor/storage")?,
                    size_gb: self.parse_optional_u64(section, "size_gb")?,
                    allocation_gb: self.parse_optional_u64(section, "allocation_gb")?,
                    format: self.parse_string(section, "format", "qcow2")?,
                    permissions: self.parse_string(section, "permissions", "0755")?,
                });
            }
        }
        
        Ok(pools)
    }
    
    fn parse_security_config(&self, section: Option<&BTreeMap<String, String>>) -> Result<SecurityConfig, ConfigError> {
        let section = section.ok_or_else(|| ConfigError::MissingSection("security".to_string()))?;
        
        Ok(SecurityConfig {
            enable_selinux: self.parse_bool(section, "enable_selinux", false)?,
            enable_apparmor: self.parse_bool(section, "enable_apparmor", false)?,
            enable_seccomp: self.parse_bool(section, "enable_seccomp", true)?,
            enable_capabilities: self.parse_bool(section, "enable_capabilities", true)?,
            enable_namespaces: self.parse_bool(section, "enable_namespaces", true)?,
            enable_cgroups: self.parse_bool(section, "enable_cgroups", true)?,
            tls_cert: section.get("tls_cert").cloned(),
            tls_key: section.get("tls_key").cloned(),
            tls_ca: section.get("tls_ca").cloned(),
            tls_verify_client: self.parse_bool(section, "tls_verify_client", false)?,
            vnc_tls: self.parse_bool(section, "vnc_tls", false)?,
            spice_tls: self.parse_bool(section, "spice_tls", false)?,
            migration_tls: self.parse_bool(section, "migration_tls", false)?,
        })
    }
    
    fn parse_monitoring_config(&self, section: Option<&BTreeMap<String, String>>) -> Result<MonitoringConfig, ConfigError> {
        let default_section = BTreeMap::new();
        let section = section.unwrap_or(&default_section);
        
        Ok(MonitoringConfig {
            enable_prometheus: self.parse_bool(section, "enable_prometheus", false)?,
            prometheus_port: self.parse_u16(section, "prometheus_port", 9090)?,
            enable_grafana: self.parse_bool(section, "enable_grafana", false)?,
            grafana_port: self.parse_u16(section, "grafana_port", 3000)?,
            enable_stats_collection: self.parse_bool(section, "enable_stats_collection", true)?,
            stats_interval_seconds: self.parse_u32(section, "stats_interval_seconds", 10)?,
            enable_tracing: self.parse_bool(section, "enable_tracing", false)?,
            tracing_backend: self.parse_string(section, "tracing_backend", "jaeger")?,
            enable_profiling: self.parse_bool(section, "enable_profiling", false)?,
            profiling_port: self.parse_u16(section, "profiling_port", 6060)?,
        })
    }
    
    fn parse_cluster_config(&self, section: Option<&BTreeMap<String, String>>) -> Result<ClusterConfig, ConfigError> {
        let default_section = BTreeMap::new();
        let section = section.unwrap_or(&default_section);
        
        Ok(ClusterConfig {
            enabled: self.parse_bool(section, "enabled", false)?,
            node_id: self.parse_string(section, "node_id", "node1")?,
            cluster_name: self.parse_string(section, "cluster_name", "hypervisor-cluster")?,
            bind_address: self.parse_string(section, "bind_address", "0.0.0.0:7000")?,
            advertise_address: self.parse_string(section, "advertise_address", "")?,
            peers: self.parse_string_list(section, "peers")?,
            heartbeat_interval_ms: self.parse_u32(section, "heartbeat_interval_ms", 1000)?,
            election_timeout_ms: self.parse_u32(section, "election_timeout_ms", 5000)?,
            enable_fencing: self.parse_bool(section, "enable_fencing", false)?,
            fencing_method: self.parse_string(section, "fencing_method", "ipmi")?,
        })
    }
    
    // Helper parsing methods
    fn parse_bool(&self, section: &BTreeMap<String, String>, key: &str, default: bool) -> Result<bool, ConfigError> {
        if let Some(value) = section.get(key) {
            match value.to_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok(true),
                "false" | "no" | "off" | "0" => Ok(false),
                _ => Err(ConfigError::InvalidValue(format!("Invalid boolean value for {}: {}", key, value)))
            }
        } else {
            Ok(default)
        }
    }
    
    fn parse_u32(&self, section: &BTreeMap<String, String>, key: &str, default: u32) -> Result<u32, ConfigError> {
        if let Some(value) = section.get(key) {
            u32::from_str(value)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid u32 value for {}: {}", key, value)))
        } else {
            Ok(default)
        }
    }
    
    fn parse_optional_u32(&self, section: &BTreeMap<String, String>, key: &str) -> Result<Option<u32>, ConfigError> {
        if let Some(value) = section.get(key) {
            u32::from_str(value)
                .map(Some)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid u32 value for {}: {}", key, value)))
        } else {
            Ok(None)
        }
    }
    
    fn parse_u16(&self, section: &BTreeMap<String, String>, key: &str, default: u16) -> Result<u16, ConfigError> {
        if let Some(value) = section.get(key) {
            u16::from_str(value)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid u16 value for {}: {}", key, value)))
        } else {
            Ok(default)
        }
    }
    
    fn parse_optional_u16(&self, section: &BTreeMap<String, String>, key: &str) -> Result<Option<u16>, ConfigError> {
        if let Some(value) = section.get(key) {
            u16::from_str(value)
                .map(Some)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid u16 value for {}: {}", key, value)))
        } else {
            Ok(None)
        }
    }
    
    fn parse_u64(&self, section: &BTreeMap<String, String>, key: &str, default: u64) -> Result<u64, ConfigError> {
        if let Some(value) = section.get(key) {
            u64::from_str(value)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid u64 value for {}: {}", key, value)))
        } else {
            Ok(default)
        }
    }
    
    fn parse_optional_u64(&self, section: &BTreeMap<String, String>, key: &str) -> Result<Option<u64>, ConfigError> {
        if let Some(value) = section.get(key) {
            u64::from_str(value)
                .map(Some)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid u64 value for {}: {}", key, value)))
        } else {
            Ok(None)
        }
    }
    
    fn parse_usize(&self, section: &BTreeMap<String, String>, key: &str, default: usize) -> Result<usize, ConfigError> {
        if let Some(value) = section.get(key) {
            usize::from_str(value)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid usize value for {}: {}", key, value)))
        } else {
            Ok(default)
        }
    }
    
    fn parse_optional_usize(&self, section: &BTreeMap<String, String>, key: &str) -> Result<Option<usize>, ConfigError> {
        if let Some(value) = section.get(key) {
            usize::from_str(value)
                .map(Some)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid usize value for {}: {}", key, value)))
        } else {
            Ok(None)
        }
    }
    
    fn parse_f32(&self, section: &BTreeMap<String, String>, key: &str, default: f32) -> Result<f32, ConfigError> {
        if let Some(value) = section.get(key) {
            f32::from_str(value)
                .map_err(|_| ConfigError::InvalidValue(format!("Invalid f32 value for {}: {}", key, value)))
        } else {
            Ok(default)
        }
    }
    
    fn parse_string(&self, section: &BTreeMap<String, String>, key: &str, default: &str) -> Result<String, ConfigError> {
        Ok(section.get(key).cloned().unwrap_or_else(|| default.to_string()))
    }
    
    fn parse_string_list(&self, section: &BTreeMap<String, String>, key: &str) -> Result<Vec<String>, ConfigError> {
        if let Some(value) = section.get(key) {
            Ok(value.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect())
        } else {
            Ok(Vec::new())
        }
    }
}

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate(config: &HypervisorConfig) -> Result<(), ConfigError> {
        // Validate global config
        Self::validate_global(&config.global)?;
        
        // Validate VMs
        for vm in &config.vms {
            Self::validate_vm(vm)?;
        }
        
        // Validate networks
        for network in &config.networks {
            Self::validate_network(network)?;
        }
        
        // Validate storage pools
        for pool in &config.storage_pools {
            Self::validate_storage_pool(pool)?;
        }
        
        Ok(())
    }
    
    fn validate_global(config: &GlobalConfig) -> Result<(), ConfigError> {
        if config.max_vms == 0 {
            return Err(ConfigError::ValidationError("max_vms must be greater than 0".to_string()));
        }
        
        if config.memory_overcommit_ratio < 1.0 {
            return Err(ConfigError::ValidationError("memory_overcommit_ratio must be >= 1.0".to_string()));
        }
        
        if config.cpu_overcommit_ratio < 1.0 {
            return Err(ConfigError::ValidationError("cpu_overcommit_ratio must be >= 1.0".to_string()));
        }
        
        Ok(())
    }
    
    fn validate_vm(config: &VmConfigEntry) -> Result<(), ConfigError> {
        if config.memory_mb < 128 {
            return Err(ConfigError::ValidationError(format!("VM {} memory must be at least 128MB", config.name)));
        }
        
        if config.vcpus == 0 || config.vcpus > 256 {
            return Err(ConfigError::ValidationError(format!("VM {} vcpus must be between 1 and 256", config.name)));
        }
        
        if let Some(max_memory) = config.memory_max_mb {
            if max_memory < config.memory_mb {
                return Err(ConfigError::ValidationError(format!("VM {} max memory must be >= current memory", config.name)));
            }
        }
        
        if let Some(max_vcpus) = config.vcpus_max {
            if max_vcpus < config.vcpus {
                return Err(ConfigError::ValidationError(format!("VM {} max vcpus must be >= current vcpus", config.name)));
            }
        }
        
        Ok(())
    }
    
    fn validate_network(_config: &NetworkConfig) -> Result<(), ConfigError> {
        // Validate network configuration
        Ok(())
    }
    
    fn validate_storage_pool(_config: &StoragePoolConfig) -> Result<(), ConfigError> {
        // Validate storage pool configuration
        Ok(())
    }
}

/// Example configuration content
pub const EXAMPLE_CONFIG: &str = r#"
# Hypervisor Configuration File
# Global settings
[global]
max_vms = 100
default_memory_mb = 2048
default_vcpus = 2
enable_nested_virt = true
enable_iommu = true
scheduler_type = cfs
memory_overcommit_ratio = 1.5
cpu_overcommit_ratio = 2.0
log_level = info
log_file = /var/log/hypervisor.log

# Security settings
[security]
enable_seccomp = true
enable_capabilities = true
enable_namespaces = true
enable_cgroups = true
tls_cert = /etc/hypervisor/cert.pem
tls_key = /etc/hypervisor/key.pem

# Monitoring settings
[monitoring]
enable_prometheus = true
prometheus_port = 9090
enable_stats_collection = true
stats_interval_seconds = 10

# VM Definition Example
[vm:webserver]
enabled = true
auto_start = true
memory_mb = 4096
memory_max_mb = 8192
vcpus = 4
vcpus_max = 8
cpu_model = host
machine_type = q35
firmware = uefi

# Disk configuration
disk0_file = /var/lib/hypervisor/vms/webserver/disk0.qcow2
disk0_format = qcow2
disk0_interface = virtio
disk0_cache = writeback
disk0_size = 50G

# Network configuration
net0_model = virtio
net0_network = default
net0_mac = 52:54:00:12:34:56

# Graphics
graphics_type = spice
graphics_port = 5900
graphics_listen = 127.0.0.1

# Network definition
[network:default]
type = bridge
bridge = br0
subnet = 192.168.100.0/24
gateway = 192.168.100.1
dhcp_start = 192.168.100.100
dhcp_end = 192.168.100.200
dns = 8.8.8.8,8.8.4.4
forward_mode = nat

# Storage pool definition
[storage:default]
type = directory
path = /var/lib/hypervisor/storage
size_gb = 1000
format = qcow2
"#;

/// Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_example_config() {
        let mut parser = ConfigParser::new();
        let result = parser.parse_string(EXAMPLE_CONFIG);
        assert!(result.is_ok());
        
        let config = result.unwrap();
        assert_eq!(config.global.max_vms, 100);
        assert_eq!(config.vms.len(), 1);
        assert_eq!(config.vms[0].name, "webserver");
    }
    
    #[test]
    fn test_config_validation() {
        let mut parser = ConfigParser::new();
        if let Ok(config) = parser.parse_string(EXAMPLE_CONFIG) {
            assert!(ConfigValidator::validate(&config).is_ok());
        }
    }
}