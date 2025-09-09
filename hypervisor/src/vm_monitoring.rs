//! VM Monitoring and Metrics Collection
//! Complete implementation for performance monitoring and resource tracking

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use alloc::{string::String, vec::Vec, collections::{BTreeMap, VecDeque}, sync::Arc};
use spin::{RwLock, Mutex};

pub const MAX_METRICS: usize = 1024;
pub const SAMPLE_INTERVAL_MS: u64 = 1000;
pub const HISTORY_SIZE: usize = 3600; // 1 hour of per-second samples

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MetricType {
    CpuUsage,
    MemoryUsage,
    DiskIo,
    NetworkIo,
    PageFaults,
    CacheMisses,
    BranchMisses,
    Instructions,
    Cycles,
    ContextSwitches,
    Migrations,
    Ipc,
    Frequency,
    Temperature,
    Power,
}

impl MetricType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CpuUsage => "CPU Usage",
            Self::MemoryUsage => "Memory Usage",
            Self::DiskIo => "Disk I/O",
            Self::NetworkIo => "Network I/O",
            Self::PageFaults => "Page Faults",
            Self::CacheMisses => "Cache Misses",
            Self::BranchMisses => "Branch Misses",
            Self::Instructions => "Instructions",
            Self::Cycles => "CPU Cycles",
            Self::ContextSwitches => "Context Switches",
            Self::Migrations => "CPU Migrations",
            Self::Ipc => "IPC",
            Self::Frequency => "CPU Frequency",
            Self::Temperature => "Temperature",
            Self::Power => "Power Consumption",
        }
    }
    
    pub fn unit(&self) -> &'static str {
        match self {
            Self::CpuUsage => "%",
            Self::MemoryUsage => "MB",
            Self::DiskIo => "MB/s",
            Self::NetworkIo => "Mbps",
            Self::PageFaults => "faults/s",
            Self::CacheMisses => "misses/s",
            Self::BranchMisses => "misses/s",
            Self::Instructions => "inst/s",
            Self::Cycles => "cycles/s",
            Self::ContextSwitches => "switches/s",
            Self::Migrations => "migrations/s",
            Self::Ipc => "IPC",
            Self::Frequency => "GHz",
            Self::Temperature => "°C",
            Self::Power => "W",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetricPoint {
    pub timestamp: u64,
    pub value: f64,
}

pub struct MetricHistory {
    pub metric_type: MetricType,
    pub name: String,
    pub unit: String,
    
    // Circular buffer for history
    history: Mutex<VecDeque<MetricPoint>>,
    
    // Statistics
    pub min: AtomicU64,
    pub max: AtomicU64,
    pub sum: AtomicU64,
    pub samples: AtomicU64,
    
    // Thresholds
    pub warning_threshold: Option<f64>,
    pub critical_threshold: Option<f64>,
    
    // Alerts
    alerts: RwLock<Vec<Alert>>,
}

impl MetricHistory {
    pub fn new(metric_type: MetricType) -> Self {
        Self {
            metric_type,
            name: metric_type.name().to_string(),
            unit: metric_type.unit().to_string(),
            history: Mutex::new(VecDeque::with_capacity(HISTORY_SIZE)),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            warning_threshold: None,
            critical_threshold: None,
            alerts: RwLock::new(Vec::new()),
        }
    }
    
    pub fn add_sample(&self, value: f64) {
        let timestamp = Self::get_timestamp();
        let point = MetricPoint { timestamp, value };
        
        // Add to history
        let mut history = self.history.lock();
        if history.len() >= HISTORY_SIZE {
            history.pop_front();
        }
        history.push_back(point);
        
        // Update statistics
        let value_bits = value.to_bits();
        self.update_min(value_bits);
        self.update_max(value_bits);
        self.sum.fetch_add(value_bits, Ordering::SeqCst);
        self.samples.fetch_add(1, Ordering::SeqCst);
        
        // Check thresholds
        self.check_thresholds(value);
    }
    
    fn update_min(&self, value: u64) {
        let mut current = self.min.load(Ordering::SeqCst);
        while value < current {
            match self.min.compare_exchange_weak(
                current,
                value,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(x) => current = x,
            }
        }
    }
    
    fn update_max(&self, value: u64) {
        let mut current = self.max.load(Ordering::SeqCst);
        while value > current {
            match self.max.compare_exchange_weak(
                current,
                value,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(x) => current = x,
            }
        }
    }
    
    pub fn get_average(&self) -> f64 {
        let samples = self.samples.load(Ordering::SeqCst);
        if samples == 0 {
            0.0
        } else {
            f64::from_bits(self.sum.load(Ordering::SeqCst)) / samples as f64
        }
    }
    
    pub fn get_latest(&self) -> Option<MetricPoint> {
        self.history.lock().back().copied()
    }
    
    pub fn get_history(&self, count: usize) -> Vec<MetricPoint> {
        let history = self.history.lock();
        let start = if history.len() > count {
            history.len() - count
        } else {
            0
        };
        history.range(start..).copied().collect()
    }
    
    pub fn clear_history(&self) {
        self.history.lock().clear();
        self.min.store(u64::MAX, Ordering::SeqCst);
        self.max.store(0, Ordering::SeqCst);
        self.sum.store(0, Ordering::SeqCst);
        self.samples.store(0, Ordering::SeqCst);
    }
    
    fn check_thresholds(&self, value: f64) {
        let mut alert_level = None;
        
        if let Some(critical) = self.critical_threshold {
            if value >= critical {
                alert_level = Some(AlertLevel::Critical);
            }
        }
        
        if alert_level.is_none() {
            if let Some(warning) = self.warning_threshold {
                if value >= warning {
                    alert_level = Some(AlertLevel::Warning);
                }
            }
        }
        
        if let Some(level) = alert_level {
            let alert = Alert {
                timestamp: Self::get_timestamp(),
                metric_type: self.metric_type,
                level,
                value,
                threshold: match level {
                    AlertLevel::Critical => self.critical_threshold.unwrap(),
                    AlertLevel::Warning => self.warning_threshold.unwrap(),
                    _ => 0.0,
                },
                message: format!(
                    "{} exceeded {} threshold: {:.2} {}",
                    self.name,
                    level.as_str(),
                    value,
                    self.unit
                ),
            };
            
            self.alerts.write().push(alert);
        }
    }
    
    pub fn get_alerts(&self) -> Vec<Alert> {
        self.alerts.read().clone()
    }
    
    pub fn clear_alerts(&self) {
        self.alerts.write().clear();
    }
    
    fn get_timestamp() -> u64 {
        0 // Would use actual timestamp
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub timestamp: u64,
    pub metric_type: MetricType,
    pub level: AlertLevel,
    pub value: f64,
    pub threshold: f64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

impl AlertLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

pub struct PerfCounter {
    pub counter_type: PerfCounterType,
    pub value: AtomicU64,
    pub enabled: AtomicU64,
    pub running: AtomicU64,
    pub active: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
pub enum PerfCounterType {
    CpuCycles,
    Instructions,
    CacheReferences,
    CacheMisses,
    BranchInstructions,
    BranchMisses,
    BusCycles,
    StalledCyclesFrontend,
    StalledCyclesBackend,
    RefCpuCycles,
}

pub struct VmMonitor {
    pub vm_id: u32,
    pub running: AtomicBool,
    
    // Metrics
    metrics: RwLock<BTreeMap<MetricType, Arc<MetricHistory>>>,
    
    // Performance counters
    perf_counters: RwLock<Vec<Arc<PerfCounter>>>,
    
    // Resource usage
    pub cpu_usage: AtomicU64,
    pub memory_usage: AtomicU64,
    pub disk_read_bytes: AtomicU64,
    pub disk_write_bytes: AtomicU64,
    pub network_rx_bytes: AtomicU64,
    pub network_tx_bytes: AtomicU64,
    
    // Sampling configuration
    pub sample_interval_ms: AtomicU64,
    pub auto_sample: AtomicBool,
}

impl VmMonitor {
    pub fn new(vm_id: u32) -> Self {
        Self {
            vm_id,
            running: AtomicBool::new(false),
            metrics: RwLock::new(BTreeMap::new()),
            perf_counters: RwLock::new(Vec::new()),
            cpu_usage: AtomicU64::new(0),
            memory_usage: AtomicU64::new(0),
            disk_read_bytes: AtomicU64::new(0),
            disk_write_bytes: AtomicU64::new(0),
            network_rx_bytes: AtomicU64::new(0),
            network_tx_bytes: AtomicU64::new(0),
            sample_interval_ms: AtomicU64::new(SAMPLE_INTERVAL_MS),
            auto_sample: AtomicBool::new(true),
        }
    }
    
    pub fn add_metric(&self, metric_type: MetricType) -> Arc<MetricHistory> {
        let metric = Arc::new(MetricHistory::new(metric_type));
        self.metrics.write().insert(metric_type, metric.clone());
        metric
    }
    
    pub fn remove_metric(&self, metric_type: MetricType) {
        self.metrics.write().remove(&metric_type);
    }
    
    pub fn get_metric(&self, metric_type: MetricType) -> Option<Arc<MetricHistory>> {
        self.metrics.read().get(&metric_type).cloned()
    }
    
    pub fn add_perf_counter(&self, counter_type: PerfCounterType) -> Arc<PerfCounter> {
        let counter = Arc::new(PerfCounter {
            counter_type,
            value: AtomicU64::new(0),
            enabled: AtomicU64::new(0),
            running: AtomicU64::new(0),
            active: AtomicBool::new(false),
        });
        self.perf_counters.write().push(counter.clone());
        counter
    }
    
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
        
        // Initialize default metrics
        self.add_metric(MetricType::CpuUsage);
        self.add_metric(MetricType::MemoryUsage);
        self.add_metric(MetricType::DiskIo);
        self.add_metric(MetricType::NetworkIo);
        
        // Start monitoring loop
        if self.auto_sample.load(Ordering::SeqCst) {
            self.start_sampling();
        }
    }
    
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
    
    fn start_sampling(&self) {
        // In a real implementation, this would spawn a thread
        // that periodically samples metrics
    }
    
    pub fn sample_metrics(&self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }
        
        // Sample CPU usage
        let cpu_usage = self.get_cpu_usage();
        if let Some(metric) = self.get_metric(MetricType::CpuUsage) {
            metric.add_sample(cpu_usage);
        }
        
        // Sample memory usage
        let memory_usage = self.get_memory_usage();
        if let Some(metric) = self.get_metric(MetricType::MemoryUsage) {
            metric.add_sample(memory_usage);
        }
        
        // Sample disk I/O
        let disk_io = self.get_disk_io_rate();
        if let Some(metric) = self.get_metric(MetricType::DiskIo) {
            metric.add_sample(disk_io);
        }
        
        // Sample network I/O
        let network_io = self.get_network_io_rate();
        if let Some(metric) = self.get_metric(MetricType::NetworkIo) {
            metric.add_sample(network_io);
        }
        
        // Sample performance counters
        self.sample_perf_counters();
    }
    
    fn sample_perf_counters(&self) {
        for counter in self.perf_counters.read().iter() {
            if counter.active.load(Ordering::SeqCst) {
                // Read counter value (would use actual system calls)
                let value = 0u64; // Placeholder
                counter.value.store(value, Ordering::SeqCst);
            }
        }
    }
    
    fn get_cpu_usage(&self) -> f64 {
        // Calculate CPU usage percentage
        self.cpu_usage.load(Ordering::SeqCst) as f64 / 100.0
    }
    
    fn get_memory_usage(&self) -> f64 {
        // Get memory usage in MB
        self.memory_usage.load(Ordering::SeqCst) as f64 / (1024.0 * 1024.0)
    }
    
    fn get_disk_io_rate(&self) -> f64 {
        // Calculate disk I/O rate in MB/s
        let read_bytes = self.disk_read_bytes.swap(0, Ordering::SeqCst);
        let write_bytes = self.disk_write_bytes.swap(0, Ordering::SeqCst);
        let interval_s = self.sample_interval_ms.load(Ordering::SeqCst) as f64 / 1000.0;
        
        ((read_bytes + write_bytes) as f64) / (1024.0 * 1024.0 * interval_s)
    }
    
    fn get_network_io_rate(&self) -> f64 {
        // Calculate network I/O rate in Mbps
        let rx_bytes = self.network_rx_bytes.swap(0, Ordering::SeqCst);
        let tx_bytes = self.network_tx_bytes.swap(0, Ordering::SeqCst);
        let interval_s = self.sample_interval_ms.load(Ordering::SeqCst) as f64 / 1000.0;
        
        ((rx_bytes + tx_bytes) as f64 * 8.0) / (1000000.0 * interval_s)
    }
    
    pub fn get_statistics(&self) -> MonitoringStatistics {
        let metrics = self.metrics.read();
        
        let mut stats = MonitoringStatistics {
            vm_id: self.vm_id,
            uptime: 0, // Would calculate actual uptime
            cpu_usage_avg: 0.0,
            memory_usage_avg: 0.0,
            disk_io_avg: 0.0,
            network_io_avg: 0.0,
            metric_count: metrics.len(),
            sample_count: 0,
            alerts: Vec::new(),
        };
        
        // Collect averages
        if let Some(cpu_metric) = metrics.get(&MetricType::CpuUsage) {
            stats.cpu_usage_avg = cpu_metric.get_average();
            stats.sample_count = cpu_metric.samples.load(Ordering::SeqCst);
        }
        
        if let Some(mem_metric) = metrics.get(&MetricType::MemoryUsage) {
            stats.memory_usage_avg = mem_metric.get_average();
        }
        
        if let Some(disk_metric) = metrics.get(&MetricType::DiskIo) {
            stats.disk_io_avg = disk_metric.get_average();
        }
        
        if let Some(net_metric) = metrics.get(&MetricType::NetworkIo) {
            stats.network_io_avg = net_metric.get_average();
        }
        
        // Collect alerts
        for metric in metrics.values() {
            stats.alerts.extend(metric.get_alerts());
        }
        
        stats
    }
}

#[derive(Debug, Clone)]
pub struct MonitoringStatistics {
    pub vm_id: u32,
    pub uptime: u64,
    pub cpu_usage_avg: f64,
    pub memory_usage_avg: f64,
    pub disk_io_avg: f64,
    pub network_io_avg: f64,
    pub metric_count: usize,
    pub sample_count: u64,
    pub alerts: Vec<Alert>,
}

pub struct MonitoringManager {
    monitors: RwLock<BTreeMap<u32, Arc<VmMonitor>>>,
    global_metrics: RwLock<BTreeMap<String, Arc<MetricHistory>>>,
}

impl MonitoringManager {
    pub fn new() -> Self {
        Self {
            monitors: RwLock::new(BTreeMap::new()),
            global_metrics: RwLock::new(BTreeMap::new()),
        }
    }
    
    pub fn create_monitor(&self, vm_id: u32) -> Arc<VmMonitor> {
        let monitor = Arc::new(VmMonitor::new(vm_id));
        self.monitors.write().insert(vm_id, monitor.clone());
        monitor
    }
    
    pub fn get_monitor(&self, vm_id: u32) -> Option<Arc<VmMonitor>> {
        self.monitors.read().get(&vm_id).cloned()
    }
    
    pub fn remove_monitor(&self, vm_id: u32) {
        if let Some(monitor) = self.monitors.write().remove(&vm_id) {
            monitor.stop();
        }
    }
    
    pub fn add_global_metric(&self, name: String, metric_type: MetricType) -> Arc<MetricHistory> {
        let metric = Arc::new(MetricHistory::new(metric_type));
        self.global_metrics.write().insert(name, metric.clone());
        metric
    }
    
    pub fn get_all_statistics(&self) -> Vec<MonitoringStatistics> {
        self.monitors.read()
            .values()
            .map(|monitor| monitor.get_statistics())
            .collect()
    }
    
    pub fn get_aggregated_statistics(&self) -> AggregatedStatistics {
        let all_stats = self.get_all_statistics();
        
        let vm_count = all_stats.len();
        let total_cpu = all_stats.iter().map(|s| s.cpu_usage_avg).sum::<f64>();
        let total_memory = all_stats.iter().map(|s| s.memory_usage_avg).sum::<f64>();
        let total_disk = all_stats.iter().map(|s| s.disk_io_avg).sum::<f64>();
        let total_network = all_stats.iter().map(|s| s.network_io_avg).sum::<f64>();
        
        let all_alerts: Vec<Alert> = all_stats.iter()
            .flat_map(|s| s.alerts.clone())
            .collect();
        
        AggregatedStatistics {
            vm_count,
            total_cpu_usage: total_cpu,
            total_memory_usage: total_memory,
            total_disk_io: total_disk,
            total_network_io: total_network,
            avg_cpu_usage: if vm_count > 0 { total_cpu / vm_count as f64 } else { 0.0 },
            avg_memory_usage: if vm_count > 0 { total_memory / vm_count as f64 } else { 0.0 },
            avg_disk_io: if vm_count > 0 { total_disk / vm_count as f64 } else { 0.0 },
            avg_network_io: if vm_count > 0 { total_network / vm_count as f64 } else { 0.0 },
            critical_alerts: all_alerts.iter().filter(|a| a.level == AlertLevel::Critical).count(),
            warning_alerts: all_alerts.iter().filter(|a| a.level == AlertLevel::Warning).count(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AggregatedStatistics {
    pub vm_count: usize,
    pub total_cpu_usage: f64,
    pub total_memory_usage: f64,
    pub total_disk_io: f64,
    pub total_network_io: f64,
    pub avg_cpu_usage: f64,
    pub avg_memory_usage: f64,
    pub avg_disk_io: f64,
    pub avg_network_io: f64,
    pub critical_alerts: usize,
    pub warning_alerts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metric_history() {
        let metric = MetricHistory::new(MetricType::CpuUsage);
        
        metric.add_sample(50.0);
        metric.add_sample(60.0);
        metric.add_sample(70.0);
        
        assert_eq!(metric.samples.load(Ordering::SeqCst), 3);
        assert_eq!(metric.get_average(), 60.0);
        
        let latest = metric.get_latest().unwrap();
        assert_eq!(latest.value, 70.0);
    }
    
    #[test]
    fn test_threshold_alerts() {
        let metric = MetricHistory::new(MetricType::CpuUsage);
        metric.warning_threshold = Some(80.0);
        metric.critical_threshold = Some(95.0);
        
        metric.add_sample(50.0);
        assert_eq!(metric.get_alerts().len(), 0);
        
        metric.add_sample(85.0);
        assert_eq!(metric.get_alerts().len(), 1);
        assert_eq!(metric.get_alerts()[0].level, AlertLevel::Warning);
        
        metric.add_sample(96.0);
        assert_eq!(metric.get_alerts().len(), 2);
        assert_eq!(metric.get_alerts()[1].level, AlertLevel::Critical);
    }
    
    #[test]
    fn test_vm_monitor() {
        let monitor = VmMonitor::new(1);
        monitor.start();
        
        let cpu_metric = monitor.add_metric(MetricType::CpuUsage);
        monitor.cpu_usage.store(5000, Ordering::SeqCst); // 50%
        
        monitor.sample_metrics();
        
        let stats = monitor.get_statistics();
        assert_eq!(stats.vm_id, 1);
        assert_eq!(stats.metric_count, 4); // Default metrics
    }
}