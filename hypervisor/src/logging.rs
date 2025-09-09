//! Comprehensive logging infrastructure for hypervisor
//! Supports multiple log levels, targets, formatting, and structured logging

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

/// Log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        }
    }
    
    pub fn color_code(&self) -> &'static str {
        match self {
            LogLevel::Trace => "\x1b[90m",    // Gray
            LogLevel::Debug => "\x1b[36m",    // Cyan
            LogLevel::Info => "\x1b[32m",     // Green
            LogLevel::Warn => "\x1b[33m",     // Yellow
            LogLevel::Error => "\x1b[31m",    // Red
            LogLevel::Fatal => "\x1b[35m",    // Magenta
        }
    }
}

impl From<&str> for LogLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "fatal" | "critical" => LogLevel::Fatal,
            _ => LogLevel::Info,
        }
    }
}

/// Log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub module: String,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub thread_id: u64,
    pub cpu_id: u32,
    pub vm_id: Option<u64>,
    pub fields: BTreeMap<String, String>,
}

impl LogEntry {
    pub fn new(
        level: LogLevel,
        module: &str,
        file: &str,
        line: u32,
        message: String,
    ) -> Self {
        Self {
            timestamp: Self::get_timestamp(),
            level,
            module: module.to_string(),
            file: file.to_string(),
            line,
            message,
            thread_id: Self::get_thread_id(),
            cpu_id: Self::get_cpu_id(),
            vm_id: None,
            fields: BTreeMap::new(),
        }
    }
    
    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }
    
    pub fn with_vm_id(mut self, vm_id: u64) -> Self {
        self.vm_id = Some(vm_id);
        self
    }
    
    fn get_timestamp() -> u64 {
        // Get current timestamp
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    
    fn get_thread_id() -> u64 {
        // Get current thread ID
        0
    }
    
    fn get_cpu_id() -> u32 {
        // Get current CPU ID
        0
    }
}

/// Log target trait
pub trait LogTarget: Send + Sync {
    fn write(&self, entry: &LogEntry);
    fn flush(&self);
    fn set_level(&self, level: LogLevel);
    fn is_enabled(&self) -> bool;
}

/// Console log target
pub struct ConsoleTarget {
    level: AtomicU32,
    enabled: AtomicBool,
    use_color: AtomicBool,
    buffer: Mutex<String>,
}

impl ConsoleTarget {
    pub fn new() -> Self {
        Self {
            level: AtomicU32::new(LogLevel::Info as u32),
            enabled: AtomicBool::new(true),
            use_color: AtomicBool::new(true),
            buffer: Mutex::new(String::with_capacity(4096)),
        }
    }
    
    pub fn set_use_color(&self, use_color: bool) {
        self.use_color.store(use_color, Ordering::SeqCst);
    }
}

impl LogTarget for ConsoleTarget {
    fn write(&self, entry: &LogEntry) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let level = self.level.load(Ordering::Relaxed);
        if entry.level < unsafe { core::mem::transmute(level as u8) } {
            return;
        }
        
        let mut buffer = self.buffer.lock();
        buffer.clear();
        
        let use_color = self.use_color.load(Ordering::Relaxed);
        
        if use_color {
            let _ = write!(buffer, "{}", entry.level.color_code());
        }
        
        // Format: [TIMESTAMP] [LEVEL] [MODULE] MESSAGE {fields}
        let _ = write!(
            buffer,
            "[{:016x}] [{}] [{}] ",
            entry.timestamp,
            entry.level.as_str(),
            entry.module
        );
        
        if let Some(vm_id) = entry.vm_id {
            let _ = write!(buffer, "[VM:{}] ", vm_id);
        }
        
        let _ = write!(buffer, "{}", entry.message);
        
        if !entry.fields.is_empty() {
            let _ = write!(buffer, " {{");
            for (i, (key, value)) in entry.fields.iter().enumerate() {
                if i > 0 {
                    let _ = write!(buffer, ", ");
                }
                let _ = write!(buffer, "{}={}", key, value);
            }
            let _ = write!(buffer, "}}");
        }
        
        let _ = write!(buffer, " ({}:{})", entry.file, entry.line);
        
        if use_color {
            let _ = write!(buffer, "\x1b[0m"); // Reset color
        }
        
        println!("{}", buffer);
    }
    
    fn flush(&self) {
        // Console is typically unbuffered
    }
    
    fn set_level(&self, level: LogLevel) {
        self.level.store(level as u32, Ordering::SeqCst);
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// File log target
pub struct FileTarget {
    path: String,
    level: AtomicU32,
    enabled: AtomicBool,
    buffer: Mutex<Vec<u8>>,
    buffer_size: AtomicUsize,
    max_size: AtomicU64,
    current_size: AtomicU64,
    rotation_count: AtomicU32,
}

impl FileTarget {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            level: AtomicU32::new(LogLevel::Info as u32),
            enabled: AtomicBool::new(true),
            buffer: Mutex::new(Vec::with_capacity(8192)),
            buffer_size: AtomicUsize::new(8192),
            max_size: AtomicU64::new(100 * 1024 * 1024), // 100MB
            current_size: AtomicU64::new(0),
            rotation_count: AtomicU32::new(5),
        }
    }
    
    pub fn set_max_size(&self, size: u64) {
        self.max_size.store(size, Ordering::SeqCst);
    }
    
    pub fn set_rotation_count(&self, count: u32) {
        self.rotation_count.store(count, Ordering::SeqCst);
    }
    
    fn rotate_if_needed(&self) {
        let current = self.current_size.load(Ordering::Relaxed);
        let max = self.max_size.load(Ordering::Relaxed);
        
        if current >= max {
            self.rotate_logs();
        }
    }
    
    fn rotate_logs(&self) {
        let count = self.rotation_count.load(Ordering::Relaxed);
        
        // Rotate log files: log.txt -> log.1.txt -> log.2.txt -> ...
        for i in (1..count).rev() {
            let old_name = if i == 1 {
                self.path.clone()
            } else {
                format!("{}.{}", self.path, i - 1)
            };
            let new_name = format!("{}.{}", self.path, i);
            
            // Rename file (in real implementation)
            let _ = Self::rename_file(&old_name, &new_name);
        }
        
        self.current_size.store(0, Ordering::SeqCst);
    }
    
    fn rename_file(_old: &str, _new: &str) -> Result<(), ()> {
        // File system operation
        Ok(())
    }
    
    fn write_to_file(&self, data: &[u8]) {
        // Write to file (in real implementation)
        self.current_size.fetch_add(data.len() as u64, Ordering::Relaxed);
    }
}

impl LogTarget for FileTarget {
    fn write(&self, entry: &LogEntry) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let level = self.level.load(Ordering::Relaxed);
        if entry.level < unsafe { core::mem::transmute(level as u8) } {
            return;
        }
        
        self.rotate_if_needed();
        
        let mut buffer = self.buffer.lock();
        buffer.clear();
        
        // Format as JSON for structured logging
        let _ = write!(buffer, "{{");
        let _ = write!(buffer, r#""timestamp":{}, "#, entry.timestamp);
        let _ = write!(buffer, r#""level":"{}", "#, entry.level.as_str());
        let _ = write!(buffer, r#""module":"{}", "#, entry.module);
        let _ = write!(buffer, r#""file":"{}", "#, entry.file);
        let _ = write!(buffer, r#""line":{}, "#, entry.line);
        let _ = write!(buffer, r#""message":"{}", "#, entry.message);
        let _ = write!(buffer, r#""thread_id":{}, "#, entry.thread_id);
        let _ = write!(buffer, r#""cpu_id":{}"#, entry.cpu_id);
        
        if let Some(vm_id) = entry.vm_id {
            let _ = write!(buffer, r#", "vm_id":{}"#, vm_id);
        }
        
        if !entry.fields.is_empty() {
            let _ = write!(buffer, r#", "fields":{{"#);
            for (i, (key, value)) in entry.fields.iter().enumerate() {
                if i > 0 {
                    let _ = write!(buffer, ", ");
                }
                let _ = write!(buffer, r#""{}":"{}""#, key, value);
            }
            let _ = write!(buffer, "}}");
        }
        
        let _ = writeln!(buffer, "}}");
        
        self.write_to_file(&buffer);
    }
    
    fn flush(&self) {
        // Flush buffer to file
    }
    
    fn set_level(&self, level: LogLevel) {
        self.level.store(level as u32, Ordering::SeqCst);
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Ring buffer log target for in-memory logging
pub struct RingBufferTarget {
    level: AtomicU32,
    enabled: AtomicBool,
    buffer: RwLock<VecDeque<LogEntry>>,
    max_entries: AtomicUsize,
}

impl RingBufferTarget {
    pub fn new(max_entries: usize) -> Self {
        Self {
            level: AtomicU32::new(LogLevel::Info as u32),
            enabled: AtomicBool::new(true),
            buffer: RwLock::new(VecDeque::with_capacity(max_entries)),
            max_entries: AtomicUsize::new(max_entries),
        }
    }
    
    pub fn get_entries(&self) -> Vec<LogEntry> {
        self.buffer.read().iter().cloned().collect()
    }
    
    pub fn clear(&self) {
        self.buffer.write().clear();
    }
}

impl LogTarget for RingBufferTarget {
    fn write(&self, entry: &LogEntry) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let level = self.level.load(Ordering::Relaxed);
        if entry.level < unsafe { core::mem::transmute(level as u8) } {
            return;
        }
        
        let mut buffer = self.buffer.write();
        let max = self.max_entries.load(Ordering::Relaxed);
        
        while buffer.len() >= max {
            buffer.pop_front();
        }
        
        buffer.push_back(entry.clone());
    }
    
    fn flush(&self) {
        // No-op for ring buffer
    }
    
    fn set_level(&self, level: LogLevel) {
        self.level.store(level as u32, Ordering::SeqCst);
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Syslog target for remote logging
pub struct SyslogTarget {
    server: String,
    facility: SyslogFacility,
    level: AtomicU32,
    enabled: AtomicBool,
    hostname: String,
    app_name: String,
}

#[derive(Debug, Clone, Copy)]
pub enum SyslogFacility {
    Kernel = 0,
    User = 1,
    System = 3,
    Daemon = 3,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl SyslogTarget {
    pub fn new(server: &str, facility: SyslogFacility) -> Self {
        Self {
            server: server.to_string(),
            facility,
            level: AtomicU32::new(LogLevel::Info as u32),
            enabled: AtomicBool::new(true),
            hostname: "hypervisor".to_string(),
            app_name: "hypervisor".to_string(),
        }
    }
    
    fn log_level_to_severity(&self, level: LogLevel) -> u8 {
        match level {
            LogLevel::Fatal => 0, // Emergency
            LogLevel::Error => 3, // Error
            LogLevel::Warn => 4,  // Warning
            LogLevel::Info => 6,  // Informational
            LogLevel::Debug => 7, // Debug
            LogLevel::Trace => 7, // Debug
        }
    }
    
    fn send_syslog(&self, entry: &LogEntry) {
        let severity = self.log_level_to_severity(entry.level);
        let priority = (self.facility as u8) * 8 + severity;
        
        // Format RFC 5424 syslog message
        let message = format!(
            "<{}> 1 {} {} {} - - {}",
            priority,
            Self::format_timestamp(entry.timestamp),
            self.hostname,
            self.app_name,
            entry.message
        );
        
        // Send over network (UDP/TCP)
        self.send_to_server(&message);
    }
    
    fn format_timestamp(_ts: u64) -> String {
        // Format as RFC3339
        "2024-01-01T00:00:00.000Z".to_string()
    }
    
    fn send_to_server(&self, _message: &str) {
        // Network send operation
    }
}

impl LogTarget for SyslogTarget {
    fn write(&self, entry: &LogEntry) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let level = self.level.load(Ordering::Relaxed);
        if entry.level < unsafe { core::mem::transmute(level as u8) } {
            return;
        }
        
        self.send_syslog(entry);
    }
    
    fn flush(&self) {
        // Network operations are typically unbuffered
    }
    
    fn set_level(&self, level: LogLevel) {
        self.level.store(level as u32, Ordering::SeqCst);
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Global logger
pub struct Logger {
    targets: RwLock<Vec<Arc<dyn LogTarget>>>,
    global_level: AtomicU32,
    enabled: AtomicBool,
    stats: LogStatistics,
    filters: RwLock<Vec<LogFilter>>,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            global_level: AtomicU32::new(LogLevel::Info as u32),
            enabled: AtomicBool::new(true),
            stats: LogStatistics::new(),
            filters: RwLock::new(Vec::new()),
        }
    }
    
    pub fn add_target(&self, target: Arc<dyn LogTarget>) {
        self.targets.write().push(target);
    }
    
    pub fn remove_all_targets(&self) {
        self.targets.write().clear();
    }
    
    pub fn set_global_level(&self, level: LogLevel) {
        self.global_level.store(level as u32, Ordering::SeqCst);
        
        // Update all targets
        for target in self.targets.read().iter() {
            target.set_level(level);
        }
    }
    
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    
    pub fn add_filter(&self, filter: LogFilter) {
        self.filters.write().push(filter);
    }
    
    pub fn clear_filters(&self) {
        self.filters.write().clear();
    }
    
    pub fn log(&self, entry: LogEntry) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let global_level = self.global_level.load(Ordering::Relaxed);
        if entry.level < unsafe { core::mem::transmute(global_level as u8) } {
            return;
        }
        
        // Apply filters
        for filter in self.filters.read().iter() {
            if !filter.should_log(&entry) {
                self.stats.filtered.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        
        // Send to all targets
        for target in self.targets.read().iter() {
            target.write(&entry);
        }
        
        // Update statistics
        match entry.level {
            LogLevel::Trace => self.stats.trace_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Debug => self.stats.debug_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Info => self.stats.info_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Warn => self.stats.warn_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Error => self.stats.error_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Fatal => self.stats.fatal_count.fetch_add(1, Ordering::Relaxed),
        };
        
        self.stats.total_logged.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn flush_all(&self) {
        for target in self.targets.read().iter() {
            target.flush();
        }
    }
    
    pub fn get_statistics(&self) -> LogStatisticsSnapshot {
        LogStatisticsSnapshot {
            total_logged: self.stats.total_logged.load(Ordering::Relaxed),
            filtered: self.stats.filtered.load(Ordering::Relaxed),
            trace_count: self.stats.trace_count.load(Ordering::Relaxed),
            debug_count: self.stats.debug_count.load(Ordering::Relaxed),
            info_count: self.stats.info_count.load(Ordering::Relaxed),
            warn_count: self.stats.warn_count.load(Ordering::Relaxed),
            error_count: self.stats.error_count.load(Ordering::Relaxed),
            fatal_count: self.stats.fatal_count.load(Ordering::Relaxed),
        }
    }
}

/// Log filter
pub struct LogFilter {
    pub module_pattern: Option<String>,
    pub min_level: Option<LogLevel>,
    pub max_level: Option<LogLevel>,
    pub vm_id: Option<u64>,
    pub exclude_modules: Vec<String>,
}

impl LogFilter {
    pub fn new() -> Self {
        Self {
            module_pattern: None,
            min_level: None,
            max_level: None,
            vm_id: None,
            exclude_modules: Vec::new(),
        }
    }
    
    pub fn should_log(&self, entry: &LogEntry) -> bool {
        // Check module pattern
        if let Some(pattern) = &self.module_pattern {
            if !entry.module.contains(pattern) {
                return false;
            }
        }
        
        // Check excluded modules
        for excluded in &self.exclude_modules {
            if entry.module.contains(excluded) {
                return false;
            }
        }
        
        // Check level range
        if let Some(min) = self.min_level {
            if entry.level < min {
                return false;
            }
        }
        
        if let Some(max) = self.max_level {
            if entry.level > max {
                return false;
            }
        }
        
        // Check VM ID
        if let Some(filter_vm_id) = self.vm_id {
            if entry.vm_id != Some(filter_vm_id) {
                return false;
            }
        }
        
        true
    }
}

/// Log statistics
pub struct LogStatistics {
    pub total_logged: AtomicU64,
    pub filtered: AtomicU64,
    pub trace_count: AtomicU64,
    pub debug_count: AtomicU64,
    pub info_count: AtomicU64,
    pub warn_count: AtomicU64,
    pub error_count: AtomicU64,
    pub fatal_count: AtomicU64,
}

impl LogStatistics {
    pub fn new() -> Self {
        Self {
            total_logged: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            trace_count: AtomicU64::new(0),
            debug_count: AtomicU64::new(0),
            info_count: AtomicU64::new(0),
            warn_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            fatal_count: AtomicU64::new(0),
        }
    }
}

/// Log statistics snapshot
#[derive(Debug, Clone)]
pub struct LogStatisticsSnapshot {
    pub total_logged: u64,
    pub filtered: u64,
    pub trace_count: u64,
    pub debug_count: u64,
    pub info_count: u64,
    pub warn_count: u64,
    pub error_count: u64,
    pub fatal_count: u64,
}

/// Global logger instance
static LOGGER: Logger = Logger {
    targets: RwLock::new(Vec::new()),
    global_level: AtomicU32::new(LogLevel::Info as u32),
    enabled: AtomicBool::new(true),
    stats: LogStatistics {
        total_logged: AtomicU64::new(0),
        filtered: AtomicU64::new(0),
        trace_count: AtomicU64::new(0),
        debug_count: AtomicU64::new(0),
        info_count: AtomicU64::new(0),
        warn_count: AtomicU64::new(0),
        error_count: AtomicU64::new(0),
        fatal_count: AtomicU64::new(0),
    },
    filters: RwLock::new(Vec::new()),
};

/// Initialize logging
pub fn init() {
    // Add default console target
    LOGGER.add_target(Arc::new(ConsoleTarget::new()));
}

/// Initialize with custom configuration
pub fn init_with_config(config: LogConfig) {
    // Clear existing targets
    LOGGER.remove_all_targets();
    
    // Set global level
    LOGGER.set_global_level(config.level);
    
    // Add configured targets
    if config.console_enabled {
        let console = ConsoleTarget::new();
        console.set_use_color(config.console_color);
        LOGGER.add_target(Arc::new(console));
    }
    
    if let Some(file_path) = config.file_path {
        let file = FileTarget::new(&file_path);
        if let Some(max_size) = config.file_max_size {
            file.set_max_size(max_size);
        }
        if let Some(rotation) = config.file_rotation_count {
            file.set_rotation_count(rotation);
        }
        LOGGER.add_target(Arc::new(file));
    }
    
    if config.ring_buffer_enabled {
        let ring_buffer = RingBufferTarget::new(config.ring_buffer_size);
        LOGGER.add_target(Arc::new(ring_buffer));
    }
    
    if let Some(syslog_server) = config.syslog_server {
        let syslog = SyslogTarget::new(&syslog_server, config.syslog_facility);
        LOGGER.add_target(Arc::new(syslog));
    }
}

/// Log configuration
pub struct LogConfig {
    pub level: LogLevel,
    pub console_enabled: bool,
    pub console_color: bool,
    pub file_path: Option<String>,
    pub file_max_size: Option<u64>,
    pub file_rotation_count: Option<u32>,
    pub ring_buffer_enabled: bool,
    pub ring_buffer_size: usize,
    pub syslog_server: Option<String>,
    pub syslog_facility: SyslogFacility,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            console_enabled: true,
            console_color: true,
            file_path: None,
            file_max_size: Some(100 * 1024 * 1024), // 100MB
            file_rotation_count: Some(5),
            ring_buffer_enabled: false,
            ring_buffer_size: 10000,
            syslog_server: None,
            syslog_facility: SyslogFacility::Local0,
        }
    }
}

/// Logging macros
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        $crate::logging::LOGGER.log($crate::logging::LogEntry::new(
            $level,
            module_path!(),
            file!(),
            line!(),
            format!($($arg)*)
        ));
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        log!($crate::logging::LogLevel::Trace, $($arg)*);
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        log!($crate::logging::LogLevel::Debug, $($arg)*);
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        log!($crate::logging::LogLevel::Info, $($arg)*);
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        log!($crate::logging::LogLevel::Warn, $($arg)*);
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        log!($crate::logging::LogLevel::Error, $($arg)*);
    };
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {
        log!($crate::logging::LogLevel::Fatal, $($arg)*);
    };
}

/// Structured logging builder
pub struct LogBuilder {
    entry: LogEntry,
}

impl LogBuilder {
    pub fn new(level: LogLevel, module: &str, file: &str, line: u32) -> Self {
        Self {
            entry: LogEntry::new(level, module, file, line, String::new()),
        }
    }
    
    pub fn message(mut self, msg: &str) -> Self {
        self.entry.message = msg.to_string();
        self
    }
    
    pub fn field(mut self, key: &str, value: &str) -> Self {
        self.entry.fields.insert(key.to_string(), value.to_string());
        self
    }
    
    pub fn vm_id(mut self, vm_id: u64) -> Self {
        self.entry.vm_id = Some(vm_id);
        self
    }
    
    pub fn log(self) {
        LOGGER.log(self.entry);
    }
}

/// Helper for write! macro
impl fmt::Write for Vec<u8> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }
    
    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(
            LogLevel::Info,
            "test_module",
            "test.rs",
            42,
            "Test message".to_string(),
        );
        
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.module, "test_module");
        assert_eq!(entry.message, "Test message");
    }
    
    #[test]
    fn test_log_filter() {
        let filter = LogFilter {
            module_pattern: Some("test".to_string()),
            min_level: Some(LogLevel::Info),
            max_level: Some(LogLevel::Error),
            vm_id: None,
            exclude_modules: vec!["exclude".to_string()],
        };
        
        let entry = LogEntry::new(
            LogLevel::Info,
            "test_module",
            "test.rs",
            1,
            "msg".to_string(),
        );
        
        assert!(filter.should_log(&entry));
    }
}