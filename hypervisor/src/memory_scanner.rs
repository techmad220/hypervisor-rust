//! Memory Scanner - Direct port from C MemScanner.c and ProcessMemScan.c

use alloc::vec::Vec;
use alloc::string::String;
use core::mem;
use crate::HypervisorError;

/// Memory pattern for scanning
#[derive(Debug, Clone)]
pub struct MemoryPattern {
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>, // 0xFF = must match, 0x00 = wildcard
    pub name: String,
}

/// Memory scanner results
#[derive(Debug)]
pub struct ScanResult {
    pub address: u64,
    pub pattern_name: String,
    pub context: Vec<u8>, // Surrounding bytes for context
}

/// Process memory information
#[derive(Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub base_address: u64,
    pub memory_size: usize,
}

/// Memory Scanner - from C MemScanner.c
pub struct MemoryScanner {
    patterns: Vec<MemoryPattern>,
    results: Vec<ScanResult>,
    scan_range: (u64, u64),
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            patterns: Self::load_default_patterns(),
            results: Vec::new(),
            scan_range: (0, u64::MAX),
        }
    }
    
    /// Load default malware/rootkit patterns
    fn load_default_patterns() -> Vec<MemoryPattern> {
        vec![
            // Common rootkit signatures
            MemoryPattern {
                pattern: vec![0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF], // mov rax, [rip+...]
                mask: vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                name: String::from("Rootkit Hook Pattern 1"),
            },
            // Process hiding pattern
            MemoryPattern {
                pattern: vec![0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC0], // call + test rax
                mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
                name: String::from("Process Hiding Hook"),
            },
            // IDT hook pattern
            MemoryPattern {
                pattern: vec![0x0F, 0x01, 0x0D], // sidt
                mask: vec![0xFF, 0xFF, 0xFF],
                name: String::from("IDT Manipulation"),
            },
            // SSDT hook pattern
            MemoryPattern {
                pattern: vec![0x4C, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0xFF], // lea r10, [rip+...]
                mask: vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                name: String::from("SSDT Hook"),
            },
            // Hypervisor detection evasion
            MemoryPattern {
                pattern: vec![0x0F, 0xA2], // cpuid
                mask: vec![0xFF, 0xFF],
                name: String::from("CPUID Hook"),
            },
            // VM detection string
            MemoryPattern {
                pattern: b"VMware".to_vec(),
                mask: vec![0xFF; 6],
                name: String::from("VMware Detection String"),
            },
            MemoryPattern {
                pattern: b"VirtualBox".to_vec(),
                mask: vec![0xFF; 10],
                name: String::from("VirtualBox Detection String"),
            },
        ]
    }
    
    /// Add custom pattern
    pub fn add_pattern(&mut self, pattern: MemoryPattern) {
        self.patterns.push(pattern);
    }
    
    /// Set scan range
    pub fn set_range(&mut self, start: u64, end: u64) {
        self.scan_range = (start, end);
    }
    
    /// Scan memory for patterns (from C: ScanMemoryForPatterns)
    pub fn scan_memory(&mut self, memory: &[u8], base_address: u64) -> Vec<ScanResult> {
        let mut results = Vec::new();
        
        for pattern in &self.patterns {
            if pattern.pattern.is_empty() {
                continue;
            }
            
            let pattern_len = pattern.pattern.len();
            
            // Sliding window search
            for i in 0..memory.len().saturating_sub(pattern_len - 1) {
                let current_addr = base_address + i as u64;
                
                // Check if in scan range
                if current_addr < self.scan_range.0 || current_addr > self.scan_range.1 {
                    continue;
                }
                
                // Check pattern match with mask
                let mut matches = true;
                for j in 0..pattern_len {
                    if pattern.mask[j] == 0xFF {
                        if memory[i + j] != pattern.pattern[j] {
                            matches = false;
                            break;
                        }
                    }
                    // 0x00 in mask means wildcard, always matches
                }
                
                if matches {
                    // Get context (32 bytes around match)
                    let context_start = i.saturating_sub(16);
                    let context_end = (i + pattern_len + 16).min(memory.len());
                    let context = memory[context_start..context_end].to_vec();
                    
                    results.push(ScanResult {
                        address: current_addr,
                        pattern_name: pattern.name.clone(),
                        context,
                    });
                    
                    log::warn!("[MemScan] Found pattern '{}' at 0x{:x}", 
                        pattern.name, current_addr);
                }
            }
        }
        
        self.results.extend(results.clone());
        results
    }
    
    /// Get all scan results
    pub fn get_results(&self) -> &[ScanResult] {
        &self.results
    }
    
    /// Clear results
    pub fn clear_results(&mut self) {
        self.results.clear();
    }
}

/// Process Memory Scanner - from C ProcessMemScan.c
pub struct ProcessMemoryScanner {
    scanner: MemoryScanner,
    processes: Vec<ProcessInfo>,
    suspended_processes: Vec<u32>,
}

impl ProcessMemoryScanner {
    pub fn new() -> Self {
        Self {
            scanner: MemoryScanner::new(),
            processes: Vec::new(),
            suspended_processes: Vec::new(),
        }
    }
    
    /// Enumerate processes (simulation for hypervisor context)
    pub fn enumerate_processes(&mut self) -> Result<Vec<ProcessInfo>, HypervisorError> {
        // In real implementation, this would walk process list
        self.processes = vec![
            ProcessInfo {
                pid: 4,
                name: String::from("System"),
                base_address: 0xFFFF800000000000,
                memory_size: 0x100000,
            },
            ProcessInfo {
                pid: 1000,
                name: String::from("svchost.exe"),
                base_address: 0x00007FF600000000,
                memory_size: 0x50000,
            },
        ];
        
        Ok(self.processes.clone())
    }
    
    /// Scan specific process memory
    pub fn scan_process(&mut self, pid: u32, memory: &[u8]) -> Result<Vec<ScanResult>, HypervisorError> {
        let process = self.processes.iter()
            .find(|p| p.pid == pid)
            .ok_or(HypervisorError::InvalidParameter)?;
        
        log::info!("[ProcessScan] Scanning process {} (PID: {})", process.name, pid);
        
        let results = self.scanner.scan_memory(memory, process.base_address);
        
        if !results.is_empty() {
            log::warn!("[ProcessScan] Process {} has {} suspicious patterns!", 
                process.name, results.len());
            
            // Optionally suspend suspicious process
            if results.len() > 3 {
                self.suspend_process(pid)?;
            }
        }
        
        Ok(results)
    }
    
    /// Suspend suspicious process
    pub fn suspend_process(&mut self, pid: u32) -> Result<(), HypervisorError> {
        if !self.suspended_processes.contains(&pid) {
            self.suspended_processes.push(pid);
            log::warn!("[ProcessScan] Suspended process PID: {}", pid);
        }
        Ok(())
    }
    
    /// Resume process
    pub fn resume_process(&mut self, pid: u32) -> Result<(), HypervisorError> {
        if let Some(pos) = self.suspended_processes.iter().position(|&p| p == pid) {
            self.suspended_processes.remove(pos);
            log::info!("[ProcessScan] Resumed process PID: {}", pid);
        }
        Ok(())
    }
    
    /// Check if address is executable
    pub fn is_executable_address(&self, address: u64) -> bool {
        // Check if address is in executable range
        // In real implementation, would check page tables
        address >= 0x00400000 && address < 0x7FFFFFFF00000000
    }
    
    /// Scan for code injection
    pub fn scan_for_injection(&mut self, memory: &[u8], base: u64) -> Vec<ScanResult> {
        let mut injection_patterns = vec![
            // SetWindowsHookEx injection
            MemoryPattern {
                pattern: vec![0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF], // call [SetWindowsHookEx]
                mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                name: String::from("SetWindowsHookEx Injection"),
            },
            // CreateRemoteThread injection
            MemoryPattern {
                pattern: vec![0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC0],
                mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
                name: String::from("CreateRemoteThread Injection"),
            },
            // Process hollowing
            MemoryPattern {
                pattern: vec![0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05], // syscall pattern
                mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
                name: String::from("Process Hollowing"),
            },
        ];
        
        self.scanner.patterns.append(&mut injection_patterns);
        self.scanner.scan_memory(memory, base)
    }
}

/// Hypervisor memory protection
pub struct HypervisorMemoryProtection {
    protected_ranges: Vec<(u64, u64)>,
    read_only_ranges: Vec<(u64, u64)>,
    no_execute_ranges: Vec<(u64, u64)>,
}

impl HypervisorMemoryProtection {
    pub fn new() -> Self {
        Self {
            protected_ranges: vec![
                (0xFFFF800000000000, 0xFFFF900000000000), // Kernel space
            ],
            read_only_ranges: vec![
                (0xFFFF800000100000, 0xFFFF800000200000), // Kernel code
            ],
            no_execute_ranges: vec![
                (0x0, 0x1000), // NULL page
            ],
        }
    }
    
    /// Check if memory access is allowed
    pub fn check_access(&self, address: u64, size: u64, write: bool, execute: bool) -> bool {
        let end = address + size;
        
        // Check protected ranges
        for &(start, range_end) in &self.protected_ranges {
            if address >= start && end <= range_end {
                log::warn!("[MemProtect] Access to protected range 0x{:x} denied", address);
                return false;
            }
        }
        
        // Check read-only ranges
        if write {
            for &(start, range_end) in &self.read_only_ranges {
                if address >= start && end <= range_end {
                    log::warn!("[MemProtect] Write to read-only range 0x{:x} denied", address);
                    return false;
                }
            }
        }
        
        // Check no-execute ranges
        if execute {
            for &(start, range_end) in &self.no_execute_ranges {
                if address >= start && end <= range_end {
                    log::warn!("[MemProtect] Execute in no-execute range 0x{:x} denied", address);
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Add protected range
    pub fn protect_range(&mut self, start: u64, end: u64) {
        self.protected_ranges.push((start, end));
        log::info!("[MemProtect] Protected range 0x{:x}-0x{:x}", start, end);
    }
}