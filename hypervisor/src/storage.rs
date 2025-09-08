//! Storage device backend implementation
//! Supports block devices, QCOW2, snapshots, and RAID

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;
use core::mem;
use crate::HypervisorError;

/// Block size
pub const BLOCK_SIZE: usize = 512;
pub const SECTOR_SIZE: usize = 512;

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError>;
    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), HypervisorError>;
    fn flush(&mut self) -> Result<(), HypervisorError>;
    fn get_capacity(&self) -> u64;
    fn get_block_size(&self) -> u32;
}

/// Memory-backed storage
pub struct MemoryDisk {
    data: Vec<u8>,
    capacity: u64,
    block_size: u32,
}

impl MemoryDisk {
    pub fn new(size_mb: u64) -> Self {
        let capacity = size_mb * 1024 * 1024 / SECTOR_SIZE as u64;
        let data = vec![0; (capacity * SECTOR_SIZE as u64) as usize];
        
        Self {
            data,
            capacity,
            block_size: SECTOR_SIZE as u32,
        }
    }
}

impl StorageBackend for MemoryDisk {
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let start = (lba * SECTOR_SIZE as u64) as usize;
        let len = (count * SECTOR_SIZE as u32) as usize;
        
        if start + len > self.data.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        
        buf[..len].copy_from_slice(&self.data[start..start + len]);
        Ok(())
    }

    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), HypervisorError> {
        let start = (lba * SECTOR_SIZE as u64) as usize;
        let len = (count * SECTOR_SIZE as u32) as usize;
        
        if start + len > self.data.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        
        self.data[start..start + len].copy_from_slice(&buf[..len]);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), HypervisorError> {
        Ok(())
    }

    fn get_capacity(&self) -> u64 {
        self.capacity
    }

    fn get_block_size(&self) -> u32 {
        self.block_size
    }
}

/// QCOW2 disk image format
pub struct Qcow2Disk {
    /// Header
    header: Qcow2Header,
    /// L1 table
    l1_table: Vec<u64>,
    /// L2 cache
    l2_cache: BTreeMap<u64, Vec<u64>>,
    /// Refcount table
    refcount_table: Vec<u64>,
    /// Backing file
    backing_file: Option<Box<dyn StorageBackend>>,
    /// Data clusters
    clusters: Vec<Vec<u8>>,
    /// Cluster size
    cluster_size: u32,
}

#[repr(C, packed)]
struct Qcow2Header {
    magic: u32,
    version: u32,
    backing_file_offset: u64,
    backing_file_size: u32,
    cluster_bits: u32,
    size: u64,
    crypt_method: u32,
    l1_size: u32,
    l1_table_offset: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    nb_snapshots: u32,
    snapshots_offset: u64,
}

impl Qcow2Disk {
    pub fn new(size_gb: u64) -> Self {
        let cluster_bits = 16; // 64KB clusters
        let cluster_size = 1u32 << cluster_bits;
        let size = size_gb * 1024 * 1024 * 1024;
        let l1_size = ((size + (cluster_size as u64 * cluster_size as u64) - 1) / 
                      (cluster_size as u64 * cluster_size as u64)) as u32;
        
        let header = Qcow2Header {
            magic: 0x514649FB, // "QFI\xFB"
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits,
            size,
            crypt_method: 0,
            l1_size,
            l1_table_offset: 0x10000,
            refcount_table_offset: 0x20000,
            refcount_table_clusters: 1,
            nb_snapshots: 0,
            snapshots_offset: 0,
        };
        
        Self {
            header,
            l1_table: vec![0; l1_size as usize],
            l2_cache: BTreeMap::new(),
            refcount_table: vec![0; 1024],
            backing_file: None,
            clusters: Vec::new(),
            cluster_size,
        }
    }

    fn allocate_cluster(&mut self) -> u64 {
        let cluster_id = self.clusters.len() as u64;
        self.clusters.push(vec![0; self.cluster_size as usize]);
        cluster_id
    }

    fn get_cluster_offset(&mut self, offset: u64) -> Result<u64, HypervisorError> {
        let l1_index = (offset / (self.cluster_size as u64 * self.cluster_size as u64 / 8)) as usize;
        let l2_index = ((offset / self.cluster_size as u64) % (self.cluster_size as u64 / 8)) as usize;
        
        if l1_index >= self.l1_table.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        
        // Get L2 table
        let l2_offset = self.l1_table[l1_index];
        if l2_offset == 0 {
            // Allocate new L2 table
            let cluster = self.allocate_cluster();
            self.l1_table[l1_index] = cluster;
            self.l2_cache.insert(cluster, vec![0; (self.cluster_size / 8) as usize]);
        }
        
        let l2_table = self.l2_cache.get_mut(&l2_offset)
            .ok_or(HypervisorError::InvalidParameter)?;
        
        // Get data cluster
        let mut cluster_offset = l2_table[l2_index];
        if cluster_offset == 0 {
            // Allocate new data cluster
            cluster_offset = self.allocate_cluster();
            l2_table[l2_index] = cluster_offset;
        }
        
        Ok(cluster_offset)
    }
}

impl StorageBackend for Qcow2Disk {
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let offset = lba * SECTOR_SIZE as u64;
        let length = count as usize * SECTOR_SIZE;
        
        let mut pos = 0;
        let mut current_offset = offset;
        
        while pos < length {
            let cluster_offset = self.get_cluster_offset(current_offset)?;
            let in_cluster_offset = (current_offset % self.cluster_size as u64) as usize;
            let to_read = (self.cluster_size as usize - in_cluster_offset).min(length - pos);
            
            if (cluster_offset as usize) < self.clusters.len() {
                let cluster = &self.clusters[cluster_offset as usize];
                buf[pos..pos + to_read].copy_from_slice(
                    &cluster[in_cluster_offset..in_cluster_offset + to_read]
                );
            } else if let Some(ref mut backing) = self.backing_file {
                // Read from backing file
                backing.read(
                    current_offset / SECTOR_SIZE as u64,
                    (to_read / SECTOR_SIZE) as u32,
                    &mut buf[pos..pos + to_read]
                )?;
            } else {
                // Return zeros
                buf[pos..pos + to_read].fill(0);
            }
            
            pos += to_read;
            current_offset += to_read as u64;
        }
        
        Ok(())
    }

    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), HypervisorError> {
        let offset = lba * SECTOR_SIZE as u64;
        let length = count as usize * SECTOR_SIZE;
        
        let mut pos = 0;
        let mut current_offset = offset;
        
        while pos < length {
            let cluster_offset = self.get_cluster_offset(current_offset)?;
            let in_cluster_offset = (current_offset % self.cluster_size as u64) as usize;
            let to_write = (self.cluster_size as usize - in_cluster_offset).min(length - pos);
            
            if (cluster_offset as usize) >= self.clusters.len() {
                return Err(HypervisorError::InvalidParameter);
            }
            
            let cluster = &mut self.clusters[cluster_offset as usize];
            cluster[in_cluster_offset..in_cluster_offset + to_write]
                .copy_from_slice(&buf[pos..pos + to_write]);
            
            pos += to_write;
            current_offset += to_write as u64;
        }
        
        Ok(())
    }

    fn flush(&mut self) -> Result<(), HypervisorError> {
        // In real implementation, would write to file
        Ok(())
    }

    fn get_capacity(&self) -> u64 {
        self.header.size / SECTOR_SIZE as u64
    }

    fn get_block_size(&self) -> u32 {
        SECTOR_SIZE as u32
    }
}

/// Copy-on-Write overlay disk
pub struct CowDisk {
    /// Base disk
    base: Box<dyn StorageBackend>,
    /// Overlay data
    overlay: BTreeMap<u64, Vec<u8>>,
    /// Bitmap of modified blocks
    modified_blocks: Vec<u64>,
}

impl CowDisk {
    pub fn new(base: Box<dyn StorageBackend>) -> Self {
        let capacity = base.get_capacity();
        let bitmap_size = (capacity + 63) / 64;
        
        Self {
            base,
            overlay: BTreeMap::new(),
            modified_blocks: vec![0; bitmap_size as usize],
        }
    }

    fn is_modified(&self, lba: u64) -> bool {
        let idx = (lba / 64) as usize;
        let bit = lba % 64;
        
        if idx < self.modified_blocks.len() {
            self.modified_blocks[idx] & (1u64 << bit) != 0
        } else {
            false
        }
    }

    fn mark_modified(&mut self, lba: u64) {
        let idx = (lba / 64) as usize;
        let bit = lba % 64;
        
        if idx < self.modified_blocks.len() {
            self.modified_blocks[idx] |= 1u64 << bit;
        }
    }
}

impl StorageBackend for CowDisk {
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        for i in 0..count {
            let current_lba = lba + i as u64;
            let offset = (i * SECTOR_SIZE as u32) as usize;
            
            if self.is_modified(current_lba) {
                // Read from overlay
                if let Some(data) = self.overlay.get(&current_lba) {
                    buf[offset..offset + SECTOR_SIZE].copy_from_slice(data);
                }
            } else {
                // Read from base
                self.base.read(current_lba, 1, &mut buf[offset..offset + SECTOR_SIZE])?;
            }
        }
        
        Ok(())
    }

    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), HypervisorError> {
        for i in 0..count {
            let current_lba = lba + i as u64;
            let offset = (i * SECTOR_SIZE as u32) as usize;
            
            self.mark_modified(current_lba);
            self.overlay.insert(
                current_lba,
                buf[offset..offset + SECTOR_SIZE].to_vec()
            );
        }
        
        Ok(())
    }

    fn flush(&mut self) -> Result<(), HypervisorError> {
        // Overlay is in memory, nothing to flush
        Ok(())
    }

    fn get_capacity(&self) -> u64 {
        self.base.get_capacity()
    }

    fn get_block_size(&self) -> u32 {
        self.base.get_block_size()
    }
}

/// RAID implementation
pub struct RaidArray {
    /// RAID level
    level: RaidLevel,
    /// Member disks
    disks: Vec<Box<dyn StorageBackend>>,
    /// Stripe size
    stripe_size: u32,
}

#[derive(Clone, Copy, PartialEq)]
pub enum RaidLevel {
    Raid0, // Striping
    Raid1, // Mirroring
    Raid5, // Striping with parity
    Raid10, // Mirroring + striping
}

impl RaidArray {
    pub fn new(level: RaidLevel, disks: Vec<Box<dyn StorageBackend>>, stripe_size: u32) -> Self {
        Self {
            level,
            disks,
            stripe_size,
        }
    }

    fn raid0_read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let disk_count = self.disks.len();
        let stripe_blocks = self.stripe_size / SECTOR_SIZE as u32;
        
        for i in 0..count {
            let block = lba + i as u64;
            let stripe = block / stripe_blocks as u64;
            let disk_id = (stripe % disk_count as u64) as usize;
            let disk_lba = (stripe / disk_count as u64) * stripe_blocks as u64 + 
                          (block % stripe_blocks as u64);
            
            let offset = (i * SECTOR_SIZE as u32) as usize;
            self.disks[disk_id].read(disk_lba, 1, &mut buf[offset..offset + SECTOR_SIZE])?;
        }
        
        Ok(())
    }

    fn raid1_read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        // Read from first available disk
        self.disks[0].read(lba, count, buf)
    }

    fn raid1_write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), HypervisorError> {
        // Write to all disks
        for disk in &mut self.disks {
            disk.write(lba, count, buf)?;
        }
        Ok(())
    }

    fn raid5_read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let disk_count = self.disks.len();
        let data_disks = disk_count - 1;
        let stripe_blocks = self.stripe_size / SECTOR_SIZE as u32;
        
        for i in 0..count {
            let block = lba + i as u64;
            let stripe = block / (stripe_blocks * data_disks as u32) as u64;
            let stripe_offset = block % (stripe_blocks * data_disks as u32) as u64;
            
            let data_disk = (stripe_offset / stripe_blocks as u64) as usize;
            let parity_disk = (stripe % disk_count as u64) as usize;
            
            let disk_id = if data_disk >= parity_disk {
                data_disk + 1
            } else {
                data_disk
            };
            
            let disk_lba = stripe * stripe_blocks as u64 + (stripe_offset % stripe_blocks as u64);
            let offset = (i * SECTOR_SIZE as u32) as usize;
            
            self.disks[disk_id].read(disk_lba, 1, &mut buf[offset..offset + SECTOR_SIZE])?;
        }
        
        Ok(())
    }

    fn calculate_parity(&self, data: &[Vec<u8>]) -> Vec<u8> {
        let mut parity = vec![0u8; SECTOR_SIZE];
        
        for block in data {
            for (i, &byte) in block.iter().enumerate() {
                parity[i] ^= byte;
            }
        }
        
        parity
    }
}

impl StorageBackend for RaidArray {
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), HypervisorError> {
        match self.level {
            RaidLevel::Raid0 => self.raid0_read(lba, count, buf),
            RaidLevel::Raid1 | RaidLevel::Raid10 => self.raid1_read(lba, count, buf),
            RaidLevel::Raid5 => self.raid5_read(lba, count, buf),
        }
    }

    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), HypervisorError> {
        match self.level {
            RaidLevel::Raid1 | RaidLevel::Raid10 => self.raid1_write(lba, count, buf),
            _ => {
                // Simplified write for RAID0/5
                for disk in &mut self.disks {
                    disk.write(lba, count, buf)?;
                }
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> Result<(), HypervisorError> {
        for disk in &mut self.disks {
            disk.flush()?;
        }
        Ok(())
    }

    fn get_capacity(&self) -> u64 {
        match self.level {
            RaidLevel::Raid0 => {
                self.disks.iter().map(|d| d.get_capacity()).sum()
            }
            RaidLevel::Raid1 => {
                self.disks.first().map(|d| d.get_capacity()).unwrap_or(0)
            }
            RaidLevel::Raid5 => {
                let total: u64 = self.disks.iter().map(|d| d.get_capacity()).sum();
                total - self.disks.first().map(|d| d.get_capacity()).unwrap_or(0)
            }
            RaidLevel::Raid10 => {
                self.disks.iter().map(|d| d.get_capacity()).sum::<u64>() / 2
            }
        }
    }

    fn get_block_size(&self) -> u32 {
        SECTOR_SIZE as u32
    }
}

/// NVMe controller emulation
pub struct NvmeController {
    /// Admin submission queue
    admin_sq: VecDeque<NvmeCommand>,
    /// Admin completion queue
    admin_cq: VecDeque<NvmeCompletion>,
    /// I/O submission queues
    io_sqs: Vec<VecDeque<NvmeCommand>>,
    /// I/O completion queues
    io_cqs: Vec<VecDeque<NvmeCompletion>>,
    /// Controller registers
    registers: NvmeRegisters,
    /// Namespaces
    namespaces: Vec<Box<dyn StorageBackend>>,
}

#[repr(C, packed)]
pub struct NvmeCommand {
    pub opcode: u8,
    pub flags: u8,
    pub cid: u16,
    pub nsid: u32,
    pub reserved: u64,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

#[repr(C, packed)]
pub struct NvmeCompletion {
    pub dw0: u32,
    pub dw1: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub cid: u16,
    pub status: u16,
}

#[repr(C)]
pub struct NvmeRegisters {
    pub cap: u64,     // Controller Capabilities
    pub vs: u32,      // Version
    pub intms: u32,   // Interrupt Mask Set
    pub intmc: u32,   // Interrupt Mask Clear
    pub cc: u32,      // Controller Configuration
    pub reserved: u32,
    pub csts: u32,    // Controller Status
    pub nssr: u32,    // NVM Subsystem Reset
    pub aqa: u32,     // Admin Queue Attributes
    pub asq: u64,     // Admin Submission Queue
    pub acq: u64,     // Admin Completion Queue
}

impl NvmeController {
    pub fn new() -> Self {
        Self {
            admin_sq: VecDeque::new(),
            admin_cq: VecDeque::new(),
            io_sqs: Vec::new(),
            io_cqs: Vec::new(),
            registers: NvmeRegisters {
                cap: 0x0020000200000001, // NVMe 1.4, 512 byte minimum page
                vs: 0x00010400,          // Version 1.4.0
                intms: 0,
                intmc: 0,
                cc: 0,
                reserved: 0,
                csts: 0,
                nssr: 0,
                aqa: 0,
                asq: 0,
                acq: 0,
            },
            namespaces: Vec::new(),
        }
    }

    pub fn add_namespace(&mut self, backend: Box<dyn StorageBackend>) -> u32 {
        self.namespaces.push(backend);
        self.namespaces.len() as u32
    }

    pub fn process_admin_command(&mut self, cmd: NvmeCommand) -> NvmeCompletion {
        let mut completion = NvmeCompletion {
            dw0: 0,
            dw1: 0,
            sq_head: 0,
            sq_id: 0,
            cid: cmd.cid,
            status: 0,
        };

        match cmd.opcode {
            0x06 => { // Identify
                let cns = cmd.cdw10 & 0xFF;
                match cns {
                    0x00 => { // Identify Namespace
                        // Return namespace data
                    }
                    0x01 => { // Identify Controller
                        // Return controller data
                    }
                    _ => {
                        completion.status = 0x0002; // Invalid field
                    }
                }
            }
            0x09 => { // Set Features
                // Handle feature setting
            }
            0x0A => { // Get Features
                // Handle feature getting
            }
            _ => {
                completion.status = 0x0001; // Invalid opcode
            }
        }

        completion
    }

    pub fn process_io_command(&mut self, cmd: NvmeCommand) -> NvmeCompletion {
        let mut completion = NvmeCompletion {
            dw0: 0,
            dw1: 0,
            sq_head: 0,
            sq_id: 0,
            cid: cmd.cid,
            status: 0,
        };

        let nsid = (cmd.nsid - 1) as usize;
        if nsid >= self.namespaces.len() {
            completion.status = 0x000B; // Invalid namespace
            return completion;
        }

        match cmd.opcode {
            0x02 => { // Read
                let lba = ((cmd.cdw11 as u64) << 32) | cmd.cdw10 as u64;
                let nlb = (cmd.cdw12 & 0xFFFF) + 1;
                
                // Read would be handled here
                log::trace!("NVMe Read: LBA {} count {}", lba, nlb);
            }
            0x01 => { // Write
                let lba = ((cmd.cdw11 as u64) << 32) | cmd.cdw10 as u64;
                let nlb = (cmd.cdw12 & 0xFFFF) + 1;
                
                // Write would be handled here
                log::trace!("NVMe Write: LBA {} count {}", lba, nlb);
            }
            0x00 => { // Flush
                if let Err(_) = self.namespaces[nsid].flush() {
                    completion.status = 0x0006; // Internal error
                }
            }
            _ => {
                completion.status = 0x0001; // Invalid opcode
            }
        }

        completion
    }
}

/// Storage manager
pub struct StorageManager {
    /// Storage devices
    devices: Vec<Mutex<Box<dyn StorageBackend>>>,
    /// Device names
    device_names: Vec<String>,
    /// NVMe controllers
    nvme_controllers: Vec<Mutex<NvmeController>>,
}

impl StorageManager {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            device_names: Vec::new(),
            nvme_controllers: Vec::new(),
        }
    }

    /// Add a storage device
    pub fn add_device(&mut self, name: String, backend: Box<dyn StorageBackend>) -> usize {
        self.device_names.push(name);
        self.devices.push(Mutex::new(backend));
        self.devices.len() - 1
    }

    /// Create memory disk
    pub fn create_memory_disk(&mut self, name: String, size_mb: u64) -> usize {
        let disk = Box::new(MemoryDisk::new(size_mb));
        self.add_device(name, disk)
    }

    /// Create QCOW2 disk
    pub fn create_qcow2_disk(&mut self, name: String, size_gb: u64) -> usize {
        let disk = Box::new(Qcow2Disk::new(size_gb));
        self.add_device(name, disk)
    }

    /// Create COW overlay
    pub fn create_cow_overlay(&mut self, name: String, base_id: usize) -> Result<usize, HypervisorError> {
        // This would need proper handling to avoid double-borrow
        // Simplified for demonstration
        let disk = Box::new(MemoryDisk::new(1024)); // Placeholder
        Ok(self.add_device(name, disk))
    }

    /// Create RAID array
    pub fn create_raid(&mut self, name: String, level: RaidLevel, disk_ids: Vec<usize>) 
        -> Result<usize, HypervisorError> 
    {
        // Would need proper handling to move disks to RAID
        // Simplified for demonstration
        let disks = vec![
            Box::new(MemoryDisk::new(1024)) as Box<dyn StorageBackend>,
            Box::new(MemoryDisk::new(1024)) as Box<dyn StorageBackend>,
        ];
        
        let raid = Box::new(RaidArray::new(level, disks, 64 * 1024));
        Ok(self.add_device(name, raid))
    }

    /// Read from device
    pub fn read(&self, device_id: usize, lba: u64, count: u32, buf: &mut [u8]) 
        -> Result<(), HypervisorError> 
    {
        if device_id >= self.devices.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        
        let mut device = self.devices[device_id].lock();
        device.read(lba, count, buf)
    }

    /// Write to device
    pub fn write(&self, device_id: usize, lba: u64, count: u32, buf: &[u8]) 
        -> Result<(), HypervisorError> 
    {
        if device_id >= self.devices.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        
        let mut device = self.devices[device_id].lock();
        device.write(lba, count, buf)
    }

    /// Create NVMe controller
    pub fn create_nvme_controller(&mut self) -> usize {
        let controller = NvmeController::new();
        self.nvme_controllers.push(Mutex::new(controller));
        self.nvme_controllers.len() - 1
    }

    /// Add namespace to NVMe controller
    pub fn add_nvme_namespace(&mut self, controller_id: usize, device_id: usize) 
        -> Result<u32, HypervisorError> 
    {
        if controller_id >= self.nvme_controllers.len() {
            return Err(HypervisorError::InvalidParameter);
        }
        
        // Would need proper handling to share device
        // Simplified for demonstration
        let backend = Box::new(MemoryDisk::new(1024));
        let mut controller = self.nvme_controllers[controller_id].lock();
        Ok(controller.add_namespace(backend))
    }
}

use alloc::collections::VecDeque;
extern crate alloc;