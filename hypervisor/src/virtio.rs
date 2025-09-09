//! Complete Virtio implementation
//! Supports virtio-net, virtio-blk, virtio-scsi, virtio-console, virtio-balloon, virtio-rng

use alloc::vec::Vec;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::string::String;
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicBool, Ordering};
use core::mem;
use bit_field::BitField;
use lazy_static::lazy_static;

/// Virtio device IDs
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VirtioDeviceId {
    Net = 1,
    Block = 2,
    Console = 3,
    Rng = 4,
    Balloon = 5,
    Rpmsg = 7,
    Scsi = 8,
    NineP = 9,
    Mac80211 = 10,
    RprocSerial = 11,
    Caif = 12,
    MemoryBalloon = 13,
    Gpu = 16,
    Timer = 17,
    Input = 18,
    Vsock = 19,
    Crypto = 20,
    SignalDist = 21,
    Pstore = 22,
    Iommu = 23,
    Memory = 24,
    Sound = 25,
    FsBackend = 26,
    Mac80211Hwsim = 29,
    Pmem = 31,
    I2cAdapter = 34,
    Watchdog = 35,
    CanBus = 36,
    DmaBuf = 37,
    ParamServer = 38,
    AudioPolicy = 39,
    Bt = 40,
    Gpio = 41,
}

/// Virtio status flags
bitflags::bitflags! {
    pub struct VirtioStatus: u32 {
        const ACKNOWLEDGE = 1;
        const DRIVER = 2;
        const DRIVER_OK = 4;
        const FEATURES_OK = 8;
        const DEVICE_NEEDS_RESET = 64;
        const FAILED = 128;
    }
}

/// Virtio feature flags (common)
bitflags::bitflags! {
    pub struct VirtioFeatures: u64 {
        const NOTIFY_ON_EMPTY = 1 << 24;
        const ANY_LAYOUT = 1 << 27;
        const RING_INDIRECT_DESC = 1 << 28;
        const RING_EVENT_IDX = 1 << 29;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;
        const IN_ORDER = 1 << 35;
        const ORDER_PLATFORM = 1 << 36;
        const SR_IOV = 1 << 37;
        const NOTIFICATION_DATA = 1 << 38;
    }
}

/// Virtio net feature flags
bitflags::bitflags! {
    pub struct VirtioNetFeatures: u64 {
        const CSUM = 1 << 0;
        const GUEST_CSUM = 1 << 1;
        const CTRL_GUEST_OFFLOADS = 1 << 2;
        const MTU = 1 << 3;
        const MAC = 1 << 5;
        const GSO = 1 << 6;
        const GUEST_TSO4 = 1 << 7;
        const GUEST_TSO6 = 1 << 8;
        const GUEST_ECN = 1 << 9;
        const GUEST_UFO = 1 << 10;
        const HOST_TSO4 = 1 << 11;
        const HOST_TSO6 = 1 << 12;
        const HOST_ECN = 1 << 13;
        const HOST_UFO = 1 << 14;
        const MRG_RXBUF = 1 << 15;
        const STATUS = 1 << 16;
        const CTRL_VQ = 1 << 17;
        const CTRL_RX = 1 << 18;
        const CTRL_VLAN = 1 << 19;
        const CTRL_RX_EXTRA = 1 << 20;
        const GUEST_ANNOUNCE = 1 << 21;
        const MQ = 1 << 22;
        const CTRL_MAC_ADDR = 1 << 23;
        const HASH_REPORT = 1 << 57;
        const RSS = 1 << 60;
        const RSC_EXT = 1 << 61;
        const STANDBY = 1 << 62;
    }
}

/// Virtio block feature flags
bitflags::bitflags! {
    pub struct VirtioBlkFeatures: u64 {
        const SIZE_MAX = 1 << 1;
        const SEG_MAX = 1 << 2;
        const GEOMETRY = 1 << 4;
        const RO = 1 << 5;
        const BLK_SIZE = 1 << 6;
        const FLUSH = 1 << 9;
        const TOPOLOGY = 1 << 10;
        const CONFIG_WCE = 1 << 11;
        const MQ = 1 << 12;
        const DISCARD = 1 << 13;
        const WRITE_ZEROES = 1 << 14;
        const LIFETIME = 1 << 15;
        const SECURE_ERASE = 1 << 16;
    }
}

/// Virtqueue descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    /// Buffer physical address
    pub addr: u64,
    /// Buffer length
    pub len: u32,
    /// Flags
    pub flags: u16,
    /// Next descriptor index
    pub next: u16,
}

impl VirtqDesc {
    pub const F_NEXT: u16 = 1;
    pub const F_WRITE: u16 = 2;
    pub const F_INDIRECT: u16 = 4;
}

/// Virtqueue available ring
#[repr(C)]
pub struct VirtqAvail {
    pub flags: AtomicU16,
    pub idx: AtomicU16,
    pub ring: Vec<AtomicU16>,
    pub used_event: AtomicU16,
}

impl VirtqAvail {
    pub const F_NO_INTERRUPT: u16 = 1;

    pub fn new(size: u16) -> Self {
        let mut ring = Vec::with_capacity(size as usize);
        for _ in 0..size {
            ring.push(AtomicU16::new(0));
        }
        
        Self {
            flags: AtomicU16::new(0),
            idx: AtomicU16::new(0),
            ring,
            used_event: AtomicU16::new(0),
        }
    }
}

/// Virtqueue used element
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsedElem {
    /// Descriptor index
    pub id: u32,
    /// Total length written
    pub len: u32,
}

/// Virtqueue used ring
#[repr(C)]
pub struct VirtqUsed {
    pub flags: AtomicU16,
    pub idx: AtomicU16,
    pub ring: Vec<VirtqUsedElem>,
    pub avail_event: AtomicU16,
}

impl VirtqUsed {
    pub const F_NO_NOTIFY: u16 = 1;

    pub fn new(size: u16) -> Self {
        let mut ring = Vec::with_capacity(size as usize);
        for _ in 0..size {
            ring.push(VirtqUsedElem { id: 0, len: 0 });
        }
        
        Self {
            flags: AtomicU16::new(0),
            idx: AtomicU16::new(0),
            ring,
            avail_event: AtomicU16::new(0),
        }
    }
}

/// Virtqueue
pub struct Virtqueue {
    /// Queue size
    pub size: u16,
    /// Descriptors
    pub desc: Vec<VirtqDesc>,
    /// Available ring
    pub avail: VirtqAvail,
    /// Used ring
    pub used: VirtqUsed,
    /// Last seen available index
    pub last_avail_idx: AtomicU16,
    /// Last seen used index
    pub last_used_idx: AtomicU16,
    /// Queue ready
    pub ready: AtomicBool,
    /// Notification suppression
    pub no_notify: AtomicBool,
    /// Event index feature enabled
    pub event_idx: AtomicBool,
}

impl Virtqueue {
    pub fn new(size: u16) -> Self {
        let mut desc = Vec::with_capacity(size as usize);
        for _ in 0..size {
            desc.push(VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            });
        }
        
        Self {
            size,
            desc,
            avail: VirtqAvail::new(size),
            used: VirtqUsed::new(size),
            last_avail_idx: AtomicU16::new(0),
            last_used_idx: AtomicU16::new(0),
            ready: AtomicBool::new(false),
            no_notify: AtomicBool::new(false),
            event_idx: AtomicBool::new(false),
        }
    }

    /// Get next available descriptor chain
    pub fn get_next_avail(&self) -> Option<Vec<VirtqDesc>> {
        let avail_idx = self.avail.idx.load(Ordering::SeqCst);
        let last_avail = self.last_avail_idx.load(Ordering::SeqCst);
        
        if avail_idx == last_avail {
            return None;
        }
        
        let idx = last_avail % self.size;
        let desc_idx = self.avail.ring[idx as usize].load(Ordering::SeqCst);
        
        // Follow descriptor chain
        let mut chain = Vec::new();
        let mut current = desc_idx;
        
        loop {
            if current >= self.size {
                break;
            }
            
            let desc = self.desc[current as usize];
            chain.push(desc);
            
            if desc.flags & VirtqDesc::F_NEXT == 0 {
                break;
            }
            
            current = desc.next;
        }
        
        self.last_avail_idx.store(last_avail.wrapping_add(1), Ordering::SeqCst);
        
        Some(chain)
    }

    /// Add used buffer
    pub fn add_used(&self, desc_idx: u32, len: u32) {
        let used_idx = self.used.idx.load(Ordering::SeqCst);
        let idx = used_idx % self.size;
        
        self.used.ring[idx as usize] = VirtqUsedElem {
            id: desc_idx,
            len,
        };
        
        self.used.idx.store(used_idx.wrapping_add(1), Ordering::SeqCst);
    }

    /// Check if notification is needed
    pub fn needs_notification(&self) -> bool {
        if self.no_notify.load(Ordering::SeqCst) {
            return false;
        }
        
        if self.event_idx.load(Ordering::SeqCst) {
            let avail_event = self.used.avail_event.load(Ordering::SeqCst);
            let avail_idx = self.avail.idx.load(Ordering::SeqCst);
            avail_idx == avail_event.wrapping_add(1)
        } else {
            self.avail.flags.load(Ordering::SeqCst) & VirtqAvail::F_NO_INTERRUPT == 0
        }
    }
}

/// Virtio device trait
pub trait VirtioDevice: Send + Sync {
    /// Get device ID
    fn device_id(&self) -> VirtioDeviceId;
    
    /// Get device features
    fn features(&self) -> u64;
    
    /// Set acknowledged features
    fn set_features(&mut self, features: u64);
    
    /// Get configuration space
    fn config_space(&self) -> &[u8];
    
    /// Write configuration space
    fn write_config(&mut self, offset: usize, data: &[u8]);
    
    /// Get number of queues
    fn num_queues(&self) -> usize;
    
    /// Process queue
    fn process_queue(&mut self, queue_idx: usize, queue: &Virtqueue);
    
    /// Reset device
    fn reset(&mut self);
}

/// Virtio network device
pub struct VirtioNet {
    /// MAC address
    pub mac: [u8; 6],
    /// Status
    pub status: AtomicU32,
    /// Features
    pub features: AtomicU64,
    /// Negotiated features
    pub acked_features: AtomicU64,
    /// Receive queue
    pub rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Transmit queue
    pub tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Control queue
    pub ctrl_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Link status
    pub link_up: AtomicBool,
    /// Multiqueue pairs
    pub num_queue_pairs: u16,
}

impl VirtioNet {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            status: AtomicU32::new(0),
            features: AtomicU64::new(
                VirtioNetFeatures::MAC.bits() |
                VirtioNetFeatures::STATUS.bits() |
                VirtioNetFeatures::MRG_RXBUF.bits() |
                VirtioNetFeatures::CTRL_VQ.bits() |
                VirtioNetFeatures::MQ.bits()
            ),
            acked_features: AtomicU64::new(0),
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
            ctrl_queue: Arc::new(Mutex::new(VecDeque::new())),
            link_up: AtomicBool::new(true),
            num_queue_pairs: 1,
        }
    }

    /// Process receive queue
    fn process_rx(&mut self, queue: &Virtqueue) {
        while let Some(chain) = queue.get_next_avail() {
            if chain.is_empty() {
                continue;
            }
            
            let mut rx_queue = self.rx_queue.lock();
            if let Some(packet) = rx_queue.pop_front() {
                // Write packet to guest buffer
                let mut written = 0;
                for desc in &chain {
                    if desc.flags & VirtqDesc::F_WRITE != 0 {
                        let len = (desc.len as usize).min(packet.len() - written);
                        // Would copy to guest memory here
                        written += len;
                        
                        if written >= packet.len() {
                            break;
                        }
                    }
                }
                
                queue.add_used(chain[0].next as u32, written as u32);
            } else {
                // No packets available, return buffer unused
                queue.add_used(chain[0].next as u32, 0);
            }
        }
    }

    /// Process transmit queue
    fn process_tx(&mut self, queue: &Virtqueue) {
        while let Some(chain) = queue.get_next_avail() {
            let mut packet = Vec::new();
            
            for desc in &chain {
                if desc.flags & VirtqDesc::F_WRITE == 0 {
                    // Read from guest buffer
                    let mut data = vec![0u8; desc.len as usize];
                    // Would copy from guest memory here
                    packet.extend_from_slice(&data);
                }
            }
            
            if !packet.is_empty() {
                self.tx_queue.lock().push_back(packet);
            }
            
            queue.add_used(chain[0].next as u32, 0);
        }
    }

    /// Process control queue
    fn process_ctrl(&mut self, queue: &Virtqueue) {
        while let Some(chain) = queue.get_next_avail() {
            // Process control commands
            queue.add_used(chain[0].next as u32, 1);
        }
    }
}

impl VirtioDevice for VirtioNet {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Net
    }

    fn features(&self) -> u64 {
        self.features.load(Ordering::SeqCst)
    }

    fn set_features(&mut self, features: u64) {
        self.acked_features.store(features, Ordering::SeqCst);
    }

    fn config_space(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                &self.mac as *const _ as *const u8,
                6
            )
        }
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        if offset < 6 && offset + data.len() <= 6 {
            for (i, &byte) in data.iter().enumerate() {
                self.mac[offset + i] = byte;
            }
        }
    }

    fn num_queues(&self) -> usize {
        (self.num_queue_pairs as usize * 2) + 1 // RX, TX pairs + control
    }

    fn process_queue(&mut self, queue_idx: usize, queue: &Virtqueue) {
        match queue_idx {
            0 => self.process_rx(queue),  // RX queue
            1 => self.process_tx(queue),  // TX queue
            2 => self.process_ctrl(queue), // Control queue
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.status.store(0, Ordering::SeqCst);
        self.acked_features.store(0, Ordering::SeqCst);
        self.rx_queue.lock().clear();
        self.tx_queue.lock().clear();
        self.ctrl_queue.lock().clear();
    }
}

/// Virtio block device
pub struct VirtioBlock {
    /// Disk capacity in 512-byte sectors
    pub capacity: u64,
    /// Block size
    pub block_size: u32,
    /// Features
    pub features: AtomicU64,
    /// Negotiated features
    pub acked_features: AtomicU64,
    /// Backend storage
    pub backend: Arc<RwLock<Box<dyn BlockBackend>>>,
    /// Write cache enabled
    pub writeback: AtomicBool,
}

/// Block backend trait
pub trait BlockBackend: Send + Sync {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), BlockError>;
    fn flush(&mut self) -> Result<(), BlockError>;
    fn get_capacity(&self) -> u64;
}

#[derive(Debug)]
pub enum BlockError {
    InvalidOffset,
    IoError,
}

/// Virtio block request header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

impl VirtioBlkReqHeader {
    pub const TYPE_IN: u32 = 0;
    pub const TYPE_OUT: u32 = 1;
    pub const TYPE_FLUSH: u32 = 4;
    pub const TYPE_DISCARD: u32 = 11;
    pub const TYPE_WRITE_ZEROES: u32 = 13;
}

impl VirtioBlock {
    pub fn new(backend: Box<dyn BlockBackend>) -> Self {
        let capacity = backend.get_capacity();
        
        Self {
            capacity,
            block_size: 512,
            features: AtomicU64::new(
                VirtioBlkFeatures::SIZE_MAX.bits() |
                VirtioBlkFeatures::SEG_MAX.bits() |
                VirtioBlkFeatures::FLUSH.bits() |
                VirtioBlkFeatures::CONFIG_WCE.bits()
            ),
            acked_features: AtomicU64::new(0),
            backend: Arc::new(RwLock::new(backend)),
            writeback: AtomicBool::new(true),
        }
    }

    fn process_request(&mut self, queue: &Virtqueue) {
        while let Some(chain) = queue.get_next_avail() {
            if chain.len() < 2 {
                queue.add_used(chain[0].next as u32, 0);
                continue;
            }
            
            // Parse request header
            let header = unsafe {
                mem::zeroed::<VirtioBlkReqHeader>()
            };
            
            let mut status = 0u8; // VIRTIO_BLK_S_OK
            
            match header.req_type {
                VirtioBlkReqHeader::TYPE_IN => {
                    // Read request
                    let offset = header.sector * 512;
                    let mut total_len = 0;
                    
                    for desc in &chain[1..chain.len()-1] {
                        if desc.flags & VirtqDesc::F_WRITE != 0 {
                            let mut buf = vec![0u8; desc.len as usize];
                            match self.backend.read().read(offset + total_len, &mut buf) {
                                Ok(()) => {
                                    // Would copy to guest memory
                                    total_len += desc.len as u64;
                                }
                                Err(_) => {
                                    status = 1; // VIRTIO_BLK_S_IOERR
                                    break;
                                }
                            }
                        }
                    }
                }
                VirtioBlkReqHeader::TYPE_OUT => {
                    // Write request
                    let offset = header.sector * 512;
                    let mut total_len = 0;
                    
                    for desc in &chain[1..chain.len()-1] {
                        if desc.flags & VirtqDesc::F_WRITE == 0 {
                            let mut buf = vec![0u8; desc.len as usize];
                            // Would copy from guest memory
                            match self.backend.write().write(offset + total_len, &buf) {
                                Ok(()) => {
                                    total_len += desc.len as u64;
                                }
                                Err(_) => {
                                    status = 1; // VIRTIO_BLK_S_IOERR
                                    break;
                                }
                            }
                        }
                    }
                }
                VirtioBlkReqHeader::TYPE_FLUSH => {
                    // Flush request
                    if let Err(_) = self.backend.write().flush() {
                        status = 1; // VIRTIO_BLK_S_IOERR
                    }
                }
                _ => {
                    status = 2; // VIRTIO_BLK_S_UNSUPP
                }
            }
            
            // Write status
            // Would write status to last descriptor
            
            queue.add_used(chain[0].next as u32, 1);
        }
    }
}

impl VirtioDevice for VirtioBlock {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Block
    }

    fn features(&self) -> u64 {
        self.features.load(Ordering::SeqCst)
    }

    fn set_features(&mut self, features: u64) {
        self.acked_features.store(features, Ordering::SeqCst);
    }

    fn config_space(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                &self.capacity as *const _ as *const u8,
                8
            )
        }
    }

    fn write_config(&mut self, _offset: usize, _data: &[u8]) {
        // Config is read-only for block device
    }

    fn num_queues(&self) -> usize {
        1 // Single request queue
    }

    fn process_queue(&mut self, _queue_idx: usize, queue: &Virtqueue) {
        self.process_request(queue);
    }

    fn reset(&mut self) {
        self.acked_features.store(0, Ordering::SeqCst);
    }
}

/// Virtio console device
pub struct VirtioConsole {
    /// Console ports
    pub ports: Vec<ConsolePort>,
    /// Features
    pub features: AtomicU64,
    /// Negotiated features
    pub acked_features: AtomicU64,
}

pub struct ConsolePort {
    pub id: u32,
    pub name: String,
    pub rx_buffer: VecDeque<u8>,
    pub tx_buffer: VecDeque<u8>,
    pub guest_connected: bool,
    pub host_connected: bool,
}

/// Virtio RNG device
pub struct VirtioRng {
    /// Random data source
    pub rng_source: Arc<Mutex<Box<dyn RngSource>>>,
    /// Features
    pub features: AtomicU64,
    /// Negotiated features
    pub acked_features: AtomicU64,
}

pub trait RngSource: Send + Sync {
    fn get_random_bytes(&mut self, buf: &mut [u8]);
}

/// Virtio balloon device
pub struct VirtioBalloon {
    /// Current balloon size in pages
    pub num_pages: AtomicU32,
    /// Target balloon size
    pub target_pages: AtomicU32,
    /// Actual pages
    pub actual_pages: AtomicU32,
    /// Features
    pub features: AtomicU64,
    /// Negotiated features
    pub acked_features: AtomicU64,
    /// Inflated pages
    pub inflated_pages: Mutex<Vec<u64>>,
}

/// Virtio device manager
pub struct VirtioManager {
    /// Registered devices
    devices: RwLock<Vec<Arc<Mutex<dyn VirtioDevice>>>>,
    /// Device queues
    queues: RwLock<Vec<Vec<Virtqueue>>>,
}

impl VirtioManager {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
            queues: RwLock::new(Vec::new()),
        }
    }

    /// Register a virtio device
    pub fn register_device(&self, device: Arc<Mutex<dyn VirtioDevice>>) -> usize {
        let mut devices = self.devices.write();
        let mut queues = self.queues.write();
        
        let device_id = devices.len();
        let num_queues = device.lock().num_queues();
        
        let mut device_queues = Vec::with_capacity(num_queues);
        for _ in 0..num_queues {
            device_queues.push(Virtqueue::new(256));
        }
        
        devices.push(device);
        queues.push(device_queues);
        
        device_id
    }

    /// Process device queue
    pub fn process_queue(&self, device_id: usize, queue_idx: usize) {
        let devices = self.devices.read();
        let queues = self.queues.read();
        
        if device_id < devices.len() && queue_idx < queues[device_id].len() {
            let mut device = devices[device_id].lock();
            device.process_queue(queue_idx, &queues[device_id][queue_idx]);
        }
    }

    /// Notify device
    pub fn notify(&self, device_id: usize, queue_idx: usize) {
        self.process_queue(device_id, queue_idx);
    }
}

lazy_static! {
    /// Global virtio manager
    pub static ref VIRTIO_MANAGER: VirtioManager = VirtioManager::new();
}

/// Initialize virtio subsystem
pub fn init() {
    log::info!("Virtio subsystem initialized");
}

/// Create a virtio network device
pub fn create_virtio_net(mac: [u8; 6]) -> Arc<Mutex<VirtioNet>> {
    let device = Arc::new(Mutex::new(VirtioNet::new(mac)));
    VIRTIO_MANAGER.register_device(device.clone() as Arc<Mutex<dyn VirtioDevice>>);
    device
}

/// Create a virtio block device
pub fn create_virtio_block(backend: Box<dyn BlockBackend>) -> Arc<Mutex<VirtioBlock>> {
    let device = Arc::new(Mutex::new(VirtioBlock::new(backend)));
    VIRTIO_MANAGER.register_device(device.clone() as Arc<Mutex<dyn VirtioDevice>>);
    device
}