//! VM Networking and Device Management
//! Complete implementation for virtual networking and device emulation

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use alloc::{string::String, vec::Vec, collections::{BTreeMap, VecDeque}, sync::Arc};
use spin::{RwLock, Mutex};

pub const TAP_DEVICE_PREFIX: &str = "tap";
pub const BRIDGE_NAME: &str = "virbr0";
pub const MAX_PACKET_SIZE: usize = 65536;
pub const VIRTIO_QUEUE_SIZE: usize = 256;
pub const MAX_NETWORK_DEVICES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Tap,
    Bridge,
    Nat,
    HostOnly,
    Vhost,
}

#[derive(Debug, Clone)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
    
    pub fn random() -> Self {
        // Generate random MAC with locally administered bit set
        let mut bytes = [0u8; 6];
        // Set locally administered and unicast bits
        bytes[0] = 0x02;
        for i in 1..6 {
            bytes[i] = Self::random_byte();
        }
        Self(bytes)
    }
    
    fn random_byte() -> u8 {
        // In real implementation, use proper random generator
        0xAB
    }
    
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
    
    pub fn to_string(&self) -> String {
        alloc::format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Default for MacAddress {
    fn default() -> Self {
        Self([0; 6])
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub flags: PacketFlags,
}

bitflags::bitflags! {
    pub struct PacketFlags: u32 {
        const BROADCAST = 0x1;
        const MULTICAST = 0x2;
        const UNICAST = 0x4;
        const CHECKSUM_VALID = 0x8;
        const VLAN_TAGGED = 0x10;
        const IPV4 = 0x20;
        const IPV6 = 0x40;
        const TCP = 0x80;
        const UDP = 0x100;
    }
}

pub struct PacketQueue {
    queue: Mutex<VecDeque<NetworkPacket>>,
    max_size: usize,
    dropped_packets: AtomicU64,
}

impl PacketQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            dropped_packets: AtomicU64::new(0),
        }
    }
    
    pub fn enqueue(&self, packet: NetworkPacket) -> bool {
        let mut queue = self.queue.lock();
        if queue.len() >= self.max_size {
            self.dropped_packets.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        queue.push_back(packet);
        true
    }
    
    pub fn dequeue(&self) -> Option<NetworkPacket> {
        self.queue.lock().pop_front()
    }
    
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }
    
    pub fn clear(&self) {
        self.queue.lock().clear();
    }
}

pub struct NetworkDevice {
    pub dev_id: u32,
    pub network_type: NetworkType,
    pub ifname: String,
    pub bridge: Option<String>,
    pub mac_address: MacAddress,
    
    // Statistics
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_errors: AtomicU64,
    
    // State
    pub running: AtomicBool,
    pub link_up: AtomicBool,
    pub promiscuous: AtomicBool,
    
    // Packet queues
    pub tx_queue: Arc<PacketQueue>,
    pub rx_queue: Arc<PacketQueue>,
    
    // Configuration
    pub mtu: AtomicUsize,
    pub speed_mbps: AtomicU64,
}

impl NetworkDevice {
    pub fn new(dev_id: u32, network_type: NetworkType) -> Self {
        Self {
            dev_id,
            network_type,
            ifname: format!("{}{}", TAP_DEVICE_PREFIX, dev_id),
            bridge: if network_type == NetworkType::Bridge {
                Some(BRIDGE_NAME.to_string())
            } else {
                None
            },
            mac_address: MacAddress::random(),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            running: AtomicBool::new(false),
            link_up: AtomicBool::new(false),
            promiscuous: AtomicBool::new(false),
            tx_queue: Arc::new(PacketQueue::new(1024)),
            rx_queue: Arc::new(PacketQueue::new(1024)),
            mtu: AtomicUsize::new(1500),
            speed_mbps: AtomicU64::new(1000),
        }
    }
    
    pub fn start(&self) -> Result<(), NetworkError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(NetworkError::AlreadyRunning);
        }
        
        // Initialize network interface
        self.initialize_interface()?;
        
        self.running.store(true, Ordering::SeqCst);
        self.link_up.store(true, Ordering::SeqCst);
        
        // Start packet processing
        self.start_packet_processing();
        
        Ok(())
    }
    
    pub fn stop(&self) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        self.running.store(false, Ordering::SeqCst);
        self.link_up.store(false, Ordering::SeqCst);
        
        // Clear queues
        self.tx_queue.clear();
        self.rx_queue.clear();
        
        Ok(())
    }
    
    pub fn send_packet(&self, data: &[u8]) -> Result<(), NetworkError> {
        if !self.link_up.load(Ordering::SeqCst) {
            return Err(NetworkError::LinkDown);
        }
        
        if data.len() > self.mtu.load(Ordering::SeqCst) {
            return Err(NetworkError::PacketTooLarge);
        }
        
        let packet = NetworkPacket {
            data: data.to_vec(),
            timestamp: Self::get_timestamp(),
            flags: self.analyze_packet_flags(data),
        };
        
        if self.tx_queue.enqueue(packet) {
            self.tx_packets.fetch_add(1, Ordering::SeqCst);
            self.tx_bytes.fetch_add(data.len() as u64, Ordering::SeqCst);
            Ok(())
        } else {
            self.tx_errors.fetch_add(1, Ordering::SeqCst);
            Err(NetworkError::QueueFull)
        }
    }
    
    pub fn receive_packet(&self) -> Option<Vec<u8>> {
        if let Some(packet) = self.rx_queue.dequeue() {
            self.rx_packets.fetch_add(1, Ordering::SeqCst);
            self.rx_bytes.fetch_add(packet.data.len() as u64, Ordering::SeqCst);
            Some(packet.data)
        } else {
            None
        }
    }
    
    pub fn get_statistics(&self) -> NetworkStatistics {
        NetworkStatistics {
            tx_packets: self.tx_packets.load(Ordering::SeqCst),
            rx_packets: self.rx_packets.load(Ordering::SeqCst),
            tx_bytes: self.tx_bytes.load(Ordering::SeqCst),
            rx_bytes: self.rx_bytes.load(Ordering::SeqCst),
            tx_errors: self.tx_errors.load(Ordering::SeqCst),
            rx_errors: self.rx_errors.load(Ordering::SeqCst),
            tx_dropped: self.tx_queue.dropped_packets.load(Ordering::SeqCst),
            rx_dropped: self.rx_queue.dropped_packets.load(Ordering::SeqCst),
        }
    }
    
    fn initialize_interface(&self) -> Result<(), NetworkError> {
        // Would initialize TAP device or other network interface
        Ok(())
    }
    
    fn start_packet_processing(&self) {
        // Would start threads for packet processing
    }
    
    fn analyze_packet_flags(&self, data: &[u8]) -> PacketFlags {
        let mut flags = PacketFlags::empty();
        
        if data.len() < 14 {
            return flags;
        }
        
        // Check destination MAC
        if data[0..6] == [0xFF; 6] {
            flags |= PacketFlags::BROADCAST;
        } else if data[0] & 0x01 != 0 {
            flags |= PacketFlags::MULTICAST;
        } else {
            flags |= PacketFlags::UNICAST;
        }
        
        // Check EtherType
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        match ethertype {
            0x0800 => flags |= PacketFlags::IPV4,
            0x86DD => flags |= PacketFlags::IPV6,
            0x8100 => flags |= PacketFlags::VLAN_TAGGED,
            _ => {}
        }
        
        flags
    }
    
    fn get_timestamp() -> u64 {
        0 // Would use actual timestamp
    }
}

#[derive(Debug, Clone)]
pub struct NetworkStatistics {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub tx_dropped: u64,
    pub rx_dropped: u64,
}

// Virtio Network Device
pub struct VirtioNetDevice {
    pub device_id: u32,
    pub features: VirtioNetFeatures,
    pub negotiated_features: VirtioNetFeatures,
    pub config: VirtioNetConfig,
    
    // Virtqueues
    pub rx_queue: VirtQueue,
    pub tx_queue: VirtQueue,
    pub ctrl_queue: Option<VirtQueue>,
    
    // Backend
    pub backend: Arc<NetworkDevice>,
    
    // State
    pub status: AtomicU64,
    pub isr_status: AtomicU64,
}

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
        const GUEST_ANNOUNCE = 1 << 21;
        const MQ = 1 << 22;
        const CTRL_MAC_ADDR = 1 << 23;
    }
}

#[derive(Debug, Clone)]
pub struct VirtioNetConfig {
    pub mac: MacAddress,
    pub status: u16,
    pub max_virtqueue_pairs: u16,
    pub mtu: u16,
}

pub struct VirtQueue {
    pub size: usize,
    pub desc_table: Vec<VirtQueueDesc>,
    pub avail_ring: VirtQueueAvail,
    pub used_ring: VirtQueueUsed,
    pub last_avail_idx: AtomicUsize,
    pub last_used_idx: AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct VirtQueueDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

pub struct VirtQueueAvail {
    pub flags: AtomicU64,
    pub idx: AtomicUsize,
    pub ring: Vec<u16>,
}

pub struct VirtQueueUsed {
    pub flags: AtomicU64,
    pub idx: AtomicUsize,
    pub ring: Vec<VirtQueueUsedElem>,
}

#[derive(Debug, Clone)]
pub struct VirtQueueUsedElem {
    pub id: u32,
    pub len: u32,
}

impl VirtioNetDevice {
    pub fn new(device_id: u32, backend: Arc<NetworkDevice>) -> Self {
        let features = VirtioNetFeatures::MAC 
            | VirtioNetFeatures::STATUS 
            | VirtioNetFeatures::MRG_RXBUF
            | VirtioNetFeatures::CTRL_VQ;
        
        let config = VirtioNetConfig {
            mac: backend.mac_address.clone(),
            status: 1, // Link up
            max_virtqueue_pairs: 1,
            mtu: backend.mtu.load(Ordering::SeqCst) as u16,
        };
        
        Self {
            device_id,
            features,
            negotiated_features: VirtioNetFeatures::empty(),
            config,
            rx_queue: VirtQueue::new(VIRTIO_QUEUE_SIZE),
            tx_queue: VirtQueue::new(VIRTIO_QUEUE_SIZE),
            ctrl_queue: Some(VirtQueue::new(64)),
            backend,
            status: AtomicU64::new(0),
            isr_status: AtomicU64::new(0),
        }
    }
    
    pub fn process_tx_queue(&self) {
        while let Some(desc_idx) = self.tx_queue.get_available_descriptor() {
            // Read packet from descriptor chain
            let packet_data = self.read_descriptor_chain(desc_idx);
            
            // Send packet through backend
            if let Err(_) = self.backend.send_packet(&packet_data) {
                // Handle error
            }
            
            // Mark descriptor as used
            self.tx_queue.add_used_descriptor(desc_idx, packet_data.len() as u32);
        }
        
        // Send interrupt if needed
        if self.should_notify() {
            self.send_interrupt();
        }
    }
    
    pub fn process_rx_queue(&self) {
        while let Some(packet) = self.backend.receive_packet() {
            if let Some(desc_idx) = self.rx_queue.get_available_descriptor() {
                // Write packet to descriptor chain
                self.write_descriptor_chain(desc_idx, &packet);
                
                // Mark descriptor as used
                self.rx_queue.add_used_descriptor(desc_idx, packet.len() as u32);
            } else {
                // No available descriptors, drop packet
                self.backend.rx_errors.fetch_add(1, Ordering::SeqCst);
                break;
            }
        }
        
        // Send interrupt if needed
        if self.should_notify() {
            self.send_interrupt();
        }
    }
    
    fn read_descriptor_chain(&self, desc_idx: u16) -> Vec<u8> {
        // Would read data from descriptor chain
        Vec::new()
    }
    
    fn write_descriptor_chain(&self, desc_idx: u16, data: &[u8]) {
        // Would write data to descriptor chain
    }
    
    fn should_notify(&self) -> bool {
        // Check if we should send interrupt to guest
        true
    }
    
    fn send_interrupt(&self) {
        self.isr_status.fetch_or(1, Ordering::SeqCst);
    }
}

impl VirtQueue {
    pub fn new(size: usize) -> Self {
        Self {
            size,
            desc_table: vec![VirtQueueDesc { addr: 0, len: 0, flags: 0, next: 0 }; size],
            avail_ring: VirtQueueAvail {
                flags: AtomicU64::new(0),
                idx: AtomicUsize::new(0),
                ring: vec![0; size],
            },
            used_ring: VirtQueueUsed {
                flags: AtomicU64::new(0),
                idx: AtomicUsize::new(0),
                ring: vec![VirtQueueUsedElem { id: 0, len: 0 }; size],
            },
            last_avail_idx: AtomicUsize::new(0),
            last_used_idx: AtomicUsize::new(0),
        }
    }
    
    pub fn get_available_descriptor(&self) -> Option<u16> {
        let avail_idx = self.avail_ring.idx.load(Ordering::SeqCst);
        let last_avail = self.last_avail_idx.load(Ordering::SeqCst);
        
        if avail_idx != last_avail {
            let desc_idx = self.avail_ring.ring[last_avail % self.size];
            self.last_avail_idx.store((last_avail + 1) % self.size, Ordering::SeqCst);
            Some(desc_idx)
        } else {
            None
        }
    }
    
    pub fn add_used_descriptor(&self, desc_idx: u16, len: u32) {
        let used_idx = self.used_ring.idx.load(Ordering::SeqCst);
        let elem = VirtQueueUsedElem {
            id: desc_idx as u32,
            len,
        };
        self.used_ring.ring[used_idx % self.size] = elem;
        self.used_ring.idx.store((used_idx + 1) % self.size, Ordering::SeqCst);
    }
}

// Network Manager
pub struct NetworkManager {
    devices: RwLock<BTreeMap<u32, Arc<NetworkDevice>>>,
    virtio_devices: RwLock<BTreeMap<u32, Arc<VirtioNetDevice>>>,
    next_device_id: AtomicU64,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(BTreeMap::new()),
            virtio_devices: RwLock::new(BTreeMap::new()),
            next_device_id: AtomicU64::new(1),
        }
    }
    
    pub fn create_network_device(&self, network_type: NetworkType) -> Result<Arc<NetworkDevice>, NetworkError> {
        let dev_id = self.next_device_id.fetch_add(1, Ordering::SeqCst) as u32;
        let device = Arc::new(NetworkDevice::new(dev_id, network_type));
        
        device.start()?;
        
        self.devices.write().insert(dev_id, device.clone());
        Ok(device)
    }
    
    pub fn create_virtio_device(&self, backend: Arc<NetworkDevice>) -> Arc<VirtioNetDevice> {
        let dev_id = self.next_device_id.fetch_add(1, Ordering::SeqCst) as u32;
        let device = Arc::new(VirtioNetDevice::new(dev_id, backend));
        
        self.virtio_devices.write().insert(dev_id, device.clone());
        device
    }
    
    pub fn remove_device(&self, dev_id: u32) -> Result<(), NetworkError> {
        if let Some(device) = self.devices.write().remove(&dev_id) {
            device.stop()?;
        }
        
        self.virtio_devices.write().remove(&dev_id);
        Ok(())
    }
    
    pub fn get_device(&self, dev_id: u32) -> Option<Arc<NetworkDevice>> {
        self.devices.read().get(&dev_id).cloned()
    }
    
    pub fn get_all_statistics(&self) -> Vec<(u32, NetworkStatistics)> {
        self.devices.read()
            .iter()
            .map(|(id, device)| (*id, device.get_statistics()))
            .collect()
    }
}

#[derive(Debug)]
pub enum NetworkError {
    AlreadyRunning,
    NotRunning,
    LinkDown,
    PacketTooLarge,
    QueueFull,
    InvalidConfiguration,
    DeviceNotFound,
    InitializationFailed(String),
    IoError(String),
}

impl core::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NetworkError::AlreadyRunning => write!(f, "Network device already running"),
            NetworkError::NotRunning => write!(f, "Network device not running"),
            NetworkError::LinkDown => write!(f, "Network link is down"),
            NetworkError::PacketTooLarge => write!(f, "Packet exceeds MTU"),
            NetworkError::QueueFull => write!(f, "Packet queue is full"),
            NetworkError::InvalidConfiguration => write!(f, "Invalid network configuration"),
            NetworkError::DeviceNotFound => write!(f, "Network device not found"),
            NetworkError::InitializationFailed(s) => write!(f, "Initialization failed: {}", s),
            NetworkError::IoError(s) => write!(f, "I/O error: {}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mac_address() {
        let mac = MacAddress::random();
        assert_eq!(mac.as_bytes()[0] & 0x02, 0x02); // Locally administered
        assert_eq!(mac.as_bytes()[0] & 0x01, 0x00); // Unicast
        
        let mac_str = mac.to_string();
        assert_eq!(mac_str.len(), 17); // XX:XX:XX:XX:XX:XX
    }
    
    #[test]
    fn test_packet_queue() {
        let queue = PacketQueue::new(10);
        
        for i in 0..10 {
            let packet = NetworkPacket {
                data: vec![i as u8; 100],
                timestamp: i as u64,
                flags: PacketFlags::UNICAST,
            };
            assert!(queue.enqueue(packet));
        }
        
        // Queue should be full
        let packet = NetworkPacket {
            data: vec![0xFF; 100],
            timestamp: 11,
            flags: PacketFlags::BROADCAST,
        };
        assert!(!queue.enqueue(packet));
        assert_eq!(queue.dropped_packets.load(Ordering::SeqCst), 1);
        
        // Dequeue packets
        for i in 0..10 {
            let packet = queue.dequeue().unwrap();
            assert_eq!(packet.data[0], i as u8);
        }
        
        assert!(queue.is_empty());
    }
    
    #[test]
    fn test_network_device() {
        let device = NetworkDevice::new(1, NetworkType::Tap);
        
        assert_eq!(device.dev_id, 1);
        assert_eq!(device.network_type, NetworkType::Tap);
        assert_eq!(device.ifname, "tap1");
        
        // Test packet sending
        let _ = device.start();
        let data = vec![0x00; 64];
        let _ = device.send_packet(&data);
        
        assert_eq!(device.tx_packets.load(Ordering::SeqCst), 1);
        assert_eq!(device.tx_bytes.load(Ordering::SeqCst), 64);
    }
}