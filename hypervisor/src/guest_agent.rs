//! Guest tools/agents communication interface
//! Provides bidirectional communication between hypervisor and guest agents
//! for enhanced VM management, monitoring, and control

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

/// Guest agent protocol versions
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum ProtocolVersion {
    V1 = 0x0100,
    V2 = 0x0200,
    V3 = 0x0300,
}

/// Communication channel types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChannelType {
    VirtioSerial,
    VirtioVsock,
    SharedMemory,
    Hypercall,
    PciDevice,
}

/// Message types for host-guest communication
#[derive(Debug, Clone, PartialEq)]
#[repr(u16)]
pub enum MessageType {
    // System messages
    Handshake = 0x0001,
    Heartbeat = 0x0002,
    Shutdown = 0x0003,
    Reboot = 0x0004,
    
    // File operations
    FileRead = 0x0100,
    FileWrite = 0x0101,
    FileList = 0x0102,
    FileCopy = 0x0103,
    FileDelete = 0x0104,
    
    // Process management
    ProcessList = 0x0200,
    ProcessKill = 0x0201,
    ProcessStart = 0x0202,
    ProcessInfo = 0x0203,
    
    // Network operations
    NetworkInfo = 0x0300,
    NetworkConfig = 0x0301,
    NetworkStats = 0x0302,
    
    // Memory operations
    MemoryStats = 0x0400,
    MemoryBalloon = 0x0401,
    MemoryHotplug = 0x0402,
    
    // Time sync
    TimeSync = 0x0500,
    TimeQuery = 0x0501,
    
    // Guest info
    GuestInfo = 0x0600,
    GuestCapabilities = 0x0601,
    GuestStatus = 0x0602,
    
    // Clipboard
    ClipboardCopy = 0x0700,
    ClipboardPaste = 0x0701,
    ClipboardClear = 0x0702,
    
    // Snapshot
    SnapshotCreate = 0x0800,
    SnapshotRestore = 0x0801,
    SnapshotDelete = 0x0802,
    
    // Custom commands
    CustomCommand = 0x0900,
    
    // Response codes
    ResponseOk = 0xF000,
    ResponseError = 0xF001,
    ResponseAsync = 0xF002,
}

/// Message header for all communications
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub magic: u32,           // 0x47554553 'GUES'
    pub version: u32,         // Protocol version
    pub msg_type: u16,        // MessageType
    pub flags: u16,           // Message flags
    pub sequence: u32,        // Sequence number
    pub timestamp: u64,       // Unix timestamp
    pub payload_size: u32,    // Size of payload
    pub checksum: u32,        // CRC32 checksum
}

impl MessageHeader {
    const MAGIC: u32 = 0x47554553; // 'GUES'
    
    pub fn new(msg_type: MessageType, payload_size: u32) -> Self {
        Self {
            magic: Self::MAGIC,
            version: ProtocolVersion::V3 as u32,
            msg_type: msg_type as u16,
            flags: 0,
            sequence: 0,
            timestamp: 0, // Would use actual timestamp
            payload_size,
            checksum: 0,
        }
    }
    
    pub fn calculate_checksum(&mut self, payload: &[u8]) {
        // Simple CRC32 implementation
        let mut crc = 0xFFFFFFFF_u32;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<Self>() - 4, // Exclude checksum field
            )
        };
        
        for &byte in bytes.iter().chain(payload.iter()) {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB88320
                } else {
                    crc >> 1
                };
            }
        }
        
        self.checksum = !crc;
    }
    
    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        let mut temp = *self;
        let saved_checksum = temp.checksum;
        temp.checksum = 0;
        temp.calculate_checksum(payload);
        temp.checksum == saved_checksum
    }
}

/// Guest capabilities
#[derive(Debug, Clone)]
pub struct GuestCapabilities {
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
    pub supported_features: Vec<String>,
    pub protocol_version: ProtocolVersion,
}

/// Guest agent state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AgentState {
    Disconnected,
    Connecting,
    Handshaking,
    Connected,
    Error,
}

/// Individual guest agent connection
pub struct GuestAgent {
    pub vm_id: u64,
    pub state: AtomicU32,
    pub capabilities: RwLock<Option<GuestCapabilities>>,
    pub last_heartbeat: AtomicU64,
    pub sequence_counter: AtomicU32,
    pub pending_requests: Mutex<BTreeMap<u32, PendingRequest>>,
    pub rx_queue: Mutex<VecDeque<Message>>,
    pub tx_queue: Mutex<VecDeque<Message>>,
    pub channel: RwLock<Option<Arc<dyn CommunicationChannel>>>,
    pub statistics: AgentStatistics,
}

impl GuestAgent {
    pub fn new(vm_id: u64) -> Self {
        Self {
            vm_id,
            state: AtomicU32::new(AgentState::Disconnected as u32),
            capabilities: RwLock::new(None),
            last_heartbeat: AtomicU64::new(0),
            sequence_counter: AtomicU32::new(0),
            pending_requests: Mutex::new(BTreeMap::new()),
            rx_queue: Mutex::new(VecDeque::new()),
            tx_queue: Mutex::new(VecDeque::new()),
            channel: RwLock::new(None),
            statistics: AgentStatistics::new(),
        }
    }
    
    pub fn connect(&self, channel: Arc<dyn CommunicationChannel>) -> Result<(), &'static str> {
        self.state.store(AgentState::Connecting as u32, Ordering::SeqCst);
        *self.channel.write() = Some(channel);
        
        // Send handshake
        self.send_handshake()?;
        
        self.state.store(AgentState::Handshaking as u32, Ordering::SeqCst);
        Ok(())
    }
    
    fn send_handshake(&self) -> Result<(), &'static str> {
        let mut header = MessageHeader::new(MessageType::Handshake, 8);
        header.sequence = self.get_next_sequence();
        
        let payload = [(ProtocolVersion::V3 as u32).to_le_bytes(), [0u8; 4]].concat();
        header.calculate_checksum(&payload);
        
        let message = Message {
            header,
            payload: payload.to_vec(),
        };
        
        self.tx_queue.lock().push_back(message);
        Ok(())
    }
    
    pub fn send_message(&self, msg_type: MessageType, payload: Vec<u8>) -> Result<u32, &'static str> {
        if self.state.load(Ordering::SeqCst) != AgentState::Connected as u32 {
            return Err("Agent not connected");
        }
        
        let mut header = MessageHeader::new(msg_type, payload.len() as u32);
        header.sequence = self.get_next_sequence();
        header.calculate_checksum(&payload);
        
        let message = Message {
            header,
            payload: payload.clone(),
        };
        
        // Store pending request if expecting response
        if !matches!(msg_type, MessageType::ResponseOk | MessageType::ResponseError) {
            self.pending_requests.lock().insert(
                header.sequence,
                PendingRequest {
                    msg_type,
                    timestamp: header.timestamp,
                    payload,
                },
            );
        }
        
        self.tx_queue.lock().push_back(message);
        self.statistics.messages_sent.fetch_add(1, Ordering::Relaxed);
        
        Ok(header.sequence)
    }
    
    pub fn receive_message(&self) -> Option<Message> {
        let message = self.rx_queue.lock().pop_front();
        if message.is_some() {
            self.statistics.messages_received.fetch_add(1, Ordering::Relaxed);
        }
        message
    }
    
    pub fn process_message(&self, message: Message) -> Result<(), &'static str> {
        if !message.header.verify_checksum(&message.payload) {
            self.statistics.errors.fetch_add(1, Ordering::Relaxed);
            return Err("Invalid checksum");
        }
        
        match MessageType::from(message.header.msg_type) {
            MessageType::Heartbeat => {
                self.last_heartbeat.store(message.header.timestamp, Ordering::SeqCst);
                self.send_heartbeat_response()?;
            }
            
            MessageType::Handshake => {
                self.process_handshake(message)?;
            }
            
            MessageType::GuestCapabilities => {
                self.process_capabilities(message)?;
            }
            
            MessageType::ResponseOk | MessageType::ResponseError => {
                self.process_response(message)?;
            }
            
            _ => {
                // Queue for application processing
                self.rx_queue.lock().push_back(message);
            }
        }
        
        Ok(())
    }
    
    fn process_handshake(&self, message: Message) -> Result<(), &'static str> {
        if message.payload.len() < 4 {
            return Err("Invalid handshake payload");
        }
        
        let version = u32::from_le_bytes([
            message.payload[0],
            message.payload[1],
            message.payload[2],
            message.payload[3],
        ]);
        
        // Verify protocol version compatibility
        if version < ProtocolVersion::V1 as u32 || version > ProtocolVersion::V3 as u32 {
            return Err("Unsupported protocol version");
        }
        
        self.state.store(AgentState::Connected as u32, Ordering::SeqCst);
        
        // Request capabilities
        self.send_message(MessageType::GuestCapabilities, Vec::new())?;
        
        Ok(())
    }
    
    fn process_capabilities(&self, message: Message) -> Result<(), &'static str> {
        // Parse capabilities from payload
        // Format: null-terminated strings
        let mut capabilities = GuestCapabilities {
            os_type: String::new(),
            os_version: String::new(),
            agent_version: String::new(),
            supported_features: Vec::new(),
            protocol_version: ProtocolVersion::V3,
        };
        
        let mut offset = 0;
        let payload = &message.payload;
        
        // Parse OS type
        if let Some(end) = payload[offset..].iter().position(|&b| b == 0) {
            capabilities.os_type = String::from_utf8_lossy(&payload[offset..offset + end]).into_owned();
            offset += end + 1;
        }
        
        // Parse OS version
        if offset < payload.len() {
            if let Some(end) = payload[offset..].iter().position(|&b| b == 0) {
                capabilities.os_version = String::from_utf8_lossy(&payload[offset..offset + end]).into_owned();
                offset += end + 1;
            }
        }
        
        // Parse agent version
        if offset < payload.len() {
            if let Some(end) = payload[offset..].iter().position(|&b| b == 0) {
                capabilities.agent_version = String::from_utf8_lossy(&payload[offset..offset + end]).into_owned();
                offset += end + 1;
            }
        }
        
        // Parse features
        while offset < payload.len() {
            if let Some(end) = payload[offset..].iter().position(|&b| b == 0) {
                let feature = String::from_utf8_lossy(&payload[offset..offset + end]).into_owned();
                if !feature.is_empty() {
                    capabilities.supported_features.push(feature);
                }
                offset += end + 1;
            } else {
                break;
            }
        }
        
        *self.capabilities.write() = Some(capabilities);
        Ok(())
    }
    
    fn process_response(&self, message: Message) -> Result<(), &'static str> {
        let sequence = message.header.sequence;
        
        if let Some(pending) = self.pending_requests.lock().remove(&sequence) {
            // Handle response for pending request
            match MessageType::from(message.header.msg_type) {
                MessageType::ResponseOk => {
                    // Success response
                    self.statistics.successful_requests.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::ResponseError => {
                    // Error response
                    self.statistics.failed_requests.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    fn send_heartbeat_response(&self) -> Result<(), &'static str> {
        let timestamp = self.get_timestamp();
        let payload = timestamp.to_le_bytes().to_vec();
        self.send_message(MessageType::Heartbeat, payload)?;
        Ok(())
    }
    
    fn get_next_sequence(&self) -> u32 {
        self.sequence_counter.fetch_add(1, Ordering::SeqCst)
    }
    
    fn get_timestamp(&self) -> u64 {
        // In real implementation, would get actual timestamp
        0
    }
    
    pub fn is_connected(&self) -> bool {
        self.state.load(Ordering::SeqCst) == AgentState::Connected as u32
    }
    
    pub fn disconnect(&self) {
        self.state.store(AgentState::Disconnected as u32, Ordering::SeqCst);
        *self.channel.write() = None;
        self.pending_requests.lock().clear();
        self.rx_queue.lock().clear();
        self.tx_queue.lock().clear();
    }
}

impl From<u16> for MessageType {
    fn from(value: u16) -> Self {
        unsafe { core::mem::transmute(value) }
    }
}

/// Pending request tracking
struct PendingRequest {
    msg_type: MessageType,
    timestamp: u64,
    payload: Vec<u8>,
}

/// Message structure
#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

/// Agent statistics
pub struct AgentStatistics {
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub successful_requests: AtomicU64,
    pub failed_requests: AtomicU64,
    pub errors: AtomicU64,
}

impl AgentStatistics {
    pub fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

/// Communication channel trait
pub trait CommunicationChannel: Send + Sync {
    fn channel_type(&self) -> ChannelType;
    fn send(&self, data: &[u8]) -> Result<usize, &'static str>;
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, &'static str>;
    fn is_connected(&self) -> bool;
    fn close(&self);
}

/// Virtio serial channel implementation
pub struct VirtioSerialChannel {
    port_id: u32,
    tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    connected: AtomicBool,
}

impl VirtioSerialChannel {
    pub fn new(port_id: u32) -> Self {
        Self {
            port_id,
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            connected: AtomicBool::new(false),
        }
    }
}

impl CommunicationChannel for VirtioSerialChannel {
    fn channel_type(&self) -> ChannelType {
        ChannelType::VirtioSerial
    }
    
    fn send(&self, data: &[u8]) -> Result<usize, &'static str> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err("Channel not connected");
        }
        
        self.tx_queue.lock().push_back(data.to_vec());
        Ok(data.len())
    }
    
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err("Channel not connected");
        }
        
        if let Some(data) = self.rx_queue.lock().pop_front() {
            let len = data.len().min(buffer.len());
            buffer[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }
    
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
    
    fn close(&self) {
        self.connected.store(false, Ordering::SeqCst);
        self.tx_queue.lock().clear();
        self.rx_queue.lock().clear();
    }
}

/// Shared memory channel implementation
pub struct SharedMemoryChannel {
    base_address: u64,
    size: usize,
    tx_offset: AtomicU64,
    rx_offset: AtomicU64,
    connected: AtomicBool,
}

impl SharedMemoryChannel {
    pub fn new(base_address: u64, size: usize) -> Self {
        Self {
            base_address,
            size,
            tx_offset: AtomicU64::new(0),
            rx_offset: AtomicU64::new(0),
            connected: AtomicBool::new(false),
        }
    }
    
    unsafe fn get_ptr(&self, offset: u64) -> *mut u8 {
        (self.base_address + offset) as *mut u8
    }
}

impl CommunicationChannel for SharedMemoryChannel {
    fn channel_type(&self) -> ChannelType {
        ChannelType::SharedMemory
    }
    
    fn send(&self, data: &[u8]) -> Result<usize, &'static str> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err("Channel not connected");
        }
        
        let offset = self.tx_offset.load(Ordering::SeqCst);
        let available = self.size / 2; // Half for TX, half for RX
        
        if offset + data.len() as u64 > available as u64 {
            return Err("Buffer full");
        }
        
        unsafe {
            let ptr = self.get_ptr(offset);
            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        
        self.tx_offset.fetch_add(data.len() as u64, Ordering::SeqCst);
        Ok(data.len())
    }
    
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err("Channel not connected");
        }
        
        let offset = self.rx_offset.load(Ordering::SeqCst);
        let rx_base = self.size / 2; // Second half for RX
        
        // Check for available data
        let available = unsafe {
            let ptr = self.get_ptr(rx_base as u64 + offset);
            // Read size prefix (first 4 bytes)
            if offset + 4 > rx_base as u64 {
                return Ok(0);
            }
            u32::from_le_bytes([
                *ptr,
                *ptr.add(1),
                *ptr.add(2),
                *ptr.add(3),
            ]) as usize
        };
        
        if available == 0 || available > buffer.len() {
            return Ok(0);
        }
        
        unsafe {
            let ptr = self.get_ptr(rx_base as u64 + offset + 4);
            core::ptr::copy_nonoverlapping(ptr, buffer.as_mut_ptr(), available);
        }
        
        self.rx_offset.fetch_add((available + 4) as u64, Ordering::SeqCst);
        Ok(available)
    }
    
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
    
    fn close(&self) {
        self.connected.store(false, Ordering::SeqCst);
        self.tx_offset.store(0, Ordering::SeqCst);
        self.rx_offset.store(0, Ordering::SeqCst);
    }
}

/// Guest agent manager
pub struct GuestAgentManager {
    agents: RwLock<BTreeMap<u64, Arc<GuestAgent>>>,
    next_vm_id: AtomicU64,
    config: AgentConfig,
}

impl GuestAgentManager {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            agents: RwLock::new(BTreeMap::new()),
            next_vm_id: AtomicU64::new(1),
            config,
        }
    }
    
    pub fn register_vm(&self) -> u64 {
        let vm_id = self.next_vm_id.fetch_add(1, Ordering::SeqCst);
        let agent = Arc::new(GuestAgent::new(vm_id));
        self.agents.write().insert(vm_id, agent);
        vm_id
    }
    
    pub fn unregister_vm(&self, vm_id: u64) {
        if let Some(agent) = self.agents.write().remove(&vm_id) {
            agent.disconnect();
        }
    }
    
    pub fn get_agent(&self, vm_id: u64) -> Option<Arc<GuestAgent>> {
        self.agents.read().get(&vm_id).cloned()
    }
    
    pub fn connect_agent(&self, vm_id: u64, channel: Arc<dyn CommunicationChannel>) -> Result<(), &'static str> {
        if let Some(agent) = self.get_agent(vm_id) {
            agent.connect(channel)
        } else {
            Err("VM not found")
        }
    }
    
    pub fn broadcast_message(&self, msg_type: MessageType, payload: Vec<u8>) {
        for agent in self.agents.read().values() {
            if agent.is_connected() {
                let _ = agent.send_message(msg_type, payload.clone());
            }
        }
    }
    
    pub fn process_all_messages(&self) {
        for agent in self.agents.read().values() {
            // Process TX queue
            while let Some(message) = agent.tx_queue.lock().pop_front() {
                if let Some(channel) = &*agent.channel.read() {
                    let header_bytes = unsafe {
                        core::slice::from_raw_parts(
                            &message.header as *const _ as *const u8,
                            core::mem::size_of::<MessageHeader>(),
                        )
                    };
                    
                    let mut data = Vec::with_capacity(header_bytes.len() + message.payload.len());
                    data.extend_from_slice(header_bytes);
                    data.extend_from_slice(&message.payload);
                    
                    if channel.send(&data).is_ok() {
                        agent.statistics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
            }
            
            // Process RX queue
            if let Some(channel) = &*agent.channel.read() {
                let mut buffer = vec![0u8; 4096];
                while let Ok(received) = channel.receive(&mut buffer) {
                    if received == 0 {
                        break;
                    }
                    
                    if received >= core::mem::size_of::<MessageHeader>() {
                        let header = unsafe {
                            core::ptr::read(buffer.as_ptr() as *const MessageHeader)
                        };
                        
                        if header.magic == MessageHeader::MAGIC {
                            let payload_start = core::mem::size_of::<MessageHeader>();
                            let payload_end = payload_start + header.payload_size as usize;
                            
                            if received >= payload_end {
                                let message = Message {
                                    header,
                                    payload: buffer[payload_start..payload_end].to_vec(),
                                };
                                
                                let _ = agent.process_message(message);
                                agent.statistics.bytes_received.fetch_add(received as u64, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }
    }
    
    pub fn check_heartbeats(&self) {
        let current_time = 0; // Would use actual timestamp
        let timeout = self.config.heartbeat_timeout;
        
        for agent in self.agents.read().values() {
            if agent.is_connected() {
                let last_heartbeat = agent.last_heartbeat.load(Ordering::SeqCst);
                if current_time - last_heartbeat > timeout {
                    // Agent timeout - mark as disconnected
                    agent.state.store(AgentState::Error as u32, Ordering::SeqCst);
                }
            }
        }
    }
}

/// Agent configuration
pub struct AgentConfig {
    pub heartbeat_interval: u64,
    pub heartbeat_timeout: u64,
    pub max_message_size: usize,
    pub channel_buffer_size: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: 5000,  // 5 seconds
            heartbeat_timeout: 15000,   // 15 seconds
            max_message_size: 1024 * 1024, // 1MB
            channel_buffer_size: 64 * 1024, // 64KB
        }
    }
}

/// High-level agent operations
pub struct AgentOperations;

impl AgentOperations {
    pub fn shutdown_guest(agent: &GuestAgent, timeout: u32) -> Result<(), &'static str> {
        let payload = timeout.to_le_bytes().to_vec();
        agent.send_message(MessageType::Shutdown, payload)?;
        Ok(())
    }
    
    pub fn reboot_guest(agent: &GuestAgent) -> Result<(), &'static str> {
        agent.send_message(MessageType::Reboot, Vec::new())?;
        Ok(())
    }
    
    pub fn sync_time(agent: &GuestAgent, unix_timestamp: u64) -> Result<(), &'static str> {
        let payload = unix_timestamp.to_le_bytes().to_vec();
        agent.send_message(MessageType::TimeSync, payload)?;
        Ok(())
    }
    
    pub fn get_guest_info(agent: &GuestAgent) -> Result<u32, &'static str> {
        agent.send_message(MessageType::GuestInfo, Vec::new())
    }
    
    pub fn get_process_list(agent: &GuestAgent) -> Result<u32, &'static str> {
        agent.send_message(MessageType::ProcessList, Vec::new())
    }
    
    pub fn kill_process(agent: &GuestAgent, pid: u32) -> Result<u32, &'static str> {
        let payload = pid.to_le_bytes().to_vec();
        agent.send_message(MessageType::ProcessKill, payload)
    }
    
    pub fn get_network_info(agent: &GuestAgent) -> Result<u32, &'static str> {
        agent.send_message(MessageType::NetworkInfo, Vec::new())
    }
    
    pub fn get_memory_stats(agent: &GuestAgent) -> Result<u32, &'static str> {
        agent.send_message(MessageType::MemoryStats, Vec::new())
    }
    
    pub fn set_memory_balloon(agent: &GuestAgent, target_mb: u32) -> Result<u32, &'static str> {
        let payload = target_mb.to_le_bytes().to_vec();
        agent.send_message(MessageType::MemoryBalloon, payload)
    }
    
    pub fn execute_command(agent: &GuestAgent, command: &str) -> Result<u32, &'static str> {
        let mut payload = Vec::new();
        payload.extend_from_slice(command.as_bytes());
        payload.push(0); // Null terminate
        agent.send_message(MessageType::CustomCommand, payload)
    }
    
    pub fn copy_to_clipboard(agent: &GuestAgent, data: &[u8]) -> Result<u32, &'static str> {
        agent.send_message(MessageType::ClipboardCopy, data.to_vec())
    }
    
    pub fn paste_from_clipboard(agent: &GuestAgent) -> Result<u32, &'static str> {
        agent.send_message(MessageType::ClipboardPaste, Vec::new())
    }
    
    pub fn create_snapshot(agent: &GuestAgent, name: &str) -> Result<u32, &'static str> {
        let mut payload = Vec::new();
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        agent.send_message(MessageType::SnapshotCreate, payload)
    }
    
    pub fn file_read(agent: &GuestAgent, path: &str) -> Result<u32, &'static str> {
        let mut payload = Vec::new();
        payload.extend_from_slice(path.as_bytes());
        payload.push(0);
        agent.send_message(MessageType::FileRead, payload)
    }
    
    pub fn file_write(agent: &GuestAgent, path: &str, data: &[u8]) -> Result<u32, &'static str> {
        let mut payload = Vec::new();
        let path_bytes = path.as_bytes();
        payload.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(path_bytes);
        payload.extend_from_slice(data);
        agent.send_message(MessageType::FileWrite, payload)
    }
}

/// Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_header() {
        let mut header = MessageHeader::new(MessageType::Heartbeat, 8);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        header.calculate_checksum(&payload);
        assert!(header.verify_checksum(&payload));
    }
    
    #[test]
    fn test_guest_agent() {
        let agent = GuestAgent::new(1);
        assert!(!agent.is_connected());
        assert_eq!(agent.vm_id, 1);
    }
    
    #[test]
    fn test_agent_manager() {
        let manager = GuestAgentManager::new(AgentConfig::default());
        let vm_id = manager.register_vm();
        assert!(manager.get_agent(vm_id).is_some());
        manager.unregister_vm(vm_id);
        assert!(manager.get_agent(vm_id).is_none());
    }
}