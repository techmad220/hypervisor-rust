//! Network device backend implementation
//! Supports TAP devices, packet filtering, and virtual networking

use alloc::vec::Vec;
use alloc::collections::VecDeque;
use alloc::string::String;
use spin::Mutex;
use crate::HypervisorError;

/// Ethernet frame
#[repr(C, packed)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
    pub payload: [u8; 1500],
}

impl EthernetFrame {
    pub const TYPE_IPV4: u16 = 0x0800;
    pub const TYPE_ARP: u16 = 0x0806;
    pub const TYPE_IPV6: u16 = 0x86DD;
    pub const TYPE_VLAN: u16 = 0x8100;

    pub fn new(dst: [u8; 6], src: [u8; 6], ether_type: u16) -> Self {
        Self {
            dst_mac: dst,
            src_mac: src,
            ether_type: ether_type.to_be(),
            payload: [0; 1500],
        }
    }
}

/// IPv4 packet header
#[repr(C, packed)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
}

impl Ipv4Header {
    pub const PROTO_ICMP: u8 = 1;
    pub const PROTO_TCP: u8 = 6;
    pub const PROTO_UDP: u8 = 17;

    pub fn new(src_ip: u32, dst_ip: u32, protocol: u8, payload_len: u16) -> Self {
        let mut header = Self {
            version_ihl: 0x45, // IPv4, 20 byte header
            tos: 0,
            total_length: (20 + payload_len).to_be(),
            identification: 0,
            flags_fragment: 0x4000u16.to_be(), // Don't fragment
            ttl: 64,
            protocol,
            checksum: 0,
            src_ip: src_ip.to_be(),
            dst_ip: dst_ip.to_be(),
        };
        
        header.checksum = header.calculate_checksum();
        header
    }

    fn calculate_checksum(&self) -> u16 {
        let mut sum = 0u32;
        let header_words = unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u16,
                10
            )
        };
        
        for &word in header_words {
            sum += u16::from_be(word) as u32;
        }
        
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        (!sum as u16).to_be()
    }
}

/// TCP header
#[repr(C, packed)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub const FLAG_FIN: u16 = 0x0001;
    pub const FLAG_SYN: u16 = 0x0002;
    pub const FLAG_RST: u16 = 0x0004;
    pub const FLAG_PSH: u16 = 0x0008;
    pub const FLAG_ACK: u16 = 0x0010;
    pub const FLAG_URG: u16 = 0x0020;
}

/// UDP header
#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// ARP packet
#[repr(C, packed)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_len: u8,
    pub proto_len: u8,
    pub operation: u16,
    pub sender_hw: [u8; 6],
    pub sender_proto: u32,
    pub target_hw: [u8; 6],
    pub target_proto: u32,
}

impl ArpPacket {
    pub const OP_REQUEST: u16 = 1;
    pub const OP_REPLY: u16 = 2;

    pub fn new_request(sender_mac: [u8; 6], sender_ip: u32, target_ip: u32) -> Self {
        Self {
            hw_type: 1u16.to_be(), // Ethernet
            proto_type: 0x0800u16.to_be(), // IPv4
            hw_len: 6,
            proto_len: 4,
            operation: Self::OP_REQUEST.to_be(),
            sender_hw: sender_mac,
            sender_proto: sender_ip.to_be(),
            target_hw: [0; 6],
            target_proto: target_ip.to_be(),
        }
    }

    pub fn new_reply(sender_mac: [u8; 6], sender_ip: u32, target_mac: [u8; 6], target_ip: u32) -> Self {
        Self {
            hw_type: 1u16.to_be(),
            proto_type: 0x0800u16.to_be(),
            hw_len: 6,
            proto_len: 4,
            operation: Self::OP_REPLY.to_be(),
            sender_hw: sender_mac,
            sender_proto: sender_ip.to_be(),
            target_hw: target_mac,
            target_proto: target_ip.to_be(),
        }
    }
}

/// DHCP message
#[repr(C, packed)]
pub struct DhcpMessage {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: [u8; 312],
}

/// Virtual network switch
pub struct VirtualSwitch {
    /// Switch ports
    ports: Vec<Mutex<SwitchPort>>,
    /// MAC address table
    mac_table: Mutex<Vec<MacTableEntry>>,
    /// VLAN configuration
    vlans: Vec<Vlan>,
    /// Spanning Tree Protocol state
    stp_state: StpState,
}

/// Switch port
pub struct SwitchPort {
    pub id: u32,
    pub name: String,
    pub mac: [u8; 6],
    pub link_up: bool,
    pub speed: u32, // Mbps
    pub vlan_id: u16,
    pub trunk: bool,
    pub allowed_vlans: Vec<u16>,
    pub rx_queue: VecDeque<Vec<u8>>,
    pub tx_queue: VecDeque<Vec<u8>>,
    pub stats: PortStatistics,
}

/// Port statistics
#[derive(Default)]
pub struct PortStatistics {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// MAC table entry
pub struct MacTableEntry {
    pub mac: [u8; 6],
    pub port_id: u32,
    pub vlan_id: u16,
    pub age: u32,
    pub static_entry: bool,
}

/// VLAN configuration
pub struct Vlan {
    pub id: u16,
    pub name: String,
    pub ports: Vec<u32>,
}

/// STP state
pub struct StpState {
    pub enabled: bool,
    pub bridge_id: u64,
    pub root_id: u64,
    pub root_path_cost: u32,
    pub root_port: u32,
}

impl VirtualSwitch {
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            mac_table: Mutex::new(Vec::new()),
            vlans: Vec::new(),
            stp_state: StpState {
                enabled: false,
                bridge_id: 0,
                root_id: 0,
                root_path_cost: 0,
                root_port: 0,
            },
        }
    }

    /// Add a port to the switch
    pub fn add_port(&mut self, name: String, mac: [u8; 6]) -> u32 {
        let port_id = self.ports.len() as u32;
        
        self.ports.push(Mutex::new(SwitchPort {
            id: port_id,
            name,
            mac,
            link_up: false,
            speed: 1000,
            vlan_id: 1,
            trunk: false,
            allowed_vlans: vec![1],
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            stats: PortStatistics::default(),
        }));
        
        port_id
    }

    /// Forward packet
    pub fn forward_packet(&self, ingress_port: u32, packet: &[u8]) {
        if packet.len() < 14 {
            return; // Too small for Ethernet frame
        }

        let dst_mac = [packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]];
        let src_mac = [packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]];
        
        // Learn source MAC
        self.learn_mac(src_mac, ingress_port, 1);
        
        // Check if broadcast or multicast
        if dst_mac[0] & 0x01 != 0 {
            // Flood to all ports except ingress
            self.flood_packet(ingress_port, packet);
        } else {
            // Lookup destination
            if let Some(egress_port) = self.lookup_mac(&dst_mac, 1) {
                if egress_port != ingress_port {
                    self.send_packet(egress_port, packet);
                }
            } else {
                // Unknown unicast - flood
                self.flood_packet(ingress_port, packet);
            }
        }
    }

    /// Learn MAC address
    fn learn_mac(&self, mac: [u8; 6], port_id: u32, vlan_id: u16) {
        let mut table = self.mac_table.lock();
        
        // Check if already exists
        for entry in table.iter_mut() {
            if entry.mac == mac && entry.vlan_id == vlan_id {
                entry.port_id = port_id;
                entry.age = 0;
                return;
            }
        }
        
        // Add new entry
        table.push(MacTableEntry {
            mac,
            port_id,
            vlan_id,
            age: 0,
            static_entry: false,
        });
        
        // Limit table size
        if table.len() > 4096 {
            table.remove(0);
        }
    }

    /// Lookup MAC address
    fn lookup_mac(&self, mac: &[u8; 6], vlan_id: u16) -> Option<u32> {
        let table = self.mac_table.lock();
        
        for entry in table.iter() {
            if entry.mac == *mac && entry.vlan_id == vlan_id {
                return Some(entry.port_id);
            }
        }
        
        None
    }

    /// Flood packet to all ports
    fn flood_packet(&self, ingress_port: u32, packet: &[u8]) {
        for (id, port) in self.ports.iter().enumerate() {
            if id as u32 != ingress_port {
                let mut port = port.lock();
                if port.link_up {
                    port.tx_queue.push_back(packet.to_vec());
                    port.stats.tx_packets += 1;
                    port.stats.tx_bytes += packet.len() as u64;
                }
            }
        }
    }

    /// Send packet to specific port
    fn send_packet(&self, port_id: u32, packet: &[u8]) {
        if (port_id as usize) < self.ports.len() {
            let mut port = self.ports[port_id as usize].lock();
            if port.link_up {
                port.tx_queue.push_back(packet.to_vec());
                port.stats.tx_packets += 1;
                port.stats.tx_bytes += packet.len() as u64;
            }
        }
    }

    /// Age MAC table entries
    pub fn age_mac_table(&self) {
        let mut table = self.mac_table.lock();
        
        table.retain(|entry| {
            if entry.static_entry {
                true
            } else {
                entry.age < 300 // 5 minutes
            }
        });
        
        for entry in table.iter_mut() {
            if !entry.static_entry {
                entry.age += 1;
            }
        }
    }
}

/// TAP device interface
pub struct TapDevice {
    pub name: String,
    pub mac: [u8; 6],
    pub mtu: u16,
    pub rx_ring: VecDeque<Vec<u8>>,
    pub tx_ring: VecDeque<Vec<u8>>,
    pub stats: PortStatistics,
}

impl TapDevice {
    pub fn new(name: String, mac: [u8; 6]) -> Self {
        Self {
            name,
            mac,
            mtu: 1500,
            rx_ring: VecDeque::with_capacity(256),
            tx_ring: VecDeque::with_capacity(256),
            stats: PortStatistics::default(),
        }
    }

    /// Receive packet from host
    pub fn receive(&mut self, packet: Vec<u8>) {
        if packet.len() <= self.mtu as usize + 14 {
            self.rx_ring.push_back(packet);
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += packet.len() as u64;
        } else {
            self.stats.rx_dropped += 1;
        }
    }

    /// Transmit packet to host
    pub fn transmit(&mut self, packet: Vec<u8>) {
        self.tx_ring.push_back(packet);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += packet.len() as u64;
    }

    /// Get next packet to send to guest
    pub fn get_rx_packet(&mut self) -> Option<Vec<u8>> {
        self.rx_ring.pop_front()
    }

    /// Get next packet to send to host
    pub fn get_tx_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_ring.pop_front()
    }
}

/// Packet filter
pub struct PacketFilter {
    rules: Vec<FilterRule>,
}

#[derive(Clone)]
pub struct FilterRule {
    pub action: FilterAction,
    pub direction: Direction,
    pub protocol: Option<u8>,
    pub src_ip: Option<u32>,
    pub src_mask: Option<u32>,
    pub dst_ip: Option<u32>,
    pub dst_mask: Option<u32>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum FilterAction {
    Accept,
    Drop,
    Reject,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Direction {
    In,
    Out,
    Both,
}

impl PacketFilter {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
    }

    pub fn filter(&self, packet: &[u8], direction: Direction) -> FilterAction {
        // Parse packet
        if packet.len() < 34 {
            return FilterAction::Drop;
        }

        let ether_type = u16::from_be_bytes([packet[12], packet[13]]);
        
        if ether_type != EthernetFrame::TYPE_IPV4 {
            return FilterAction::Accept; // Only filter IPv4
        }

        let ip_header = unsafe {
            &*(packet[14..].as_ptr() as *const Ipv4Header)
        };

        let protocol = ip_header.protocol;
        let src_ip = u32::from_be(ip_header.src_ip);
        let dst_ip = u32::from_be(ip_header.dst_ip);
        
        let (src_port, dst_port) = if packet.len() >= 38 {
            match protocol {
                Ipv4Header::PROTO_TCP | Ipv4Header::PROTO_UDP => {
                    let src = u16::from_be_bytes([packet[34], packet[35]]);
                    let dst = u16::from_be_bytes([packet[36], packet[37]]);
                    (Some(src), Some(dst))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        // Check rules
        for rule in &self.rules {
            if rule.direction != Direction::Both && rule.direction != direction {
                continue;
            }

            let mut matches = true;

            if let Some(rule_proto) = rule.protocol {
                if rule_proto != protocol {
                    matches = false;
                }
            }

            if let (Some(rule_src), Some(mask)) = (rule.src_ip, rule.src_mask) {
                if (src_ip & mask) != (rule_src & mask) {
                    matches = false;
                }
            }

            if let (Some(rule_dst), Some(mask)) = (rule.dst_ip, rule.dst_mask) {
                if (dst_ip & mask) != (rule_dst & mask) {
                    matches = false;
                }
            }

            if let Some(rule_port) = rule.src_port {
                if src_port != Some(rule_port) {
                    matches = false;
                }
            }

            if let Some(rule_port) = rule.dst_port {
                if dst_port != Some(rule_port) {
                    matches = false;
                }
            }

            if matches {
                return rule.action;
            }
        }

        FilterAction::Accept // Default accept
    }
}

/// NAT (Network Address Translation)
pub struct Nat {
    /// NAT table
    table: Mutex<Vec<NatEntry>>,
    /// External IP
    external_ip: u32,
    /// Next available port
    next_port: u16,
}

pub struct NatEntry {
    pub internal_ip: u32,
    pub internal_port: u16,
    pub external_ip: u32,
    pub external_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,
    pub protocol: u8,
    pub last_activity: u64,
}

impl Nat {
    pub fn new(external_ip: u32) -> Self {
        Self {
            table: Mutex::new(Vec::new()),
            external_ip,
            next_port: 32768,
        }
    }

    /// Perform outbound NAT
    pub fn nat_outbound(&mut self, packet: &mut [u8]) -> Result<(), HypervisorError> {
        if packet.len() < 34 {
            return Err(HypervisorError::InvalidParameter);
        }

        let ip_header = unsafe {
            &mut *(packet[14..].as_ptr() as *mut Ipv4Header)
        };

        let protocol = ip_header.protocol;
        let internal_ip = u32::from_be(ip_header.src_ip);
        
        if protocol != Ipv4Header::PROTO_TCP && protocol != Ipv4Header::PROTO_UDP {
            return Ok(()); // Only NAT TCP/UDP
        }

        let internal_port = u16::from_be_bytes([packet[34], packet[35]]);
        let remote_ip = u32::from_be(ip_header.dst_ip);
        let remote_port = u16::from_be_bytes([packet[36], packet[37]]);

        // Find or create NAT entry
        let mut table = self.table.lock();
        
        let external_port = if let Some(entry) = table.iter_mut().find(|e| {
            e.internal_ip == internal_ip &&
            e.internal_port == internal_port &&
            e.protocol == protocol
        }) {
            entry.last_activity = 0;
            entry.external_port
        } else {
            let port = self.next_port;
            self.next_port = self.next_port.wrapping_add(1);
            if self.next_port < 32768 {
                self.next_port = 32768;
            }

            table.push(NatEntry {
                internal_ip,
                internal_port,
                external_ip: self.external_ip,
                external_port: port,
                remote_ip,
                remote_port,
                protocol,
                last_activity: 0,
            });

            port
        };

        // Rewrite packet
        ip_header.src_ip = self.external_ip.to_be();
        packet[34] = (external_port >> 8) as u8;
        packet[35] = external_port as u8;

        // Recalculate checksums
        ip_header.checksum = 0;
        ip_header.checksum = ip_header.calculate_checksum();

        Ok(())
    }

    /// Perform inbound NAT
    pub fn nat_inbound(&self, packet: &mut [u8]) -> Result<(), HypervisorError> {
        if packet.len() < 34 {
            return Err(HypervisorError::InvalidParameter);
        }

        let ip_header = unsafe {
            &mut *(packet[14..].as_ptr() as *mut Ipv4Header)
        };

        let protocol = ip_header.protocol;
        let external_port = u16::from_be_bytes([packet[36], packet[37]]);
        
        // Find NAT entry
        let table = self.table.lock();
        
        if let Some(entry) = table.iter().find(|e| {
            e.external_port == external_port &&
            e.protocol == protocol
        }) {
            // Rewrite packet
            ip_header.dst_ip = entry.internal_ip.to_be();
            packet[36] = (entry.internal_port >> 8) as u8;
            packet[37] = entry.internal_port as u8;

            // Recalculate checksums
            ip_header.checksum = 0;
            ip_header.checksum = ip_header.calculate_checksum();

            Ok(())
        } else {
            Err(HypervisorError::InvalidParameter)
        }
    }

    /// Clean up old NAT entries
    pub fn cleanup(&self) {
        let mut table = self.table.lock();
        
        table.retain(|entry| {
            entry.last_activity < 300 // 5 minutes timeout
        });

        for entry in table.iter_mut() {
            entry.last_activity += 1;
        }
    }
}

/// Network manager
pub struct NetworkManager {
    pub switches: Vec<VirtualSwitch>,
    pub tap_devices: Vec<Mutex<TapDevice>>,
    pub packet_filter: PacketFilter,
    pub nat: Option<Nat>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            switches: Vec::new(),
            tap_devices: Vec::new(),
            packet_filter: PacketFilter::new(),
            nat: None,
        }
    }

    /// Create virtual switch
    pub fn create_switch(&mut self) -> usize {
        let switch = VirtualSwitch::new();
        self.switches.push(switch);
        self.switches.len() - 1
    }

    /// Create TAP device
    pub fn create_tap(&mut self, name: String, mac: [u8; 6]) -> usize {
        let tap = TapDevice::new(name, mac);
        self.tap_devices.push(Mutex::new(tap));
        self.tap_devices.len() - 1
    }

    /// Enable NAT
    pub fn enable_nat(&mut self, external_ip: u32) {
        self.nat = Some(Nat::new(external_ip));
    }

    /// Process packet from guest
    pub fn process_guest_packet(&mut self, tap_id: usize, packet: Vec<u8>) 
        -> Result<(), HypervisorError> 
    {
        // Apply packet filter
        if self.packet_filter.filter(&packet, Direction::Out) == FilterAction::Drop {
            return Ok(());
        }

        // Apply NAT if enabled
        let mut packet = packet;
        if let Some(ref mut nat) = self.nat {
            nat.nat_outbound(&mut packet)?;
        }

        // Send to TAP device
        if tap_id < self.tap_devices.len() {
            let mut tap = self.tap_devices[tap_id].lock();
            tap.transmit(packet);
        }

        Ok(())
    }

    /// Process packet from host
    pub fn process_host_packet(&mut self, tap_id: usize, mut packet: Vec<u8>) 
        -> Result<(), HypervisorError> 
    {
        // Apply NAT if enabled
        if let Some(ref nat) = self.nat {
            nat.nat_inbound(&mut packet)?;
        }

        // Apply packet filter
        if self.packet_filter.filter(&packet, Direction::In) == FilterAction::Drop {
            return Ok(());
        }

        // Send to TAP device
        if tap_id < self.tap_devices.len() {
            let mut tap = self.tap_devices[tap_id].lock();
            tap.receive(packet);
        }

        Ok(())
    }
}

extern crate alloc;