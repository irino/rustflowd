use super::ipfix::{FieldSpecifier, default_ipv4_field_specifiers, default_ipv6_field_specifiers};

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::id;
use std::string::String;
use std::vec::Vec;
use pnet::packet::{PrimitiveValues, ip::IpNextHeaderProtocols};
use pnet::util::MacAddr;

use super::ipfix::{
    IPFIX_PROTOCOL_VERSION,
    IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC,
    PSAMP_SELECTOR_ALGORITHM_SYSTEMATIC_COUNT
};

const RUSTFLOWD_MAX_MESSAGE_SIZE: usize = 1472; // 1500(Ethernet) - 20(IPv4) - 8(UDP)

pub const RUSTFLOWD_FLOW_IPV4_INDEX: usize = 0;
pub const RUSTFLOWD_FLOW_IPV6_INDEX: usize = 1;    
pub const RUSTFLOWD_FLOW_MAX_INDEX: usize = 2;    

pub const METER_ETHER: u8 = 0x01;
pub const METER_VLAN: u8 = 0x02;
pub const METER_IPV4: u8 = 0x04;
pub const METER_IPV6: u8 = 0x08;
pub const METER_LAYER4: u8 = 0x10;
pub const METER_TUNNEL: u8 = 0x20;

pub fn flow_index(ip_version: u8) -> usize {
    return match ip_version {
	4 => RUSTFLOWD_FLOW_IPV4_INDEX,
	6 => RUSTFLOWD_FLOW_IPV6_INDEX,
	_ => RUSTFLOWD_FLOW_MAX_INDEX,
    };
}

pub struct ExportingProcessConfiguration {
    pub socket_addr: SocketAddr, // Information Element 130, 131, 217: exporter*
    pub collectors: Vec<SocketAddr>, // Information Element 211, 212, 216: collector*
    //pub interface: u32, // Information Element 213: exportInterface // not implemented
    pub protocol_version: u8, // Information Element 214: exportProtocolVersion
    pub transport_protocol: u8, // Information Element 215: exportTransportProtocol
    pub max_message_size: usize, // rustflowd original
    pub udp_socket: UdpSocket,
    pub field_specifiers: [Vec<FieldSpecifier>; 2],
    //pub max_records_per_message: [usize; 2],
}
impl Default for ExportingProcessConfiguration {
    fn default() -> ExportingProcessConfiguration {
	let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
	ExportingProcessConfiguration {
	    socket_addr: socket_addr,
            collectors: Vec::new(),
            protocol_version: IPFIX_PROTOCOL_VERSION,
            transport_protocol: IpNextHeaderProtocols::Udp.to_primitive_values().0,
            max_message_size: RUSTFLOWD_MAX_MESSAGE_SIZE,
            udp_socket: UdpSocket::bind(socket_addr).expect("failed to bind address"),
            field_specifiers: [default_ipv4_field_specifiers(), default_ipv6_field_specifiers()],
        }
    }
}

#[derive(Debug)]
pub struct MeteringProcessConfiguration {
    pub flow_active_timeout: u16, // Information Element 37 (default: 1800 seconds)
    pub flow_idle_timeout: u16, // Information Element 38 (default: 15 seconds)
    pub selector_algorithm: u16, // Information Element 304 (default: 1: Systematic count-based Sampling)
    pub sampling_packet_interval: u32, // Information Element 305 (default: 1)
    pub sampling_packet_space: u32, // Information Element 306 (default: 0)
    pub observation_domain_id: u32,
    pub observation_point_name: String,
    pub observation_point_online: bool,
    pub observation_point_mac_addr: MacAddr,
    pub track_level: u8,
    pub process_id: u32,
}
impl Default for MeteringProcessConfiguration {
    fn default() -> MeteringProcessConfiguration {
        MeteringProcessConfiguration {
            flow_active_timeout: 1800,
            flow_idle_timeout: 15,
            selector_algorithm: PSAMP_SELECTOR_ALGORITHM_SYSTEMATIC_COUNT,
            sampling_packet_interval: 1,
            sampling_packet_space: 0,
            observation_domain_id: 0,
            observation_point_name: String::with_capacity(255),
            observation_point_online: true,
            observation_point_mac_addr: MacAddr::zero(),
	    track_level: METER_ETHER|METER_IPV4|METER_LAYER4,
            process_id: id(),
        }
    }
}

impl MeteringProcessConfiguration {
    pub fn observation_domain_id_from_mac_addr(&self) -> u32{
        let mac_addr = self.observation_point_mac_addr.to_primitive_values();
        //return mac_addr.0 << 24 & mac_addr.1 << 16 & mac_addr.2 << 8 & mac_addr.3);
        return u32::from_ne_bytes([mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3]);
        }
        pub fn sampling_interval(&self) -> u32 { // Information Element 34
        (self.sampling_packet_interval + self.sampling_packet_space) / self.sampling_packet_interval
        }
        pub fn sampling_algorithm(&self) -> u8 { // Information Element 35
        match self.selector_algorithm {
            PSAMP_SELECTOR_ALGORITHM_SYSTEMATIC_COUNT => IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC,
            _ => 0,
        }
    }
}

pub struct CliConfiguration {
    pub verbose: u64,
}
impl Default for CliConfiguration {
    fn default() -> CliConfiguration {
	CliConfiguration {
	    verbose: 0,
	}
    }
}

pub struct Configuration {
    pub cli: CliConfiguration,
    pub export: ExportingProcessConfiguration,
    pub meter: MeteringProcessConfiguration,
}
impl Default for Configuration {
    fn default() -> Configuration {
	Configuration {
	    cli: Default::default(),
	    export: Default::default(),
	    meter: Default::default(),
	}
    }
}
