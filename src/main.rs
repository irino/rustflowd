#[macro_use]
extern crate clap;
extern crate pnet;
use pnet::packet::PrimitiveValues;
use byteorder::{NetworkEndian, WriteBytesExt};
use bytes::{BytesMut, BufMut};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Cursor, Error};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::net::UdpSocket;
use std::result::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use clap::{App, Arg};
use pcap_file::pcap::PcapReader;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

struct NetflowV5Header {
    version: u16,
    count: u16,
    system_up_time: u32, // Time in milliseconds since this device was first booted.
    export_time: u32, // seconds since the UNIX epoch of 1 January 1970 at 00:00 UTC
    export_time_nsecs: u32,
    sequence_number: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_algorithm_interval: u16,
}

impl NetflowV5Header {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);
        c.write_u16::<NetworkEndian>(self.version)?;
        c.write_u16::<NetworkEndian>(self.count)?;
        c.write_u32::<NetworkEndian>(self.system_up_time)?;
        c.write_u32::<NetworkEndian>(self.export_time)?;
        c.write_u32::<NetworkEndian>(self.export_time_nsecs)?;
        c.write_u32::<NetworkEndian>(self.sequence_number)?;
        c.write_u8(self.engine_type)?;
        c.write_u8(self.engine_id)?;
        c.write_u16::<NetworkEndian>(
            self.sampling_algorithm_interval,
        )?;
        Ok(c.into_inner())
    }
}

#[derive(Debug)]
struct Option {
    flow_active_timeout: u16, // Information Element 37 (default: 1800 seconds)
    flow_idle_timeout: u16, // Information Element 38 (default: 15 seconds)
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    ip_addresses: [Ipv6Addr; 2], // Using to_compatible for storeing Ipv4Addr
    transport_ports: [u16; 2],
    protocol_identifier: IpNextHeaderProtocol,
    ip_version: u8,
    ip_class_of_service: u8,
}

#[derive(Debug, Clone, Copy)]
struct FlowValue {
    start: SystemTime,
    end: SystemTime,
    packet_delta_count: u64,
    octet_delta_count: u64,
    tcp_control_bits: u16,
}

impl FlowValue {
    fn update(&mut self, new_flow_value: FlowValue) {
        self.end = new_flow_value.end;
        self.packet_delta_count += 1;
        self.octet_delta_count += new_flow_value.octet_delta_count;
        self.tcp_control_bits |= new_flow_value.tcp_control_bits;
    }
}

#[derive(Debug)]
struct Flow {
    key: FlowKey,
    value: FlowValue,
}

impl Flow {
    pub fn to_netflowv5_record_bytes(
        &self,
        system_init_time: SystemTime,
    ) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);
        c.write_u32::<NetworkEndian>(
            u32::from(self.key.ip_addresses[0].to_ipv4().unwrap()),
        )?;
        c.write_u32::<NetworkEndian>(
            u32::from(self.key.ip_addresses[1].to_ipv4().unwrap()),
        )?;
        c.write_u32::<NetworkEndian>(
            u32::from(Ipv4Addr::UNSPECIFIED),
        )?;
        c.write_u16::<NetworkEndian>(0)?; //ingressInterface
        c.write_u16::<NetworkEndian>(0)?; //egressInterface
        c.write_u32::<NetworkEndian>(
            self.value.octet_delta_count as u32,
        )?;
        c.write_u32::<NetworkEndian>(
            self.value.packet_delta_count as u32,
        )?;
        c.write_u32::<NetworkEndian>(self.value
            .start
            .duration_since(system_init_time)
            .unwrap()
            .as_millis() as u32)?;
        c.write_u32::<NetworkEndian>(self.value
            .end
            .duration_since(system_init_time)
            .unwrap()
            .as_millis() as u32)?;
        c.write_u16::<NetworkEndian>(self.key.transport_ports[0])?; //sourceTransportPort
        c.write_u16::<NetworkEndian>(self.key.transport_ports[1])?; //destinationTransportPort
        c.write_u8(0)?; //paddingOcctets
        c.write_u8(self.value.tcp_control_bits as u8)?;
        c.write_u8(self.key.protocol_identifier.0)?;
        c.write_u8(self.key.ip_class_of_service)?;
        c.write_u16::<NetworkEndian>(0)?; //bgpSourceAsNumber
        c.write_u16::<NetworkEndian>(0)?; //bgpDestinationAsNumber
        c.write_u8(0)?; //sourceIPv4PrefixLength
        c.write_u8(0)?; //sourceIPv4PrefixLength
        c.write_u16::<NetworkEndian>(0)?; //paddingOcctets
        Ok(c.into_inner())
    }
}

fn handle_udp_packet(packet: &[u8], flow: &mut Flow) {
    let udp = UdpPacket::new(packet);
    if let Some(udp) = udp {
        flow.key.transport_ports[0] = udp.get_source();
        flow.key.transport_ports[1] = udp.get_destination();
    }
}
fn handle_tcp_packet(packet: &[u8], flow: &mut Flow) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        flow.key.transport_ports[0] = tcp.get_source();
        flow.key.transport_ports[1] = tcp.get_destination();
        flow.value.tcp_control_bits = tcp.get_flags();
    }
}
fn handle_icmp_packet(packet: &[u8], flow: &mut Flow) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        flow.key.transport_ports[1] = (icmp_packet.get_icmp_type().to_primitive_values().0 as
                                           u16) * 256 +
            icmp_packet.get_icmp_code().to_primitive_values().0 as u16;
    }
}
fn handle_icmpv6_packet(packet: &[u8], flow: &mut Flow) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        flow.key.transport_ports[1] =
            (icmpv6_packet.get_icmpv6_type().to_primitive_values().0 as u16) * 256 +
                icmpv6_packet.get_icmpv6_code().to_primitive_values().0 as u16
    }
}

fn handle_transport_protocol(packet: &[u8], flow: &mut Flow) {
    match flow.key.protocol_identifier {
        IpNextHeaderProtocols::Udp => handle_udp_packet(packet, flow),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(packet, flow),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(packet, flow),
        IpNextHeaderProtocols::Icmpv6 => handle_icmpv6_packet(packet, flow),
        _ => println!("Unsupported protocol: {:?}", flow.key.protocol_identifier),
    }
}

fn handle_ipv4_packet(packet: &[u8], flow: &mut Flow) {
    let ipv4packet = Ipv4Packet::new(packet);
    if let Some(ipv4packet) = ipv4packet {
        flow.key.ip_addresses[0] = ipv4packet.get_source().to_ipv6_compatible();
        flow.key.ip_addresses[1] = ipv4packet.get_destination().to_ipv6_compatible();
        flow.key.protocol_identifier = ipv4packet.get_next_level_protocol();
        flow.key.ip_version = ipv4packet.get_version();
        flow.key.ip_class_of_service = ipv4packet.get_dscp() | ipv4packet.get_ecn();
        handle_transport_protocol(ipv4packet.payload(), flow);
    }
}

fn handle_ipv6_packet(packet: &[u8], flow: &mut Flow) {
    let ipv6packet = Ipv6Packet::new(packet);
    if let Some(ipv6packet) = ipv6packet {
        flow.key.ip_addresses[0] = ipv6packet.get_source();
        flow.key.ip_addresses[1] = ipv6packet.get_destination();
        flow.key.protocol_identifier = ipv6packet.get_next_header();
        flow.key.ip_version = ipv6packet.get_version();
        flow.key.ip_class_of_service = ipv6packet.get_traffic_class();
        handle_transport_protocol(ipv6packet.payload(), flow);
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, flow: &mut Flow) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet.payload(), flow),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet.payload(), flow),
        _ => println!("Unsupported ethertype"),
    }
}

fn read_pcap_file_packet(
    packet: pcap_file::pcap::Packet,
    option: &Option,
    flows: &mut HashMap<FlowKey, FlowValue>,
    expired_flows: &mut VecDeque<Flow>,
    socket: &UdpSocket,
    system_init_time: SystemTime,
) -> SystemTime {
    let ethernet_packet = EthernetPacket::new(&packet.data[..]).unwrap();
    let timestamp = SystemTime::checked_add(
        &UNIX_EPOCH,
        Duration::new(packet.header.ts_sec.into(), packet.header.ts_nsec),
    ).unwrap();
    let mut flow = Flow {
        key: FlowKey {
            ip_addresses: [Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED],
            transport_ports: [0, 0],
            protocol_identifier: IpNextHeaderProtocols::Reserved,
            ip_version: 0,
            ip_class_of_service: 0,
        },
        value: FlowValue {
            start: timestamp,
            end: timestamp,
            packet_delta_count: 1,
            octet_delta_count: packet.header.orig_len.into(),
            tcp_control_bits: 0,
        },
    };
    handle_ethernet_frame(&ethernet_packet, &mut flow);
    if flows.is_empty() {
        flows.insert(flow.key, flow.value);
        return timestamp;
    }
    if flows.contains_key(&flow.key) {
        if let Some(exist_flow_value) = flows.get_mut(&flow.key) {
            let idle_duration = flow.value
                .start
                .duration_since(exist_flow_value.end)
                .unwrap();
            let active_duration = flow.value
                .start
                .duration_since(exist_flow_value.start)
                .unwrap();
            if idle_duration.as_secs() > option.flow_idle_timeout.into() {
                println!("flow timeout {:?}, {:?}", flow.key, exist_flow_value);
                expired_flows.push_back(Flow {
                    key: flow.key.clone(),
                    value: *exist_flow_value,
                });
                if expired_flows.len() >= 30 {
                    send_netflowv5_packet(expired_flows, socket, timestamp, system_init_time)
                }
                *exist_flow_value = flow.value;
            } else if active_duration.as_secs() > option.flow_active_timeout.into() {
                println!("flow timeout {:?}, {:?}", flow.key, exist_flow_value);
                expired_flows.push_back(Flow {
                    key: flow.key.clone(),
                    value: *exist_flow_value,
                });
                *exist_flow_value = flow.value;
            } else {
                exist_flow_value.update(flow.value);
            }
            let tcp_flag = exist_flow_value.tcp_control_bits;
            if tcp_flag & TcpFlags::FIN > 0 || tcp_flag & TcpFlags::RST > 0 {
                expired_flows.push_back(Flow {
                    key: flow.key.clone(),
                    value: *exist_flow_value,
                });
                flows.remove(&flow.key);
            }
        }
    } else {
        flows.insert(flow.key, flow.value);
    }
    return timestamp;
}

fn read_pcap_file_packets(
    pcap_reader: PcapReader<File>,
    option: &Option,
    flows: &mut HashMap<FlowKey, FlowValue>,
    expired_flows: &mut VecDeque<Flow>,
    socket: &UdpSocket,
    system_init_time: SystemTime,
) -> SystemTime {
    let mut timestamp = UNIX_EPOCH;
    for pcap in pcap_reader {
        timestamp = read_pcap_file_packet(
            pcap.unwrap(),
            option,
            flows,
            expired_flows,
            socket,
            system_init_time,
        );
    }
    return timestamp;
}

fn send_netflowv5_packet(
    expired_flows: &mut VecDeque<Flow>,
    socket: &UdpSocket,
    time: SystemTime,
    system_init_time: SystemTime,
) {
    let mut bytes = BytesMut::with_capacity(1464);
    let header = NetflowV5Header {
        version: 5,
        count: 30,
        system_up_time: time.duration_since(system_init_time).unwrap().as_secs() as u32,
        export_time: time.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
        export_time_nsecs: time.duration_since(system_init_time).unwrap().as_nanos() as u32,
        sequence_number: 30,
        engine_type: 0,
        engine_id: 0,
        sampling_algorithm_interval: 0,
    };
    let header_buf = header.to_bytes().unwrap();
    bytes.put_slice(&header_buf);
    for _r in 0..header.count {
        let record_buf = expired_flows
            .pop_front()
            .unwrap()
            .to_netflowv5_record_bytes(system_init_time)
            .unwrap();
        bytes.put_slice(&record_buf);
    }
    socket.send(bytes.as_ref()).unwrap();
}

fn main() {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!())
        .arg(
            Arg::with_name("export-version")
                .help("NetFlow export packet version")
                .short("v")
                .long("export-version")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("read-pcap-file")
                .help("Offiline packet capture (pcap) file to read")
                .short("r")
                .long("read-pcap-file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("destination-host-port")
                .help("Destination host and port")
                .short("d")
                .long("destination-host-port")
                .takes_value(true),
        );
    let matches = app.get_matches();
    let pcap_file = matches.value_of("read-pcap-file").unwrap_or("");
    println!("Use read-pcap-file: {}", pcap_file);
    let exportversion = matches.value_of("export-version").unwrap_or("5");
    println!("Use export version: {}", exportversion);
    let destination_host_port = matches.value_of("destination-host-port").unwrap_or("");
    println!("destination host and port: {}", destination_host_port);
    let socket = UdpSocket::bind("0.0.0.0:4739").expect("couldn't bind to address");
    socket.connect(destination_host_port).expect(
        "connect function failed",
    );
    let option = Option {
        flow_active_timeout: 1800,
        flow_idle_timeout: 15,
    };
    let mut pcap_reader = PcapReader::new(File::open(pcap_file).unwrap()).unwrap();
    let mut flows: HashMap<FlowKey, FlowValue> = HashMap::new();
    let mut expired_flows: VecDeque<Flow> = VecDeque::new();

    let system_init_time = read_pcap_file_packet(
        pcap_reader.next().unwrap().unwrap(),
        &option,
        &mut flows,
        &mut expired_flows,
        &socket,
        UNIX_EPOCH,
    );
    let timestamp = read_pcap_file_packets(
        pcap_reader,
        &option,
        &mut flows,
        &mut expired_flows,
        &socket,
        system_init_time,
    );
    for (key, value) in flows {
        expired_flows.push_back(Flow {
            key: key,
            value: value,
        });
    }
    loop {
        if expired_flows.len() >= 30 {
            send_netflowv5_packet(&mut expired_flows, &socket, timestamp, system_init_time)
        } else {
            break;
        }
    }
}
