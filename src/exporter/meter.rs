use crate::rustflowd::api::*;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::gre::GrePacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::{ExtensionPacket, Ipv6Packet};
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::{Packet, PrimitiveValues};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Error, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

enum PacketSource {
    Interfaces(Vec<NetworkInterface>),
    Files(Vec<File>),
}

pub struct Meter {
    packet_source: PacketSource,
}

// refer to https://cipepser.hatenablog.com/entry/rust-multi-interface-packet-capture in japanese

#[derive(Clone, Debug)]
pub struct PacketInformation {
    interface: NetworkInterface,
    packet: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Queue<T: Send> {
    inner: Arc<Mutex<VecDeque<T>>>,
}

impl<T: Send> Queue<T> {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn get(&self) -> Option<T> {
        let _queue = self.inner.lock();
        if let Ok(mut queue) = _queue {
            queue.pop_front()
        } else {
            None
        }
    }
    fn add(&self, obj: T) -> usize {
        let _queue = self.inner.lock();
        if let Ok(mut queue) = _queue {
            queue.push_back(obj);
            queue.len()
        } else {
            0
        }
    }
}

impl Meter {
    pub fn new(observation_point_configuration: &ipfix::ObservationPoint) -> Meter {
        let offline = observation_point_configuration
            .offline
            .as_ref()
            .unwrap_or(&BoolValue { value: false })
            .value;

        if offline {
            if observation_point_configuration.if_name.len() > 0 {
                panic!("if_name is not specified although offline is specified");
            }
            let mut files: Vec<File> = Vec::new();
            for each_if_name in &observation_point_configuration.if_name {
                files.push(File::open(&each_if_name.value).expect("failed to read file"));
            }
            Meter {
                packet_source: PacketSource::Files(files),
            }
        } else {
            // online: setup interfaces
            if observation_point_configuration.if_name.len() > 0 {
                // if_name is specified
                let mut interfaces: Vec<NetworkInterface> = Vec::new();
                for each_if_name in &observation_point_configuration.if_name {
                    let interface = datalink::interfaces()
                        .into_iter()
                        .filter(|nif: &NetworkInterface| nif.name == each_if_name.value)
                        .next()
                        .expect("Failed to get Inteface");
                    interfaces.push(interface);
                }
                Meter {
                    packet_source: PacketSource::Interfaces(interfaces),
                }
            } else {
                // if_name is not specified, all interfaces will be used
                Meter {
                    packet_source: PacketSource::Interfaces(datalink::interfaces()),
                }
            }
        }
    }
    pub fn read(self: &'static Meter) -> Vec<std::thread::JoinHandle<()>>{
        let mut handles: Vec<_> = Vec::new();
        match &self.packet_source {
            // refer to https://cipepser.hatenablog.com/entry/rust-multi-interface-packet-capture in japanese
            PacketSource::Interfaces(interfaces) => {
                let queue = Queue::new();
                //let mut handles: Vec<_> = interfaces
                handles = interfaces
                    .into_iter()
                    .map(|interface| {
                        let queue = queue.clone();
                        thread::spawn(move || {
                            let mut rx = datalink::channel(&interface, Default::default())
                                .map(|chan| match chan {
                                    Ethernet(_, rx) => rx,
                                    _ => panic!(
                                        "could not initialize datalink channel {:?}",
                                        interface.name
                                    ),
                                })
                                .unwrap();
                            loop {
                                match rx.next() {
                                    Ok(src) => {
                                        queue.add(PacketInformation {
                                            interface: interface.clone(),
                                            packet: src.to_owned(),
                                        });
                                    }
                                    Err(_) => {
                                        continue;
                                    }
                                }
                            }
                        })
                    })
                    .collect();
                handles.push(thread::spawn(move || loop {
                    let queue = queue.clone();
                    match queue.get() {
                        Some(packet_information) => {
                            let packet = &packet_information.packet[..];
                            match EthernetPacket::new(packet) {
                                Some(packet) => {
                                    handle_ethernet_frame(
                                        &packet, 2u64, /*&packet_information.interface*/
                                    );
                                }
                                _ => {
                                    continue;
                                }
                            }
                        }
                        _ => {
                            continue;
                        }
                    }
                }));
            }
            PacketSource::Files(files) => {
                for mut file in files {
                    let mut buffer = [0; 4];
                    file.read(&mut buffer[..])
                        .expect("Failed to read magic number from file"); // read magic number
                    file.seek(SeekFrom::Start(0)).expect("Failed to seek"); // rewind to top
                    if buffer == [0x0A, 0x0D, 0x0D, 0x0A] {
                        let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
                        let mut if_linktypes = Vec::new();
                        loop {
                            match reader.next() {
                                Ok((offset, block)) => {
                                    match block {
                                        PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                                            // starting a new section, clear known interfaces
                                            if_linktypes = Vec::new();
                                        }
                                        PcapBlockOwned::NG(Block::InterfaceDescription(
                                            ref idb,
                                        )) => {
                                            if_linktypes.push(idb.linktype);
                                        }
                                        PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                                            assert!((epb.if_id as usize) < if_linktypes.len());
                                            let linktype = if_linktypes[epb.if_id as usize];
                                            #[cfg(feature = "data")]
                                            let packet_data = pcap_parser::data::get_packetdata(
                                                epb.data,
                                                linktype,
                                                epb.caplen as usize,
                                            );
                                        }
                                        PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                                            assert!(if_linktypes.len() > 0);
                                            let linktype = if_linktypes[0];
                                            let blen = (spb.block_len1 - 16) as usize;
                                            #[cfg(feature = "data")]
                                            let packet_data = pcap_parser::data::get_packetdata(
                                                spb.data, linktype, blen,
                                            );
                                        }
                                        PcapBlockOwned::NG(_) => {
                                            // can be statistics (ISB), name resolution (NRB), etc.
                                            eprintln!("unsupported block");
                                        }
                                        PcapBlockOwned::Legacy(_)
                                        | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
                                    }
                                    reader.consume(offset);
                                }
                                Err(PcapError::Eof) => break,
                                Err(PcapError::Incomplete) => {
                                    reader.refill().unwrap();
                                }
                                Err(e) => panic!("error while reading: {:?}", e),
                            }
                        }
                    } else if buffer == [0xA1, 0xB2, 0xC3, 0xD4]
                        || buffer == [0xD4, 0xC3, 0xB2, 0xA1]
                    {
                        let mut reader =
                            LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
                        loop {
                            match reader.next() {
                                Ok((offset, block)) => {
                                    match block {
                                        PcapBlockOwned::LegacyHeader(_hdr) => {
                                            // save hdr.network (linktype)
                                        }
                                        PcapBlockOwned::Legacy(b) => {
                                            // use linktype to parse b.data()
                                            let time = SystemTime::checked_add(
                                                &UNIX_EPOCH,
                                                Duration::new(b.ts_sec.into(), b.ts_usec),
                                            )
                                            .expect("failed to get time in offline");
                                        }
                                        PcapBlockOwned::NG(_) => unreachable!(),
                                    }
                                    reader.consume(offset);
                                }
                                Err(PcapError::Eof) => break,
                                Err(PcapError::Incomplete) => {
                                    reader.refill().unwrap();
                                }
                                Err(e) => panic!("error while reading: {:?}", e),
                            }
                        }
                    }
                }
            }
        }
        handles
    }
}

fn handle_udp_packet(packet: &[u8], /* flow: &mut Flow, */ verbose: u64) {
    let udp_packet = UdpPacket::new(packet);
    if verbose >= 2 {
        println!("handle_udp_packet {:?}", udp_packet)
    }
    /*
    if let Some(udp_packet) = udp_packet {
        flow.key.transport_ports[0] = udp_packet.get_source();
        flow.key.transport_ports[1] = udp_packet.get_destination();
    }
    */
}
fn handle_tcp_packet(packet: &[u8], /* flow: &mut Flow, */ verbose: u64) {
    let tcp_packet = TcpPacket::new(packet);
    if verbose >= 2 {
        println!("handle_tcp_packet {:?}", tcp_packet)
    }
    /*
    if let Some(tcp_packet) = tcp_packet {
        flow.key.transport_ports[0] = tcp_packet.get_source();
        flow.key.transport_ports[1] = tcp_packet.get_destination();
        flow.value.tcp_control_bits = tcp_packet.get_flags();
    }
    */
}
fn handle_icmp_packet(packet: &[u8], /* flow: &mut Flow, */ verbose: u64) {
    let icmp_packet = IcmpPacket::new(packet);
    if verbose >= 2 {
        println!("handle_icmp_packet {:?}", icmp_packet)
    }
    /*
    if let Some(icmp_packet) = icmp_packet {
        flow.key.transport_ports[1] = (icmp_packet.get_icmp_type().to_primitive_values().0 as u16)
            * 256
            + icmp_packet.get_icmp_code().to_primitive_values().0 as u16;
    }
    */
}
fn handle_icmpv6_packet(packet: &[u8], /* flow: &mut Flow, */ verbose: u64) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if verbose >= 2 {
        println!("handle_icmpv6_packet {:?}", icmpv6_packet)
    }
    /*
    if let Some(icmpv6_packet) = icmpv6_packet {
        flow.key.transport_ports[1] =
            (icmpv6_packet.get_icmpv6_type().to_primitive_values().0 as u16) * 256
                + icmpv6_packet.get_icmpv6_code().to_primitive_values().0 as u16
    }
    */
}

fn handle_transport_protocol(
    packet: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    /*
    match flow.key.protocol_identifier {
        IpNextHeaderProtocols::Udp => handle_udp_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Icmpv6 => handle_icmpv6_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Gre => {
            //if track_level & METER_TUNNEL > 0 {
            handle_gre_packet(
                packet,
                flow,
                metering_process_statistics,
                verbose,
                track_level,
            )
            //}
        }
        IpNextHeaderProtocols::Ipv4 => {
            //if track_level & METER_TUNNEL > 0 {
            handle_ipv4_packet(
                packet,
                flow,
                metering_process_statistics,
                verbose,
                track_level,
            )
            //}
        }

        IpNextHeaderProtocols::Ipv6 => {
            //if track_level & METER_TUNNEL > 0 {
            handle_ipv6_packet(
                packet,
                flow,
                metering_process_statistics,
                verbose,
                track_level,
            )
            //}
        }
        _ => {
            if verbose >= 1 {
                println!(
                    "Unsupported transport protocol: {:?}",
                    flow.key.protocol_identifier
                );
            }
        }
    }
    */
}

fn handle_ipv4_packet(
    packet: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    let ipv4_packet = Ipv4Packet::new(packet);
    if verbose >= 2 {
        println!("handle_ipv4_packet {:?}", ipv4_packet)
    }
    if let Some(ipv4_packet) = ipv4_packet {
        let source = IpAddr::V4(ipv4_packet.get_source());
        let destination = IpAddr::V4(ipv4_packet.get_destination());
        /*
        let _index = match source.cmp(&destination) {
            Less | Equal => 0,
            Greater => 1,
        };
            flow.key.ip_addresses[0] = source;
            flow.key.ip_addresses[1] = destination;
            flow.key.protocol_identifier = ipv4_packet.get_next_level_protocol();
            flow.key.ip_version = ipv4_packet.get_version();
            flow.key.ip_class_of_service = ipv4_packet.get_dscp() | ipv4_packet.get_ecn();
            handle_transport_protocol(
                ipv4_packet.payload(),
                flow,
                metering_process_statistics,
                verbose,
                track_level,
            );
        */
    }
}

fn handle_ipv6_extension_packet(
    packet: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    let extension_packet = ExtensionPacket::new(packet);
    if verbose >= 2 {
        println!("handle_ipv6_extension_packet {:?}", extension_packet)
    }
    /*
    if let Some(extension_packet) = extension_packet {
        flow.key.protocol_identifier = extension_packet.get_next_header();
        handle_transport_protocol(
            extension_packet.payload(),
            //flow,
            //metering_process_statistics,
            verbose,
            track_level,
        );
    }
    */
}

fn handle_ipv6_packet(
    packet: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    let ipv6_packet = Ipv6Packet::new(packet);
    if verbose >= 2 {
        println!("handle_ipv6_packet {:?}", ipv6_packet)
    }
    /*
    if let Some(ipv6_packet) = ipv6_packet {
        let source = IpAddr::V6(ipv6_packet.get_source());
        let destination = IpAddr::V6(ipv6_packet.get_destination());
        let _index = match source.cmp(&destination) {
            Less | Equal => 0,
            Greater => 1,
        };
        flow.key.ip_addresses[0] = source;
        flow.key.ip_addresses[1] = destination;
        flow.key.protocol_identifier = ipv6_packet.get_next_header();
        flow.key.ip_version = ipv6_packet.get_version();
        flow.key.ip_class_of_service = ipv6_packet.get_traffic_class();
        match flow.key.protocol_identifier {
            IpNextHeaderProtocols::Hopopt
            | IpNextHeaderProtocols::Ipv6Route
            | IpNextHeaderProtocols::Ipv6Frag
            | IpNextHeaderProtocols::Ipv6Opts => handle_ipv6_extension_packet(
                ipv6_packet.payload(),
                flow,
                metering_process_statistics,
                verbose,
                track_level,
            ), //0, 43, 44, 60
            _ => handle_transport_protocol(
                ipv6_packet.payload(),
                flow,
                metering_process_statistics,
                verbose,
                track_level,
            ),
        }
    }
    */
}

fn match_ethertype(
    ethertype: EtherType,
    payload: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    match ethertype {
        EtherTypes::Ipv4 => handle_ipv4_packet(
            payload,
            //flow,
            //metering_process_statistics,
            verbose,
            //track_level,
        ),
        EtherTypes::Ipv6 => {
            //if track_level & METER_IPV6 > 0 {
            handle_ipv6_packet(
                payload,
                //flow,
                //metering_process_statistics,
                verbose,
                //track_level,
            );
            //} else {
            //metering_process_statistics.ignored_packet_total_count += 1;
            //}
        }
        EtherTypes::Vlan | EtherTypes::QinQ => {
            handle_vlan_frame(
                payload,
                //flow,
                //metering_process_statistics,
                verbose,
                //track_level,
            );
        }
        _ => {
            //metering_process_statistics.ignored_packet_total_count += 1;
        }
    }
}

fn handle_gre_packet(
    packet: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    let gre_packet = GrePacket::new(packet);
    if verbose >= 2 {
        println!("handle_gre_packet {:?}", gre_packet)
    }
    if let Some(gre_packet) = gre_packet {
        match_ethertype(
            EtherType::new(gre_packet.get_protocol_type()),
            gre_packet.payload(),
            //flow,
            //metering_process_statistics,
            verbose,
            //track_level,
        );
    }
}

fn handle_vlan_frame(
    frame: &[u8],
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    let vlan_packet = VlanPacket::new(frame);
    if verbose >= 2 {
        println!("handle_vlan_frame {:?}", vlan_packet)
    }
    //flow.value.octet_delta_count -= 4; // 4 means vlan frame header
    if let Some(vlan_packet) = vlan_packet {
        match_ethertype(
            vlan_packet.get_ethertype(),
            vlan_packet.payload(),
            //flow,
            //metering_process_statistics,
            verbose,
            //track_level,
        );
    }
}

fn handle_ethernet_frame(
    ethernet: &EthernetPacket,
    //flow: &mut Flow,
    //metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    //track_level: u8,
) {
    if verbose >= 2 {
        println!("handle_ethernet_frame {:?}", ethernet)
    }
    //flow.value.octet_delta_count -= 14; // 14 means ethernet frame header
    match_ethertype(
        ethernet.get_ethertype(),
        ethernet.payload(),
        //flow,
        //metering_process_statistics,
        verbose,
        //track_level,
    );
}
