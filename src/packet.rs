use super::flow::{FlowKey, FlowValue, Flow};
use super::ipfix::{IPFIX_FLOW_END_REASON_IDLE_TIMEOUT, IPFIX_FLOW_END_REASON_ACTIVE_TIMEOUT,
                   IPFIX_FLOW_END_REASON_END_OF_FLOW, IPFIX_FLOW_END_REASON_FORCE_END,
                   PSAMP_SELECTOR_ALGORITHM_SYSTEMATIC_COUNT};
use super::configuration::{Configuration, RUSTFLOWD_FLOW_MAX_INDEX, flow_index,
			   METER_IPV6, METER_TUNNEL};
use super::export::{export_data_set, get_max_records_per_message};
use super::statistics::{Statistics, MeteringProcessStatistics};

use std::cmp::Ordering::{Less, Equal, Greater};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Error};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use pcap_parser::traits::PcapReaderIterator;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, EtherType};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::{Ipv6Packet, ExtensionPacket};
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use pnet::packet::udp::UdpPacket;
use pnet::packet::gre::GrePacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::{Packet, PrimitiveValues};

fn handle_udp_packet(packet: &[u8], flow: &mut Flow, verbose: u64) {
    let udp_packet = UdpPacket::new(packet);
    if verbose >= 2 {
        println!("handle_udp_packet {:?}", udp_packet)
    }
    if let Some(udp_packet) = udp_packet {
        flow.key.transport_ports[0] = udp_packet.get_source();
        flow.key.transport_ports[1] = udp_packet.get_destination();
    }
}
fn handle_tcp_packet(packet: &[u8], flow: &mut Flow, verbose: u64) {
    let tcp_packet = TcpPacket::new(packet);
    if verbose >= 2 {
        println!("handle_tcp_packet {:?}", tcp_packet)
    }
    if let Some(tcp_packet) = tcp_packet {
        flow.key.transport_ports[0] = tcp_packet.get_source();
        flow.key.transport_ports[1] = tcp_packet.get_destination();
        flow.value.tcp_control_bits = tcp_packet.get_flags();
    }
}
fn handle_icmp_packet(packet: &[u8], flow: &mut Flow, verbose: u64) {
    let icmp_packet = IcmpPacket::new(packet);
    if verbose >= 2 {
        println!("handle_icmp_packet {:?}", icmp_packet)
    }
    if let Some(icmp_packet) = icmp_packet {
        flow.key.transport_ports[1] = (icmp_packet.get_icmp_type().to_primitive_values().0 as
                                           u16) * 256 +
            icmp_packet.get_icmp_code().to_primitive_values().0 as u16;
    }
}
fn handle_icmpv6_packet(packet: &[u8], flow: &mut Flow, verbose: u64) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if verbose >= 2 {
        println!("handle_icmpv6_packet {:?}", icmpv6_packet)
    }
    if let Some(icmpv6_packet) = icmpv6_packet {
        flow.key.transport_ports[1] =
            (icmpv6_packet.get_icmpv6_type().to_primitive_values().0 as u16) * 256 +
                icmpv6_packet.get_icmpv6_code().to_primitive_values().0 as u16
    }
}

fn handle_transport_protocol(
    packet: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    match flow.key.protocol_identifier {
        IpNextHeaderProtocols::Udp => handle_udp_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Icmpv6 => handle_icmpv6_packet(packet, flow, verbose),
        IpNextHeaderProtocols::Gre => if track_level & METER_TUNNEL > 0 {
            handle_gre_packet(packet, flow, metering_process_statistics, verbose, track_level)
        }
        IpNextHeaderProtocols::Ipv4 => if track_level & METER_TUNNEL > 0 {
            handle_ipv4_packet(packet, flow, metering_process_statistics, verbose, track_level)
        }

        IpNextHeaderProtocols::Ipv6 => if track_level & METER_TUNNEL > 0 {
            handle_ipv6_packet(packet, flow, metering_process_statistics, verbose, track_level)
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
}

fn handle_ipv4_packet(
    packet: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    let ipv4_packet = Ipv4Packet::new(packet);
    if verbose >= 2 {
        println!("handle_ipv4_packet {:?}", ipv4_packet)
    }
    if let Some(ipv4_packet) = ipv4_packet {
        let source = IpAddr::V4(ipv4_packet.get_source());
        let destination = IpAddr::V4(ipv4_packet.get_destination());
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
    }
}

fn handle_ipv6_extension_packet(
    packet: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    let extension_packet = ExtensionPacket::new(packet);
    if verbose >= 2 {
        println!("handle_ipv6_extension_packet {:?}", extension_packet)
    }
    if let Some(extension_packet) = extension_packet {
        flow.key.protocol_identifier = extension_packet.get_next_header();
        handle_transport_protocol(
            extension_packet.payload(),
            flow,
            metering_process_statistics,
            verbose,
	    track_level,
        );
    }
}

fn handle_ipv6_packet(
    packet: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    let ipv6_packet = Ipv6Packet::new(packet);
    if verbose >= 2 {
        println!("handle_ipv6_packet {:?}", ipv6_packet)
    }
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
            IpNextHeaderProtocols::Hopopt |
            IpNextHeaderProtocols::Ipv6Route |
            IpNextHeaderProtocols::Ipv6Frag |
            IpNextHeaderProtocols::Ipv6Opts => {
                handle_ipv6_extension_packet(
                    ipv6_packet.payload(),
                    flow,
                    metering_process_statistics,
                    verbose,
		    track_level,
                )
            } //0, 43, 44, 60
            _ => {
                handle_transport_protocol(
                    ipv6_packet.payload(),
                    flow,
                    metering_process_statistics,
                    verbose,
		    track_level,
                )
            }
        }
    }
}

fn match_ethertype(
    ethertype: EtherType,
    payload: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    match ethertype {
        EtherTypes::Ipv4 => handle_ipv4_packet(payload, flow, metering_process_statistics, verbose, track_level),
        EtherTypes::Ipv6 => if track_level & METER_IPV6 > 0 {
	    handle_ipv6_packet(payload, flow, metering_process_statistics, verbose, track_level);
	} else {
	    metering_process_statistics.ignored_packet_total_count += 1;		
	},
        EtherTypes::Vlan | EtherTypes::QinQ => {
            handle_vlan_frame(payload, flow, metering_process_statistics, verbose, track_level);
        }
        _ => {
	    metering_process_statistics.ignored_packet_total_count += 1;		
        }
    }
}

fn handle_gre_packet(
    packet: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    let gre_packet = GrePacket::new(packet);
    if verbose >= 2 {
        println!("handle_gre_packet {:?}", gre_packet)
    }
    if let Some(gre_packet) = gre_packet {
        match_ethertype(
            EtherType::new(gre_packet.get_protocol_type()),
            gre_packet.payload(),
            flow,
            metering_process_statistics,
            verbose,
	    track_level,
        );
    }
}

fn handle_vlan_frame(
    frame: &[u8],
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    let vlan_packet = VlanPacket::new(frame);
    if verbose >= 2 {
        println!("handle_vlan_frame {:?}", vlan_packet)
    }
    flow.value.octet_delta_count -= 4; // 4 means vlan frame header
    if let Some(vlan_packet) = vlan_packet {
        match_ethertype(
            vlan_packet.get_ethertype(),
            vlan_packet.payload(),
            flow,
            metering_process_statistics,
            verbose,
	    track_level,
        );
    }
}

fn handle_ethernet_frame(
    ethernet: &EthernetPacket,
    flow: &mut Flow,
    metering_process_statistics: &mut MeteringProcessStatistics,
    verbose: u64,
    track_level: u8,
) {
    if verbose >= 2 {
        println!("handle_ethernet_frame {:?}", ethernet)
    }
    flow.value.octet_delta_count -= 14; // 14 means ethernet frame header
    match_ethertype(
        ethernet.get_ethertype(),
        ethernet.payload(), 
        flow,
        metering_process_statistics,
        verbose,
	track_level,
    );
}

fn observe_packet(
    config: &Configuration,
    stats: &mut Statistics,
    flows: &mut HashMap<FlowKey, FlowValue>,
    expired_flows: &mut [&mut VecDeque<Flow>; 2],
    packet_data: &[u8],
    packet_length: usize,
) -> Result<(), Error> {
    let mut flow = Flow {
        key: Default::default(),
        value: FlowValue {
            start: stats.meter.last_packet_time,
            end: stats.meter.last_packet_time,
            packet_delta_count: 1,
            octet_delta_count: packet_length as u64,
            tcp_control_bits: 0,
            flow_end_reason: 0,
        },
    };
    let ethernet_packet =
        EthernetPacket::new(&packet_data[..]).expect("failed to convert to ethernet_packet");
    let sampling_packet_interval_and_space: u64 =
        (config.meter.sampling_packet_interval + config.meter.sampling_packet_space) as u64;
    stats.meter.observed_packet_total_count += 1;
    if (config.meter.selector_algorithm == PSAMP_SELECTOR_ALGORITHM_SYSTEMATIC_COUNT) &&
        ((stats.meter.observed_packet_total_count % sampling_packet_interval_and_space) >
             config.meter.sampling_packet_interval as u64)
    {
        stats.meter.non_sampled_packet_total_count += 1;
        return Ok(());
    }
    handle_ethernet_frame(
        &ethernet_packet,
        &mut flow,
        &mut stats.meter,
        config.cli.verbose,
	config.meter.track_level,
    );
    if flow.key.ip_version != 4 && flow.key.ip_version != 6 {
        return Ok(()); // do nothing
    }
    let max_records_per_message = get_max_records_per_message(config, flow.key.ip_version);
    if flows.is_empty() {
        stats.meter.observed_flow_total_count += 1;
        flows.insert(flow.key, flow.value);
        return Ok(());
    }
    if flows.contains_key(&flow.key) {
        let index = flow_index(flow.key.ip_version);
        if let Some(exist_flow_value) = flows.get_mut(&flow.key) {
            let idle_duration = flow.value
                .start
                .duration_since(exist_flow_value.end)
                .unwrap();
            let active_duration = flow.value
                .start
                .duration_since(exist_flow_value.start)
                .unwrap();
            if idle_duration.as_secs() > config.meter.flow_idle_timeout.into() {
                if config.cli.verbose >= 1 {
                    println!("flow idle tiameout {:?}, {:?}", flow.key, exist_flow_value);
                }
                exist_flow_value.flow_end_reason = IPFIX_FLOW_END_REASON_IDLE_TIMEOUT;
                stats.meter.idle_timeout_expired_flow_total_count += 1;
                expired_flows[index].push_back(Flow {
                    key: flow.key.clone(),
                    value: *exist_flow_value,
                });
                // Export
                if expired_flows[index].len() >= max_records_per_message {
                    export_data_set(config, stats, expired_flows[index])?;
                }
                stats.meter.observed_flow_total_count += 1;
                *exist_flow_value = flow.value;
            } else if active_duration.as_secs() > config.meter.flow_active_timeout.into() {
                if config.cli.verbose >= 1 {
                    println!("flow active timeout {:?}, {:?}", flow.key, exist_flow_value);
                }
                exist_flow_value.flow_end_reason = IPFIX_FLOW_END_REASON_ACTIVE_TIMEOUT;
                stats.meter.active_timeout_expired_flow_total_count += 1;
                expired_flows[index].push_back(Flow {
                    key: flow.key.clone(),
                    value: *exist_flow_value,
                });
                stats.meter.observed_flow_total_count += 1;
                *exist_flow_value = flow.value;
            } else {
                exist_flow_value.update(flow.value);
            }
            let tcp_flag = exist_flow_value.tcp_control_bits;
            if tcp_flag & TcpFlags::FIN > 0 || tcp_flag & TcpFlags::RST > 0 {
                exist_flow_value.flow_end_reason = IPFIX_FLOW_END_REASON_END_OF_FLOW;
                stats.meter.end_of_flow_expired_flow_total_count += 1;
                expired_flows[index].push_back(Flow {
                    key: flow.key.clone(),
                    value: *exist_flow_value,
                });
                flows.remove(&flow.key);
            }
        }
    } else {
        stats.meter.observed_flow_total_count += 1;
        flows.insert(flow.key, flow.value);
    }
    Ok(())
}
pub fn observe_packets_online(
    config: &mut Configuration,
    stats: &mut Statistics,
    flows: &mut HashMap<FlowKey, FlowValue>,
    expired_flows: &mut [&mut VecDeque<Flow>; 2],
) {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| {
            iface.name == config.meter.observation_point_name
        })
        .next()
        .expect("Failed to get Inteface");
    if config.meter.observation_point_mac_addr.is_zero() {
        config.meter.observation_point_mac_addr = interface.mac.expect("failed to get mac address");
    }
    // Create a new channel, dealing with layer 2 packets
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => (_tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            )
        }
    };
    loop {
        match rx.next() {
            Ok(packet) => {
                stats.meter.last_packet_time = SystemTime::now();
                observe_packet(config, stats, flows, expired_flows, packet, packet.len())
                    .expect("failed in observe_packet");
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
pub fn observe_packets_offline(
    config: &Configuration,
    stats: &mut Statistics,
    flows: &mut HashMap<FlowKey, FlowValue>,
    expired_flows: &mut [&mut VecDeque<Flow>; 2],
) {
    let read_file = File::open(&config.meter.observation_point_name).expect("failed to read file");
    let mut count = 0;
    let mut reader = LegacyPcapReader::new(65536, read_file).expect("LegacyPcapReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(b) => {
                        // use linktype to parse b.data()
                        stats.meter.last_packet_time =
                            SystemTime::checked_add(
                                &UNIX_EPOCH,
                                Duration::new(b.ts_sec.into(), b.ts_usec),
                            ).expect("failed to get last_packet_time in offline");
                        if count == 0 {
                            stats.meter.system_init_time = stats.meter.last_packet_time;
                        }
                        observe_packet(
                            config,
                            stats,
                            flows,
                            expired_flows,
                            &b.data,
                            b.origlen as usize,
                        ).expect("failed in observe_packet");
                        count += 1;
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
    for (key, value) in flows {
        let index = flow_index(key.ip_version);
        if index >= RUSTFLOWD_FLOW_MAX_INDEX {
            println!("key: {:?}, value: {:?}", key, value);
            continue;
        }
        value.flow_end_reason = IPFIX_FLOW_END_REASON_FORCE_END;
        stats.meter.force_end_expired_flow_total_count += 1;
        expired_flows[index].push_back(Flow {
            key: *key,
            value: *value,
        });
    }
    let mut index = 0;
    while index < RUSTFLOWD_FLOW_MAX_INDEX {
        loop {
            if expired_flows[index].len() == 0 {
                break;
            }
            export_data_set(config, stats, expired_flows[index])
                .expect("failed in export_data_set");
        }
        index += 1;
    }
}

pub fn observe_packets(
    config: &mut Configuration,
    stats: &mut Statistics,
    flows: &mut HashMap<FlowKey, FlowValue>,
    expired_flows: &mut [&mut VecDeque<Flow>; 2],
) {
    if config.meter.observation_point_online {
        observe_packets_online(config, stats, flows, expired_flows);
    } else {
        observe_packets_offline(config, stats, flows, expired_flows);
    }
}
