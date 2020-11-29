#[macro_use]
extern crate clap;
use clap::{App, Arg};

use std::collections::{HashMap, VecDeque};
use std::net::UdpSocket;
extern crate rustflowd;
use rustflowd::export::export_template_set;
use rustflowd::flow::{FlowKey, FlowValue, Flow};
use rustflowd::packet::observe_packets;
use rustflowd::configuration::{Configuration, METER_IPV6};
use rustflowd::statistics::Statistics;

fn main() {
    let mut config: Configuration = Default::default();
    let app = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!())
        .arg(
            Arg::with_name("bind-address-port")
                .help("Bind address and port")
                .short("B")
                .long("bind-address-port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("collectors")
                .help("Collector's address and port")
                .required(true)
                .short("c")
                .long("collectors")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export-version")
                .help("NetFlow export packet version")
                .short("v")
                .long("export-version")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("interface")
                .help("Interface to observe packets")
                .short("i")
                .long("interface")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("read-file")
                .help("read from packet capture file")
                .short("r")
                .long("read-file")
                .takes_value(true),
        )
	.arg(
            Arg::with_name("max-message-size")
                .help(
                    "max message size for exporting (default: 1472 = 1500(Ethernet) - 20(IPv4) - 8(UDP))",
                )
                .short("m")
                .long("max-message-size")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sampling-interval")
                .help(
                    "sampling interval which means the rate at which packets are sampled",
                )
                .short("s")
                .long("sampling-interval")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .help("verbose")
                .multiple(true)
                .short("V")
                .long("verbose"),
        );
    let mut flows: HashMap<FlowKey, FlowValue> = HashMap::new();
    let mut expired_flows: [&mut VecDeque<Flow>; 2] = [&mut VecDeque::new(), &mut VecDeque::new()];
    let mut stats: Statistics = Default::default();
    let matches = app.get_matches();

    let bind_address_port = matches.value_of("bind-address-port").unwrap_or("[::]:0");
    config.export.socket_addr = bind_address_port.parse().expect(
        "failed to parse bind address and port",
    );

    let collectors_str = matches.value_of("collectors").unwrap_or("");
    let collector_strs: Vec<&str> = collectors_str.split(",").collect();
    for collector_str in &collector_strs {
        let collector = collector_str.parse().expect("failed to parse collector");
        config.export.collectors.push(collector);
    }

    let export_version_str = matches.value_of("export-version").unwrap_or("10");
    config.export.protocol_version = export_version_str.parse().expect(
        "failed to parse export_version",
    );

    let interface = matches.value_of("interface").unwrap_or("");
    let read_file = matches.value_of("read-file").unwrap_or("");
    if interface.len() > 0 {
        config.meter.observation_point_name = interface.to_string();
        config.meter.observation_point_online = true;
    } else if read_file.len() > 0 {
        config.meter.observation_point_name = read_file.to_string();
        config.meter.observation_point_online = false;
    }

    let max_message_size_str = matches.value_of("max-message-size").unwrap_or("1472");
    config.export.max_message_size = max_message_size_str.parse().expect(
        "failed to parse max_message_size",
    );

    let sampling_interval_str = matches.value_of("sampling-interval").unwrap_or("1");
    let sampling_interval: u32 = sampling_interval_str.parse().expect(
        "failed to parse sampling_interval",
    );
    let interval_diff = sampling_interval - config.meter.sampling_packet_interval;
    config.meter.sampling_packet_space = interval_diff * config.meter.sampling_packet_interval;
    if config.export.protocol_version >= 9 {
        config.meter.track_level |= METER_IPV6;
    }

    config.cli.verbose = matches.occurrences_of("verbose");
    if config.cli.verbose >= 1 {
        println!("bind address and port: {}", bind_address_port);
        println!("collctor's address and port: {}", collectors_str);
        println!("export version: {}", export_version_str);
        println!("interface: {}", interface);
        println!("read_file: {}", read_file);
        println!("sampling_interval: {}", sampling_interval);
        println!(
            "sampling_packet_interval: {}",
            config.meter.sampling_packet_interval
        );
        println!(
            "sampling_packet_space: {}",
            config.meter.sampling_packet_space
        );
    }
    config.export.udp_socket = UdpSocket::bind(bind_address_port).expect("failed to bind address");
    if config.export.protocol_version >= 9 {
        let _ = export_template_set(&mut config, &mut stats);
    }
    observe_packets(&mut config, &mut stats, &mut flows, &mut expired_flows);
    println!("stats: {:?}", stats);
}
