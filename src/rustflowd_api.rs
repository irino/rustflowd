use serde::{Serialize, Deserialize};
#[derive(Serialize, Deserialize)]
pub mod rustflowd_api {
    tonic::include_proto!("rustflowd_api");
}

use rustflowd_api::ipfix::*;
use rustflowd_api::*;

impl Default for Ipfix {
    fn default() -> Self {
        Self {
            cache: vec![ipfix::CacheKey {
                name: "cache".to_string(),
                cache: Some(ipfix::Cache {
                    active_flows: None,
                    active_timeout: Some(UintValue { value: 60 }),
                    cache_discontinuity_time: None,
                    cache_layout: Some(cache::CacheLayout {
                        cache_field: vec![
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "field1".to_string(),
                                cache_field: Some(CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 8 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "sourceIPv4Address".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "field2".to_string(),
                                cache_field: Some(CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 12 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "destinationIPv4Address".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                        ],
                    }),
                    check_expiry_interval: None,
                    data_records: Some(UintValue { value: 0 }),
                    export_interval: None,
                    exporting_process: vec![StringValue {
                        value: "exporter".to_string(),
                    }],
                    icmp_idle_timeouts: Some(UintValue { value: 60 }),
                    idle_timeout: Some(UintValue { value: 60 }),
                    max_flows: Some(UintValue { value: 8192 }),
                    metering_process_id: None,
                    tcp_fin_idle_timeouts: Some(UintValue { value: 0 }),
                    tcp_idle_timeouts: Some(UintValue { value: 60 }),
                    tcp_rst_idle_timeouts: Some(UintValue { value: 0 }),
                    udp_idle_timeouts: Some(UintValue { value: 60 }),
                    unused_cache_entries: None,
                }),
                //cache: Default::default(),
            }],
            collecting_process: vec![ipfix::CollectingProcessKey {
                name: "colletor".to_string(),
                collecting_process: Some(ipfix::CollectingProcess {
                    exporting_process: vec![],
                    file_reader: None,
                    sctp_collector: vec![],
                    tcp_collector: vec![],
                    udp_collector: vec![ipfix::collecting_process::UdpCollectorKey {
                        name: "udp_collector".to_string(),
                        udp_collector: Some(ipfix::collecting_process::UdpCollector {
                            local_ip_address: Some(StringValue {
                                value: "::".to_string(),
                            }),
                            local_port: Some(UintValue { value: 4739 }),
                            options_template_life_packet: None,
                            options_template_life_time: Some(UintValue { value: 1800 }),
                            template_life_packet: None,
                            template_life_time: Some(UintValue { value: 1800 }),
                            transport_layer_security: None,
                            transport_session: None,
                        }),
                    }],
                }),
                //collecting_process: Default::default(),
            }],
            exporting_process: vec![ipfix::ExportingProcessKey {
                name: "exportor".to_string(),
                exporting_process: Some(ipfix::ExportingProcess {
                    destination: vec![ipfix::exporting_process::DestinationKey {
                        name: "localhost".to_string(),
                        destination: Some(ipfix::exporting_process::Destination {
                            destination_ip_address: Some(StringValue {
                                value: "localhost".to_string(),
                            }),
                            destination_port: Some(UintValue { value: 4739 }),
                            if_index: None,
                            if_name: None,
                            ipfix_version: Some(UintValue { value: 10 }),
                            max_packet_size: Some(UintValue { value: 1500 }),
                            options_template_refresh_packet: None,
                            options_template_refresh_timeout: Some(UintValue { value: 1800 }),
                            rate_limit: None,
                            send_buffer_size: None,
                            source_ip_address: None,
                            template_refresh_packet: None,
                            template_refresh_timeout: Some(UintValue { value: 1800 }),
                            transport_layer_security: None,
                            transport_session: None,
                        }),
                    }],
                    export_mode: 0,
                    exporting_process_id: None,
                    options: vec![],
                }),
                //exporting_process: Default::default(),
            }],
            observation_point: vec![ipfix::ObservationPointKey {
                name: "observation_point".to_string(),
                observation_point: Some(ipfix::ObservationPoint {
                    direction: 0,
                    ent_physical_index: None,
                    ent_physical_name: None,
                    if_index: vec![UintValue { value: 0 }],
                    if_name: vec![StringValue {
                        value: "lo".to_string(),
                    }],
                    max_observing_packets: Some(UintValue { value: 0 }),
                    observation_domain_id: Some(UintValue { value: 0 }),
                    observation_point_id: Some(UintValue { value: 0 }),
                    packet_capture_file: Some(StringValue {
                        value: "pcapfile.pcap".to_string(),
                    }),
                    packet_capture_length: Some(UintValue { value: 1500 }),
                    promiscuous: Some(BoolValue { value: true }),
                    selection_process: vec![StringValue {
                        value: "selectionProcess".to_string(),
                    }],
                }),
                //observation_point: Default::default(),
            }],
            selection_process: vec![ipfix::SelectionProcessKey {
                name: "selectionProcess".to_string(),
                selection_process: Some(ipfix::SelectionProcess {
                    cache: Some(StringValue {
                        value: "cache".to_string(),
                    }),

                    selection_sequence: None,
                    selector: vec![ipfix::selection_process::SelectorKey {
                        name: "selector".to_string(),
                        selector: Some(Selector {
                            packet_interval: Some(UintValue { value: 1 }),
                            packet_space: Some(UintValue { value: 0 }),
                            packets_dropped: None,
                            packets_observed: None,
                            selector_discontinuity_time: None,
                        }),
                    }],
                }),
                //selection_process: Default::default(),
            }],
        }
    }
}
