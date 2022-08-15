// defintion grpc api provided by tonic
pub mod api {
    tonic::include_proto!("rustflowd");
}
use tonic::{Request, Response, Status};

use api::ipfix::*;
use api::rustflowd_api_server::RustflowdApi;
use api::*;

#[derive(Debug, Default)]
pub struct RustflowdApiService {}

#[tonic::async_trait]
impl RustflowdApi for RustflowdApiService {
    async fn create_cache(
        &self,
        request: Request<ipfix::CacheKey>,
    ) -> Result<Response<()>, Status> {
        println!("Got a request: {:?}", request);

        Ok(Response::new(())) // Send back
    }

    async fn create_collecting_process(
        &self,
        request: Request<ipfix::CollectingProcessKey>,
    ) -> Result<Response<()>, Status> {
        println!("Got a request: {:?}", request);

        Ok(Response::new(())) // Send back
    }

    async fn create_exporting_process(
        &self,
        request: Request<ipfix::ExportingProcessKey>,
    ) -> Result<Response<()>, Status> {
        println!("Got a request: {:?}", request);

        Ok(Response::new(())) // Send back
    }

    async fn create_observation_point(
        &self,
        request: Request<ipfix::ObservationPointKey>,
    ) -> Result<Response<()>, Status> {
        println!("Got a request: {:?}", request);

        Ok(Response::new(())) // Send back
    }

    async fn create_selection_process(
        &self,
        request: Request<ipfix::SelectionProcessKey>,
    ) -> Result<Response<()>, Status> {
        println!("Got a request: {:?}", request);

        Ok(Response::new(())) // Send back
    }
}

// Default trait conflicts to prost definitions, hence constructor is
// defined here instead of default traint implementation
impl Ipfix {
    pub fn new() -> Self {
        Self {
            cache: vec![ipfix::CacheKey {
                name: "ipv4_cache".to_string(),
                cache: Some(ipfix::Cache {
                    active_flows: None,
                    active_timeout: Some(UintValue { value: 60 }),
                    cache_discontinuity_time: None,
                    cache_layout: Some(cache::CacheLayout {
                        cache_field: vec![
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "sourceIPv4Address".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
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
                                name: "destinationIPv4Address".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 12 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "destinationIPv4Address".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "ipNexthopIPv4Address".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 15 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "ipNexthopIPv4Address".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "ingressInterface".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 10 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "ingressInterface".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "egressInterface".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 14 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "egressInterface".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "packetDeltaCount".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 2 }),
                                    ie_length: Some(UintValue { value: 8 }),
                                    ie_name: Some(StringValue {
                                        value: "packetDeltaCount".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "octetDeltaCount".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 1 }),
                                    ie_length: Some(UintValue { value: 8 }),
                                    ie_name: Some(StringValue {
                                        value: "octetDeltaCount".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "flowStartNanoseconds".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 156 }),
                                    ie_length: Some(UintValue { value: 8 }),
                                    ie_name: Some(StringValue {
                                        value: "flowStartNanoseconds".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "flowEndNanoseconds".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 157 }),
                                    ie_length: Some(UintValue { value: 8 }),
                                    ie_name: Some(StringValue {
                                        value: "flowEndNanoseconds".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "sourceTransportPort".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 7 }),
                                    ie_length: Some(UintValue { value: 2 }),
                                    ie_name: Some(StringValue {
                                        value: "sourceTransportPort".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "destinationTransportPort".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 11 }),
                                    ie_length: Some(UintValue { value: 2 }),
                                    ie_name: Some(StringValue {
                                        value: "destinationTransportPort".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "tcpControlBits".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 6 }),
                                    ie_length: Some(UintValue { value: 2 }),
                                    ie_name: Some(StringValue {
                                        value: "tcpControlBits".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "protocolIdentifier".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 4 }),
                                    ie_length: Some(UintValue { value: 1 }),
                                    ie_name: Some(StringValue {
                                        value: "protocolIdentifier".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "ipClassOfService".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 5 }),
                                    ie_length: Some(UintValue { value: 1 }),
                                    ie_name: Some(StringValue {
                                        value: "ipClassOfService".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: true }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "bgpSourceAsNumber".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 16 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "bgpSourceAsNumber".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "bgpDestinationAsNumber".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 17 }),
                                    ie_length: Some(UintValue { value: 4 }),
                                    ie_name: Some(StringValue {
                                        value: "bgpDestinationAsNumber".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "sourceIPv4PrefixLength".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 9 }),
                                    ie_length: Some(UintValue { value: 1 }),
                                    ie_name: Some(StringValue {
                                        value: "sourceIPv4PrefixLength".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                            ipfix::cache::cache_layout::CacheFieldKey {
                                name: "destinationIPv4PrefixLength".to_string(),
                                cache_field: Some(ipfix::cache::cache_layout::CacheField {
                                    ie_enterprise_number: None,
                                    ie_id: Some(UintValue { value: 13 }),
                                    ie_length: Some(UintValue { value: 1 }),
                                    ie_name: Some(StringValue {
                                        value: "destinationIPv4PrefixLength".to_string(),
                                    }),
                                    is_flow_key: Some(BoolValue { value: false }),
                                }),
                            },
                        ],
                    }),
                    cache_type: 0,
                    check_expiry_interval: None,
                    data_records: Some(UintValue { value: 0 }),
                    export_interval: None,
                    exporting_process: vec![StringValue {
                        value: "exporter".to_string(),
                    }],
                    icmp_idle_timeout: Some(UintValue { value: 60 }),
                    idle_timeout: Some(UintValue { value: 60 }),
                    max_flows: Some(UintValue { value: 8192 }),
                    metering_process_id: None,
                    tcp_fin_idle_timeout: Some(UintValue { value: 0 }),
                    tcp_idle_timeout: Some(UintValue { value: 60 }),
                    tcp_rst_idle_timeout: Some(UintValue { value: 0 }),
                    udp_idle_timeout: Some(UintValue { value: 60 }),
                    unused_cache_entries: None,
                }),
            }],
            collecting_process: vec![ipfix::CollectingProcessKey {
                name: "colletor".to_string(),
                collecting_process: Some(ipfix::CollectingProcess {
                    exporting_process: vec![],
                    file_reader: vec![],
                    sctp_collector: vec![],
                    tcp_collector: vec![ipfix::collecting_process::TcpCollectorKey {
                        name: "tcp_collector".to_string(),
                        tcp_collector: Some(ipfix::collecting_process::TcpCollector {
                            local_ip_address: vec![StringValue {
                                value: "::".to_string(),
                            }],
                            local_port: Some(UintValue { value: 4739 }),
                            transport_layer_security: None,
                            transport_session: vec![],
                        }),
                    }],
                    udp_collector: vec![ipfix::collecting_process::UdpCollectorKey {
                        name: "udp_collector".to_string(),
                        udp_collector: Some(ipfix::collecting_process::UdpCollector {
                            local_ip_address: vec![StringValue {
                                value: "::".to_string(),
                            }],
                            local_port: Some(UintValue { value: 4739 }),
                            options_template_life_packet: None,
                            options_template_life_time: Some(UintValue { value: 1800 }),
                            template_life_packet: None,
                            template_life_time: Some(UintValue { value: 1800 }),
                            transport_layer_security: None,
                            transport_session: vec![],
                        }),
                    }],
                }),
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
                            export_transport_protocol_name: Some(StringValue {
                                value: "udp".to_string(),
                            }),
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
            }],
            observation_point: vec![ipfix::ObservationPointKey {
                name: "observation_point".to_string(),
                observation_point: Some(ipfix::ObservationPoint {
                    direction: 0,
                    ent_physical_index: vec![],
                    ent_physical_name: vec![],
                    if_index: vec![UintValue { value: 0 }],
                    if_name: vec![StringValue {
                        value: "lo".to_string(),
                    }],
                    max_observing_packets: Some(UintValue { value: 0 }),
                    observation_domain_id: Some(UintValue { value: 0 }),
                    observation_point_id: Some(UintValue { value: 0 }),
                    //packet_capture_file_name: None,
                    //packet_capture_length: Some(UintValue { value: 1500 }),
                    offline: Some(BoolValue { value: false }),
                    promiscuous: Some(BoolValue { value: true }),
                    selection_process: vec![StringValue {
                        value: "selectionProcess".to_string(),
                    }],
                }),
            }],
            selection_process: vec![ipfix::SelectionProcessKey {
                name: "selectionProcess".to_string(),
                selection_process: Some(ipfix::SelectionProcess {
                    cache: Some(StringValue {
                        value: "cache".to_string(),
                    }),
                    selection_sequence: vec![],
                    selector: vec![ipfix::selection_process::SelectorKey {
                        name: "selector".to_string(),
                        selector: Some(ipfix::selection_process::Selector {
                            packet_interval: Some(UintValue { value: 1 }),
                            packet_space: Some(UintValue { value: 0 }),
                            packets_dropped: None,
                            packets_observed: None,
                            selector_discontinuity_time: None,
                        }),
                    }],
                }),
            }],
        }
    }
}
