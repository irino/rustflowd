use super::configuration::{Configuration, flow_index};
use super::statistics::Statistics;

use bytes::{BytesMut, BufMut};
use std::time::UNIX_EPOCH;

pub const IPFIX_PROTOCOL_VERSION: u8 = 10;
pub const IPFIX_TRANSPORT_PORT: u16 = 4739;
const NETFLOW_V9_TEMPLATE_SET_ID: u16 = 0;
const NETFLOW_V9_OPTION_TEMPLATE_SET_ID: u16 = 1;
const IPFIX_TEMPLATE_SET_ID: u16 = 2;
const IPFIX_OPTION_TEMPLATE_SET_ID: u16 = 3;

pub const IPFIX_SET_HEADER_SIZE: u16 = 4;
const IPFIX_TEMPLATE_RECORD_HEADER_SIZE: u16 = 4;
const IPFIX_OPTION_TEMPLATE_RECORD_HEADER_SIZE: u16 = 6;
const IPFIX_FIELD_SPECIFIER_SIZE: u16 = 4;

pub const IPFIX_DATA_SET_TEMPLATE_ID_BASE: u16 = 256;
const RUSTFLOWD_OPTION_TEMPLATE_ID: u16 = 512;

// Information Elements
const IPFIX_OCTET_DELTA_COUNT: u16 = 1;
const IPFIX_PACKET_DELTA_COUNT: u16 = 2;
const IPFIX_PROTOCOL_IDENTIFIER: u16 = 4;
const IPFIX_IP_CLASS_OF_SERVICE: u16 = 5;
const IPFIX_TCP_CONTROL_BITS: u16 = 6;
const IPFIX_SOURCE_TRANSPORT_PORT: u16 = 7;
const IPFIX_SOURCE_IPV4_ADDRESS: u16 = 8;
const IPFIX_SOURCE_IPV4_PREFIX_LENGTH: u16 = 9;
const IPFIX_INGRESS_INTERFACE: u16 = 10;
const IPFIX_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IPFIX_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IPFIX_DESTINATION_IPV4_PREFIX_LENGTH: u16 = 13;
const IPFIX_EGRESS_INTERFACE: u16 = 14;
const IPFIX_IP_NEXTHOP_IPV4_ADDRESS: u16 = 15;
const IPFIX_BGP_SOURCE_AS_NUMBER: u16 = 16;
const IPFIX_BGP_DESTINATION_AS_NUMBER: u16 = 17;
const IPFIX_FLOW_END_SYS_UP_TIME: u16 = 21;
const IPFIX_FLOW_START_SYS_UP_TIME: u16 = 22;
const IPFIX_SOURCE_IPV6_ADDRESS: u16 = 27;
const IPFIX_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IPFIX_SOURCE_IPV6_PREFIX_LENGTH: u16 = 29;
const IPFIX_DESTINATION_IPV6_PREFIX_LENGTH: u16 = 30;
const IPFIX_ICMP_TYPE_CODE_IPV4: u16 = 32;
const IPFIX_IP_NEXTHOP_IPV6_ADDRESS: u16 = 62;
const IPFIX_ICMP_TYPE_CODE_IPV6: u16 = 139;
const IPFIX_METERING_PROCESS_ID: u16 = 143;
const IPFIX_SYSTEM_INIT_TIME_MILLISECONDS: u16 = 160;
const PSAMP_SELECTOR_ALGORITHM: u16 = 304;
const PSAMP_SAMPLING_PACKET_INTERVAL: u16 = 305;
const PSAMP_SAMPLING_PACKET_SPACE: u16 = 306;

pub const IPFIX_FLOW_END_REASON_IDLE_TIMEOUT: u8 = 0x01; // Information Element 136
pub const IPFIX_FLOW_END_REASON_ACTIVE_TIMEOUT: u8 = 0x02; // Information Element 136
pub const IPFIX_FLOW_END_REASON_END_OF_FLOW: u8 = 0x03; // Information Element 136
pub const IPFIX_FLOW_END_REASON_FORCE_END: u8 = 0x04; // Information Element 136

pub const IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC: u8 = 1; // Information Element 35, deprecated
pub const PSAMP_SELECTOR_ALGORITHM_SYSTEMATIC_COUNT: u16 = 1; // Information Element 304

pub struct SetHeader {
    pub set_id: u16, // version 10, 9
    pub length: u16, // version 10, 9
}

impl SetHeader {
    pub fn put_to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_slice(&self.set_id.to_be_bytes());
        bytes.put_slice(&self.length.to_be_bytes());
    }
}

struct TemplateRecordHeader {
    template_id: u16,
    field_count: u16,
}

impl TemplateRecordHeader {
    pub fn put_to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_slice(&self.template_id.to_be_bytes());
        bytes.put_slice(&self.field_count.to_be_bytes());
    }
}

struct OptionTemplateRecordHeader {
    template_id: u16,
    field_count: u16, // NetFlow v9: option scope length (total length)
    scope_field_count: u16, // NetFlow v9 option length
}

impl OptionTemplateRecordHeader {
    pub fn put_to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_slice(&self.template_id.to_be_bytes());
        bytes.put_slice(&self.field_count.to_be_bytes());
        bytes.put_slice(&self.scope_field_count.to_be_bytes());
    }
}

pub struct FieldSpecifier {
    information_element_identifier: u16,
    field_length: u16,
    enterprise_number: u32,
}

impl FieldSpecifier {
    pub fn new(
        information_element_identifier: u16,
        field_length: u16,
        enterprise_number: u32,
    ) -> FieldSpecifier {
        FieldSpecifier {
            information_element_identifier,
            field_length,
            enterprise_number,
        }
    }
    pub fn put_to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_slice(&self.information_element_identifier.to_be_bytes());
        bytes.put_slice(&self.field_length.to_be_bytes());
        if self.information_element_identifier & 0x8000 > 0 {
            bytes.put_slice(&self.enterprise_number.to_be_bytes());
        }
    }
}

pub fn default_ipv4_field_specifiers() -> Vec<FieldSpecifier> {
    return vec![
        FieldSpecifier::new(IPFIX_SOURCE_IPV4_ADDRESS, 4, 0),
        FieldSpecifier::new(IPFIX_DESTINATION_IPV4_ADDRESS, 4, 0),
        FieldSpecifier::new(IPFIX_IP_NEXTHOP_IPV4_ADDRESS, 4, 0),
        FieldSpecifier::new(IPFIX_INGRESS_INTERFACE, 4, 0),
        FieldSpecifier::new(IPFIX_EGRESS_INTERFACE, 4, 0),
        FieldSpecifier::new(IPFIX_PACKET_DELTA_COUNT, 8, 0),
        FieldSpecifier::new(IPFIX_OCTET_DELTA_COUNT, 8, 0),
        FieldSpecifier::new(IPFIX_FLOW_START_SYS_UP_TIME, 4, 0),
        FieldSpecifier::new(IPFIX_FLOW_END_SYS_UP_TIME, 4, 0),
        FieldSpecifier::new(IPFIX_SOURCE_TRANSPORT_PORT, 2, 0),
        FieldSpecifier::new(IPFIX_DESTINATION_TRANSPORT_PORT, 2, 0),
        FieldSpecifier::new(IPFIX_TCP_CONTROL_BITS, 2, 0),
        FieldSpecifier::new(IPFIX_PROTOCOL_IDENTIFIER, 1, 0),
        FieldSpecifier::new(IPFIX_IP_CLASS_OF_SERVICE, 1, 0),
        FieldSpecifier::new(IPFIX_BGP_SOURCE_AS_NUMBER, 4, 0),
        FieldSpecifier::new(IPFIX_BGP_DESTINATION_AS_NUMBER, 4, 0),
        FieldSpecifier::new(IPFIX_SOURCE_IPV4_PREFIX_LENGTH, 1, 0),
        FieldSpecifier::new(IPFIX_DESTINATION_IPV4_PREFIX_LENGTH, 1, 0),
        FieldSpecifier::new(IPFIX_ICMP_TYPE_CODE_IPV4, 2, 0),
    ];
}

pub fn default_ipv6_field_specifiers() -> Vec<FieldSpecifier> {
    return vec![
        FieldSpecifier::new(IPFIX_SOURCE_IPV6_ADDRESS, 16, 0),
        FieldSpecifier::new(IPFIX_DESTINATION_IPV6_ADDRESS, 16, 0),
        FieldSpecifier::new(IPFIX_IP_NEXTHOP_IPV6_ADDRESS, 16, 0),
        FieldSpecifier::new(IPFIX_INGRESS_INTERFACE, 4, 0),
        FieldSpecifier::new(IPFIX_EGRESS_INTERFACE, 4, 0),
        FieldSpecifier::new(IPFIX_PACKET_DELTA_COUNT, 8, 0),
        FieldSpecifier::new(IPFIX_OCTET_DELTA_COUNT, 8, 0),
        FieldSpecifier::new(IPFIX_FLOW_START_SYS_UP_TIME, 4, 0),
        FieldSpecifier::new(IPFIX_FLOW_END_SYS_UP_TIME, 4, 0),
        FieldSpecifier::new(IPFIX_SOURCE_TRANSPORT_PORT, 2, 0),
        FieldSpecifier::new(IPFIX_DESTINATION_TRANSPORT_PORT, 2, 0),
        FieldSpecifier::new(IPFIX_TCP_CONTROL_BITS, 2, 0),
        FieldSpecifier::new(IPFIX_PROTOCOL_IDENTIFIER, 1, 0),
        FieldSpecifier::new(IPFIX_IP_CLASS_OF_SERVICE, 1, 0),
        FieldSpecifier::new(IPFIX_BGP_SOURCE_AS_NUMBER, 4, 0),
        FieldSpecifier::new(IPFIX_BGP_DESTINATION_AS_NUMBER, 4, 0),
        FieldSpecifier::new(IPFIX_SOURCE_IPV6_PREFIX_LENGTH, 1, 0),
        FieldSpecifier::new(IPFIX_DESTINATION_IPV6_PREFIX_LENGTH, 1, 0),
        FieldSpecifier::new(IPFIX_ICMP_TYPE_CODE_IPV6, 2, 0),
    ];
}

pub fn default_scope_field_specifiers() -> Vec<FieldSpecifier> {
    return vec![
	FieldSpecifier::new(IPFIX_METERING_PROCESS_ID, 4, 0), // scope
    ];
}

pub fn default_option_field_specifiers() -> Vec<FieldSpecifier> {
    return vec![
        FieldSpecifier::new(IPFIX_SYSTEM_INIT_TIME_MILLISECONDS, 8, 0),
        FieldSpecifier::new(PSAMP_SELECTOR_ALGORITHM, 2, 0),
        FieldSpecifier::new(PSAMP_SAMPLING_PACKET_INTERVAL, 4, 0),
        FieldSpecifier::new(PSAMP_SAMPLING_PACKET_SPACE, 4, 0),
    ];
}

pub fn field_specifiers_data_length(field_specifiers: &Vec<FieldSpecifier>) -> u16 {
    let mut length: u16 = 0;
    for field in field_specifiers {
        length += field.field_length;
    }
    return length;
}

pub fn put_template_set(config: &Configuration, bytes: &mut BytesMut) -> u16 {
    let set_id: u16 = if config.export.protocol_version == 10 {
        IPFIX_TEMPLATE_SET_ID
    } else {
        NETFLOW_V9_TEMPLATE_SET_ID
    };
    let set_length: u16 = IPFIX_SET_HEADER_SIZE +
        (IPFIX_TEMPLATE_RECORD_HEADER_SIZE +
             IPFIX_FIELD_SPECIFIER_SIZE *
                 config.export.field_specifiers[flow_index(4)].len() as u16) +
        (IPFIX_TEMPLATE_RECORD_HEADER_SIZE +
             IPFIX_FIELD_SPECIFIER_SIZE *
                 config.export.field_specifiers[flow_index(6)].len() as u16);
    let set_header = SetHeader {
        set_id: set_id,
        length: set_length,
    };
    let template_record_header_ipv4 = TemplateRecordHeader {
        template_id: IPFIX_DATA_SET_TEMPLATE_ID_BASE + flow_index(4) as u16,
        field_count: config.export.field_specifiers[flow_index(4)].len() as u16,
    };
    let template_record_header_ipv6 = TemplateRecordHeader {
        template_id: IPFIX_DATA_SET_TEMPLATE_ID_BASE + flow_index(6) as u16,
        field_count: config.export.field_specifiers[flow_index(6)].len() as u16,
    };
    set_header.put_to_bytes(bytes);
    template_record_header_ipv4.put_to_bytes(bytes);
    for field in &config.export.field_specifiers[flow_index(4)] {
        field.put_to_bytes(bytes);
    }
    template_record_header_ipv6.put_to_bytes(bytes);
    for field in &config.export.field_specifiers[flow_index(6)] {
        field.put_to_bytes(bytes);
    }
    return set_length;
}

pub fn put_option_template_set(config: &Configuration, bytes: &mut BytesMut) -> u16 {
    let set_id: u16 = if config.export.protocol_version == 10 {
        IPFIX_OPTION_TEMPLATE_SET_ID
    } else {
        NETFLOW_V9_OPTION_TEMPLATE_SET_ID
    };
    let option_field_specifiers = default_option_field_specifiers();
    let scope_field_specifiers = default_scope_field_specifiers();
    let set_length: u16 = IPFIX_SET_HEADER_SIZE +
        (IPFIX_OPTION_TEMPLATE_RECORD_HEADER_SIZE +
             IPFIX_FIELD_SPECIFIER_SIZE * scope_field_specifiers.len() as u16) +
        (IPFIX_FIELD_SPECIFIER_SIZE * option_field_specifiers.len() as u16);
    let set_header = SetHeader {
        set_id: set_id,
        length: set_length,
    };
    let option_template_record_header = OptionTemplateRecordHeader {
        template_id: RUSTFLOWD_OPTION_TEMPLATE_ID,
        field_count: (scope_field_specifiers.len() + option_field_specifiers.len()) as u16,
        scope_field_count: scope_field_specifiers.len() as u16,
    };
    set_header.put_to_bytes(bytes);
    option_template_record_header.put_to_bytes(bytes);
    for field in scope_field_specifiers {
        field.put_to_bytes(bytes);
    }
    for field in option_field_specifiers {
        field.put_to_bytes(bytes);
    }
    return set_length;
}

pub fn put_option_data_set(
    config: &Configuration,
    stats: &Statistics,
    bytes: &mut BytesMut,
) -> u16 {
    let set_length: u16 = IPFIX_SET_HEADER_SIZE as u16 +
        field_specifiers_data_length(&default_scope_field_specifiers()) +
        field_specifiers_data_length(&default_option_field_specifiers());
    let set_header = SetHeader {
        set_id: RUSTFLOWD_OPTION_TEMPLATE_ID,
        length: set_length,
    };
    let system_init_time: u64 = stats
        .meter
        .system_init_time
        .duration_since(UNIX_EPOCH)
        .expect("failed to get system_init_time")
        .as_millis() as u64;
    set_header.put_to_bytes(bytes); // put set header
    //put data
    bytes.put_slice(&config.meter.process_id.to_be_bytes()); // scope: meteringPorcessId
    bytes.put_slice(&system_init_time.to_be_bytes()); // systemInitTime
    bytes.put_slice(&config.meter.selector_algorithm.to_be_bytes()); // selectorAlgorithm
    bytes.put_slice(&config.meter.sampling_packet_interval.to_be_bytes()); // samplingPacketInterval
    bytes.put_slice(&config.meter.sampling_packet_space.to_be_bytes()); // samplingPacketSpace
    return set_length;
}
