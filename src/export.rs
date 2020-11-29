use super::flow::Flow;
use super::ipfix::{IPFIX_SET_HEADER_SIZE, IPFIX_DATA_SET_TEMPLATE_ID_BASE, SetHeader,
                   field_specifiers_data_length, put_template_set, put_option_template_set,
                   put_option_data_set};
use super::configuration::{Configuration, flow_index};
use super::statistics::Statistics;

use bytes::{BytesMut, BufMut};
use std::collections::VecDeque;
use std::io::Error;
use std::time::UNIX_EPOCH;

const NETFLOW_V1_HEADER_SIZE: u16 = 16;
const NETFLOW_V1_RECORD_SIZE: u16 = 48;
const NETFLOW_V5_HEADER_SIZE: u16 = 24;
const NETFLOW_V5_RECORD_SIZE: u16 = 48;
const NETFLOW_V7_HEADER_SIZE: u16 = 24;
const NETFLOW_V7_RECORD_SIZE: u16 = 52;
const NETFLOW_V9_HEADER_SIZE: u16 = 20;
const IPFIX_HEADER_SIZE: u16 = 16;

pub fn get_message_header_size(config: &Configuration) -> u16 {
    let header_size = match config.export.protocol_version {
        1 => NETFLOW_V1_HEADER_SIZE,
        5 => NETFLOW_V5_HEADER_SIZE,
        7 => NETFLOW_V7_HEADER_SIZE,
        9 => NETFLOW_V9_HEADER_SIZE,
        10 => IPFIX_HEADER_SIZE,
        _ => 0,
    };
    return header_size;
}

pub fn get_data_record_size(config: &Configuration, ip_version: u8) -> u16 {
    match config.export.protocol_version {
        1 => NETFLOW_V1_RECORD_SIZE,
        5 => NETFLOW_V5_RECORD_SIZE,
        7 => NETFLOW_V7_RECORD_SIZE,
        9 | 10 => field_specifiers_data_length(
            &config.export.field_specifiers[flow_index(ip_version)],
        ),
        _ => 0,
    }
}
pub fn get_max_records_per_message(config: &Configuration, ip_version: u8) -> usize {
    let data_record_size = get_data_record_size(config, ip_version) as usize;
    let message_header_size = get_message_header_size(config) as usize;
    let set_header_size = if config.export.protocol_version < 9 {
        0
    } else {
        IPFIX_SET_HEADER_SIZE as usize
    };
    return (config.export.max_message_size - message_header_size - set_header_size) /
        data_record_size;
}

pub fn put_message_header_to_bytes(
    config: &Configuration,
    stats: &mut Statistics,
    length: u16,
    count: u16,
    bytes: &mut BytesMut,
) {
    let version: u16 = config.export.protocol_version as u16;
    let export_time = stats
        .meter
        .last_packet_time
        .duration_since(UNIX_EPOCH)
        .expect("failed to get export_time");
    bytes.put_slice(&version.to_be_bytes());
    if version == 10 {
        // IPFIX
        bytes.put_slice(&length.to_be_bytes());
    } else {
        // NetFlow
        bytes.put_slice(&count.to_be_bytes());
    }
    if version < 10 {
        // NetFlow
        let system_up_time = stats
            .meter
            .last_packet_time
            .duration_since(stats.meter.system_init_time)
            .unwrap()
            .as_millis() as u32;
        bytes.put_slice(&system_up_time.to_be_bytes());
    }
    bytes.put_slice(&(export_time.as_secs() as u32).to_be_bytes());
    if version < 9 {
        // NetFlow fixed format
        bytes.put_slice(&export_time.subsec_nanos().to_be_bytes());
    }
    if version > 1 {
        // Except NetFlow version 1
        let sequence_number: u32 = if config.export.protocol_version == 9 {
            stats.export.exported_message_total_count as u32 // v9
        } else {
            stats.export.exported_flow_record_total_count as u32 // v5, v7, v8, IPFIX
        };
        bytes.put_slice(&sequence_number.to_be_bytes());
    }
    if version >= 9 {
        bytes.put_slice(&config.meter.observation_domain_id.to_be_bytes());
    } else if version > 1 {
        // NetFlow fixed format except NetFlow version 1
        bytes.put_u8(0); // engine_type: 0: RP, VIP/Line card = 1, PFC/DFC = 2
        bytes.put_u8((config.meter.observation_domain_id & 0x000000ff) as u8); // engine_id
    }
    if version == 5 {
        let sampling: u16 = ((config.meter.sampling_algorithm() as u32) << 14 |
                                 (config.meter.sampling_interval() & 0x00003fff)) as
            u16;
        bytes.put_slice(&sampling.to_be_bytes());
    }
}

pub fn export_template_set(config: &Configuration, stats: &mut Statistics) -> Result<usize, Error> {
    if config.export.protocol_version < 9 {
        return Ok(0); // do nothing
    }
    let mut bytes = BytesMut::with_capacity(config.export.max_message_size);
    let header_size = get_message_header_size(config); // including set header size
    let mut template_records_bytes = bytes.split_off(header_size as usize);
    let template_set_length = put_template_set(config, &mut template_records_bytes);
    let option_template_set_length = put_option_template_set(config, &mut template_records_bytes);
    let option_data_set_length = put_option_data_set(config, stats, &mut template_records_bytes);
    let length = header_size + template_set_length + option_template_set_length +
        option_data_set_length;
    let count = 4; // 2 templates, 1 option template and 1 (option) data record will be reported in NetFlow v9
    // put set header and template record
    put_message_header_to_bytes(config, stats, length as u16, count as u16, &mut bytes);
    bytes.unsplit(template_records_bytes);

    let mut sent = 0;
    for collector in &config.export.collectors {
        sent = config
            .export
            .udp_socket
            .send_to(bytes.as_ref(), collector)
            .expect("failed to send_to");
    }
    stats.export.exported_octet_total_count += length as u64;
    stats.export.exported_message_total_count += 1;
    stats.export.exported_flow_record_total_count += 1; // 1 option data record is contained
    Ok(sent)
}

pub fn export_data_set(
    config: &Configuration,
    stats: &mut Statistics,
    expired_flows: &mut VecDeque<Flow>,
) -> Result<usize, Error> {
    let mut bytes = BytesMut::with_capacity(config.export.max_message_size);
    let mut header_size = get_message_header_size(config); // including set header size
    if config.export.protocol_version >= 9 {
        header_size += IPFIX_SET_HEADER_SIZE;
    }
    let mut ip_version = 4; // default IPv4
    let mut data_record_size = get_data_record_size(config, ip_version);
    let mut data_records_bytes = bytes.split_off(header_size as usize);
    let mut count = 0;
    let mut ignored_count = 0;
    let mut data_records_total_size = 0;
    let mut max_records_per_message = get_max_records_per_message(config, ip_version);
    if expired_flows.len() < max_records_per_message {
        max_records_per_message = expired_flows.len();
    }

    while count + ignored_count < max_records_per_message {
        let flow = expired_flows.pop_front().expect(
            "failed to pop from expired_flows",
        );

        if config.export.protocol_version < 9 && flow.key.ip_version != 4 {
            ignored_count += 1;
            continue;
        }
        if count == 0 {
            if flow.key.ip_version != 4 {
                ip_version = flow.key.ip_version;
                max_records_per_message = get_max_records_per_message(config, ip_version);
                if expired_flows.len() < max_records_per_message {
                    max_records_per_message = expired_flows.len();
                }
                data_record_size = get_data_record_size(config, ip_version);
            }
        }
        flow.put_record(
            &mut data_records_bytes,
            config.export.protocol_version as u16,
            stats.meter.system_init_time,
        ); // record
        data_records_total_size += data_record_size;
        count += 1;
    }
    if count == 0 {
        return Ok(0); // do nothing
    }
    //header
    put_message_header_to_bytes(
        config,
        stats,
        header_size + data_records_total_size,
        count as u16,
        &mut bytes,
    );

    if config.export.protocol_version >= 9 {
        // put set header
        let set_header = SetHeader {
            set_id: IPFIX_DATA_SET_TEMPLATE_ID_BASE + flow_index(ip_version) as u16,
            length: IPFIX_SET_HEADER_SIZE + data_records_total_size,
        };
        set_header.put_to_bytes(&mut bytes);
    }
    bytes.unsplit(data_records_bytes);

    let mut sent = 0;
    for collector in &config.export.collectors {
        sent = config
            .export
            .udp_socket
            .send_to(bytes.as_ref(), collector)
            .expect("failed to send_to");
    }
    stats.export.exported_flow_record_total_count += count as u64;
    stats.export.exported_octet_total_count += (header_size + data_records_total_size) as u64;
    stats.export.exported_message_total_count += 1;
    Ok(sent)
}
