use std::time::SystemTime;

pub struct PerProtocolStatistics {
    // from softflowd
    pub packet_total_count: u64,
    pub octet_total_count: u64,
}

impl Default for PerProtocolStatistics {
    fn default() -> PerProtocolStatistics {
        PerProtocolStatistics {
            packet_total_count: 0,
            octet_total_count: 0,
        }
    }
}
#[derive(Debug)]
pub struct MeteringProcessStatistics {
    pub observed_flow_total_count: u64, // Information Element 163
    pub ignored_packet_total_count: u64, // Information Element 164
    pub ignored_octet_total_count: u64, // Information Element 165
    pub observed_packet_total_count: u64, // from softflowd
    pub non_sampled_packet_total_count: u64, //from softflowd: of not sampled packets
    pub idle_timeout_expired_flow_total_count: u64,
    pub active_timeout_expired_flow_total_count: u64,
    pub end_of_flow_expired_flow_total_count: u64,
    pub force_end_expired_flow_total_count: u64,
    pub lack_of_resources_expired_flow_total_count: u64,
    pub system_init_time: SystemTime,
    pub last_packet_time: SystemTime,
}
impl Default for MeteringProcessStatistics {
    fn default() -> MeteringProcessStatistics {
        let now = SystemTime::now();
        MeteringProcessStatistics {
            observed_flow_total_count: 0,
            ignored_packet_total_count: 0,
            ignored_octet_total_count: 0,
            observed_packet_total_count: 0,
            non_sampled_packet_total_count: 0,
            idle_timeout_expired_flow_total_count: 0,
            active_timeout_expired_flow_total_count: 0,
            end_of_flow_expired_flow_total_count: 0,
            force_end_expired_flow_total_count: 0,
            lack_of_resources_expired_flow_total_count: 0,
            system_init_time: now,
            last_packet_time: now,
        }
    }
}
#[derive(Debug)]
pub struct ExportingProcessStatistics {
    pub exported_octet_total_count: u64, //Information Element: 40
    pub exported_message_total_count: u64, //Information Element: 41
    pub exported_flow_record_total_count: u64, //Information Element: 42
}
impl Default for ExportingProcessStatistics {
    fn default() -> ExportingProcessStatistics {
        ExportingProcessStatistics {
            exported_octet_total_count: 0,
            exported_message_total_count: 0,
            exported_flow_record_total_count: 0,
        }
    }
}
#[derive(Debug)]
pub struct Statistics {
    pub export: ExportingProcessStatistics,
    pub meter: MeteringProcessStatistics,
}
impl Default for Statistics {
    fn default() -> Statistics {
        Statistics {
            export: Default::default(),
            meter: Default::default(),
        }
    }
}
