use bytes::{BytesMut, BufMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub struct FlowKey {
    pub ip_addresses: [IpAddr; 2], // Using to_compatible for storeing Ipv4Addr
    pub transport_ports: [u16; 2],
    pub protocol_identifier: IpNextHeaderProtocol,
    pub ip_version: u8,
    pub ip_class_of_service: u8,
}
impl Default for FlowKey {
    fn default() -> FlowKey {
        FlowKey {
            ip_addresses: [
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ],
            transport_ports: [0, 0],
            protocol_identifier: IpNextHeaderProtocols::Reserved,
            ip_version: 0,
            ip_class_of_service: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowValue {
    pub start: SystemTime,
    pub end: SystemTime,
    pub octet_delta_count: u64, // Information Element 1:
    pub packet_delta_count: u64, // Information Element 2
    pub tcp_control_bits: u16, // Information Element 6

    // Information Element 136: The reason for Flow termination.
    // 0x01: idle timeout 0x02: active timeout 0x03: end of Flow
    // detected 0x04: forced end 0x05: lack of resources
    pub flow_end_reason: u8,
}
impl Default for FlowValue {
    fn default() -> FlowValue {
        FlowValue {
            start: UNIX_EPOCH,
            end: UNIX_EPOCH,
            octet_delta_count: 0,
            packet_delta_count: 1,
            tcp_control_bits: 0,
            flow_end_reason: 0,
        }
    }
}

impl FlowValue {
    pub fn update(&mut self, new_flow_value: FlowValue) {
        self.end = new_flow_value.end;
        self.packet_delta_count += 1;
        self.octet_delta_count += new_flow_value.octet_delta_count;
        self.tcp_control_bits |= new_flow_value.tcp_control_bits;
    }
}

#[derive(Debug)]
pub struct Flow {
    pub key: FlowKey,
    pub value: FlowValue,
}

impl Flow {
    pub fn put_record(
        &self,
        bytes: &mut BytesMut,
        version: u16,
        system_init_time: SystemTime,
    ) -> usize {
        let mut length = 0;
        match self.key.ip_addresses[0] { // sourceIpAddress
            IpAddr::V4(addr) => {
                bytes.put_slice(&(u32::from(addr)).to_be_bytes());
                length += 4;
            }
            IpAddr::V6(addr) => {
                if version >= 9 {
                    bytes.put_slice(&(u128::from(addr)).to_be_bytes());
                    length += 16;
                }
            }
        };
        match self.key.ip_addresses[1] { // destinationIpAddress
            IpAddr::V4(addr) => {
                bytes.put_slice(&(u32::from(addr)).to_be_bytes());
                length += 4;
                // ipNexthopIPAddress is looked up from destinationIpAddress
                bytes.put_slice(&u32::from(Ipv4Addr::UNSPECIFIED).to_be_bytes()); // ipNextHopIPv4Address
                length += 4;
            }
            IpAddr::V6(addr) => {
                if version >= 9 {
                    bytes.put_slice(&(u128::from(addr)).to_be_bytes());
                    length += 16;
                    // ipNexthopIPAddress is looked up from destinationIpAddress
                    bytes.put_slice(&(u128::from(Ipv6Addr::UNSPECIFIED)).to_be_bytes()); // ipNextHopIPv6Address
                    length += 16;
                }
            }
        };
        if version >= 9 {
            //IPFIX and NetFlow v9
            bytes.put_slice(&0u32.to_be_bytes()); //ingressInterface 32bit
            length += 4;
            bytes.put_slice(&0u32.to_be_bytes()); //egressInterface 32bit
            length += 4;
            bytes.put_slice(&self.value.octet_delta_count.to_be_bytes()); //64bit
            length += 8;
            bytes.put_slice(&self.value.packet_delta_count.to_be_bytes()); //64bit
            length += 8;
        } else {
            bytes.put_slice(&0u16.to_be_bytes()); //ingressInterface 16bit
            length += 2;
            bytes.put_slice(&0u16.to_be_bytes()); //egressInterface 16bit
            length += 2;
            bytes.put_slice(&(self.value.octet_delta_count as u32).to_be_bytes()); //32bit
            length += 4;
            bytes.put_slice(&(self.value.packet_delta_count as u32).to_be_bytes()); //32bit
            length += 4;
        }
        bytes.put_slice(&(self.value
              .start
              .duration_since(system_init_time)
              .unwrap()
              .as_millis() as u32)
            .to_be_bytes());
        length += 4;
        bytes.put_slice(&(self.value
              .end
              .duration_since(system_init_time)
              .unwrap()
              .as_millis() as u32)
            .to_be_bytes());
        length += 4;
        bytes.put_slice(&self.key.transport_ports[0].to_be_bytes()); //sourceTransportPort
        length += 2;
        bytes.put_slice(&self.key.transport_ports[1].to_be_bytes()); //destinationTransportPort
        length += 2;
        if version >= 5 {
            if version >= 9 {
                bytes.put_slice(&self.value.tcp_control_bits.to_be_bytes());
                length += 2;
            } else {
                bytes.put_u8(0u8); //paddingOctets, if version is 7 this field is flag
                bytes.put_u8(self.value.tcp_control_bits as u8);
                length += 2;
            }
            bytes.put_u8(self.key.protocol_identifier.0);
            length += 1;
            bytes.put_u8(self.key.ip_class_of_service);
            length += 1;
            if version >= 9 {
                bytes.put_slice(&(0u32).to_be_bytes()); //bgpSourceAsNumber 4Byte AS
                length += 4;
                bytes.put_slice(&(0u32).to_be_bytes()); //bgpDestinationAsNumber 4Byte AS
                length += 4;
            } else {
                bytes.put_slice(&(0u16).to_be_bytes()); //bgpSourceAsNumber 2Byte AS
                length += 2;
                bytes.put_slice(&(0u16).to_be_bytes()); //bgpDestinationAsNumber 2Byte AS
                length += 2;
            }
            bytes.put_u8(0u8); //sourceIPv4PrefixLength
            length += 1;
            bytes.put_u8(0u8); //destinationIPv4PrefixLength
            length += 1;
            if version >= 9 &&
                (self.key.protocol_identifier == IpNextHeaderProtocols::Icmp ||
                     self.key.protocol_identifier == IpNextHeaderProtocols::Icmpv6)
            {
                bytes.put_slice(&self.key.transport_ports[1].to_be_bytes());
                length += 2;
            } else {
                bytes.put_u16(0u16); //paddingOcctets
                length += 2;
            }
        } else if version == 1 {
            // version 1
            bytes.put_u16(0u16); //paddingOcctets
            bytes.put_u8(self.key.protocol_identifier.0);
            bytes.put_u8(self.key.ip_class_of_service);
            bytes.put_u8(self.value.tcp_control_bits as u8);
            bytes.put_u8(0u8); //paddingOctets
            bytes.put_u16(0u16); //paddingOcctets
            bytes.put_u32(0u32); //paddingOcctets
            length += 12;
        }
        if version == 7 {
            bytes.put_slice(&u32::from(Ipv4Addr::UNSPECIFIED).to_be_bytes()); //router_sc
            length += 4;
        }
        return length;
    }
}
