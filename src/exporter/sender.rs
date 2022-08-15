use crate::rustflowd::api::*;
use std::io::Error;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
const IPFIX_TRANSPORT_PORT: u16 = 4739;

enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

pub struct Destination {
    connection: Connection,
    destination: SocketAddr,
    source: SocketAddr,
}

impl Destination {
    pub fn new(destination_configuration: &ipfix::exporting_process::Destination) -> Destination {
        let destination_ip_address = &(destination_configuration.destination_ip_address)
            .as_ref()
            .expect("destination ip address is not specified.")
            .value;
        let destination_port = &(destination_configuration.destination_port)
            .as_ref()
            .unwrap_or(&UintValue {
                value: IPFIX_TRANSPORT_PORT as u64,
            })
            .value;
        let destination = (destination_ip_address.as_str(), *destination_port as u16)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let export_transport_protocol_name = &(destination_configuration
            .export_transport_protocol_name)
            .as_ref()
            .expect("export transport protocol name is not specified.")
            .value;
        /*
           let source_ip_address = &(destination_configuration.source_ip_address)
               .as_ref()
               .expect("source ip address is not specified.")
               .value;
        */
        let source: SocketAddr = match &destination_configuration.source_ip_address {
            None => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0u16),
            Some(source_ip_address) => (source_ip_address.value.as_str(), 0u16)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
        };

        //let source_ip_address_port = format!("{}:0", source_ip_address);
        //println! {"source_ip_address_port: {:?}", source_ip_address_port};
        /*
           let source = (source_ip_address_port.as_str(), 0u16)
               .to_socket_addrs()
               .unwrap()
               .next()
               .unwrap();
        */
        Destination {
            connection: match export_transport_protocol_name.as_str() {
                "udp" => Connection::Udp(UdpSocket::bind(source).expect("failed to udp bind")),
                "tcp" => {
                    Connection::Tcp(TcpStream::connect(destination).expect("failed to tcp connect"))
                }
                _ => {
                    panic!()
                }
            },
            destination: destination,
            source: source,
        }
    }
    pub fn connect(&self) -> Result<(), Error> {
        // connect is needed for only UDP, TCP is already connected when stream is created
        return match &self.connection {
            Connection::Udp(udp_socket) => udp_socket.connect(self.destination),
            _ => Ok(()),
        };
    }
}
