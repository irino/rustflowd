use clap::Parser;
use serde_derive::*;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::net::SocketAddr;
use tonic::transport::Server;

// separate file to rustflowd.rs (include tonic api)
mod rustflowd;
use crate::rustflowd::api::rustflowd_api_server::RustflowdApiServer;
use crate::rustflowd::api::*;
use crate::rustflowd::RustflowdApiService;
mod exporter;
use crate::exporter::meter::Meter;
use crate::exporter::sender::Destination;


#[derive(Parser)]
#[clap(author, version, about, long_about = None)] // Read from `Cargo.toml`
struct Cli {
    #[clap(long, value_parser)]
    configuration_file_name: String,
    write_configuration_file_name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut ipfix: Ipfix = Ipfix::new();
    
    if cli.configuration_file_name != "" {
        let configuration_file = File::open(cli.configuration_file_name).unwrap();
        let configuration_reader = BufReader::new(configuration_file);
        ipfix = serde_json::from_reader(configuration_reader).unwrap();
    }

    if cli.write_configuration_file_name != "" {
        let write_configuration_file = File::create(cli.write_configuration_file_name).unwrap();
        let mut configuration_writer = BufWriter::new(write_configuration_file);
        let output_json = serde_json::to_string_pretty(&ipfix).unwrap();
        configuration_writer.write(&output_json.into_bytes())?;
    }

    let mut destinations: Vec<Destination> = Vec::new();
    for each_exporting_process in &ipfix.exporting_process {
        if let Some(exporting_process) = &each_exporting_process.exporting_process {
            for each_destination in &exporting_process.destination {
                if let Some(destination) = &each_destination.destination {
                    destinations.push(Destination::new(&destination));
                }
            }
        }
    }

    let mut meters: Vec<Meter> = Vec::new();
    for each_observation_point in &ipfix.observation_point {
        if let Some(observation_point) = &each_observation_point.observation_point {
            meters.push(Meter::new(&observation_point));
        }
    }
    let mut meter_handles: Vec<Vec<std::thread::JoinHandle<()>>> = Vec::new();
    //meters.into_iter().map(|meter| meter_handles.push(meter.read())); // compile error by
    //lifetime

    // run tonic grpc server
    let addr: SocketAddr = "[::1]:50051".parse().unwrap();
    let service = RustflowdApiService::default();

    Server::builder()
        .add_service(RustflowdApiServer::new(service))
        .serve(addr)
        .await?;

    for handles in meter_handles.into_iter() {
        for handle in handles.into_iter() {
            handle.join();
        }
    }
    Ok(())
}
