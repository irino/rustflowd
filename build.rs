fn main() -> Result<(), Box<dyn std::error::Error>> {
    "proto/rustflowd_api.proto";
    //tonic_build::compile_protos("proto/rustflowd_api.proto")?;
    tonic_build::configure().build_server(true)
                .type_attribute(".", "#[derive(serde::Deserialize, serde::Serialize)]")
                .compile(&["proto/rustflowd_api.proto"], &["proto/"])
                .unwrap_or_else(|e| panic!("protobuf compile error: {}", e));
    Ok(())
}
