fn main() {
    let proto_files = vec![
        "src/proto/tapcommon.proto",
        "src/proto/taprootassets.proto",
        "src/proto/tapchannelrpc/tapchannel.proto",
        "src/proto/rfqrpc/rfq.proto",
        "src/proto/routerrpc/router.proto",
        "src/proto/lightning.proto",
    ];

    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&proto_files, &["src/proto"]).expect("compile litd protos");
}


