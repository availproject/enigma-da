use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    number_of_nodes: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct NodeDetails {
    node_name: String,
    key_file_path: String,
    peer_id: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut node_details = Vec::new();
    // Ensure the keys directory exists
    std::fs::create_dir_all("./data/keys").unwrap();
    println!(">>> Generating {} node keys", args.number_of_nodes);
    for i in 0..args.number_of_nodes {
        let node_name = format!("node_{}", i);
        println!(">>> Generating key for node {}", node_name);
        let key_file = format!("./data/keys/node_key_{}.bin", node_name);
        let key_file_path = format!("./data/keys/node_key_{}.bin", node_name);
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let key_bytes = keypair.to_protobuf_encoding().unwrap();
        std::fs::write(key_file, key_bytes).unwrap();
        node_details.push(NodeDetails {
            node_name: node_name.clone(),
            key_file_path,
            peer_id: keypair.public().to_peer_id().to_string(),
        });
        println!(
            ">>> Node {} Details: {:?}",
            node_name,
            node_details.last().unwrap()
        );
    }
    let json = serde_json::to_string(&node_details).unwrap();
    std::fs::write("./data/node_details.json", json).unwrap();
    println!(">>> Node details saved to ./data/node_details.json");
}

// Usage: cargo run --release --bin node_key_gen -- --number_of_nodes 4
