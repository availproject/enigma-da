use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use libp2p::PeerId;
use tokio::{sync::Mutex, time::sleep};

use crate::p2p::node::{NetworkNode, NodeCommand};

#[tokio::test]
async fn test_p2p_send_shards() -> anyhow::Result<()> {
    // run the network nodes
    let node1_pid = run_node("node1", 9000)?;
    let node2_pid = run_node("node2", 9001)?;

    // Wait for nodes to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    let node1_peer_id = read_peer_id("node1")?;
    let node2_peer_id = read_peer_id("node2")?;

    println!(">>> Node1 Peer ID: {}", node1_peer_id);
    println!(">>> Node2 Peer ID: {}", node2_peer_id);

    // start the main node
    let network_node = Arc::new(Mutex::new(
        NetworkNode::new(9002, "main_node".to_string()).await?,
    ));
    let network_node_peer_id = network_node.lock().await.local_peer_id().to_string();
    println!(">>> Main Node Peer ID: {}", network_node_peer_id);

    let command_sender = network_node.lock().await.get_command_sender();

    let handle = tokio::spawn(async move {
        let mut node = network_node.lock().await;
        println!("🔄 Main Node starting event loop...");
        node.run().await.unwrap();
    });

    sleep(Duration::from_secs(1)).await; // Give the main node time to start
    println!("⏰ Main Node startup wait completed");

    let job_id = uuid::Uuid::new_v4();

    // send a shard to the node 1
    command_sender.send(NodeCommand::SendShard {
        peer_id: node1_peer_id.to_string(),
        app_id: "app1".to_string(),
        shard_index: 0,
        shard: "shard1".to_string(),
        job_id,
    })?;
    // send a shard to the node 2
    command_sender.send(NodeCommand::SendShard {
        peer_id: node2_peer_id.to_string(),
        app_id: "app1".to_string(),
        shard_index: 1,
        shard: "shard2".to_string(),
        job_id,
    })?;

    sleep(Duration::from_secs(10)).await;

    kill_process(node1_pid)?;
    kill_process(node2_pid)?;

    command_sender.send(NodeCommand::Shutdown)?;
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_p2p_fetch_shards() -> anyhow::Result<()> {
    // run the network nodes
    let node1_pid = run_node("node1", 9000)?;
    let node2_pid = run_node("node2", 9001)?;

    // Wait for nodes to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    let node1_peer_id = read_peer_id("node1")?;
    let node2_peer_id = read_peer_id("node2")?;

    println!(">>> Node1 Peer ID: {}", node1_peer_id);
    println!(">>> Node2 Peer ID: {}", node2_peer_id);

    // start the main node
    let network_node = Arc::new(Mutex::new(
        NetworkNode::new(9002, "main_node".to_string()).await?,
    ));
    let network_node_peer_id = network_node.lock().await.local_peer_id().to_string();
    println!(">>> Main Node Peer ID: {}", network_node_peer_id);

    let command_sender = network_node.lock().await.get_command_sender();

    let handle = tokio::spawn(async move {
        let mut node = network_node.lock().await;
        println!("🔄 Main Node starting event loop...");
        node.run().await.unwrap();
    });

    sleep(Duration::from_secs(1)).await; // Give the main node time to start
    println!("⏰ Main Node startup wait completed");

    let job_id = uuid::Uuid::new_v4();

    // send a shard to the node 1
    command_sender.send(NodeCommand::SendShard {
        peer_id: node1_peer_id.to_string(),
        app_id: "app1".to_string(),
        shard_index: 0,
        shard: "shard1".to_string(),
        job_id,
    })?;
    // send a shard to the node 2
    command_sender.send(NodeCommand::SendShard {
        peer_id: node2_peer_id.to_string(),
        app_id: "app1".to_string(),
        shard_index: 1,
        shard: "shard2".to_string(),
        job_id,
    })?;

    // wait for shards to be stored in the nodes
    sleep(Duration::from_secs(10)).await;

    // fetch the shards from all the nodes for app1
    command_sender.send(NodeCommand::RequestShard {
        peer_id: node1_peer_id.to_string(),
        app_id: "app1".to_string(),
        job_id,
    })?;
    command_sender.send(NodeCommand::RequestShard {
        peer_id: node2_peer_id.to_string(),
        app_id: "app1".to_string(),
        job_id,
    })?;

    sleep(Duration::from_secs(10)).await;

    kill_process(node1_pid)?;
    kill_process(node2_pid)?;

    command_sender.send(NodeCommand::Shutdown)?;
    handle.await?;

    Ok(())
}

// ===============================
// P2P Helper Functions
// ===============================

pub fn run_node(name: &str, port: u16) -> anyhow::Result<u32> {
    let node = Command::new("../target/debug/enigma-kms-node")
        .env("RUST_LOG", "info")
        .env("P2P_NODE_NAME", name)
        .env("P2P_NODE_PORT", port.to_string())
        .env("P2P_NODE_PEER_ID_FILE", format!("peer_id_{}.txt", name))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to run node");

    let p_id = node.id();

    Ok(p_id)
}

fn read_peer_id(name: &str) -> anyhow::Result<PeerId> {
    let file = File::open(format!("peer_id_{}.txt", name))?;
    let reader = BufReader::new(file);
    let peer_id: String =
        String::from_utf8(reader.lines().next().unwrap().unwrap().as_bytes().to_vec())?;
    Ok(peer_id.parse()?)
}

fn kill_process(pid: u32) -> anyhow::Result<()> {
    Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to kill process {}: {}", pid, e))?;

    println!("✅ Killed process {}", pid);
    Ok(())
}
