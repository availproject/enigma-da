use std::{str::FromStr, sync::Arc};

use crate::{
    config::ServiceConfig,
    p2p::node::{NetworkNode, NodeCommand},
    tests::cleanup_test_files,
};
use kms_node::{NodeConfig, run};
use libp2p::PeerId;
use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};

const TEST_SHARD: &str = "[[48,129,128,2,1,0,4,123,48,121,2,1,1,4,33,1,196,150,40,136,159,143,117,108,125,163,226,120,71,132,214,204,187,87,206,254,220,131,225,25,98,238,62,171,33,99,255,63,4,81,48,79,2,1,4,2,1,3,4,65,4,179,197,116,13,36,228,122,200,9,13,231,99,203,245,54,217,198,0,60,160,236,237,209,127,30,206,71,183,173,36,132,128,174,47,220,92,7,131,219,131,132,241,234,245,178,181,123,109,35,46,9,87,40,238,143,131,7,5,29,69,237,136,175,160,4,4,0,0,1,65],[48,130,1,79,2,1,0,4,130,1,72,48,130,1,68,2,1,1,4,33,1,249,36,137,75,139,160,97,55,41,179,70,99,199,69,113,75,62,85,2,147,160,114,66,131,15,134,61,243,6,102,252,108,4,130,1,26,3,179,212,96,241,246,110,30,232,40,51,234,177,198,77,223,78,142,195,7,119,126,49,179,172,0,244,243,215,145,122,239,212,2,121,190,102,126,249,220,187,172,85,160,98,149,206,135,11,7,2,155,252,219,45,206,40,217,89,242,129,91,22,248,23,152,100,0,0,0,0,0,0,0,3,2,179,197,116,13,36,228,122,200,9,13,231,99,203,245,54,217,198,0,60,160,236,237,209,127,30,206,71,183,173,36,132,128,3,101,244,101,159,151,58,91,35,186,122,180,225,73,94,78,178,216,110,70,90,243,103,208,199,231,164,95,178,200,46,194,90,3,250,197,31,83,243,105,248,142,229,48,142,16,40,19,16,137,22,37,160,232,83,79,103,211,171,64,112,112,166,49,7,250,100,0,0,0,0,0,0,0,3,3,191,139,188,202,80,156,5,183,164,27,205,212,43,10,113,209,160,44,2,194,168,67,159,168,212,243,26,223,115,121,98,114,3,253,80,248,186,140,102,44,223,21,20,224,85,245,176,231,144,190,148,230,80,141,43,201,48,49,94,193,51,33,12,203,90,3,139,88,17,23,86,171,26,152,133,84,93,7,175,109,143,158,97,114,9,108,97,216,147,106,106,132,191,150,149,187,54,16]]";

#[tokio::test]
async fn test_p2p_send_shards() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    // run the network nodes
    let node1_pid = run_node("node1", 9000)?;
    let node2_pid = run_node("node2", 9001)?;

    // Wait for nodes to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    let node1_peer_id = PeerId::from_str("12D3KooWL3rbRMvYtoJiz8xEqsL4nsUdK46E9bFnuZjvX9NTuhPP")?;
    let node2_peer_id = PeerId::from_str("12D3KooWP9YCShgX1gunS9EHywQEcZ85cfY3Lz1ttgfdqbYqK299")?;

    println!(">>> Node1 Peer ID: {}", node1_peer_id);
    println!(">>> Node2 Peer ID: {}", node2_peer_id);

    // start the main node
    let network_node = Arc::new(Mutex::new(
        NetworkNode::new(8002, "main_node".to_string(), ServiceConfig::default()).await?,
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
        app_id: "123".to_string(),
        shard_index: 0,
        shard: TEST_SHARD.to_string(),
        job_id,
    })?;
    // send a shard to the node 2
    command_sender.send(NodeCommand::SendShard {
        peer_id: node2_peer_id.to_string(),
        app_id: "123".to_string(),
        shard_index: 1,
        shard: TEST_SHARD.to_string(),
        job_id,
    })?;

    sleep(Duration::from_secs(10)).await;

    kill_process(node1_pid)?;
    kill_process(node2_pid)?;

    command_sender.send(NodeCommand::Shutdown)?;
    handle.await?;
    cleanup_test_files().await;
    Ok(())
}

#[tokio::test]
async fn test_p2p_fetch_shards() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    // run the network nodes
    let node1_pid = run_node("node1", 9000)?;
    let node2_pid = run_node("node2", 9001)?;

    // Wait for nodes to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    let node1_peer_id = PeerId::from_str("12D3KooWL3rbRMvYtoJiz8xEqsL4nsUdK46E9bFnuZjvX9NTuhPP")?;
    let node2_peer_id = PeerId::from_str("12D3KooWP9YCShgX1gunS9EHywQEcZ85cfY3Lz1ttgfdqbYqK299")?;

    println!(">>> Node1 Peer ID: {}", node1_peer_id);
    println!(">>> Node2 Peer ID: {}", node2_peer_id);

    // start the main node
    let network_node = Arc::new(Mutex::new(
        NetworkNode::new(8002, "main_node".to_string(), ServiceConfig::default()).await?,
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
        app_id: "123".to_string(),
        shard_index: 0,
        shard: TEST_SHARD.to_string(),
        job_id,
    })?;
    // send a shard to the node 2
    command_sender.send(NodeCommand::SendShard {
        peer_id: node2_peer_id.to_string(),
        app_id: "123".to_string(),
        shard_index: 1,
        shard: TEST_SHARD.to_string(),
        job_id,
    })?;

    // wait for shards to be stored in the nodes
    sleep(Duration::from_secs(10)).await;

    // fetch the shards from all the nodes for app1
    command_sender.send(NodeCommand::RequestShard {
        peer_id: node1_peer_id.to_string(),
        app_id: "123".to_string(),
        job_id,
    })?;
    command_sender.send(NodeCommand::RequestShard {
        peer_id: node2_peer_id.to_string(),
        app_id: "123".to_string(),
        job_id,
    })?;

    sleep(Duration::from_secs(10)).await;

    kill_process(node1_pid)?;
    kill_process(node2_pid)?;

    command_sender.send(NodeCommand::Shutdown)?;
    handle.await?;

    cleanup_test_files().await;

    Ok(())
}

// ===============================
// P2P Helper Functions
// ===============================

pub fn run_node(
    name: &str,
    port: u16,
) -> anyhow::Result<tokio::task::JoinHandle<Result<(), anyhow::Error>>> {
    let config = NodeConfig {
        port,
        node_name: name.to_string(),
    };

    unsafe {
        std::env::set_var("RUST_LOG", "info");
        std::env::set_var("P2P_NODE_NAME", name);
        std::env::set_var("P2P_NODE_PORT", port.to_string());
        std::env::set_var("P2P_NODE_PEER_ID_FILE", format!("peer_id_{}.txt", name));
    }

    let handle = tokio::spawn(async move { run(config).await });

    Ok(handle)
}

pub fn kill_process(pid: tokio::task::JoinHandle<Result<(), anyhow::Error>>) -> anyhow::Result<()> {
    let id = pid.id();
    pid.abort();
    println!("✅ Killed process {}", id);
    Ok(())
}
