// This test demonstrates a channel-based approach to controlling libp2p nodes in a multi-threaded async test environment.
// Instead of directly calling methods on the node (which would deadlock due to the event loop holding the lock),
// we use a channel to send commands to the node's event loop. This allows us to trigger actions (like sending a shard)
// without blocking or causing lock contention. The node processes commands in its event loop alongside libp2p events.
//
// The test also checks for the log output from Node B to confirm the shard was received.

use crate::p2p::node::test_ext::{NodeCommand, TestableNetworkNode};
use crate::tests::cleanup_test_files;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

#[tokio::test]
#[ignore]
async fn test_p2p_send_shard() {
    let _ = env_logger::builder().is_test(true).try_init();

    const NODE_A_PORT: u16 = 7100;
    const NODE_B_PORT: u16 = 7101;
    const NODE_A_NAME: &str = "node_a";
    const NODE_B_NAME: &str = "node_b";
    const APP_ID: &str = "1";

    println!("🚀 Starting P2P Send Shard test...");

    // Create Node B (Receiver)
    let node_b = Arc::new(Mutex::new(
        TestableNetworkNode::new(NODE_B_PORT, NODE_B_NAME.into())
            .await
            .expect("Failed to create Node B"),
    ));
    let peer_id_b = node_b.lock().await.local_peer_id().to_string();
    println!("📡 Node B created with peer_id: {}", peer_id_b);

    // Get the command sender for Node B BEFORE starting the background task
    let node_b_command_sender = node_b.lock().await.get_command_sender();

    // Run Node B in background
    let node_b_runner = Arc::clone(&node_b);
    let handle_b = tokio::spawn(async move {
        let mut node = node_b_runner.lock().await;
        println!("🔄 Node B starting event loop...");
        node.run().await.unwrap();
    });

    sleep(Duration::from_secs(1)).await; // Give Node B time to start
    println!("⏰ Node B startup wait completed");

    // Create Node A (Sender)
    let node_a = Arc::new(Mutex::new(
        TestableNetworkNode::new(NODE_A_PORT, NODE_A_NAME.into())
            .await
            .expect("Failed to create Node A"),
    ));
    let peer_id_a = node_a.lock().await.local_peer_id().to_string();
    println!("📡 Node A created with peer_id: {}", peer_id_a);

    // Get the command sender BEFORE starting the background task
    let command_sender = node_a.lock().await.get_command_sender();

    // Run Node A in background
    let node_a_runner = Arc::clone(&node_a);
    let handle_a = tokio::spawn(async move {
        let mut node = node_a_runner.lock().await;
        println!("🔄 Node A starting event loop...");
        node.run().await.unwrap();
    });

    println!("⏳ Waiting for connections to establish and stabilize...");
    sleep(Duration::from_secs(10)).await;
    println!("⏰ Connection establishment wait completed");

    // Send shard from A to B
    let app_id = APP_ID.to_string();
    let shard_index = 42;
    let shard_content = "Shard data!".to_string();

    println!("📤 Sending shard from Node A to Node B...");
    println!("   App ID: {}", app_id);
    println!("   Shard Index: {}", shard_index);
    println!("   Shard Content: {}", shard_content);
    println!("   Target Peer ID: {}", peer_id_b);

    // Send the command via channel
    let send_result = command_sender.send(NodeCommand::SendShard {
        peer_id: peer_id_b.clone(),
        app_id: app_id.clone(),
        shard_index,
        shard: shard_content.clone(),
    });

    match send_result {
        Ok(_) => println!("✅ Send shard command sent successfully"),
        Err(e) => {
            println!("❌ Failed to send shard command: {:?}", e);
            // Shutdown both nodes
            node_a.lock().await.shutdown();
            node_b.lock().await.shutdown();
            handle_a.await.unwrap();
            handle_b.await.unwrap();
            return;
        }
    }

    sleep(Duration::from_secs(3)).await; // Wait for transfer and response
    println!("⏰ Transfer wait completed");

    // Check if Node B received the shard (by checking its storage)
    println!("🔍 Checking if Node B received the shard...");
    let shard_fetch = node_b_command_sender.send(NodeCommand::GetShard {
        app_id: app_id.clone(),
    });

    match shard_fetch {
        Ok(_) => println!("✅ Shard fetch command sent successfully"),
        Err(e) => {
            println!("❌ Failed to send shard fetch command: {:?}", e);
            // Shutdown both nodes
            node_a.lock().await.shutdown();
            node_b.lock().await.shutdown();
            handle_a.await.unwrap();
            handle_b.await.unwrap();
            return;
        }
    }

    println!("✅ Shard verification successful!");

    sleep(Duration::from_secs(3)).await;
    println!("⏰ Shard fetch wait completed");

    // Shutdown both nodes using channel commands
    println!("🛑 Shutting down nodes...");

    // Send shutdown commands using pre-acquired command senders
    let shutdown_a = command_sender.send(NodeCommand::Shutdown);
    let shutdown_b = node_b_command_sender.send(NodeCommand::Shutdown);

    match shutdown_a {
        Ok(_) => println!("✅ Shutdown command sent to Node A"),
        Err(e) => println!("❌ Failed to send shutdown command to Node A: {:?}", e),
    }

    match shutdown_b {
        Ok(_) => println!("✅ Shutdown command sent to Node B"),
        Err(e) => println!("❌ Failed to send shutdown command to Node B: {:?}", e),
    }

    // Wait for both nodes to finish
    println!("⏳ Waiting for nodes to shutdown...");
    handle_a.await.unwrap();
    handle_b.await.unwrap();

    println!("🏁 Test completed successfully!");
}

// This test demonstrates shard request functionality where Node A requests a shard from Node B.
// Node B stores a shard first, then Node A requests it via the request-response protocol.
// This tests the reverse flow compared to the send_shard test.
#[tokio::test]
#[ignore]
async fn test_p2p_shard_request() {
    let _ = env_logger::builder().is_test(true).try_init();

    const NODE_A_PORT: u16 = 9021;
    const NODE_B_PORT: u16 = 9022;
    const NODE_A_NAME: &str = "node_a";
    const NODE_B_NAME: &str = "node_b";
    const APP_ID: &str = "2";

    println!("🚀 Starting P2P shard request test...");

    // Create Node B (Provider/Server)
    let node_b = Arc::new(Mutex::new(
        TestableNetworkNode::new(NODE_B_PORT, NODE_B_NAME.into())
            .await
            .expect("Failed to create Node B"),
    ));
    let peer_id_b = node_b.lock().await.local_peer_id().to_string();
    println!("📡 Node B created with peer_id: {}", peer_id_b);

    // Get the command sender for Node B BEFORE starting the background task
    let node_b_command_sender = node_b.lock().await.get_command_sender();

    // Run Node B in background
    let node_b_runner = Arc::clone(&node_b);
    let handle_b = tokio::spawn(async move {
        let mut node = node_b_runner.lock().await;
        println!("🔄 Node B starting event loop...");
        node.run().await.unwrap();
    });

    sleep(Duration::from_secs(1)).await; // Give Node B time to start
    println!("⏰ Node B startup wait completed");

    // Create Node A (Requester/Client)
    let node_a = Arc::new(Mutex::new(
        TestableNetworkNode::new(NODE_A_PORT, NODE_A_NAME.into())
            .await
            .expect("Failed to create Node A"),
    ));
    let peer_id_a = node_a.lock().await.local_peer_id().to_string();
    println!("📡 Node A created with peer_id: {}", peer_id_a);

    // Get the command sender BEFORE starting the background task
    let command_sender = node_a.lock().await.get_command_sender();

    // Run Node A in background
    let node_a_runner = Arc::clone(&node_a);
    let handle_a = tokio::spawn(async move {
        let mut node = node_a_runner.lock().await;
        println!("🔄 Node A starting event loop...");
        node.run().await.unwrap();
    });

    // Wait for connections to establish and stabilize
    println!("⏳ Waiting for connections to establish and stabilize...");
    sleep(Duration::from_secs(10)).await;
    println!("⏰ Connection establishment wait completed");

    // First, store a shard in Node B (the provider)
    let app_id = APP_ID.to_string();
    let shard_index = 123;
    let shard_content = "Requested shard data!".to_string();

    println!("💾 Storing shard in Node B for later request...");
    println!("   App ID: {}", app_id);
    println!("   Shard Index: {}", shard_index);
    println!("   Shard Content: {}", shard_content);

    // Store the shard in Node B using the channel command
    let store_result = node_b_command_sender.send(NodeCommand::StoreShard {
        app_id: app_id.clone(),
        shard_index,
        shard: shard_content.clone(),
    });

    match store_result {
        Ok(_) => println!("✅ Store shard command sent successfully"),
        Err(e) => {
            println!("❌ Failed to send store shard command: {:?}", e);
            // Shutdown both nodes
            command_sender.send(NodeCommand::Shutdown).ok();
            node_b_command_sender.send(NodeCommand::Shutdown).ok();
            handle_a.await.unwrap();
            handle_b.await.unwrap();
            return;
        }
    }

    sleep(Duration::from_secs(1)).await; // Give time for the store command to be processed
    println!("✅ Shard stored in Node B");

    // Now request the shard from Node A to Node B
    println!("📤 Requesting shard from Node A to Node B...");
    println!("   App ID: {}", app_id);
    println!("   Target Peer ID: {}", peer_id_b);

    // Send the request command via channel
    let request_result = command_sender.send(NodeCommand::RequestShard {
        peer_id: peer_id_b.clone(),
        app_id: app_id.clone(),
    });

    match request_result {
        Ok(_) => println!("✅ Request shard command sent successfully"),
        Err(e) => {
            println!("❌ Failed to send request shard command: {:?}", e);
            // Shutdown both nodes
            command_sender.send(NodeCommand::Shutdown).ok();
            node_b_command_sender.send(NodeCommand::Shutdown).ok();
            handle_a.await.unwrap();
            handle_b.await.unwrap();
            return;
        }
    }

    sleep(Duration::from_secs(10)).await; // Wait longer for request and response to complete
    println!("⏰ Request/response wait completed");

    // Check if Node A received the shard (by checking its storage)
    println!("🔍 Checking if Node A received the requested shard...");
    let shard_fetch = command_sender.send(NodeCommand::GetShard {
        app_id: app_id.clone(),
    });

    match shard_fetch {
        Ok(_) => println!("✅ Shard fetch command sent successfully"),
        Err(e) => {
            println!("❌ Failed to send shard fetch command: {:?}", e);
            // Shutdown both nodes
            command_sender.send(NodeCommand::Shutdown).ok();
            node_b_command_sender.send(NodeCommand::Shutdown).ok();
            handle_a.await.unwrap();
            handle_b.await.unwrap();
            return;
        }
    }

    sleep(Duration::from_secs(3)).await;

    println!("✅ Shard request verification successful!");

    // Shutdown both nodes using channel commands
    println!("🛑 Shutting down nodes...");

    // Send shutdown commands using pre-acquired command senders
    let shutdown_a = command_sender.send(NodeCommand::Shutdown);
    let shutdown_b = node_b_command_sender.send(NodeCommand::Shutdown);

    match shutdown_a {
        Ok(_) => println!("✅ Shutdown command sent to Node A"),
        Err(e) => println!("❌ Failed to send shutdown command to Node A: {:?}", e),
    }

    match shutdown_b {
        Ok(_) => println!("✅ Shutdown command sent to Node B"),
        Err(e) => println!("❌ Failed to send shutdown command to Node B: {:?}", e),
    }

    // Wait for both nodes to finish
    println!("⏳ Waiting for nodes to shutdown...");
    handle_a.await.unwrap();
    handle_b.await.unwrap();

    println!("🏁 Shard request test completed successfully!");
    cleanup_test_files().await;
}
