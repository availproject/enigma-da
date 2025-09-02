use uuid::Uuid;

use crate::{p2p::store::ShardStore, tests::cleanup_test_files};

#[tokio::test]

async fn test_sled_storage_demo() -> anyhow::Result<()> {
    println!("🚀 Sled Storage Demo Test");
    println!("========================");

    // Create a new ShardStore with unique suffix for test isolation
    let store = ShardStore::new_with_suffix("demo_node", "test_demo")
        .map_err(|e| anyhow::anyhow!("Failed to create ShardStore: {}", e))?;
    println!("✅ ShardStore created successfully");

    // Store some test shards
    let app_id = Uuid::new_v4();
    let shards = vec![
        (1, "shard_data_1".to_string()),
        (2, "shard_data_2".to_string()),
        (3, "shard_data_3".to_string()),
    ];

    println!("\n📝 Storing shards for app_id: {}", app_id);
    for (shard_index, shard_data) in &shards {
        store
            .add_shard(app_id, *shard_index, shard_data.clone())
            .map_err(|e| anyhow::anyhow!("Failed to add shard {}: {}", shard_index, e))?;
        println!("   ✅ Stored shard {}: {}", shard_index, shard_data);
    }

    // Retrieve individual shards
    println!("\n🔍 Retrieving individual shards:");
    for (shard_index, expected_data) in &shards {
        match store
            .get_shard(app_id, *shard_index)
            .map_err(|e| anyhow::anyhow!("Failed to get shard {}: {}", shard_index, e))?
        {
            Some(retrieved_data) => {
                if &retrieved_data == expected_data {
                    println!("   ✅ Shard {}: {}", shard_index, retrieved_data);
                } else {
                    println!("   ❌ Shard {}: data mismatch", shard_index);
                }
            }
            None => println!("   ❌ Shard {}: not found", shard_index),
        }
    }

    // Retrieve all shards for the app
    println!("\n📋 Retrieving all shards for app_id: {}", app_id);
    let all_shards = store
        .get_all_shards_for_app(app_id)
        .map_err(|e| anyhow::anyhow!("Failed to get all shards for app {}: {}", app_id, e))?;
    println!("   Found {} shards:", all_shards.len());
    for (shard_index, shard_data) in all_shards {
        println!("     Shard {}: {}", shard_index, shard_data);
    }

    // Test with a different app_id
    let app_id_2 = Uuid::new_v4();
    println!("\n📝 Storing shards for app_id: {}", app_id_2);
    store
        .add_shard(app_id_2, 1, "different_app_shard".to_string())
        .map_err(|e| anyhow::anyhow!("Failed to add shard for app {}: {}", app_id_2, e))?;
    println!("   ✅ Stored shard for app_id: {}", app_id_2);

    // Verify isolation between apps
    println!("\n🔍 Verifying app isolation:");
    let app1_shards = store
        .get_all_shards_for_app(app_id)
        .map_err(|e| anyhow::anyhow!("Failed to get shards for app {}: {}", app_id, e))?;
    let app2_shards = store
        .get_all_shards_for_app(app_id_2)
        .map_err(|e| anyhow::anyhow!("Failed to get shards for app {}: {}", app_id_2, e))?;
    println!("   App {} has {} shards", app_id, app1_shards.len());
    println!("   App {} has {} shards", app_id_2, app2_shards.len());

    // Test removing a shard
    println!("\n🗑️  Testing shard removal:");
    store
        .remove_shard(app_id, 2)
        .map_err(|e| anyhow::anyhow!("Failed to remove shard 2 from app {}: {}", app_id, e))?;
    println!("   ✅ Removed shard 2 from app {}", app_id);

    match store
        .get_shard(app_id, 2)
        .map_err(|e| anyhow::anyhow!("Failed to get shard 2 from app {}: {}", app_id, e))?
    {
        Some(_) => println!("   ❌ Shard 2 still exists"),
        None => println!("   ✅ Shard 2 successfully removed"),
    }

    // Final state
    println!("\n📊 Final state:");
    let final_shards = store.get_all_shards_for_app(app_id).unwrap();
    println!(
        "   App {} has {} shards: {:?}",
        app_id,
        final_shards.len(),
        final_shards
    );

    println!("\n🎉 Demo test completed successfully!");
    cleanup_test_files().await;
    Ok(())
}
