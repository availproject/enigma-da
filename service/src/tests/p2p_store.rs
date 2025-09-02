use crate::{config::ServiceConfig, db::store::DataStore};
use anyhow::Result;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn test_p2p_store_basic_operations() -> Result<()> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_p2p_store_db");
    let store = DataStore::new(db_path.to_str().unwrap(), ServiceConfig::default())?;

    let app_id = Uuid::new_v4();
    let app_id2 = Uuid::new_v4();

    // Test adding and getting shards
    store.add_shard(app_id, 0, "shard0_data".to_string())?;
    store.add_shard(app_id, 1, "shard1_data".to_string())?;
    store.add_shard(app_id2, 0, "app2_shard0".to_string())?;

    assert_eq!(store.get_shard(app_id, 0)?.unwrap(), "shard0_data");
    assert_eq!(store.get_shard(app_id, 1)?.unwrap(), "shard1_data");
    assert_eq!(store.get_shard(app_id2, 0)?.unwrap(), "app2_shard0");
    assert!(store.get_shard(app_id, 2)?.is_none());

    // Test getting all shards
    let all_shards = store.get_all_shards(app_id)?;
    assert_eq!(all_shards.len(), 2);
    assert_eq!(all_shards.get(&0).unwrap().shard, "shard0_data".to_string());
    assert_eq!(all_shards.get(&1).unwrap().shard, "shard1_data".to_string());

    // Test peer IDs
    store.add_app_peer_ids(app_id, vec!["peer1".to_string(), "peer2".to_string()])?;
    let peer_ids = store.get_app_peer_ids(app_id)?.unwrap();
    assert_eq!(peer_ids, vec!["peer1", "peer2"]);

    // Test listing apps
    let apps = store.list_apps()?;
    assert!(apps.contains(&app_id));
    assert!(apps.contains(&app_id2));

    // Test removing shard
    store.remove_shard(app_id, 0)?;
    assert!(store.get_shard(app_id, 0)?.is_none());
    assert!(store.get_shard(app_id, 1)?.is_some());

    // Test removing app
    store.remove_app(app_id)?;
    assert!(store.get_shard(app_id, 1)?.is_none());
    assert!(store.get_app_peer_ids(app_id)?.is_none());
    assert!(store.get_shard(app_id2, 0)?.is_some()); // app2 should still exist

    Ok(())
}

#[test]
fn test_p2p_store_persistence() -> Result<()> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("persistence_test_db");

    let app_id = Uuid::new_v4();
    let app_id2 = Uuid::new_v4();

    // Create store and add data
    {
        let store = DataStore::new(db_path.to_str().unwrap(), ServiceConfig::default())?;
        store.add_shard(app_id, 0, "persistent_data".to_string())?;
        store.add_app_peer_ids(app_id, vec!["peer1".to_string()])?;
    } // Store is dropped here

    // Reopen store and verify data persists
    let store = DataStore::new(db_path.to_str().unwrap(), ServiceConfig::default())?;
    assert_eq!(store.get_shard(app_id, 0)?.unwrap(), "persistent_data");
    assert_eq!(store.get_app_peer_ids(app_id)?.unwrap(), vec!["peer1"]);

    Ok(())
}
