use crate::db::store::DataStore;
use anyhow::Result;
use tempfile::tempdir;

#[test]
fn test_p2p_store_basic_operations() -> Result<()> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_p2p_store_db");
    let store = DataStore::new(db_path.to_str().unwrap())?;

    // Test adding and getting shards
    store.add_shard(1, 0, "shard0_data".to_string())?;
    store.add_shard(1, 1, "shard1_data".to_string())?;
    store.add_shard(2, 0, "app2_shard0".to_string())?;

    assert_eq!(store.get_shard(1, 0)?.unwrap(), "shard0_data");
    assert_eq!(store.get_shard(1, 1)?.unwrap(), "shard1_data");
    assert_eq!(store.get_shard(2, 0)?.unwrap(), "app2_shard0");
    assert!(store.get_shard(1, 2)?.is_none());

    // Test getting all shards
    let all_shards = store.get_all_shards(1)?;
    assert_eq!(all_shards.len(), 2);
    assert_eq!(all_shards.get(&0).unwrap(), "shard0_data");
    assert_eq!(all_shards.get(&1).unwrap(), "shard1_data");

    // Test peer IDs
    store.add_app_peer_ids(1, vec!["peer1".to_string(), "peer2".to_string()])?;
    let peer_ids = store.get_app_peer_ids(1)?.unwrap();
    assert_eq!(peer_ids, vec!["peer1", "peer2"]);

    // Test listing apps
    let apps = store.list_apps()?;
    assert!(apps.contains(&1));
    assert!(apps.contains(&2));

    // Test removing shard
    store.remove_shard(1, 0)?;
    assert!(store.get_shard(1, 0)?.is_none());
    assert!(store.get_shard(1, 1)?.is_some());

    // Test removing app
    store.remove_app(1)?;
    assert!(store.get_shard(1, 1)?.is_none());
    assert!(store.get_app_peer_ids(1)?.is_none());
    assert!(store.get_shard(2, 0)?.is_some()); // app2 should still exist

    Ok(())
}

#[test]
fn test_p2p_store_persistence() -> Result<()> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("persistence_test_db");

    // Create store and add data
    {
        let store = DataStore::new(db_path.to_str().unwrap())?;
        store.add_shard(1, 0, "persistent_data".to_string())?;
        store.add_app_peer_ids(1, vec!["peer1".to_string()])?;
    } // Store is dropped here

    // Reopen store and verify data persists
    let store = DataStore::new(db_path.to_str().unwrap())?;
    assert_eq!(store.get_shard(1, 0)?.unwrap(), "persistent_data");
    assert_eq!(store.get_app_peer_ids(1)?.unwrap(), vec!["peer1"]);

    Ok(())
}
