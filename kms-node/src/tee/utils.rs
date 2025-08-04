use sha2::{Digest, Sha384};

use crate::tee::types::DstackMRData;

pub const INIT_MR: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

pub fn read_mr_values_from_env() -> anyhow::Result<DstackMRData> {
    let mrtd = std::env::var("EXPECTED_MR_VALUE_MRTD")?;
    let rtmr0 = std::env::var("EXPECTED_MR_VALUE_RTMR0")?;
    let rtmr1 = std::env::var("EXPECTED_MR_VALUE_RTMR1")?;
    let rtmr2 = std::env::var("EXPECTED_MR_VALUE_RTMR2")?;
    let data = DstackMRData {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
    };
    Ok(data)
}

pub fn read_app_compose_hash_from_env() -> anyhow::Result<String> {
    let app_compose_hash = std::env::var("APP_COMPOSE_HASH")?;
    Ok(app_compose_hash)
}

pub fn replay_rtmr(history: Vec<String>) -> anyhow::Result<String> {
    if history.is_empty() {
        return Ok(INIT_MR.to_string());
    }
    let mut mr = hex::decode(INIT_MR)?;
    for content in history {
        let mut content = hex::decode(content)?;
        if content.len() < 48 {
            content = right_pad_to_48(content);
        }
        let mut hasher = Sha384::new();
        hasher.update(&mr);
        hasher.update(&content);
        mr = hasher.finalize().to_vec();
    }
    Ok(hex::encode(mr))
}

pub fn convert_u8_48_to_string(mr: Vec<u8>) -> String {
    let mut mr = mr.clone();
    mr.resize(48, 0u8);
    hex::encode(mr)
}

fn right_pad_to_48(mut content: Vec<u8>) -> Vec<u8> {
    content.resize(48, 0u8);
    content
}
