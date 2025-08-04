use std::fs;

use rstest::rstest;

use crate::tee::{
    types::{RawReport, convert_raw_report_to_report},
    utils::{read_app_compose_hash_from_env, read_mr_values_from_env},
    verify_attestation,
};

#[rstest]
fn test_read_report() -> anyhow::Result<()> {
    let report = fs::read_to_string("src/tests/assets/report.json")?;
    let report = serde_json::from_str::<RawReport>(&report)?;
    let report = convert_raw_report_to_report(report);
    println!("{:?}", report);
    assert!(!report.unwrap().event_log.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_verify_attestation() -> anyhow::Result<()> {
    unsafe {
        std::env::set_var(
            "EXPECTED_MR_VALUE_MRTD",
            "c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd",
        );
        std::env::set_var(
            "EXPECTED_MR_VALUE_RTMR0",
            "85e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb6547",
        );
        std::env::set_var(
            "EXPECTED_MR_VALUE_RTMR1",
            "154e08f5c1f7b1fce4cbfe1c14f3ba67b70044ede2751487279cd1f2e4239dee99a6d45e24ebde6b6a6f5ae49878e0e6",
        );
        std::env::set_var(
            "EXPECTED_MR_VALUE_RTMR2",
            "9edcd363660e85b71c318324996dda756c372d9f6960edbfa863b1e684822eb48dd95e218ae2b78e51ef97f3b8f5c9dc",
        );
        std::env::set_var(
            "APP_COMPOSE_HASH",
            "49b5d28fc6ff20ad7907c4fa981a722b712f72a4695c483f13ad03857e749674",
        );
    }

    let quote = fs::read("src/tests/assets/dstack_quote_1.bin")?;
    let event_log = fs::read_to_string("src/tests/assets/dstack_quote_event_log.json")?;
    let expected_mr_data = read_mr_values_from_env()?;
    let app_compose_hash = read_app_compose_hash_from_env()?;
    verify_attestation(
        hex::encode(quote.clone()),
        event_log.clone(),
        Some("https://api.trustedservices.intel.com/tdx/certification/v4".to_string()),
        expected_mr_data,
        app_compose_hash.to_string(),
    )
    .await?;
    Ok(())
}
