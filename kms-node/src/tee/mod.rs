use dstack_sdk::tappd_client::TdxQuoteResponse;
pub mod quote;
pub mod types;
pub mod utils;

pub async fn verify_attestation(
    quote: String,
    event_log: String,
    pccs_url: Option<String>,
    expected_mr_data: types::DstackMRData,
    app_compose_hash: String,
) -> anyhow::Result<()> {
    let mut quote = quote::DstackTdxQuote::new(quote, event_log, pccs_url)?;
    quote.extract_info_from_event_log();
    quote.verify().await?;

    let verified_mrs = quote.mrs();
    if verified_mrs.is_none() {
        return Err(anyhow::anyhow!("failed to get verified mrs"));
    }

    let verified_mr = match verified_mrs {
        Some(dcap_qvl::quote::Report::TD15(report)) => (
            report.base.mr_td,
            report.base.rt_mr0,
            report.base.rt_mr1,
            report.base.rt_mr2,
            report.base.rt_mr3,
        ),
        Some(dcap_qvl::quote::Report::TD10(report)) => (
            report.mr_td,
            report.rt_mr0,
            report.rt_mr1,
            report.rt_mr2,
            report.rt_mr3,
        ),
        Some(_) => {
            return Err(anyhow::anyhow!("unsupported report type"));
        }
        None => {
            return Err(anyhow::anyhow!("no verified report available"));
        }
    };

    assert_eq!(
        utils::convert_u8_48_to_string(verified_mr.0.to_vec()),
        expected_mr_data.mrtd
    );
    assert_eq!(
        utils::convert_u8_48_to_string(verified_mr.1.to_vec()),
        expected_mr_data.rtmr0
    );
    assert_eq!(
        utils::convert_u8_48_to_string(verified_mr.2.to_vec()),
        expected_mr_data.rtmr1
    );
    assert_eq!(
        utils::convert_u8_48_to_string(verified_mr.3.to_vec()),
        expected_mr_data.rtmr2
    );

    let replayed_mrs = quote.replay_rtmrs().await?;
    assert_eq!(
        utils::convert_u8_48_to_string(verified_mr.4.to_vec()),
        replayed_mrs[3]
    );

    let app_compose_hash_from_quote = quote.app_compose_hash();
    assert_eq!(app_compose_hash_from_quote, Some(app_compose_hash));
    Ok(())
}

pub async fn verify_attestation_from_quote(quote: TdxQuoteResponse) -> anyhow::Result<()> {
    #[cfg(any(feature = "local-quote-verification", test))]
    {
        return Ok(());
    }
    #[cfg(not(test))]
    {
        use crate::tee::quote::PCCS_URL;
        let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PCCS_URL.to_string());
        let expected_mr_data = types::DstackMRData {
            mrtd: std::env::var("EXPECTED_MR_VALUE_MRTD")
                .map_err(|e| anyhow::anyhow!("Failed to get EXPECTED_MR_VALUE_MRTD: {}", e))?,
            rtmr0: std::env::var("EXPECTED_MR_VALUE_RTMR0")
                .map_err(|e| anyhow::anyhow!("Failed to get EXPECTED_MR_VALUE_RTMR0: {}", e))?,
            rtmr1: std::env::var("EXPECTED_MR_VALUE_RTMR1")
                .map_err(|e| anyhow::anyhow!("Failed to get EXPECTED_MR_VALUE_RTMR1: {}", e))?,
            rtmr2: std::env::var("EXPECTED_MR_VALUE_RTMR2")
                .map_err(|e| anyhow::anyhow!("Failed to get EXPECTED_MR_VALUE_RTMR2: {}", e))?,
        };
        let app_compose_hash = std::env::var("APP_COMPOSE_HASH")
            .map_err(|e| anyhow::anyhow!("Failed to get APP_COMPOSE_HASH: {}", e))?;
        verify_attestation(
            quote.quote,
            quote.event_log,
            Some(pccs_url),
            expected_mr_data,
            app_compose_hash,
        )
        .await?;
        Ok(())
    }
}
