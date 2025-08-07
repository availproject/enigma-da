use crate::tee::{types::EventLog, utils::replay_rtmr};
use dcap_qvl::{collateral::get_collateral, verify::VerifiedReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub const PCCS_URL: &str = "https://pccs.phala.network/sgx/certification/v4/";
const MR_VALUES: usize = 4;

#[derive(Serialize, Deserialize)]
pub struct DstackTdxQuote {
    quote: String,
    event_log: String,
    verified_quote: Option<VerifiedReport>,
    parsed_event_log: Vec<EventLog>,
    app_id: Option<String>,
    compose_hash: Option<String>,
    instance_id: Option<String>,
    key_provider: Option<String>,
    pccs_url: String,
}

impl DstackTdxQuote {
    pub fn new(quote: String, event_log: String, pccs_url: Option<String>) -> anyhow::Result<Self> {
        let parsed_event_log = serde_json::from_str::<Vec<EventLog>>(&event_log)
            .map_err(|e| anyhow::anyhow!("Failed to parse event log: {}", e))?;
        Ok(Self {
            quote,
            event_log,
            verified_quote: None,
            parsed_event_log,
            app_id: None,
            compose_hash: None,
            instance_id: None,
            key_provider: None,
            pccs_url: pccs_url.unwrap_or(PCCS_URL.to_string()),
        })
    }

    pub fn extract_info_from_event_log(&mut self) {
        for event in &self.parsed_event_log {
            if event.event == "app-id" {
                self.app_id = Some(event.event_payload.clone());
            } else if event.event == "compose-hash" {
                self.compose_hash = Some(event.event_payload.clone());
            } else if event.event == "instance-id" {
                self.instance_id = Some(event.event_payload.clone());
            } else if event.event == "key-provider" {
                self.key_provider = Some(event.event_payload.clone());
            }
        }
    }

    pub fn mrs(&self) -> Option<dcap_qvl::quote::Report> {
        let verified_quote = self.verified_quote.as_ref()?;
        match &verified_quote.report {
            dcap_qvl::quote::Report::TD10(report) => {
                Some(dcap_qvl::quote::Report::TD10(report.clone()))
            }
            dcap_qvl::quote::Report::TD15(report) => {
                Some(dcap_qvl::quote::Report::TD15(report.clone()))
            }
            dcap_qvl::quote::Report::SgxEnclave(report) => {
                Some(dcap_qvl::quote::Report::SgxEnclave(report.clone()))
            }
        }
    }

    pub async fn verify(&mut self) -> anyhow::Result<()> {
        let quote_bytes = hex::decode(&self.quote)?;
        let collateral = get_collateral(
            &self.pccs_url,
            &quote_bytes,
            std::time::Duration::from_secs(10),
        )
        .await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Failed to get system time: {}", e))?
            .as_secs();
        let verified_quote = dcap_qvl::verify::verify(&quote_bytes, &collateral, now)
            .map_err(|e| anyhow::anyhow!("failed to verify quote: {:?}", e))?;
        self.verified_quote = Some(verified_quote);
        Ok(())
    }

    pub async fn validate_event(&self, event: EventLog) -> anyhow::Result<bool> {
        if event.imr != 3 {
            return Ok(true);
        }

        let event_type = event.event_type;
        let event_name = event.event;
        let event_payload = hex::decode(event.event_payload)
            .map_err(|e| anyhow::anyhow!("failed to decode event payload: {:?}", e))?;

        let mut hasher = Sha384::new();
        hasher.update(event_type.to_le_bytes());
        hasher.update(b":");
        hasher.update(event_name.as_bytes());
        hasher.update(b":");
        hasher.update(event_payload);
        let result = hasher.finalize().to_vec();
        let expected_digest = hex::decode(event.digest)
            .map_err(|e| anyhow::anyhow!("failed to decode digest: {:?}", e))?;
        Ok(result == expected_digest)
    }

    pub async fn replay_rtmrs(&self) -> anyhow::Result<Vec<String>> {
        let mut rtmrs = Vec::new();
        for index in 0..MR_VALUES {
            let mut history = Vec::new();
            for event in &self.parsed_event_log {
                if event.imr == index as u32 && self.validate_event(event.clone()).await? {
                    history.push(event.digest.clone());
                }
            }
            rtmrs.insert(index, replay_rtmr(history)?);
        }
        Ok(rtmrs)
    }

    pub fn app_compose_hash(&self) -> Option<String> {
        self.compose_hash.clone()
    }
}
