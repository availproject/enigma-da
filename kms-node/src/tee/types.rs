use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Report {
    pub quote: String,
    pub event_log: Vec<EventLog>,
    pub hash_algorithm: String,
    pub prefix: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EventLog {
    pub imr: u32,
    pub event_type: u32,
    pub digest: String,
    pub event: String,
    pub event_payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DstackMRData {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
}

#[derive(Deserialize, Debug)]
pub struct RawReport {
    pub quote: String,
    pub event_log: String,
    pub hash_algorithm: String,
    pub prefix: String,
}

pub fn convert_raw_report_to_report(raw_report: RawReport) -> anyhow::Result<Report> {
    Ok(Report {
        quote: raw_report.quote,
        event_log: serde_json::from_str::<Vec<EventLog>>(&raw_report.event_log)
            .map_err(|e| anyhow::anyhow!("Failed to parse event log: {}", e))?,
        hash_algorithm: raw_report.hash_algorithm,
        prefix: raw_report.prefix,
    })
}
