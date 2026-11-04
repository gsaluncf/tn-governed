use serde::Serialize;

use crate::error::{AdmissionStage, TnLlamaError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientTraceEvent {
    pub ordinal: u64,
    pub event: String,
    pub state: String,
    pub task_id: Option<i64>,
    pub slot_id: Option<i32>,
    pub row_hash: Option<String>,
    pub selected_sections: Vec<String>,
    pub tool_name: Option<String>,
    pub event_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionOutcome {
    Continue,
    GovernedRelease(GovernedReportRelease),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedReportRelease {
    pub protocol: &'static str,
    pub run_id: String,
    pub source_object_id: String,
    pub output_object_id: String,
    pub output_object: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_objects: Vec<String>,
    pub trace: Vec<ClientTraceEvent>,
}
impl GovernedReportRelease {
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, TnLlamaError> {
        serde_json::to_vec(self).map_err(|_| {
            TnLlamaError::new(
                "tn_release_encode_failed",
                AdmissionStage::Session,
                "closed governed report release could not be serialized",
            )
        })
    }
}
