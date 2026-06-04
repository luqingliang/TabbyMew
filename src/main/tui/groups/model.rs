use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuiPolicyGroupDelayResult {
    pub(crate) outbound: String,
    pub(crate) resolved_outbound: Option<String>,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) status_code: Option<u16>,
    pub(crate) error: Option<String>,
}

pub(crate) struct TuiPolicyGroupDelayRun {
    pub(crate) id: u64,
    pub(crate) group: String,
    pub(crate) total: usize,
    pub(crate) completed: usize,
    pub(crate) tasks: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
pub(crate) struct TuiPolicyGroupDelayUpdate {
    pub(crate) run_id: u64,
    pub(crate) group: String,
    pub(crate) result: TuiPolicyGroupDelayResult,
}
