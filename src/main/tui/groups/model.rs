use super::*;

#[derive(Debug, Clone)]
pub(super) struct TuiPolicyGroup {
    pub(super) tag: String,
    pub(super) kind: String,
    pub(super) outbounds: Vec<String>,
    pub(super) selected: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TuiPolicyGroupDelayResult {
    pub(super) outbound: String,
    pub(super) resolved_outbound: Option<String>,
    pub(super) latency_ms: Option<u64>,
    pub(super) status_code: Option<u16>,
    pub(super) error: Option<String>,
}

pub(super) struct TuiPolicyGroupDelayRun {
    pub(super) id: u64,
    pub(super) group: String,
    pub(super) total: usize,
    pub(super) completed: usize,
    pub(super) tasks: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
pub(super) struct TuiPolicyGroupDelayUpdate {
    pub(super) run_id: u64,
    pub(super) group: String,
    pub(super) result: TuiPolicyGroupDelayResult,
}

#[derive(Debug, Clone)]
pub(super) struct TuiPolicyGroupSelection {
    pub(super) group: TuiPolicyGroup,
    pub(super) outbound: Option<String>,
}
