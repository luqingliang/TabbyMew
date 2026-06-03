use anyhow::{Result, anyhow};
use tokio::task::JoinError;
use tracing::{info, warn};

use crate::{net::egress, platform};

use super::{ProxyRuntimeInner, TASK_CANCELLED};

pub(super) async fn reap_finished(inner: &mut ProxyRuntimeInner) {
    let mut stopped = false;
    while let Some(result) = inner.tasks.try_join_next() {
        stopped = true;
        let message = task_result_message(result);
        warn!(error = %message, "proxy listener stopped");
        if message != TASK_CANCELLED {
            inner.last_error = Some(message);
        }
    }
    if stopped {
        inner.enabled = false;
        inner.last_warnings = Vec::new();
        abort_and_drain(inner).await;
        clear_tun_egress_binding(inner);
    }
}

pub(super) async fn abort_and_drain(inner: &mut ProxyRuntimeInner) {
    inner.tasks.abort_all();
    while inner.tasks.join_next().await.is_some() {}
}

pub(super) fn prepare_tun_egress_binding(inner: &mut ProxyRuntimeInner) -> Result<()> {
    if !egress::interface_binding_supported() {
        inner.tun_egress_interface = None;
        inner
            .last_warnings
            .push(platform::TUN_EGRESS_BINDING_UNSUPPORTED_WARNING.to_string());
        return Ok(());
    }

    let interface = match egress::default_interface_name() {
        Ok(interface) => interface,
        Err(err) => {
            let detail =
                format!("failed to capture current network interface before starting TUN: {err}");
            inner.last_error = Some(detail.clone());
            return Err(anyhow!(detail));
        }
    };

    if let Err(err) = egress::set_bound_interface(Some(&interface)) {
        let detail = format!("failed to bind outbound egress to pre-TUN interface: {err}");
        inner.last_error = Some(detail.clone());
        return Err(anyhow!(detail));
    }

    info!(interface = %interface, "bound outbound egress to pre-TUN interface");
    inner.tun_egress_interface = Some(interface);
    Ok(())
}

pub(super) fn task_result_message(result: Result<Result<()>, JoinError>) -> String {
    match result {
        Ok(Ok(())) => "proxy listener stopped unexpectedly".to_string(),
        Ok(Err(err)) => format!("{err:#}"),
        Err(err) if err.is_cancelled() => TASK_CANCELLED.to_string(),
        Err(err) => format!("proxy listener task failed: {err}"),
    }
}

pub(super) fn clear_tun_egress_binding(inner: &mut ProxyRuntimeInner) {
    if let Some(interface) = inner.tun_egress_interface.as_deref() {
        match egress::set_bound_interface(None) {
            Ok(()) => {
                info!(interface, "cleared TUN egress interface binding");
                inner.tun_egress_interface = None;
            }
            Err(err) => {
                warn!(
                    interface,
                    error = %err,
                    "failed to clear TUN egress interface binding"
                );
            }
        }
    }
}
