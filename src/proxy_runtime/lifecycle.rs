use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::time::{sleep, timeout};
use tokio::{sync::Mutex, task::JoinSet};
use tracing::{debug, info, warn};

use crate::{
    config::{InboundConfig, OutboundConfig},
    inbound::{self, tun},
    platform, resource_limits,
    router::Router,
};

use super::{
    ProxyRuntime, ProxyRuntimeInner, ProxyRuntimeSnapshot, TunRuntimeStatus,
    tasks::{
        abort_and_drain, clear_tun_egress_binding, prepare_tun_egress_binding, reap_finished,
        task_result_message,
    },
    tun_bypass::{tun_bypass_entry_count, tun_bypass_sources_from_outbounds},
};

impl ProxyRuntime {
    #[cfg(test)]
    pub fn new(inbounds: Vec<InboundConfig>, router: Router) -> Self {
        Self::new_with_outbounds(inbounds, router, &[])
    }

    pub fn new_with_outbounds(
        inbounds: Vec<InboundConfig>,
        router: Router,
        outbounds: &[OutboundConfig],
    ) -> Self {
        let (tun_inbounds, inbounds) = inbounds
            .into_iter()
            .partition(|inbound| matches!(inbound, InboundConfig::Tun { .. }));
        Self {
            inbounds,
            tun_inbounds,
            tun_bypass_sources: tun_bypass_sources_from_outbounds(outbounds),
            router,
            inner: Mutex::new(ProxyRuntimeInner {
                desired_enabled: false,
                enabled: false,
                last_error: None,
                last_warnings: Vec::new(),
                tasks: JoinSet::new(),
                tun_egress_interface: None,
                watchdog_restarts: 0,
                last_watchdog_reason: None,
            }),
            tun_inner: Mutex::new(ProxyRuntimeInner {
                desired_enabled: false,
                enabled: false,
                last_error: None,
                last_warnings: Vec::new(),
                tasks: JoinSet::new(),
                tun_egress_interface: None,
                watchdog_restarts: 0,
                last_watchdog_reason: None,
            }),
            tun_operation: Mutex::new(()),
            lan_enabled: Mutex::new(false),
        }
    }

    pub async fn set_lan_enabled(&self, enabled: bool) -> Result<ProxyRuntimeSnapshot> {
        let old_lan_enabled = *self.lan_enabled.lock().await;
        if old_lan_enabled == enabled {
            return Ok(self.snapshot().await);
        }
        let was_enabled = {
            let mut inner = self.inner.lock().await;
            reap_finished(&mut inner).await;
            inner.enabled
        };
        if was_enabled {
            self.stop_regular().await?;
        }
        {
            let mut lan_enabled = self.lan_enabled.lock().await;
            *lan_enabled = enabled;
        }
        if was_enabled && let Err(err) = self.start_regular().await {
            {
                let mut lan_enabled = self.lan_enabled.lock().await;
                *lan_enabled = old_lan_enabled;
            }
            if let Err(restore_err) = self.start_regular().await {
                warn!(error = %restore_err, "failed to restore previous proxy listeners after LAN switch failure");
            }
            return Err(err);
        }
        Ok(self.snapshot().await)
    }

    pub async fn start(&self) -> Result<ProxyRuntimeSnapshot> {
        self.start_regular().await
    }

    #[cfg(test)]
    pub async fn start_all(&self) -> Result<ProxyRuntimeSnapshot> {
        if self.inbounds.is_empty() && self.tun_inbounds.is_empty() {
            bail!("no proxy inbounds are configured");
        }
        let before = self.snapshot().await;
        if !self.inbounds.is_empty() {
            self.start_regular().await?;
        }
        if !self.tun_inbounds.is_empty()
            && let Err(err) = {
                let _tun_operation = self.tun_operation.lock().await;
                self.start_tun_locked().await
            }
        {
            if !before.enabled {
                let _ = self.stop_regular().await;
            }
            return Err(err);
        }
        Ok(self.snapshot().await)
    }

    pub async fn stop_all(&self) -> Result<ProxyRuntimeSnapshot> {
        self.stop_regular().await?;
        let _tun_operation = self.tun_operation.lock().await;
        self.stop_tun_locked().await
    }

    pub async fn set_tun_enabled(&self, enabled: bool) -> Result<ProxyRuntimeSnapshot> {
        let _tun_operation = self.tun_operation.lock().await;
        if enabled {
            self.start_tun_locked().await
        } else {
            self.stop_tun_locked().await
        }
    }

    pub async fn restart_tun_for_recovery(
        &self,
        reason: impl Into<String>,
    ) -> Result<ProxyRuntimeSnapshot> {
        let reason = reason.into();
        let _tun_operation = self.tun_operation.lock().await;
        let before = self.snapshot().await;
        if !(before.tun_enabled || before.tun_desired_enabled) {
            return Ok(before);
        }
        info!(
            reason = %reason,
            desired_enabled = before.tun_desired_enabled,
            enabled = before.tun_enabled,
            status = ?before.tun_status,
            egress_interface = before.tun_egress_interface.as_deref().unwrap_or("-"),
            bound_interface = before.tun_bound_interface.as_deref().unwrap_or("-"),
            "restarting TUN for runtime recovery"
        );

        if before.tun_enabled {
            self.stop_tun_locked().await?;
            sleep(Duration::from_millis(500)).await;
        }

        match self.start_tun_locked().await {
            Ok(_) => {
                {
                    let mut inner = self.tun_inner.lock().await;
                    inner.watchdog_restarts = inner.watchdog_restarts.saturating_add(1);
                    inner.last_watchdog_reason = Some(reason.clone());
                }
                let snapshot = self.snapshot().await;
                info!(
                    reason = %reason,
                    status = ?snapshot.tun_status,
                    egress_interface = snapshot.tun_egress_interface.as_deref().unwrap_or("-"),
                    bound_interface = snapshot.tun_bound_interface.as_deref().unwrap_or("-"),
                    "TUN runtime recovery completed"
                );
                Ok(snapshot)
            }
            Err(err) => {
                let fd_snapshot = resource_limits::nofile_limit_snapshot().ok();
                {
                    let mut inner = self.tun_inner.lock().await;
                    inner.desired_enabled = true;
                    inner.watchdog_restarts = inner.watchdog_restarts.saturating_add(1);
                    inner.last_watchdog_reason = Some(reason.clone());
                    inner.last_error = Some(format!("TUN recovery failed after {reason}: {err:#}"));
                }
                warn!(
                    reason = %reason,
                    error = %err,
                    fd_soft_limit = fd_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.soft.as_str())
                        .unwrap_or("-"),
                    fd_hard_limit = fd_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.hard.as_str())
                        .unwrap_or("-"),
                    fd_open_count = ?fd_snapshot.as_ref().and_then(|snapshot| snapshot.open_files),
                    "TUN runtime recovery failed"
                );
                Err(err)
            }
        }
    }

    async fn start_regular(&self) -> Result<ProxyRuntimeSnapshot> {
        {
            let mut inner = self.inner.lock().await;
            reap_finished(&mut inner).await;
            if inner.enabled {
                drop(inner);
                return Ok(self.snapshot().await);
            }
            if self.inbounds.is_empty() {
                bail!("no proxy inbounds are configured");
            }

            inner.last_error = None;
            let lan_enabled = *self.lan_enabled.lock().await;
            for inbound_config in self.regular_inbounds(lan_enabled) {
                let router = self.router.clone();
                inner
                    .tasks
                    .spawn(async move { inbound::serve(inbound_config, router).await });
            }

            match timeout(Duration::from_millis(100), inner.tasks.join_next()).await {
                Ok(Some(result)) => {
                    let error = task_result_message(result);
                    abort_and_drain(&mut inner).await;
                    inner.enabled = false;
                    inner.last_error = Some(error.clone());
                    return Err(anyhow!("failed to start proxy listeners: {error}"));
                }
                Ok(None) => {
                    inner.enabled = false;
                    inner.last_error = Some("no proxy listener task was started".to_string());
                    return Err(anyhow!("no proxy listener task was started"));
                }
                Err(_) => {
                    inner.enabled = true;
                    debug!(
                        inbounds = self.inbounds.len(),
                        lan_enabled, "proxy listeners started"
                    );
                }
            }
        }
        Ok(self.snapshot().await)
    }

    async fn stop_regular(&self) -> Result<ProxyRuntimeSnapshot> {
        {
            let mut inner = self.inner.lock().await;
            reap_finished(&mut inner).await;
            if !inner.enabled && inner.tasks.is_empty() {
                inner.last_error = None;
                drop(inner);
                return Ok(self.snapshot().await);
            }
            abort_and_drain(&mut inner).await;
            inner.enabled = false;
            inner.last_error = None;
            debug!("proxy listeners stopped");
        }
        Ok(self.snapshot().await)
    }

    async fn start_tun_locked(&self) -> Result<ProxyRuntimeSnapshot> {
        {
            let mut inner = self.tun_inner.lock().await;
            reap_finished(&mut inner).await;
            if inner.enabled {
                inner.desired_enabled = true;
                drop(inner);
                return Ok(self.snapshot().await);
            }
            if self.tun_inbounds.is_empty() {
                bail!("no TUN inbounds are configured");
            }

            inner.last_error = None;
            inner.last_warnings = Vec::new();
            let preflight = self.tun_preflight(&inner);
            match preflight.status {
                TunRuntimeStatus::Stopped => {}
                TunRuntimeStatus::RequiresPermission if tun::can_start_with_privileged_helper() => {
                }
                TunRuntimeStatus::RequiresPermission
                | TunRuntimeStatus::Unsupported
                | TunRuntimeStatus::RequiresConfiguration => {
                    return Err(anyhow!(preflight.detail));
                }
                TunRuntimeStatus::Failed
                | TunRuntimeStatus::NotConfigured
                | TunRuntimeStatus::Running => {
                    return Err(anyhow!(preflight.detail));
                }
            }

            let (tun_inbounds, warnings) = match self.prepare_tun_inbounds().await {
                Ok(result) => result,
                Err(err) => {
                    inner.last_error = Some(format!("{err:#}"));
                    return Err(err);
                }
            };
            inner.last_warnings = warnings;
            if self.auto_route_enabled() {
                prepare_tun_egress_binding(&mut inner)?;
            }
            let tun_config = self.tun_config_summary();
            let effective_bypass_count = tun_bypass_entry_count(&tun_inbounds);
            let fd_snapshot = resource_limits::nofile_limit_snapshot().ok();
            info!(
                inbounds = self.tun_inbounds.len(),
                auto_route = tun_config.auto_route,
                ipv6_enabled = tun_config.ipv6_enabled,
                dns = tun_config.dns_mode.as_deref().unwrap_or("-"),
                dns_addr = tun_config.dns_addr.as_deref().unwrap_or("-"),
                configured_bypass_count = tun_config.configured_bypass_count,
                effective_bypass_count,
                proxy_bypass_sources = self.tun_bypass_sources.len(),
                warning_count = inner.last_warnings.len(),
                fd_soft_limit = fd_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.soft.as_str())
                    .unwrap_or("-"),
                fd_hard_limit = fd_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.hard.as_str())
                    .unwrap_or("-"),
                fd_open_count = ?fd_snapshot.as_ref().and_then(|snapshot| snapshot.open_files),
                "starting TUN listeners"
            );
            for warning in &inner.last_warnings {
                warn!(warning = %warning, "TUN startup warning");
            }
            for inbound_config in tun_inbounds {
                let router = self.router.clone();
                inner
                    .tasks
                    .spawn(async move { inbound::serve(inbound_config, router).await });
            }

            match timeout(Duration::from_millis(100), inner.tasks.join_next()).await {
                Ok(Some(result)) => {
                    let error = task_result_message(result);
                    abort_and_drain(&mut inner).await;
                    clear_tun_egress_binding(&mut inner);
                    inner.enabled = false;
                    inner.last_error = Some(error.clone());
                    return Err(anyhow!("failed to start TUN listeners: {error}"));
                }
                Ok(None) => {
                    inner.enabled = false;
                    inner.last_error = Some("no TUN listener task was started".to_string());
                    inner.last_warnings = Vec::new();
                    clear_tun_egress_binding(&mut inner);
                    return Err(anyhow!("no TUN listener task was started"));
                }
                Err(_) => {
                    inner.enabled = true;
                    inner.desired_enabled = true;
                    info!(inbounds = self.tun_inbounds.len(), "TUN listeners started");
                }
            }
        }
        refresh_tun_dns_state_after_transition(&self.router, "TUN start").await;
        Ok(self.snapshot().await)
    }

    async fn stop_tun_locked(&self) -> Result<ProxyRuntimeSnapshot> {
        {
            let mut inner = self.tun_inner.lock().await;
            reap_finished(&mut inner).await;
            if !inner.enabled && inner.tasks.is_empty() {
                inner.desired_enabled = false;
                clear_tun_egress_binding(&mut inner);
                inner.last_error = None;
                inner.last_warnings = Vec::new();
                drop(inner);
                return Ok(self.snapshot().await);
            }
            abort_and_drain(&mut inner).await;
            clear_tun_egress_binding(&mut inner);
            inner.enabled = false;
            inner.desired_enabled = false;
            inner.last_error = None;
            inner.last_warnings = Vec::new();
            let fd_snapshot = resource_limits::nofile_limit_snapshot().ok();
            debug!(
                fd_soft_limit = fd_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.soft.as_str())
                    .unwrap_or("-"),
                fd_hard_limit = fd_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.hard.as_str())
                    .unwrap_or("-"),
                fd_open_count = ?fd_snapshot.as_ref().and_then(|snapshot| snapshot.open_files),
                "TUN listeners stopped"
            );
        }
        refresh_tun_dns_state_after_transition(&self.router, "TUN stop").await;
        Ok(self.snapshot().await)
    }
}

async fn refresh_tun_dns_state_after_transition(router: &Router, context: &'static str) {
    match router.clear_dns_cache().await {
        Some(removed) => info!(
            context,
            removed_entries = removed,
            "cleared resolver DNS cache for TUN transition"
        ),
        None => debug!(
            context,
            "no configured resolver DNS cache to clear for TUN transition"
        ),
    }
    flush_system_dns_cache_after_tun_transition(context).await;
}

async fn flush_system_dns_cache_after_tun_transition(context: &'static str) {
    match tun::flush_system_dns_cache_with_privileged_helper().await {
        Ok(true) => {
            info!(
                context,
                method = "privileged_helper",
                "system DNS cache flushed for TUN transition"
            );
            return;
        }
        Ok(false) => {}
        Err(err) => warn!(
            context,
            error = %err,
            "failed to flush system DNS cache through privileged TUN helper"
        ),
    }

    match platform::flush_system_dns_cache().await {
        Ok(true) => info!(
            context,
            method = "direct",
            "system DNS cache flushed for TUN transition"
        ),
        Ok(false) => debug!(
            context,
            "system DNS cache flush is unsupported for TUN transition"
        ),
        Err(err) => warn!(
            context,
            error = %err,
            "failed to flush system DNS cache for TUN transition"
        ),
    }
}
