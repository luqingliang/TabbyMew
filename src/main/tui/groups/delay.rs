use super::*;

pub(crate) fn tui_policy_group_delay_table_title(app: &TuiApp, group: &str) -> String {
    if let Some(run) = &app.policy_group_delay_run
        && run.group == group
    {
        return format!(" Outbounds (delay {}/{}) ", run.completed, run.total);
    }
    if app.policy_group_delay_group.as_deref() == Some(group) {
        format!(
            " Outbounds (delay {}) ",
            app.policy_group_delay_results.len()
        )
    } else {
        " Outbounds ".to_string()
    }
}

pub(crate) fn tui_policy_group_delay_results(response: &Value) -> Vec<TuiPolicyGroupDelayResult> {
    value_array(response, &["results"])
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let outbound = value_str(item, &["outbound"])?.to_string();
                    Some(TuiPolicyGroupDelayResult {
                        outbound,
                        resolved_outbound: value_str(item, &["resolved_outbound"])
                            .map(str::to_string),
                        latency_ms: value_u64(item, &["latency_ms"]),
                        status_code: value_u64(item, &["status_code"])
                            .and_then(|value| u16::try_from(value).ok()),
                        error: value_str(item, &["error"]).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn first_tui_policy_group_delay_result(
    response: &Value,
    outbound: &str,
) -> TuiPolicyGroupDelayResult {
    tui_policy_group_delay_results(response)
        .into_iter()
        .next()
        .unwrap_or_else(|| failed_tui_policy_group_delay_result(outbound, "delay result missing"))
}

pub(crate) fn failed_tui_policy_group_delay_result(
    outbound: &str,
    error: impl Into<String>,
) -> TuiPolicyGroupDelayResult {
    TuiPolicyGroupDelayResult {
        outbound: outbound.to_string(),
        resolved_outbound: None,
        latency_ms: None,
        status_code: None,
        error: Some(error.into()),
    }
}

pub(crate) fn tui_policy_group_delay_for<'a>(
    app: &'a TuiApp,
    group: &str,
    outbound: &str,
) -> Option<&'a TuiPolicyGroupDelayResult> {
    if app.policy_group_delay_group.as_deref() != Some(group) {
        return None;
    }
    app.policy_group_delay_results
        .iter()
        .find(|result| result.outbound == outbound)
}

pub(crate) fn format_tui_policy_group_delay(result: Option<&TuiPolicyGroupDelayResult>) -> String {
    match result {
        Some(result) => {
            if let Some(latency_ms) = result.latency_ms {
                format!("{latency_ms} ms")
            } else if result
                .error
                .as_deref()
                .is_some_and(|error| error.eq_ignore_ascii_case("timeout"))
            {
                "timeout".to_string()
            } else if result.error.is_some() {
                "failed".to_string()
            } else {
                "-".to_string()
            }
        }
        None => "-".to_string(),
    }
}

pub(crate) fn tui_policy_group_delay_cell(
    result: Option<&TuiPolicyGroupDelayResult>,
) -> Cell<'static> {
    let cell = Cell::from(format_tui_policy_group_delay(result));
    match tui_policy_group_delay_color(result) {
        Some(color) => cell.style(Style::default().fg(color)),
        None => cell,
    }
}

pub(crate) fn tui_policy_group_delay_color(
    result: Option<&TuiPolicyGroupDelayResult>,
) -> Option<Color> {
    let result = result?;
    match result.latency_ms {
        Some(latency_ms) if latency_ms <= 300 => Some(Color::Green),
        Some(latency_ms) if latency_ms <= 500 => Some(Color::Yellow),
        Some(latency_ms) if latency_ms <= 1_000 => Some(Color::Rgb(255, 165, 0)),
        Some(_) => Some(Color::Red),
        None => Some(Color::Red),
    }
}

pub(crate) fn upsert_tui_policy_group_delay_result(
    results: &mut Vec<TuiPolicyGroupDelayResult>,
    result: TuiPolicyGroupDelayResult,
) {
    if let Some(existing) = results
        .iter_mut()
        .find(|existing| existing.outbound == result.outbound)
    {
        *existing = result;
    } else {
        results.push(result);
    }
}

pub(crate) fn drain_tui_policy_group_delay_updates(app: &mut TuiApp) -> bool {
    let Some(receiver) = app.policy_group_delay_updates.as_mut() else {
        return false;
    };

    let mut updates = Vec::new();
    let mut disconnected = false;
    loop {
        match receiver.try_recv() {
            Ok(update) => updates.push(update),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }

    let mut changed = false;
    for update in updates {
        changed |= apply_tui_policy_group_delay_update(app, update);
    }

    let completed = app
        .policy_group_delay_run
        .as_ref()
        .is_some_and(|run| run.completed >= run.total);
    if completed {
        if let Some(run) = &app.policy_group_delay_run {
            app.last_message = format!(
                "tested {} outbounds for policy group {}",
                run.completed, run.group
            );
        }
        app.policy_group_delay_run = None;
        app.policy_group_delay_updates = None;
        changed = true;
    } else if disconnected {
        if let Some(run) = &app.policy_group_delay_run {
            app.last_message = format!(
                "policy group delay stopped for {} after {}/{}",
                run.group, run.completed, run.total
            );
        }
        app.policy_group_delay_run = None;
        app.policy_group_delay_updates = None;
        changed = true;
    }

    changed
}

pub(crate) fn cancel_tui_policy_group_delay(app: &mut TuiApp) -> bool {
    let mut cancelled = false;
    if let Some(run) = app.policy_group_delay_run.take() {
        for task in run.tasks {
            task.abort();
        }
        cancelled = true;
    }
    if app.policy_group_delay_updates.take().is_some() {
        cancelled = true;
    }
    cancelled
}

pub(crate) fn apply_tui_policy_group_delay_update(
    app: &mut TuiApp,
    update: TuiPolicyGroupDelayUpdate,
) -> bool {
    let Some(run) = app.policy_group_delay_run.as_mut() else {
        return false;
    };
    if run.id != update.run_id || run.group != update.group {
        return false;
    }

    upsert_tui_policy_group_delay_result(&mut app.policy_group_delay_results, update.result);
    run.completed = (run.completed + 1).min(run.total);
    app.last_message = format!(
        "testing delays for policy group {}: {}/{}",
        run.group, run.completed, run.total
    );
    true
}
pub(crate) async fn tui_start_policy_group_delay(app: &mut TuiApp, group: &str) -> Result<usize> {
    cancel_tui_policy_group_delay(app);
    app.refresh_status().await?;
    let group = policy_groups(app.control_snapshot.as_ref())
        .into_iter()
        .find(|item| item.tag == group)
        .with_context(|| format!("policy group `{group}` is no longer available"))?;
    if group.outbounds.is_empty() {
        bail!("policy group `{}` has no selectable outbounds", group.tag);
    }
    let control = app.status.control_api.as_ref().context(
        "TabbyMew service is not running; run /restart before testing policy group delay",
    )?;
    if !control.healthy {
        bail!(
            "control API is unhealthy at http://{}: {}",
            control.listen,
            control.error.as_deref().unwrap_or("unknown error")
        );
    }
    let listen = control::parse_listen(&control.listen)
        .context("invalid control API listen address from local state")?;
    let token = tui_control_token(&app.session)?;
    let total = group.outbounds.len();
    let run_id = app.policy_group_delay_next_run_id;
    app.policy_group_delay_next_run_id = app.policy_group_delay_next_run_id.wrapping_add(1).max(1);
    let (sender, receiver) = mpsc::unbounded_channel();

    app.policy_group_delay_group = Some(group.tag.clone());
    app.policy_group_delay_results.clear();
    app.policy_group_delay_run = Some(TuiPolicyGroupDelayRun {
        id: run_id,
        group: group.tag.clone(),
        total,
        completed: 0,
        tasks: spawn_tui_policy_group_delay_run(
            run_id,
            group.tag.clone(),
            group.outbounds.clone(),
            listen,
            token,
            sender,
        ),
    });
    app.policy_group_delay_updates = Some(receiver);
    Ok(total)
}

pub(crate) fn tui_policy_group_delay_request_timeout(outbound_count: usize) -> Duration {
    let count = u64::try_from(outbound_count.max(1)).unwrap_or(u64::MAX);
    Duration::from_secs(count.saturating_mul(15).saturating_add(10).min(1_800))
}

pub(crate) fn spawn_tui_policy_group_delay_run(
    run_id: u64,
    group: String,
    outbounds: Vec<String>,
    listen: std::net::SocketAddr,
    token: String,
    sender: mpsc::UnboundedSender<TuiPolicyGroupDelayUpdate>,
) -> Vec<JoinHandle<()>> {
    let timeout = tui_policy_group_delay_request_timeout(1);
    outbounds
        .into_iter()
        .enumerate()
        .map(|(index, outbound)| {
            let group = group.clone();
            let token = token.clone();
            let sender = sender.clone();
            let delay =
                Duration::from_millis(u64::try_from(index).unwrap_or(u64::MAX).saturating_mul(300));
            tokio::spawn(async move {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                let result = tui_measure_policy_group_delay_outbound(
                    listen,
                    timeout,
                    token,
                    group.clone(),
                    outbound,
                )
                .await;
                let _ = sender.send(TuiPolicyGroupDelayUpdate {
                    run_id,
                    group,
                    result,
                });
            })
        })
        .collect()
}

pub(crate) async fn tui_measure_policy_group_delay_outbound(
    listen: std::net::SocketAddr,
    timeout: Duration,
    token: String,
    group: String,
    outbound: String,
) -> TuiPolicyGroupDelayResult {
    let client = ControlClient::new(listen, timeout);
    let body = serde_json::json!({ "group": group.as_str(), "outbound": outbound.as_str() });
    match client
        .post_json("/control/api/policy-groups/delay", &token, &body)
        .await
    {
        Ok(response) => first_tui_policy_group_delay_result(&response, &outbound),
        Err(err) => failed_tui_policy_group_delay_result(&outbound, format!("{err:#}")),
    }
}
