use super::*;

pub(super) async fn add_subscription(command: SubscriptionAddCommand) -> Result<()> {
    subscription_remote::validate_name(&command.name)?;
    subscription_remote::validate_url(&command.url)?;
    subscription_remote::validate_update_interval_seconds(command.update_interval_seconds)?;
    subscription_remote::validate_timeout_ms(command.timeout_ms)?;
    let runtime = subscription_runtime(command.state_dir);
    let record = subscription_remote::SubscriptionRecord {
        name: command.name.clone(),
        source: subscription_remote::SubscriptionSource::Remote,
        url: command.url,
        output: runtime.output_path_for(&command.name)?,
        inbound_tag: command.inbound_tag,
        listen: command.listen.unwrap_or_else(Config::default_local_listen),
        listen_port: command
            .listen_port
            .unwrap_or_else(Config::default_local_listen_port),
        user_agent: command.user_agent,
        auto_update: !command.no_auto_update,
        update_interval_seconds: command.update_interval_seconds,
        timeout_ms: command.timeout_ms,
        retries: command.retries,
        last_checked_unix: None,
        last_updated_unix: None,
        last_success_unix: None,
        next_update_unix: None,
        last_error: None,
        imported: None,
        warnings: Vec::new(),
        last_etag: None,
        last_modified: None,
        last_final_url: None,
    };
    let report = runtime
        .add(
            record,
            subscription_remote::SubscriptionRefreshOverrides::default(),
        )
        .await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_subscription_apply_report("added", &report);
    println!("store: {}", runtime.store_path().display());
    Ok(())
}

pub(super) async fn list_subscriptions(command: SubscriptionListCommand) -> Result<()> {
    let runtime = subscription_runtime(command.state_dir);
    let snapshot = runtime.snapshot().await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(());
    }

    println!("store: {}", snapshot.store);
    if snapshot.subscriptions.is_empty() {
        println!("subscriptions: none");
        return Ok(());
    }
    println!("subscriptions: {}", snapshot.subscriptions.len());
    for record in &snapshot.subscriptions {
        print_subscription_summary(record);
    }
    Ok(())
}

pub(super) async fn update_subscriptions(command: SubscriptionUpdateCommand) -> Result<()> {
    if command.all && command.name.is_some() {
        bail!("subscription update accepts either <name> or --all, not both");
    }
    if !command.all && command.name.is_none() {
        bail!("subscription update requires <name> or --all");
    }

    if let Some(timeout_ms) = command.timeout_ms {
        subscription_remote::validate_timeout_ms(timeout_ms)?;
    }
    let runtime = subscription_runtime(command.state_dir);
    let overrides = subscription_remote::SubscriptionRefreshOverrides {
        timeout_ms: command.timeout_ms,
        retries: command.retries,
    };
    if command.all {
        let outcomes = runtime.refresh_all(overrides).await?;
        if command.json {
            println!("{}", serde_json::to_string_pretty(&outcomes)?);
            let failures = outcomes
                .iter()
                .filter(|outcome| !outcome.ok)
                .map(|outcome| outcome.name.clone())
                .collect::<Vec<_>>();
            if !failures.is_empty() {
                bail!("failed to update subscription(s): {}", failures.join(", "));
            }
            return Ok(());
        }
        if outcomes.is_empty() {
            println!("subscriptions: none");
            return Ok(());
        }
        let mut failures = Vec::new();
        for outcome in outcomes {
            match (outcome.ok, outcome.report, outcome.error) {
                (true, Some(report), _) => print_subscription_apply_report("updated", &report),
                (_, _, Some(error)) => {
                    eprintln!("failed to update subscription {}: {error}", outcome.name);
                    failures.push(outcome.name);
                }
                _ => {}
            }
        }
        println!("store: {}", runtime.store_path().display());
        if !failures.is_empty() {
            bail!("failed to update subscription(s): {}", failures.join(", "));
        }
        return Ok(());
    }

    let name = command.name.expect("checked above");
    let report = runtime.refresh_one(&name, overrides).await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_subscription_apply_report("updated", &report);
    println!("store: {}", runtime.store_path().display());
    Ok(())
}

pub(super) async fn set_subscription(command: SubscriptionSetCommand) -> Result<()> {
    if command.auto_update && command.no_auto_update {
        bail!("subscription set accepts either --auto-update or --no-auto-update, not both");
    }
    if let Some(timeout_ms) = command.timeout_ms {
        subscription_remote::validate_timeout_ms(timeout_ms)?;
    }
    if let Some(update_interval_seconds) = command.update_interval_seconds {
        subscription_remote::validate_update_interval_seconds(update_interval_seconds)?;
    }
    let runtime = subscription_runtime(command.state_dir);
    let auto_update = if command.auto_update {
        Some(true)
    } else if command.no_auto_update {
        Some(false)
    } else {
        None
    };
    let summary = runtime
        .update_settings(
            &command.name,
            subscription_remote::SubscriptionSettingsPatch {
                auto_update,
                update_interval_seconds: command.update_interval_seconds,
                timeout_ms: command.timeout_ms,
                retries: command.retries,
                user_agent: command.user_agent,
            },
        )
        .await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    println!("subscription updated settings: {}", summary.name);
    print_subscription_summary(&summary);
    println!("store: {}", runtime.store_path().display());
    Ok(())
}

pub(super) async fn remove_subscription(command: SubscriptionRemoveCommand) -> Result<()> {
    let runtime = subscription_runtime(command.state_dir);
    let summary = runtime.remove(&command.name).await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    println!("removed subscription {}", summary.name);
    println!("store: {}", runtime.store_path().display());
    Ok(())
}

pub(super) fn subscription_runtime(state_dir: Option<PathBuf>) -> subscription_remote::SubscriptionRuntime {
    let state_dir = state_dir.unwrap_or_else(process_manager::default_state_dir);
    subscription_remote::SubscriptionRuntime::new(state_dir)
}

pub(super) fn print_subscription_apply_report(
    action: &str,
    report: &subscription_remote::SubscriptionApplyReport,
) {
    println!("subscription {}: {}", action, report.name);
    println!("  source: {}", report.source.as_str());
    println!("  url: {}", report.url);
    println!("  output: {}", report.output);
    println!(
        "  fetched: {} byte(s) from {}",
        report.fetched_bytes, report.final_url
    );
    println!("  imported: {} outbound(s)", report.imported);
    println!(
        "  routing: final={}, policy_groups={}, rules={}",
        report.route_final, report.policy_groups, report.rules
    );
    println!(
        "  next_update_unix: {}",
        report
            .next_update_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "disabled".to_string())
    );
    if report.warnings.is_empty() {
        println!("  warnings: none");
    } else {
        println!("  warnings: {}", report.warnings.len());
        for warning in &report.warnings {
            println!("    - {warning}");
        }
    }
}

pub(super) fn print_subscription_summary(record: &subscription_remote::SubscriptionSummary) {
    println!("- {}", record.name);
    println!("  source: {}", record.source.as_str());
    println!("  url: {}", record.url);
    println!("  output: {}", record.output);
    println!(
        "  auto_update: {}",
        if record.auto_update {
            format!("on every {}s", record.update_interval_seconds)
        } else {
            "off".to_string()
        }
    );
    println!(
        "  last_success_unix: {}",
        record
            .last_success_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "never".to_string())
    );
    println!(
        "  imported: {}",
        record
            .imported
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "  next_update_unix: {}",
        record
            .next_update_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "disabled".to_string())
    );
    println!("  warnings: {}", record.warnings);
    if let Some(error) = &record.last_error {
        println!("  last_error: {error}");
    }
}
