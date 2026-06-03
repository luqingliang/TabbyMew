use super::*;

pub(super) fn cleanup_service_state(state_dir: &Path) -> Result<CleanupReport> {
    cleanup_service_state_with_system_proxy(
        state_dir,
        &|target| system_proxy::status_for_target(target),
        &|target| system_proxy::disable_target_without_prompt(target),
    )
}

pub(super) fn cleanup_service_state_with_system_proxy(
    state_dir: &Path,
    system_proxy_status: &dyn Fn(
        Option<&system_proxy::SystemProxyTarget>,
    ) -> system_proxy::SystemProxyStatus,
    disable_system_proxy: &dyn Fn(
        Option<&system_proxy::SystemProxyTarget>,
    ) -> Result<system_proxy::SystemProxyStatus>,
) -> Result<CleanupReport> {
    let before = process_manager::service_status(state_dir);
    let before_summary = cleanup_state_summary(state_dir, &before, system_proxy_status);
    let mut actions = Vec::new();
    let mut errors = Vec::new();
    record_service_lifecycle_event(
        &before,
        "cleanup_requested",
        vec![("cleanup_items", before.cleanup_items.join(","))],
    );

    cleanup_stale_state_files(&before, &mut actions, &mut errors);

    if before.running {
        actions.push(CleanupAction {
            name: "running_service",
            ok: true,
            error_code: None,
            message: "service is running; live-owned state and system proxy were left untouched"
                .to_string(),
        });
        record_service_lifecycle_event(&before, "cleanup_skipped_running", Vec::new());
    } else {
        cleanup_system_proxy_residue(
            state_dir,
            &before,
            service_lifecycle_log_path(&before),
            &mut actions,
            &mut errors,
            system_proxy_status,
            disable_system_proxy,
        )?;
    }

    let after = process_manager::service_status(state_dir);
    let after_summary = cleanup_state_summary(state_dir, &after, system_proxy_status);
    let ok = errors.is_empty()
        && !after.needs_cleanup()
        && after.state_error.is_none()
        && after.preference_error.is_none();
    let issues = cleanup_report_issues(&actions, &after, &errors);
    let next_actions = next_actions_for_issues_with_state_dir(&issues, Some(&after.state_dir));
    record_lifecycle_event(
        service_lifecycle_log_path(&before),
        "cleanup_completed",
        vec![
            ("ok", ok.to_string()),
            ("before_status", before.status.as_str().to_string()),
            ("after_status", after.status.as_str().to_string()),
            ("actions", actions.len().to_string()),
            ("errors", errors.len().to_string()),
        ],
    );
    Ok(CleanupReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok,
        before,
        after,
        before_summary,
        after_summary,
        actions,
        errors,
        issues,
        next_actions,
    })
}

#[derive(Debug, Clone)]
pub(super) struct SystemProxyCleanupCandidate {
    pub(super) target: system_proxy::SystemProxyTarget,
    pub(super) target_recorded: bool,
    pub(super) source: String,
}

pub(super) fn cleanup_state_summary(
    state_dir: &Path,
    service: &ServiceStatus,
    system_proxy_status: &dyn Fn(
        Option<&system_proxy::SystemProxyTarget>,
    ) -> system_proxy::SystemProxyStatus,
) -> CleanupStateSummary {
    let system_proxy = system_proxy_cleanup_candidate(state_dir, service).map(|candidate| {
        let status = system_proxy_status(Some(&candidate.target))
            .with_target_recorded(candidate.target_recorded);
        CleanupSystemProxySummary {
            candidate_source: candidate.source,
            status,
        }
    });

    CleanupStateSummary {
        service_status: service.status.as_str().to_string(),
        running: service.running,
        cleanup_items: service.cleanup_items.clone(),
        state_file_exists: service.state_file_exists,
        runtime_state_file_exists: service.runtime_state_file_exists,
        managed_system_proxy_recorded: service.managed_system_proxy_recorded,
        system_proxy,
    }
}

pub(super) fn system_proxy_cleanup_candidate(
    state_dir: &Path,
    service: &ServiceStatus,
) -> Option<SystemProxyCleanupCandidate> {
    let preferences_path = process_manager::preferences_path(state_dir);
    let preferences = process_manager::load_preferences(&preferences_path).ok();
    if let Some(target) = preferences
        .as_ref()
        .and_then(|preferences| preferences.system_proxy_target.clone())
    {
        return Some(SystemProxyCleanupCandidate {
            target,
            target_recorded: true,
            source: "preferences.system_proxy_target".to_string(),
        });
    }

    let config_candidates = system_proxy_cleanup_config_candidates(service, preferences.as_ref());
    for (source, config_path) in config_candidates {
        let Ok(config) = Config::load(&config_path) else {
            continue;
        };
        if let Some(target) = system_proxy::target_from_inbounds(&config.summary().inbounds) {
            return Some(SystemProxyCleanupCandidate {
                target,
                target_recorded: false,
                source,
            });
        }
    }

    None
}

pub(super) fn system_proxy_cleanup_config_candidates(
    service: &ServiceStatus,
    preferences: Option<&process_manager::RuntimePreferences>,
) -> Vec<(String, PathBuf)> {
    let mut candidates = Vec::new();
    if let Some(config) = service.config.as_ref().filter(|path| path.exists()) {
        candidates.push(("state.config".to_string(), config.clone()));
    }
    if let Some(active_config) = preferences
        .and_then(|preferences| preferences.active_config.as_ref())
        .filter(|path| path.exists())
        && !candidates
            .iter()
            .any(|(_, candidate)| candidate == active_config)
    {
        candidates.push((
            "preferences.active_config".to_string(),
            active_config.clone(),
        ));
    }
    candidates
}

pub(super) fn cleanup_stale_state_files(
    service: &ServiceStatus,
    actions: &mut Vec<CleanupAction>,
    errors: &mut Vec<String>,
) {
    cleanup_stale_state_file(
        service,
        &service.state_file,
        service.state_file_exists,
        "stale_state_file",
        "state_file",
        actions,
        errors,
    );
    cleanup_stale_state_file(
        service,
        &service.runtime_state_file,
        service.runtime_state_file_exists,
        "stale_runtime_state_file",
        "runtime_state_file",
        actions,
        errors,
    );
}

pub(super) fn cleanup_stale_state_file(
    service: &ServiceStatus,
    state_file: &Path,
    exists: bool,
    cleanup_item: &str,
    action_name: &'static str,
    actions: &mut Vec<CleanupAction>,
    errors: &mut Vec<String>,
) {
    if !exists
        || !service
            .cleanup_items
            .iter()
            .any(|item| item == cleanup_item)
    {
        return;
    }
    if service
        .active_state_file
        .as_deref()
        .is_some_and(|active| active == state_file)
        && service.running
    {
        return;
    }
    match process_manager::remove_state_file(state_file) {
        Ok(()) => {
            actions.push(CleanupAction {
                name: action_name,
                ok: true,
                error_code: None,
                message: format!("removed {}", state_file.display()),
            });
            record_service_lifecycle_event(
                service,
                "cleanup_state_file_removed",
                vec![
                    ("state_file", state_file.display().to_string()),
                    ("kind", action_name.to_string()),
                ],
            );
        }
        Err(err) => {
            let message = format!(
                "failed to remove state file {}: {err:#}",
                state_file.display()
            );
            actions.push(CleanupAction {
                name: action_name,
                ok: false,
                error_code: Some("state_file_remove_failed"),
                message: message.clone(),
            });
            errors.push(message);
            record_service_lifecycle_event(
                service,
                "cleanup_state_file_failed",
                vec![
                    ("state_file", state_file.display().to_string()),
                    ("kind", action_name.to_string()),
                    ("error", format!("{err:#}")),
                ],
            );
        }
    }
}

pub(super) fn cleanup_system_proxy_residue(
    state_dir: &Path,
    service: &ServiceStatus,
    log_file: Option<&Path>,
    actions: &mut Vec<CleanupAction>,
    errors: &mut Vec<String>,
    system_proxy_status: &dyn Fn(
        Option<&system_proxy::SystemProxyTarget>,
    ) -> system_proxy::SystemProxyStatus,
    disable_system_proxy: &dyn Fn(
        Option<&system_proxy::SystemProxyTarget>,
    ) -> Result<system_proxy::SystemProxyStatus>,
) -> Result<()> {
    let preferences_path = process_manager::preferences_path(state_dir);
    if let Some(error) = service.preference_error.as_ref() {
        let message = format!(
            "failed to load runtime preferences {}: {error}",
            preferences_path.display()
        );
        actions.push(CleanupAction {
            name: "preferences",
            ok: false,
            error_code: Some("preferences_unreadable"),
            message: message.clone(),
        });
        errors.push(message);
        record_lifecycle_event(
            log_file,
            "cleanup_preferences_failed",
            vec![("error", error.clone())],
        );
        return Ok(());
    }

    let Some(candidate) = system_proxy_cleanup_candidate(state_dir, service) else {
        return Ok(());
    };

    let before_status = system_proxy_status(Some(&candidate.target))
        .with_target_recorded(candidate.target_recorded);
    if !before_status.matches_target {
        if candidate.target_recorded {
            clear_recorded_system_proxy_preference(
                &preferences_path,
                log_file,
                actions,
                errors,
                "system_proxy_record_stale",
                "cleared stale system proxy ownership record; OS proxy no longer matches TabbyMew",
            );
        }
        return Ok(());
    }

    record_lifecycle_event(
        log_file,
        "cleanup_system_proxy_started",
        vec![
            ("target_recorded", candidate.target_recorded.to_string()),
            ("candidate_source", candidate.source.clone()),
        ],
    );
    match disable_system_proxy(Some(&candidate.target)) {
        Ok(status) if !status.matches_target => {
            let mut preference_cleared = false;
            if candidate.target_recorded {
                preference_cleared = clear_recorded_system_proxy_preference(
                    &preferences_path,
                    log_file,
                    actions,
                    errors,
                    "system_proxy_preference_save_failed",
                    "cleared recorded TabbyMew-managed system proxy target",
                );
            } else {
                actions.push(CleanupAction {
                    name: "system_proxy_unrecorded",
                    ok: true,
                    error_code: None,
                    message: format!(
                        "disabled unrecorded TabbyMew system proxy target from {}",
                        candidate.source
                    ),
                });
            }
            record_lifecycle_event(
                log_file,
                "cleanup_system_proxy_completed",
                vec![
                    ("ok", "true".to_string()),
                    ("supported", status.supported.to_string()),
                    ("enabled", status.enabled.to_string()),
                    ("managed", status.managed.to_string()),
                    ("matches_target", status.matches_target.to_string()),
                    ("preference_cleared", preference_cleared.to_string()),
                    ("target_recorded", candidate.target_recorded.to_string()),
                    ("candidate_source", candidate.source),
                ],
            );
        }
        Ok(status) => {
            let message = format!(
                "system proxy still appears to be managed by TabbyMew target {}",
                candidate.target.source
            );
            actions.push(CleanupAction {
                name: "system_proxy",
                ok: false,
                error_code: Some("system_proxy_cleanup_failed"),
                message: message.clone(),
            });
            errors.push(format!("{message}; status={status:?}"));
            record_lifecycle_event(
                log_file,
                "cleanup_system_proxy_failed",
                vec![
                    ("reason", "still_managed".to_string()),
                    ("supported", status.supported.to_string()),
                    ("enabled", status.enabled.to_string()),
                    ("managed", status.managed.to_string()),
                    ("matches_target", status.matches_target.to_string()),
                ],
            );
        }
        Err(err) => {
            let message = format!("failed to disable TabbyMew-managed system proxy: {err:#}");
            actions.push(CleanupAction {
                name: "system_proxy",
                ok: false,
                error_code: Some("system_proxy_cleanup_failed"),
                message: message.clone(),
            });
            errors.push(message);
            record_lifecycle_event(
                log_file,
                "cleanup_system_proxy_failed",
                vec![("error", format!("{err:#}"))],
            );
        }
    }
    Ok(())
}

pub(super) fn clear_recorded_system_proxy_preference(
    preferences_path: &Path,
    log_file: Option<&Path>,
    actions: &mut Vec<CleanupAction>,
    errors: &mut Vec<String>,
    error_code: &'static str,
    success_message: &str,
) -> bool {
    let mut preferences = match process_manager::load_preferences(preferences_path) {
        Ok(preferences) => preferences,
        Err(err) => {
            let message = format!(
                "failed to load runtime preferences {}: {err:#}",
                preferences_path.display()
            );
            actions.push(CleanupAction {
                name: "preferences",
                ok: false,
                error_code: Some("preferences_unreadable"),
                message: message.clone(),
            });
            errors.push(message);
            record_lifecycle_event(
                log_file,
                "cleanup_preferences_failed",
                vec![("error", format!("{err:#}"))],
            );
            return false;
        }
    };
    preferences.system_proxy_target = None;
    match process_manager::save_preferences(preferences_path, &preferences) {
        Ok(()) => {
            actions.push(CleanupAction {
                name: "system_proxy",
                ok: true,
                error_code: None,
                message: success_message.to_string(),
            });
            true
        }
        Err(err) => {
            let message = format!(
                "failed to clear system proxy preference {}: {err:#}",
                preferences_path.display()
            );
            actions.push(CleanupAction {
                name: "system_proxy",
                ok: false,
                error_code: Some(error_code),
                message: message.clone(),
            });
            errors.push(message);
            record_lifecycle_event(
                log_file,
                "cleanup_system_proxy_failed",
                vec![
                    ("reason", "preference_save_failed".to_string()),
                    ("error", format!("{err:#}")),
                ],
            );
            false
        }
    }
}
