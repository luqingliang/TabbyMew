use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result};

use crate::fs_security;

use super::{
    DEFAULT_LOG_DIR, LOG_TAIL_BLOCK_BYTES, MAX_LOG_ARCHIVES, MAX_LOG_FILE_BYTES,
    MAX_LOG_TAIL_BYTES, MAX_SESSION_LOG_FILES, SESSION_LOG_PREFIX, SESSION_LOG_SUFFIX,
    paths::{absolute_output_path, unix_now, unix_now_nanos},
};

pub fn new_session_log_file(state_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let log_dir = state_dir.as_ref().join(DEFAULT_LOG_DIR);
    prune_session_logs(&log_dir, MAX_SESSION_LOG_FILES.saturating_sub(1))?;
    absolute_output_path(&log_dir.join(session_log_file_name()))
}

pub fn append_lifecycle_event(
    log_file: impl AsRef<Path>,
    event: &str,
    fields: &[(&str, String)],
) -> Result<()> {
    let log_file = log_file.as_ref();
    if let Some(parent) = log_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .filter(|parent| !parent.exists())
    {
        fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create log dir {}", parent.display()))?;
    }
    let mut file = fs_security::open_private_append(log_file)
        .with_context(|| format!("failed to open log file {}", log_file.display()))?;
    write!(
        file,
        "{} INFO lifecycle event={}",
        unix_now(),
        log_value(event)
    )
    .with_context(|| format!("failed to write log file {}", log_file.display()))?;
    for (key, value) in fields {
        write!(file, " {key}={}", log_value(value))
            .with_context(|| format!("failed to write log file {}", log_file.display()))?;
    }
    writeln!(file).with_context(|| format!("failed to write log file {}", log_file.display()))
}

pub fn append_lifecycle_event_best_effort(
    log_file: impl AsRef<Path>,
    event: &str,
    fields: &[(&str, String)],
) {
    let _ = super::append_lifecycle_event(log_file, event, fields);
}

pub fn read_log_tail(path: impl AsRef<Path>, lines: usize) -> Result<String> {
    let path = path.as_ref();
    let text = read_tail_text(path, lines)?;
    Ok(tail_lines(&text, lines))
}

pub(super) fn append_log_separator(path: &Path) -> Result<()> {
    use std::io::Write;

    let mut file = fs_security::open_private_append(path)
        .with_context(|| format!("failed to open log file {}", path.display()))?;
    writeln!(file, "\n== TabbyMew start {} ==", unix_now())
        .with_context(|| format!("failed to write log file {}", path.display()))
}

pub(super) fn rotate_log_if_needed(path: &Path) -> Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() <= MAX_LOG_FILE_BYTES {
        return Ok(());
    }

    let oldest = rotated_log_path(path, MAX_LOG_ARCHIVES);
    match fs::remove_file(&oldest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to remove old log {}", oldest.display()));
        }
    }

    for index in (1..MAX_LOG_ARCHIVES).rev() {
        let from = rotated_log_path(path, index);
        let to = rotated_log_path(path, index + 1);
        match fs::rename(&from, &to) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to rotate log {} to {}",
                        from.display(),
                        to.display()
                    )
                });
            }
        }
    }

    let first = rotated_log_path(path, 1);
    fs::rename(path, &first).with_context(|| {
        format!(
            "failed to rotate log {} to {}",
            path.display(),
            first.display()
        )
    })
}

pub(super) fn rotated_log_path(path: &Path, index: usize) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.{index}"))
        .unwrap_or_else(|| format!("tabbymew.log.{index}"));
    path.with_file_name(file_name)
}

fn session_log_file_name() -> String {
    format!(
        "{SESSION_LOG_PREFIX}{}{SESSION_LOG_SUFFIX}",
        unix_now_nanos()
    )
}

pub(super) fn is_session_log_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with(SESSION_LOG_PREFIX) && name.ends_with(SESSION_LOG_SUFFIX)
}

pub(super) fn prune_session_logs(dir: &Path, keep: usize) -> Result<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut logs = Vec::new();
    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read log dir entry {}", dir.display()))?;
        let path = entry.path();
        if !is_session_log_file(&path) {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to read log metadata {}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
        logs.push((modified, path));
    }

    logs.sort_by(|(left_modified, left_path), (right_modified, right_path)| {
        left_modified
            .cmp(right_modified)
            .then_with(|| left_path.cmp(right_path))
    });
    let remove_count = logs.len().saturating_sub(keep);
    for (_, path) in logs.into_iter().take(remove_count) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove old session log {}", path.display()))?;
    }
    Ok(())
}

fn read_tail_text(path: &Path, lines: usize) -> Result<String> {
    if lines == 0 {
        return Ok(String::new());
    }

    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to read log file {}", path.display()))?;
    let mut position = file
        .metadata()
        .with_context(|| format!("failed to read log metadata {}", path.display()))?
        .len();
    let mut chunks = Vec::new();
    let mut newline_count = 0usize;
    let mut bytes_read = 0u64;

    while position > 0 && newline_count <= lines && bytes_read < MAX_LOG_TAIL_BYTES {
        let remaining_budget = MAX_LOG_TAIL_BYTES - bytes_read;
        let read_len = LOG_TAIL_BLOCK_BYTES.min(position).min(remaining_budget);
        position -= read_len;
        file.seek(SeekFrom::Start(position))
            .with_context(|| format!("failed to seek log file {}", path.display()))?;
        let mut chunk = vec![0u8; read_len as usize];
        file.read_exact(&mut chunk)
            .with_context(|| format!("failed to read log file {}", path.display()))?;
        newline_count += chunk.iter().filter(|byte| **byte == b'\n').count();
        bytes_read += read_len;
        chunks.push(chunk);
    }

    chunks.reverse();
    let mut bytes = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
    for chunk in chunks {
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn tail_lines(text: &str, lines: usize) -> String {
    if lines == 0 || text.is_empty() {
        return String::new();
    }
    let all = text.lines().collect::<Vec<_>>();
    let start = all.len().saturating_sub(lines);
    let mut output = all[start..].join("\n");
    if !output.is_empty() && text.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn log_value(value: &str) -> String {
    let sanitized = value.replace(['\r', '\n', '\t'], " ");
    serde_json::to_string(&sanitized).unwrap_or_else(|_| "\"<invalid>\"".to_string())
}
