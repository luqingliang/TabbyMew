use super::*;

#[derive(Debug, Serialize)]
pub(super) struct CliControlApiSummary {
    pub(super) listen: String,
    pub(super) url: String,
}

#[derive(Debug, Serialize)]
pub(super) struct CheckJsonReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) status: &'static str,
    pub(super) message: String,
    pub(super) config: PathBuf,
    pub(super) summary: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct StartJsonReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) status: &'static str,
    pub(super) message: String,
    pub(super) pid: u32,
    pub(super) state_dir: PathBuf,
    pub(super) state_file: PathBuf,
    pub(super) config: PathBuf,
    pub(super) log_file: PathBuf,
    pub(super) control_api: Option<CliControlApiSummary>,
    pub(super) warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct StopJsonReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) status: &'static str,
    pub(super) message: String,
    pub(super) pid: Option<u32>,
    pub(super) state_dir: PathBuf,
    pub(super) state_file: PathBuf,
    pub(super) log_file: Option<PathBuf>,
    pub(super) removed_state_file: bool,
    pub(super) terminated: bool,
}

pub(super) struct StopJsonReportInput<'a> {
    pub(super) ok: bool,
    pub(super) status: &'static str,
    pub(super) message: String,
    pub(super) pid: Option<u32>,
    pub(super) state_dir: &'a Path,
    pub(super) state_file: &'a Path,
    pub(super) log_file: Option<&'a Path>,
    pub(super) removed_state_file: bool,
    pub(super) terminated: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct LogsJsonReport {
    pub(super) schema_version: u16,
    pub(super) ok: bool,
    pub(super) status: &'static str,
    pub(super) message: String,
    pub(super) log_file: PathBuf,
    pub(super) lines: usize,
    pub(super) line_count: usize,
    pub(super) content: String,
}

pub(super) fn control_api_summary(listen: Option<&str>) -> Option<CliControlApiSummary> {
    listen.map(|listen| CliControlApiSummary {
        listen: listen.to_string(),
        url: format!("http://{listen}"),
    })
}

pub(super) fn config_summary_lines(config: &Config) -> Vec<String> {
    config.summary().lines()
}

pub(super) fn check_json_report(path: &Path, config: &Config) -> CheckJsonReport {
    CheckJsonReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok: true,
        status: "ok",
        message: format!("configuration ok: {}", path.display()),
        config: path.to_path_buf(),
        summary: config_summary_lines(config),
    }
}

pub(super) fn start_json_report(
    state: &ProcessState,
    state_dir: &Path,
    state_file: &Path,
    warnings: Vec<String>,
) -> StartJsonReport {
    StartJsonReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok: true,
        status: "started",
        message: format!("started TabbyMew pid {}", state.pid),
        pid: state.pid,
        state_dir: state_dir.to_path_buf(),
        state_file: state_file.to_path_buf(),
        config: state.config.clone(),
        log_file: state.log.clone(),
        control_api: control_api_summary(state.listen.as_deref()),
        warnings,
    }
}

pub(super) fn stop_json_report(input: StopJsonReportInput<'_>) -> StopJsonReport {
    StopJsonReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok: input.ok,
        status: input.status,
        message: input.message,
        pid: input.pid,
        state_dir: input.state_dir.to_path_buf(),
        state_file: input.state_file.to_path_buf(),
        log_file: input.log_file.map(Path::to_path_buf),
        removed_state_file: input.removed_state_file,
        terminated: input.terminated,
    }
}

pub(super) fn logs_json_report(path: &Path, lines: usize, content: String) -> LogsJsonReport {
    let line_count = content.lines().count();
    LogsJsonReport {
        schema_version: CLI_JSON_SCHEMA_VERSION,
        ok: true,
        status: "ok",
        message: format!("read {line_count} line(s) from {}", path.display()),
        log_file: path.to_path_buf(),
        lines,
        line_count,
        content,
    }
}

pub(super) fn print_start_report(mut writer: impl Write, state: &ProcessState) -> Result<()> {
    writeln!(writer, "started TabbyMew pid {}", state.pid)?;
    writeln!(writer, "  config: {}", state.config.display())?;
    writeln!(writer, "  log: {}", state.log.display())?;
    writeln!(writer, "  proxy: started with TabbyMew")?;
    if let Some(listen) = &state.listen {
        writeln!(writer, "  control api: http://{listen}")?;
        writeln!(
            writer,
            "  status: TabbyMew --config {} status --listen {listen}",
            state.config.display(),
        )?;
    }
    Ok(())
}

pub(super) fn follow_log(path: &Path, lines: usize) -> Result<()> {
    let mut stdout = io::stdout().lock();
    let initial = process_manager::read_log_tail(path, lines)?;
    stdout.write_all(initial.as_bytes())?;
    stdout.flush()?;

    let mut offset = fs::metadata(path)
        .with_context(|| format!("failed to stat log file {}", path.display()))?
        .len();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let metadata = fs::metadata(path)
            .with_context(|| format!("failed to stat log file {}", path.display()))?;
        if metadata.len() < offset {
            offset = 0;
        }
        if metadata.len() == offset {
            continue;
        }
        let mut file =
            fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed to seek {}", path.display()))?;
        let mut chunk = String::new();
        file.read_to_string(&mut chunk)
            .with_context(|| format!("failed to read {}", path.display()))?;
        offset = metadata.len();
        stdout.write_all(chunk.as_bytes())?;
        stdout.flush()?;
    }
}
