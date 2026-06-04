#[derive(Debug, Parser)]
#[command(name = "TabbyMew")]
#[command(about = "A cross-platform Rust proxy core and control console.")]
struct Cli {
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Open the interactive TabbyMew control shell")]
    Shell(ShellCommand),
    #[command(about = "Run TabbyMew as a foreground proxy service")]
    Run(RunCommand),
    #[command(about = "Start TabbyMew in the background and write a local state file")]
    Start(StartCommand),
    #[command(about = "Stop a background TabbyMew process from the local state file")]
    Stop(StopCommand),
    #[command(about = "Clean stale TabbyMew-owned local runtime state")]
    Cleanup(CleanupCommand),
    #[command(about = "Diagnose local TabbyMew service state and control API health")]
    Doctor(DoctorCommand),
    #[command(about = "Wait for service, TUN, or system proxy runtime state")]
    Wait(WaitCommand),
    #[command(about = "Read or follow the background process log")]
    Logs(LogsCommand),
    #[command(about = "Validate the selected config without starting listeners")]
    Check(CheckCommand),
    #[command(about = "Print local service status and control API health")]
    Status(StatusCommand),
    #[command(about = "Get or set the runtime route mode")]
    Mode(ModeCommand),
    #[command(about = "Get or set the global-mode outbound target")]
    Global(GlobalCommand),
    #[command(
        name = "groups",
        alias = "policy-groups",
        about = "List policy groups or select a group outbound"
    )]
    Groups(GroupsCommand),
    #[command(about = "Get or switch TUN mode")]
    Tun(TunCommand),
    #[command(
        name = "system-proxy",
        alias = "sysproxy",
        about = "Get or switch the OS system proxy"
    )]
    SystemProxy(SystemProxyCommand),
    #[command(about = "Query read-only local control API endpoints")]
    Api(ApiCommand),
    #[command(about = "Manage route rules through the local control API")]
    Rules(RulesCommand),
    #[command(about = "Print a minimal example config")]
    Example,
    #[command(about = "Inspect or rewrite local config files")]
    Config(ConfigCommand),
    #[command(
        name = "subscription",
        alias = "subscriptions",
        about = "Manage subscriptions"
    )]
    Subscription(SubscriptionCommand),
    #[command(name = "internal-tun-helper", hide = true)]
    InternalTunHelper(inbound::tun::PrivilegedTunHelperCommand),
}

#[derive(Debug, Parser)]
struct ShellCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    timeout_ms: u64,
}

impl Default for ShellCommand {
    fn default() -> Self {
        Self {
            state_dir: None,
            timeout_ms: DEFAULT_CONTROL_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Parser)]
struct StartCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    log: Option<PathBuf>,

    #[arg(long = "control-listen", alias = "console-listen")]
    control_listen: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser, Default)]
struct RunCommand {
    #[arg(long = "control-listen", alias = "console-listen")]
    control_listen: Option<String>,
}

#[derive(Debug, Parser)]
struct StopCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    pid: Option<u32>,

    #[arg(long)]
    force: bool,

    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct CleanupCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct DoctorCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    timeout_ms: u64,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct WaitCommand {
    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = 30000)]
    timeout_ms: u64,

    #[arg(long, default_value_t = 250)]
    interval_ms: u64,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    request_timeout_ms: u64,

    #[arg(long)]
    json: bool,

    #[arg(value_name = "service|tun|system-proxy")]
    target: String,

    #[arg(value_name = "ready|stopped|on|off")]
    state: Option<String>,
}

#[derive(Debug, Parser)]
struct LogsCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    log: Option<PathBuf>,

    #[arg(long, default_value_t = 80)]
    lines: usize,

    #[arg(short, long)]
    follow: bool,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct CheckCommand {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct StatusCommand {
    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    timeout_ms: u64,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser, Clone)]
struct RuntimeControlOptions {
    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    timeout_ms: u64,
}

#[derive(Debug, Parser)]
struct ModeCommand {
    #[command(flatten)]
    control: RuntimeControlOptions,

    #[arg(value_name = "rule|global|direct")]
    mode: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct GlobalCommand {
    #[command(flatten)]
    control: RuntimeControlOptions,

    target: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct GroupsCommand {
    #[command(flatten)]
    control: RuntimeControlOptions,

    group: Option<String>,

    outbound: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct TunCommand {
    #[command(flatten)]
    control: RuntimeControlOptions,

    #[arg(value_name = "status|on|off|toggle")]
    action: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct SystemProxyCommand {
    #[command(flatten)]
    control: RuntimeControlOptions,

    #[arg(value_name = "status|on|off|toggle")]
    action: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct ApiCommand {
    #[command(subcommand)]
    command: ApiSubcommand,
}

#[derive(Debug, Subcommand)]
enum ApiSubcommand {
    #[command(about = "GET a read-only local control API endpoint")]
    Get(ApiGetCommand),
}

#[derive(Debug, Parser)]
struct ApiGetCommand {
    path: String,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    timeout_ms: u64,

    #[arg(long)]
    compact: bool,
}

#[derive(Debug, Parser)]
struct RulesCommand {
    #[command(subcommand)]
    command: RulesSubcommand,
}

#[derive(Debug, Subcommand)]
enum RulesSubcommand {
    #[command(about = "List route rules in structured form")]
    List(RulesListCommand),
    #[command(about = "Add a custom route rule")]
    Add(RulesUpsertCommand),
    #[command(about = "Edit an existing custom route rule")]
    Edit(RulesEditCommand),
    #[command(alias = "delete", alias = "rm", about = "Remove a custom route rule")]
    Remove(RulesRemoveCommand),
    #[command(about = "Reload route rules from disk")]
    Reload(RulesControlCommand),
    #[command(
        alias = "route-test",
        about = "Test which route and outbound a destination uses"
    )]
    Test(RulesTestCommand),
}

#[derive(Debug, Parser, Clone)]
struct RulesControlOptions {
    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value_t = DEFAULT_CONTROL_TIMEOUT_MS)]
    timeout_ms: u64,
}

#[derive(Debug, Parser)]
struct RulesListCommand {
    #[command(flatten)]
    control: RulesControlOptions,

    #[arg(long)]
    filter: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct RulesUpsertCommand {
    #[command(flatten)]
    control: RulesControlOptions,

    #[arg(long, value_name = "domain-suffix|domain|domain-keyword|ip-cidr")]
    kind: String,

    #[arg(long)]
    value: String,

    #[arg(long)]
    outbound: String,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct RulesEditCommand {
    id: String,

    #[command(flatten)]
    upsert: RulesUpsertCommand,
}

#[derive(Debug, Parser)]
struct RulesRemoveCommand {
    id: String,

    #[command(flatten)]
    control: RulesControlOptions,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct RulesControlCommand {
    #[command(flatten)]
    control: RulesControlOptions,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct RulesTestCommand {
    destination: String,

    #[command(flatten)]
    control: RulesControlOptions,

    #[arg(long)]
    port: Option<u16>,

    #[arg(long, value_name = "tcp|udp")]
    network: Option<String>,

    #[arg(long)]
    inbound: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct ConfigCommand {
    #[command(subcommand)]
    command: ConfigSubcommand,
}

#[derive(Debug, Subcommand)]
enum ConfigSubcommand {
    #[command(about = "Print the native config schema contract as JSON")]
    Schema,
    #[command(about = "Print stable pretty JSON, redacted by default")]
    Normalize(NormalizeCommand),
}

#[derive(Debug, Parser)]
struct NormalizeCommand {
    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    show_secrets: bool,
}

#[derive(Debug, Parser)]
struct SubscriptionCommand {
    #[command(subcommand)]
    command: SubscriptionSubcommand,
}

#[derive(Debug, Subcommand)]
enum SubscriptionSubcommand {
    #[command(about = "Fetch, import, validate, and save a remote subscription")]
    Add(SubscriptionAddCommand),
    #[command(
        name = "import-file",
        about = "Import, validate, and save a local subscription file"
    )]
    ImportFile(SubscriptionImportFileCommand),
    #[command(about = "List saved subscriptions")]
    List(SubscriptionListCommand),
    #[command(about = "Update one saved remote subscription or all remote subscriptions")]
    Update(SubscriptionUpdateCommand),
    #[command(about = "Update saved subscription settings")]
    Set(SubscriptionSetCommand),
    #[command(about = "Remove a saved subscription entry")]
    Remove(SubscriptionRemoveCommand),
}

#[derive(Debug, Parser)]
struct SubscriptionAddCommand {
    name: String,
    url: String,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value = "hybrid-in")]
    inbound_tag: String,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    listen_port: Option<u16>,

    #[arg(long, default_value_t = 15000)]
    timeout_ms: u64,

    #[arg(long, default_value_t = 2)]
    retries: u8,

    #[arg(long)]
    no_auto_update: bool,

    #[arg(long, default_value_t = subscription_remote::DEFAULT_UPDATE_INTERVAL_SECONDS)]
    update_interval_seconds: u64,

    #[arg(long, default_value = subscription_remote::DEFAULT_USER_AGENT)]
    user_agent: String,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct SubscriptionImportFileCommand {
    name: String,
    input: PathBuf,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long, default_value = "hybrid-in")]
    inbound_tag: String,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    listen_port: Option<u16>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct SubscriptionListCommand {
    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct SubscriptionUpdateCommand {
    name: Option<String>,

    #[arg(long)]
    all: bool,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    timeout_ms: Option<u64>,

    #[arg(long)]
    retries: Option<u8>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct SubscriptionSetCommand {
    name: String,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    auto_update: bool,

    #[arg(long)]
    no_auto_update: bool,

    #[arg(long)]
    update_interval_seconds: Option<u64>,

    #[arg(long)]
    timeout_ms: Option<u64>,

    #[arg(long)]
    retries: Option<u8>,

    #[arg(long)]
    user_agent: Option<String>,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct SubscriptionRemoveCommand {
    name: String,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    json: bool,
}
