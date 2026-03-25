use clap::{Args, Parser, Subcommand, ValueEnum};
use raven_core::DiscoveryProviderKind;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "raven", version, about = "RavenOSINT CLI")]
pub struct Cli {
    #[arg(long, default_value = "config/default.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Discover candidate URLs from search providers or a seed file.
    Discover(DiscoverArgs),
    /// Scan a single URL through the full validation pipeline.
    Scan(ScanArgs),
    /// Validate every URL in a newline-delimited file.
    Validate(ValidateArgs),
    /// View stored scan results without opening the database.
    Results(ResultsArgs),
    /// View stored discovery results without opening the database.
    Discoveries(DiscoveriesArgs),
    /// Configuration utilities.
    Config(ConfigArgs),
    /// Plugin registry utilities.
    Plugin(PluginArgs),
}

// ─────────────────────────────────────────────────────────────────────────────
// Results viewing
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub struct ResultsArgs {
    #[command(subcommand)]
    pub command: ResultsCommand,
}

#[derive(Debug, Subcommand)]
pub enum ResultsCommand {
    /// List all stored scan results.
    List(ResultsListArgs),
    /// Show full details for one scan result.
    Get(ResultsGetArgs),
}

#[derive(Debug, Args)]
pub struct ResultsListArgs {
    /// Maximum number of results to show.
    #[arg(long, default_value_t = 20)]
    pub limit: i64,

    /// Skip this many results (for pagination).
    #[arg(long, default_value_t = 0)]
    pub offset: i64,

    /// Filter by status: active, suspicious, malicious, down, unknown.
    #[arg(long)]
    pub status: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ResultsGetArgs {
    /// Job UUID to retrieve.
    pub job_id: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

// ─────────────────────────────────────────────────────────────────────────────
// Discoveries viewing
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub struct DiscoveriesArgs {
    #[command(subcommand)]
    pub command: DiscoveriesCommand,
}

#[derive(Debug, Subcommand)]
pub enum DiscoveriesCommand {
    /// List all stored discovery jobs.
    List(DiscoveriesListArgs),
    /// Show URLs from one discovery job.
    Get(DiscoveriesGetArgs),
}

#[derive(Debug, Args)]
pub struct DiscoveriesListArgs {
    /// Maximum number of discovery jobs to show.
    #[arg(long, default_value_t = 20)]
    pub limit: i64,

    /// Skip this many jobs (for pagination).
    #[arg(long, default_value_t = 0)]
    pub offset: i64,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct DiscoveriesGetArgs {
    /// Discovery job UUID to retrieve.
    pub job_id: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

// ─────────────────────────────────────────────────────────────────────────────
// Existing commands
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    /// Search query, domain, or path to a seed file.
    pub query: String,

    #[arg(long)]
    pub site: Option<String>,

    #[arg(long, value_enum, default_value_t = DiscoveryProviderArg::Serper)]
    pub provider: DiscoveryProviderArg,

    #[arg(long, default_value_t = 25)]
    pub limit: usize,

    #[arg(long)]
    pub country: Option<String>,

    #[arg(long)]
    pub lang: Option<String>,

    #[arg(long, default_value_t = true)]
    pub include_subdomains: bool,

    /// Also run the full scan pipeline on every discovered URL.
    #[arg(long)]
    pub validate: bool,

    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,

    /// `urls` emits one URL per line for piping into `raven validate`.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    pub url: String,

    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    pub file: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the resolved configuration as JSON.
    Show,
}

#[derive(Debug, Args)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub command: PluginCommand,
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    List,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
    /// One URL per line — for piping into `raven validate`.
    Urls,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DiscoveryProviderArg {
    Serper,
    Exa,
    /// Accepts: seed-file or seedfile
    #[value(name = "seed-file", alias = "seedfile")]
    SeedFile,
    #[value(alias = "cens")]
    Censys,
    /// Accepts: virustotal or virus-total
    #[value(name = "virustotal", alias = "virus-total")]
    VirusTotal,
}

impl From<DiscoveryProviderArg> for DiscoveryProviderKind {
    fn from(value: DiscoveryProviderArg) -> Self {
        match value {
            DiscoveryProviderArg::Serper => DiscoveryProviderKind::Serper,
            DiscoveryProviderArg::Exa => DiscoveryProviderKind::Exa,
            DiscoveryProviderArg::SeedFile => DiscoveryProviderKind::SeedFile,
            DiscoveryProviderArg::Censys => DiscoveryProviderKind::Censys,
            DiscoveryProviderArg::VirusTotal => DiscoveryProviderKind::VirusTotal,
        }
    }
}
