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
    /// Configuration utilities.
    Config(ConfigArgs),
    /// Plugin registry utilities.
    Plugin(PluginArgs),
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    /// Search query, domain, or path to a seed file (used with --provider=seed_file).
    pub query: String,

    /// Restrict results to this domain (e.g. example.com).
    #[arg(long)]
    pub site: Option<String>,

    /// Discovery provider to use.
    #[arg(long, value_enum, default_value_t = DiscoveryProviderArg::Serper)]
    pub provider: DiscoveryProviderArg,

    /// Maximum number of candidate URLs to return.
    #[arg(long, default_value_t = 25)]
    pub limit: usize,

    /// ISO 3166-1 alpha-2 country code for geo-localised results (e.g. us, de).
    #[arg(long)]
    pub country: Option<String>,

    /// BCP 47 language code for localised results (e.g. en, de).
    #[arg(long)]
    pub lang: Option<String>,

    /// Include subdomain results when --site is set.
    #[arg(long, default_value_t = true)]
    pub include_subdomains: bool,

    /// Automatically feed discovered URLs into the validation pipeline.
    /// Defaults to false — discovery only unless this flag is set.
    #[arg(long)]
    pub validate: bool,

    /// Comma-separated tags to attach to validation jobs created by --validate.
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,

    /// Output format.
    /// `urls` emits one URL per line for piping into `raven validate`.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// URL to scan.
    pub url: String,

    /// Comma-separated tags.
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Path to a newline-delimited file of URLs to validate.
    pub file: PathBuf,

    /// Output format.
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
    /// List registered providers, scrapers, agents, and LLM backends.
    List,
}

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Pretty-printed JSON — machine-readable and pipeable to `jq`.
    Json,
    /// Human-readable table — default for interactive use.
    Table,
    /// One URL per line — for piping directly into `raven validate`.
    /// Example: raven discover "phishing kits" --output urls | raven validate -
    Urls,
}

/// Discovery provider selection for the CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DiscoveryProviderArg {
    /// Serper (Google-style search) — default provider.
    Serper,
    /// Exa (agentic web search with richer metadata).
    Exa,
    /// Seed file — reads URLs/domains from a file or inline query string.
    SeedFile,
}

impl From<DiscoveryProviderArg> for DiscoveryProviderKind {
    fn from(value: DiscoveryProviderArg) -> Self {
        match value {
            DiscoveryProviderArg::Serper   => DiscoveryProviderKind::Serper,
            DiscoveryProviderArg::Exa      => DiscoveryProviderKind::Exa,
            DiscoveryProviderArg::SeedFile => DiscoveryProviderKind::SeedFile,
        }
    }
}