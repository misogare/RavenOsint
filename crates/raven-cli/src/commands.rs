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
    Discover(DiscoverArgs),
    Scan(ScanArgs),
    Validate(ValidateArgs),
    Config(ConfigArgs),
    Plugin(PluginArgs),
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
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

    #[arg(long)]
    pub validate: bool,

    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,

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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DiscoveryProviderArg {
    Serper,
    Exa,
    SeedFile,
}

impl From<DiscoveryProviderArg> for DiscoveryProviderKind {
    fn from(value: DiscoveryProviderArg) -> Self {
        match value {
            DiscoveryProviderArg::Serper => DiscoveryProviderKind::Serper,
            DiscoveryProviderArg::Exa => DiscoveryProviderKind::Exa,
            DiscoveryProviderArg::SeedFile => DiscoveryProviderKind::SeedFile,
        }
    }
}
