use anyhow::{Context, Result};
use chrono::Utc;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
use raven_api::pipeline::WorkflowRuntime;
use raven_core::{DiscoveryRequest, OsintTarget, RavenConfig};
use raven_storage::new_store;
use serde_json::json;
use std::{collections::HashMap, fs, path::Path, sync::Arc};
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

use crate::commands::{Cli, Command, ConfigCommand, DiscoverArgs, OutputFormat, PluginCommand};

pub async fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config.to_string_lossy().to_string();
    let config = RavenConfig::load(&config_path)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    init_tracing(&config.logging.level)?;

    let store = Arc::<dyn raven_storage::ResultStore>::from(
        new_store(&config.database.url)
            .await
            .map_err(anyhow::Error::msg)?,
    );
    let workflow = WorkflowRuntime::new(&config, Arc::clone(&store)).map_err(anyhow::Error::msg)?;

    match cli.command {
        Command::Discover(args) => handle_discover(&workflow, args).await,
        Command::Scan(args) => handle_scan(&workflow, args.url, args.tags, args.output).await,
        Command::Validate(args) => handle_validate(&workflow, &args.file, args.output).await,
        Command::Config(args) => match args.command {
            ConfigCommand::Show => show_config(&config),
        },
        Command::Plugin(args) => match args.command {
            PluginCommand::List => list_plugins(),
        },
    }
}

fn init_tracing(level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level).or_else(|_| EnvFilter::try_new("info"))?;
    let _ = fmt().with_env_filter(filter).try_init();
    Ok(())
}

async fn handle_discover(workflow: &WorkflowRuntime, args: DiscoverArgs) -> Result<()> {
    let mut request = DiscoveryRequest::new(args.query);
    request.site = args.site;
    request.provider = args.provider.into();
    request.limit = args.limit.clamp(1, 250);
    request.country = args.country;
    request.lang = args.lang;
    request.include_subdomains = args.include_subdomains;
    request.validate = args.validate;

    if request.validate {
        let result = workflow
            .discover_and_validate(request, args.tags, HashMap::new())
            .await
            .map_err(anyhow::Error::msg)?;
        render_payload(args.output, serde_json::to_value(result)?)
    } else {
        let result = workflow.discover(request).await.map_err(anyhow::Error::msg)?;
        render_payload(args.output, serde_json::to_value(result)?)
    }
}

async fn handle_scan(workflow: &WorkflowRuntime, url: String, tags: Vec<String>, output: OutputFormat) -> Result<()> {
    let target = OsintTarget {
        id: Uuid::new_v4(),
        url,
        tags,
        metadata: HashMap::new(),
        submitted_at: Utc::now(),
    };

    let result = workflow.validate_target(target).await.map_err(anyhow::Error::msg)?;
    render_payload(output, serde_json::to_value(result)?)
}

async fn handle_validate(workflow: &WorkflowRuntime, path: &Path, output: OutputFormat) -> Result<()> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let urls: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();

    let mut results = Vec::with_capacity(urls.len());
    for url in urls {
        let target = OsintTarget {
            id: Uuid::new_v4(),
            url,
            tags: Vec::new(),
            metadata: HashMap::new(),
            submitted_at: Utc::now(),
        };
        results.push(workflow.validate_target(target).await.map_err(anyhow::Error::msg)?);
    }

    render_payload(output, json!(results))
}

fn show_config(config: &RavenConfig) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(config)?);
    Ok(())
}

fn list_plugins() -> Result<()> {
    let payload = json!({
        "discovery_providers": ["seed_file", "serper", "exa"],
        "scrapers": ["generic_http"],
        "agents": ["availability", "ssl", "content_analyzer"],
        "llm_providers": ["deepseek"]
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn render_payload(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![Cell::new("Field"), Cell::new("Value")]);

            if let Some(obj) = payload.as_object() {
                for (key, value) in obj {
                    let rendered = if value.is_string() {
                        value.as_str().unwrap_or_default().to_string()
                    } else {
                        serde_json::to_string_pretty(value)?
                    };
                    table.add_row(vec![Cell::new(key), Cell::new(rendered)]);
                }
            }

            println!("{table}");
        }
    }

    Ok(())
}
