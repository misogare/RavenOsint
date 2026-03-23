use anyhow::{Context, Result};
use chrono::Utc;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
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
    let workflow =
        WorkflowRuntime::new(&config, Arc::clone(&store)).map_err(anyhow::Error::msg)?;

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
        render_discovery_workflow(args.output, serde_json::to_value(result)?)
    } else {
        let result = workflow
            .discover(request)
            .await
            .map_err(anyhow::Error::msg)?;
        render_discovery_result(args.output, serde_json::to_value(result)?)
    }
}

async fn handle_scan(
    workflow: &WorkflowRuntime,
    url: String,
    tags: Vec<String>,
    output: OutputFormat,
) -> Result<()> {
    let target = OsintTarget {
        id: Uuid::new_v4(),
        url,
        tags,
        metadata: HashMap::new(),
        submitted_at: Utc::now(),
    };

    let result = workflow
        .validate_target(target)
        .await
        .map_err(anyhow::Error::msg)?;
    render_generic(output, serde_json::to_value(result)?)
}

async fn handle_validate(
    workflow: &WorkflowRuntime,
    path: &Path,
    output: OutputFormat,
) -> Result<()> {
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
        results.push(
            workflow
                .validate_target(target)
                .await
                .map_err(anyhow::Error::msg)?,
        );
    }

    render_generic(output, json!(results))
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

// ─────────────────────────────────────────────────────────────────────────────
// Renderers
// ─────────────────────────────────────────────────────────────────────────────

/// Render a `DiscoveryResult` payload.
///
/// - `Json`  — pretty-printed JSON (machine-readable, pipeable to `jq`)
/// - `Table` — purpose-built URL table with rank, domain, title columns
/// - `Urls`  — one URL per line, for piping directly into `raven validate`
fn render_discovery_result(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            render_discovery_table(&payload);
        }
        OutputFormat::Urls => {
            render_url_lines(&payload, "urls");
        }
    }
    Ok(())
}

/// Render a `DiscoveryWorkflowResult` (discovery + validations).
fn render_discovery_workflow(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            // Show discovered URLs first.
            if let Some(discovery) = payload.get("discovery") {
                eprintln!("── Discovery ─────────────────────────────────────────────────────────");
                render_discovery_table(discovery);
            }
            // Then show validation summary.
            if let Some(validations) = payload.get("validations").and_then(|v| v.as_array()) {
                if !validations.is_empty() {
                    eprintln!();
                    eprintln!("── Validation ────────────────────────────────────────────────────────");
                    render_validation_summary_table(validations);
                }
            }
        }
        OutputFormat::Urls => {
            // Emit only validated URLs for piping, falling back to discovered URLs.
            let validated = payload
                .get("validations")
                .and_then(|v| v.as_array())
                .filter(|v| !v.is_empty());

            if let Some(validations) = validated {
                for v in validations {
                    if let Some(url) = v.pointer("/target/url").and_then(|u| u.as_str()) {
                        println!("{url}");
                    }
                }
            } else if let Some(discovery) = payload.get("discovery") {
                render_url_lines(discovery, "urls");
            }
        }
    }
    Ok(())
}

/// Generic key-value table for arbitrary JSON payloads (scan results, config, etc.).
fn render_generic(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Urls => {
            // For a scan result, just emit the URL.
            if let Some(url) = payload.pointer("/target/url").and_then(|v| v.as_str()) {
                println!("{url}");
            } else if let Some(arr) = payload.as_array() {
                for item in arr {
                    if let Some(url) = item.pointer("/target/url").and_then(|v| v.as_str()) {
                        println!("{url}");
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
        }
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("Field").add_attribute(Attribute::Bold),
                    Cell::new("Value").add_attribute(Attribute::Bold),
                ]);

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

// ─────────────────────────────────────────────────────────────────────────────
// Table helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Render a discovery result as a readable URL table.
fn render_discovery_table(payload: &serde_json::Value) {
    let empty = vec![];
    let urls = payload
        .get("urls")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    let job_id = payload
        .get("job_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let total = payload
        .get("total_discovered")
        .and_then(|v| v.as_u64())
        .unwrap_or(urls.len() as u64);

    eprintln!("Job: {job_id}  |  Discovered: {total}");

    if urls.is_empty() {
        eprintln!("(no URLs discovered)");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("#").add_attribute(Attribute::Bold),
            Cell::new("URL").add_attribute(Attribute::Bold),
            Cell::new("Domain").add_attribute(Attribute::Bold),
            Cell::new("Provider").add_attribute(Attribute::Bold),
            Cell::new("Type").add_attribute(Attribute::Bold),
            Cell::new("Title").add_attribute(Attribute::Bold),
        ]);

    for (i, url) in urls.iter().enumerate() {
        let rank = url
            .get("rank")
            .and_then(|v| v.as_u64())
            .map(|r| r.to_string())
            .unwrap_or_else(|| (i + 1).to_string());

        table.add_row(vec![
            Cell::new(rank),
            Cell::new(url.get("url").and_then(|v| v.as_str()).unwrap_or("-")),
            Cell::new(url.get("domain").and_then(|v| v.as_str()).unwrap_or("-")),
            Cell::new(url.get("provider").and_then(|v| v.as_str()).unwrap_or("-")),
            Cell::new(
                url.get("discovery_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
            ),
            Cell::new(
                url.get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect::<String>(),
            ),
        ]);
    }

    println!("{table}");
}

/// Render a compact validation summary table for chained discover-and-validate results.
fn render_validation_summary_table(validations: &[serde_json::Value]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("URL").add_attribute(Attribute::Bold),
            Cell::new("Status").add_attribute(Attribute::Bold),
            Cell::new("Confidence").add_attribute(Attribute::Bold),
        ]);

    for v in validations {
        let url = v
            .pointer("/target/url")
            .and_then(|u| u.as_str())
            .unwrap_or("-");
        let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
        let confidence = v
            .get("confidence")
            .and_then(|c| c.as_f64())
            .unwrap_or(0.0);

        let status_cell = match status {
            "active" => Cell::new(status).fg(Color::Green),
            "suspicious" => Cell::new(status).fg(Color::Yellow),
            "malicious" => Cell::new(status).fg(Color::Red),
            "down" => Cell::new(status).fg(Color::DarkGrey),
            _ => Cell::new(status),
        };

        table.add_row(vec![
            Cell::new(url),
            status_cell,
            Cell::new(format!("{:.0}%", confidence * 100.0)),
        ]);
    }

    println!("{table}");
}

/// Print one URL per line from a JSON payload — for piping into `raven validate`.
fn render_url_lines(payload: &serde_json::Value, array_key: &str) {
    if let Some(urls) = payload.get(array_key).and_then(|v| v.as_array()) {
        for url in urls {
            if let Some(u) = url.get("url").and_then(|v| v.as_str()) {
                println!("{u}");
            }
        }
    }
}