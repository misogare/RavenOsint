use anyhow::{Context, Result};
use chrono::Utc;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use raven_api::pipeline::WorkflowRuntime;
use raven_core::{DiscoveryRequest, OsintTarget, RavenConfig};
use raven_storage::{new_store, ListParams};
use serde_json::json;
use std::{collections::HashMap, fs, path::Path, sync::Arc};
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

use crate::commands::{
    Cli, Command, ConfigCommand, DiscoverArgs, DiscoveriesCommand, DiscoveriesGetArgs,
    DiscoveriesListArgs, OutputFormat, ResultsCommand, ResultsGetArgs, ResultsListArgs,
};

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

    match &cli.command {
        // Results and discoveries views only need the store — no workflow needed.
        Command::Results(args) => {
            return match &args.command {
                ResultsCommand::List(a) => handle_results_list(Arc::clone(&store), a).await,
                ResultsCommand::Get(a) => handle_results_get(Arc::clone(&store), a).await,
            };
        }
        Command::Discoveries(args) => {
            return match &args.command {
                DiscoveriesCommand::List(a) => handle_discoveries_list(Arc::clone(&store), a).await,
                DiscoveriesCommand::Get(a) => handle_discoveries_get(Arc::clone(&store), a).await,
            };
        }
        Command::Config(args) => {
            return match args.command {
                ConfigCommand::Show => show_config(&config),
            };
        }
        Command::Plugin(_) => {
            return list_plugins();
        }
        _ => {}
    }

    // Commands that need the full workflow runtime.
    let workflow = WorkflowRuntime::new(&config, Arc::clone(&store)).map_err(anyhow::Error::msg)?;

    match cli.command {
        Command::Discover(args) => handle_discover(&workflow, args).await,
        Command::Scan(args) => handle_scan(&workflow, args.url, args.tags, args.output).await,
        Command::Validate(args) => handle_validate(&workflow, &args.file, args.output).await,
        Command::Results(_) | Command::Discoveries(_) | Command::Config(_) | Command::Plugin(_) => {
            unreachable!()
        }
    }
}

fn init_tracing(level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level).or_else(|_| EnvFilter::try_new("info"))?;
    let _ = fmt().with_env_filter(filter).try_init();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Results viewing
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_results_list(
    store: Arc<dyn raven_storage::ResultStore>,
    args: &ResultsListArgs,
) -> Result<()> {
    let params = ListParams {
        limit: args.limit,
        offset: args.offset,
    };
    let total = store.count().await.map_err(anyhow::Error::msg)?;
    let items = store.list(params).await.map_err(anyhow::Error::msg)?;

    // Optional status filter (client-side — avoids adding a filter param to the trait).
    let items: Vec<_> = match &args.status {
        Some(filter) => items
            .into_iter()
            .filter(|r| r.status.to_string().eq_ignore_ascii_case(filter))
            .collect(),
        None => items,
    };

    match args.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "total": total,
                    "showing": items.len(),
                    "offset": args.offset,
                    "items": items,
                }))?
            );
        }
        OutputFormat::Urls => {
            for item in &items {
                println!("{}", item.target.url);
            }
        }
        OutputFormat::Table => {
            eprintln!(
                "Scan results — showing {} of {} total (offset {})",
                items.len(),
                total,
                args.offset
            );

            if items.is_empty() {
                eprintln!("(no results stored yet — run `raven scan <url>` to get started)");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("Job ID").add_attribute(Attribute::Bold),
                    Cell::new("URL").add_attribute(Attribute::Bold),
                    Cell::new("Status").add_attribute(Attribute::Bold),
                    Cell::new("Confidence").add_attribute(Attribute::Bold),
                    Cell::new("LLM").add_attribute(Attribute::Bold),
                    Cell::new("Completed").add_attribute(Attribute::Bold),
                ]);

            for item in &items {
                let status_str = item.status.to_string();
                let status_cell = status_colour(&status_str);
                let llm_status = item.llm_verdict.status.to_string();

                table.add_row(vec![
                    Cell::new(&item.job_id.to_string()),
                    Cell::new(truncate_url(&item.target.url, 55)),
                    status_cell,
                    Cell::new(format!("{:.0}%", item.confidence * 100.0)),
                    status_colour(&llm_status),
                    Cell::new(item.completed_at.format("%Y-%m-%d %H:%M").to_string()),
                ]);
            }

            println!("{table}");
            eprintln!("\nTip: use `raven results get <job_id>` to see full details for a result.");
        }
    }
    Ok(())
}

async fn handle_results_get(
    store: Arc<dyn raven_storage::ResultStore>,
    args: &ResultsGetArgs,
) -> Result<()> {
    let job_id = Uuid::parse_str(&args.job_id)
        .with_context(|| format!("'{}' is not a valid UUID", args.job_id))?;

    let result = store.find_by_id(job_id).await.map_err(anyhow::Error::msg)?;

    match args.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Urls => {
            println!("{}", result.target.url);
        }
        OutputFormat::Table => {
            // ── Summary ──────────────────────────────────────────────────────
            let mut summary = Table::new();
            summary
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("Field").add_attribute(Attribute::Bold),
                    Cell::new("Value").add_attribute(Attribute::Bold),
                ]);

            summary.add_row(vec![
                Cell::new("Job ID"),
                Cell::new(result.job_id.to_string()),
            ]);
            summary.add_row(vec![Cell::new("URL"), Cell::new(&result.target.url)]);
            summary.add_row(vec![
                Cell::new("Status"),
                status_colour(&result.status.to_string()),
            ]);
            summary.add_row(vec![
                Cell::new("Confidence"),
                Cell::new(format!("{:.1}%", result.confidence * 100.0)),
            ]);
            summary.add_row(vec![
                Cell::new("Completed"),
                Cell::new(
                    result
                        .completed_at
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                ),
            ]);

            if let Some(ref scrape) = result.scraper_output {
                summary.add_row(vec![Cell::new("Final URL"), Cell::new(&scrape.final_url)]);
                summary.add_row(vec![
                    Cell::new("Status Code"),
                    Cell::new(scrape.status_code.to_string()),
                ]);
                summary.add_row(vec![
                    Cell::new("Latency"),
                    Cell::new(format!("{}ms", scrape.latency_ms)),
                ]);
                summary.add_row(vec![
                    Cell::new("SSL Valid"),
                    Cell::new(
                        scrape
                            .ssl_valid
                            .map(|v| if v { "✓" } else { "✗" })
                            .unwrap_or("n/a"),
                    ),
                ]);
                if let Some(days) = scrape.ssl_expiry_days {
                    summary.add_row(vec![
                        Cell::new("SSL Expiry"),
                        Cell::new(format!("{days} days")),
                    ]);
                }
            }

            println!("{summary}");

            // ── LLM verdict ──────────────────────────────────────────────────
            eprintln!("\n── LLM Verdict ───────────────────────────────────────────────────────");
            let mut llm_table = Table::new();
            llm_table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);
            llm_table.set_header(vec![
                Cell::new("Status").add_attribute(Attribute::Bold),
                Cell::new("Confidence").add_attribute(Attribute::Bold),
                Cell::new("Reasoning").add_attribute(Attribute::Bold),
            ]);
            llm_table.add_row(vec![
                status_colour(&result.llm_verdict.status.to_string()),
                Cell::new(format!("{:.1}%", result.llm_verdict.confidence * 100.0)),
                Cell::new(&result.llm_verdict.reasoning),
            ]);
            println!("{llm_table}");

            // ── Agent reports ─────────────────────────────────────────────────
            if !result.agent_reports.is_empty() {
                eprintln!(
                    "\n── Agent Reports ─────────────────────────────────────────────────────"
                );
                let mut agent_table = Table::new();
                agent_table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);
                agent_table.set_header(vec![
                    Cell::new("Agent").add_attribute(Attribute::Bold),
                    Cell::new("Passed").add_attribute(Attribute::Bold),
                    Cell::new("Delta").add_attribute(Attribute::Bold),
                    Cell::new("Findings").add_attribute(Attribute::Bold),
                ]);

                for report in &result.agent_reports {
                    let pass_cell = if report.passed {
                        Cell::new("✓ pass").fg(Color::Green)
                    } else {
                        Cell::new("✗ fail").fg(Color::Red)
                    };

                    let findings: String = report
                        .details
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}"))
                        .collect::<Vec<_>>()
                        .join("\n");

                    let delta_str = format!("{:+.2}", report.confidence_delta);
                    let delta_cell = if report.confidence_delta >= 0.0 {
                        Cell::new(delta_str).fg(Color::Green)
                    } else {
                        Cell::new(delta_str).fg(Color::Red)
                    };

                    agent_table.add_row(vec![
                        Cell::new(&report.agent_name),
                        pass_cell,
                        delta_cell,
                        Cell::new(findings),
                    ]);
                }
                println!("{agent_table}");
            }

            // ── Tags / metadata ───────────────────────────────────────────────
            if !result.target.tags.is_empty() {
                eprintln!("\nTags: {}", result.target.tags.join(", "));
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Discoveries viewing
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_discoveries_list(
    store: Arc<dyn raven_storage::ResultStore>,
    args: &DiscoveriesListArgs,
) -> Result<()> {
    let params = ListParams {
        limit: args.limit,
        offset: args.offset,
    };
    let total = store.discovery_count().await.map_err(anyhow::Error::msg)?;
    let items = store
        .list_discoveries(params)
        .await
        .map_err(anyhow::Error::msg)?;

    match args.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "total": total,
                    "showing": items.len(),
                    "offset": args.offset,
                    "items": items,
                }))?
            );
        }
        OutputFormat::Urls => {
            for item in &items {
                for url in &item.urls {
                    println!("{}", url.url);
                }
            }
        }
        OutputFormat::Table => {
            eprintln!(
                "Discovery jobs — showing {} of {} total (offset {})",
                items.len(),
                total,
                args.offset
            );

            if items.is_empty() {
                eprintln!(
                    "(no discovery jobs stored yet — run `raven discover <query>` to get started)"
                );
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("Job ID").add_attribute(Attribute::Bold),
                    Cell::new("Query").add_attribute(Attribute::Bold),
                    Cell::new("Provider").add_attribute(Attribute::Bold),
                    Cell::new("URLs Found").add_attribute(Attribute::Bold),
                    Cell::new("Validated?").add_attribute(Attribute::Bold),
                    Cell::new("Completed").add_attribute(Attribute::Bold),
                ]);

            for item in &items {
                table.add_row(vec![
                    Cell::new(&item.job_id.to_string()),
                    Cell::new(item.request.query.chars().take(45).collect::<String>()),
                    Cell::new(format!("{:?}", item.request.provider).to_lowercase()),
                    Cell::new(item.total_discovered.to_string()),
                    Cell::new(if item.request.validate { "yes" } else { "no" }),
                    Cell::new(item.completed_at.format("%Y-%m-%d %H:%M").to_string()),
                ]);
            }

            println!("{table}");
            eprintln!("\nTip: use `raven discoveries get <job_id>` to see all URLs from a job.");
        }
    }
    Ok(())
}

async fn handle_discoveries_get(
    store: Arc<dyn raven_storage::ResultStore>,
    args: &DiscoveriesGetArgs,
) -> Result<()> {
    let job_id = Uuid::parse_str(&args.job_id)
        .with_context(|| format!("'{}' is not a valid UUID", args.job_id))?;

    let result = store
        .find_discovery_by_id(job_id)
        .await
        .map_err(anyhow::Error::msg)?;

    match args.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Urls => {
            for url in &result.urls {
                println!("{}", url.url);
            }
        }
        OutputFormat::Table => {
            eprintln!(
                "Discovery job {} — query: \"{}\" | provider: {:?} | {} URLs found",
                &result.job_id.to_string(),
                result.request.query,
                result.request.provider,
                result.total_discovered,
            );

            if result.urls.is_empty() {
                eprintln!("(no URLs in this job)");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("#").add_attribute(Attribute::Bold),
                    Cell::new("URL").add_attribute(Attribute::Bold),
                    Cell::new("Domain").add_attribute(Attribute::Bold),
                    Cell::new("Type").add_attribute(Attribute::Bold),
                    Cell::new("Confidence").add_attribute(Attribute::Bold),
                    Cell::new("Title / Snippet").add_attribute(Attribute::Bold),
                ]);

            for (i, url) in result.urls.iter().enumerate() {
                let snippet = url
                    .title
                    .as_deref()
                    .or(url.snippet.as_deref())
                    .unwrap_or("")
                    .chars()
                    .take(55)
                    .collect::<String>();

                table.add_row(vec![
                    Cell::new(i + 1),
                    Cell::new(truncate_url(&url.url, 55)),
                    Cell::new(&url.domain),
                    Cell::new(format!("{:?}", url.discovery_type).to_lowercase()),
                    Cell::new(format!("{:.0}%", url.confidence * 100.0)),
                    Cell::new(snippet),
                ]);
            }

            println!("{table}");
            eprintln!("\nTip: export as URLs with `--output urls` and pipe into `raven validate`.");
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Existing command handlers
// ─────────────────────────────────────────────────────────────────────────────

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
        id: uuid::Uuid::new_v4(),
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
    let body =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    let urls: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();

    let mut results = Vec::with_capacity(urls.len());
    for url in urls {
        let target = OsintTarget {
            id: uuid::Uuid::new_v4(),
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
        "discovery_providers": ["seed_file", "serper", "exa", "censys", "virustotal"],
        "scrapers": ["generic_http"],
        "agents": ["availability", "ssl", "content_analyzer"],
        "llm_providers": ["deepseek", "openai", "kimi", "github_copilot", "gemini", "claude"],
        "storage_backends": ["sqlite", "postgres", "duckdb"]
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Renderers
// ─────────────────────────────────────────────────────────────────────────────

fn render_discovery_result(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&payload)?),
        OutputFormat::Table => render_discovery_table(&payload),
        OutputFormat::Urls => render_url_lines(&payload, "urls"),
    }
    Ok(())
}

fn render_discovery_workflow(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&payload)?),
        OutputFormat::Table => {
            if let Some(d) = payload.get("discovery") {
                eprintln!(
                    "── Discovery ──────────────────────────────────────────────────────────"
                );
                render_discovery_table(d);
            }
            if let Some(vs) = payload.get("validations").and_then(|v| v.as_array()) {
                if !vs.is_empty() {
                    eprintln!(
                        "\n── Validation ─────────────────────────────────────────────────────────"
                    );
                    render_validation_summary_table(vs);
                }
            }
        }
        OutputFormat::Urls => {
            render_url_lines(payload.get("discovery").unwrap_or(&payload), "urls")
        }
    }
    Ok(())
}

fn render_generic(output: OutputFormat, payload: serde_json::Value) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&payload)?),
        OutputFormat::Urls => {
            if let Some(u) = payload.pointer("/target/url").and_then(|v| v.as_str()) {
                println!("{u}");
            } else if let Some(arr) = payload.as_array() {
                for item in arr {
                    if let Some(u) = item.pointer("/target/url").and_then(|v| v.as_str()) {
                        println!("{u}");
                    }
                }
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
                for (k, v) in obj {
                    let rendered = if v.is_string() {
                        v.as_str().unwrap_or_default().to_string()
                    } else {
                        serde_json::to_string_pretty(v)?
                    };
                    table.add_row(vec![Cell::new(k), Cell::new(rendered)]);
                }
            }
            println!("{table}");
        }
    }
    Ok(())
}

fn render_discovery_table(payload: &serde_json::Value) {
    let empty = vec![];
    let urls = payload
        .get("urls")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let job = payload
        .get("job_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let total = payload
        .get("total_discovered")
        .and_then(|v| v.as_u64())
        .unwrap_or(urls.len() as u64);

    eprintln!("Job: {job}  |  Discovered: {total}");
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
            Cell::new("Confidence").add_attribute(Attribute::Bold),
            Cell::new("Title").add_attribute(Attribute::Bold),
        ]);

    for (i, url) in urls.iter().enumerate() {
        let rank = url
            .get("rank")
            .and_then(|v| v.as_u64())
            .map(|r| r.to_string())
            .unwrap_or_else(|| (i + 1).to_string());
        let confidence = url
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        table.add_row(vec![
            Cell::new(rank),
            Cell::new(truncate_url(
                url.get("url").and_then(|v| v.as_str()).unwrap_or("-"),
                55,
            )),
            Cell::new(url.get("domain").and_then(|v| v.as_str()).unwrap_or("-")),
            Cell::new(url.get("provider").and_then(|v| v.as_str()).unwrap_or("-")),
            Cell::new(format!("{:.0}%", confidence * 100.0)),
            Cell::new(
                url.get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(40)
                    .collect::<String>(),
            ),
        ]);
    }
    println!("{table}");
}

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
        let status = v
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        let conf = v.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);

        table.add_row(vec![
            Cell::new(truncate_url(url, 60)),
            status_colour(status),
            Cell::new(format!("{:.0}%", conf * 100.0)),
        ]);
    }
    println!("{table}");
}

fn render_url_lines(payload: &serde_json::Value, key: &str) {
    if let Some(urls) = payload.get(key).and_then(|v| v.as_array()) {
        for url in urls {
            if let Some(u) = url.get("url").and_then(|v| v.as_str()) {
                println!("{u}");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn status_colour(status: &str) -> Cell {
    match status {
        "active" => Cell::new(status).fg(Color::Green),
        "suspicious" => Cell::new(status).fg(Color::Yellow),
        "malicious" => Cell::new(status).fg(Color::Red),
        "down" => Cell::new(status).fg(Color::DarkGrey),
        _ => Cell::new(status),
    }
}

fn truncate_url(url: &str, max: usize) -> String {
    if url.len() <= max {
        url.to_string()
    } else {
        format!("{}…", &url[..max.saturating_sub(1)])
    }
}
