# 🦅 RavenOSINT

> A multi-agent, fully modular OSINT framework written in Rust — built to detect phishing sites, malicious domains, and suspicious web infrastructure at scale.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Cross Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

---

> ⚠️ **Educational Use Only** — RavenOSINT is built for security researchers, threat intelligence analysts, and educators. Only scan domains and URLs you own or have explicit written permission to analyse. The authors are not responsible for misuse.

---

## What is RavenOSINT?

RavenOSINT is a cross-platform OSINT (Open Source Intelligence) framework for **automated phishing site detection and malicious domain analysis**. It combines:

- **Automated discovery** — finds candidate URLs using search engines and seed lists
- **Multi-agent validation** — runs parallel checks for SSL health, availability, content signals, and redirect chains
- **LLM verification** — passes findings to DeepSeek for AI-powered classification
- **Persistent storage** — saves all results to SQLite or PostgreSQL for later review
- **REST API + CLI** — use it interactively, in scripts, or as a backend service

Built entirely in Rust for performance, memory safety, and true cross-platform support (Windows, Linux, macOS).
![alt text](image-1.png)

![alt text](image-2.png)
---

## Related Work

This tool was built alongside and used in **[ cybercrime research repository](https://github.com/misogare/awesome-cybercrimefs)** — a collection of threat intelligence notes, phishing campaign analysis, and infrastructure research. RavenOSINT is the automation layer behind that work.

---

## Architecture

```
RavenOSINT/
├── raven-core        # Shared types, traits, config contracts
├── raven-bus         # Async event bus (tokio broadcast)
├── raven-discovery   # URL discovery — Serper, Exa, seed files
├── raven-scraper     # HTTP engine — rate limiting, UA rotation, SSL checks
├── raven-agent       # Validation agents — availability, SSL, content analysis
├── raven-llm         # DeepSeek LLM integration for AI verdict
├── raven-storage     # SQLite / PostgreSQL persistence layer
├── raven-api         # Axum REST API with Swagger UI
└── raven-cli         # Clap CLI — the main binary
```

Every component is a separate crate with a clean trait boundary. Swap out any piece without touching the rest.

---

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later
- Git

### Build from source

```bash
git clone https://github.com/yourorg/raven-osint
cd raven-osint
cargo build --release
```

The binary will be at `target/release/raven` (or `raven.exe` on Windows).

### Environment setup

Create a `.env` file in the project root:

```env
# Required for Serper search (get a free key at serper.dev)
RAVEN__DISCOVERY__SERPER__API_KEY=your_serper_key_here

# Optional — Exa search (get a key at exa.ai)
RAVEN__DISCOVERY__EXA__API_KEY=your_exa_key_here

# Optional — DeepSeek LLM for AI-powered verdict
RAVEN__LLM__API_KEY=your_deepseek_key_here
```

Never commit your `.env` file. It is already in `.gitignore`.

---
![alt text](image.png)

## Quick Start

```bash
# Scan a single suspicious URL
raven scan https://suspicious-site.com

# Discover phishing-related URLs and scan them all
raven discover "paypal login phishing" --limit 10 --validate

# Validate a list of URLs from a file
raven validate urls.txt

# Start the REST API server
cargo run -p raven-api
```

---

## Detailed Usage

### `scan` — Analyse a single URL

Runs the full pipeline: scrape → agent checks → LLM verdict → save to DB.

```bash
raven scan <URL> [OPTIONS]

# Examples
raven scan https://example.com
raven scan https://suspicious-domain.net --output json
raven scan https://example.com --tags phishing,campaign-2024
```

**Options:**
| Flag | Description | Default |
|---|---|---|
| `--output` | `table` or `json` | `table` |
| `--tags` | Comma-separated tags for grouping results | none |

**What the pipeline does:**
1. Fetches the URL, follows redirects, records final URL, status code, latency, headers
2. Checks SSL validity and certificate details
3. Runs availability agent — flags suspicious cross-domain redirects
4. Runs content agent — scans for phishing keywords, missing security headers, suspicious JS
5. Sends findings to DeepSeek LLM for a final verdict
6. Saves everything to the database
7. Returns: `active` / `suspicious` / `malicious` / `down` / `unknown` with a confidence score

---

### `discover` — Find candidate URLs automatically

Queries search engines or reads seed files to build a list of candidate URLs. Optionally feeds them directly into the scan pipeline.

```bash
raven discover <QUERY> [OPTIONS]

# Basic search
raven discover "paypal phishing"

# Scope to a domain
raven discover "login" --site paypal.com

# Use Exa instead of Serper
raven discover "phishing kit" --provider exa --limit 20

# Discover and immediately scan everything found
raven discover "suspicious login page" --limit 10 --validate

# Output one URL per line (for scripting)
raven discover "query" --output urls

# Pipe discovered URLs into validate
raven discover "query" --limit 25 --output urls > found.txt
raven validate found.txt

# Filter by country and language
raven discover "phishing" --country us --lang en --limit 10

# Use a seed file (one URL/domain per line)
raven discover seeds.txt --provider seed_file
```

**Options:**
| Flag | Description | Default |
|---|---|---|
| `--site` | Restrict results to this domain | none |
| `--provider` | `serper`, `exa`, or `seed_file` | `serper` |
| `--limit` | Max URLs to return | `25` |
| `--country` | ISO country code (e.g. `us`, `de`) | none |
| `--lang` | Language code (e.g. `en`, `fr`) | none |
| `--include-subdomains` | Include subdomains when `--site` is set | `true` |
| `--validate` | Also run full scan on every discovered URL | `false` |
| `--tags` | Tags to attach to validation jobs | none |
| `--output` | `table`, `json`, or `urls` | `table` |

---

### `validate` — Scan every URL in a file

Reads a plain text file — one URL per line — and runs the full scan pipeline on each one.

```bash
raven validate <FILE> [OPTIONS]

# Examples
raven validate urls.txt
raven validate urls.txt --output json > results.json
```

**File format:**
```
# Lines starting with # are ignored
https://example.com
https://suspicious-site.net
https://another-domain.org
```

**Working with CSV files:**

`validate` expects plain text, not CSV. Convert first:

```powershell
# PowerShell — extract a "url" column from a CSV
Import-Csv targets.csv | Select-Object -ExpandProperty url | Out-File -Encoding utf8 urls.txt
raven validate urls.txt
```

```bash
# Bash — extract second column (adjust column number as needed)
cut -d',' -f2 targets.csv | tail -n +2 > urls.txt
raven validate urls.txt
```

---

### `config show` — Inspect loaded configuration

Prints the fully resolved configuration as JSON, including which API keys are loaded (values shown as empty strings if missing). Useful for debugging.

```bash
raven config show
```

---

### `plugin list` — List registered components

Shows all active discovery providers, scrapers, agents, and LLM backends.


```bash
raven plugin list
```

---

## REST API

Start the server:

```bash
cargo run -p raven-api
# Listening on http://127.0.0.1:3000
```

Interactive Swagger UI: **http://127.0.0.1:3000/docs**

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/scan` | Submit a URL for scanning |
| `GET` | `/results` | List all scan results |
| `GET` | `/results/{job_id}` | Get one scan result |
| `POST` | `/discover` | Start a discovery job |
| `GET` | `/discoveries` | List discovery results |
| `GET` | `/discoveries/{job_id}` | Get one discovery result |

### Example: Submit a scan

```bash
curl -X POST http://127.0.0.1:3000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.com",
    "tags": ["phishing", "manual-review"]
  }'
```

### Example: Run a discovery job

```bash
curl -X POST http://127.0.0.1:3000/discover \
  -H "Content-Type: application/json" \
  -d '{
    "query": "paypal login phishing",
    "provider": "serper",
    "limit": 10,
    "validate": true
  }'
```

### Example: Retrieve results

```bash
# List all results
curl http://127.0.0.1:3000/results

# Get a specific job
curl http://127.0.0.1:3000/results/70da917b-a309-45ef-bd53-84a62e67061b
```

---

## Configuration

All settings live in `config/default.toml`. Every value can be overridden with an environment variable using the pattern `RAVEN__<SECTION>__<KEY>`.

```toml
[database]
url = "sqlite://raven.db"         # or postgres://user:pass@host/db

[scraper]
rate_rpm       = 10               # requests per minute per domain
timeout_secs   = 30
max_redirects  = 10

[discovery]
default_provider    = "serper"
default_limit       = 25
validate_by_default = false       # set true to auto-scan all discovered URLs

[discovery.serper]
enabled  = true
base_url = "https://google.serper.dev/search"
api_key  = ""                     # use RAVEN__DISCOVERY__SERPER__API_KEY env var

[discovery.exa]
enabled  = true
base_url = "https://api.exa.ai/search"
api_key  = ""                     # use RAVEN__DISCOVERY__EXA__API_KEY env var

[llm]
provider    = "deepseek"
base_url    = "https://api.deepseek.com/v1"
model       = "deepseek-chat"
api_key     = ""                  # use RAVEN__LLM__API_KEY env var

[api]
host = "127.0.0.1"
port = 3000

[logging]
level  = "info"                   # off | error | warn | info | debug | trace
format = "pretty"                 # pretty | json
```

---

## Understanding Results

Every scan returns a result with these fields:

| Field | Description |
|---|---|
| `status` | `active`, `suspicious`, `malicious`, `down`, or `unknown` |
| `confidence` | 0.0 to 1.0 — how confident the system is in the verdict |
| `agent_reports` | Individual findings from each agent |
| `llm_verdict` | AI reasoning and classification |
| `scraper_output` | Raw HTTP data — headers, body, SSL info, redirect chain |

**Agent signals that increase suspicion:**
- Cross-domain redirect (e.g. `site.com` → `site.net`)
- Missing security headers (`x-frame-options`, `content-security-policy`)
- High latency suggesting evasive infrastructure
- Phishing keywords in page content
- Suspicious JavaScript patterns

---

## Roadmap

RavenOSINT is actively developed. Planned additions:

### Discovery providers
- **VirusTotal** — domain reputation, URL scan history, passive DNS
- **Censys** — internet-wide asset and certificate discovery
- **Shodan** — open port and service fingerprinting
- **Bing Search** — secondary search engine source
- **CommonCrawl** — bulk historical web data

### LLM providers
- **OpenAI GPT-4o** — as an alternative to DeepSeek
- **Ollama** — fully local LLM inference, no API key required
- **Anthropic Claude** — via the Messages API

### Agents
- **WHOIS agent** — registrar, registration date, registrant country
- **DNS agent** — MX, TXT, NS records, typosquatting detection
- **Screenshot agent** — headless browser capture for visual similarity scoring
- **Threat feed agent** — check against known phishing feed blocklists

### Platform
- **Web dashboard** — visual results browser
- **Webhook support** — push results to Slack, Discord, or custom endpoints
- **Batch API** — submit hundreds of URLs in one request
- **Export formats** — STIX 2.1, CSV, MISP event format

---

## Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p raven-scraper
cargo test -p raven-discovery

# With output (useful for debugging)
cargo test --workspace -- --nocapture
```

---

## Contributing

Pull requests are welcome. For major changes open an issue first. Please make sure `cargo test --workspace` passes and `cargo clippy` has no warnings before submitting.

---

## License

Licensed under the [Apache License 2.0](LICENSE).

---

*Built for threat intelligence research. Use responsibly.*