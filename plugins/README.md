# Community Plugins

Place third-party scraper, agent, or analyzer crates here.
Each plugin must implement the relevant trait from `raven-core`:
- `ScraperPlugin` for scrapers
- `AgentPlugin` for agents/validators
- `LlmProvider` for alternative LLM backends

See `crates/raven-core/src/lib.rs` for trait definitions.
