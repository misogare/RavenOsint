mod app;
mod commands;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    app::run(commands::Cli::parse()).await
}
