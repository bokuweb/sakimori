#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

mod cgroup;
mod cli;
mod doctor;
mod enforcer;
mod events;
mod install_gate;
mod loader;
mod policy;
mod resolve;
mod resolve_hostnames;
mod resolve_refresh;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cli::Cli::parse();
    cli::run(args).await
}
