use anyhow::Result;
use clap::Parser;
use ector::{cli::Cli, store::local::LocalStorage};
use std::fs;

fn main() -> Result<()> {
    // Get current directory or use a default data directory
    let current_dir = std::env::current_dir()?;
    let threats_dir = current_dir.join("threats");

    // Create threats directory if it doesn't exist
    fs::create_dir_all(&threats_dir)?;

    let cli = Cli::parse();
    let storage = LocalStorage::new(threats_dir);
    cli.run(storage)
}
