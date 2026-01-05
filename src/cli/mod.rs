use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod commands;

use crate::{cli::commands::add::AddArgs, store::Store};

#[derive(Parser)]
#[command(name = "ector")]
#[command(about = "NPM Supply Chain Security Scanner")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Add a new attack to the database
    Add {
        /// Attack name
        #[arg(long)]
        name: Option<String>,

        /// Discovery date (YYYY-MM-DD)
        #[arg(long)]
        date: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// CVE number (optional)
        #[arg(long)]
        cve: Option<String>,

        /// Compromised packages (package@version, can be specified multiple times)
        #[arg(long = "package", short = 'p')]
        packages: Vec<String>,

        /// Code signatures (can be specified multiple times)
        #[arg(long = "signature", short = 's')]
        signatures: Vec<String>,

        /// Payload files (can be specified multiple times)
        #[arg(long = "payload", short = 'f')]
        payload_files: Vec<String>,

        /// Workflow paths (can be specified multiple times)
        #[arg(long = "workflow", short = 'w')]
        workflow_paths: Vec<String>,

        /// Interactive mode (prompt for all fields)
        #[arg(short, long)]
        interactive: bool,
    },

    /// Check for compromised packages
    Check {
        /// Check all known attacks
        #[arg(long, conflicts_with = "attack")]
        all: bool,

        /// Check specific attack by name
        #[arg(short = 'a', long, conflicts_with = "all")]
        attack: Option<String>,

        /// Directory to scan
        #[arg(short, long, default_value = ".")]
        directory: PathBuf,

        /// Interactive mode: select attack from list
        #[arg(short, long)]
        interactive: bool,
    },

    /// List all known attacks
    List,
}

impl Cli {
    pub fn run(self, store: impl Store) -> Result<()> {
        match self.command {
            Commands::Add {
                name,
                date,
                description,
                cve,
                packages,
                signatures,
                payload_files,
                workflow_paths,
                interactive,
            } => commands::add::handle(
                store,
                AddArgs {
                    name,
                    date,
                    description,
                    cve,
                    packages,
                    signatures,
                    payload_files,
                    workflow_paths,
                    interactive,
                },
            ),

            Commands::List => commands::list::handle(store),

            Commands::Check {
                all,
                attack,
                directory,
                interactive,
            } => commands::check::handle(store, all, attack, &directory, interactive),
        }
    }
}
