use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use inquire::Text;

use crate::core::threat::{Threat, ThreatName};
use crate::scanner::FSScanner;
use crate::store::Store;

pub fn handle(
    store: impl Store,
    all: bool,
    threat: Option<String>,
    dir: &Path,
    interactive: bool,
) -> Result<()> {
    if !dir.exists() {
        anyhow::bail!("Directory does not exist: {}", dir.display());
    }

    let threats = if all {
        load_all_threats(&store)?
    } else if let Some(threat_name) = threat {
        load_specific_threat(&store, &threat_name)?
    } else if interactive {
        load_interactive_threat(&store)?
    } else {
        anyhow::bail!("Must specify --all, --threat <name>, or --interactive");
    };

    println!();
    println!("{}", "=== Starting Security Scan ===".bold().cyan());
    println!("Directory: {}", dir.display());
    println!();

    let scanner = FSScanner::new(threats);

    let result = scanner.scan_directory(dir)?;

    print_final_report(&result)?;

    if result.has_issues() {
        std::process::exit(1);
    }

    Ok(())
}

fn load_all_threats(store: &impl Store) -> Result<Vec<Threat>> {
    println!("{} Loading all known threats...", "[INFO]".blue());

    let threats = store.get_all()?;

    println!("{} Loaded {} threats", "[SUCCESS]".green(), threats.len());

    for threat in &threats {
        println!(
            "  • {} ({} packages)",
            threat.name.as_str().cyan(),
            threat.package_count()
        );
    }
    println!();

    Ok(threats)
}

fn load_specific_threat(store: &impl Store, threat_name: &str) -> Result<Vec<Threat>> {
    println!(
        "{} Loading threat: {}",
        "[INFO]".blue(),
        threat_name.yellow()
    );

    let name = ThreatName::new(threat_name)?;
    let threat = store.get_by_name(&name)?;

    println!(
        "{} Loaded: {} ({} packages)",
        "[SUCCESS]".green(),
        threat.name.as_str(),
        threat.package_count()
    );
    println!();

    Ok(vec![threat])
}

fn load_interactive_threat(store: &impl Store) -> Result<Vec<Threat>> {
    println!("{} Interactive threat selection", "[INFO]".blue());

    let threats = store.get_all()?;

    if threats.is_empty() {
        anyhow::bail!("No threats available. Use 'ector add' to register threats.");
    }

    println!();
    println!("Available threats:");
    for (i, threat) in threats.iter().enumerate() {
        println!(
            "  {}. {} ({} packages)",
            i + 1,
            threat.name.as_str().cyan(),
            threat.package_count()
        );
    }
    println!();

    let selection = Text::new("Select threat number (or 'all'):")
        .with_placeholder("1")
        .prompt()?;

    if selection.trim().to_lowercase() == "all" {
        println!("{} Selected: All threats", "[INFO]".blue());
        Ok(threats)
    } else {
        let idx = selection
            .parse::<usize>()
            .context("Invalid number")?
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("Number must be >= 1"))?;

        let threat = threats
            .into_iter()
            .nth(idx)
            .ok_or_else(|| anyhow::anyhow!("Invalid selection"))?;

        println!(
            "{} Selected: {}",
            "[INFO]".blue(),
            threat.name.as_str().yellow()
        );
        println!();

        Ok(vec![threat])
    }
}

fn print_final_report(result: &crate::core::checker::ScanResult) -> Result<()> {
    println!("{}", "=== Final Report ===".bold().cyan());
    println!();
    println!("Packages checked: {}", result.packages_checked);
    println!("Files scanned:    {}", result.files_scanned);
    println!();

    if result.issues_found() == 0 {
        println!("{}", "✓ No issues found!".green().bold());
        println!(
            "{}",
            "Your project appears to be safe from known supply chain threats.".green()
        );
        return Ok(());
    }

    println!(
        "{}",
        format!("⚠ {} CRITICAL ISSUES FOUND", result.issues_found())
            .red()
            .bold()
    );
    println!();

    if !result.compromised_packages().is_empty() {
        println!("{}", "Compromised Packages:".red().bold());
        println!();
        for issue in result.compromised_packages() {
            println!(
                "  • {}@{} in {}",
                issue.package_name.yellow().bold(),
                issue.version,
                issue.location.dimmed()
            );
            println!("    Threat: {}", issue.threat_name.cyan());
        }
        println!();
    }

    if !result.malicious_code().is_empty() {
        println!("{}", "Malicious Code Detected:".red().bold());
        println!();
        for issue in result.malicious_code() {
            if let Some(line) = issue.line_number {
                println!(
                    "  • {} (line {})",
                    issue.file_path.yellow(),
                    line.to_string().cyan()
                );
            } else {
                println!("  • {}", issue.file_path.yellow());
            }
            println!("    Threat: {}", issue.threat_name.cyan());
            println!("    Signature: {}", issue.signature.dimmed());
        }
        println!();
    }

    if !result.payload_files().is_empty() {
        println!("{}", "Payload Files Found:".red().bold());
        println!();
        for issue in result.payload_files() {
            println!("  • {}", issue.file_path.yellow());
            println!("    Threat: {}", issue.threat_name.cyan());
            println!("    Type: {}", issue.payload_type.dimmed());
        }
        println!();
    }

    println!("{}", "Recommended Actions:".bold());
    println!("  1. Remove or update compromised packages immediately");
    println!("  2. Review your dependency tree for transitive dependencies");
    println!("  3. Check your package-lock.json or yarn.lock for version locks");
    println!("  4. Consider using npm audit or yarn audit for additional checks");
    println!();

    Ok(())
}
