use anyhow::{Context, Result};
use chrono::NaiveDate;
use colored::Colorize;
use inquire::{Confirm, Text};

use crate::core::package::Package;
use crate::core::threat::{CveNumber, Threat, ThreatName};
use crate::store::Store;

pub struct AddArgs {
    pub name: Option<String>,
    pub date: Option<String>,
    pub description: Option<String>,
    pub cve: Option<String>,
    pub packages: Vec<String>,
    pub signatures: Vec<String>,
    pub payload_files: Vec<String>,
    pub workflow_paths: Vec<String>,
    pub interactive: bool,
}

impl AddArgs {
    fn all_none(&self) -> bool {
        self.name.is_none()
            && self.date.is_none()
            && self.description.is_none()
            && self.cve.is_none()
            && self.packages.is_empty()
            && self.signatures.is_empty()
            && self.payload_files.is_empty()
            && self.workflow_paths.is_empty()
    }
}

pub fn handle(store: impl Store, args: AddArgs) -> Result<()> {
    println!();
    println!("{}", "=== Add New Threat ===".bold().cyan());
    println!();

    if args.interactive || args.all_none() {
        handle_add_interactive(store)
    } else {
        handle_add_non_interactive(store, args)
    }
}

fn handle_add_non_interactive(store: impl Store, args: AddArgs) -> Result<()> {
    println!(
        "{} Non-interactive mode (using provided args)",
        "[INFO]".blue()
    );
    println!();

    let name_str = args
        .name
        .ok_or_else(|| anyhow::anyhow!("--name is required"))?;

    let name = match ThreatName::new(&name_str) {
        Ok(name) => name,
        Err(_) => {
            let slugified = ThreatName::slugify(&name_str);
            ThreatName::new(&slugified).context(format!(
                "Invalid threat name. Tried to slugify '{}' to '{}', but it's still invalid.",
                name_str, slugified
            ))?
        }
    };

    let date = NaiveDate::parse_from_str(
        &args
            .date
            .ok_or_else(|| anyhow::anyhow!("--date is required"))?,
        "%Y-%m-%d",
    )
    .context("Invalid date format. Use YYYY-MM-DD")?;

    let description = args
        .description
        .ok_or_else(|| anyhow::anyhow!("--description is required"))?;

    let cve_number = args.cve.map(CveNumber::new).transpose()?;

    let mut threat = Threat::new(name);
    threat.date = date;
    threat.description = description;
    threat.cve_number = cve_number;

    if !args.packages.is_empty() {
        println!(
            "{} Processing {} package(s)...",
            "[INFO]".blue(),
            args.packages.len()
        );
        for pkg_str in args.packages {
            match Package::try_from(pkg_str) {
                Ok(pkg) => {
                    threat.add_package(pkg.clone());
                    println!("  {} Added: {}", "✓".green(), &pkg);
                }
                Err(e) => {
                    println!("  {} Invalid package format: {}", "✗".red(), e);
                }
            }
        }
    }

    if !args.signatures.is_empty() {
        println!(
            "{} Adding {} signature(s)...",
            "[INFO]".blue(),
            args.signatures.len()
        );
        threat.add_signatures(args.signatures);
    }

    if !args.payload_files.is_empty() {
        println!(
            "{} Adding {} payload file(s)...",
            "[INFO]".blue(),
            args.payload_files.len()
        );
        threat.add_payload_files(args.payload_files);
    }

    if !args.workflow_paths.is_empty() {
        println!(
            "{} Adding {} workflow path(s)...",
            "[INFO]".blue(),
            args.workflow_paths.len()
        );
        threat.add_workflow_paths(args.workflow_paths);
    }

    println!();
    display_threat_summary(&threat)?;

    store.save(&threat)?;

    println!();
    println!("{} Threat saved successfully!", "✓".green());
    println!("File: {}.ect", threat.name.as_str());
    println!();

    Ok(())
}

fn handle_add_interactive(store: impl Store) -> Result<()> {
    println!("{} Interactive mode", "[INFO]".blue());
    println!();

    let name = loop {
        let input = Text::new("Threat Name:")
            .with_placeholder("Event Stream 2018")
            .prompt()?;

        match ThreatName::new(&input) {
            Ok(name) => break name,
            Err(_) => {
                // Auto-slugify and try again
                let suggested = ThreatName::slugify(&input);
                match ThreatName::new(&suggested) {
                    Ok(name) => {
                        println!("💡 Using slug: {}", suggested.green());
                        break name;
                    }
                    Err(e) => {
                        println!("{} Invalid name: {}", "✗".red(), e);
                        println!("Try again...");
                        println!();
                    }
                }
            }
        }
    };

    let date = loop {
        let date_str = Text::new("Date (YYYY-MM-DD):")
            .with_placeholder("2018-11-26")
            .prompt()?;

        match NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
            Ok(date) => break date,
            Err(e) => {
                println!("{} Invalid date format: {}", "✗".red(), e);
                println!("Please use YYYY-MM-DD format (e.g., 2025-01-15)");
            }
        }
    };

    let description = Text::new("Description:")
        .with_placeholder("Malicious code in event-stream dependency")
        .prompt()?;

    let cve_number = prompt_cve_interactive()?;

    let mut threat = Threat::new(name);
    threat.date = date;
    threat.description = description;
    threat.cve_number = cve_number;

    let packages = prompt_packages()?;
    let signatures = prompt_signatures()?;
    let payload_files = prompt_payload_files()?;
    let workflow_paths = prompt_workflow_paths()?;

    threat.add_signatures(signatures);
    threat.add_payload_files(payload_files);
    threat.add_workflow_paths(workflow_paths);

    for pkg in packages {
        threat.add_package(pkg);
    }

    display_threat_summary(&threat)?;

    let confirmed = Confirm::new("Save this threat?")
        .with_default(true)
        .prompt()?;

    if !confirmed {
        anyhow::bail!("Threat creation cancelled");
    }

    store.save(&threat)?;

    println!();
    println!("{} Threat saved successfully!", "✓".green());
    println!("File: {}.ect", threat.name.as_str());
    println!();

    Ok(())
}

fn prompt_cve_interactive() -> Result<Option<CveNumber>> {
    loop {
        let cve_str = Text::new("CVE Number (optional, press Enter to skip):")
            .with_placeholder("2018-3728")
            .prompt()?;

        if cve_str.trim().is_empty() {
            return Ok(None);
        }

        match CveNumber::new(format!("CVE-{}", &cve_str)) {
            Ok(cve) => return Ok(Some(cve)),
            Err(e) => {
                println!("{} Invalid CVE format: {}", "✗".red(), e);
                println!("CVE format must be: CVE-YYYY-NNNNN (e.g., CVE-2018-3728)");

                let retry = Confirm::new("Try again?").with_default(true).prompt()?;

                if !retry {
                    return Ok(None);
                }
            }
        }
    }
}

fn prompt_packages() -> Result<Vec<Package>> {
    println!();
    println!("{}", "Compromised Packages".bold());
    println!("Enter packages in format: package@version");
    println!("Examples: lodash@4.17.21, @babel/core@7.23.0");
    println!();

    let mut packages = Vec::new();

    loop {
        let input = Text::new("Package (or press Enter to finish):")
            .with_placeholder("lodash@4.17.21")
            .prompt()?;

        if input.trim().is_empty() {
            break;
        }

        match Package::try_from(input) {
            Ok(pkg) => {
                packages.push(pkg.clone());
                println!("{} Added: {}", "✓".green(), pkg);
            }
            Err(e) => {
                println!("{} Invalid package format: {}", "✗".red(), e);
                println!("Expected format: package@version or @scope/package@version");
                println!("Try again or press Enter to skip...");
            }
        }
    }

    if packages.is_empty() {
        println!("{} No packages added", "[WARNING]".yellow());
        println!("You can add them later by editing the .ect file");
    } else {
        println!("{} Added {} package(s)", "✓".green(), packages.len());
    }

    Ok(packages)
}

fn prompt_signatures() -> Result<Vec<String>> {
    println!();
    println!("{}", "Malicious Code Signatures".bold());
    println!("Enter strings/patterns to detect in source code");
    println!("Examples: eval(Buffer.from(, atob(, require('child_process')");
    println!();

    let mut signatures = Vec::new();

    loop {
        let sig = Text::new("Signature (or press Enter to finish):")
            .with_placeholder("eval(Buffer.from(")
            .prompt()?;

        if sig.trim().is_empty() {
            break;
        }

        signatures.push(sig);
        println!("{} Added", "✓".green());
    }

    if signatures.is_empty() {
        println!("{} No signatures added", "[INFO]".blue());
    } else {
        println!("{} Added {} signature(s)", "✓".green(), signatures.len());
    }

    Ok(signatures)
}

fn prompt_payload_files() -> Result<Vec<String>> {
    println!();
    println!("{}", "Payload Files".bold());
    println!("Enter filenames that indicate compromise");
    println!("Examples: malicious-setup.js, backdoor.sh");
    println!();

    let mut files = Vec::new();

    loop {
        let file = Text::new("Filename (or press Enter to finish):")
            .with_placeholder("malicious-setup.js")
            .prompt()?;

        if file.trim().is_empty() {
            break;
        }

        if file.contains("..") {
            println!("{} Path traversal not allowed", "✗".red());
            println!("Please enter a valid filename without '..'");
            continue;
        }

        files.push(file);
        println!("{} Added", "✓".green());
    }

    if files.is_empty() {
        println!("{} No payload files added", "[INFO]".blue());
    } else {
        println!("{} Added {} payload file(s)", "✓".green(), files.len());
    }

    Ok(files)
}

fn prompt_workflow_paths() -> Result<Vec<String>> {
    println!();
    println!("{}", "Workflow Paths".bold());
    println!("Enter GitHub Actions workflow paths");
    println!("Examples: .github/workflows/publish.yml, .github/workflows/build.yml");
    println!();

    let mut paths = Vec::new();

    loop {
        let path = Text::new("Workflow path (or press Enter to finish):")
            .with_placeholder(".github/workflows/publish.yml")
            .prompt()?;

        if path.trim().is_empty() {
            break;
        }

        if path.contains("..") {
            println!("{} Path traversal not allowed", "✗".red());
            println!("Please enter a valid path without '..'");
            continue;
        }

        paths.push(path);
        println!("{} Added", "✓".green());
    }

    if paths.is_empty() {
        println!("{} No workflow paths added", "[INFO]".blue());
    } else {
        println!("{} Added {} workflow path(s)", "✓".green(), paths.len());
    }

    Ok(paths)
}

fn display_threat_summary(threat: &Threat) -> Result<()> {
    println!();
    println!("{}", "=== Threat Summary ===".bold().cyan());
    println!();
    println!("Name:        {}", threat.name.as_str().green());
    println!("Date:        {}", threat.date);
    println!("Packages:    {}", threat.package_count());

    if let Some(ref cve) = threat.cve_number {
        println!("CVE:         {}", cve.as_str().yellow());
    }

    println!("Description: {}", threat.description);
    println!();

    if !threat.packages().is_empty() {
        println!("{}", "Packages:".bold());
        for pkg in threat.packages() {
            println!("  • {}", pkg);
        }
        println!();
    }

    if !threat.signatures.is_empty() {
        println!("{}", "Signatures:".bold());
        for sig in &threat.signatures {
            println!("  • {}", sig);
        }
        println!();
    }

    if !threat.payload_files.is_empty() {
        println!("{}", "Payload Files:".bold());
        for file in &threat.payload_files {
            println!("  • {}", file);
        }
        println!();
    }

    if !threat.workflow_paths.is_empty() {
        println!("{}", "Workflow Paths:".bold());
        for path in &threat.workflow_paths {
            println!("  • {}", path);
        }
        println!();
    }

    Ok(())
}
