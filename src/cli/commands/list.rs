use anyhow::Result;
use colored::Colorize;

use crate::store::Store;

pub fn handle(store: impl Store) -> Result<()> {
    println!();
    println!("{}", "=== Known Threats ===".bold().cyan());
    println!();

    let threats = store.get_all()?;

    if threats.is_empty() {
        println!("{}", "No threats registered yet.".yellow());
        println!("Use 'ector add' to register a new threat.");
        return Ok(());
    }

    for threat in &threats {
        println!("{}", format!("• {}", threat.name).bold());
        println!("  Date:     {}", threat.date);
        println!("  Packages: {}", threat.package_count());

        if let Some(ref cve) = threat.cve_number {
            println!("  CVE:      {}", cve.as_str().yellow());
        }

        if !threat.description.is_empty() {
            println!("  Info:     {}", threat.description);
        }

        println!();
    }

    println!(
        "Total: {} threat{}",
        threats.len(),
        if threats.len() == 1 { "" } else { "s" }
    );
    println!();

    Ok(())
}
