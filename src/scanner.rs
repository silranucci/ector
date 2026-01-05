use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;
use std::{fs, path::Path};
use walkdir::WalkDir;

use crate::core::checker::{Checker, MaliciousCodeIssue, ScanResult};
use crate::core::threat::Threat;
use crate::util::json::read_json;

pub struct FSScanner {
    core: Checker,
}

impl FSScanner {
    pub fn new(threats: Vec<Threat>) -> Self {
        Self {
            core: Checker::new(threats),
        }
    }

    /// Orchestrates scanning
    pub fn scan_directory(&self, dir: &Path) -> Result<ScanResult> {
        if !dir.exists() {
            anyhow::bail!("Directory does not exist: {}", dir.display());
        }

        println!();
        println!("{}", "=== Starting Security Scan ===".bold().cyan());
        println!("Directory: {}", dir.display());
        println!();

        let mut result = ScanResult::empty();

        let directories = self.collect_directories(dir)?;
        for directory in directories {
            result = result.combine(self.scan_package_files(&directory)?);
        }

        if self.has_signatures() {
            result = result.combine(self.scan_source_files(dir)?);
        }

        if self.has_payload_files() {
            result = result.combine(self.scan_payload_files(dir)?);
        }

        self.print_summary(&result);

        Ok(result)
    }

    fn has_signatures(&self) -> bool {
        self.core.has_signatures()
    }

    fn has_payload_files(&self) -> bool {
        self.core.has_payload_files()
    }

    fn collect_directories(&self, dir: &Path) -> Result<Vec<std::path::PathBuf>> {
        let directories: Vec<_> = WalkDir::new(dir)
            .min_depth(0)
            .into_iter()
            .filter_entry(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|name| !should_skip_directory(name))
                    .unwrap_or(false)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.path().to_path_buf())
            .collect();

        Ok(directories)
    }

    fn collect_scannable_files(&self, dir: &Path) -> Result<Vec<std::path::PathBuf>> {
        let files: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    !should_skip_directory(&name)
                } else {
                    true
                }
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| is_scannable_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        Ok(files)
    }

    fn scan_package_files(&self, dir: &Path) -> Result<ScanResult> {
        let mut result = ScanResult::empty();

        let package_json = dir.join("package.json");
        if package_json.exists() {
            result = result.combine(self.scan_package_json(&package_json)?);
        }

        let package_lock = dir.join("package-lock.json");
        if package_lock.exists() {
            result = result.combine(self.scan_package_lock(&package_lock)?);
        }

        let yarn_lock = dir.join("yarn.lock");
        if yarn_lock.exists() {
            result = result.combine(self.scan_yarn_lock(&yarn_lock)?);
        }

        Ok(result)
    }

    fn scan_package_json(&self, path: &Path) -> Result<ScanResult> {
        println!("{} Checking package.json...", "[SCAN]".cyan());

        let json_value: serde_json::Value = read_json(path)?;
        let result = self
            .core
            .scan_package_json_data(&json_value, "package.json");

        for issue in result.compromised_packages() {
            println!(
                "  {} {}@{} ({})",
                "[COMPROMISED]".red().bold(),
                issue.package_name.yellow(),
                issue.version,
                issue.threat_name.dimmed()
            );
        }

        if !result.has_issues() {
            println!("  {} No issues found", "[OK]".green());
        }

        Ok(result)
    }

    fn scan_package_lock(&self, path: &Path) -> Result<ScanResult> {
        println!("{} Checking package-lock.json...", "[SCAN]".cyan());

        let json_value: serde_json::Value = read_json(path)?;
        let result = self
            .core
            .scan_package_lock_data(&json_value, "package-lock.json");

        for issue in result.compromised_packages() {
            println!(
                "  {} {}@{}",
                "[COMPROMISED]".red().bold(),
                issue.package_name.yellow(),
                issue.version
            );
        }

        if !result.has_issues() {
            println!("  {} No issues found", "[OK]".green());
        }

        Ok(result)
    }

    fn scan_yarn_lock(&self, path: &Path) -> Result<ScanResult> {
        println!("{} Checking yarn.lock...", "[SCAN]".cyan());

        let content = fs::read_to_string(path).context("Failed to read yarn.lock")?;
        let result = self.core.scan_yarn_lock_data(&content, "yarn.lock");

        for issue in result.compromised_packages() {
            println!(
                "  {} {}@{}",
                "[COMPROMISED]".red().bold(),
                issue.package_name.yellow(),
                issue.version
            );
        }

        if !result.has_issues() {
            println!("  {} No issues found", "[OK]".green());
        }

        Ok(result)
    }

    fn scan_source_files(&self, dir: &Path) -> Result<ScanResult> {
        println!(
            "{} Scanning source files for malicious code...",
            "[SCAN]".cyan()
        );

        let files = self.collect_scannable_files(dir)?;
        println!("  {} Found {} files to scan", "[INFO]".blue(), files.len());

        // Parallel scan
        let issues: Vec<MaliciousCodeIssue> = files
            .par_iter()
            .filter_map(|path| self.scan_file(path).ok())
            .flatten()
            .collect();

        for issue in &issues {
            println!(
                "  {} in {} (line {}) - {} - signature: {}",
                "[MALICIOUS CODE]".red().bold(),
                issue.file_path.yellow(),
                issue.line_number.unwrap_or(0),
                issue.threat_name.cyan(),
                issue.signature.dimmed()
            );
        }

        if issues.is_empty() {
            println!("  {} No malicious code detected", "[OK]".green());
        }

        let mut result = ScanResult::empty().with_files_scanned(files.len());

        for issue in issues {
            result = result.with_malicious_code(issue);
        }

        Ok(result)
    }

    /// Scan a single file
    fn scan_file(&self, path: &Path) -> Result<Vec<MaliciousCodeIssue>> {
        let code = fs::read_to_string(path)?;

        let file_path = path.display().to_string();
        let issues = self.core.check_file_content(&code, &file_path);

        Ok(issues)
    }

    fn scan_payload_files(&self, dir: &Path) -> Result<ScanResult> {
        println!("{} Checking for payload files...", "[SCAN]".cyan());

        let mut result = ScanResult::empty();

        let files: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().display().to_string())
            .collect();

        for file_path in files {
            let issues = self.core.check_payload_file(&file_path);

            for issue in &issues {
                println!(
                    "  {} {} found ({})",
                    "[PAYLOAD]".red().bold(),
                    issue.payload_type.yellow(),
                    issue.threat_name.cyan()
                );
            }

            for issue in issues {
                result = result.with_payload_file(issue);
            }
        }

        if !result.has_issues() {
            println!("  {} No payload files detected", "[OK]".green());
        }

        Ok(result)
    }

    fn print_summary(&self, result: &ScanResult) {
        println!();
        println!("{}", "=== Scan Summary ===".bold().cyan());
        println!("  Packages checked: {}", result.packages_checked);
        println!("  Files scanned: {}", result.files_scanned);
        println!();

        if result.has_issues() {
            println!(
                "{} {} security issues found:",
                "✗".red().bold(),
                result.issues_found()
            );
            println!(
                "  - {} compromised packages",
                result.compromised_packages().len()
            );
            println!(
                "  - {} malicious code patterns",
                result.malicious_code().len()
            );
            println!("  - {} payload files", result.payload_files().len());
        } else {
            println!("{}", "✓ No security issues found".green().bold());
        }
        println!();
    }
}

fn is_scannable_file(path: &Path) -> bool {
    if path.to_string_lossy().contains(".min.") {
        return false;
    }

    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs"))
        .unwrap_or(false)
}

fn should_skip_directory(name: &str) -> bool {
    matches!(
        name,
        "node_modules"
            | ".git"
            | "dist"
            | "build"
            | ".cache"
            | "coverage"
            | ".next"
            | ".nuxt"
            | ".output"
            | "target"
            | ".idea"
            | ".vscode"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::package::Package;
    use crate::core::threat::{Threat, ThreatName};
    use tempfile::TempDir;

    fn create_test_threat() -> Threat {
        let mut threat = Threat::new(ThreatName::new("test-threat").unwrap());
        threat.add_package(Package::from_strings("lodash", "4.17.20").unwrap());
        threat.add_signature("eval(".to_string());
        threat
    }

    fn create_temp_dir_with_file(filename: &str, content: &str) -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join(filename), content).unwrap();
        temp_dir
    }

    #[test]
    fn test_scanner_creation() {
        let threats = vec![create_test_threat()];
        let scanner = FSScanner::new(threats);
        // Verify scanner was created with threats
        assert!(scanner.has_signatures())
    }

    #[test]
    fn test_scanner_finds_compromised_package() {
        let temp_dir =
            create_temp_dir_with_file("package.json", r#"{"dependencies": {"lodash": "4.17.20"}}"#);

        let scanner = FSScanner::new(vec![create_test_threat()]);
        let result = scanner.scan_directory(temp_dir.path()).unwrap();

        assert_eq!(result.issues_found(), 1);
        assert_eq!(result.compromised_packages().len(), 1);
        let pkg = result.compromised_packages().iter().next().unwrap();
        assert_eq!(pkg.package_name, "lodash");
    }

    #[test]
    fn test_scanner_clean_package() {
        let temp_dir =
            create_temp_dir_with_file("package.json", r#"{"dependencies": {"express": "4.18.0"}}"#);

        let scanner = FSScanner::new(vec![create_test_threat()]);
        let result = scanner.scan_directory(temp_dir.path()).unwrap();

        assert_eq!(result.issues_found(), 0);
        assert!(!result.has_issues());
    }

    #[test]
    fn test_scanner_immutability() {
        let scanner = FSScanner::new(vec![create_test_threat()]);

        let dir1 =
            create_temp_dir_with_file("package.json", r#"{"dependencies": {"lodash": "4.17.20"}}"#);
        let dir2 =
            create_temp_dir_with_file("package.json", r#"{"dependencies": {"express": "4.18.0"}}"#);

        let result1 = scanner.scan_directory(dir1.path()).unwrap();
        let result2 = scanner.scan_directory(dir2.path()).unwrap();

        assert_eq!(result1.issues_found(), 1);
        assert_eq!(result2.issues_found(), 0);
    }
}
