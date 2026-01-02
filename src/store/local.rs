use std::{
    fs::{self},
    path::PathBuf,
};

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::{
    core::{
        package::Package,
        threat::{CveNumber, Threat, ThreatName},
    },
    json::read_json,
    store::Store,
};

/// Internal metadata structure for indexing threats
/// This is stored in metadata.json and used to efficiently load threats
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    pub name: ThreatName,
    pub date: NaiveDate,

    #[serde(rename = "cveNumber")]
    pub cve_number: Option<CveNumber>,

    #[serde(rename = "affectedPackages")]
    pub affected_packages: u32,

    pub description: String,
    pub signatures: Vec<String>,

    #[serde(rename = "payloadFiles")]
    pub payload_files: Vec<String>,

    #[serde(rename = "workflowPaths")]
    pub workflow_paths: Vec<String>,
}

impl Metadata {
    fn from_threat(threat: &Threat) -> Self {
        Self {
            name: threat.name.clone(),
            date: threat.date,
            cve_number: threat.cve_number.clone(),
            affected_packages: threat.package_count() as u32,
            description: threat.description.clone(),
            // Convert HashSet to Vec for serialization
            signatures: threat.signatures.iter().cloned().collect(),
            payload_files: threat.payload_files.iter().cloned().collect(),
            workflow_paths: threat.workflow_paths.iter().cloned().collect(),
        }
    }
}

pub struct LocalStorage {
    threats_dir: PathBuf,
    metadata_path: PathBuf,
}

impl LocalStorage {
    pub fn new(threats_dir: PathBuf) -> Self {
        let metadata_path = threats_dir.join("metadata.json");

        Self {
            threats_dir,
            metadata_path,
        }
    }

    /// Load metadata from disk
    fn load_metadata(&self) -> Result<Vec<Metadata>> {
        let exists = self.metadata_path.try_exists()?;
        if exists {
            read_json(&self.metadata_path).context("Failed to load threats metadata")
        } else {
            Ok(Vec::new())
        }
    }

    /// Write metadata to disk
    fn write_metadata(&self, metadata: &[Metadata]) -> Result<()> {
        let json = serde_json::to_string_pretty(metadata)?;
        fs::write(&self.metadata_path, json)?;
        Ok(())
    }

    /// Find metadata by name
    fn find_metadata(&self, threat_name: &ThreatName) -> Result<Option<Metadata>> {
        let metadata = self.load_metadata()?;
        Ok(metadata.into_iter().find(|m| &m.name == threat_name))
    }

    /// Load threat from file
    fn load_threat_from_file(&self, metadata: &Metadata) -> Result<Threat> {
        let file_path = self
            .threats_dir
            .join(format!("{}.ect", metadata.name.as_str()));

        let content = fs::read_to_string(&file_path).context(format!(
            "Failed to read threat file: {}",
            file_path.display()
        ))?;

        let packages = parse_threat_file(&content)?;

        let mut threat = Threat::new(metadata.name.clone());
        threat.date = metadata.date;
        threat.cve_number = metadata.cve_number.clone();
        threat.description = metadata.description.clone();

        // Convert Vec from metadata to HashSet in threat
        threat.add_signatures(metadata.signatures.clone());
        threat.add_payload_files(metadata.payload_files.clone());
        threat.add_workflow_paths(metadata.workflow_paths.clone());

        for pkg in packages {
            threat.add_package(pkg);
        }

        Ok(threat)
    }
}

impl Store for LocalStorage {
    fn get_all(&self) -> Result<Vec<Threat>> {
        let metadata_list = self.load_metadata()?;
        let mut threats = Vec::new();

        for metadata in metadata_list.iter() {
            let threat = self.load_threat_from_file(metadata)?;
            threats.push(threat);
        }

        Ok(threats)
    }

    fn get_by_name(&self, name: &ThreatName) -> Result<Threat> {
        let metadata = self
            .find_metadata(name)?
            .ok_or_else(|| anyhow::anyhow!("Threat '{}' not found", name.as_str()))?;

        self.load_threat_from_file(&metadata)
    }

    fn save(&self, threat: &Threat) -> Result<()> {
        if self.exists(&threat.name)? {
            anyhow::bail!("Threat '{}' already exists", threat.name.as_str());
        }

        let mut all_metadata = self.load_metadata()?;

        let metadata = Metadata::from_threat(threat);
        all_metadata.push(metadata);

        self.write_metadata(&all_metadata)
            .context("Failed to write metadata")?;

        let file_path = self
            .threats_dir
            .join(format!("{}.ect", threat.name.as_str()));
        let content = to_file_format(threat);
        fs::write(&file_path, content)?;

        Ok(())
    }

    fn exists(&self, threat_name: &ThreatName) -> Result<bool> {
        Ok(self.find_metadata(threat_name)?.is_some())
    }
}

/// Parse threat file content into Vec<Package>
fn parse_threat_file(content: &str) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    let mut errors = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_package_line(line) {
            Ok(pkg) => packages.push(pkg),
            Err(e) => {
                errors.push(format!("Line {}: {} - {}", line_num + 1, e, line));
            }
        }
    }

    if !errors.is_empty() {
        eprintln!("[WARNING] Skipped {} invalid lines:", errors.len());
        for error in errors.iter().take(5) {
            eprintln!("  {}", error);
        }
        if errors.len() > 5 {
            eprintln!("  ... and {} more", errors.len() - 5);
        }
    }

    Ok(packages)
}

/// Parse a single line: ["package"]="version"
fn parse_package_line(line: &str) -> Result<Package> {
    // Check for exact format: starts with [" and contains "]="
    if !line.starts_with("[\"") || !line.contains("\"]=") {
        anyhow::bail!("Invalid format (expected [\"package\"]=\"version\")");
    }

    // Split on "]="
    let parts: Vec<&str> = line.split("\"]=").collect();
    if parts.len() != 2 {
        anyhow::bail!("Could not split on '\"]='");
    }

    let package_str = parts[0].trim_start_matches("[\"").trim_end_matches('"');
    let version_part = parts[1];

    // Strict validation: version must be wrapped in quotes
    if !version_part.starts_with('"') || !version_part.ends_with('"') {
        anyhow::bail!("Version must be wrapped in quotes");
    }

    let version_str = version_part.trim_matches('"');

    if package_str.is_empty() || version_str.is_empty() {
        anyhow::bail!("Package name and version cannot be empty");
    }

    Package::from_strings(package_str, version_str)
}

fn to_file_format(threat: &Threat) -> String {
    let mut lines = Vec::new();

    lines.push(format!("# Threat: {}", threat.name.as_str()));

    if let Some(cve) = &threat.cve_number {
        lines.push(format!("# CVE: {}", cve));
    }

    lines.push("# Format: [\"package\"]=\"version\"".to_string());
    lines.push(String::new()); // Empty line

    // Sort packages for deterministic output
    let mut packages: Vec<_> = threat.packages().iter().collect();
    packages.sort_by(|a, b| {
        a.name_str()
            .cmp(b.name_str())
            .then(a.version_str().cmp(b.version_str()))
    });

    for pkg in packages {
        lines.push(format!(
            "[\"{}\"]=\"{}\"",
            pkg.name_str(),
            pkg.version_str()
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_threat_metadata_from_threat() {
        let threat_name = ThreatName::new("test-threat").unwrap();
        let mut threat = Threat::new(threat_name);
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 15).unwrap();
        threat.description = "Test description".to_string();
        threat.add_signature("eval(".to_string());
        threat.add_payload_file("malicious.js".to_string());
        threat.add_package(Package::from_strings("lodash", "4.17.20").unwrap());

        let metadata = Metadata::from_threat(&threat);

        assert_eq!(metadata.name.as_str(), "test-threat");
        assert_eq!(metadata.affected_packages, 1);
        assert_eq!(metadata.description, "Test description");
        assert_eq!(metadata.signatures.len(), 1);
        assert_eq!(metadata.payload_files.len(), 1);
    }

    #[test]
    fn test_get_by_name_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("nonexistent").unwrap();
        let result = storage.get_by_name(&threat_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_threats() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        for i in 1..=3 {
            let threat_name = ThreatName::new(&format!("threat-{}", i)).unwrap();
            let mut threat = Threat::new(threat_name);
            threat.date = NaiveDate::from_ymd_opt(2025, 1, i as u32).unwrap();
            threat.description = format!("Test threat {}", i);
            threat.add_package(Package::from_strings("lodash", &format!("4.17.{}", i)).unwrap());

            storage.save(&threat).unwrap();
        }

        let all = storage.get_all().unwrap();
        assert_eq!(all.len(), 3);

        assert!(all.iter().any(|t| t.name.as_str() == "threat-1"));
        assert!(all.iter().any(|t| t.name.as_str() == "threat-2"));
        assert!(all.iter().any(|t| t.name.as_str() == "threat-3"));
    }

    #[test]
    fn test_storage_law_roundtrip() {
        // Law: save(x) -> load() = x
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test-threat").unwrap();
        let mut threat = Threat::new(threat_name.clone());
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 15).unwrap();
        threat.description = "Test description".to_string();
        threat.add_package(Package::from_strings("lodash", "4.17.20").unwrap());
        threat.add_signature("eval(".to_string());
        threat.add_payload_file("evil.js".to_string());

        // Save
        storage.save(&threat).unwrap();

        // Load
        let loaded = storage.get_by_name(&threat_name).unwrap();

        // Should be identical
        assert_eq!(loaded.name.as_str(), threat.name.as_str());
        assert_eq!(loaded.date, threat.date);
        assert_eq!(loaded.description, threat.description);
        assert_eq!(loaded.package_count(), threat.package_count());
        assert_eq!(loaded.signatures.len(), threat.signatures.len());
        assert_eq!(loaded.payload_files.len(), threat.payload_files.len());
    }

    #[test]
    fn test_storage_law_idempotent_load() {
        // Law: load(load(x)) = load(x)
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test").unwrap();
        let mut threat = Threat::new(threat_name.clone());
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        threat.add_package(Package::from_strings("lodash", "4.17.20").unwrap());

        storage.save(&threat).unwrap();

        // Load multiple times
        let loaded1 = storage.get_by_name(&threat_name).unwrap();
        let loaded2 = storage.get_by_name(&threat_name).unwrap();
        let loaded3 = storage.get_by_name(&threat_name).unwrap();

        // All should be identical
        assert_eq!(loaded1.name.as_str(), loaded2.name.as_str());
        assert_eq!(loaded2.name.as_str(), loaded3.name.as_str());
        assert_eq!(loaded1.package_count(), loaded2.package_count());
        assert_eq!(loaded2.package_count(), loaded3.package_count());
    }

    #[test]
    fn test_storage_law_exists_after_save() {
        // Law: save(x) -> exists(x) = true
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test").unwrap();
        let threat = Threat::new(threat_name.clone());

        // Before save
        assert!(!storage.exists(&threat_name).unwrap());

        // After save
        storage.save(&threat).unwrap();
        assert!(storage.exists(&threat_name).unwrap());
    }

    #[test]
    fn test_storage_law_get_all_contains_saved() {
        // Law: save(x) -> x ∈ get_all()
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test-threat").unwrap();
        let threat = Threat::new(threat_name);

        storage.save(&threat).unwrap();

        let all = storage.get_all().unwrap();
        assert!(all.iter().any(|t| t.name.as_str() == "test-threat"));
    }

    #[test]
    fn test_storage_law_no_duplicates() {
        // Law: Saving same name twice should fail
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test").unwrap();
        let threat1 = Threat::new(threat_name.clone());

        // First save succeeds
        assert!(storage.save(&threat1).is_ok());

        // Second save with same name fails
        let threat2 = Threat::new(threat_name);
        let result = storage.save(&threat2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_storage_law_hashset_preserved() {
        // Law: HashSet deduplication is preserved through save/load
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test").unwrap();
        let mut threat = Threat::new(threat_name.clone());
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

        // Add same package multiple times (should deduplicate)
        let pkg = Package::from_strings("lodash", "4.17.20").unwrap();
        threat.add_package(pkg.clone());
        threat.add_package(pkg.clone());
        threat.add_package(pkg);
        assert_eq!(threat.package_count(), 1);

        // Add same signature multiple times (should deduplicate)
        threat.add_signature("eval(".to_string());
        threat.add_signature("eval(".to_string());
        assert_eq!(threat.signatures.len(), 1);

        // Save and load
        storage.save(&threat).unwrap();
        let loaded = storage.get_by_name(&threat_name).unwrap();

        // Deduplication should be preserved
        assert_eq!(loaded.package_count(), 1);
        assert_eq!(loaded.signatures.len(), 1);
    }

    #[test]
    fn test_storage_law_signatures_preserved() {
        // Law: All signatures are preserved through roundtrip
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test").unwrap();
        let mut threat = Threat::new(threat_name.clone());
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

        threat.add_signatures(vec![
            "eval(".to_string(),
            "atob(".to_string(),
            "require(".to_string(),
        ]);

        storage.save(&threat).unwrap();
        let loaded = storage.get_by_name(&threat_name).unwrap();

        // All signatures present
        assert_eq!(loaded.signatures.len(), 3);
        assert!(loaded.signatures.contains("eval("));
        assert!(loaded.signatures.contains("atob("));
        assert!(loaded.signatures.contains("require("));
    }

    #[test]
    fn test_storage_law_payload_files_preserved() {
        // Law: All payload files are preserved through roundtrip
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let threat_name = ThreatName::new("test").unwrap();
        let mut threat = Threat::new(threat_name.clone());
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

        threat.add_payload_files(vec![
            "evil.js".to_string(),
            "malicious.sh".to_string(),
            "backdoor.py".to_string(),
        ]);

        storage.save(&threat).unwrap();
        let loaded = storage.get_by_name(&threat_name).unwrap();

        // All files present
        assert_eq!(loaded.payload_files.len(), 3);
        assert!(loaded.payload_files.contains("evil.js"));
        assert!(loaded.payload_files.contains("malicious.sh"));
        assert!(loaded.payload_files.contains("backdoor.py"));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

    /// Strategy that generates valid ThreatNames
    /// Uses a curated list to ensure all generated names pass validation:
    /// - Must be lowercase
    /// - Only a-z, 0-9, and hyphens
    /// - Cannot start or end with hyphen
    /// - No consecutive hyphens
    fn valid_threat_name_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "test-threat".to_string(),
            "event-stream-2018".to_string(),
            "shai-hulud-2".to_string(),
            "cve-2025-12345".to_string(),
            "my-threat".to_string(),
            "threat123".to_string(),
            "test-1".to_string(),
            "attack-vector-3".to_string(),
            "npm-malware".to_string(),
            "backdoor-js".to_string(),
            "supply-chain-attack".to_string(),
            "typosquatting-attack".to_string(),
            "dependency-confusion".to_string(),
            "malicious-package".to_string(),
            "code-injection".to_string(),
            "prototype-pollution".to_string(),
            "xss-vulnerability".to_string(),
            "sql-injection-2024".to_string(),
            "remote-code-execution".to_string(),
            "path-traversal".to_string(),
        ])
    }

    fn threat_strategy() -> impl Strategy<Value = Threat> {
        (
            valid_threat_name_strategy(),
            (2020u32..=2025),
            (1u32..=12),
            (1u32..=28),
            prop::collection::vec("[a-z]{3,10}", 1..5),
            "[0-9]\\.[0-9]\\.[0-9]",
        )
            .prop_map(|(name, year, month, day, pkg_names, version)| {
                let threat_name = ThreatName::new(&name).unwrap();
                let mut threat = Threat::new(threat_name);
                threat.date = NaiveDate::from_ymd_opt(year as i32, month, day).unwrap();
                threat.description = "Generated threat".to_string();

                for pkg_name in pkg_names {
                    if let Ok(pkg) = Package::from_strings(&pkg_name, &version) {
                        threat.add_package(pkg);
                    }
                }

                threat
            })
    }

    proptest! {
        #[test]
        fn prop_storage_roundtrip(threat in threat_strategy()) {
            // Law: save(x) -> load(name) = x
            let temp_dir = TempDir::new().unwrap();
            let storage = LocalStorage::new(temp_dir.path().to_path_buf());

            storage.save(&threat).unwrap();
            let loaded = storage.get_by_name(&threat.name).unwrap();

            prop_assert_eq!(loaded.package_count(), threat.package_count());
            prop_assert_eq!(loaded.name.as_str(), threat.name.as_str());
            prop_assert_eq!(loaded.date, threat.date);
        }

        #[test]
        fn prop_storage_exists_consistency(threat in threat_strategy()) {
            // Law: exists(name) <=> can load(name)
            let temp_dir = TempDir::new().unwrap();
            let storage = LocalStorage::new(temp_dir.path().to_path_buf());

            storage.save(&threat).unwrap();

            let exists = storage.exists(&threat.name).unwrap();
            let can_load = storage.get_by_name(&threat.name).is_ok();

            prop_assert_eq!(exists, can_load);
        }

        #[test]
        fn prop_storage_get_all_membership(threat in threat_strategy()) {
            // Law: save(x) => x ∈ get_all()
            let temp_dir = TempDir::new().unwrap();
            let storage = LocalStorage::new(temp_dir.path().to_path_buf());

            storage.save(&threat).unwrap();
            let all = storage.get_all().unwrap();

            let found = all.iter().any(|t| t.name.as_str() == threat.name.as_str());
            prop_assert!(found);
        }

        #[test]
        fn prop_storage_idempotent_load(threat in threat_strategy()) {
            // Law: load(name) = load(name) (deterministic)
            let temp_dir = TempDir::new().unwrap();
            let storage = LocalStorage::new(temp_dir.path().to_path_buf());

            storage.save(&threat).unwrap();

            let loaded1 = storage.get_by_name(&threat.name).unwrap();
            let loaded2 = storage.get_by_name(&threat.name).unwrap();

            prop_assert_eq!(loaded1.package_count(), loaded2.package_count());
            prop_assert_eq!(loaded1.name.as_str(), loaded2.name.as_str());
        }
    }
}

#[cfg(test)]
mod property_tests_threat_file_format {
    use super::*;
    use proptest::prelude::*;

    /// Generate valid package names (lowercase, alphanumeric, optional @scope)
    fn package_name_strategy() -> impl Strategy<Value = String> {
        prop::bool::ANY.prop_flat_map(|scoped| {
            if scoped {
                // Scoped package: @scope/name
                (
                    "[a-z][a-z0-9]{1,10}",  // scope
                    "[a-z][a-z0-9-]{1,15}", // name
                )
                    .prop_map(|(scope, name)| format!("@{}/{}", scope, name))
                    .boxed()
            } else {
                // Regular package
                "[a-z][a-z0-9-]{1,20}".prop_map(|name| name).boxed()
            }
        })
    }

    /// Generate valid semantic versions
    fn version_strategy() -> impl Strategy<Value = String> {
        (0u32..100, 0u32..100, 0u32..100)
            .prop_map(|(major, minor, patch)| format!("{}.{}.{}", major, minor, patch))
    }

    /// Generate a valid package (name + version)
    fn package_strategy() -> impl Strategy<Value = Package> {
        (package_name_strategy(), version_strategy())
            .prop_map(|(name, version)| Package::from_strings(name, version).unwrap())
    }

    /// Generate a valid threat file line
    fn valid_line_strategy() -> impl Strategy<Value = String> {
        (package_name_strategy(), version_strategy())
            .prop_map(|(name, version)| format!("[\"{}\"]=\"{}\"", name, version))
    }

    /// Generate file content with valid lines
    fn file_content_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(valid_line_strategy(), 0..50).prop_map(|lines| lines.join("\n"))
    }

    /// Generate file content with comments and empty lines
    fn file_with_noise_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::option::of(valid_line_strategy()), 0..50).prop_map(|lines| {
            lines
                .into_iter()
                .enumerate()
                .map(|(i, opt_line)| {
                    match opt_line {
                        Some(line) => line,
                        None => {
                            // Randomly insert comment or empty line
                            if i % 3 == 0 {
                                format!("# Comment line {}", i)
                            } else {
                                String::new()
                            }
                        }
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
    }

    proptest! {
        /// Property: Parsing and then regenerating should preserve package count
        #[test]
        fn prop_parse_preserves_package_count(
            packages in prop::collection::vec(package_strategy(), 1..20)
        ) {
            // Generate file content from packages
            let content = packages.iter()
                .map(|pkg| format!("[\"{}\"]=\"{}\"", pkg.name_str(), pkg.version_str()))
                .collect::<Vec<_>>()
                .join("\n");

            // Parse it back
            let parsed = parse_threat_file(&content).unwrap();

            // Should have same number of packages
            prop_assert_eq!(parsed.len(), packages.len());
        }

        /// Property: Parsing valid content should never fail
        #[test]
        fn prop_parse_valid_content_succeeds(
            content in file_content_strategy()
        ) {
            let result = parse_threat_file(&content);
            prop_assert!(result.is_ok());
        }

        /// Property: Empty lines and comments should be ignored
        #[test]
        fn prop_parse_ignores_noise(
            content in file_with_noise_strategy()
        ) {
            let result = parse_threat_file(&content);
            prop_assert!(result.is_ok());

            // Count actual package lines
            let expected_count = content.lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.is_empty()
                        && !trimmed.starts_with('#')
                        && trimmed.starts_with("[\"")
                })
                .count();

            let parsed = result.unwrap();
            prop_assert_eq!(parsed.len(), expected_count);
        }

        /// Property: Scoped packages should be parsed correctly
        #[test]
        fn prop_parse_scoped_packages(
            scope in "[a-z]{2,10}",
            name in "[a-z][a-z0-9-]{2,15}",
            version in version_strategy()
        ) {
            let package_name = format!("@{}/{}", scope, name);
            let line = format!("[\"{}\"]=\"{}\"", package_name, version);

            let parsed = parse_threat_file(&line).unwrap();

            prop_assert_eq!(parsed.len(), 1);
            prop_assert_eq!(parsed[0].name_str(), &package_name);
            prop_assert_eq!(parsed[0].version_str(), &version);
        }

        /// Property: Parse should handle any number of leading/trailing spaces
        #[test]
        fn prop_parse_handles_whitespace(
            pkg_name in package_name_strategy(),
            version in version_strategy(),
            leading_spaces in 0usize..10,
            trailing_spaces in 0usize..10
        ) {
            let spaces_before = " ".repeat(leading_spaces);
            let spaces_after = " ".repeat(trailing_spaces);
            let line = format!(
                "{}[\"{}\"]=\"{}\"{}",
                spaces_before, pkg_name, version, spaces_after
            );

            let parsed = parse_threat_file(&line).unwrap();

            prop_assert_eq!(parsed.len(), 1);
            prop_assert_eq!(parsed[0].name_str(), pkg_name);
            prop_assert_eq!(parsed[0].version_str(), version);
        }

        /// Property: Valid format should always parse
        #[test]
        fn prop_parse_line_valid_format(
            name in package_name_strategy(),
            version in version_strategy()
        ) {
            let line = format!("[\"{}\"]=\"{}\"", name, version);
            let result = parse_package_line(&line);

            prop_assert!(result.is_ok());
            let pkg = result.unwrap();
            prop_assert_eq!(pkg.name_str(), name);
            prop_assert_eq!(pkg.version_str(), version);
        }

        /// Property: Invalid formats should fail
        #[test]
        fn prop_parse_line_rejects_invalid(
            name in package_name_strategy(),
            version in version_strategy()
        ) {
            // Test various invalid formats
            let invalid_formats = vec![
                format!("{}={}", name, version),           // No brackets/quotes
                format!("[\"{}\"]={}", name, version),     // Missing quotes on version
                format!("{}=\"{}\"", name, version),       // Missing brackets
                format!("[{}]=\"{}\"", name, version),     // Missing quotes on name
            ];

            for invalid in invalid_formats {
                let result = parse_package_line(&invalid);
                prop_assert!(result.is_err(), "Should reject: {}", invalid);
            }
        }
    }
}
