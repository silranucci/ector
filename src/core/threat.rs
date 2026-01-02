use anyhow::Result;
use chrono::{Datelike, NaiveDate};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    path::Path,
};

use crate::core::package::{Package, PackageName, Version};

/// CVE Number (e.g., "CVE-2025-55183")
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CveNumber(String);

impl CveNumber {
    pub fn new(s: impl AsRef<str>) -> Result<Self> {
        let s = s.as_ref();

        if !s.starts_with("CVE-") {
            anyhow::bail!("CVE number must start with 'CVE-'");
        }

        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            anyhow::bail!("CVE format must be CVE-YYYY-NNNNN");
        }

        let year_str = parts[1];
        if year_str.len() != 4 || !year_str.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid CVE year: '{}' (must be 4 digits)", year_str);
        }

        let year: i32 = year_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CVE year: '{}'", year_str))?;

        let current_year = chrono::Utc::now().year();
        const MIN_CVE_YEAR: i32 = 1999;
        let max_cve_year = current_year + 1;

        if year < MIN_CVE_YEAR || year > max_cve_year {
            anyhow::bail!(
                "CVE year must be between {} and {} (got {})",
                MIN_CVE_YEAR,
                max_cve_year,
                year
            );
        }

        if !parts[2].chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid CVE number: {}", parts[2]);
        }

        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CveNumber {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<CveNumber> for String {
    fn from(cve: CveNumber) -> String {
        cve.0
    }
}

impl Display for CveNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Threat Name - Unique identifier for threats (lowercase, hyphens, digits only)
///
/// Examples: "event-stream-2018", "shai-hulud-2", "cve-2025-55183"
///
/// This format ensures:
/// - URL-safe filenames
/// - Easy to type in CLI
/// - Consistent format across systems
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ThreatName(String);

impl ThreatName {
    /// Create a ThreatName from a string
    ///
    /// Rules:
    /// - Must be lowercase
    /// - Can only contain: a-z, 0-9, hyphens
    /// - Cannot be empty
    /// - Max 100 characters
    pub fn new(s: impl AsRef<str>) -> Result<Self> {
        let s = s.as_ref();

        if s.is_empty() {
            anyhow::bail!("Threat name cannot be empty");
        }

        if s.len() > 100 {
            anyhow::bail!("Threat name cannot exceed 100 characters");
        }

        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            anyhow::bail!(
                "Threat name must be lowercase with hyphens only (e.g., 'event-stream-2018')"
            );
        }

        // Don't allow starting or ending with hyphen
        if s.starts_with('-') || s.ends_with('-') {
            anyhow::bail!("Threat name cannot start or end with a hyphen");
        }

        // Don't allow consecutive hyphens
        if s.contains("--") {
            anyhow::bail!("Threat name cannot contain consecutive hyphens");
        }

        Ok(Self(s.to_string()))
    }

    /// Convert a display name to a slug
    ///
    /// - Converts to lowercase
    /// - Replaces spaces and underscores with hyphens
    /// - Preserves existing hyphens
    /// - Removes other special characters
    /// - Removes consecutive hyphens
    /// - Trims hyphens from start/end
    pub fn slugify(s: &str) -> String {
        s.to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    c
                } else if c.is_whitespace() || c == '_' || c == '-' {
                    '-'
                } else {
                    // Remove other special characters
                    '\0'
                }
            })
            .collect::<String>()
            .replace('\0', "")
            // Replace consecutive hyphens with single hyphen
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ThreatName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ThreatName {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<ThreatName> for String {
    fn from(name: ThreatName) -> String {
        name.0
    }
}

impl Display for ThreatName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Threat - Supply chain threat definition (CVE or Attack)
///
/// Uses HashSet for all collections to ensure:
/// - Idempotent operations (adding same item multiple times = adding once)
/// - No duplicates
/// - Set algebra operations
///
/// The `name` field serves as the unique identifier and must follow slug format.
#[derive(Debug, Clone)]
pub struct Threat {
    pub name: ThreatName,
    pub date: NaiveDate,
    pub cve_number: Option<CveNumber>,
    pub description: String,
    // Using HashSet for automatic deduplication
    pub signatures: HashSet<String>,
    pub payload_files: HashSet<String>,
    pub workflow_paths: HashSet<String>,
    pub compromised_packages: HashSet<Package>,
}

impl Threat {
    pub fn new(name: ThreatName) -> Self {
        Self {
            name,
            date: chrono::Utc::now().date_naive(),
            cve_number: None,
            description: String::new(),
            signatures: HashSet::new(),
            payload_files: HashSet::new(),
            workflow_paths: HashSet::new(),
            compromised_packages: HashSet::new(),
        }
    }

    /// Add a compromised package
    pub fn add_package(&mut self, package: Package) {
        self.compromised_packages.insert(package);
    }

    /// Add multiple packages at once (idempotent)
    pub fn add_packages(&mut self, packages: impl IntoIterator<Item = Package>) {
        self.compromised_packages.extend(packages);
    }

    /// Check if this threat affects a Package
    pub fn affects(&self, package: &Package) -> bool {
        self.compromised_packages.contains(package)
    }

    /// Get all compromised packages
    pub fn packages(&self) -> &HashSet<Package> {
        &self.compromised_packages
    }

    /// Get package count
    pub fn package_count(&self) -> usize {
        self.compromised_packages.len()
    }

    /// Check if this threat affects any of the given packages
    pub fn affects_any(&self, packages: &[Package]) -> bool {
        packages.iter().any(|pkg| self.affects(pkg))
    }

    /// Find all packages from the list that this threat affects
    pub fn find_affected<'a>(&self, packages: &'a [Package]) -> Vec<&'a Package> {
        packages.iter().filter(|pkg| self.affects(pkg)).collect()
    }

    /// Check if code contains any of this threat's signatures
    pub fn matches_code(&self, code: &str) -> bool {
        self.signatures.iter().any(|sig| code.contains(sig))
    }

    /// Find all matching signatures in code
    pub fn find_signatures(&self, code: &str) -> Vec<&str> {
        self.signatures
            .iter()
            .filter(|sig| code.contains(sig.as_str()))
            .map(|s| s.as_str())
            .collect()
    }

    /// Add a signature (idempotent)
    pub fn add_signature(&mut self, signature: String) {
        self.signatures.insert(signature);
    }

    /// Add multiple signatures (idempotent)
    pub fn add_signatures(&mut self, signatures: impl IntoIterator<Item = String>) {
        self.signatures.extend(signatures);
    }

    /// Add a payload file (idempotent)
    pub fn add_payload_file(&mut self, file: String) {
        self.payload_files.insert(file);
    }

    /// Add multiple payload files (idempotent)
    pub fn add_payload_files(&mut self, files: impl IntoIterator<Item = String>) {
        self.payload_files.extend(files);
    }

    /// Add a workflow path (idempotent)
    pub fn add_workflow_path(&mut self, path: String) {
        self.workflow_paths.insert(path);
    }

    /// Add multiple workflow paths (idempotent)
    pub fn add_workflow_paths(&mut self, paths: impl IntoIterator<Item = String>) {
        self.workflow_paths.extend(paths);
    }

    /// Check if a file is a known payload file for this threat
    pub fn is_payload_file_known(&self, filename: &str) -> bool {
        let file_path = Path::new(filename);

        for payload in &self.payload_files {
            let payload_path = Path::new(payload);

            // Check for exact match
            if file_path == payload_path {
                return true;
            }

            // Check if the file path ends with the payload path
            // This handles cases like "src/evil.js" matching payload "evil.js"
            // or "node_modules/package/evil.js" matching "evil.js"
            if file_path.ends_with(payload_path) {
                return true;
            }
        }

        false
    }

    /// Get packages as HashMap: PackageName -> Vec<Version>
    pub fn as_package_map(&self) -> HashMap<PackageName, Vec<Version>> {
        let mut map: HashMap<PackageName, Vec<Version>> = HashMap::new();

        for pkg in &self.compromised_packages {
            map.entry(pkg.name.clone())
                .or_default()
                .push(pkg.version.clone());
        }

        map
    }
}

impl Display for Threat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\n{}\n{}: {}\n{}: {}",
            self.name.as_ref().bold(),
            self.description,
            "Date".italic(),
            self.date,
            "Packages".italic(),
            self.compromised_packages.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_name_valid() {
        assert!(ThreatName::new("event-stream-2018").is_ok());
        assert!(ThreatName::new("shai-hulud-2").is_ok());
        assert!(ThreatName::new("test").is_ok());
        assert!(ThreatName::new("my-threat-123").is_ok());
    }

    #[test]
    fn test_threat_name_invalid() {
        // Empty
        assert!(ThreatName::new("").is_err());

        // Uppercase
        assert!(ThreatName::new("Event-Stream").is_err());

        // Special characters
        assert!(ThreatName::new("event_stream").is_err());
        assert!(ThreatName::new("event.stream").is_err());
        assert!(ThreatName::new("event/stream").is_err());

        // Starting/ending with hyphen
        assert!(ThreatName::new("-event").is_err());
        assert!(ThreatName::new("event-").is_err());

        // Consecutive hyphens
        assert!(ThreatName::new("event--stream").is_err());

        // Too long
        assert!(ThreatName::new(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_threat_name_slugify() {
        assert_eq!(
            ThreatName::slugify("Event Stream Compromise"),
            "event-stream-compromise"
        );
        assert_eq!(ThreatName::slugify("CVE-2025-12345"), "cve-2025-12345");
        assert_eq!(ThreatName::slugify("My_Threat_Name"), "my-threat-name");
        assert_eq!(
            ThreatName::slugify("  Multiple   Spaces  "),
            "multiple-spaces"
        );
        assert_eq!(
            ThreatName::slugify("Special!@#Characters"),
            "specialcharacters"
        );
        assert_eq!(
            ThreatName::slugify("Numbers123AndText"),
            "numbers123andtext"
        );
        assert_eq!(
            ThreatName::slugify("already-has---hyphens"),
            "already-has-hyphens"
        );
    }

    #[test]
    fn test_threat_affects() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        let pkg = Package::from_strings("lodash", "4.17.20").unwrap();
        threat.add_package(pkg.clone());

        assert!(threat.affects(&pkg));

        let other = Package::from_strings("chalk", "4.1.2").unwrap();
        assert!(!threat.affects(&other));
    }

    #[test]
    fn test_threat_affects_any() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_package(Package::from_strings("lodash", "4.17.20").unwrap());

        let packages = vec![
            Package::from_strings("express", "4.18.0").unwrap(),
            Package::from_strings("lodash", "4.17.20").unwrap(),
        ];

        assert!(threat.affects_any(&packages));
    }

    #[test]
    fn test_threat_find_affected() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_package(Package::from_strings("lodash", "4.17.20").unwrap());

        let packages = vec![
            Package::from_strings("express", "4.18.0").unwrap(),
            Package::from_strings("lodash", "4.17.20").unwrap(),
            Package::from_strings("chalk", "4.1.2").unwrap(),
        ];

        let affected = threat.find_affected(&packages);
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0].name_str(), "lodash");
    }

    #[test]
    fn test_threat_matches_code() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.signatures = HashSet::from(["eval(".to_string(), "Buffer.from(".to_string()]);

        assert!(threat.matches_code("const x = eval(malicious);"));
        assert!(threat.matches_code("const data = Buffer.from('base64');"));
        assert!(!threat.matches_code("const safe = 'hello world';"));
    }

    #[test]
    fn test_threat_find_signatures() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_signature("eval(".to_string());
        threat.add_signature("atob(".to_string());

        let sigs = threat.find_signatures("eval(atob('encoded'));");
        assert_eq!(sigs.len(), 2);
        assert!(sigs.contains(&"eval("));
        assert!(sigs.contains(&"atob("));
    }

    #[test]
    fn test_threat_is_payload_file() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_payload_file("evil.js".to_string());

        // Exact match
        assert!(threat.is_payload_file_known("evil.js"));

        // Path ending with payload file
        assert!(threat.is_payload_file_known("src/evil.js"));
        assert!(threat.is_payload_file_known("node_modules/package/evil.js"));
        assert!(threat.is_payload_file_known("./evil.js"));

        assert!(!threat.is_payload_file_known("notevil.js"));
        assert!(!threat.is_payload_file_known("src/notevil.js"));
        assert!(!threat.is_payload_file_known("evilX.js"));
        assert!(!threat.is_payload_file_known("myevil.js"));

        // Different file
        assert!(!threat.is_payload_file_known("safe.js"));
        assert!(!threat.is_payload_file_known("evil.ts"));
    }

    #[test]
    fn test_threat_is_payload_file_with_subdirectory() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_payload_file("malicious/setup.js".to_string());

        // Exact match
        assert!(threat.is_payload_file_known("malicious/setup.js"));

        // Path ending with payload
        assert!(threat.is_payload_file_known("src/malicious/setup.js"));
        assert!(threat.is_payload_file_known("./malicious/setup.js"));

        assert!(!threat.is_payload_file_known("setup.js")); // Missing directory
        assert!(!threat.is_payload_file_known("malicious/notsetup.js"));
        assert!(!threat.is_payload_file_known("notmalicious/setup.js"));
    }

    #[test]
    fn test_threat_is_payload_file_edge_cases() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_payload_file("a.js".to_string());

        assert!(threat.is_payload_file_known("a.js"));
        assert!(threat.is_payload_file_known("dir/a.js"));

        assert!(!threat.is_payload_file_known("ba.js"));
        assert!(!threat.is_payload_file_known("a.json"));
        assert!(!threat.is_payload_file_known("a.jso"));
    }

    #[test]
    fn test_threat_is_payload_file_multiple_payloads() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_payload_file("evil.js".to_string());
        threat.add_payload_file("backdoor.sh".to_string());
        threat.add_payload_file("malware/inject.py".to_string());

        // All payloads should match
        assert!(threat.is_payload_file_known("evil.js"));
        assert!(threat.is_payload_file_known("backdoor.sh"));
        assert!(threat.is_payload_file_known("malware/inject.py"));

        // With parent paths
        assert!(threat.is_payload_file_known("src/evil.js"));
        assert!(threat.is_payload_file_known("scripts/backdoor.sh"));
        assert!(threat.is_payload_file_known("node_modules/pkg/malware/inject.py"));

        // Should NOT match
        assert!(!threat.is_payload_file_known("notevil.js"));
        assert!(!threat.is_payload_file_known("backdoor.py"));
        assert!(!threat.is_payload_file_known("inject.py")); // Missing directory
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_add_package_idempotent(
            name in "[a-z]{3,10}",
            version in "[0-9]\\.[0-9]\\.[0-9]"
        ) {
            let mut threat = Threat::new(ThreatName::new("test").unwrap());
            let pkg = Package::from_strings(&name, &version).unwrap();

            // Add same package N times
            for _ in 0..10 {
                threat.add_package(pkg.clone());
            }

            // Should only have 1
            prop_assert_eq!(threat.package_count(), 1);
        }

        #[test]
        fn prop_add_signature_idempotent(sig in "[a-z()]{5,15}") {
            let mut threat = Threat::new(ThreatName::new("test").unwrap());

            // Add same signature N times
            for _ in 0..10 {
                threat.add_signature(sig.clone());
            }

            // Should only have 1
            prop_assert_eq!(threat.signatures.len(), 1);
        }

        #[test]
        fn prop_add_payload_file_idempotent(file in "[a-z]{3,10}\\.(js|sh)") {
            let mut threat = Threat::new(ThreatName::new("test").unwrap());

            // Add same file N times
            for _ in 0..10 {
                threat.add_payload_file(file.clone());
            }

            // Should only have 1
            prop_assert_eq!(threat.payload_files.len(), 1);
        }

        #[test]
        fn prop_add_packages_order_independent(
            pkg1_name in "[a-z]{3,8}",
            pkg2_name in "[a-z]{3,8}",
            version in "[0-9]\\.[0-9]\\.[0-9]"
        ) {
            let pkg1 = Package::from_strings(&pkg1_name, &version).unwrap();
            let pkg2 = Package::from_strings(&pkg2_name, &version).unwrap();

            let mut threat1 = Threat::new(ThreatName::new("test").unwrap());
            threat1.add_package(pkg1.clone());
            threat1.add_package(pkg2.clone());

            let mut threat2 = Threat::new(ThreatName::new("test").unwrap());
            threat2.add_package(pkg2);
            threat2.add_package(pkg1);

            // Order shouldn't matter
            prop_assert_eq!(threat1.package_count(), threat2.package_count());
        }

        #[test]
        fn prop_affects_consistent(
            name in "[a-z]{3,10}",
            version in "[0-9]\\.[0-9]\\.[0-9]"
        ) {
            let mut threat = Threat::new(ThreatName::new("test").unwrap());
            let pkg = Package::from_strings(&name, &version).unwrap();

            threat.add_package(pkg.clone());

            // affects() should always return true for added package
            prop_assert!(threat.affects(&pkg));

            // Multiple checks should be consistent
            for _ in 0..10 {
                prop_assert!(threat.affects(&pkg));
            }
        }

        #[test]
        fn prop_slugify_produces_valid_names(
            input in "[A-Za-z0-9 _-]{1,50}"
        ) {
            let slugified = ThreatName::slugify(&input);

            // Should either be valid or empty (if all special chars)
            if !slugified.is_empty() {
                let result = ThreatName::new(&slugified);
                prop_assert!(result.is_ok(), "Slugified '{}' from '{}' should be valid", slugified, input);
            }
        }

        #[test]
        fn prop_valid_slug_format_accepts(
            name in "[a-z][a-z0-9-]{0,98}[a-z0-9]"
        ) {
            // Generate valid slug-like strings
            if !name.contains("--") {
                let result = ThreatName::new(&name);
                prop_assert!(result.is_ok(), "Should accept valid slug: {}", name);
            }
        }
    }
}
