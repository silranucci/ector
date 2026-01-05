use std::collections::HashSet;

use crate::core::{
    package::Package,
    parser::{PackageJson, PackageLock, YarnLock},
    threat::Threat,
};

pub struct Checker {
    threats: Vec<Threat>,
}

impl Checker {
    pub fn new(threats: Vec<Threat>) -> Self {
        Self { threats }
    }

    /// Check if packages are compromised
    pub fn check_packages(
        &self,
        packages: &[Package],
        location: &str,
    ) -> Vec<CompromisedPackageIssue> {
        packages
            .iter()
            .flat_map(|pkg| {
                self.threats
                    .iter()
                    .filter(|threat| threat.affects(pkg))
                    .map(|threat| CompromisedPackageIssue {
                        package_name: pkg.name_str().to_string(),
                        version: pkg.version_str().to_string(),
                        location: location.to_string(),
                        threat_name: threat.name.as_str().to_string(),
                    })
            })
            .collect()
    }

    /// Check if file content contains malicious signatures
    pub fn check_file_content(&self, content: &str, file_path: &str) -> Vec<MaliciousCodeIssue> {
        let mut issues = Vec::new();

        for threat in &self.threats {
            for signature in &threat.signatures {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(signature) {
                        issues.push(MaliciousCodeIssue {
                            file_path: file_path.to_string(),
                            signature: signature.clone(),
                            line_number: Some(line_num + 1),
                            threat_name: threat.name.as_str().to_string(),
                        });
                    }
                }
            }
        }

        issues
    }

    /// Check if payload file exists in given path (using proper path matching)
    pub fn check_payload_file(&self, file_path: &str) -> Vec<PayloadFileIssue> {
        let mut issues = Vec::new();

        for threat in &self.threats {
            if threat.is_payload_file_known(file_path) {
                // Find which specific payload file matched
                for payload_file in &threat.payload_files {
                    if file_path == payload_file || file_path.ends_with(payload_file) {
                        issues.push(PayloadFileIssue {
                            file_path: file_path.to_string(),
                            payload_type: payload_file.clone(),
                            threat_name: threat.name.as_str().to_string(),
                        });
                        break; // Only report once per threat
                    }
                }
            }
        }

        issues
    }

    /// Check if any threats have signatures
    pub fn has_signatures(&self) -> bool {
        self.threats.iter().any(|t| !t.signatures.is_empty())
    }

    /// Check if any threats have payload files
    pub fn has_payload_files(&self) -> bool {
        self.threats.iter().any(|t| !t.payload_files.is_empty())
    }

    /// Parse package.json and check packages
    pub fn scan_package_json_data(
        &self,
        json_value: &serde_json::Value,
        location: &str,
    ) -> ScanResult {
        let package_json = PackageJson::parse(json_value);
        let packages = package_json.all_packages();
        let issues = self.check_packages(&packages, location);

        let mut result = ScanResult::empty().with_packages_checked(packages.len());

        for issue in issues {
            result = result.with_compromised_package(issue);
        }

        result
    }

    /// Parse package-lock.json and check packages
    pub fn scan_package_lock_data(
        &self,
        json_value: &serde_json::Value,
        location: &str,
    ) -> ScanResult {
        let package_lock = PackageLock::parse(json_value);
        let packages = package_lock.all_packages();
        let issues = self.check_packages(&packages, location);

        let mut result = ScanResult::empty().with_packages_checked(packages.len());

        for issue in issues {
            result = result.with_compromised_package(issue);
        }

        result
    }

    /// Parse yarn.lock and check packages
    pub fn scan_yarn_lock_data(&self, content: &str, location: &str) -> ScanResult {
        let yarn_lock = YarnLock::parse(content);
        let packages = yarn_lock.all_packages();
        let issues = self.check_packages(&packages, location);

        let mut result = ScanResult::empty().with_packages_checked(packages.len());

        for issue in issues {
            result = result.with_compromised_package(issue);
        }

        result
    }

    // /// Scan file content for malicious code
    // pub fn scan_file_content(&self, content: &str, file_path: &str) -> ScanResult {
    //     let issues = self.check_file_content(content, file_path);
    //
    //     let mut result = ScanResult::empty().with_files_scanned(1);
    //
    //     for issue in issues {
    //         result = result.with_malicious_code(issue);
    //     }
    //
    //     result
    // }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompromisedPackageIssue {
    pub package_name: String,
    pub version: String,
    pub location: String,
    pub threat_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MaliciousCodeIssue {
    pub file_path: String,
    pub signature: String,
    pub line_number: Option<usize>,
    pub threat_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PayloadFileIssue {
    pub file_path: String,
    pub payload_type: String,
    pub threat_name: String,
}

/// Scan result implementing Monoid algebra
///
/// Laws:
/// 1. Identity: `result.combine(empty()) = result`
/// 2. Associativity: `(a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)`
/// 3. Commutativity: `a ⊕ b = b ⊕ a` (bonus property)
///
/// Uses HashSet for automatic deduplication of issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub packages_checked: usize,
    pub files_scanned: usize,
    // Issues stored in HashSet for automatic deduplication
    compromised_packages: HashSet<CompromisedPackageIssue>,
    malicious_code: HashSet<MaliciousCodeIssue>,
    payload_files: HashSet<PayloadFileIssue>,
}

impl ScanResult {
    /// Monoid identity element (empty result)
    pub fn empty() -> Self {
        Self {
            packages_checked: 0,
            files_scanned: 0,
            compromised_packages: HashSet::new(),
            malicious_code: HashSet::new(),
            payload_files: HashSet::new(),
        }
    }

    /// Monoid combine operation (associative, commutative)
    ///
    /// Satisfies:
    /// - `empty().combine(x) = x`
    /// - `x.combine(empty()) = x`
    /// - `(a.combine(b)).combine(c) = a.combine(b.combine(c))`
    /// - `a.combine(b) = b.combine(a)`
    pub fn combine(mut self, other: Self) -> Self {
        self.packages_checked += other.packages_checked;
        self.files_scanned += other.files_scanned;
        self.compromised_packages.extend(other.compromised_packages);
        self.malicious_code.extend(other.malicious_code);
        self.payload_files.extend(other.payload_files);
        self
    }

    /// Builder: add packages checked
    pub fn with_packages_checked(mut self, count: usize) -> Self {
        self.packages_checked += count;
        self
    }

    /// Builder: add files scanned
    pub fn with_files_scanned(mut self, count: usize) -> Self {
        self.files_scanned += count;
        self
    }

    /// Builder: add a compromised package issue
    pub fn with_compromised_package(mut self, issue: CompromisedPackageIssue) -> Self {
        self.compromised_packages.insert(issue);
        self
    }

    /// Builder: add malicious code issue
    pub fn with_malicious_code(mut self, issue: MaliciousCodeIssue) -> Self {
        self.malicious_code.insert(issue);
        self
    }

    /// Builder: add payload file issue
    pub fn with_payload_file(mut self, issue: PayloadFileIssue) -> Self {
        self.payload_files.insert(issue);
        self
    }

    /// Check if any issues were found
    pub fn has_issues(&self) -> bool {
        !self.compromised_packages.is_empty()
            || !self.malicious_code.is_empty()
            || !self.payload_files.is_empty()
    }

    /// Get total count of issues
    pub fn issues_found(&self) -> usize {
        self.compromised_packages.len() + self.malicious_code.len() + self.payload_files.len()
    }

    /// Get compromised packages
    pub fn compromised_packages(&self) -> &HashSet<CompromisedPackageIssue> {
        &self.compromised_packages
    }

    /// Get malicious code issues
    pub fn malicious_code(&self) -> &HashSet<MaliciousCodeIssue> {
        &self.malicious_code
    }

    /// Get payload files
    pub fn payload_files(&self) -> &HashSet<PayloadFileIssue> {
        &self.payload_files
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod core_tests {
    use super::*;
    use crate::core::{
        package::Package,
        threat::{Threat, ThreatName},
    };
    use chrono::NaiveDate;

    fn create_test_threat() -> Threat {
        let mut threat = Threat::new(ThreatName::new("test-threat").unwrap());
        threat.date = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

        let pkg = Package::from_strings("lodash", "4.17.20").unwrap();
        threat.add_package(pkg);
        threat.add_signature("eval(".to_string());
        threat.add_payload_file("malicious.sh".to_string());

        threat
    }

    #[test]
    fn test_core_check_packages_idempotent() {
        let core = Checker::new(vec![create_test_threat()]);
        let packages = vec![Package::from_strings("lodash", "4.17.20").unwrap()];

        let result1 = core.check_packages(&packages, "test.json");
        let result2 = core.check_packages(&packages, "test.json");

        assert_eq!(result1.len(), 1);
        assert_eq!(result1.len(), 1);
        assert_eq!(result1.len(), result2.len());
        assert_eq!(result1[0].package_name, "lodash");
    }

    #[test]
    fn test_core_check_packages_empty() {
        let core = Checker::new(vec![create_test_threat()]);

        // Law: Empty input = empty output
        let result = core.check_packages(&[], "test.json");
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_core_check_file_content_idempotent() {
        let core = Checker::new(vec![create_test_threat()]);
        let content = "const x = eval(something);";

        let result1 = core.check_file_content(content, "test.js");
        let result2 = core.check_file_content(content, "test.js");

        assert_eq!(result1.len(), 1);
        assert_eq!(result2.len(), 1);
        assert_eq!(result1.len(), result2.len());
        assert_eq!(result1[0].signature, "eval(");
    }

    #[test]
    fn test_core_check_file_content_no_match() {
        let core = Checker::new(vec![create_test_threat()]);
        let content = "const x = 42;";

        // Law: No malicious code = empty result
        let result = core.check_file_content(content, "test.js");
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_core_scan_package_json_idempotent() {
        let core = Checker::new(vec![create_test_threat()]);
        let json = serde_json::json!({
            "dependencies": {
                "lodash": "4.17.20"
            }
        });

        let result1 = core.scan_package_json_data(&json, "package.json");
        let result2 = core.scan_package_json_data(&json, "package.json");

        assert_eq!(result1, result2);
        assert_eq!(result1.packages_checked, 1);
        assert_eq!(result1.compromised_packages().len(), 1);
        assert_eq!(result2.packages_checked, 1);
        assert_eq!(result2.compromised_packages().len(), 1);
    }

    #[test]
    fn test_check_payload_file_no_false_positives() {
        let mut threat = Threat::new(ThreatName::new("test").unwrap());
        threat.add_payload_file("evil.js".to_string());

        let checker = Checker::new(vec![threat]);

        // Should match
        assert_eq!(checker.check_payload_file("evil.js").len(), 1);
        assert_eq!(checker.check_payload_file("src/evil.js").len(), 1);

        // Should NOT match - false positive prevention
        assert_eq!(checker.check_payload_file("notevil.js").len(), 0);
        assert_eq!(checker.check_payload_file("myevil.js").len(), 0);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    // Generators for test data
    prop_compose! {
        fn compromised_package_issue()(
            package_name in "[a-z]{3,10}",
            version in "[0-9]\\.[0-9]\\.[0-9]",
            location in "[a-z/]{5,15}\\.json",
            threat_name in "[a-z-]{5,15}",
        ) -> CompromisedPackageIssue {
            CompromisedPackageIssue {
                package_name,
                version,
                location,
                threat_name,
            }
        }
    }

    prop_compose! {
        fn malicious_code_issue()(
            file_path in "[a-z/]{5,15}\\.js",
            signature in "[a-z()]{5,15}",
            line_number in prop::option::of(1usize..1000),
            threat_name in "[a-z-]{5,15}",
        ) -> MaliciousCodeIssue {
            MaliciousCodeIssue {
                file_path,
                signature,
                line_number,
                threat_name,
            }
        }
    }

    prop_compose! {
        fn payload_file_issue()(
            file_path in "[a-z/]{5,15}\\.(sh|js|py)",
            payload_type in "[a-z]{4,10}",
            threat_name in "[a-z-]{5,15}",
        ) -> PayloadFileIssue {
            PayloadFileIssue {
                file_path,
                payload_type,
                threat_name,
            }
        }
    }

    prop_compose! {
        fn scan_result()(
            packages_checked in 0usize..100,
            files_scanned in 0usize..100,
            comp_issues in prop::collection::vec(compromised_package_issue(), 0..5),
            mal_issues in prop::collection::vec(malicious_code_issue(), 0..5),
            pay_issues in prop::collection::vec(payload_file_issue(), 0..5),
        ) -> ScanResult {
            let mut result = ScanResult::empty()
                .with_packages_checked(packages_checked)
                .with_files_scanned(files_scanned);

            for issue in comp_issues {
                result = result.with_compromised_package(issue);
            }
            for issue in mal_issues {
                result = result.with_malicious_code(issue);
            }
            for issue in pay_issues {
                result = result.with_payload_file(issue);
            }

            result
        }
    }

    proptest! {
        #[test]
        fn prop_monoid_left_identity(result in scan_result()) {
            // Law: empty().combine(x) = x
            let combined = ScanResult::empty().combine(result.clone());
            prop_assert_eq!(combined, result);
        }

        #[test]
        fn prop_monoid_right_identity(result in scan_result()) {
            // Law: x.combine(empty()) = x
            let combined = result.clone().combine(ScanResult::empty());
            prop_assert_eq!(combined, result);
        }

        #[test]
        fn prop_monoid_associativity(
            a in scan_result(),
            b in scan_result(),
            c in scan_result()
        ) {
            // Law: (a * b) * c = a * (b * c)
            let left = a.clone().combine(b.clone()).combine(c.clone());
            let right = a.combine(b.combine(c));
            prop_assert_eq!(left, right);
        }

        #[test]
        fn prop_monoid_commutativity(
            a in scan_result(),
            b in scan_result()
        ) {
            // Bonus property: a * b = b * a (commutative monoid)
            let ab = a.clone().combine(b.clone());
            let ba = b.combine(a);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn prop_combine_preserves_counts(
            packages_a in 0usize..50,
            packages_b in 0usize..50,
            files_a in 0usize..50,
            files_b in 0usize..50,
        ) {
            let a = ScanResult::empty()
                .with_packages_checked(packages_a)
                .with_files_scanned(files_a);

            let b = ScanResult::empty()
                .with_packages_checked(packages_b)
                .with_files_scanned(files_b);

            let result = a.combine(b);

            prop_assert_eq!(result.packages_checked, packages_a + packages_b);
            prop_assert_eq!(result.files_scanned, files_a + files_b);
        }

        #[test]
        fn prop_deduplication_idempotent(issue in compromised_package_issue()) {
            // Adding the same issue multiple times should result in 1 issue
            let result = ScanResult::empty()
                .with_compromised_package(issue.clone())
                .with_compromised_package(issue.clone())
                .with_compromised_package(issue);

            prop_assert_eq!(result.compromised_packages().len(), 1);
        }

        #[test]
        fn prop_has_issues_correct(result in scan_result()) {
            let has_issues = result.has_issues();
            let actual_issues = !result.compromised_packages().is_empty()
                || !result.malicious_code().is_empty()
                || !result.payload_files().is_empty();

            prop_assert_eq!(has_issues, actual_issues);
        }

        #[test]
        fn prop_issues_count_correct(result in scan_result()) {
            let expected = result.compromised_packages().len()
                + result.malicious_code().len()
                + result.payload_files().len();

            prop_assert_eq!(result.issues_found(), expected);
        }
    }
}
