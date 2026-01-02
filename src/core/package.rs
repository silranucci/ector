use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Package Name (validates NPM naming rules)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackageName(String);

impl PackageName {
    pub fn new(s: impl AsRef<str>) -> Result<Self> {
        let s = s.as_ref();

        if s.is_empty() {
            anyhow::bail!("Package name cannot be empty");
        }

        if s.chars().any(|c| c.is_ascii_uppercase()) {
            anyhow::bail!("Package name cannot contain uppercase letters");
        }

        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PackageName {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<PackageName> for String {
    fn from(name: PackageName) -> String {
        name.0
    }
}

impl Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Semantic Version
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version(String);

impl Version {
    pub fn new(s: impl AsRef<str>) -> Result<Self> {
        let s = s.as_ref();

        if s.is_empty() {
            anyhow::bail!("Version cannot be empty");
        }

        if !s.chars().next().unwrap_or('0').is_ascii_digit() {
            anyhow::bail!("Version must start with a digit");
        }

        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Version should have three parts: <Major>.<Minor>.<Patch>");
        }

        for part in &parts {
            if !part.chars().all(|c| c.is_ascii_digit()) {
                anyhow::bail!("Invalid version number part: {}", part);
            }
        }

        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Version {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<Version> for String {
    fn from(v: Version) -> String {
        v.0
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Package {
    pub name: PackageName,
    pub version: Version,
}

impl Package {
    pub fn new(name: PackageName, version: Version) -> Self {
        Self { name, version }
    }

    /// Create from strings (convenience)
    pub fn from_strings(name: impl AsRef<str>, version: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: PackageName::new(name)?,
            version: Version::new(version)?,
        })
    }

    /// Check if this package matches name and version strings
    pub fn matches(&self, name: &str, version: &str) -> bool {
        self.name.as_str() == name && self.version.as_str() == version
    }

    /// Get name as string
    pub fn name_str(&self) -> &str {
        self.name.as_str()
    }

    /// Get version as string
    pub fn version_str(&self) -> &str {
        self.version.as_str()
    }
}

fn parse_package_input(input: String) -> Result<Package> {
    if input.starts_with('@') {
        let parts: Vec<&str> = input.rsplitn(2, '@').collect();
        if parts.len() != 2 {
            anyhow::bail!("Format must be: @scope/package@version");
        }

        let version = parts[0].trim();
        let name = parts[1].trim();

        if name.is_empty() || version.is_empty() {
            anyhow::bail!("Package name and version cannot be empty");
        }

        return Package::from_strings(name, version);
    }

    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        anyhow::bail!("Format must be: package@version");
    }

    let name = parts[0].trim();
    let version = parts[1].trim();

    if name.is_empty() || version.is_empty() {
        anyhow::bail!("Package name and version cannot be empty");
    }

    Package::from_strings(name, version)
}

impl TryFrom<String> for Package {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        parse_package_input(s)
    }
}

impl Display for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_creation() {
        let pkg = Package::new(
            PackageName::new("lodash").unwrap(),
            Version::new("4.17.20").unwrap(),
        );

        assert_eq!(pkg.name_str(), "lodash");
        assert_eq!(pkg.version_str(), "4.17.20");
    }

    #[test]
    fn test_package_from_strings() {
        let pkg = Package::from_strings("lodash", "4.17.20").unwrap();
        assert_eq!(pkg.name_str(), "lodash");
        assert_eq!(pkg.version_str(), "4.17.20");
    }

    #[test]
    fn test_package_matches() {
        let pkg = Package::from_strings("lodash", "4.17.20").unwrap();

        assert!(pkg.matches("lodash", "4.17.20"));
        assert!(!pkg.matches("lodash", "4.17.21"));
        assert!(!pkg.matches("chalk", "4.17.20"));
    }

    #[test]
    fn test_package_display() {
        let pkg = Package::from_strings("lodash", "4.17.20").unwrap();
        assert_eq!(format!("{}", pkg), "lodash@4.17.20");
    }

    #[test]
    fn test_package_equality() {
        let pkg1 = Package::from_strings("lodash", "4.17.20").unwrap();
        let pkg2 = Package::from_strings("lodash", "4.17.20").unwrap();
        let pkg3 = Package::from_strings("lodash", "4.17.21").unwrap();

        assert_eq!(pkg1, pkg2);
        assert_ne!(pkg1, pkg3);
    }

    #[test]
    fn test_package_scoped() {
        let pkg = Package::from_strings("@babel/core", "7.23.0").unwrap();
        assert_eq!(format!("{}", pkg), "@babel/core@7.23.0");
    }

    #[test]
    fn test_parse_package_input_simple() {
        let pkg = parse_package_input("lodash@4.17.20".into()).unwrap();
        assert_eq!(pkg.name_str(), "lodash");
        assert_eq!(pkg.version_str(), "4.17.20");
    }

    #[test]
    fn test_parse_package_input_scoped() {
        let pkg = parse_package_input("@babel/core@7.23.0".into()).unwrap();
        assert_eq!(pkg.name_str(), "@babel/core");
        assert_eq!(pkg.version_str(), "7.23.0");
    }

    #[test]
    fn test_parse_package_input_invalid() {
        assert!(parse_package_input("lodash".into()).is_err());
        assert!(parse_package_input("lodash@".into()).is_err());
        assert!(parse_package_input("@7.23.0".into()).is_err());
        assert!(parse_package_input("".into()).is_err());
    }

    #[test]
    fn test_parse_package_input_whitespace() {
        let pkg = parse_package_input("  lodash  @  4.17.20  ".into()).unwrap();
        assert_eq!(pkg.name_str(), "lodash");
        assert_eq!(pkg.version_str(), "4.17.20");
    }
}
