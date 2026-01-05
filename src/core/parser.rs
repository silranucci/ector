use crate::core::package::Package;

pub struct PackageJson {
    dependencies: Vec<Package>,
    dev_dependencies: Vec<Package>,
    peer_dependencies: Vec<Package>,
    optional_dependencies: Vec<Package>,
}

impl PackageJson {
    pub fn parse(value: &serde_json::Value) -> Self {
        Self {
            dependencies: Self::parse_deps(value, "dependencies"),
            dev_dependencies: Self::parse_deps(value, "devDependencies"),
            peer_dependencies: Self::parse_deps(value, "peerDependencies"),
            optional_dependencies: Self::parse_deps(value, "optionalDependencies"),
        }
    }

    fn parse_deps(value: &serde_json::Value, key: &str) -> Vec<Package> {
        value
            .get(key)
            .and_then(|deps| deps.as_object())
            .map(|deps| {
                deps.iter()
                    .filter_map(|(name, version)| {
                        version
                            .as_str()
                            .and_then(|v| Package::from_strings(name, v).ok())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all packages (all dependency types combined)
    pub fn all_packages(&self) -> Vec<Package> {
        let mut all = Vec::new();
        all.extend(self.dependencies.clone());
        all.extend(self.dev_dependencies.clone());
        all.extend(self.peer_dependencies.clone());
        all.extend(self.optional_dependencies.clone());
        all
    }
}

pub struct PackageLock {
    pub packages: Vec<Package>,
}

impl PackageLock {
    pub fn parse(value: &serde_json::Value) -> Self {
        let lockfile_version = value
            .get("lockfileVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(1);

        let packages = if lockfile_version >= 2 {
            Self::parse_v2_packages(value)
        } else {
            Self::parse_v1_dependencies(value)
        };

        Self { packages }
    }

    fn parse_v2_packages(value: &serde_json::Value) -> Vec<Package> {
        value
            .get("packages")
            .and_then(|p| p.as_object())
            .map(|packages| {
                packages
                    .iter()
                    .filter(|(path, _)| !path.is_empty())
                    .filter_map(|(path, pkg_info)| {
                        let name = extract_package_name_from_path(path);
                        let version = pkg_info.get("version")?.as_str()?;
                        Package::from_strings(name, version).ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_v1_dependencies(value: &serde_json::Value) -> Vec<Package> {
        value
            .get("dependencies")
            .and_then(|d| d.as_object())
            .map(|deps| {
                deps.iter()
                    .filter_map(|(name, dep_info)| {
                        let version = dep_info.get("version")?.as_str()?;
                        Package::from_strings(name, version).ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn all_packages(&self) -> Vec<Package> {
        self.packages.clone()
    }
}

pub struct YarnLock {
    pub packages: Vec<Package>,
}

impl YarnLock {
    pub fn parse(content: &str) -> Self {
        let mut packages = Vec::new();
        let mut current_name: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Package name line (doesn't start with space, contains @)
            if !trimmed.starts_with(' ') && trimmed.contains('@') {
                current_name = extract_yarn_package_name(trimmed);
            }
            // Version line (starts with space, contains "version")
            else if trimmed.starts_with("version ")
                && let Some(name) = current_name.take()
            {
                let version = trimmed
                    .trim_start_matches("version ")
                    .trim_matches('"')
                    .to_string();

                if let Ok(pkg) = Package::from_strings(&name, &version) {
                    packages.push(pkg);
                }
            }
        }

        Self { packages }
    }

    pub fn all_packages(&self) -> Vec<Package> {
        self.packages.clone()
    }
}

fn extract_package_name_from_path(path: &str) -> &str {
    // Handle scoped packages: node_modules/@babel/core -> @babel/core
    // Handle regular packages: node_modules/lodash -> lodash

    if let Some(idx) = path.rfind("node_modules/") {
        // Everything after "node_modules/"
        &path[idx + "node_modules/".len()..]
    } else {
        // No node_modules prefix, return as-is
        path
    }
}

fn extract_yarn_package_name(line: &str) -> Option<String> {
    // Remove quotes and get first spec (before comma)
    let spec = line
        .split(',')
        .next()?
        .trim()
        .trim_matches('"')
        .trim_end_matches(':');

    if let Some(rest) = spec.strip_prefix('@') {
        // Scoped package: @babel/core@^7.0.0
        if let Some(idx) = rest.find('@') {
            // idx is relative to rest, so add 1 to get position in spec
            return Some(spec[..idx + 1].to_string());
        }
    } else {
        // Regular package: lodash@^4.17.20
        if let Some(idx) = spec.find('@') {
            return Some(spec[..idx].to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_json_parse() {
        let json = serde_json::json!({
            "dependencies": {
                "lodash": "4.17.20",
                "express": "4.18.0"
            },
            "devDependencies": {
                "jest": "29.0.0"
            }
        });

        let pkg_json = PackageJson::parse(&json);
        let all = pkg_json.all_packages();

        assert_eq!(all.len(), 3);
        assert!(all.iter().any(|p| p.name_str() == "lodash"));
        assert!(all.iter().any(|p| p.name_str() == "express"));
        assert!(all.iter().any(|p| p.name_str() == "jest"));
    }

    #[test]
    fn test_package_json_all_dependency_types() {
        let json = serde_json::json!({
            "dependencies": {
                "lodash": "4.17.20"
            },
            "devDependencies": {
                "jest": "29.0.0"
            },
            "peerDependencies": {
                "react": "18.0.0"
            },
            "optionalDependencies": {
                "fsevents": "2.3.2"
            }
        });

        let pkg_json = PackageJson::parse(&json);
        let all = pkg_json.all_packages();

        assert_eq!(all.len(), 4);
        assert!(all.iter().any(|p| p.name_str() == "lodash"));
        assert!(all.iter().any(|p| p.name_str() == "jest"));
        assert!(all.iter().any(|p| p.name_str() == "react"));
        assert!(all.iter().any(|p| p.name_str() == "fsevents"));
    }

    #[test]
    fn test_package_json_empty() {
        let json = serde_json::json!({});
        let pkg_json = PackageJson::parse(&json);
        let all = pkg_json.all_packages();
        assert_eq!(all.len(), 0);
    }

    #[test]
    fn test_package_lock_v1_parse() {
        let json = serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                },
                "express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz"
                }
            }
        });

        let lock = PackageLock::parse(&json);

        assert_eq!(lock.packages.len(), 2);
        assert!(
            lock.packages
                .iter()
                .any(|p| p.name_str() == "lodash" && p.version_str() == "4.17.20")
        );
        assert!(
            lock.packages
                .iter()
                .any(|p| p.name_str() == "express" && p.version_str() == "4.18.0")
        );
    }

    #[test]
    fn test_package_lock_v2_parse() {
        let json = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {
                "": {
                    "name": "my-project",
                    "version": "1.0.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                },
                "node_modules/@babel/core": {
                    "version": "7.23.0",
                    "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz"
                }
            }
        });

        let lock = PackageLock::parse(&json);

        assert_eq!(lock.packages.len(), 2); // Root package is filtered out (empty path)
        assert!(
            lock.packages
                .iter()
                .any(|p| p.name_str() == "lodash" && p.version_str() == "4.17.21")
        );
        assert!(
            lock.packages
                .iter()
                .any(|p| p.name_str() == "@babel/core" && p.version_str() == "7.23.0")
        );
    }

    #[test]
    fn test_package_lock_v3_parse() {
        // v3 has same structure as v2
        let json = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-project"
                },
                "node_modules/react": {
                    "version": "18.2.0"
                }
            }
        });

        let lock = PackageLock::parse(&json);

        assert_eq!(lock.packages.len(), 1);
        assert!(lock.packages.iter().any(|p| p.name_str() == "react"));
    }

    #[test]
    fn test_package_lock_missing_version() {
        // Should default to v1
        let json = serde_json::json!({
            "dependencies": {
                "lodash": {
                    "version": "4.17.20"
                }
            }
        });

        let lock = PackageLock::parse(&json);
        assert_eq!(lock.packages.len(), 1);
    }

    #[test]
    fn test_package_lock_empty() {
        let json = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {}
        });

        let lock = PackageLock::parse(&json);
        assert_eq!(lock.packages.len(), 0);
    }

    #[test]
    fn test_package_lock_scoped_packages() {
        let json = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/@types/node": {
                    "version": "20.0.0"
                },
                "node_modules/@babel/preset-env": {
                    "version": "7.22.0"
                }
            }
        });

        let lock = PackageLock::parse(&json);

        assert_eq!(lock.packages.len(), 2);
        assert!(lock.packages.iter().any(|p| p.name_str() == "@types/node"));
        assert!(
            lock.packages
                .iter()
                .any(|p| p.name_str() == "@babel/preset-env")
        );
    }

    #[test]
    fn test_yarn_lock_parse() {
        let content = r#"
lodash@^4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

"@babel/core@^7.0.0":
  version "7.23.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.0.tgz"
"#;

        let yarn = YarnLock::parse(content);
        let packages = yarn.all_packages();

        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name_str() == "lodash"));
        assert!(packages.iter().any(|p| p.name_str() == "@babel/core"));
    }

    #[test]
    fn test_yarn_lock_multiple_versions() {
        let content = r#"
lodash@^4.17.15, lodash@^4.17.20:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"#;

        let yarn = YarnLock::parse(content);
        let packages = yarn.all_packages();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name_str(), "lodash");
        assert_eq!(packages[0].version_str(), "4.17.21");
    }

    #[test]
    fn test_yarn_lock_with_comments() {
        let content = r#"
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"
"#;

        let yarn = YarnLock::parse(content);
        let packages = yarn.all_packages();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name_str(), "lodash");
    }

    #[test]
    fn test_yarn_lock_empty() {
        let content = "";
        let yarn = YarnLock::parse(content);
        assert_eq!(yarn.packages.len(), 0);
    }

    #[test]
    fn test_extract_yarn_package_name() {
        // Regular package
        assert_eq!(
            extract_yarn_package_name("lodash@^4.17.20:"),
            Some("lodash".to_string())
        );

        // Scoped package
        assert_eq!(
            extract_yarn_package_name("\"@babel/core@^7.0.0\":"),
            Some("@babel/core".to_string())
        );

        // Scoped package without quotes
        assert_eq!(
            extract_yarn_package_name("@babel/core@^7.0.0:"),
            Some("@babel/core".to_string())
        );

        // Multiple version ranges
        assert_eq!(
            extract_yarn_package_name("lodash@^4.17.15, lodash@^4.17.20:"),
            Some("lodash".to_string())
        );
    }

    #[test]
    fn test_extract_package_name_from_path() {
        assert_eq!(
            extract_package_name_from_path("node_modules/lodash"),
            "lodash"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/@babel/core"),
            "@babel/core"
        );
        assert_eq!(extract_package_name_from_path("lodash"), "lodash");
    }
}
