use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

/// Get a command for the CLI binary
fn ector_cmd() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap()
}

/// Create a temporary directory for tests with threats subdirectory
fn setup_temp_dir() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir_all(temp_dir.path().join("threats")).unwrap();
    temp_dir
}

/// Normalize CLI output to remove dynamic content for stable snapshots
fn normalize_output(output: &str) -> String {
    use regex::Regex;

    let mut normalized = output.to_string();

    // Normalize timestamps if present (e.g., "2025-01-09 14:30:15" -> "<TIMESTAMP>")
    let timestamp_re = Regex::new(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}").unwrap();
    normalized = timestamp_re
        .replace_all(&normalized, "<TIMESTAMP>")
        .to_string();

    // Normalize absolute paths to relative (e.g., "/home/user/project" -> "<PROJECT_DIR>")
    let current_dir = std::env::current_dir().unwrap();
    let current_dir_str = current_dir.to_string_lossy();
    normalized = normalized.replace(&current_dir_str.to_string(), "<PROJECT_DIR>");

    // Normalize file counts if they vary (e.g., "Files scanned: 123" -> "Files scanned: <N>")
    // Only normalize if > 0 (we want to keep "0" as meaningful)
    let files_scanned_re = Regex::new(r"Files scanned:\s+([1-9]\d*)").unwrap();
    normalized = files_scanned_re
        .replace_all(&normalized, "Files scanned: <N>")
        .to_string();

    // Normalize package counts > 10 (exact small numbers are meaningful)
    let packages_checked_re = Regex::new(r"Packages checked:\s+(\d{2,})").unwrap();
    normalized = packages_checked_re
        .replace_all(&normalized, "Packages checked: <N>")
        .to_string();

    // Remove stack backtraces (added by RUST_BACKTRACE in CI)
    normalized = remove_backtrace(&normalized);

    // Sort lists to handle non-deterministic ordering
    normalized = sort_lists_in_output(&normalized);

    normalized
}

/// Remove stack backtrace from error output
fn remove_backtrace(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let mut result = Vec::new();
    let mut skip_backtrace = false;

    for line in lines {
        // Detect start of backtrace
        if line.trim() == "Stack backtrace:" {
            skip_backtrace = true;
            continue;
        }

        // Skip backtrace lines (numbered entries)
        if skip_backtrace {
            // Backtrace lines typically start with whitespace and a number
            if line.trim_start().starts_with(|c: char| c.is_numeric()) && line.contains(':') {
                continue;
            } else {
                // End of backtrace
                skip_backtrace = false;
            }
        }

        result.push(line);
    }

    result.join("\n")
}

/// Sort lists in output to handle non-deterministic ordering
fn sort_lists_in_output(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let mut result = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Check if this is a list header (Packages:, Signatures:, etc.)
        if line.trim().ends_with(':')
            && (line.contains("Packages:")
                || line.contains("Signatures:")
                || line.contains("Payload Files:")
                || line.contains("Workflow Paths:"))
        {
            result.push(line.to_string());
            i += 1;

            // Collect all list items (lines starting with "  • ")
            let mut items = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with("•") {
                items.push(lines[i].to_string());
                i += 1;
            }

            // Sort the items
            items.sort();

            // Add sorted items to result
            result.extend(items);
        } else {
            result.push(line.to_string());
            i += 1;
        }
    }

    result.join("\n")
}

// ============================================================================
// ADD COMMAND TESTS
// ============================================================================

#[test]
fn test_add_with_single_package() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Test Package Attack")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with package")
        .arg("-p")
        .arg("lodash@4.17.20")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_single_package", normalized);
    assert_eq!(output.status.code(), Some(0), "Command should succeed");
}

#[test]
fn test_add_with_multiple_packages() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Multi Package Attack")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with multiple packages")
        .arg("-p")
        .arg("lodash@4.17.20")
        .arg("-p")
        .arg("express@4.18.0")
        .arg("-p")
        .arg("@babel/core@7.23.0")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_multiple_packages", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_invalid_package_format() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Bad Package")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with invalid package")
        .arg("-p")
        .arg("lodash") // Missing version
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_invalid_package", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_scoped_package() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Scoped Package Attack")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with scoped package")
        .arg("-p")
        .arg("@babel/core@7.23.0")
        .arg("-p")
        .arg("@types/node@20.0.0")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_scoped_packages", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_single_signature() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Signature Test")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with signature")
        .arg("-s")
        .arg("eval(Buffer.from(")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_single_signature", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_multiple_signatures() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Multi Signature")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Multiple signatures")
        .arg("-s")
        .arg("eval(Buffer.from(")
        .arg("-s")
        .arg("atob(")
        .arg("-s")
        .arg("require('child_process')")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_multiple_signatures", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_single_payload() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Payload Test")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with payload")
        .arg("-f")
        .arg("malicious-setup.js")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_single_payload", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_multiple_payloads() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Multi Payload")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Multiple payloads")
        .arg("-f")
        .arg("setup.js")
        .arg("-f")
        .arg("install.sh")
        .arg("-f")
        .arg("postinstall.js")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_multiple_payloads", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_single_workflow() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Workflow Test")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Test with workflow")
        .arg("-w")
        .arg(".github/workflows/publish.yml")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_single_workflow", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_multiple_workflows() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Multi Workflow")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Multiple workflows")
        .arg("-w")
        .arg(".github/workflows/release.yml")
        .arg("-w")
        .arg(".github/workflows/publish.yml")
        .arg("-w")
        .arg(".github/workflows/ci.yml")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_multiple_workflows", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_with_all_fields() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Complete Attack")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Attack with all fields")
        .arg("--cve")
        .arg("CVE-2025-12345")
        .arg("-p")
        .arg("lodash@4.17.20")
        .arg("-p")
        .arg("express@4.18.0")
        .arg("-s")
        .arg("eval(")
        .arg("-s")
        .arg("atob(")
        .arg("-f")
        .arg("malicious.js")
        .arg("-w")
        .arg(".github/workflows/publish.yml")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_all_fields", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_event_stream_realistic() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Event Stream Compromise")
        .arg("--date")
        .arg("2018-11-26")
        .arg("--description")
        .arg("Malicious code injection in event-stream via flatmap-stream")
        .arg("--cve")
        .arg("CVE-2018-3728")
        .arg("-p")
        .arg("event-stream@3.3.6")
        .arg("-p")
        .arg("flatmap-stream@0.1.1")
        .arg("-s")
        .arg("eval(Buffer.from(")
        .arg("-s")
        .arg("module.exports = function()")
        .arg("-f")
        .arg("flatmap-stream/index.js")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_event_stream_realistic", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_add_packages_only_without_metadata() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("-p")
        .arg("lodash@4.17.20")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("=== STDOUT ===\n{}\n=== STDERR ===\n{}", stdout, stderr);
    let normalized = normalize_output(&combined);

    insta::assert_snapshot!("add_missing_required_fields", normalized);
    // Should fail - missing required fields
    assert_ne!(output.status.code(), Some(0));
}

#[test]
fn test_add_minimal_metadata_with_packages() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Minimal")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("Minimal attack")
        .arg("-p")
        .arg("lodash@4.17.20")
        .output()
        .expect("Failed to execute add command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("add_minimal_with_package", normalized);
    assert_eq!(output.status.code(), Some(0));
}

// ============================================================================
// LIST COMMAND TESTS
// ============================================================================

#[test]
fn test_list_when_empty() {
    let temp_dir = setup_temp_dir();

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .output()
        .expect("Failed to execute list command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("list_empty", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_list_shows_multiple_threats() {
    let temp_dir = setup_temp_dir();

    // Add first threat
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("First Attack")
        .arg("--date")
        .arg("2025-01-01")
        .arg("--description")
        .arg("First")
        .output()
        .expect("Failed to add first threat");

    // Add second threat
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Second Attack")
        .arg("--date")
        .arg("2025-01-02")
        .arg("--description")
        .arg("Second")
        .output()
        .expect("Failed to add second threat");

    // Add third threat
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("--name")
        .arg("Third Attack")
        .arg("--date")
        .arg("2025-01-03")
        .arg("--description")
        .arg("Third")
        .output()
        .expect("Failed to add third threat");

    // List all threats
    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .output()
        .expect("Failed to execute list command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("list_multiple_threats", normalized);
    assert_eq!(output.status.code(), Some(0));
}

// ============================================================================
// HELP COMMAND TESTS
// ============================================================================

#[test]
fn test_add_help_shows_all_options() {
    let output = ector_cmd()
        .arg("add")
        .arg("--help")
        .output()
        .expect("Failed to execute help command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("help_add", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_list_help() {
    let output = ector_cmd()
        .arg("list")
        .arg("--help")
        .output()
        .expect("Failed to execute help command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("help_list", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_check_help() {
    let output = ector_cmd()
        .arg("check")
        .arg("--help")
        .output()
        .expect("Failed to execute help command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("help_check", normalized);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_main_help() {
    let output = ector_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute help command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("help_main", normalized);
    assert_eq!(output.status.code(), Some(0));
}

// ============================================================================
// CHECK COMMAND TESTS - SETUP + CHECK + SNAPSHOT PATTERN
// ============================================================================

/// Setup phase: Add a threat and verify it was added successfully via list command
fn setup_threat(
    temp_dir: &TempDir,
    name: &str,
    date: &str,
    description: &str,
    cve: Option<&str>,
    packages: &[&str],
    signatures: &[&str],
    payload_files: &[&str],
) {
    let mut cmd = ector_cmd();
    cmd.current_dir(temp_dir)
        .arg("add")
        .arg("--name")
        .arg(name)
        .arg("--date")
        .arg(date)
        .arg("--description")
        .arg(description);

    if let Some(cve) = cve {
        cmd.arg("--cve").arg(cve);
    }

    for package in packages {
        cmd.arg("-p").arg(package);
    }

    for signature in signatures {
        cmd.arg("-s").arg(signature);
    }

    for payload in payload_files {
        cmd.arg("-f").arg(payload);
    }

    let output = cmd.output().expect("Failed to execute add command");
    assert_eq!(output.status.code(), Some(0), "Add command should succeed");

    let list_output = ector_cmd()
        .current_dir(temp_dir)
        .arg("list")
        .output()
        .expect("Failed to run list command");

    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    let threat_slug = name.to_lowercase().replace(' ', "-");

    assert!(
        list_stdout.contains(&threat_slug),
        "Threat '{}' should appear in list output",
        threat_slug
    );

    if !packages.is_empty() {
        assert!(
            list_stdout.contains(&format!("Packages: {}", packages.len())),
            "List should show {} package(s)",
            packages.len()
        );
    }
}

#[test]
fn test_check_effect_app_npm_with_effect_platform_threat() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found at {:?}", fixture_path);
        return;
    }

    setup_threat(
        &temp_dir,
        "Effect Platform Compromise",
        "2025-01-09",
        "Malicious code injection in @effect/platform package",
        Some("CVE-2025-12345"),
        &["@effect/platform@0.90.3"],
        &["eval(", "process.env.SECRET"],
        &["malicious-setup.js"],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_npm_platform_threat", normalized_stdout);
}

#[test]
fn test_check_effect_app_npm_with_effect_core_threat() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "Effect Core Vulnerability",
        "2025-01-09",
        "Critical vulnerability in core Effect library",
        Some("CVE-2025-99999"),
        &["effect@3.17.7"],
        &["Buffer.from(", "eval("],
        &[],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_npm_core_threat", normalized_stdout);
}

#[test]
fn test_check_effect_app_npm_with_typescript_threat() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "TypeScript Compiler Backdoor",
        "2025-01-09",
        "Malicious TypeScript compiler with code execution backdoor",
        Some("CVE-2025-88888"),
        &["typescript@5.6.3"],
        &["eval(", "Function("],
        &[],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_npm_typescript_threat", normalized_stdout);
}

#[test]
fn test_check_effect_app_npm_clean_with_unrelated_threat() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "Lodash Compromise",
        "2025-01-09",
        "Malicious lodash package with data exfiltration",
        Some("CVE-2025-00000"),
        &["lodash@4.17.21"],
        &["eval(", "fetch("],
        &[],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_npm_clean", normalized_stdout);
}

#[test]
fn test_check_effect_app_npm_with_multiple_threats() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "Effect Platform Compromise",
        "2025-01-09",
        "Malicious @effect/platform",
        Some("CVE-2025-12345"),
        &["@effect/platform@0.90.3"],
        &["eval("],
        &[],
    );

    setup_threat(
        &temp_dir,
        "Effect Core Vulnerability",
        "2025-01-09",
        "Core library vulnerability",
        Some("CVE-2025-99999"),
        &["effect@3.17.7"],
        &["Buffer.from("],
        &[],
    );

    setup_threat(
        &temp_dir,
        "TypeScript Backdoor",
        "2025-01-09",
        "TypeScript compiler backdoor",
        Some("CVE-2025-88888"),
        &["typescript@5.6.3"],
        &["Function("],
        &[],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_npm_multiple_threats", normalized_stdout);
}

#[test]
fn test_check_effect_app_yarn_with_platform_threat() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app-yarn");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found at {:?}", fixture_path);
        return;
    }

    setup_threat(
        &temp_dir,
        "Effect Platform Compromise",
        "2025-01-09",
        "Malicious @effect/platform for yarn project",
        Some("CVE-2025-12345"),
        &["@effect/platform@0.90.3"],
        &["eval(", "process.env.SECRET"],
        &[],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_yarn_platform_threat", normalized_stdout);
}

#[test]
fn test_check_effect_app_yarn_clean() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app-yarn");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "Lodash Compromise",
        "2025-01-09",
        "Malicious lodash",
        Some("CVE-2025-00000"),
        &["lodash@4.17.21"],
        &[],
        &[],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_effect_yarn_clean", normalized_stdout);
}

#[test]
fn test_check_npm_vs_yarn_consistency() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();

    let npm_fixture = project_root.join("tests/fixture-projects/effect-app");
    let yarn_fixture = project_root.join("tests/fixture-projects/effect-app-yarn");

    if !npm_fixture.exists() || !yarn_fixture.exists() {
        eprintln!("Skipping: fixtures not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "Effect Platform Compromise",
        "2025-01-09",
        "Malicious @effect/platform",
        Some("CVE-2025-12345"),
        &["@effect/platform@0.90.3"],
        &["eval("],
        &[],
    );

    let npm_output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&npm_fixture)
        .output()
        .unwrap();

    let yarn_output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&yarn_fixture)
        .output()
        .unwrap();

    let npm_stdout = String::from_utf8_lossy(&npm_output.stdout).to_string();
    let yarn_stdout = String::from_utf8_lossy(&yarn_output.stdout).to_string();

    let npm_normalized = normalize_output(&npm_stdout);
    let yarn_normalized = normalize_output(&yarn_stdout);

    insta::assert_snapshot!("check_npm_vs_yarn_npm", npm_normalized);
    insta::assert_snapshot!("check_npm_vs_yarn_yarn", yarn_normalized);
}

#[test]
fn test_check_with_no_threats_loaded() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_no_threats_loaded", normalized_stdout);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_check_with_payload_file_detection() {
    let temp_dir = setup_temp_dir();
    let project_root = std::env::current_dir().unwrap();
    let fixture_path = project_root.join("tests/fixture-projects/effect-app");

    if !fixture_path.exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }

    setup_threat(
        &temp_dir,
        "Effect SQL Injection",
        "2025-01-09",
        "SQL injection in @effect/sql",
        Some("CVE-2025-11111"),
        &["@effect/sql@0.44.1"],
        &["DROP TABLE"],
        &["malicious-migration.ts", "backdoor.sql"],
    );

    let output = ector_cmd()
        .current_dir(&temp_dir)
        .arg("check")
        .arg("--all")
        .arg("--directory")
        .arg(&fixture_path)
        .output()
        .expect("Failed to execute check command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let normalized_stdout = normalize_output(&stdout);

    insta::assert_snapshot!("check_payload_file_detection", normalized_stdout);
}
