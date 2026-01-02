use assert_cmd::Command;
use predicates::prelude::*;
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
    // Ensure threats directory exists
    fs::create_dir_all(temp_dir.path().join("threats")).unwrap();
    temp_dir
}

#[test]
fn test_add_with_single_package() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Added: lodash@4.17.20"))
        .stdout(predicate::str::contains("Threat saved successfully"));

    // Verify threat was added using list command
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("test-package-attack"))
        .stdout(predicate::str::contains("Packages: 1"));
}

#[test]
fn test_add_with_multiple_packages() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Processing 3 package(s)"))
        .stdout(predicate::str::contains("lodash@4.17.20"))
        .stdout(predicate::str::contains("express@4.18.0"))
        .stdout(predicate::str::contains("@babel/core@7.23.0"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("multi-package-attack"))
        .stdout(predicate::str::contains("Packages: 3"));
}

#[test]
fn test_add_with_invalid_package_format() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success() // Should still succeed but show error
        .stdout(predicate::str::contains("Invalid package"));

    // Verify threat was created but with 0 packages
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("bad-package"))
        .stdout(predicate::str::contains("Packages: 0"));
}

#[test]
fn test_add_with_scoped_package() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("@babel/core"))
        .stdout(predicate::str::contains("@types/node"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("scoped-package-attack"))
        .stdout(predicate::str::contains("Packages: 2"));
}

#[test]
fn test_add_with_single_signature() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding 1 signature(s)"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("signature-test"))
        .stdout(predicate::str::contains("2025-01-01"));
}

#[test]
fn test_add_with_multiple_signatures() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding 3 signature(s)"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("multi-signature"))
        .stdout(predicate::str::contains("Multiple signatures"));
}

#[test]
fn test_add_with_single_payload() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding 1 payload file(s)"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("payload-test"))
        .stdout(predicate::str::contains("Test with payload"));
}

#[test]
fn test_add_with_multiple_payloads() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding 3 payload file(s)"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("multi-payload"))
        .stdout(predicate::str::contains("Multiple payloads"));
}

#[test]
fn test_add_with_single_workflow() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding 1 workflow path(s)"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("workflow-test"))
        .stdout(predicate::str::contains("Test with workflow"));
}

#[test]
fn test_add_with_multiple_workflows() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding 3 workflow path(s)"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("multi-workflow"))
        .stdout(predicate::str::contains("Multiple workflows"));
}

#[test]
fn test_add_with_all_fields() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("Processing 2 package(s)"))
        .stdout(predicate::str::contains("Adding 2 signature(s)"))
        .stdout(predicate::str::contains("Adding 1 payload file(s)"))
        .stdout(predicate::str::contains("Adding 1 workflow path(s)"))
        .stdout(predicate::str::contains("CVE-2025-12345"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("complete-attack"))
        .stdout(predicate::str::contains("CVE-2025-12345"))
        .stdout(predicate::str::contains("Packages: 2"))
        .stdout(predicate::str::contains("Attack with all fields"));
}

#[test]
fn test_add_event_stream_realistic() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success()
        .stdout(predicate::str::contains("event-stream-compromise"))
        .stdout(predicate::str::contains("CVE-2018-3728"))
        .stdout(predicate::str::contains("event-stream@3.3.6"))
        .stdout(predicate::str::contains("flatmap-stream@0.1.1"));

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("event-stream-compromise"))
        .stdout(predicate::str::contains("CVE-2018-3728"))
        .stdout(predicate::str::contains("2018-11-26"))
        .stdout(predicate::str::contains("Packages: 2"))
        .stdout(predicate::str::contains(
            "Malicious code injection in event-stream via flatmap-stream",
        ));
}

#[test]
fn test_add_packages_only_without_metadata() {
    let temp_dir = setup_temp_dir();

    // Should fail - missing required fields
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("add")
        .arg("-p")
        .arg("lodash@4.17.20")
        .assert()
        .failure();

    // Verify nothing was added using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats registered yet"));
}

#[test]
fn test_add_minimal_metadata_with_packages() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
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
        .assert()
        .success();

    // Verify using list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Minimal"))
        .stdout(predicate::str::contains("Packages: 1"))
        .stdout(predicate::str::contains("Minimal attack"));
}

#[test]
fn test_list_when_empty() {
    let temp_dir = setup_temp_dir();

    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats registered yet"))
        .stdout(predicate::str::contains("Use 'ector add'"));
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
        .assert()
        .success();

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
        .assert()
        .success();

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
        .assert()
        .success();

    // Verify all three show in list
    ector_cmd()
        .current_dir(&temp_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("first-attack"))
        .stdout(predicate::str::contains("second-attack"))
        .stdout(predicate::str::contains("third-attack"))
        .stdout(predicate::str::contains("Total: 3 threats"));
}

#[test]
fn test_add_help_shows_all_options() {
    ector_cmd()
        .arg("add")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--package"))
        .stdout(predicate::str::contains("--signature"))
        .stdout(predicate::str::contains("--payload"))
        .stdout(predicate::str::contains("--workflow"))
        .stdout(predicate::str::contains("-p"))
        .stdout(predicate::str::contains("-s"))
        .stdout(predicate::str::contains("-f"))
        .stdout(predicate::str::contains("-w"));
}
