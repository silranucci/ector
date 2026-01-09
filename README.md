# Ector

A command-line tool for detecting and managing known supply chain threats in JavaScript/TypeScript projects.

## Installation

### Prerequisites

- Rust toolchain (1.70+)
- Cargo

### Development Dependencies

Install required development tools:

```bash
# Snapshot testing
cargo install cargo-insta

# Continuous testing (optional)
cargo install bacon
```

## Usage

### Basic Commands

#### Add a Threat

```bash
# Add threat with all metadata
ector add \
  --name "Event Stream Compromise" \
  --date "2018-11-26" \
  --description "Malicious code injection in event-stream" \
  --cve "CVE-2018-3728" \
  -p "event-stream@3.3.6" \
  -p "flatmap-stream@0.1.1" \
  -s "eval(Buffer.from(" \
  -f "flatmap-stream/index.js"

# Interactive mode
ector add --interactive
```

#### List Threats

```bash
# List all registered threats
ector list

# Show detailed information
ector list --verbose
```

#### Check Project

```bash
# Check current directory
ector check --all

# Check specific directory
ector check --all --directory /path/to/project

# Check specific threat
ector check --name "event-stream-compromise"
```

### Command Reference

| Command | Purpose |
|---------|---------|
| `add` | Register a new supply chain threat |
| `list` | Display all registered threats |
| `check` | Scan a project for known threats |
| `help` | Show help information |

### Command Options

#### `ector add`

- `--name <NAME>` - Threat name (required)
- `--date <DATE>` - Discovery date in YYYY-MM-DD format (required)
- `--description <DESC>` - Threat description (required)
- `--cve <CVE>` - CVE identifier (optional)
- `-p, --package <PKG>` - Affected package (can be used multiple times)
- `-s, --signature <SIG>` - Code signature to detect (can be used multiple times)
- `-f, --payload <FILE>` - Payload filename (can be used multiple times)
- `-w, --workflow <PATH>` - Workflow path (can be used multiple times)
- `--interactive` - Interactive mode

#### `ector check`

- `--all` - Check all registered threats
- `--name <NAME>` - Check specific threat by name
- `--directory <DIR>` - Project directory to scan (default: current directory)

#### `ector list`

- `--verbose` - Show detailed threat information

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test cli

# Run unit tests only
cargo test --lib
```

### Snapshot Testing

Review and update snapshots after changes:

```bash
# Run tests and review snapshots
cargo insta test
cargo insta review

# Accept all snapshot changes
cargo insta accept
```

### Continuous Testing with Bacon

Monitor tests while developing:

```bash
# Watch and run tests continuously
bacon test

# Watch specific test suite
bacon test -- --test cli

# Watch and check compilation
bacon check
```

### Code Formatting

```bash
# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt
```

### Linting

```bash
# Run clippy
cargo clippy

# Run clippy with all features
cargo clippy --all-features
```

## Project Structure

```
ector/
├── src/
│   ├── cli/           # Command-line interface
│   ├── core/          # Core threat detection logic
│   ├── scanner.rs     # File system scanner
│   ├── store/         # Threat storage
│   └── util/          # Utilities
├── tests/
│   ├── fixtures/      # Test projects
│   ├── snapshots/     # Snapshot test data
│   └── cli.rs         # E2E tests
└── Cargo.toml
```

## License

GNU General Public License v3.0
