use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

/// Read JSON file
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let content = fs::read_to_string(path).context(format!("Failed to read {}", path.display()))?;
    let data: T =
        serde_json::from_str(&content).context(format!("Failed to parse {}", path.display()))?;
    Ok(data)
}
