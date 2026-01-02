use anyhow::Result;

use crate::core::threat::{Threat, ThreatName};

pub mod local;

/// Storage abstraction for threats
pub trait Store {
    /// Load all threats
    fn get_all(&self) -> Result<Vec<Threat>>;

    /// Load specific threat by ID
    fn get_by_name(&self, name: &ThreatName) -> Result<Threat>;

    /// Save new threat
    fn save(&self, threat: &Threat) -> Result<()>;

    /// Check if threat exists
    fn exists(&self, name: &ThreatName) -> Result<bool>;
}
