//! Consensus module registry — manages pluggable proof modules at runtime.

use crate::error::ConsensusError;
use crate::proof::ConsensusProof;
use std::collections::HashMap;

pub struct ConsensusRegistry {
    modules: HashMap<String, Box<dyn ConsensusProof>>,
    active_module: Option<String>,
}

impl ConsensusRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            active_module: None,
        }
    }

    pub fn register(&mut self, module: Box<dyn ConsensusProof>) -> Result<(), ConsensusError> {
        let name = module.name().to_string();
        if self.modules.contains_key(&name) {
            return Err(ConsensusError::UnknownProofType(format!(
                "module '{}' already registered",
                name
            )));
        }
        if self.active_module.is_none() {
            self.active_module = Some(name.clone());
        }
        self.modules.insert(name, module);
        Ok(())
    }

    pub fn set_active(&mut self, name: &str) -> Result<(), ConsensusError> {
        if !self.modules.contains_key(name) {
            return Err(ConsensusError::UnknownProofType(format!(
                "module '{}' not registered",
                name
            )));
        }
        self.active_module = Some(name.to_string());
        Ok(())
    }

    pub fn active(&self) -> Option<&dyn ConsensusProof> {
        self.active_module
            .as_ref()
            .and_then(|name| self.modules.get(name))
            .map(|m| m.as_ref())
    }

    pub fn get(&self, name: &str) -> Option<&dyn ConsensusProof> {
        self.modules.get(name).map(|m| m.as_ref())
    }

    pub fn list_modules(&self) -> Vec<&str> {
        self.modules.keys().map(|k| k.as_str()).collect()
    }
}

impl Default for ConsensusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::randomx::RandomXProof;

    #[test]
    fn test_register_and_get() {
        let mut reg = ConsensusRegistry::new();
        reg.register(Box::new(RandomXProof::new(120, 720))).unwrap();
        assert!(reg.get("RandomX").is_some());
        assert_eq!(reg.list_modules(), vec!["RandomX"]);
    }

    #[test]
    fn test_active_defaults_to_first() {
        let mut reg = ConsensusRegistry::new();
        reg.register(Box::new(RandomXProof::new(120, 720))).unwrap();
        assert_eq!(reg.active().unwrap().name(), "RandomX");
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut reg = ConsensusRegistry::new();
        reg.register(Box::new(RandomXProof::new(120, 720))).unwrap();
        assert!(reg.register(Box::new(RandomXProof::new(120, 720))).is_err());
    }
}
