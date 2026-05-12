use std::collections::BTreeMap;
use std::sync::RwLock;

use crate::descriptor::CircuitDescriptor;
use crate::error::{CircuitError, Result};

/// Per-binary collection of `&'static dyn CircuitDescriptor`.
///
/// Populated at startup by `register` calls (typically a `register_builtins`
/// helper, plus any user-supplied circuits). The CLI and debugger receive
/// a borrowed `&Registry` and never look up circuits by hardcoded name.
pub struct Registry {
    entries: RwLock<BTreeMap<&'static str, &'static dyn CircuitDescriptor>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { entries: RwLock::new(BTreeMap::new()) }
    }

    pub fn register(&self, descriptor: &'static dyn CircuitDescriptor) -> Result<()> {
        let mut entries = self.entries.write().expect("registry lock poisoned");
        let name = descriptor.name();
        if entries.contains_key(name) {
            return Err(CircuitError::AlreadyRegistered(name.to_string()));
        }
        entries.insert(name, descriptor);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<&'static dyn CircuitDescriptor> {
        self.entries
            .read()
            .expect("registry lock poisoned")
            .get(name)
            .copied()
            .ok_or_else(|| CircuitError::CircuitNotFound(name.to_string()))
    }

    pub fn list(&self) -> Vec<&'static str> {
        self.entries.read().expect("registry lock poisoned").keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.read().expect("registry lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("registry lock poisoned").is_empty()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::OnceLock;

    use super::*;
    use crate::proof::ProofArtifact;
    use crate::report::{CircuitIntrospection, MockProverReport};
    use crate::schema::{PublicInputsSchema, WitnessSchema};

    fn empty_witness_schema() -> &'static WitnessSchema {
        static S: OnceLock<WitnessSchema> = OnceLock::new();
        S.get_or_init(|| WitnessSchema { fields: vec![] })
    }

    fn empty_public_schema() -> &'static PublicInputsSchema {
        static S: OnceLock<PublicInputsSchema> = OnceLock::new();
        S.get_or_init(|| PublicInputsSchema { fields: vec![] })
    }

    struct DummyA;
    struct DummyB;

    macro_rules! dummy_impl {
        ($ty:ty, $name:expr, $k:expr) => {
            impl CircuitDescriptor for $ty {
                fn name(&self) -> &'static str {
                    $name
                }
                fn version(&self) -> &'static str {
                    "0.1.0"
                }
                fn description(&self) -> &'static str {
                    "test dummy"
                }
                fn default_k(&self) -> u32 {
                    $k
                }
                fn num_public_inputs(&self) -> usize {
                    0
                }
                fn num_private_witnesses(&self) -> usize {
                    0
                }
                fn witness_schema(&self) -> &'static WitnessSchema {
                    empty_witness_schema()
                }
                fn public_inputs_schema(&self) -> &'static PublicInputsSchema {
                    empty_public_schema()
                }
                fn prove(&self, _: &str, _: u32, _: &Path) -> Result<ProofArtifact> {
                    unimplemented!()
                }
                fn verify(&self, _: &[u8], _: &str, _: u32, _: &Path) -> Result<bool> {
                    unimplemented!()
                }
                fn mock_prove(&self, _: &str, _: u32) -> Result<MockProverReport> {
                    unimplemented!()
                }
                fn inspect(&self) -> Result<CircuitIntrospection> {
                    unimplemented!()
                }
            }
        };
    }

    dummy_impl!(DummyA, "dummy_a", 4);
    dummy_impl!(DummyB, "dummy_b", 5);

    static DUMMY_A: DummyA = DummyA;
    static DUMMY_B: DummyB = DummyB;

    #[test]
    fn register_and_get_returns_same_descriptor() {
        let reg = Registry::new();
        reg.register(&DUMMY_A).unwrap();
        let d = reg.get("dummy_a").unwrap();
        assert_eq!(d.name(), "dummy_a");
        assert_eq!(d.default_k(), 4);
    }

    #[test]
    fn list_returns_sorted_names() {
        let reg = Registry::new();
        reg.register(&DUMMY_B).unwrap();
        reg.register(&DUMMY_A).unwrap();
        assert_eq!(reg.list(), vec!["dummy_a", "dummy_b"]);
    }

    #[test]
    fn register_duplicate_returns_already_registered() {
        let reg = Registry::new();
        reg.register(&DUMMY_A).unwrap();
        let err = reg.register(&DUMMY_A).unwrap_err();
        assert!(matches!(err, CircuitError::AlreadyRegistered(name) if name == "dummy_a"));
    }

    #[test]
    fn get_missing_returns_circuit_not_found() {
        let reg = Registry::new();
        let err = reg.get("nope").err().unwrap();
        assert!(matches!(err, CircuitError::CircuitNotFound(name) if name == "nope"));
    }

    #[test]
    fn len_and_is_empty_track_state() {
        let reg = Registry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        reg.register(&DUMMY_A).unwrap();
        reg.register(&DUMMY_B).unwrap();
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn trait_is_dyn_safe() {
        let _: &dyn CircuitDescriptor = &DUMMY_A;
    }
}
