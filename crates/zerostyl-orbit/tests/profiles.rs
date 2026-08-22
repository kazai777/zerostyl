//! Integration tests for chain-profile loading and deployability assessment.

use zerostyl_circuits::ProvingSystem;
use zerostyl_orbit::{
    arbitrum_sepolia, assess, assess_verification, orbit_template, ArtifactSize, ChainProfile,
};

#[test]
fn load_custom_profile_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("my-chain.toml");
    std::fs::write(&path, orbit_template().to_toml()).unwrap();

    let loaded = ChainProfile::load_file(&path).unwrap();
    assert_eq!(loaded, orbit_template());
}

#[test]
fn load_rejects_malformed_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "this is not = valid = toml").unwrap();
    assert!(ChainProfile::load_file(&path).is_err());
}

#[test]
fn verifier_sized_artifact_is_rejected_on_sepolia_but_precompiles_exist() {
    // The zerostyl-verifier reference: ~91 KB compressed / ~338 KB decompressed.
    let artifact = ArtifactSize { compressed: 91 * 1024, uncompressed: 338 * 1024 };
    let sepolia = arbitrum_sepolia();

    let deploy = assess(&sepolia, &artifact);
    assert!(!deploy.deployable(), "verifier must not fit Sepolia's 24 KB cap");

    // But the chain DOES have the precompiles a real KZG verifier would need — the blocker is
    // size, not precompile availability.
    let verify = assess_verification(&sepolia, ProvingSystem::Halo2Kzg);
    assert!(verify.all_available());
}

#[test]
fn small_contract_is_deployable_everywhere() {
    let artifact = ArtifactSize { compressed: 12 * 1024, uncompressed: 40 * 1024 };
    for profile in zerostyl_orbit::builtins() {
        assert!(assess(&profile, &artifact).deployable(), "{} should accept it", profile.name);
    }
}
