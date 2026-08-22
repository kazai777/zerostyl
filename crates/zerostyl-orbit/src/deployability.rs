//! Deployability analysis: does a WASM artifact fit a chain, and can a proving system be verified
//! on it?

use std::fmt;
use std::io::Write;
use std::path::Path;

use zerostyl_circuits::ProvingSystem;

use crate::error::Result;
use crate::precompiles::{required_for, Precompile};
use crate::profile::ChainProfile;

/// Measured size of a compiled artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactSize {
    /// Compressed (Brotli) size in bytes — the on-chain code size.
    pub compressed: usize,
    /// Decompressed size in bytes.
    pub uncompressed: usize,
}

impl ArtifactSize {
    /// Measure a `.wasm` file: `uncompressed` = file length, `compressed` = Brotli(quality 11).
    ///
    /// The Brotli figure approximates `cargo-stylus` closely but is not byte-identical; treat it
    /// as indicative and use `cargo stylus check` as the deployment source of truth.
    ///
    /// # Errors
    /// Returns [`crate::OrbitError::Io`] if the file cannot be read.
    pub fn measure_wasm(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(Self::measure_bytes(&bytes))
    }

    /// Measure an in-memory artifact (same semantics as [`Self::measure_wasm`]).
    #[must_use]
    pub fn measure_bytes(bytes: &[u8]) -> Self {
        Self { compressed: brotli_len(bytes), uncompressed: bytes.len() }
    }
}

/// Brotli-compress `data` at quality 11 (window 2^22) and return the compressed length.
fn brotli_len(data: &[u8]) -> usize {
    let mut sink = CountingSink::default();
    {
        let mut writer = brotli::CompressorWriter::new(&mut sink, 4096, 11, 22);
        // Writing to an in-memory counter cannot fail.
        writer.write_all(data).expect("brotli write");
        writer.flush().expect("brotli flush");
    }
    sink.count
}

/// A `Write` sink that only counts bytes, avoiding a full compressed buffer allocation.
#[derive(Default)]
struct CountingSink {
    count: usize,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.count += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One size check within a [`DeployabilityReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeCheck {
    /// Human-readable check name.
    pub name: &'static str,
    /// The chain limit, bytes.
    pub limit: usize,
    /// The artifact's measured value, bytes.
    pub actual: usize,
}

impl SizeCheck {
    /// Whether the artifact is within the limit.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.actual <= self.limit
    }

    /// Signed margin (`limit - actual`): positive = headroom, negative = overflow.
    #[must_use]
    pub fn margin(&self) -> isize {
        self.limit as isize - self.actual as isize
    }
}

/// Result of assessing an artifact's size against a chain.
#[derive(Debug, Clone)]
pub struct DeployabilityReport {
    /// Chain the artifact was assessed against.
    pub chain: String,
    /// Per-limit checks.
    pub checks: Vec<SizeCheck>,
}

impl DeployabilityReport {
    /// Deployable iff every size check passes.
    #[must_use]
    pub fn deployable(&self) -> bool {
        self.checks.iter().all(SizeCheck::ok)
    }
}

/// Assess whether `artifact` fits the size limits of `chain`.
#[must_use]
pub fn assess(chain: &ChainProfile, artifact: &ArtifactSize) -> DeployabilityReport {
    DeployabilityReport {
        chain: chain.name.clone(),
        checks: vec![
            SizeCheck {
                name: "compressed (on-chain code)",
                limit: chain.limits.max_code_size,
                actual: artifact.compressed,
            },
            SizeCheck {
                name: "decompressed WASM",
                limit: chain.limits.max_wasm_size,
                actual: artifact.uncompressed,
            },
        ],
    }
}

/// Result of checking whether a chain has the precompiles a proving system needs on-chain.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Chain assessed.
    pub chain: String,
    /// Proving system assessed.
    pub system: ProvingSystem,
    /// Precompiles required and whether each is available.
    pub required: Vec<(Precompile, bool)>,
}

impl VerificationReport {
    /// Whether every required precompile is available.
    ///
    /// `true` with an empty `required` means the system needs no precompile (transparent), OR that
    /// it has no BN254 precompile path at all — read [`Self::supported`] together with the system.
    #[must_use]
    pub fn all_available(&self) -> bool {
        self.required.iter().all(|(_, ok)| *ok)
    }

    /// Whether an on-chain verification path exists for this system on BN254 at all.
    #[must_use]
    pub fn supported(&self) -> bool {
        !matches!(self.system, ProvingSystem::Halo2Ipa)
    }
}

/// Check whether `chain` exposes the precompiles an on-chain verifier for `system` would need.
#[must_use]
pub fn assess_verification(chain: &ChainProfile, system: ProvingSystem) -> VerificationReport {
    let required = required_for(system).iter().map(|p| (*p, chain.precompiles.has(*p))).collect();
    VerificationReport { chain: chain.name.clone(), system, required }
}

// ── Display ───────────────────────────────────────────────────────────────

fn human(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

impl fmt::Display for DeployabilityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}: {}",
            self.chain,
            if self.deployable() { "DEPLOYABLE" } else { "NOT deployable" }
        )?;
        for c in &self.checks {
            let mark = if c.ok() { "ok " } else { "OVER" };
            let margin = c.margin();
            let margin_str = if margin >= 0 {
                format!("{} headroom", human(margin as usize))
            } else {
                format!("{} over", human((-margin) as usize))
            };
            writeln!(
                f,
                "  [{mark}] {}: {} / {} ({margin_str})",
                c.name,
                human(c.actual),
                human(c.limit),
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.supported() {
            return write!(
                f,
                "{}: {:?} has no BN254 on-chain verification path (wrong curve)",
                self.chain, self.system
            );
        }
        if self.required.is_empty() {
            return write!(
                f,
                "{}: {:?} needs no precompiles (transparent verification)",
                self.chain, self.system
            );
        }
        writeln!(
            f,
            "{}: {:?} on-chain verification precompiles {}",
            self.chain,
            self.system,
            if self.all_available() { "available" } else { "MISSING" }
        )?;
        for (p, ok) in &self.required {
            writeln!(f, "  [{}] 0x{:02x} {}", if *ok { "ok " } else { "no " }, p.address, p.name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{arbitrum_sepolia, orbit_template};

    #[test]
    fn small_artifact_is_deployable_on_sepolia() {
        let artifact = ArtifactSize { compressed: 18 * 1024, uncompressed: 90 * 1024 };
        let report = assess(&arbitrum_sepolia(), &artifact);
        assert!(report.deployable());
    }

    #[test]
    fn oversized_verifier_not_deployable_on_sepolia() {
        // The state_mask verifier: ~240 KB compressed / ~559 KB uncompressed.
        let artifact = ArtifactSize { compressed: 240 * 1024, uncompressed: 559 * 1024 };
        let report = assess(&arbitrum_sepolia(), &artifact);
        assert!(!report.deployable());
        assert!(!report.checks[0].ok(), "compressed check must fail");
    }

    #[test]
    fn orbit_template_has_more_headroom_but_still_bounded() {
        // 91.5 KB compressed fits the 96 KB custom cap; 240 KB would not.
        let fits = ArtifactSize { compressed: 91 * 1024, uncompressed: 250 * 1024 };
        assert!(assess(&orbit_template(), &fits).deployable());
        let too_big = ArtifactSize { compressed: 97 * 1024, uncompressed: 250 * 1024 };
        assert!(!assess(&orbit_template(), &too_big).deployable());
    }

    #[test]
    fn measure_bytes_compresses() {
        let data = vec![0u8; 10_000]; // highly compressible
        let m = ArtifactSize::measure_bytes(&data);
        assert_eq!(m.uncompressed, 10_000);
        assert!(m.compressed < m.uncompressed);
    }

    #[test]
    fn kzg_verification_available_on_standard_chain() {
        let r = assess_verification(&arbitrum_sepolia(), ProvingSystem::Halo2Kzg);
        assert!(r.supported());
        assert!(r.all_available());
    }

    #[test]
    fn kzg_verification_blocked_when_pairing_removed() {
        let mut chain = arbitrum_sepolia();
        chain.precompiles.bn256_pairing = false;
        let r = assess_verification(&chain, ProvingSystem::Halo2Kzg);
        assert!(!r.all_available());
    }

    #[test]
    fn ipa_has_no_supported_path() {
        let r = assess_verification(&arbitrum_sepolia(), ProvingSystem::Halo2Ipa);
        assert!(!r.supported());
    }
}
