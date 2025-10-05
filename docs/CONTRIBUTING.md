# Contributing to ZeroStyl

**Welcome!** 🎉 Thank you for your interest in contributing to ZeroStyl, a privacy toolkit for Arbitrum Stylus. We're building the future of zero-knowledge smart contracts, and your help is invaluable!

---

## About This Project

ZeroStyl is an **open-source MIT-licensed**. Our mission is to make privacy-preserving smart contracts accessible to all Rust developers by reducing zk-SNARK development complexity by 50%.

Whether you're a cryptography expert, a Rust enthusiast, or a Web3 beginner, there's a place for you here. We value all contributions, big and small!

---

## Ways to Contribute

There are many ways to help ZeroStyl grow:

### Report Bugs
Found a bug? [Open an issue](https://github.com/kazai777/zerostyl/issues/new) with:
- Clear description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- Rust version and OS (run `rustc --version` and `uname -a`)

### Suggest Features
Have an idea? We'd love to hear it! [Start a discussion](https://github.com/kazai777/zerostyl/discussions) or open a feature request issue.

### Improve Documentation
Documentation is as important as code! Help us by:
- Fixing typos and grammar
- Adding examples and tutorials
- Improving rustdoc comments
- Translating to other languages

### Submit Code
Ready to code? Check our [good first issues](https://github.com/kazai777/zerostyl/labels/good%20first%20issue) or tackle open bugs and features.

### Write Tests
More tests = better quality! Add unit tests, integration tests, or improve coverage for existing code.

### Create Examples & Tutorials
Share your knowledge:
- Build example circuits using ZeroStyl
- Write blog posts or video tutorials
- Present at meetups or conferences

---

## Development Setup

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **Git**: For version control
- **GitHub Account**: To submit PRs

### Getting Started

```bash
# 1. Fork the repository on GitHub
# (Click "Fork" button at https://github.com/kazai777/zerostyl)

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/zerostyl.git
cd zerostyl

# 3. Add upstream remote
git remote add upstream https://github.com/kazai777/zerostyl.git

# 4. Build the project
cargo build --workspace

# 5. Run tests to ensure everything works
cargo test --workspace

# 6. Run linter
cargo clippy --workspace

# 7. Format code
cargo fmt --all
```

### Verify Your Setup

If all commands succeed without errors, you're ready to contribute! 🎉

---

## Code Guidelines

Follow these principles to maintain code quality:

### Rust Conventions

- ✅ Use `snake_case` for functions and variables
- ✅ Use `PascalCase` for types and traits
- ✅ Use `SCREAMING_SNAKE_CASE` for constants
- ✅ Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

### Documentation

- ✅ Write rustdoc comments for **all public APIs**
  ```rust
  /// Generates a zero-knowledge proof for the given circuit.
  ///
  /// # Arguments
  /// * `circuit` - The halo2 circuit to prove
  /// * `params` - Proving parameters
  ///
  /// # Returns
  /// A serialized proof on success, or an error if proving fails.
  ///
  /// # Examples
  /// ```
  /// let proof = generate_proof(&my_circuit, &params)?;
  /// ```
  pub fn generate_proof(circuit: &impl Circuit, params: &Params) -> Result<ZkProof> {
      // ...
  }
  ```

### Code Quality

- ✅ Add **unit tests** for new features (target: **80%+ coverage**)
- ✅ Run `cargo fmt --all` before committing
- ✅ Ensure `cargo clippy --workspace` passes **without warnings**
- ✅ Keep PRs focused: **one feature or fix per PR**
- ✅ Avoid unwrap(): Use proper error handling with `Result<T, E>`

### Example: Good vs. Bad Code

**❌ Bad**:
```rust
fn parse_config(path: &str) -> CircuitConfig {
    let file = std::fs::read_to_string(path).unwrap(); // Can panic!
    serde_json::from_str(&file).unwrap() // No error handling
}
```

**✅ Good**:
```rust
/// Parses circuit configuration from a JSON file.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
fn parse_config(path: &str) -> Result<CircuitConfig> {
    let file = std::fs::read_to_string(path)
        .map_err(|e| ZeroStylError::other(format!("Failed to read config: {}", e)))?;

    serde_json::from_str(&file)
        .map_err(|e| ZeroStylError::serialization_error(e.to_string()))
}
```

---

## 🧪 Testing Requirements

Quality is our top priority. **Every new feature must include tests.**

### Test Types

1. **Unit Tests** (in `src/` files):
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_zkproof_serialization_with_empty_bytes() {
           let proof = ZkProof::new(vec![]);
           let json = serde_json::to_string(&proof).unwrap();
           let deserialized: ZkProof = serde_json::from_str(&json).unwrap();
           assert_eq!(deserialized.size(), 0);
       }
   }
   ```

2. **Integration Tests** (in `tests/` directory):
   ```rust
   // tests/compiler_integration.rs
   use zerostyl_compiler::Compiler;
   use zerostyl_runtime::CircuitConfig;

   #[test]
   fn test_compile_tx_privacy_circuit() {
       let config = CircuitConfig::minimal(17);
       let compiler = Compiler::new(config);
       // Test full compilation pipeline
   }
   ```

### Test Naming

Use descriptive names that explain **what** is being tested:

- ✅ `test_commitment_creation_with_valid_randomness`
- ✅ `test_circuit_config_rejects_invalid_k_parameter`
- ❌ `test1` (too vague)
- ❌ `test_works` (not specific)

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test --package zerostyl-runtime

# Run a specific test
cargo test test_zkproof_serialization

# Run tests with output
cargo test -- --nocapture
```

---

## Pull Request Process

### Step-by-Step Guide

1. **Fork the repository** on GitHub

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/add-pedersen-helper
   ```

3. **Make your changes**:
   - Write code following our guidelines
   - Add rustdoc comments
   - Write tests

4. **Run the full test suite**:
   ```bash
   cargo test --workspace
   ```

5. **Run the linter**:
   ```bash
   cargo clippy --workspace -- -D warnings
   ```

6. **Format your code**:
   ```bash
   cargo fmt --all
   ```

7. **Commit with a clear message**:
   ```bash
   git add .
   git commit -m "feat(compiler): add Pedersen commitment helper function"
   ```

8. **Push to your fork**:
   ```bash
   git push origin feature/add-pedersen-helper
   ```

9. **Create a Pull Request** on GitHub:
   - Go to your fork on GitHub
   - Click "Compare & pull request"
   - Fill in the PR template with details
   - Link related issues (e.g., "Closes #42")

10. **Wait for CI to pass**:
    - GitHub Actions will run tests, clippy, and formatting checks
    - Fix any failures before requesting review

11. **Address review comments**:
    - Maintainers will review within **48 hours**
    - Make requested changes
    - Push updates to the same branch

12. **Celebrate!** 🎉
    - Once approved, your PR will be merged
    - You're now a ZeroStyl contributor!

---

## Commit Message Convention

We use **Conventional Commits** for clear and consistent git history.

### Format

```
<type>(<scope>): <short description>

<optional longer description>

<optional footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Add or update tests
- `refactor`: Code refactoring (no functional changes)
- `perf`: Performance improvements
- `chore`: Maintenance tasks (dependencies, CI, etc.)
- `style`: Code style changes (formatting, no logic changes)

### Scopes (Optional)

- `compiler`: zerostyl-compiler crate
- `debugger`: zerostyl-debugger crate
- `exporter`: zerostyl-exporter crate
- `runtime`: zerostyl-runtime crate
- `ci`: CI/CD configuration
- `docs`: Documentation

### Examples

```bash
feat(compiler): add halo2 circuit parser for tx_privacy

Implements AST transformation from Rust functions to halo2 circuits.
Supports Pedersen commitments and Merkle tree verification.

Closes #15
```

```bash
fix(debugger): resolve zk-mocking timeout issue

The mocking framework was timing out on circuits with >50k constraints.
Added pagination to constraint checks.
```

```bash
docs: update architecture diagram with STARK integration

Added section explaining v2.0 roadmap with FRI-based STARKs.
```

```bash
test(runtime): add edge case tests for CircuitConfig

- Test k=0 (should error)
- Test k=32 (maximum allowed)
- Test empty custom_params
```

---

## Code Review Process

All contributions go through code review to maintain quality.

### What We Look For

- ✅ Code follows Rust conventions
- ✅ Tests are included and passing
- ✅ Documentation is clear and complete
- ✅ No clippy warnings
- ✅ Commit messages follow conventions
- ✅ PR description explains the change

### Review Timeline

- **48 hours**: Initial review by maintainers
- **1 week**: Typical merge time for small PRs
- **2-3 weeks**: Complex features may require multiple review rounds

### Responding to Feedback

- Be open to suggestions and constructive criticism
- Ask questions if you don't understand feedback
- Make requested changes or explain why an alternative is better
- Mark conversations as resolved once addressed

---

## Questions & Support

Need help? We're here for you!

### Where to Ask

- **[GitHub Discussions](https://github.com/kazai777/zerostyl/discussions)**: General questions, ideas, and community chat
- **[GitHub Issues](https://github.com/kazai777/zerostyl/issues)**: Bug reports and feature requests
- **[Arbitrum Discord](https://discord.gg/arbitrum)**: Live chat in the #stylus channel
- **Email**: kazai777.dev@gmail.com (for private inquiries)

### Before Asking

1. Search existing issues and discussions
2. Check the [documentation](../README.md)
3. Review the [architecture guide](ARCHITECTURE.md)
4. Read the [roadmap](ROADMAP.md)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment.

### Our Pledge

- ✅ **Be respectful**: Treat everyone with kindness and professionalism
- ✅ **Be inclusive**: Welcome newcomers and diverse perspectives
- ✅ **Be constructive**: Focus on helpful feedback, not criticism
- ✅ **Be patient**: Remember that everyone is learning

### Unacceptable Behavior

- ❌ Harassment, discrimination, or offensive comments
- ❌ Personal attacks or insults
- ❌ Trolling or deliberately disruptive behavior
- ❌ Sharing private information without consent

### Enforcement

Violations will be addressed promptly:
1. **First offense**: Warning from maintainers
2. **Second offense**: Temporary ban (1 week)
3. **Third offense**: Permanent ban

Report violations to kazai777.dev@gmail.com (private and confidential).

We follow the [GitHub Community Guidelines](https://docs.github.com/en/site-policy/github-terms/github-community-guidelines).

---

## License

By contributing to ZeroStyl, you agree that your contributions will be licensed under the **MIT License**.

This means:
- ✅ Your code can be freely used, modified, and distributed
- ✅ You retain copyright to your contributions
- ✅ You grant ZeroStyl and the community a perpetual license to use your work

See the [LICENSE](../LICENSE) file for full details.

---

## Recognition

We value every contribution! Contributors will be recognized:

- Listed in the project README
- Featured in release notes for significant contributions
- NFT badges for milestone achievements (coming soon)


---

## Additional Resources

### Learning Materials

- [Rust Book](https://doc.rust-lang.org/book/)
- [halo2 Documentation](https://zcash.github.io/halo2/)
- [Arbitrum Stylus Guide](https://docs.arbitrum.io/stylus)
- [Zero-Knowledge Proofs Explained](https://z.cash/technology/zksnarks/)

### Community Projects

- [halo2 Circuits](https://github.com/privacy-scaling-explorations/halo2)
- [Stylus Examples](https://github.com/OffchainLabs/stylus-sdk-rs/tree/main/examples)
- [zkSNARK Tutorials](https://www.zkdocs.com/)

---

<div align="center">

**Thank you for contributing to ZeroStyl!** 🙏

Together, we're building the privacy-first future of Web3.

[Start Contributing](https://github.com/kazai777/zerostyl/issues) • [Join Discord](https://discord.gg/arbitrum) • [Follow Updates](https://twitter.com/zerostyl_dev)

</div>
