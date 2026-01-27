# Audit Report

## Title
Use of Unaudited Forked Arkworks Cryptographic Dependencies in Pairing Operations

## Summary
The `ark_bls12_381::Bls12_381` and `ark_bn254::Bn254` curve implementations used in pairing operations at lines 186 and 198 of `pairing.rs` are sourced from official crates.io, but they transitively depend on forked core arkworks cryptographic libraries (`ark-ec`, `ark-ff`, `ark-serialize`, `ark-poly`) from `https://github.com/aptos-labs/algebra` that deviate from the official audited arkworks implementations. There is no evidence in the codebase that this fork has been independently audited, creating a supply chain risk where bugs in the forked cryptographic arithmetic could lead to consensus failures or cryptographic vulnerabilities. [1](#0-0) [2](#0-1) 

## Finding Description
The pairing operations use `ark_bls12_381::Bls12_381` and `ark_bn254::Bn254` from the official crates.io registry (version 0.5.0). However, the Cargo.toml workspace configuration patches core arkworks dependencies to use a fork maintained by aptos-labs: [3](#0-2) 

The Cargo.lock reveals that the actual resolved dependencies use this fork: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

While `ark-bls12-381` and `ark-bn254` themselves come from crates.io, they depend on these forked crates: [8](#0-7) [9](#0-8) 

These core crates contain the actual elliptic curve arithmetic, field operations, and serialization logic. Any bugs in the fork could violate the **Deterministic Execution** and **Cryptographic Correctness** invariants, causing:

1. **Consensus Divergence**: Different validators computing different pairing results
2. **Invalid Signature Verification**: Accepting invalid proofs or rejecting valid ones
3. **Cryptographic Weaknesses**: Subtle arithmetic bugs enabling cryptographic attacks

The codebase's secure coding guidelines require third-party crate evaluation: [10](#0-9) 

However, there is no documentation justifying the use of this fork or evidence of independent cryptographic audit.

## Impact Explanation
**High Severity** - This meets the "Significant protocol violations" category because:

1. **Consensus Safety Risk**: Bugs in elliptic curve arithmetic could cause validators to compute different pairing results for the same inputs, violating deterministic execution and potentially causing chain splits
2. **Cryptographic Integrity**: The pairing operations are used in Move VM native functions exposed to smart contracts, affecting any on-chain cryptographic protocols
3. **Supply Chain Risk**: Using unaudited forked cryptographic code violates best practices and increases attack surface

While no specific bug has been identified in the fork, the use of unaudited cryptographic code in consensus-critical operations represents a significant protocol risk.

## Likelihood Explanation
**Medium Likelihood** - The risk materializes if:

1. The fork contains arithmetic bugs not present in the official arkworks implementation
2. An attacker discovers these bugs through code review or fuzzing
3. The bugs can be triggered through Move VM transactions calling pairing operations

The branch name `fix-fft-parallelism-cutoff` suggests performance optimizations that could introduce subtle correctness bugs. Without independent audit, the probability of undiscovered bugs remains non-negligible.

## Recommendation
1. **Document Fork Justification**: Add comprehensive documentation explaining why the fork is necessary and what changes were made
2. **Independent Audit**: Commission a cryptographic audit of the forked arkworks implementation by qualified cryptographers
3. **Upstream Contribution**: Work to merge necessary fixes upstream to the official arkworks repository
4. **Continuous Monitoring**: Set up automated testing to compare fork behavior against official arkworks releases

Add documentation to the codebase:

```rust
// aptos-move/framework/src/natives/cryptography/algebra/pairing.rs
// SECURITY NOTE: This module uses ark_bls12_381 and ark_bn254 which depend on
// forked arkworks core libraries (ark-ec, ark-ff) from github.com/aptos-labs/algebra.
// The fork applies FFT parallelism optimizations. Changes have been reviewed by [AUDITOR]
// on [DATE]. See [AUDIT-REPORT-LINK] for details.
```

## Proof of Concept
Unable to provide a concrete PoC without identifying a specific bug in the forked implementation. However, to verify the supply chain risk:

```bash
# Check resolved dependencies
cargo tree -p ark-bls12-381 -e normal
# Output will show ark-ec 0.5.0 from git+https://github.com/aptos-labs/algebra

# Verify the fork commit
grep -A 5 "ark-ec" Cargo.lock | grep source
# Shows: source = "git+https://github.com/aptos-labs/algebra?branch=fix-fft-parallelism-cutoff#..."
```

## Notes
The question asks whether the implementations are from "audited, official arkworks implementations." While the top-level crates (`ark-bls12-381`, `ark-bn254`) are from official sources, the core cryptographic operations are implemented in the forked dependencies. Any deviation from audited code in cryptographic primitives represents a security risk, even absent a concrete exploit. This finding highlights a supply chain vulnerability that should be addressed through proper audit and documentation.

### Citations

**File:** aptos-move/framework/src/natives/cryptography/algebra/pairing.rs (L186-186)
```rust
                ark_bls12_381::Bls12_381,
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/pairing.rs (L198-198)
```rust
                ark_bn254::Bn254,
```

**File:** Cargo.toml (L975-980)
```text
ark-ec = { git = "https://github.com/aptos-labs/algebra", branch = "fix-fft-parallelism-cutoff" }
ark-ff = { git = "https://github.com/aptos-labs/algebra", branch = "fix-fft-parallelism-cutoff" }
ark-ff-macros = { git = "https://github.com/aptos-labs/algebra", branch = "fix-fft-parallelism-cutoff" }
ark-ff-asm = { git = "https://github.com/aptos-labs/algebra", branch = "fix-fft-parallelism-cutoff" }
ark-poly = { git = "https://github.com/aptos-labs/algebra", branch = "fix-fft-parallelism-cutoff" }
ark-serialize = { git = "https://github.com/aptos-labs/algebra", branch = "fix-fft-parallelism-cutoff" }
```

**File:** Cargo.lock (L5200-5209)
```text
name = "ark-bls12-381"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3df4dcc01ff89867cd86b0da835f23c3f02738353aaee7dde7495af71363b8d5"
dependencies = [
 "ark-ec 0.5.0",
 "ark-ff 0.5.0",
 "ark-serialize 0.5.0",
 "ark-std 0.5.0",
]
```

**File:** Cargo.lock (L5212-5220)
```text
name = "ark-bn254"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d69eab57e8d2663efa5c63135b2af4f396d66424f88954c21104125ab6b3e6bc"
dependencies = [
 "ark-ec 0.5.0",
 "ark-ff 0.5.0",
 "ark-std 0.5.0",
]
```

**File:** Cargo.lock (L5274-5276)
```text
name = "ark-ec"
version = "0.5.0"
source = "git+https://github.com/aptos-labs/algebra?branch=fix-fft-parallelism-cutoff#2cacd5efad67bce331aec780b6fcfa4a45f44306"
```

**File:** Cargo.lock (L5315-5317)
```text
name = "ark-ff"
version = "0.5.0"
source = "git+https://github.com/aptos-labs/algebra?branch=fix-fft-parallelism-cutoff#2cacd5efad67bce331aec780b6fcfa4a45f44306"
```

**File:** Cargo.lock (L5408-5410)
```text
name = "ark-poly"
version = "0.5.0"
source = "git+https://github.com/aptos-labs/algebra?branch=fix-fft-parallelism-cutoff#2cacd5efad67bce331aec780b6fcfa4a45f44306"
```

**File:** Cargo.lock (L5447-5449)
```text
name = "ark-serialize"
version = "0.5.0"
source = "git+https://github.com/aptos-labs/algebra?branch=fix-fft-parallelism-cutoff#2cacd5efad67bce331aec780b6fcfa4a45f44306"
```

**File:** RUST_SECURE_CODING.md (L38-43)
```markdown
### Crate Quality and Security

Assess and monitor the quality and maintenance of crates that are being introduced to the codebase, employing tools like `cargo-outdated` and `cargo-audit` for version management and vulnerability checking.

- Aptos utilizes **[Dependabot](https://github.com/dependabot)** to continuously monitor libraries. Our policy requires mandatory updates for critical and high-vulnerabilities, or upon impact evaluation given the context for medium and lower.
- We recommend leveraging [deps.dev](https://deps.dev) to evaluate new third party crates. This site provides an OpenSSF scorecard containing essential information. As a guideline, libraries with a score of 7 or higher are typically safe to import. However, those scoring **below 7** must be flagged during the PR and require a specific justification.
```
