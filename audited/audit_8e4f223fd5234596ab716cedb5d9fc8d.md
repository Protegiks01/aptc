# Audit Report

## Title
Missing Automated Security Advisory Checks for Move Compiler Dependencies Despite Documented Policy

## Summary
The Aptos Core codebase lacks automated CVE/security advisory checking for critical dependencies in the Move compiler toolchain (clap, petgraph, once_cell) despite documentation claiming such checks are performed. The CI pipeline only validates dependency licenses but does not check for known security vulnerabilities.

## Finding Description

The security question asks whether external dependencies in `third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs` are audited for known CVEs. Investigation reveals a critical gap between documented security practices and actual implementation. [1](#0-0) 

These dependencies are used throughout the Move compiler:
- `clap 4.3.9` - command-line argument parsing
- `petgraph 0.6.5` - graph algorithms for dependency analysis  
- `once_cell 1.10.0` - lazy static initialization [2](#0-1) [3](#0-2) [4](#0-3) 

**The Documentation Claims:** [5](#0-4) 

The documentation explicitly states that `cargo-audit` is used for vulnerability checking and Dependabot monitors libraries for critical and high vulnerabilities.

**The Reality:**

The CI pipeline's `rust-cargo-deny` job only checks licenses: [6](#0-5) 

The `deny.toml` configuration file only contains license checking rules with no `[advisories]` section: [7](#0-6) 

No `cargo-audit` execution was found in any CI workflow, and no Dependabot configuration file exists in the repository.

**Security Implications:**

Without automated CVE checking, vulnerable dependency versions could be:
1. Introduced through dependency updates without detection
2. Remain unpatched in the codebase even after CVEs are publicly disclosed
3. Affect the Move compiler, which is critical infrastructure for all Move bytecode compilation
4. Potentially impact deterministic execution if compiler bugs cause different bytecode generation across nodes

## Impact Explanation

This issue qualifies as **Medium Severity** based on the following reasoning:

While this is primarily a **missing security control** rather than a direct exploitable vulnerability, it creates significant supply chain security risk:

1. **No Direct Exploit Path**: Without access to external CVE databases, I cannot demonstrate that current dependency versions contain known vulnerabilities
2. **Process Gap with Potential Impact**: If any of these dependencies have published CVEs, they would go undetected
3. **Critical Component Affected**: The Move compiler is infrastructure-level code that affects all Move bytecode execution
4. **Documentation vs Reality Gap**: The documented security policy creates false assurance

This does not meet **Critical** or **High** severity because:
- No specific CVE exploitation is demonstrated
- The issue requires an actual CVE to exist in the dependencies
- Cryptographic primitives are not directly affected
- No consensus violation is shown

However, it exceeds **Low** severity because:
- Move compiler bugs could affect deterministic execution
- Supply chain vulnerabilities in compilers can have cascading effects
- The gap between documented and actual security controls is significant

## Likelihood Explanation

**Likelihood: Medium**

The likelihood depends on whether the specific dependency versions contain known CVEs, which I cannot verify without external database access. However:

1. **Dependencies are commonly used**: clap, petgraph, and once_cell are popular crates with active development
2. **Version currency**: The versions used (clap 4.3.9 from July 2023, petgraph 0.6.5, once_cell 1.10.0 from March 2022) are not the latest
3. **Public disclosure**: Any CVEs in these versions would be publicly documented in RustSec Advisory Database
4. **No automated detection**: Without cargo-audit/cargo-deny advisories check, updates would be manual

## Recommendation

**Immediate Actions:**

1. **Enable advisory checking in deny.toml**:

Add an `[advisories]` section to `deny.toml`:

```toml
[advisories]
version = 2
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"
```

2. **Update CI workflow**: [8](#0-7) 

Change to:
```yaml
command: check advisories licenses
```

3. **Add cargo-audit to CI** as documented, or rely on cargo-deny with advisories enabled

4. **Configure Dependabot** if not already present at the GitHub organization level

5. **Immediate audit**: Run `cargo audit` manually to check current dependency versions for known CVEs

## Proof of Concept

**Verification Steps:**

```bash
# 1. Check current deny.toml configuration
cat deny.toml
# Shows only [licenses] section, no [advisories]

# 2. Check CI configuration
grep -A 5 "cargo-deny-action" .github/workflows/lint-test.yaml
# Shows "command: check licenses" only

# 3. Manual vulnerability check (requires cargo-audit)
cargo install cargo-audit
cargo audit
# This will reveal any known CVEs in current dependencies

# 4. Verify versions in use
grep -E "(clap|petgraph|once_cell) =" Cargo.toml
# Shows clap 4.3.9, petgraph 0.6.5, once_cell 1.10.0
```

## Notes

**Important Clarifications:**

1. **This is not a code vulnerability**: This finding identifies a gap between documented security practices and actual implementation. I cannot demonstrate exploitation without access to CVE databases.

2. **Dependabot may exist**: The documentation mentions Dependabot, which might be configured at the GitHub organization level (not visible in repository files). However, Dependabot alone is insufficient without CI enforcement.

3. **Actual CVE status unknown**: I cannot verify whether clap 4.3.9, petgraph 0.6.5, or once_cell 1.10.0 have known CVEs without external database access.

4. **move_symbol_pool**: This is an internal crate and not subject to external CVE databases.

5. **The bar for "vulnerability" vs "security gap"**: Per the validation checklist, this issue does not demonstrate "clear security harm" without proving specific CVEs exist. However, it definitively answers the security question: **No, dependencies are not audited for known CVEs in automated CI**.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L9-14)
```rust
use clap::*;
use move_command_line_common::env::{bool_to_str, read_bool_env_var};
use move_ir_types::location::*;
use move_symbol_pool::Symbol;
use once_cell::sync::Lazy;
use petgraph::{algo::astar as petgraph_astar, graphmap::DiGraphMap};
```

**File:** Cargo.toml (L554-559)
```text
clap = { version = "4.3.9", features = [
    "derive",
    "env",
    "unstable-styles",
    "wrap_help",
] }
```

**File:** Cargo.toml (L702-702)
```text
once_cell = "1.10.0"
```

**File:** Cargo.toml (L721-721)
```text
petgraph = "0.6.5"
```

**File:** RUST_SECURE_CODING.md (L38-43)
```markdown
### Crate Quality and Security

Assess and monitor the quality and maintenance of crates that are being introduced to the codebase, employing tools like `cargo-outdated` and `cargo-audit` for version management and vulnerability checking.

- Aptos utilizes **[Dependabot](https://github.com/dependabot)** to continuously monitor libraries. Our policy requires mandatory updates for critical and high-vulnerabilities, or upon impact evaluation given the context for medium and lower.
- We recommend leveraging [deps.dev](https://deps.dev) to evaluate new third party crates. This site provides an OpenSSF scorecard containing essential information. As a guideline, libraries with a score of 7 or higher are typically safe to import. However, those scoring **below 7** must be flagged during the PR and require a specific justification.
```

**File:** .github/workflows/lint-test.yaml (L82-93)
```yaml
  # Run cargo deny. This is a PR required job.
  rust-cargo-deny:
    needs: file_change_determinator
    runs-on: 2cpu-gh-ubuntu24-x64
    steps:
      - uses: actions/checkout@v4
        if: needs.file_change_determinator.outputs.only_docs_changed != 'true'
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check licenses
      - run: echo "Skipping cargo deny! Unrelated changes detected."
        if: needs.file_change_determinator.outputs.only_docs_changed == 'true'
```

**File:** deny.toml (L1-26)
```text
# This is a configuration file for cargo deny, the tool we use to prevent accidentally
# onboarding dependencies with licenses we don't want to use. To test this config, try
# running a command like this:
#
# cargo deny check licenses --hide-inclusion-graph

[licenses]
version = 2
allow = [
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "CDDL-1.0",
    "ISC",
    "LicenseRef-Aptos",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "OpenSSL",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
    "NCSA",
]
```
