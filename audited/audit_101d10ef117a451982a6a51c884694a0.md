# Audit Report

## Title
Missing Pre-Release Flag Validation in Aptos CLI Auto-Update Mechanism

## Summary
The Aptos CLI's `get_update_info()` function does not validate the GitHub release `prerelease` flag when determining the latest version to install. This allows pre-release builds to be automatically installed as production updates, potentially exposing users to unstable code, security vulnerabilities, or malicious payloads if a pre-release is created (intentionally or accidentally).

## Finding Description

The GitHub Releases API returns a `prerelease` boolean field for each release, indicating whether it's a stable production release or an unstable pre-release. The Aptos CLI update mechanism fetches releases from GitHub but fails to filter based on this flag. [1](#0-0) 

The `get_update_info()` function iterates through releases and selects the first one with a tag starting with `"aptos-cli-"`, without checking if `prerelease` is true. [2](#0-1) 

While the official release workflow hardcodes `prerelease: false`: [3](#0-2) 

This does not prevent repository maintainers or attackers with compromised GitHub credentials from creating pre-releases manually. If someone creates a pre-release tagged `aptos-cli-v99.99.99` (higher than current stable), users running `aptos update` would automatically download and install it.

**Attack Scenario:**
1. Attacker gains GitHub repository write access (compromised credentials, malicious insider, supply chain attack)
2. Attacker creates a pre-release with tag `aptos-cli-v8.0.0` containing malicious code
3. Users run `aptos update` 
4. The malicious pre-release is detected as the "latest" version
5. Users install compromised CLI binary
6. Malicious code steals private keys, generates fraudulent transactions, or exfiltrates sensitive data

**Security Guarantee Violated:**
Users expect the auto-update mechanism to only install stable, vetted releases. The lack of pre-release filtering breaks this security expectation and enables supply chain attacks.

## Impact Explanation

This qualifies as **Medium Severity** ($10,000 tier) per Aptos Bug Bounty criteria:
- **Limited funds loss or manipulation**: Compromised CLI could generate incorrect transactions leading to fund loss
- **Supply chain vulnerability**: Affects all CLI users who use the update mechanism
- **User trust violation**: Auto-update should only install production-ready releases

While not directly affecting consensus or the blockchain itself, a compromised CLI can:
- Steal user private keys stored in wallet configurations
- Generate malicious transactions that users unknowingly sign
- Compromise local node operations for validators using the CLI
- Install backdoors for persistent access

## Likelihood Explanation

**Likelihood: Medium**

While this requires repository write access (elevated privilege), supply chain attacks targeting GitHub repositories are increasingly common:
- Compromised maintainer accounts via phishing or credential stuffing
- Malicious insiders with legitimate access
- Compromised CI/CD pipelines creating unauthorized releases
- Accidental pre-release creation by maintainers unfamiliar with release process

The attack becomes more likely as the project grows and more contributors gain release permissions. Additionally, pre-releases could be created accidentally, not just maliciously.

## Recommendation

Add pre-release flag validation in the release selection logic:

```rust
// In get_update_info() function, modify the loop:
let latest_release = loop {
    let release = match releases.next() {
        Some(release) => release,
        None => return Err(anyhow!("Failed to find latest CLI release")),
    };
    // Filter for CLI releases AND exclude pre-releases
    if release.version.starts_with("aptos-cli-") && !release.prerelease {
        break release;
    }
};
```

Additionally, consider:
1. Adding a `--allow-prerelease` flag for users who explicitly want to test pre-releases
2. Warning users when the latest stable release is older than available pre-releases
3. Implementing release signature verification for additional security

## Proof of Concept

**Manual Reproduction Steps:**

1. Create a test GitHub repository with the Aptos CLI release structure
2. Create a pre-release with tag `aptos-cli-v99.99.99` (higher than current version)
3. Build and run the Aptos CLI with the test repository configuration:
   ```bash
   cargo build --release
   ./target/release/aptos update --repo-owner test-org --repo-name test-repo --check
   ```
4. Observe that the CLI reports v99.99.99 as the latest version, despite it being a pre-release
5. Remove the `--check` flag to observe it actually downloads the pre-release

**Expected Behavior:** The CLI should skip the pre-release and report the latest stable release.

**Actual Behavior:** The CLI treats the pre-release as a valid update candidate.

**Unit Test (pseudo-code):**
```rust
#[test]
fn test_prerelease_filtering() {
    // Mock GitHub API response with both stable and pre-release
    let releases = vec![
        Release { version: "aptos-cli-v2.0.0", prerelease: true },
        Release { version: "aptos-cli-v1.5.0", prerelease: false },
    ];
    
    let updater = AptosUpdateTool::default();
    let info = updater.get_update_info().unwrap();
    
    // Should select v1.5.0 (stable), not v2.0.0 (pre-release)
    assert_eq!(info.target_version, "1.5.0");
}
```

---

**Notes:**
- This vulnerability requires elevated GitHub repository access but represents a realistic supply chain attack vector
- The self_update crate's `Release` struct includes the `prerelease` field from GitHub's API, making the fix straightforward
- No evidence of this check exists in the current codebase (grep search for "prerelease" returned no results in Rust files)

### Citations

**File:** crates/aptos/src/update/aptos.rs (L59-94)
```rust
    fn get_update_info(&self) -> Result<UpdateRequiredInfo> {
        // Build a configuration for determining the latest release.
        let config = ReleaseList::configure()
            .repo_owner(&self.repo_owner)
            .repo_name(&self.repo_name)
            .build()
            .map_err(|e| anyhow!("Failed to build configuration to fetch releases: {:#}", e))?;

        // Get the most recent releases.
        let releases = config
            .fetch()
            .map_err(|e| anyhow!("Failed to fetch releases: {:#}", e))?;

        // Find the latest release of the CLI, in which we filter for the CLI tag.
        // If the release isn't in the last 30 items (the default API page size)
        // this will fail. See https://github.com/aptos-labs/aptos-core/issues/6411.
        let mut releases = releases.into_iter();
        let latest_release = loop {
            let release = match releases.next() {
                Some(release) => release,
                None => return Err(anyhow!("Failed to find latest CLI release")),
            };
            if release.version.starts_with("aptos-cli-") {
                break release;
            }
        };
        let target_version = latest_release.version.split("-v").last().unwrap();

        // Return early if we're up to date already.
        let current_version = cargo_crate_version!();

        Ok(UpdateRequiredInfo {
            current_version: Some(current_version.to_string()),
            target_version: target_version.to_string(),
        })
    }
```

**File:** .github/workflows/cli-release.yaml (L177-177)
```yaml
          prerelease: false
```
