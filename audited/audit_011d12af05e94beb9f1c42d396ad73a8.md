# Audit Report

## Title
Credential Leakage in Git URLs Through Error Messages and Console Output

## Summary
Git URLs containing embedded credentials (e.g., `https://user:pass@github.com/repo`) in Move package dependencies can leak into error messages and console output, exposing authentication credentials in logs and build outputs.

## Finding Description

The Move package system accepts Git URLs that may contain embedded credentials in the userinfo component (`https://username:password@host/repo`). These URLs are stored without sanitization and subsequently exposed through multiple code paths:

1. **Manifest Parsing**: [1](#0-0) 

2. **Error Message Exposure in Package Cache**: [2](#0-1) 

3. **Error Message Exposure (Clone Failure)**: [3](#0-2) 

4. **Error Message Exposure (Revision Resolution)**: [4](#0-3) 

5. **Console Output Exposure (Fetching)**: [5](#0-4) 

6. **Console Output Exposure (Updating)**: [6](#0-5) 

While the codebase implements `CanonicalGitIdentity` that strips credentials: [7](#0-6) 

The original URLs containing credentials are used in error handling and logging **before** canonicalization occurs, resulting in credential exposure.

## Impact Explanation

This qualifies as a **Low Severity** vulnerability per the Aptos bug bounty criteria ("Minor information leaks"). The leaked credentials could provide unauthorized access to private Git repositories, potentially enabling:

- Unauthorized code access to proprietary Move packages
- Supply chain attack vectors if repositories are compromised
- Exposure of development credentials in CI/CD logs

However, this does **not** directly impact on-chain security, consensus, validator operations, or user funds.

## Likelihood Explanation

**High likelihood** for the following reasons:
1. Developers commonly embed credentials in URLs for private repository access
2. Error conditions (network failures, invalid revisions) are common during development
3. Build logs are frequently shared in CI/CD systems, issue trackers, and team communications
4. The vulnerability triggers during normal package resolution operations

## Recommendation

Implement credential sanitization before displaying URLs in any user-facing output:

```rust
use url::Url;

fn sanitize_url(url: &Url) -> String {
    let mut sanitized = url.clone();
    sanitized.set_username("").ok();
    sanitized.set_password(None).ok();
    sanitized.to_string()
}
```

Apply sanitization in:
- All error messages in `package_cache.rs`
- Console output in `resolution_graph.rs`  
- Any logging or display of Git URLs

## Proof of Concept

1. Create a Move.toml with embedded credentials:
```toml
[package]
name = "TestPackage"
version = "1.0.0"

[dependencies]
SecretDep = { git = "https://user:secretpass@github.com/private/repo.git", rev = "main" }
```

2. Attempt to build the package when:
   - Repository doesn't exist (triggers error)
   - Network is unavailable
   - Invalid revision is specified

3. Observe credentials in:
   - Console output: `FETCHING GIT DEPENDENCY https://user:secretpass@github.com/private/repo.git`
   - Error messages: `Failed to clone git repo at https://user:secretpass@github.com/private/repo.git: ...`

## Notes

This vulnerability exists in the Move package development tooling layer, not in the core Aptos blockchain protocol. While it represents a genuine credential leakage issue in the codebase, it does **not** affect:

- Blockchain consensus mechanisms
- On-chain state or transaction execution  
- Validator operations or staking
- Smart contract security or Move VM execution
- Any of the 10 Critical Invariants defined for Aptos Core

The issue is confined to the development environment and does not compromise blockchain security properties. It should be addressed to protect developer credentials and prevent supply chain risks, but it does not constitute a threat to the Aptos network itself.

### Citations

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L284-288)
```rust
            (None, Some(url), None) => PackageLocation::Git {
                url,
                rev: raw.rev,
                subdir: raw.subdir,
            },
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L153-153)
```rust
                    .map_err(|err| anyhow!("Failed to update git repo at {}: {}", git_url, err))?;
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L168-168)
```rust
                .map_err(|err| anyhow!("Failed to clone git repo at {}: {}", git_url, err))?;
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L193-197)
```rust
                anyhow!(
                    "Failed to resolve rev string \"{}\" in repo {}",
                    rev,
                    git_url
                )
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L564-569)
```rust
                writeln!(
                    writer,
                    "{} {}",
                    "FETCHING GIT DEPENDENCY".bold().green(),
                    git_url,
                )?;
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L599-604)
```rust
                writeln!(
                    writer,
                    "{} {}",
                    "UPDATING GIT DEPENDENCY".bold().green(),
                    git_url,
                )?;
```

**File:** third_party/move/tools/move-package-cache/src/canonical.rs (L20-38)
```rust
    pub fn new(git_url: &Url) -> Result<Self> {
        let host = git_url
            .host_str()
            .ok_or_else(|| anyhow!("invalid git URL, unable to extract host: {}", git_url))?
            .to_ascii_lowercase();

        let port = match git_url.port() {
            Some(port) => match (git_url.scheme(), port) {
                ("http", 80) | ("https", 443) | ("ssh", 22) => "".to_string(),
                _ => format!(":{}", port),
            },
            None => "".to_string(),
        };

        let path = git_url.path().to_ascii_lowercase();
        let path = path.trim_end_matches("/").trim_end_matches(".git");

        Ok(Self(format!("{}{}{}", host, port, path)))
    }
```
