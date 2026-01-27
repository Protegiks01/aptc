# Audit Report

## Title
Malicious REST Endpoints Can Bypass Package Safety Checks via Unverified PackageRegistry Data

## Summary
The `CachedPackageRegistry::create()` function fetches package metadata from user-configurable REST endpoints without cryptographic verification. This allows malicious endpoints to return fake `PackageRegistry` data that bypasses critical client-side safety checks, enabling supply chain attacks through the download of packages with manipulated upgrade policies.

## Finding Description

The vulnerability exists in the package metadata retrieval flow: [1](#0-0) 

This function creates a REST client from a user-provided URL and fetches `PackageRegistry` data without any cryptographic validation. The REST client only validates HTTP headers for metadata but never verifies the actual data payload using state proofs or Merkle proofs: [2](#0-1) [3](#0-2) [4](#0-3) 

The `State::from_headers()` only extracts chain_id, version, and epoch from HTTP headers—no cryptographic proofs are verified.

**Attack Scenario 1: DownloadPackage Bypass (CRITICAL)**

The `DownloadPackage` command implements a safety check to prevent downloading packages with `arbitrary` upgrade policy: [5](#0-4) 

A malicious REST endpoint can bypass this by returning fake data claiming the package has `immutable` or `compatible` policy when it actually has `arbitrary` policy on-chain. This enables:

1. **Supply Chain Attack**: Users download mutable code thinking it's stable
2. **Build Non-Determinism**: Downloaded package can change on-chain, breaking reproducible builds  
3. **Dependency Safety Violation**: Violates the invariant that arbitrary packages should not be used as dependencies

**Attack Scenario 2: UpgradeObjectPackage Bypass** [6](#0-5) 

A malicious endpoint can claim a package is upgradeable when it's actually immutable, causing users to waste transaction fees on failed upgrade attempts.

**Attack Scenario 3: VerifyPackage Bypass** [7](#0-6) 

Same arbitrary policy bypass as DownloadPackage, allowing verification of unsafe packages.

**Exploitation Steps:**

1. Attacker deploys malicious REST endpoint mimicking Aptos API
2. Social engineering: convince user to configure malicious URL via `--url` flag or `.aptos/config.yaml`
3. User runs: `aptos move download --account 0xVICTIM --package EvilPackage --url https://malicious-endpoint.com`
4. Malicious endpoint returns fake PackageRegistry with `upgrade_policy = 1` (immutable) when on-chain value is `upgrade_policy = 2` (arbitrary)
5. CLI bypasses safety check at line 1991-1996
6. User incorporates downloaded package as dependency
7. User builds and deploys their package believing dependency is stable
8. Attacker later upgrades the on-chain arbitrary package, changing behavior
9. User's deployed code now depends on different logic than audited

## Impact Explanation

**HIGH Severity** per Aptos bug bounty criteria for "Significant protocol violations":

1. **Safety Invariant Violation**: Breaks the documented safety requirement that arbitrary packages must not be used as dependencies due to their mutability
2. **Supply Chain Attack Vector**: Enables widespread compromise if malicious endpoint is promoted to multiple developers
3. **Build Reproducibility Failure**: Violates deterministic execution invariant (Invariant #1) as identical source can produce different behavior
4. **Audit Invalidation**: Security audits become meaningless when dependencies can silently change

While this doesn't directly cause consensus violations or fund loss, it represents a significant protocol-level security failure that undermines the trust model of the Move package ecosystem.

## Likelihood Explanation

**MEDIUM to HIGH likelihood:**

- **Low Barrier**: Requires only social engineering to change REST endpoint URL
- **Realistic Attack**: Attacker could promote malicious endpoint through:
  - Fake tutorials/documentation
  - Compromised development tools
  - Supply chain attacks on CLI distribution
- **Detection Difficulty**: Users have no way to detect fake data without manually querying trusted endpoints
- **Wide Impact**: Single malicious endpoint can affect multiple developers

## Recommendation

Implement cryptographic verification of REST endpoint responses using state proofs:

```rust
pub async fn create(
    url: Url,
    addr: AccountAddress,
    with_bytecode: bool,
) -> anyhow::Result<Self> {
    let client = Client::new(url);
    
    // Fetch PackageRegistry WITH state proof
    let response = client
        .get_account_resource_with_proof::<PackageRegistry>(
            addr, 
            "0x1::code::PackageRegistry"
        )
        .await?;
    
    // VERIFY the state proof against trusted root
    verify_state_proof(&response.proof, &response.state)?;
    
    let inner = response.into_inner();
    
    // ... rest of function
}
```

**Alternative Mitigation** (if state proofs unavailable):

Add prominent warnings when using non-default REST endpoints:

```rust
pub async fn create(
    url: Url,
    addr: AccountAddress, 
    with_bytecode: bool,
) -> anyhow::Result<Self> {
    // Warn if using non-default endpoint
    if !is_trusted_endpoint(&url) {
        eprintln!("⚠️  WARNING: Using non-default REST endpoint: {}", url);
        eprintln!("⚠️  Package metadata cannot be cryptographically verified.");
        eprintln!("⚠️  Only proceed if you trust this endpoint.");
    }
    
    // ... existing code
}
```

## Proof of Concept

```rust
// File: crates/aptos/tests/malicious_endpoint_test.rs
use aptos_rest_client::Client;
use mockito::mock;
use aptos_types::account_address::AccountAddress;

#[tokio::test]
async fn test_malicious_endpoint_bypass() {
    // Setup malicious mock server
    let _m = mock("GET", "/v1/accounts/0x1/resource/0x1::code::PackageRegistry")
        .with_status(200)
        .with_header("content-type", "application/x-bcs")
        .with_body({
            // BCS-encoded PackageRegistry with fake upgrade_policy
            // On-chain: arbitrary (2), Returned: immutable (1)
            let fake_registry = PackageRegistry {
                packages: vec![PackageMetadata {
                    name: "TestPackage".to_string(),
                    upgrade_policy: UpgradePolicy::immutable(), // FAKE
                    // ... other fields
                }]
            };
            bcs::to_bytes(&fake_registry).unwrap()
        })
        .create();

    // User runs download command with malicious URL
    let url = mockito::server_url().parse().unwrap();
    let registry = CachedPackageRegistry::create(
        url,
        AccountAddress::from_hex_literal("0x1").unwrap(),
        false
    ).await.unwrap();

    // Verify CLI accepts fake data
    let package = registry.get_package("TestPackage").await.unwrap();
    assert_eq!(package.upgrade_policy(), UpgradePolicy::immutable());
    
    // Safety check is bypassed - package downloads despite being arbitrary on-chain
    // In real scenario: on-chain value is arbitrary, but CLI thinks it's immutable
}
```

**Notes:**

- This vulnerability is client-side and does NOT affect consensus or validator nodes
- On-chain verification remains intact—transactions still get validated properly
- The issue specifically enables **pre-deployment** attacks via corrupted package downloads
- Impact is amplified in scenarios where downloaded packages are used as build dependencies
- Aptos codebase has state proof mechanisms but they're not used by the REST client for resource queries

### Citations

**File:** crates/aptos/src/move_tool/stored_package.rs (L43-69)
```rust
    pub async fn create(
        url: Url,
        addr: AccountAddress,
        with_bytecode: bool,
    ) -> anyhow::Result<Self> {
        let client = Client::new(url);
        // Need to use a different type to deserialize JSON
        let inner = client
            .get_account_resource_bcs::<PackageRegistry>(addr, "0x1::code::PackageRegistry")
            .await?
            .into_inner();
        let mut bytecode = BTreeMap::new();
        if with_bytecode {
            for pack in &inner.packages {
                for module in &pack.modules {
                    let bytes = client
                        .get_account_module(addr, &module.name)
                        .await?
                        .into_inner()
                        .bytecode
                        .0;
                    bytecode.insert(module.name.clone(), bytes);
                }
            }
        }
        Ok(Self { inner, bytecode })
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1687-1690)
```rust
    async fn get_bcs(&self, url: Url) -> AptosResult<Response<bytes::Bytes>> {
        let response = self.inner.get(url).header(ACCEPT, BCS).send().await?;
        self.check_and_parse_bcs_response(response).await
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1773-1779)
```rust
    async fn check_and_parse_bcs_response(
        &self,
        response: reqwest::Response,
    ) -> AptosResult<Response<bytes::Bytes>> {
        let (response, state) = self.check_response(response).await?;
        Ok(Response::new(response.bytes().await?, state))
    }
```

**File:** crates/aptos-rest-client/src/state.rs (L22-102)
```rust
impl State {
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> anyhow::Result<Self> {
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_version = headers
            .get(X_APTOS_LEDGER_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_timestamp = headers
            .get(X_APTOS_LEDGER_TIMESTAMP)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_epoch = headers
            .get(X_APTOS_EPOCH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_ledger_version = headers
            .get(X_APTOS_LEDGER_OLDEST_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_block_height = headers
            .get(X_APTOS_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_block_height = headers
            .get(X_APTOS_OLDEST_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cursor = headers
            .get(X_APTOS_CURSOR)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let state = if let (
            Some(chain_id),
            Some(version),
            Some(timestamp_usecs),
            Some(epoch),
            Some(oldest_ledger_version),
            Some(block_height),
            Some(oldest_block_height),
            cursor,
        ) = (
            maybe_chain_id,
            maybe_version,
            maybe_timestamp,
            maybe_epoch,
            maybe_oldest_ledger_version,
            maybe_block_height,
            maybe_oldest_block_height,
            cursor,
        ) {
            Self {
                chain_id,
                epoch,
                version,
                timestamp_usecs,
                oldest_ledger_version,
                block_height,
                oldest_block_height,
                cursor,
            }
        } else {
            anyhow::bail!(
                "Failed to build State from headers due to missing values in response. \
                Chain ID: {:?}, Version: {:?}, Timestamp: {:?}, Epoch: {:?}, \
                Oldest Ledger Version: {:?}, Block Height: {:?} Oldest Block Height: {:?}",
                maybe_chain_id,
                maybe_version,
                maybe_timestamp,
                maybe_epoch,
                maybe_oldest_ledger_version,
                maybe_block_height,
                maybe_oldest_block_height,
            )
        };

        Ok(state)
    }
```

**File:** crates/aptos/src/move_tool/mod.rs (L1307-1318)
```rust
        // Get the `PackageRegistry` at the given object address.
        let registry = CachedPackageRegistry::create(url, self.object_address, false).await?;
        let package = registry
            .get_package(built_package.name())
            .await
            .map_err(|s| CliError::CommandArgumentError(s.to_string()))?;

        if package.upgrade_policy() == UpgradePolicy::immutable() {
            return Err(CliError::CommandArgumentError(
                "A package with upgrade policy `immutable` cannot be upgraded".to_owned(),
            ));
        }
```

**File:** crates/aptos/src/move_tool/mod.rs (L1983-1997)
```rust
        let url = self.rest_options.url(&self.profile_options)?;
        let registry = CachedPackageRegistry::create(url, self.account, self.bytecode).await?;
        let output_dir = dir_default_to_current(self.output_dir)?;

        let package = registry
            .get_package(self.package)
            .await
            .map_err(|s| CliError::CommandArgumentError(s.to_string()))?;
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            return Err(CliError::CommandArgumentError(
                "A package with upgrade policy `arbitrary` cannot be downloaded \
                since it is not safe to depend on such packages."
                    .to_owned(),
            ));
        }
```

**File:** crates/aptos/src/move_tool/mod.rs (L2063-2077)
```rust
        let url = self.rest_options.url(&self.profile_options)?;
        let registry = CachedPackageRegistry::create(url, self.account, false).await?;
        let package = registry
            .get_package(pack.name())
            .await
            .map_err(|s| CliError::CommandArgumentError(s.to_string()))?;

        // We can't check the arbitrary, because it could change on us
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            return Err(CliError::CommandArgumentError(
                "A package with upgrade policy `arbitrary` cannot be downloaded \
                since it is not safe to depend on such packages."
                    .to_owned(),
            ));
        }
```
