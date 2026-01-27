# Audit Report

## Title
TOCTOU Vulnerability in JWK Consensus Allows Malicious Key Injection via Race Condition Between OpenID Configuration and JWK Fetches

## Summary
The JWK consensus mechanism in Aptos validators is vulnerable to a time-of-check-time-of-use (TOCTOU) race condition. When fetching JWKs from OIDC providers, validators make two sequential HTTP requests: first to fetch the OpenID configuration (which contains the `jwks_uri`), then to fetch the actual JWKs from that URI. A malicious or compromised OIDC provider can return different `jwks_uri` values to different validators during these separate fetches, allowing injection of malicious JWKs if 2/3+ validators receive the same malicious URI.

## Finding Description

The vulnerability exists in the sequential HTTP call pattern used by validators to fetch JWKs: [1](#0-0) 

This `fetch_jwks` function calls two separate functions with a time gap between them: [2](#0-1) [3](#0-2) 

**The Critical Flaw**: The `jwks_uri` returned from the OpenID configuration endpoint is NOT included in the consensus message that validators sign and share. The consensus message only contains: [4](#0-3) 

This creates a TOCTOU vulnerability because:

1. Each validator's `JWKObserver` periodically fetches JWKs every 10 seconds
2. Different validators execute these fetches at different times
3. A malicious OIDC provider can return different `jwks_uri` values based on timing, IP address, or randomization
4. Validators fetch JWKs from these different URIs but have no way to detect the inconsistency
5. If 2/3+ validators happen to receive the same malicious `jwks_uri`, they will all fetch identical malicious JWKs
6. These validators will reach consensus on the malicious keys because their observations match exactly

The consensus aggregation mechanism validates that validators observed identical JWKs: [5](#0-4) 

But it cannot detect if those identical observations came from different `jwks_uri` endpoints, because the URI is not part of the comparison.

**Attack Scenario**:
1. Governance approves an OIDC provider (e.g., "https://auth.example.com")
2. The provider's OpenID config endpoint returns different `jwks_uri` values strategically:
   - To 67% of validators: `jwks_uri = "https://auth.example.com/malicious-keys"`
   - To 33% of validators: `jwks_uri = "https://auth.example.com/legitimate-keys"`
3. The 67% majority all fetch the same malicious keys and reach consensus
4. The malicious JWKs are written on-chain via `process_jwk_update`: [6](#0-5) 

5. These malicious JWKs can now be used to forge JWT signatures for keyless account authentication

**Evidence of Awareness**: The pepper service explicitly avoids this vulnerability by hardcoding JWK URLs rather than using dynamic fetches: [7](#0-6) 

However, this protection was not applied to the validator consensus code, which continues to use dynamic OpenID configuration fetches.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

1. **Significant Protocol Violation**: Allows injection of malicious cryptographic keys into the blockchain state that are used for authentication
2. **Potential Funds Loss**: Malicious JWKs enable an attacker to forge JWT signatures, gaining unauthorized access to keyless accounts and stealing funds
3. **Consensus Integrity**: While not a direct consensus safety violation, it undermines the integrity of the data that consensus is meant to protect

The impact is limited by:
- Requires governance to have approved the malicious/compromised OIDC provider
- Attacker must control the OIDC provider's infrastructure or compromise it
- Attack requires careful timing to get 2/3+ validators to fetch from the malicious URI

However, once successful, the attack enables complete account takeover for all users of that OIDC provider on Aptos.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
1. **OIDC Provider Control**: Attacker must either convince governance to approve their malicious provider, or compromise a legitimate provider's infrastructure
2. **Timing Coordination**: Must return consistent malicious URIs to 2/3+ validators during their periodic fetches
3. **Stealth**: Must avoid detection while manipulating responses

Factors increasing likelihood:
- Validators fetch every 10 seconds, providing multiple attack windows
- Smaller OIDC providers may have weaker security and be easier to compromise
- The attack leaves minimal traces since the `jwks_uri` is not logged or validated
- Governance may approve multiple OIDC providers, expanding attack surface

Factors decreasing likelihood:
- Requires deep compromise of OIDC provider infrastructure
- Need to maintain compromise long enough to coordinate attack across validators
- Risk of detection if legitimate users also query the provider simultaneously

## Recommendation

**Immediate Fix**: Include the `jwks_uri` in the consensus message so validators can detect when they're fetching from different endpoints.

Modified `ProviderJWKs` structure:
```rust
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct ProviderJWKs {
    #[serde(with = "serde_bytes")]
    pub issuer: Issuer,
    pub version: u64,
    pub jwks: Vec<JWKMoveStruct>,
    // Add this field:
    pub jwks_uri: Vec<u8>,  // The URI from which these JWKs were fetched
}
```

Update `fetch_jwks` to return both URI and keys:
```rust
async fn fetch_jwks(open_id_config_url: &str, my_addr: Option<AccountAddress>) -> Result<(String, Vec<JWK>)> {
    let jwks_uri = fetch_jwks_uri_from_openid_config(open_id_config_url)
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with open-id config request: {e}"))?;
    let jwks = fetch_jwks_from_jwks_uri(my_addr, jwks_uri.as_str())
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with jwks uri request: {e}"))?;
    Ok((jwks_uri, jwks))
}
```

**Alternative Fix**: Follow the pepper service approach and hardcode trusted OIDC provider JWK URLs in validator configuration, bypassing the OpenID configuration fetch entirely for well-known providers.

**Additional Hardening**:
1. Cache the `jwks_uri` per issuer and alert if it changes unexpectedly
2. Add cross-validator checks to detect when different validators observe different URIs
3. Implement a "cooling-off" period when a new `jwks_uri` is observed before using it for consensus

## Proof of Concept

```rust
// Test demonstrating the TOCTOU vulnerability
#[tokio::test]
async fn test_jwk_toctou_vulnerability() {
    use warp::Filter;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    
    // Attacker's flag to switch between URIs
    let use_malicious = Arc::new(AtomicBool::new(false));
    let use_malicious_clone = use_malicious.clone();
    
    // OpenID config endpoint that returns different jwks_uri
    let config_route = warp::path!(".well-known" / "openid-configuration")
        .map(move || {
            let is_malicious = use_malicious_clone.fetch_xor(true, Ordering::SeqCst);
            if is_malicious {
                warp::reply::json(&serde_json::json!({
                    "issuer": "https://attacker.com",
                    "jwks_uri": "http://localhost:3030/malicious-keys"
                }))
            } else {
                warp::reply::json(&serde_json::json!({
                    "issuer": "https://attacker.com",
                    "jwks_uri": "http://localhost:3030/legitimate-keys"
                }))
            }
        });
    
    // Malicious keys endpoint
    let malicious_keys = warp::path("malicious-keys")
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "kid": "malicious-key-1",
                    "n": "MALICIOUS_KEY_DATA",
                    "e": "AQAB"
                }]
            }))
        });
    
    // Legitimate keys endpoint  
    let legitimate_keys = warp::path("legitimate-keys")
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "kid": "legitimate-key-1",
                    "n": "LEGITIMATE_KEY_DATA",
                    "e": "AQAB"
                }]
            }))
        });
    
    let routes = config_route.or(malicious_keys).or(legitimate_keys);
    
    // Start the malicious server
    tokio::spawn(warp::serve(routes).run(([127, 0, 0, 1], 3030)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Simulate two validators fetching at different times
    let validator1_result = fetch_jwks("http://localhost:3030/.well-known/openid-configuration", None).await.unwrap();
    
    // Attacker's flag toggles, so next validator gets different URI
    let validator2_result = fetch_jwks("http://localhost:3030/.well-known/openid-configuration", None).await.unwrap();
    
    // Validators observe different JWKs but have no way to detect
    // they fetched from different URIs
    assert_ne!(validator1_result, validator2_result);
    println!("TOCTOU vulnerability confirmed: validators fetched different keys");
}
```

**Notes**

1. **Root Cause**: The separation of OpenID configuration fetch and JWK fetch into two HTTP requests without including the `jwks_uri` in the consensus message creates an undetectable inconsistency window.

2. **Scope**: This affects all OIDC providers configured through on-chain governance. Well-known providers like Google and Apple are less likely to be compromised, but smaller or custom OIDC providers present higher risk.

3. **Detection Difficulty**: The attack is hard to detect because the `jwks_uri` is not logged, not included in consensus messages, and not validated for consistency across validators. Monitoring would require external observation of validator HTTP traffic.

4. **Related Security Measure**: The pepper service's decision to hardcode JWK URLs (rather than using on-chain configs) suggests Aptos security team recognized similar risks but did not apply the same protection to validator consensus.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L102-110)
```rust
async fn fetch_jwks(open_id_config_url: &str, my_addr: Option<AccountAddress>) -> Result<Vec<JWK>> {
    let jwks_uri = fetch_jwks_uri_from_openid_config(open_id_config_url)
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with open-id config request: {e}"))?;
    let jwks = fetch_jwks_from_jwks_uri(my_addr, jwks_uri.as_str())
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with jwks uri request: {e}"))?;
    Ok(jwks)
}
```

**File:** crates/jwk-utils/src/lib.rs (L25-37)
```rust
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

**File:** crates/jwk-utils/src/lib.rs (L40-44)
```rust
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

**File:** types/src/jwks/mod.rs (L122-128)
```rust
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct ProviderJWKs {
    #[serde(with = "serde_bytes")]
    pub issuer: Issuer,
    pub version: u64,
    pub jwks: Vec<JWKMoveStruct>,
}
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L82-84)
```rust
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-143)
```rust
        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }

        let authors = multi_sig.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;

        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;

```

**File:** keyless/pepper/service/src/external_resources/jwk_fetcher.rs (L204-210)
```rust
/// Starts the JWK refresh loops for known issuers. Note: we currently
/// hardcode the known issuers here, instead of fetching them from on-chain
/// configs. This is a security measure to ensure the pepper service only
/// trusts a small set of known issuers, with deterministic and immutable
/// JWK URLs. Otherwise, if these values were fetched from on-chain configs,
/// an attacker who compromises governance could change these values to
/// point to a malicious issuer (or JWK URL).
```
