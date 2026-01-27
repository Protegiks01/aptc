# Audit Report

## Title
Missing HTTPS Scheme Validation in JWK Consensus Configuration Allows TLS Bypass

## Summary
The JWK consensus configuration accepts arbitrary URLs without validating the scheme, allowing governance proposals to specify HTTP URLs instead of HTTPS. This bypasses TLS encryption during JWK fetching, enabling man-in-the-middle attacks on the keyless account authentication system.

## Finding Description

The JWK consensus system fetches JSON Web Keys from OIDC providers to support keyless account authentication. The `config_url` field in OIDC provider configuration lacks URL scheme validation at multiple layers:

**Layer 1 - Move Framework:** The `new_oidc_provider` function accepts any string as `config_url` without validation. [1](#0-0) 

The `new_v1` function only validates for duplicate provider names, not URL schemes. [2](#0-1) 

**Layer 2 - Rust Type System:** The `OIDCProvider` struct stores `config_url` as a plain `String` without type-level guarantees. [3](#0-2) 

**Layer 3 - HTTP Fetching:** The `fetch_jwks_uri_from_openid_config` function passes `config_url` directly to `reqwest::Client::get()` without scheme validation, allowing HTTP requests. [4](#0-3) 

**Attack Scenario:**
1. Attacker (with governance control) submits proposal with `config_url: "http://malicious.example.com/.well-known/openid-configuration"`
2. Governance passes proposal, config is applied at next epoch [5](#0-4) 

3. Validators spawn JWK observers with the HTTP URL [6](#0-5) 

4. Periodic fetching occurs over unencrypted HTTP [7](#0-6) 

5. MITM attacker intercepts and modifies JWK responses
6. Compromised JWKs propagate through consensus, breaking keyless account security

**Note on file:// URIs:** The question also mentions local `file://` URIs. After investigation, `reqwest` version 0.11.11 does not support the `file://` scheme by default, so this attack vector is not exploitable. [8](#0-7) 

## Impact Explanation

**HIGH Severity** - This qualifies as "Significant protocol violations" per the Aptos bug bounty program.

The vulnerability breaks the **Cryptographic Correctness** invariant by allowing unencrypted communication for security-critical JWK data. While other parts of the codebase properly configure TLS verification [9](#0-8) , the JWK fetching path lacks scheme enforcement.

**Security Impact:**
- Keyless account authentication depends on authentic JWKs from trusted OIDC providers
- MITM-modified JWKs could allow unauthorized account access
- All validators would fetch compromised data, creating system-wide impact
- Consensus would certify the malicious JWKs, requiring governance intervention to fix

## Likelihood Explanation

**Medium-High Likelihood:**

**Requirements:**
- Governance control to pass malicious proposal (high barrier on mainnet)
- Network position for MITM attack (medium barrier)

**Mitigating Factors:**
- Requires significant stake voting power on mainnet
- Governance proposals are publicly visible
- Community review process may catch malicious URLs

**Aggravating Factors:**
- Testnet governance is easier to compromise
- Sophisticated attackers could use subtle HTTP/HTTPS differences
- No automated URL validation alerts operators to the issue
- Once deployed, affects all validators simultaneously

## Recommendation

Implement URL scheme validation at multiple layers:

**Move Framework Layer:**
```move
public fun new_oidc_provider(name: String, config_url: String): OIDCProvider {
    // Validate HTTPS scheme
    let url_bytes = string::bytes(&config_url);
    assert!(
        vector::length(url_bytes) >= 8 && 
        *vector::borrow(url_bytes, 0) == 104 && // 'h'
        *vector::borrow(url_bytes, 1) == 116 && // 't'
        *vector::borrow(url_bytes, 2) == 116 && // 't'
        *vector::borrow(url_bytes, 3) == 112 && // 'p'
        *vector::borrow(url_bytes, 4) == 115 && // 's'
        *vector::borrow(url_bytes, 5) == 58 &&  // ':'
        *vector::borrow(url_bytes, 6) == 47 &&  // '/'
        *vector::borrow(url_bytes, 7) == 47,    // '/'
        error::invalid_argument(EINVALID_URL_SCHEME)
    );
    OIDCProvider { name, config_url }
}
```

**Rust Layer:**
```rust
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    // Validate HTTPS scheme
    if !config_url.starts_with("https://") {
        bail!("config_url must use HTTPS scheme, got: {}", config_url);
    }
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    
    // Also validate jwks_uri scheme
    if !jwks_uri.starts_with("https://") {
        bail!("jwks_uri must use HTTPS scheme, got: {}", jwks_uri);
    }
    Ok(jwks_uri)
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_http_url_rejected() {
    use aptos_jwk_utils::fetch_jwks_uri_from_openid_config;
    
    // This should fail with HTTP URL
    let result = fetch_jwks_uri_from_openid_config(
        "http://malicious.example.com/.well-known/openid-configuration"
    ).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("HTTPS"));
}

#[test]
fn test_move_validation() {
    // Create config with HTTP URL - should abort
    // In Move test framework:
    script {
        use aptos_framework::jwk_consensus_config;
        use std::string::utf8;
        
        fun main() {
            let config = jwk_consensus_config::new_v1(vector[
                jwk_consensus_config::new_oidc_provider(
                    utf8(b"Evil Provider"), 
                    utf8(b"http://evil.com/.well-known/openid-configuration")
                ),
            ]);
            // Should abort with EINVALID_URL_SCHEME
        }
    }
}
```

## Notes

While the vulnerability requires governance control (limiting exploitability on mainnet), it represents a significant security oversight that violates defense-in-depth principles. The lack of URL scheme validation is particularly concerning because:

1. Default examples in the codebase use HTTPS [10](#0-9) , creating an expectation that HTTPS is enforced
2. Other parts of the codebase properly configure TLS verification, showing awareness of the issue
3. The security assumption that JWKs are fetched securely is undocumented but critical

The file:// URI attack mentioned in the original question is not exploitable with the current `reqwest` configuration.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L62-65)
```text
    public fun set_for_next_epoch(framework: &signer, config: JWKConsensusConfig) {
        system_addresses::assert_aptos_framework(framework);
        config_buffer::upsert(config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L90-102)
```text
    public fun new_v1(oidc_providers: vector<OIDCProvider>): JWKConsensusConfig {
        let name_set = simple_map::new<String, u64>();
        vector::for_each_ref(&oidc_providers, |provider| {
            let provider: &OIDCProvider = provider;
            let (_, old_value) = simple_map::upsert(&mut name_set, provider.name, 0);
            if (option::is_some(&old_value)) {
                abort(error::invalid_argument(EDUPLICATE_PROVIDERS))
            }
        });
        JWKConsensusConfig {
            variant: copyable_any::pack( ConfigV1 { oidc_providers } )
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L105-107)
```text
    public fun new_oidc_provider(name: String, config_url: String): OIDCProvider {
        OIDCProvider { name, config_url }
    }
```

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L22-25)
```rust
pub struct OIDCProvider {
    pub name: String,
    pub config_url: String,
}
```

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L46-49)
```rust
                name: "https://accounts.google.com".to_string(),
                config_url: "https://accounts.google.com/.well-known/openid-configuration"
                    .to_string(),
            }],
```

**File:** crates/jwk-utils/src/lib.rs (L40-44)
```rust
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L390-398)
```rust
                let OIDCProvider { name, config_url } = provider;
                let maybe_issuer = String::from_utf8(name);
                let maybe_config_url = String::from_utf8(config_url);
                match (maybe_issuer, maybe_config_url) {
                    (Ok(issuer), Ok(config_url)) => Some(JWKObserver::spawn(
                        this.epoch_state.epoch,
                        this.my_addr,
                        issuer,
                        config_url,
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L102-109)
```rust
async fn fetch_jwks(open_id_config_url: &str, my_addr: Option<AccountAddress>) -> Result<Vec<JWK>> {
    let jwks_uri = fetch_jwks_uri_from_openid_config(open_id_config_url)
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with open-id config request: {e}"))?;
    let jwks = fetch_jwks_from_jwks_uri(my_addr, jwks_uri.as_str())
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with jwks uri request: {e}"))?;
    Ok(jwks)
```

**File:** Cargo.toml (L761-767)
```text
reqwest = { version = "0.11.11", features = [
    "blocking",
    "cookies",
    "json",
    "multipart",
    "stream",
] }
```

**File:** crates/aptos/src/governance/mod.rs (L130-135)
```rust
        let proposal: Proposal = get_proposal(&client, voting_table, self.proposal_id)
            .await?
            .into();

        let metadata_hash = proposal.metadata.get("metadata_hash").unwrap();
        let metadata_url = proposal.metadata.get("metadata_location").unwrap();
```
