# Audit Report

## Title
Critical JWK Consensus Configuration Vulnerability Enabling Complete Keyless Authentication Bypass

## Summary
The `jwk_consensus_config_override` parameter at line 307 in `fetch_genesis_info()` accepts arbitrary OIDC provider configurations without validating that the `config_url` corresponds to the claimed issuer name. An attacker controlling the genesis layout file can substitute legitimate issuers (e.g., "https://accounts.google.com") with attacker-controlled URLs, causing validators to fetch and store malicious JWKs on-chain under trusted issuer names. This enables complete forgery of keyless authentication, allowing unauthorized access to any account using the compromised issuer.

## Finding Description

The vulnerability exists in the JWK consensus configuration initialization path, specifically in how OIDC providers are configured and validated during genesis.

**Vulnerable Code Flow:**

1. **Genesis Configuration Loading** - The layout file's `jwk_consensus_config_override` is read without validation: [1](#0-0) 

2. **OIDC Provider Structure** - Each provider contains a `name` (issuer) and `config_url` that are never validated to match: [2](#0-1) 

3. **JWK Observer Spawning** - Validators spawn observers using the unvalidated `config_url`: [3](#0-2) 

4. **Missing Issuer Validation** - The OpenID configuration's `issuer` field is fetched but never validated against the expected issuer: [4](#0-3) 

5. **Keyless Authentication** - During authentication, JWKs are fetched by issuer name from on-chain storage, trusting whatever validators stored: [5](#0-4) 

**Attack Scenario:**

An attacker with control over the genesis layout file (testnet, private deployment, or compromised genesis ceremony) sets:

```yaml
jwk_consensus_config_override:
  V1:
    oidc_providers:
      - name: "https://accounts.google.com"  # Legitimate issuer
        config_url: "https://attacker.com/.well-known/openid-configuration"  # Malicious URL
```

**Exploitation Path:**

1. Validators fetch OpenID configuration from `attacker.com`
2. Attacker's endpoint returns their own JWKs
3. Validators reach consensus and store attacker's JWKs on-chain under issuer "https://accounts.google.com"
4. Users create keyless accounts with `iss_val: "https://accounts.google.com"`
5. Attacker forges JWTs with `iss: "https://accounts.google.com"` signed with their private key
6. During validation, the on-chain JWK lookup returns attacker's public key
7. Signature verification passes - attacker gains unauthorized account access

The JWT claims validation only checks that `iss` matches `pk.iss_val`: [6](#0-5) 

This check cannot detect the substitution because both the JWT and the KeylessPublicKey use the legitimate issuer name - only the JWK itself has been poisoned.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Complete Authentication Bypass**: Attacker can impersonate any user of the compromised OIDC provider
2. **Loss of Funds**: Full control over victim accounts enables theft of all assets
3. **Consensus-Level Impact**: All validators store and accept the malicious JWKs, making this a network-wide compromise
4. **Persistent Compromise**: Once malicious JWKs are committed on-chain, they remain trusted until explicitly replaced through governance

The impact matches the "Loss of Funds (theft or minting)" category for Critical severity. Every keyless account using the compromised issuer becomes vulnerable to complete takeover.

## Likelihood Explanation

**Likelihood: Medium to High** depending on deployment context:

**High Likelihood Scenarios:**
- Test networks where genesis files may not receive security review
- Private enterprise deployments where operators may not understand the implications
- Development/staging environments handling real authentication flows
- Forked chains where genesis configuration might be attacker-influenced

**Medium Likelihood Scenarios:**
- Mainnet genesis (requires compromising the trusted ceremony, but code lacks defense-in-depth)
- Post-genesis governance updates (requires significant stake but is technically feasible)

The layout file can be loaded from: [7](#0-6) 

Making it potentially accessible to attackers in various deployment scenarios.

**Exploitation Complexity: Low** - Once genesis control is achieved, the attack is straightforward:
- No sophisticated cryptography required
- No race conditions or timing dependencies
- No complex state manipulation needed
- Attack succeeds deterministically

## Recommendation

Implement strict validation of OIDC provider configurations:

1. **Immediate Fix**: Add validation in `fetch_jwks_uri_from_openid_config`:

```rust
// In crates/jwk-utils/src/lib.rs
pub async fn fetch_jwks_uri_from_openid_config(
    config_url: &str,
    expected_issuer: &str,
) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { issuer, jwks_uri } = client.get(config_url)
        .send()
        .await?
        .json()
        .await?;
    
    // Validate that the returned issuer matches expectations
    if issuer != expected_issuer {
        return Err(anyhow::anyhow!(
            "Issuer mismatch: expected '{}' but OpenID config declared '{}'",
            expected_issuer,
            issuer
        ));
    }
    
    Ok(jwks_uri)
}
```

2. **Update call sites** to pass the expected issuer: [8](#0-7) 

3. **Add genesis validation** to verify OIDC provider names match well-known issuer formats
4. **Implement config_url allowlisting** for known legitimate OIDC providers in production configurations
5. **Add monitoring** to detect JWK updates that don't match expected issuers

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// This would be a Rust integration test in crates/aptos-jwk-consensus/tests/

#[tokio::test]
async fn test_malicious_jwk_consensus_config_attack() {
    // Step 1: Setup attacker's mock OIDC server
    let attacker_server = MockServer::start().await;
    let attacker_jwk = generate_test_rsa_keypair();
    
    Mock::given(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": "https://attacker.com",  // Attacker's actual issuer
            "jwks_uri": format!("{}/jwks", attacker_server.uri())
        })))
        .mount(&attacker_server)
        .await;
    
    Mock::given(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [attacker_jwk.to_jwk()]
        })))
        .mount(&attacker_server)
        .await;
    
    // Step 2: Create malicious genesis config
    let malicious_config = OnChainJWKConsensusConfig::V1(ConfigV1 {
        oidc_providers: vec![OIDCProvider {
            name: b"https://accounts.google.com".to_vec(),  // Claim to be Google
            config_url: format!("{}/.well-known/openid-configuration", attacker_server.uri()).into_bytes()
        }]
    });
    
    // Step 3: Initialize genesis with malicious config
    let genesis_config = GenesisConfiguration {
        jwk_consensus_config_override: Some(malicious_config),
        // ... other fields
    };
    
    // Step 4: Run JWK consensus
    // Validators will fetch JWKs from attacker's server
    // and store them on-chain under "https://accounts.google.com"
    
    // Step 5: Verify attacker can forge authentication
    let victim_account = create_keyless_account(
        "https://accounts.google.com",  // Legitimate issuer
        "victim@gmail.com"
    );
    
    // Attacker creates malicious JWT signed with their key
    let malicious_jwt = create_jwt(
        attacker_jwk.private_key,
        "https://accounts.google.com",  // Claim to be from Google
        "victim@gmail.com"
    );
    
    // Step 6: Attempt authentication - should succeed due to poisoned JWKs
    let result = validate_keyless_signature(
        &victim_account.public_key,
        &malicious_jwt
    );
    
    assert!(result.is_ok(), "Attack succeeded: forged authentication was accepted");
}
```

**Notes:**
- The actual genesis initialization code at line 307 provides no defense against this attack
- The Move module at `jwk_consensus_config.move` performs no issuer validation
- Post-genesis updates via governance proposal are equally vulnerable
- This represents a fundamental architectural security gap in the keyless authentication system

### Citations

**File:** crates/aptos/src/genesis/mod.rs (L307-307)
```rust
            jwk_consensus_config_override: layout.jwk_consensus_config_override.clone(),
```

**File:** crates/aptos-genesis/src/config.rs (L79-81)
```rust
    /// An optional JWK consensus config to use, instead of `default_for_genesis()`.
    #[serde(default)]
    pub jwk_consensus_config_override: Option<OnChainJWKConsensusConfig>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L108-134)
```rust
        this.jwk_observers = oidc_providers
            .unwrap_or_default()
            .into_provider_vec()
            .into_iter()
            .filter_map(|provider| {
                let OIDCProvider { name, config_url } = provider;
                let maybe_issuer = String::from_utf8(name);
                let maybe_config_url = String::from_utf8(config_url);
                match (maybe_issuer, maybe_config_url) {
                    (Ok(issuer), Ok(config_url)) => Some(JWKObserver::spawn(
                        this.epoch_state.epoch,
                        this.my_addr,
                        issuer,
                        config_url,
                        Duration::from_secs(10),
                        local_observation_tx.clone(),
                    )),
                    (maybe_issuer, maybe_config_url) => {
                        warn!(
                            "unable to spawn observer, issuer={:?}, config_url={:?}",
                            maybe_issuer, maybe_config_url
                        );
                        None
                    },
                }
            })
            .collect();
```

**File:** crates/jwk-utils/src/lib.rs (L40-44)
```rust
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L112-149)
```rust
fn get_jwk_for_authenticator(
    jwks: &AllProvidersJWKs,
    pk: &KeylessPublicKey,
    sig: &KeylessSignature,
) -> Result<JWK, VMStatus> {
    let jwt_header = sig
        .parse_jwt_header()
        .map_err(|_| invalid_signature!("Failed to parse JWT header"))?;

    let jwk_move_struct = jwks.get_jwk(&pk.iss_val, &jwt_header.kid).map_err(|_| {
        invalid_signature!(format!(
            "JWK for {} with KID {} was not found",
            pk.iss_val, jwt_header.kid
        ))
    })?;

    let jwk = JWK::try_from(jwk_move_struct)
        .map_err(|_| invalid_signature!("Could not unpack Any in JWK Move struct"))?;

    match &jwk {
        JWK::RSA(rsa_jwk) => {
            if rsa_jwk.alg != jwt_header.alg {
                return Err(invalid_signature!(format!(
                    "JWK alg ({}) does not match JWT header's alg ({})",
                    rsa_jwk.alg, jwt_header.alg
                )));
            }
        },
        JWK::Unsupported(jwk) => {
            return Err(invalid_signature!(format!(
                "JWK with KID {} and hex-encoded payload {} is not supported",
                jwt_header.kid,
                hex::encode(&jwk.payload)
            )))
        },
    }

    Ok(jwk)
```

**File:** types/src/keyless/openid_sig.rs (L80-84)
```rust
        ensure!(
            claims.oidc_claims.iss.eq(&pk.iss_val),
            "'iss' claim was supposed to match \"{}\"",
            pk.iss_val
        );
```

**File:** crates/aptos/src/genesis/git.rs (L110-128)
```rust
    pub fn get_client(self) -> CliTypedResult<Client> {
        if self.github_repository.is_none()
            && self.github_token_file.is_none()
            && self.local_repository_dir.is_some()
        {
            Ok(Client::local(self.local_repository_dir.unwrap()))
        } else if self.github_repository.is_some()
            && self.github_token_file.is_some()
            && self.local_repository_dir.is_none()
        {
            Client::github(
                self.github_repository.unwrap(),
                self.github_branch,
                self.github_token_file.unwrap(),
            )
        } else {
            Err(CliError::CommandArgumentError("Must provide either only --local-repository-dir or both --github-repository and --github-token-path".to_string()))
        }
    }
```

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
