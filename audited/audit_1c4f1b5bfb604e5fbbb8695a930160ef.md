# Audit Report

## Title
Missing Validation on Minimum OIDC Provider Count Enables Single Point of Failure in JWK Consensus

## Summary
The `new_v1()` function in the JWK consensus configuration allows governance to set zero or a single OIDC provider without validation. This weakens the security model by eliminating source diversity, enabling an external attacker who compromises the single provider to inject malicious JWKs that will be accepted by validator consensus, leading to keyless account takeover and theft of funds.

## Finding Description

The JWK (JSON Web Key) consensus system in Aptos enables keyless authentication where users authenticate via OIDC providers (Google, Facebook, etc.) instead of private keys. Validators fetch JWKs from configured OIDC providers and reach 2/3+ consensus on the observed keys, which are then used to validate keyless transactions.

The vulnerability exists in the configuration validation logic: [1](#0-0) 

The `new_v1()` function only validates against duplicate provider names but has **no minimum count validation**. This allows governance to configure:
- Zero providers: `new_v1(vector[])`
- Single provider: `new_v1(vector[single_provider])`

When the provider list is passed to the epoch manager, it spawns JWK observers: [2](#0-1) 

With only one provider, all validators observe the **same single source**. While the quorum requirement (2/3+ validator voting power) remains constant: [3](#0-2) 

The security model is fundamentally weakened because:
1. All validators fetch JWKs from the same endpoint via HTTP(S)
2. An external attacker who compromises that single provider (via MITM, DNS hijacking, or endpoint compromise) can serve malicious JWKs
3. All validators observe identical malicious data
4. Validators easily reach 2/3+ consensus on the malicious JWKs (all seeing the same data)
5. Malicious JWKs are committed on-chain as a validator transaction

The JWK fetching mechanism uses standard HTTPS without certificate pinning: [4](#0-3) 

Once malicious JWKs are on-chain, they are used to validate keyless transactions: [5](#0-4) 

An attacker with malicious JWKs can forge JWT signatures and impersonate any user with keyless authentication.

## Impact Explanation

**Severity: CRITICAL** (Loss of Funds)

This vulnerability enables:
- **Account Takeover**: Attacker forges JWT tokens validated against malicious JWKs
- **Theft of Funds**: Complete access to victim keyless accounts
- **Scale**: Affects all users relying on keyless authentication from the compromised provider

The attack path requires:
1. Governance reduces providers to 1 (could be legitimate operational decision, not malicious intent)
2. External attacker compromises the single OIDC provider's JWK endpoint
3. System accepts malicious JWKs through normal consensus process
4. Attacker steals funds from keyless accounts

This meets **Critical Severity** criteria: "Loss of Funds (theft or minting)" per the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

Prerequisites:
- Governance configures single provider (could happen for cost reduction, testing, or operational reasons)
- Attacker compromises that provider's endpoint (via MITM, DNS hijacking, or direct compromise)

The likelihood is elevated because:
- No technical barriers prevent single-provider configuration
- OIDC provider endpoints are external attack surfaces (not under Aptos control)
- No certificate pinning increases compromise vectors
- Consequences are severe (immediate funds theft capability)

With zero providers configured, the impact is different but still severe:
- JWK consensus stops running
- Stale keys remain on-chain indefinitely
- If provider rotates keys externally, keyless authentication breaks or uses compromised old keys

## Recommendation

Add minimum provider count validation in the `new_v1()` function:

```move
/// Construct a `JWKConsensusConfig` of variant `ConfigV1`.
///
/// Abort if the given provider list contains duplicated provider names.
/// Abort if the provider list contains fewer than minimum required providers.
public fun new_v1(oidc_providers: vector<OIDCProvider>): JWKConsensusConfig {
    // Enforce minimum of 2 providers for diversity
    assert!(vector::length(&oidc_providers) >= 2, error::invalid_argument(EINSUFFICIENT_PROVIDERS));
    
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

Add the new error constant:
```move
/// `ConfigV1` creation failed with insufficient providers.
const EINSUFFICIENT_PROVIDERS: u64 = 2;
```

Additionally, consider implementing certificate pinning or additional endpoint verification in the Rust fetching code to reduce MITM attack surface.

## Proof of Concept

```move
#[test(framework = @0x1)]
#[expected_failure(abort_code = 0x010002, location = aptos_framework::jwk_consensus_config)]
fun test_single_provider_rejected(framework: signer) {
    use std::string::utf8;
    use aptos_framework::jwk_consensus_config;
    
    // This should abort with EINSUFFICIENT_PROVIDERS
    let config = jwk_consensus_config::new_v1(vector[
        jwk_consensus_config::new_oidc_provider(
            utf8(b"https://accounts.google.com"), 
            utf8(b"https://accounts.google.com/.well-known/openid-configuration")
        ),
    ]);
}

#[test(framework = @0x1)]
#[expected_failure(abort_code = 0x010002, location = aptos_framework::jwk_consensus_config)]
fun test_empty_providers_rejected(framework: signer) {
    use aptos_framework::jwk_consensus_config;
    
    // This should abort with EINSUFFICIENT_PROVIDERS
    let config = jwk_consensus_config::new_v1(vector[]);
}

#[test(framework = @0x1)]
fun test_multiple_providers_accepted(framework: signer) {
    use std::string::utf8;
    use aptos_framework::jwk_consensus_config;
    
    // This should succeed with 2+ providers
    let config = jwk_consensus_config::new_v1(vector[
        jwk_consensus_config::new_oidc_provider(
            utf8(b"https://accounts.google.com"), 
            utf8(b"https://accounts.google.com/.well-known/openid-configuration")
        ),
        jwk_consensus_config::new_oidc_provider(
            utf8(b"https://www.facebook.com"), 
            utf8(b"https://www.facebook.com/.well-known/openid-configuration")
        ),
    ]);
}
```

## Notes

The core issue is that while the **quorum requirement** (2/3+ validator voting power) is not directly weakened by reducing providers, the **security assumption of source diversity** is eliminated. With multiple providers, an attacker must compromise multiple independent endpoints. With a single provider, the attacker has only one target, and all validators will observe and agree on the same malicious data, easily reaching consensus. This fundamentally breaks the intended security model of the JWK consensus system.

### Citations

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

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L134-137)
```rust
        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;
```

**File:** crates/jwk-utils/src/lib.rs (L25-44)
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

/// Given an Open ID configuration URL, fetch its JWK url.
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
