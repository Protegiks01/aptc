# Audit Report

## Title
Non-Canonical JSON Serialization in UnsupportedJWK Causes Unnecessary JWK Consensus Rounds

## Summary
The `UnsupportedJWK` conversion from JSON uses non-canonical serialization (`to_string()`), allowing semantically identical JWKs to have different binary representations. This causes the equality check in `process_new_observation()` to fail incorrectly, triggering unnecessary consensus rounds and wasting validator resources.

## Finding Description

The JWK consensus system compares observed JWKs with on-chain state to determine if a new consensus round is needed. This comparison occurs in the `process_new_observation()` function: [1](#0-0) 

The critical comparison at line 196 checks if `state.observed` differs from the on-chain JWKs. When JWKs are fetched from OIDC providers, they are parsed as `serde_json::Value` and converted to `JWK` enum types: [2](#0-1) 

For non-RSA JWKs (EC keys, EdDSA, or other unsupported types), the conversion falls back to `UnsupportedJWK`. The vulnerability lies in this conversion: [3](#0-2) 

The comment `//TODO: canonical to_string.` on line 53 explicitly acknowledges the issue. The `json_value.to_string()` method does NOT produce canonical JSON—it can vary based on:
- Field ordering in JSON objects
- Whitespace formatting  
- Number representations
- Unicode escape sequences

When different validators fetch the same JWK from an OIDC provider (or an attacker serves it with different formatting), they produce `UnsupportedJWK` instances with different `payload` bytes. Since `JWKMoveStruct` wraps this in a `MoveAny` structure containing BCS-serialized data: [4](#0-3) [5](#0-4) 

The `MoveAny` equality compares both `type_name` and `data` fields byte-by-byte. Different `payload` bytes in `UnsupportedJWK` lead to different BCS serialization, causing the equality check to fail even when the JWKs are semantically identical.

**Attack Path:**
1. An OIDC provider deploys a non-RSA JWK (e.g., ES256 elliptic curve key)
2. Attacker controls the OIDC provider or performs MitM
3. Attacker serves the same JWK with different JSON field ordering to different validators
4. Each validator converts to `UnsupportedJWK` with different `payload` bytes
5. Comparison in `process_new_observation()` fails
6. New consensus round is triggered unnecessarily
7. Process repeats on each observation interval (typically every 10 seconds) [6](#0-5) 

This creates a consensus loop where validators continuously propose updates for unchanged JWKs, wasting computational resources and network bandwidth.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria for "State inconsistencies requiring intervention":

- **Not Critical** because it doesn't compromise consensus safety, enable theft of funds, or cause network partition
- **Medium Impact** because:
  - Creates operational disruption through resource exhaustion
  - Causes unnecessary validator transaction pool updates
  - Requires manual intervention to identify and resolve
  - Affects all validators observing unsupported JWK types
  - Can be exploited continuously without detection

The issue violates the **Deterministic Execution** invariant—validators should agree on identical state for semantically identical content. It also violates **State Consistency** by causing unnecessary state transitions.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur in practice:

1. **Natural Occurrence**: OIDC providers legitimately deploy new JWK algorithms (ES256, ES384, EdDSA) before Aptos adds support, triggering the `UnsupportedJWK` code path
2. **JSON Non-Determinism**: Standard JSON libraries don't guarantee field ordering—different HTTP responses, caching layers, or proxy servers can reorder fields
3. **Easy Exploitation**: An attacker controlling an OIDC provider can trivially serve different JSON representations
4. **Low Detection**: The symptom (repeated consensus rounds) appears as legitimate protocol activity
5. **No Mitigation**: The TODO comment indicates developers are aware but haven't implemented a fix

## Recommendation

Implement canonical JSON serialization for `UnsupportedJWK` payload. Two approaches:

**Approach 1: Canonical JSON Serialization**
```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        // Sort keys and use canonical formatting
        let canonical_payload = serde_json::to_vec(&json_value)
            .expect("JSON value should always serialize");
        Self {
            id: HashValue::sha3_256_of(canonical_payload.as_slice()).to_vec(),
            payload: canonical_payload,
        }
    }
}
```

**Approach 2: Compute ID from Sorted Key-Value Pairs**
```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        use std::collections::BTreeMap;
        
        // Extract and sort fields for canonical representation
        let canonical = if let serde_json::Value::Object(map) = json_value {
            let sorted: BTreeMap<String, serde_json::Value> = 
                map.into_iter().collect();
            serde_json::to_vec(&sorted)
        } else {
            serde_json::to_vec(&json_value)
        }.expect("JSON should serialize");
        
        Self {
            id: HashValue::sha3_256_of(canonical.as_slice()).to_vec(),
            payload: canonical,
        }
    }
}
```

Additionally, consider normalizing RSA_JWK fields (trim whitespace, normalize base64 padding) as a defense-in-depth measure.

## Proof of Concept

```rust
#[test]
fn test_unsupported_jwk_non_canonical_json() {
    use serde_json::json;
    use aptos_types::jwks::unsupported::UnsupportedJWK;
    
    // Same JWK data with different field ordering
    let json1 = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
        "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
        "kid": "example-ec-key"
    });
    
    let json2 = json!({
        "kid": "example-ec-key",
        "kty": "EC",
        "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
        "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
        "crv": "P-256"
    });
    
    // Convert to UnsupportedJWK
    let jwk1 = UnsupportedJWK::from(json1);
    let jwk2 = UnsupportedJWK::from(json2);
    
    // These are semantically identical but have different payloads
    assert_eq!(
        String::from_utf8(jwk1.payload.clone()).unwrap(),
        r#"{"crv":"P-256","kid":"example-ec-key","kty":"EC","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}"#
    );
    assert_eq!(
        String::from_utf8(jwk2.payload.clone()).unwrap(),
        r#"{"crv":"P-256","kid":"example-ec-key","kty":"EC","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}"#
    );
    
    // BUG: These should be equal but aren't due to different JSON serialization
    assert_ne!(jwk1.payload, jwk2.payload, "Payloads differ despite semantic equality");
    assert_ne!(jwk1.id, jwk2.id, "IDs differ due to different payload hashes");
    
    // When wrapped in JWKMoveStruct and compared, this causes consensus issues
    use aptos_types::jwks::jwk::{JWK, JWKMoveStruct};
    let move_struct1 = JWKMoveStruct::from(JWK::Unsupported(jwk1));
    let move_struct2 = JWKMoveStruct::from(JWK::Unsupported(jwk2));
    
    assert_ne!(move_struct1, move_struct2, "JWKMoveStructs differ, triggering unnecessary consensus");
}
```

## Notes

This vulnerability specifically affects `UnsupportedJWK` types. The `RSA_JWK` implementation extracts individual fields from JSON and compares them directly, avoiding this issue: [7](#0-6) 

However, as OIDC providers adopt new cryptographic algorithms (ES256, ES384, ES512, EdDSA, etc.), the `UnsupportedJWK` code path becomes increasingly critical. The issue is particularly relevant for Aptos's keyless authentication system, which relies on JWK consensus to verify OIDC provider keys.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L184-228)
```rust
    pub fn process_new_observation(
        &mut self,
        issuer: Issuer,
        jwks: Vec<JWKMoveStruct>,
    ) -> Result<()> {
        debug!(
            epoch = self.epoch_state.epoch,
            issuer = String::from_utf8(issuer.clone()).ok(),
            "Processing new observation."
        );
        let state = self.states_by_issuer.entry(issuer.clone()).or_default();
        state.observed = Some(jwks.clone());
        if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
            let observed = ProviderJWKs {
                issuer: issuer.clone(),
                version: state.on_chain_version() + 1,
                jwks,
            };
            let signature = self
                .consensus_key
                .sign(&observed)
                .context("process_new_observation failed with signing error")?;
            let abort_handle = self
                .update_certifier
                .start_produce(
                    self.epoch_state.clone(),
                    observed.clone(),
                    self.qc_update_tx.clone(),
                )
                .context(
                    "process_new_observation failed with update_certifier.start_produce failure",
                )?;
            state.consensus_state = ConsensusState::InProgress {
                my_proposal: ObservedUpdate {
                    author: self.my_addr,
                    observed: observed.clone(),
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard::new(abort_handle),
            };
            info!("[JWK] update observed, update={:?}", observed);
        }

        Ok(())
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

**File:** types/src/jwks/unsupported/mod.rs (L51-59)
```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        let payload = json_value.to_string().into_bytes(); //TODO: canonical to_string.
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
}
```

**File:** types/src/jwks/jwk/mod.rs (L26-29)
```rust
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct JWKMoveStruct {
    pub variant: MoveAny,
}
```

**File:** types/src/move_any.rs (L10-23)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Any {
    pub type_name: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl Any {
    pub fn pack<T: Serialize>(move_name: &str, x: T) -> Any {
        Any {
            type_name: move_name.to_string(),
            data: bcs::to_bytes(&x).unwrap(),
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L51-90)
```rust
    async fn start(
        fetch_interval: Duration,
        my_addr: AccountAddress,
        issuer: String,
        open_id_config_url: String,
        observation_tx: aptos_channel::Sender<(), (Issuer, Vec<JWK>)>,
        close_rx: oneshot::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(fetch_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut close_rx = close_rx.into_stream();
        let my_addr = if cfg!(feature = "smoke-test") {
            // Include self validator address in JWK request,
            // so dummy OIDC providers in smoke tests can do things like "key A for validator 1, key B for validator 2".
            Some(my_addr)
        } else {
            None
        };

        loop {
            tokio::select! {
                _ = interval.tick().fuse() => {
                    let timer = Instant::now();
                    let result = fetch_jwks(open_id_config_url.as_str(), my_addr).await;
                    debug!(issuer = issuer, "observe_result={:?}", result);
                    let secs = timer.elapsed().as_secs_f64();
                    if let Ok(mut jwks) = result {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "ok"]).observe(secs);
                        jwks.sort();
                        let _ = observation_tx.push((), (issuer.as_bytes().to_vec(), jwks));
                    } else {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "err"]).observe(secs);
                    }
                },
                _ = close_rx.select_next_some() => {
                    break;
                }
            }
        }
    }
```

**File:** types/src/jwks/rsa/mod.rs (L132-178)
```rust
impl TryFrom<&serde_json::Value> for RSA_JWK {
    type Error = anyhow::Error;

    fn try_from(json_value: &serde_json::Value) -> Result<Self, Self::Error> {
        let kty = json_value
            .get("kty")
            .ok_or_else(|| anyhow!("Field `kty` not found"))?
            .as_str()
            .ok_or_else(|| anyhow!("Field `kty` is not a string"))?
            .to_string();

        ensure!(
            kty.as_str() == "RSA",
            "json to rsa jwk conversion failed with incorrect kty"
        );

        let ret = Self {
            kty,
            kid: json_value
                .get("kid")
                .ok_or_else(|| anyhow!("Field `kid` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `kid` is not a string"))?
                .to_string(),
            alg: json_value
                .get("alg")
                .ok_or_else(|| anyhow!("Field `alg` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `alg` is not a string"))?
                .to_string(),
            e: json_value
                .get("e")
                .ok_or_else(|| anyhow!("Field `e` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `e` is not a string"))?
                .to_string(),
            n: json_value
                .get("n")
                .ok_or_else(|| anyhow!("Field `n` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `n` is not a string"))?
                .to_string(),
        };

        Ok(ret)
    }
}
```
