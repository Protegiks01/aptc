# Audit Report

## Title
API Server Panic on Malformed JWK Conversion Can Crash Validator Nodes

## Summary
The API server's JWK conversion logic in `api/types/src/transaction.rs` contains an `.expect()` call that will panic if it encounters malformed JWKs when serving REST API responses about validator transactions. Since the API server runs embedded within the validator node process, this panic can crash the entire validator, violating the availability invariant. [1](#0-0) 

## Finding Description
When the REST API server responds to requests about validator transactions containing JWK updates, it converts the internal `ProviderJWKs` type to the API-friendly `ExportedProviderJWKs` type. During this conversion, each `JWKMoveStruct` is converted to a `JWK` using `try_from()`, followed by an `.expect()` call on line 825. [2](#0-1) 

The conversion chain is:
1. Client requests validator transaction details via REST API
2. API server fetches transaction from storage
3. For `ObservedJWKUpdate` transactions, the server converts `QuorumCertifiedUpdate` to `ExportedQuorumCertifiedUpdate` [3](#0-2) 

4. This triggers conversion of `ProviderJWKs` to `ExportedProviderJWKs`, which panics if JWK conversion fails

The underlying conversion logic itself uses proper error handling: [4](#0-3) [5](#0-4) 

However, the API layer wraps this in an `.expect()`, removing the error handling benefit.

The API server runs embedded within the validator node process: [6](#0-5) 

This means a panic in the API server can crash the entire validator node.

## Impact Explanation
**Severity: HIGH** per Aptos bug bounty criteria - "API crashes" and "Validator node slowdowns"

If malformed JWKs are stored on-chain (potentially through a consensus bug, Move framework vulnerability, or validator transaction processing flaw), any client requesting validator transaction details via the REST API will trigger this panic, causing:

1. **Validator Unavailability**: The validator node process crashes or hangs
2. **Network Degradation**: If multiple validators are affected, consensus liveness may be impacted
3. **DoS Vector**: An attacker can repeatedly query the API to keep validators offline
4. **Deterministic Crash**: All validators will crash when processing the same API request

While the validator transaction processing code attempts to validate JWKs before storage, defense-in-depth principles require the API layer to handle errors gracefully rather than panicking.

## Likelihood Explanation
**Likelihood: Low to Medium**

The attack requires malformed JWKs to first be stored on-chain. The validator transaction processing validates JWKs during storage: [7](#0-6) 

However, if a bug exists in:
- The Move framework's `upsert_into_observed_jwks` function
- The multi-signature verification logic
- The BCS deserialization layer
- Consensus transaction ordering

Then malformed JWKs could bypass validation and be stored on-chain, making this vulnerability exploitable.

## Recommendation
Replace the `.expect()` with proper error handling that logs the error and returns a graceful API error response:

```rust
impl From<ProviderJWKs> for ExportedProviderJWKs {
    fn from(value: ProviderJWKs) -> Self {
        let ProviderJWKs {
            issuer,
            version,
            jwks,
        } = value;
        Self {
            issuer: String::from_utf8(issuer).unwrap_or("non_utf8_issuer".to_string()),
            version,
            jwks: jwks.iter().filter_map(|on_chain_jwk| {
                match JWK::try_from(on_chain_jwk) {
                    Ok(jwk) => Some(jwk),
                    Err(e) => {
                        warn!("Failed to convert on-chain JWK to API format: {}", e);
                        None // Skip malformed JWKs instead of panicking
                    }
                }
            }).collect(),
        }
    }
}
```

Alternatively, implement `TryFrom` instead of `From` to propagate errors up the API stack.

## Proof of Concept

```rust
// Test demonstrating the panic
#[test]
#[should_panic(expected = "conversion from on-chain representation to human-friendly representation should work")]
fn test_api_conversion_panics_on_malformed_jwk() {
    use aptos_types::jwks::{ProviderJWKs, issuer_from_str};
    use aptos_types::jwks::jwk::JWKMoveStruct;
    use aptos_types::move_any::Any;
    use aptos_api_types::transaction::ExportedProviderJWKs;
    
    // Create a ProviderJWKs with a malformed JWKMoveStruct
    let malformed_jwk = JWKMoveStruct {
        variant: Any {
            type_name: "0x1::invalid::MalformedType".to_string(),
            data: vec![0xFF; 100], // Invalid BCS data
        }
    };
    
    let provider_jwks = ProviderJWKs {
        issuer: issuer_from_str("https://accounts.google.com"),
        version: 1,
        jwks: vec![malformed_jwk],
    };
    
    // This will panic due to the .expect() on line 825
    let _exported: ExportedProviderJWKs = provider_jwks.into();
}
```

**Notes:**
The direct `TryFrom<&JWKMoveStruct> for JWK` conversion logic is correctly implemented with proper error handling. However, the API layer's use of `.expect()` when converting for REST API responses creates a panic vulnerability that can crash validator nodes. This violates defense-in-depth principles and the availability invariant, especially given that the API server runs in the same process as the consensus engine.

### Citations

**File:** api/types/src/transaction.rs (L747-754)
```rust
            aptos_types::validator_txn::ValidatorTransaction::ObservedJWKUpdate(
                quorum_certified_update,
            ) => Self::ObservedJwkUpdate(JWKUpdateTransaction {
                info,
                events,
                timestamp: U64::from(timestamp),
                quorum_certified_update: quorum_certified_update.into(),
            }),
```

**File:** api/types/src/transaction.rs (L814-829)
```rust
impl From<ProviderJWKs> for ExportedProviderJWKs {
    fn from(value: ProviderJWKs) -> Self {
        let ProviderJWKs {
            issuer,
            version,
            jwks,
        } = value;
        Self {
            issuer: String::from_utf8(issuer).unwrap_or("non_utf8_issuer".to_string()),
            version,
            jwks: jwks.iter().map(|on_chain_jwk|{
                JWK::try_from(on_chain_jwk).expect("conversion from on-chain representation to human-friendly representation should work")
            }).collect(),
        }
    }
}
```

**File:** types/src/jwks/jwk/mod.rs (L102-122)
```rust
impl TryFrom<&JWKMoveStruct> for JWK {
    type Error = anyhow::Error;

    fn try_from(value: &JWKMoveStruct) -> Result<Self, Self::Error> {
        match value.variant.type_name.as_str() {
            RSA_JWK::MOVE_TYPE_NAME => {
                let rsa_jwk =
                    MoveAny::unpack(RSA_JWK::MOVE_TYPE_NAME, value.variant.clone()).map_err(|e|anyhow!("converting from jwk move struct to jwk failed with move any to rsa unpacking error: {e}"))?;
                Ok(Self::RSA(rsa_jwk))
            },
            UnsupportedJWK::MOVE_TYPE_NAME => {
                let unsupported_jwk =
                    MoveAny::unpack(UnsupportedJWK::MOVE_TYPE_NAME, value.variant.clone()).map_err(|e|anyhow!("converting from jwk move struct to jwk failed with move any to unsupported unpacking error: {e}"))?;
                Ok(Self::Unsupported(unsupported_jwk))
            },
            _ => Err(anyhow!(
                "converting from jwk move struct to jwk failed with unknown variant"
            )),
        }
    }
}
```

**File:** types/src/move_any.rs (L25-33)
```rust
    pub fn unpack<T: DeserializeOwned>(move_name: &str, x: Any) -> anyhow::Result<T> {
        let Any { type_name, data } = x;
        if type_name == move_name {
            let y = bcs::from_bytes::<T>(&data)?;
            Ok(y)
        } else {
            bail!("type mismatch")
        }
    }
```

**File:** docker/compose/aptos-node/validator.yaml (L1-50)
```yaml
base:
  role: "validator"
  data_dir: "/opt/aptos/data"
  waypoint:
    from_file: "/opt/aptos/genesis/waypoint.txt"

consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml

execution:
  genesis_file_location: "/opt/aptos/genesis/genesis.blob"

storage:
  rocksdb_configs:
    enable_storage_sharding: true

validator_network:
  discovery_method: "onchain"
  mutual_authentication: true
  identity:
    type: "from_file"
    path: /opt/aptos/genesis/validator-identity.yaml

full_node_networks:
- network_id:
    private: "vfn"
  listen_address: "/ip4/0.0.0.0/tcp/6181"
  identity:
    type: "from_config"
    key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
    peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"

api:
  enabled: true
  address: "0.0.0.0:8080"
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L100-143)
```rust
    fn process_jwk_update_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        update: jwks::QuorumCertifiedUpdate,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        // Load resources.
        let validator_set =
            ValidatorSet::fetch_config(resolver).ok_or(Expected(MissingResourceValidatorSet))?;
        let observed_jwks =
            ObservedJWKs::fetch_config(resolver).ok_or(Expected(MissingResourceObservedJWKs))?;

        let mut jwks_by_issuer: HashMap<Issuer, ProviderJWKs> =
            observed_jwks.into_providers_jwks().into();
        let issuer = update.update.issuer.clone();
        let on_chain = jwks_by_issuer
            .entry(issuer.clone())
            .or_insert_with(|| ProviderJWKs::new(issuer));
        let verifier = ValidatorVerifier::from(&validator_set);

        let QuorumCertifiedUpdate {
            update: observed,
            multi_sig,
        } = update;

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
