# Audit Report

## Title
Epoch Inconsistency in Validator Cache Update Causes VFN Telemetry Service Denial of Service

## Summary

In `update_for_chain()`, when the validator peer set is empty but the VFN peer set is non-empty, the function updates `vfn_cache` with the new epoch before returning a `ValidatorSetEmpty` error, while leaving `validator_cache` unmodified. This creates an epoch mismatch between the two caches, causing authenticated VFNs to receive JWT tokens that fail subsequent validation, resulting in a denial of service for the telemetry service.

## Finding Description

The vulnerability exists in the cache update logic that violates atomicity guarantees. The `update_for_chain()` function processes validator and VFN peer sets independently: [1](#0-0) 

The error determination correctly identifies when validator_peers is empty, but the cache updates occur **before** the error is returned: [2](#0-1) [3](#0-2) 

When `has_validators` is false but `has_vfns` is true:
- `validator_cache` is NOT updated (retains old epoch or remains empty)
- `vfn_cache` IS updated with new epoch
- Function returns `ValidatorSetEmpty` error

This creates dangling VFN entries at the new epoch without corresponding validators.

**Authentication Flow Impact:**

When a VFN authenticates, it uses the `vfn_cache`: [4](#0-3) [5](#0-4) 

The VFN successfully authenticates and receives a JWT token with the **new epoch** from `vfn_cache`.

**JWT Validation Failure:**

However, JWT validation **always** checks the validators cache for epoch validation: [6](#0-5) [7](#0-6) 

This creates two failure scenarios:

1. **Empty validators cache**: If the chain_id doesn't exist in validators cache, line 60-63 returns `ExpiredAuthToken`
2. **Epoch mismatch**: If validators cache has an old epoch, line 72 comparison fails (new_epoch ≠ old_epoch), returning `ExpiredAuthToken`

**Invariant Violation:**

This breaks the fundamental invariant that Validator Full Nodes (VFNs) should only exist when their corresponding validators exist. The system maintains two authoritative sources of epoch information that can become desynchronized, violating state consistency requirements.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria - "API crashes, Validator node slowdowns, Significant protocol violations"

**Specific Impacts:**

1. **VFN Telemetry Service DoS**: VFNs can authenticate but cannot use any authenticated endpoints. They receive valid JWT tokens that immediately fail validation, making the telemetry service completely unusable for affected VFNs.

2. **Operational Blindness**: Validator operators lose telemetry visibility from their VFNs during critical periods like epoch transitions or validator set reconfigurations.

3. **Chain Availability Confusion**: The `chain_set()` method only checks validators cache, causing chains with VFN entries to appear unavailable: [8](#0-7) 

4. **State Consistency Violation**: Two caches maintaining the same logical state (active peer sets per chain) can diverge in epoch numbers, violating atomicity requirements for state updates.

## Likelihood Explanation

**High Likelihood** - This can occur naturally during:

1. **Epoch Transitions**: Timing windows where validator information is fetched but hasn't fully propagated
2. **Validator Set Reconfiguration**: Validators may temporarily have empty validator addresses while VFN addresses remain configured
3. **On-chain Data Inconsistencies**: Malformed validator configurations with missing validator network addresses but present VFN addresses
4. **Network Partitions**: REST API queries during network splits may return incomplete validator sets

The vulnerability requires no attacker action - it's triggered by normal operational conditions that can reasonably occur in a distributed blockchain system.

## Recommendation

Implement atomic cache updates to maintain consistency between `validator_cache` and `vfn_cache`. The caches should only be updated if **both** peer sets are non-empty, or handle partial updates by synchronizing epochs.

**Recommended Fix:**

```rust
async fn update_for_chain(
    &self,
    chain_name: &ChainCommonName,
    url: &str,
) -> Result<(), ValidatorCacheUpdateError> {
    // ... existing code to fetch peer_addrs ...

    let mut validator_cache = self.validators.write();
    let mut vfn_cache = self.validator_fullnodes.write();

    // ... existing code to build validator_peers and vfn_peers ...

    let validator_count = validator_peers.len();
    let vfn_count = vfn_peers.len();
    let has_validators = !validator_peers.is_empty();
    let has_vfns = !vfn_peers.is_empty();

    // Determine result FIRST, before any cache updates
    let result = if !has_validators && !has_vfns {
        Err(ValidatorCacheUpdateError::BothPeerSetEmpty)
    } else if !has_validators {
        Err(ValidatorCacheUpdateError::ValidatorSetEmpty)
    } else if !has_vfns {
        Err(ValidatorCacheUpdateError::VfnSetEmpty)
    } else {
        Ok(())
    };

    // ONLY update caches if BOTH are present (atomic update)
    // This ensures epoch consistency between caches
    if has_validators && has_vfns {
        let chain_id_str = chain_id.to_string();
        
        validator_cache.insert(chain_id, (state.epoch, validator_peers));
        VALIDATOR_CACHE_SIZE
            .with_label_values(&[&chain_id_str, ValidatorCachePeerType::Validator.as_str()])
            .set(validator_count as i64);

        vfn_cache.insert(chain_id, (state.epoch, vfn_peers));
        VALIDATOR_CACHE_SIZE
            .with_label_values(&[&chain_id_str, ValidatorCachePeerType::ValidatorFullnode.as_str()])
            .set(vfn_count as i64);

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        VALIDATOR_CACHE_LAST_UPDATE_TIMESTAMP
            .with_label_values(&[&chain_id_str])
            .set(now_unix as i64);
    }

    result
}
```

**Alternative Fix** (if partial updates are required):

Synchronize epochs by always updating both caches to the latest epoch, even if one peer set is empty:

```rust
// Always update both caches to maintain epoch consistency
validator_cache.insert(chain_id, (state.epoch, validator_peers));
vfn_cache.insert(chain_id, (state.epoch, vfn_peers));
```

Then handle empty peer sets at authentication time rather than cache update time.

## Proof of Concept

```rust
#[cfg(test)]
mod test_epoch_inconsistency {
    use super::*;
    use aptos_crypto::{
        bls12381::{PrivateKey, PublicKey},
        test_utils::KeyPair,
        Uniform,
    };
    use aptos_rest_client::aptos_api_types::*;
    use aptos_types::{
        chain_id::ChainId,
        network_address::NetworkAddress,
        on_chain_config::ValidatorSet,
        validator_config::ValidatorConfig,
        validator_info::ValidatorInfo,
        PeerId,
    };
    use httpmock::MockServer;
    use rand_core::OsRng;
    use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

    #[tokio::test]
    async fn test_vfn_cache_update_without_validators_causes_epoch_mismatch() {
        let mut rng = OsRng;
        let keypair = KeyPair::<PrivateKey, PublicKey>::generate(&mut rng);
        
        // Create validator info with ONLY VFN address, no validator address
        let validator_info = ValidatorInfo::new(
            PeerId::random(),
            10,
            ValidatorConfig::new(
                keypair.public_key,
                vec![0, 0], // Invalid validator address
                bcs::to_bytes(&vec![NetworkAddress::from_str(
                    "/dns/vfn.example.com/tcp/6182/noise-ik/0xea19ab47ed9191865f15d85d751ed0663205c0b2f0f465714b1947c023715973/handshake/0"
                ).unwrap()]).unwrap(),
                2,
            ),
        );
        let validator_set = ValidatorSet::new(vec![validator_info]);

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method("GET")
                .path("/v1/accounts/0000000000000000000000000000000000000000000000000000000000000001/resource/0x1::stake::ValidatorSet");
            then.status(200)
                .body(bcs::to_bytes(&validator_set).unwrap())
                .header(X_APTOS_CHAIN_ID, "25")
                .header(X_APTOS_EPOCH, "11") // NEW EPOCH
                .header(X_APTOS_LEDGER_VERSION, "100")
                .header(X_APTOS_LEDGER_OLDEST_VERSION, "2")
                .header(X_APTOS_BLOCK_HEIGHT, "50")
                .header(X_APTOS_OLDEST_BLOCK_HEIGHT, "10")
                .header(X_APTOS_LEDGER_TIMESTAMP, "100");
        });

        let validators_cache = Arc::new(RwLock::new(HashMap::new()));
        let vfn_cache = Arc::new(RwLock::new(HashMap::new()));

        // Simulate old state at epoch 10
        validators_cache.write().insert(ChainId::new(25), (10, HashMap::new()));

        let mut fullnodes = HashMap::new();
        fullnodes.insert("testing".into(), server.base_url());

        let updater = PeerSetCacheUpdater::new(
            validators_cache.clone(),
            vfn_cache.clone(),
            fullnodes,
            Duration::from_secs(10),
        );

        // Execute update - should return ValidatorSetEmpty error
        updater.update().await;

        // VULNERABILITY: validator_cache still at epoch 10
        let validator_epoch = validators_cache.read().get(&ChainId::new(25)).map(|(e, _)| *e);
        assert_eq!(validator_epoch, Some(10), "Validator cache should remain at old epoch");

        // VULNERABILITY: vfn_cache updated to epoch 11
        let vfn_epoch = vfn_cache.read().get(&ChainId::new(25)).map(|(e, _)| *e);
        assert_eq!(vfn_epoch, Some(11), "VFN cache was updated to new epoch");

        // VULNERABILITY DEMONSTRATED: Epoch mismatch between caches
        assert_ne!(
            validator_epoch,
            vfn_epoch,
            "VULNERABILITY: Epoch mismatch - VFNs at epoch 11, validators at epoch 10"
        );

        // VFN would authenticate with epoch 11 but JWT validation checks epoch 10
        // causing ExpiredAuthToken error on all subsequent API calls
    }
}
```

**Expected Behavior:** Both caches should be at the same epoch, or neither should be updated.

**Actual Behavior:** `vfn_cache` is at epoch 11 while `validator_cache` remains at epoch 10, causing JWT validation failures for VFNs.

### Citations

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L163-171)
```rust
        let result = if !has_validators && !has_vfns {
            Err(ValidatorCacheUpdateError::BothPeerSetEmpty)
        } else if !has_validators {
            Err(ValidatorCacheUpdateError::ValidatorSetEmpty)
        } else if !has_vfns {
            Err(ValidatorCacheUpdateError::VfnSetEmpty)
        } else {
            Ok(())
        };
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L175-182)
```rust
        if has_validators {
            validator_cache.insert(chain_id, (state.epoch, validator_peers));

            // Record cache size for validators
            VALIDATOR_CACHE_SIZE
                .with_label_values(&[&chain_id_str, ValidatorCachePeerType::Validator.as_str()])
                .set(validator_count as i64);
        }
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L189-199)
```rust
        if has_vfns {
            vfn_cache.insert(chain_id, (state.epoch, vfn_peers));

            // Record cache size for VFNs
            VALIDATOR_CACHE_SIZE
                .with_label_values(&[
                    &chain_id_str,
                    ValidatorCachePeerType::ValidatorFullnode.as_str(),
                ])
                .set(vfn_count as i64);
        }
```

**File:** crates/aptos-telemetry-service/src/auth.rs (L66-70)
```rust
    let cache = if body.role_type == RoleType::Validator {
        context.peers().validators()
    } else {
        context.peers().validator_fullnodes()
    };
```

**File:** crates/aptos-telemetry-service/src/auth.rs (L72-86)
```rust
    let (epoch, peer_role) = match cache.read().get(&body.chain_id) {
        Some((epoch, peer_set)) => {
            match peer_set.get(&body.peer_id) {
                Some(peer) => {
                    let remote_public_key = &remote_public_key;
                    if !peer.keys.contains(remote_public_key) {
                        warn!("peer found in peer set but public_key is not found. request body: {}, role_type: {}, peer_id: {}, received public_key: {}", body.chain_id, body.role_type, body.peer_id, remote_public_key);
                        return Err(reject::custom(ServiceError::forbidden(
                            ServiceErrorCode::AuthError(
                                AuthError::PeerPublicKeyNotFound,
                                body.chain_id,
                            ),
                        )));
                    }
                    Ok((*epoch, peer.role))
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L57-64)
```rust
    let current_epoch = match context.peers().validators().read().get(&claims.chain_id) {
        Some(info) => info.0,
        None => {
            return Err(reject::custom(ServiceError::unauthorized(
                JwtAuthError::ExpiredAuthToken.into(),
            )));
        },
    };
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L72-78)
```rust
    if claims.epoch == current_epoch && claims.exp > Utc::now().timestamp() as usize {
        Ok(claims)
    } else {
        Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )))
    }
```

**File:** crates/aptos-telemetry-service/src/context.rs (L340-342)
```rust
    pub fn chain_set(&self) -> HashSet<ChainId> {
        self.peers.validators.read().keys().cloned().collect()
    }
```
