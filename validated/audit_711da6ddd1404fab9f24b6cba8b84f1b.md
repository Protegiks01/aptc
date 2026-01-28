# Audit Report

## Title
Race Condition in Per-Key JWK Consensus Causes Silent Discarding of Legitimate Updates

## Summary
When the `JWK_CONSENSUS_PER_KEY_MODE` feature flag is enabled, multiple JWK updates for the same issuer but different keys can be included in a single block. Due to sequential execution and issuer-level version checking, only the first update succeeds while subsequent updates fail the version check and are silently discarded, resulting in permanent loss of legitimate security updates.

## Finding Description

The vulnerability exists in the interaction between per-key consensus mode and version validation logic. When per-key mode is enabled, validators create independent quorum-certified updates for different keys of the same issuer using distinct topics in the validator transaction pool. [1](#0-0) 

The pool architecture allows multiple updates for the same issuer (with different key IDs) to coexist because they use different topics: [2](#0-1) 

When creating updates, all key-level updates for the same issuer use the current on-chain version as their `base_version`: [3](#0-2) 

During block execution, validator transactions are processed sequentially. Each update is converted to have `version = base_version + 1`: [4](#0-3) 

The first update succeeds and modifies the on-chain version. When the second update executes in the same block, it fails the version check because it loads the already-modified state: [5](#0-4) 

This triggers the Expected failure path, which returns a Discard status: [6](#0-5) 

The Move code also enforces this version check in per-key mode: [7](#0-6) 

After block execution, when the on-chain state update event is processed, `reset_with_on_chain_state` discards consensus states for keys where the version changed, causing the `vtxn_guard` to drop and permanently remove the failed transaction from the pool: [8](#0-7) 

The block proposal mechanism has no filtering to prevent multiple updates for the same issuer from being pulled together: [9](#0-8) 

**Attack Scenario:**
1. Current on-chain `ProviderJWKs` for issuer "google.com" has version 10
2. Validator node A certifies: `KeyLevelUpdate { issuer: "google.com", base_version: 10, kid: "key1", ... }` → `ProviderJWKs { version: 11 }`
3. Validator node B certifies: `KeyLevelUpdate { issuer: "google.com", base_version: 10, kid: "key2", ... }` → `ProviderJWKs { version: 11 }`
4. Both enter the pool with different topics and are included in the same block
5. Update for key1 executes first and succeeds, version becomes 11
6. Update for key2 fails version check (11 + 1 ≠ 11), gets discarded via `TransactionStatus::Discard(StatusCode::ABORTED)`
7. The key2 update is permanently lost

This breaks protocol integrity because the per-key consensus mechanism fails to achieve its design goal of allowing independent key updates.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria ("Significant protocol violations"):

1. **Authentication/Authorization Impact**: Legitimate JWK updates being discarded while potentially stale or malicious keys remain compromises OIDC-based authentication mechanisms
2. **Silent Data Loss**: Quorum-certified security updates are permanently discarded with no error or recovery mechanism
3. **Protocol Integrity Violation**: The per-key consensus feature is documented to enable independent key updates, but this bug makes multiple updates mutually exclusive within a block

The feature documentation indicates the design intent for independent consensus per key: [10](#0-9) 

The test suite comment confirms updates should be separate: [11](#0-10) 

While not Critical severity (no direct fund loss or network halt), this significantly impacts protocol security and authentication systems.

## Likelihood Explanation

**Likelihood: Medium to High** when per-key mode is enabled (enabled by default).

Factors increasing likelihood:
- No malicious intent required - this occurs between legitimate validators
- Happens whenever multiple validators independently observe different key updates for the same issuer within timing that allows both to reach the same block proposal
- More likely during JWK rotation events when providers update multiple keys
- The per-key mode is specifically designed to enable independent key updates, making this scenario the expected use case

## Recommendation

Implement one of the following solutions:

**Option 1: Block-level filtering** - Modify the payload pull mechanism to ensure only one JWK update per issuer is included in any single block, deferring others to subsequent blocks.

**Option 2: Issuer-level locking** - Track issuer versions during block execution and skip processing updates with stale base_versions instead of discarding them, allowing them to remain in the pool for the next block.

**Option 3: Batching mechanism** - When multiple key updates for the same issuer are available, batch them into a single transaction with proper version sequencing before block inclusion.

**Option 4: Version re-targeting** - Allow updates with stale base_versions to automatically re-target to the current on-chain version during execution, though this requires careful consideration of consensus implications.

The cleanest solution is Option 1, filtering at the block proposal level to ensure deterministic behavior while preserving the per-key consensus design.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Enable `JWK_CONSENSUS_PER_KEY_MODE` feature flag
2. Configure two validators to observe different keys of the same issuer simultaneously
3. Wait for both to create quorum-certified updates with the same base_version
4. Observe that when both transactions are included in a block, only the first succeeds and the second is silently discarded
5. Verify the discarded update never reappears in subsequent blocks

The existing test suite does not cover this scenario because it waits sufficient time between assertions to ensure updates occur in different blocks.

## Notes

This vulnerability affects the integrity of the JWK consensus mechanism which is critical for keyless authentication in Aptos. The silent nature of the failure (no error propagation to operators or validators) makes this particularly dangerous as legitimate security updates can be lost without detection. The issue arises from a mismatch between the per-key topic design (which allows parallel consensus) and the issuer-level version checking (which assumes sequential updates).

### Citations

**File:** types/src/validator_txn.rs (L60-63)
```rust
    JWK_CONSENSUS_PER_KEY_MODE {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
```

**File:** crates/validator-transaction-pool/src/lib.rs (L119-119)
```rust
    /// We allow only 1 txn per topic and this index helps find the old txn when adding a new one for the same topic.
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L138-143)
```rust
                        let update = KeyLevelUpdate {
                            issuer: issuer.clone(),
                            base_version: effectively_onchain.version,
                            kid: kid.clone(),
                            to_upsert: Some(y.clone()),
                        };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L244-254)
```rust
        self.states_by_key.retain(|(issuer, _), _| {
            new_onchain_jwks
                .get(issuer)
                .map(|jwks| jwks.version)
                .unwrap_or_default()
                == self
                    .onchain_jwks
                    .get(issuer)
                    .map(|jwks| jwks.version)
                    .unwrap_or_default()
        });
```

**File:** types/src/jwks/mod.rs (L342-358)
```rust
    pub fn try_as_issuer_level_repr(&self) -> anyhow::Result<ProviderJWKs> {
        let jwk_repr = self.to_upsert.clone().unwrap_or_else(|| {
            JWK::Unsupported(UnsupportedJWK {
                id: self.kid.clone(),
                payload: DELETE_COMMAND_INDICATOR.as_bytes().to_vec(),
            })
        });
        let version = self
            .base_version
            .checked_add(1)
            .context("KeyLevelUpdate::as_issuer_level_repr failed on version")?;
        Ok(ProviderJWKs {
            issuer: self.issuer.clone(),
            version,
            jwks: vec![JWKMoveStruct::from(jwk_repr)],
        })
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L78-88)
```rust
            Err(Expected(failure)) => {
                // Pretend we are inside Move, and expected failures are like Move aborts.
                debug!("Processing dkg transaction expected failure: {:?}", failure);
                Ok((
                    VMStatus::MoveAbort {
                        location: AbortLocation::Script,
                        code: failure as u64,
                        message: None,
                    },
                    VMOutput::empty_with_status(TransactionStatus::Discard(StatusCode::ABORTED)),
                ))
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-129)
```rust
        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L478-478)
```text
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

**File:** consensus/src/payload_client/mixed.rs (L65-79)
```rust
        let mut validator_txns = self
            .validator_txn_pool_client
            .pull(
                params.max_poll_time,
                min(
                    params.max_txns.count(),
                    self.validator_txn_config.per_block_limit_txn_count(),
                ),
                min(
                    params.max_txns.size_in_bytes(),
                    self.validator_txn_config.per_block_limit_total_bytes(),
                ),
                validator_txn_filter,
            )
            .await;
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L692-698)
```text
    /// If enabled, JWK consensus should run in per-key mode, where:
    /// - The consensus is for key-level updates
    ///   (e.g., "issuer A key 1 should be deleted", "issuer B key 2 should be upserted");
    /// - transaction type `ValidatorTransaction::ObservedJWKUpdate` is reused;
    /// - while a key-level update is mostly represented by a new type `KeyLevelUpdate` locally,
    ///   For simplicity, it is represented by type `ProviderJWKs` (used to represent issuer-level update)
    ///   in JWK Consensus messages, in validator transactions, and in Move.
```

**File:** testsuite/smoke-test/src/jwks/jwk_consensus_per_key.rs (L187-187)
```rust
                    version: 2, // In per-key mode, we can only consensus one key at a time, and need 2 txns here.
```
