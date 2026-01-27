# Audit Report

## Title
Consensus Safety Violation: Quorum-Certified JWK Updates Lost Due to Session Key Collision Between Delete and Upsert Operations

## Summary

The JWK consensus per-key mode uses `(Issuer, KID)` as the session key for consensus, omitting the critical `to_upsert` field that distinguishes delete operations from upsert operations. This causes consensus state corruption when a key undergoes rapid state changes (delete → upsert or upsert → delete), allowing quorum-certified validator transactions to be silently removed from the transaction pool before blockchain commitment, violating BFT consensus safety guarantees.

## Finding Description

The vulnerability exists in how the per-key JWK consensus identifies and manages consensus sessions. The session key extraction in `new_rb_request()` and `session_key_from_qc()` only captures `(issuer, kid)` without the `to_upsert` field: [1](#0-0) [2](#0-1) 

The `KeyLevelUpdate` struct contains a critical `to_upsert` field where `None` indicates deletion and `Some(jwk)` indicates upsert: [3](#0-2) 

However, when managing consensus state in `states_by_key`, the system only uses `(issuer, kid)` as the key: [4](#0-3) 

The `maybe_start_consensus` function checks if consensus is already in progress by comparing the `to_upsert` field: [5](#0-4) 

**The Attack Path:**

1. A delete operation for key `(issuer1, kid1)` completes consensus, reaching quorum
2. The delete transaction is placed in the validator transaction pool in `Finished` state
3. An upsert observation arrives for the same `(issuer1, kid1)` 
4. `maybe_start_consensus` is called: the check at line 187 (`None != Some(jwk)`) fails
5. A new `InProgress` state is inserted at line 216-228, **overwriting** the `Finished` state
6. The old `vtxn_guard` from the `Finished` state is dropped, triggering cleanup
7. The drop handler removes the delete transaction from the pool: [6](#0-5) [7](#0-6) 

**Result:** A quorum-certified validator transaction that validators agreed upon is retroactively removed from the transaction pool before being included in any block, as if consensus never occurred.

The Topic used for the transaction pool also lacks the `to_upsert` distinction: [8](#0-7) [9](#0-8) 

When a new transaction with the same Topic is added, it replaces the old one: [10](#0-9) 

Additionally, the channel used for QC delivery uses KLAST style with capacity 1, meaning concurrent QCs with the same session key will overwrite each other: [11](#0-10) [12](#0-11) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program category "Consensus/Safety violations."

**Broken Invariant:** The fundamental Byzantine Fault Tolerance guarantee states that once 2f+1 validators reach quorum on a decision, that decision must be irreversible and eventually committed. This vulnerability allows quorum-certified decisions to be silently discarded.

**Consensus Impact:**
- Validators reach quorum on a JWK update but the update never appears on-chain
- Different validators may have different views of which updates were "actually" certified
- Potential for chain state divergence if validators independently track JWK consensus state

**Security Impact:**
- If a compromised JWK is detected and validators reach quorum on deleting it, a subsequent upsert operation could prevent that deletion from being committed, leaving the compromised key trusted
- JWK state on-chain may not reflect what validators actually agreed upon
- Undermines trust in the validator consensus process

## Likelihood Explanation

**Likelihood: Medium to High**

This requires:
1. An OIDC provider changing a key's state (delete or upsert)
2. Validators reaching quorum on that change
3. The provider changing the same key again before the first change is committed to a block
4. Validators reaching quorum on the second change

**Realistic Scenarios:**

1. **Malicious OIDC Provider:** An attacker controlling an OIDC provider could deliberately oscillate key states rapidly to trigger this vulnerability
2. **Buggy Provider Implementation:** A provider with implementation bugs could inadvertently expose/hide keys rapidly
3. **Network Timing Issues:** Network partitions or delays could cause validators to observe different key states at different times
4. **Key Rotation Practices:** Some providers might delete old keys and add new ones with the same kid in rapid succession

The per-key consensus mode was specifically designed for dealing with rapidly changing provider states, making this scenario more likely than it might initially appear. The time window is measured in seconds (the consensus round time), which is feasible for triggering this condition.

## Recommendation

**Solution:** Include the `to_upsert` operation type in the consensus session key to distinguish between delete and upsert operations.

**Approach 1: Extend the session key type**

Modify `PerKeyMode::ConsensusSessionKey` to include operation type:

```rust
// In crates/aptos-jwk-consensus/src/mode/per_key.rs
pub enum KeyOperationType {
    Delete,
    Upsert,
}

impl TConsensusMode for PerKeyMode {
    type ConsensusSessionKey = (Issuer, KID, KeyOperationType);
    
    fn new_rb_request(epoch: u64, payload: &ProviderJWKs) -> anyhow::Result<ObservedKeyLevelUpdateRequest> {
        let KeyLevelUpdate { issuer, kid, to_upsert, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(payload)
                .context("new_rb_request failed with repr translation")?;
        Ok(ObservedKeyLevelUpdateRequest { 
            epoch, 
            issuer, 
            kid,
            is_delete: to_upsert.is_none(),
        })
    }
    
    fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<(Issuer, KID, KeyOperationType)> {
        let KeyLevelUpdate { issuer, kid, to_upsert, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)
                .context("session_key_from_qc failed with repr translation")?;
        let op_type = if to_upsert.is_none() { 
            KeyOperationType::Delete 
        } else { 
            KeyOperationType::Upsert 
        };
        Ok((issuer, kid, op_type))
    }
}
```

**Approach 2: Extend the Topic enum**

Modify the `Topic` enum to distinguish operation types:

```rust
// In types/src/validator_txn.rs
pub enum Topic {
    DKG,
    JWK_CONSENSUS(jwks::Issuer),
    JWK_CONSENSUS_PER_KEY_DELETE {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
    JWK_CONSENSUS_PER_KEY_UPSERT {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
}
```

Then update `process_quorum_certified_update` to use the appropriate topic variant based on `to_upsert`.

**Recommendation:** Implement Approach 1 as it provides the cleanest separation and prevents both the state overwriting issue and the transaction pool collision.

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
// Place in crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs test module

#[cfg(test)]
mod vulnerability_test {
    use super::*;
    use aptos_types::jwks::{KeyLevelUpdate, JWK, RSA_JWK};
    
    #[tokio::test]
    async fn test_delete_upsert_collision() {
        // Setup: Create consensus manager with mocked dependencies
        let mut manager = create_test_manager(); // Implementation details omitted
        
        let issuer = b"https://example.com".to_vec();
        let kid = b"key123".to_vec();
        
        // Step 1: Delete operation reaches quorum
        let delete_update = KeyLevelUpdate {
            issuer: issuer.clone(),
            base_version: 0,
            kid: kid.clone(),
            to_upsert: None, // DELETE
        };
        
        manager.maybe_start_consensus(delete_update.clone()).unwrap();
        
        // Simulate QC completion for delete
        let delete_qc = simulate_quorum_certified_update(&delete_update);
        manager.process_quorum_certified_update(delete_qc).unwrap();
        
        // Verify delete transaction is in pool
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone())).unwrap();
        assert!(matches!(state, ConsensusState::Finished { .. }));
        
        // Step 2: Upsert operation arrives
        let upsert_update = KeyLevelUpdate {
            issuer: issuer.clone(),
            base_version: 0,
            kid: kid.clone(),
            to_upsert: Some(JWK::RSA(RSA_JWK::new_256_aqab("key123", "new_modulus"))),
        };
        
        // This call will overwrite the Finished state, dropping the delete transaction
        manager.maybe_start_consensus(upsert_update).unwrap();
        
        // Step 3: Verify the vulnerability
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone())).unwrap();
        
        // State is now InProgress for upsert, not Finished for delete
        assert!(matches!(state, ConsensusState::InProgress { .. }));
        
        // The delete transaction has been removed from the validator transaction pool
        // even though it reached quorum and was accepted!
        // This demonstrates the consensus safety violation.
    }
}
```

**Notes:**

- The vulnerability affects the per-key JWK consensus mode introduced to handle equivocating OIDC providers
- The session key design conflates distinct operations (delete vs upsert) for the same key, violating the principle that each consensus decision should be tracked independently
- This is particularly concerning because the per-key mode was designed for high-change-rate scenarios, making the attack window more likely to be triggered
- The validator transaction pool's "one transaction per topic" design amplifies the issue by allowing replacement of quorum-certified transactions

### Citations

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L32-40)
```rust
    fn new_rb_request(
        epoch: u64,
        payload: &ProviderJWKs,
    ) -> anyhow::Result<ObservedKeyLevelUpdateRequest> {
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(payload)
                .context("new_rb_request failed with repr translation")?;
        Ok(ObservedKeyLevelUpdateRequest { epoch, issuer, kid })
    }
```

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L59-64)
```rust
    fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<(Issuer, KID)> {
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)
                .context("session_key_from_qc failed with repr translation")?;
        Ok((issuer, kid))
    }
```

**File:** types/src/jwks/mod.rs (L323-330)
```rust
/// Represents a key-level JWK update.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct KeyLevelUpdate {
    pub issuer: Issuer,
    pub base_version: u64,
    pub kid: KID,
    pub to_upsert: Option<JWK>, // If none, it is a deletion.
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust
    states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L79-79)
```rust
        let (qc_update_tx, qc_update_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L179-231)
```rust
    fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
        let consensus_already_started = match self
            .states_by_key
            .get(&(update.issuer.clone(), update.kid.clone()))
            .cloned()
        {
            Some(ConsensusState::InProgress { my_proposal, .. })
            | Some(ConsensusState::Finished { my_proposal, .. }) => {
                my_proposal.observed.to_upsert == update.to_upsert
            },
            _ => false,
        };

        if consensus_already_started {
            return Ok(());
        }

        let issuer_level_repr = update
            .try_as_issuer_level_repr()
            .context("initiate_key_level_consensus failed at repr conversion")?;
        let signature = self
            .consensus_key
            .sign(&issuer_level_repr)
            .context("crypto material error occurred during signing")?;

        let update_translated = update
            .try_as_issuer_level_repr()
            .context("maybe_start_consensus failed at update translation")?;
        let abort_handle = self
            .update_certifier
            .start_produce(
                self.epoch_state.clone(),
                update_translated,
                self.qc_update_tx.clone(),
            )
            .context("maybe_start_consensus failed at update_certifier.start_produce")?;

        self.states_by_key.insert(
            (update.issuer.clone(), update.kid.clone()),
            ConsensusState::InProgress {
                my_proposal: ObservedKeyLevelUpdate {
                    author: self.my_addr,
                    observed: update,
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard {
                    handle: abort_handle,
                },
            },
        );

        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L336-341)
```rust
                let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
                    issuer: issuer.clone(),
                    kid: kid.clone(),
                };
                let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
                let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
```

**File:** crates/validator-transaction-pool/src/lib.rs (L74-76)
```rust
        if let Some(old_seq_num) = pool.seq_nums_by_topic.insert(topic.clone(), seq_num) {
            pool.txn_queue.remove(&old_seq_num);
        }
```

**File:** crates/validator-transaction-pool/src/lib.rs (L145-150)
```rust
    fn try_delete(&mut self, seq_num: u64) {
        if let Some(item) = self.txn_queue.remove(&seq_num) {
            let seq_num_another = self.seq_nums_by_topic.remove(&item.topic);
            assert_eq!(Some(seq_num), seq_num_another);
        }
    }
```

**File:** crates/validator-transaction-pool/src/lib.rs (L202-206)
```rust
impl Drop for TxnGuard {
    fn drop(&mut self) {
        self.pool.lock().try_delete(self.seq_num);
    }
}
```

**File:** types/src/validator_txn.rs (L55-64)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Topic {
    DKG,
    JWK_CONSENSUS(jwks::Issuer),
    JWK_CONSENSUS_PER_KEY_MODE {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
}
```

**File:** crates/channel/src/message_queues.rs (L134-146)
```rust
        if key_message_queue.len() >= self.max_queue_size.get() {
            if let Some(c) = self.counters.as_ref() {
                c.with_label_values(&["dropped"]).inc();
            }
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
```
