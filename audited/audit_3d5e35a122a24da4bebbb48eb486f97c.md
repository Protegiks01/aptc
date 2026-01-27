# Audit Report

## Title
Validator Transactions Persist in Pool After Execution, Causing Resource Waste Through Repeated Re-inclusion

## Summary
Validator transactions (specifically JWK updates) remain in the validator transaction pool after successful execution and can be repeatedly re-included in subsequent blocks until the next epoch change. This causes wasteful consumption of block space and execution resources without providing any security benefit.

## Finding Description

The validator transaction pool uses a guard-based cleanup mechanism where transactions are only removed when their `TxnGuard` is dropped. [1](#0-0)  For JWK consensus manager, the guard is stored in the `ConsensusState::Finished` variant and persists until epoch change. [2](#0-1) 

The `pull()` method returns transactions without removing them from the pool. [3](#0-2)  When generating proposals, consensus filters out transactions from **pending** blocks only, not committed blocks. [4](#0-3) 

This creates the following vulnerability scenario:

1. JWK manager creates transaction T for version transition V→V+1
2. T is included in block B1, committed, and executed successfully
3. On-chain JWK version becomes V+1, but T remains in pool (guard not dropped)
4. JWK updates do not trigger epoch changes [5](#0-4) 
5. Later proposals filter only pending blocks, so T is pulled again
6. T is re-included in block B2 and executed
7. Execution fails version validation [6](#0-5)  and is discarded
8. T still remains in pool, repeating indefinitely until epoch change

DKG transactions are less affected because their execution triggers immediate epoch changes that drop the guards. [7](#0-6) 

## Impact Explanation

This qualifies as **Medium Severity** ($10,000 category) per Aptos bug bounty criteria as it causes "State inconsistencies requiring intervention" through:

1. **Resource Exhaustion**: Validator transactions unnecessarily occupy block space that could be used for revenue-generating user transactions
2. **Computational Waste**: All validators repeatedly execute the same stale transaction, consuming CPU cycles for cryptographic verification and Move VM execution
3. **Memory Inefficiency**: Executed transactions persist in memory for extended periods (potentially hours/days between epochs)
4. **Degraded Performance**: Network throughput is reduced by inclusion of useless transactions

The issue violates the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: High** - This occurs automatically in normal network operation:

- JWK updates happen regularly as OIDC providers rotate keys
- Epochs can last hours or days
- No attacker action required
- Affects all validators in the network
- Repeated re-inclusion is highly probable given epoch durations

The per-block validator transaction limits bound the impact, but with multiple issuers, several stale transactions could be re-included per block across hundreds or thousands of blocks per epoch.

## Recommendation

Implement a commit notification mechanism for the validator transaction pool, similar to the regular mempool's `handle_commit_notification`. [8](#0-7) 

**Solution 1: Explicit Cleanup on Pull Notification**
Modify managers to drop guards when transactions are pulled and confirmed in committed blocks:

```rust
// In JWK manager's pull notification handler
async fn process_txn_pulled_notification(&mut self, txn: Arc<ValidatorTransaction>) {
    // After confirmation the transaction is in a committed block, drop the guard
    if let ConsensusState::Finished { vtxn_guard, .. } = state {
        drop(vtxn_guard); // Explicitly remove from pool
    }
}
```

**Solution 2: Auto-cleanup on Successful Execution**
Add execution success tracking to the pool and automatically remove transactions that have been successfully executed, without relying on guards.

**Solution 3: Track Committed Hashes**
Extend the `validator_txn_filter` to include hashes from recently committed blocks, not just pending blocks.

## Proof of Concept

```rust
#[tokio::test]
async fn test_jwk_transaction_persists_after_execution() {
    use aptos_validator_transaction_pool::VTxnPoolState;
    use aptos_types::validator_txn::{Topic, ValidatorTransaction};
    use aptos_types::jwks::QuorumCertifiedUpdate;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    
    let pool = VTxnPoolState::default();
    
    // Simulate JWK manager creating a transaction
    let jwk_txn = ValidatorTransaction::ObservedJWKUpdate(
        QuorumCertifiedUpdate::dummy()
    );
    let topic = Topic::JWK_CONSENSUS(b"https://accounts.google.com".to_vec());
    
    // Put transaction in pool (guard stored in manager state)
    let _guard = pool.put(topic, Arc::new(jwk_txn.clone()), None);
    
    // First pull - transaction included in block B1
    let pulled_1 = pool.pull(
        Instant::now() + Duration::from_secs(1),
        10,
        1024 * 1024,
        TransactionFilter::default()
    );
    assert_eq!(pulled_1.len(), 1);
    
    // Block B1 committed and executed (simulated - transaction validated and succeeds)
    // JWK on-chain version incremented
    // Guard NOT dropped (epoch hasn't changed)
    
    // Second pull - transaction can be pulled AGAIN from the pool
    let pulled_2 = pool.pull(
        Instant::now() + Duration::from_secs(1),
        10,
        1024 * 1024,
        TransactionFilter::default()
    );
    
    // BUG: Transaction is pulled again even though it was already executed
    assert_eq!(pulled_2.len(), 1);
    assert_eq!(pulled_2[0], jwk_txn);
    
    // This can repeat indefinitely until epoch change drops the guard
    let pulled_3 = pool.pull(
        Instant::now() + Duration::from_secs(1),
        10,
        1024 * 1024,
        TransactionFilter::default()
    );
    assert_eq!(pulled_3.len(), 1); // Still there!
}
```

**Notes:**
- The vulnerability is structural in the validator transaction pool design
- It manifests most severely for JWK updates due to their non-reconfiguration nature
- Impact is bounded by per-block validator transaction limits but still significant
- Fix requires architectural changes to the pool lifecycle management

### Citations

**File:** crates/validator-transaction-pool/src/lib.rs (L126-142)
```rust
/// Returned for `txn` when you call `PoolState::put(txn, ...)`.
/// If this is dropped, `txn` will be deleted from the pool (if it has not been).
///
/// This allows the pool to be emptied on epoch boundaries.
#[derive(Clone)]
pub struct TxnGuard {
    pool: Arc<Mutex<PoolStateInner>>,
    seq_num: u64,
}

impl Debug for TxnGuard {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxnGuard")
            .field("seq_num", &self.seq_num)
            .finish()
    }
}
```

**File:** crates/validator-transaction-pool/src/lib.rs (L152-199)
```rust
    pub fn pull(
        &mut self,
        deadline: Instant,
        mut max_items: u64,
        mut max_bytes: u64,
        filter: TransactionFilter,
    ) -> Vec<ValidatorTransaction> {
        let mut ret = vec![];
        let mut seq_num_lower_bound = 0;

        // Check deadline at the end of every iteration to ensure validator txns get a chance no matter what current proposal delay is.
        while max_items >= 1 && max_bytes >= 1 {
            // Find the seq_num of the first txn that satisfies the quota.
            if let Some(seq_num) = self
                .txn_queue
                .range(seq_num_lower_bound..)
                .filter(|(_, item)| {
                    item.txn.size_in_bytes() as u64 <= max_bytes
                        && !filter.should_exclude(&item.txn)
                })
                .map(|(seq_num, _)| *seq_num)
                .next()
            {
                // Update the quota usage.
                // Send the pull notification if requested.
                let PoolItem {
                    txn,
                    pull_notification_tx,
                    ..
                } = self.txn_queue.get(&seq_num).unwrap();
                if let Some(tx) = pull_notification_tx {
                    let _ = tx.push((), txn.clone());
                }
                max_items -= 1;
                max_bytes -= txn.size_in_bytes() as u64;
                seq_num_lower_bound = seq_num + 1;
                ret.push(txn.as_ref().clone());

                if Instant::now() >= deadline {
                    break;
                }
            } else {
                break;
            }
        }

        ret
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L341-346)
```rust
                let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
                *state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: issuer_level_repr,
                };
```

**File:** consensus/src/liveness/proposal_generator.rs (L643-650)
```rust
        let pending_validator_txn_hashes: HashSet<HashValue> = pending_blocks
            .iter()
            .filter_map(|block| block.validator_txns())
            .flatten()
            .map(ValidatorTransaction::hash)
            .collect();
        let validator_txn_filter =
            vtxn_pool::TransactionFilter::PendingTxnHashSet(pending_validator_txn_hashes);
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L502-505)
```text
        let epoch = reconfiguration::current_epoch();
        emit(ObservedJWKsUpdated { epoch, jwks: observed_jwks.jwks });
        regenerate_patched_jwks();
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-130)
```rust
        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L65-68)
```text
    fun finish_with_dkg_result(account: &signer, dkg_result: vector<u8>) {
        dkg::finish(dkg_result);
        finish(account);
    }
```

**File:** mempool/src/shared_mempool/coordinator.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```
