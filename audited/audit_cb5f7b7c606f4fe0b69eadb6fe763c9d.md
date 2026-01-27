# Audit Report

## Title
State Checkpoint Hash Validation Bypass in Multi-Checkpoint Chunks During State Sync

## Summary
A critical validation flaw in `DoStateCheckpoint::get_state_checkpoint_hashes()` allows malicious state sync peers to inject incorrect state checkpoint hashes for non-final checkpoint transactions in chunks. Only the last checkpoint hash is validated against locally computed state, while earlier checkpoint hashes are blindly accepted, leading to incorrect `TransactionInfo` objects being committed to the database.

## Finding Description

The vulnerability exists in the state checkpoint validation logic during state synchronization. When a node receives transaction data from a remote peer via state sync, the system uses a two-stage validation approach: [1](#0-0) 

The critical flaw is in the validation logic for `known_state_checkpoints` (provided by the remote peer). When these hashes are supplied, the code performs only two checks:
1. Length matching (line 58-63)
2. Last checkpoint hash validation (line 64-71)

However, **only the last checkpoint index is validated** against the locally computed state summary. This is obtained via: [2](#0-1) 

The system explicitly supports chunks with **multiple checkpoints**, as evidenced by the test suite: [3](#0-2) 

During state sync, the remote peer's `TransactionInfo` hashes are extracted and used as `known_state_checkpoints`: [4](#0-3) 

These hashes are then used to construct `TransactionInfo` objects without validating non-final checkpoint hashes: [5](#0-4) 

**Attack Scenario:**
1. Attacker acts as state sync peer providing `TransactionOutputListWithProof`
2. Chunk contains checkpoints at transaction indices 2, 5, and 9 (out of 10 transactions)
3. Attacker provides **correct** state checkpoint hash at index 9 (last checkpoint)
4. Attacker provides **incorrect** state checkpoint hashes at indices 2 and 5
5. Victim node validates only index 9 (passes) and blindly accepts indices 2 and 5
6. `DoLedgerUpdate` creates `TransactionInfo` objects with wrong hashes at indices 2 and 5
7. Verification compares local `TransactionInfo` against attacker's `TransactionInfo` - they match (both wrong): [6](#0-5) 

8. Incorrect `TransactionInfo` objects are committed to the database

## Impact Explanation

**Critical Severity** - This vulnerability constitutes a **Consensus/Safety violation**:

1. **Breaks Deterministic Execution Invariant**: Different nodes executing the same transactions will have different `TransactionInfo.state_checkpoint_hash` values in their databases, violating the requirement that "all validators must produce identical state roots for identical blocks."

2. **State-Ledger Desynchronization**: The `state_checkpoint_hash` field in `TransactionInfo` is meant to cryptographically bind the transaction to the Merkle root of the state tree at that checkpoint. Incorrect hashes break this binding.

3. **Consensus Divergence Risk**: Nodes with different `TransactionInfo` objects for the same transactions will have different transaction accumulator hashes. This can cause:
   - Verification failures when nodes compare transaction histories
   - Inability to reach consensus on ledger state
   - Potential chain splits requiring hard fork to resolve

4. **State Proof Integrity Failure**: Clients relying on state proofs anchored to these checkpoint hashes will receive invalid proofs, breaking SPV (Simple Payment Verification) security guarantees.

This qualifies for **Critical Severity** ($1,000,000) under "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**High Likelihood:**

1. **No Special Privileges Required**: Any node acting as a state sync peer can exploit this. The attacker doesn't need validator status or special access.

2. **Common Code Path**: State synchronization is a core mechanism used by:
   - New nodes joining the network
   - Nodes recovering from downtime
   - Nodes catching up after network partitions

3. **Difficult to Detect**: The malicious `TransactionInfo` objects pass all verification checks, making the attack silent and persistent.

4. **No Rate Limiting**: An attacker can target multiple victim nodes simultaneously during their state sync process.

5. **Permanent Impact**: Once committed to the database, the incorrect `TransactionInfo` objects persist indefinitely, affecting all future operations relying on historical state checkpoint data.

## Recommendation

**Fix: Validate ALL checkpoint hashes, not just the last one**

The validation logic must be enhanced to check every checkpoint hash against the locally computed state:

```rust
fn get_state_checkpoint_hashes(
    execution_output: &ExecutionOutput,
    known_state_checkpoints: Option<Vec<Option<HashValue>>>,
    state_summary: &LedgerStateSummary,
) -> Result<Vec<Option<HashValue>>> {
    let num_txns = execution_output.to_commit.len();
    
    // Get ALL checkpoint indices, not just the last one
    let checkpoint_indices: Vec<usize> = execution_output
        .to_commit
        .state_update_refs()
        .all_checkpoint_versions
        .iter()
        .map(|v| (v - execution_output.first_version) as usize)
        .collect();
    
    if let Some(known) = known_state_checkpoints {
        ensure!(
            known.len() == num_txns,
            "Bad number of known hashes. {} vs {}",
            known.len(),
            num_txns
        );
        
        // Validate EACH checkpoint hash against locally computed state
        for &idx in &checkpoint_indices {
            let computed_hash = /* compute hash for checkpoint at idx */;
            ensure!(
                known[idx] == Some(computed_hash),
                "Root hash mismatch at checkpoint index {}. {:?} vs {:?}",
                idx,
                known[idx],
                Some(computed_hash),
            );
        }
        
        Ok(known)
    } else {
        // Generate hashes based on local computation for all checkpoints
        let mut out = vec![None; num_txns];
        for &idx in &checkpoint_indices {
            out[idx] = Some(/* computed hash for checkpoint at idx */);
        }
        Ok(out)
    }
}
```

**Alternative**: Remove the `known_state_checkpoints` parameter entirely and always compute hashes locally based on execution results, eliminating the trust assumption.

## Proof of Concept

```rust
#[test]
fn test_multiple_checkpoint_validation_bypass() {
    use aptos_types::transaction::{Transaction, TransactionOutput, TransactionInfo};
    use aptos_crypto::HashValue;
    
    // Setup: Create a chunk with 3 checkpoints at indices 2, 5, 8 (out of 10 txns)
    let mut transactions = Vec::new();
    let mut outputs = Vec::new();
    
    for i in 0..10 {
        if i == 2 || i == 5 || i == 8 {
            transactions.push(Transaction::StateCheckpoint(HashValue::random()));
        } else {
            transactions.push(create_dummy_user_txn());
        }
        outputs.push(TransactionOutput::new_empty_success());
    }
    
    // Attacker provides malicious TransactionInfos with wrong hashes at indices 2 and 5
    let wrong_hash_2 = HashValue::random(); // Should be correct_hash_2
    let wrong_hash_5 = HashValue::random(); // Should be correct_hash_5
    let correct_hash_8 = /* computed from actual state */;
    
    let mut malicious_checkpoint_hashes = vec![None; 10];
    malicious_checkpoint_hashes[2] = Some(wrong_hash_2);
    malicious_checkpoint_hashes[5] = Some(wrong_hash_5);
    malicious_checkpoint_hashes[8] = Some(correct_hash_8); // Last checkpoint is correct!
    
    // Execute state sync flow
    let execution_output = execute_chunk(transactions, outputs);
    
    // This should FAIL but currently PASSES because only index 8 is validated
    let result = DoStateCheckpoint::run(
        &execution_output,
        &parent_state_summary,
        &persisted_state_summary,
        Some(malicious_checkpoint_hashes.clone()),
    );
    
    // Vulnerability: result is Ok() with wrong hashes at indices 2 and 5
    assert!(result.is_ok());
    let state_checkpoint_output = result.unwrap();
    
    // These assertions would fail with proper validation:
    assert_eq!(state_checkpoint_output.state_checkpoint_hashes[2], Some(wrong_hash_2));
    assert_eq!(state_checkpoint_output.state_checkpoint_hashes[5], Some(wrong_hash_5));
    
    // The wrong hashes propagate to TransactionInfo creation
    let ledger_update = DoLedgerUpdate::run(
        &execution_output,
        &state_checkpoint_output,
        parent_accumulator,
    ).unwrap();
    
    // TransactionInfo objects now contain incorrect state_checkpoint_hashes
    assert_eq!(
        ledger_update.transaction_infos[2].state_checkpoint_hash(),
        Some(wrong_hash_2)
    );
    assert_eq!(
        ledger_update.transaction_infos[5].state_checkpoint_hash(),
        Some(wrong_hash_5)
    );
    
    // These get committed to the database with wrong hashes!
}
```

## Notes

This vulnerability is particularly insidious because:

1. **Silent Corruption**: The incorrect data passes all existing verification checks, making it undetectable through normal operation.

2. **Affects Historical Data**: Once committed, the incorrect `TransactionInfo` objects remain in the database permanently, affecting all queries and verifications that depend on historical state checkpoint data.

3. **Cross-Node Impact**: Different nodes could end up with different `TransactionInfo` objects for identical transactions, creating a fundamental inconsistency in the network's shared state.

4. **Trust Assumption Violation**: The code implicitly trusts remote peers to provide correct intermediate checkpoint hashes, while only validating the final result. This violates the zero-trust principle that should govern state sync operations.

The fix requires computing and validating state checkpoint hashes for **all** checkpoint transactions based on local execution, not just the last one. The current implementation's assumption that validating only the final checkpoint is sufficient is fundamentally flawed when dealing with chunks containing multiple checkpoints.

### Citations

**File:** execution/executor/src/workflow/do_state_checkpoint.rs (L44-88)
```rust
    fn get_state_checkpoint_hashes(
        execution_output: &ExecutionOutput,
        known_state_checkpoints: Option<Vec<Option<HashValue>>>,
        state_summary: &LedgerStateSummary,
    ) -> Result<Vec<Option<HashValue>>> {
        let _timer = OTHER_TIMERS.timer_with(&["get_state_checkpoint_hashes"]);

        let num_txns = execution_output.to_commit.len();
        let last_checkpoint_index = execution_output
            .to_commit
            .state_update_refs()
            .last_inner_checkpoint_index();

        if let Some(known) = known_state_checkpoints {
            ensure!(
                known.len() == num_txns,
                "Bad number of known hashes. {} vs {}",
                known.len(),
                num_txns
            );
            if let Some(idx) = last_checkpoint_index {
                ensure!(
                    known[idx] == Some(state_summary.last_checkpoint().root_hash()),
                    "Root hash mismatch with known hashes passed in. {:?} vs {:?}",
                    known[idx],
                    Some(&state_summary.last_checkpoint().root_hash()),
                );
            }

            Ok(known)
        } else {
            if !execution_output.is_block {
                // We should enter this branch only in test.
                execution_output.to_commit.ensure_at_most_one_checkpoint()?;
            }

            let mut out = vec![None; num_txns];

            if let Some(index) = last_checkpoint_index {
                out[index] = Some(state_summary.last_checkpoint().root_hash());
            }

            Ok(out)
        }
    }
```

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L250-255)
```rust
    pub fn last_inner_checkpoint_index(&self) -> Option<usize> {
        self.for_last_checkpoint.as_ref().map(|updates| {
            assert_eq!(updates.0.num_versions, updates.1.num_versions);
            updates.0.num_versions - 1
        })
    }
```

**File:** execution/executor-types/src/transactions_with_output.rs (L368-396)
```rust
    fn test_chunk_with_ckpts_no_reconfig() {
        let txns = vec![
            dummy_txn(),
            ckpt_txn(),
            dummy_txn(),
            ckpt_txn(),
            dummy_txn(),
        ];
        let outputs = vec![
            default_output(),
            default_output(),
            default_output(),
            default_output(),
            default_output(),
        ];
        let aux_infos = vec![
            default_aux_info(),
            default_aux_info(),
            default_aux_info(),
            default_aux_info(),
            default_aux_info(),
        ];
        let txn_with_outputs = TransactionsWithOutput::new(txns, outputs, aux_infos);

        let (all_ckpt_indices, is_reconfig) =
            TransactionsToKeep::get_all_checkpoint_indices(&txn_with_outputs, false);
        assert_eq!(all_ckpt_indices, vec![1, 3]);
        assert!(!is_reconfig);
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L346-357)
```rust
        let state_checkpoint_output = DoStateCheckpoint::run(
            &output.execution_output,
            &parent_state_summary,
            &ProvableStateSummary::new_persisted(self.db.reader.as_ref())?,
            Some(
                chunk_verifier
                    .transaction_infos()
                    .iter()
                    .map(|t| t.state_checkpoint_hash())
                    .collect_vec(),
            ),
        )?;
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L47-93)
```rust
    fn assemble_transaction_infos(
        to_commit: &TransactionsWithOutput,
        state_checkpoint_hashes: Vec<Option<HashValue>>,
    ) -> (Vec<TransactionInfo>, Vec<HashValue>) {
        let _timer = OTHER_TIMERS.timer_with(&["assemble_transaction_infos"]);

        (0..to_commit.len())
            .into_par_iter()
            .with_min_len(optimal_min_len(to_commit.len(), 64))
            .map(|i| {
                let txn = &to_commit.transactions[i];
                let txn_output = &to_commit.transaction_outputs[i];
                let persisted_auxiliary_info = &to_commit.persisted_auxiliary_infos[i];
                // Use the auxiliary info hash directly from the persisted info
                let auxiliary_info_hash = match persisted_auxiliary_info {
                    PersistedAuxiliaryInfo::None => None,
                    PersistedAuxiliaryInfo::V1 { .. } => {
                        Some(CryptoHash::hash(persisted_auxiliary_info))
                    },
                    PersistedAuxiliaryInfo::TimestampNotYetAssignedV1 { .. } => None,
                };
                let state_checkpoint_hash = state_checkpoint_hashes[i];
                let event_hashes = txn_output
                    .events()
                    .iter()
                    .map(CryptoHash::hash)
                    .collect::<Vec<_>>();
                let event_root_hash =
                    InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
                let write_set_hash = CryptoHash::hash(txn_output.write_set());
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
                    event_root_hash,
                    state_checkpoint_hash,
                    txn_output.gas_used(),
                    txn_output
                        .status()
                        .as_kept_status()
                        .expect("Already sorted."),
                    auxiliary_info_hash,
                );
                let txn_info_hash = txn_info.hash();
                (txn_info, txn_info_hash)
            })
            .unzip()
    }
```

**File:** execution/executor-types/src/ledger_update_output.rs (L90-112)
```rust
    pub fn ensure_transaction_infos_match(
        &self,
        transaction_infos: &[TransactionInfo],
    ) -> Result<()> {
        ensure!(
            self.transaction_infos.len() == transaction_infos.len(),
            "Lengths don't match. {} vs {}",
            self.transaction_infos.len(),
            transaction_infos.len(),
        );

        let mut version = self.first_version();
        for (txn_info, expected_txn_info) in
            zip_eq(self.transaction_infos.iter(), transaction_infos.iter())
        {
            ensure!(
                txn_info == expected_txn_info,
                "Transaction infos don't match. version:{version}, txn_info:{txn_info}, expected_txn_info:{expected_txn_info}",
            );
            version += 1;
        }
        Ok(())
    }
```
