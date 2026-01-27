# Audit Report

## Title
Incomplete State Checkpoint Verification During State Sync Allows Undetected Execution Divergence

## Summary
The `DoStateCheckpoint::run()` function only verifies the LAST state checkpoint hash when processing chunks with multiple checkpoints during state synchronization, while accepting ALL checkpoint hashes from remote peers without verification. This incomplete verification could mask non-deterministic execution bugs at intermediate checkpoint boundaries.

## Finding Description

During state synchronization, the chunk executor processes transaction chunks that may span multiple blocks, each ending with a state checkpoint. The vulnerability exists in how these checkpoints are verified. [1](#0-0) 

When `known_state_checkpoints` is provided (during state sync), the function only verifies that the last checkpoint hash matches local execution, but returns ALL checkpoint hashes from the remote peer: [2](#0-1) 

The chunk executor calls this during state sync by extracting checkpoint hashes from remote transaction infos: [3](#0-2) 

State sync chunks are version-based and can span multiple blocks: [4](#0-3) 

These checkpoint hashes are then used to create TransactionInfo objects that are stored in the ledger: [5](#0-4) [6](#0-5) 

Later, these stored checkpoint hashes are used to create verified state views: [7](#0-6) 

**Exploitation Path:**
1. Chunk contains transactions 1000-3999 with checkpoints at versions 1499, 1999, 2499, 2999
2. Local execution produces different state at version 1999 (due to subtle execution bug)
3. Only checkpoint at version 2999 is verified against local execution
4. Checkpoint hash at version 1999 from remote peer is accepted without verification
5. Different validators may accept different intermediate checkpoint hashes if syncing at different times or if execution non-determinism exists
6. Validators commit different TransactionInfo data for intermediate checkpoints
7. When creating verified state views at these versions, validators use different root hashes

## Impact Explanation

**Severity: Critical - Consensus/Safety Violation**

This violates the fundamental invariant that "All validators must produce identical state roots for identical blocks." While during normal consensus operation (block execution) all checkpoints are computed locally, during state sync this incomplete verification could lead to:

1. **Validator State Divergence**: Different validators may store different checkpoint hashes for the same transaction version if they sync from different peers or at different times
2. **Determinism Check Bypass**: The purpose of re-execution during state sync is to detect non-deterministic bugs, but intermediate checkpoint verification is bypassed
3. **Potential Consensus Failures**: When validators later use these checkpoints as trusted state roots for creating verified views, they may have different roots, potentially causing future consensus disagreements

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability manifests when:
- State sync chunks span multiple blocks (common with default 3000 transaction chunk size)
- Subtle execution non-determinism exists that affects intermediate but not final checkpoints
- Multiple validators sync the same chunk range at different times or from different peers

While execution should be deterministic, subtle bugs or timing-dependent behavior could cause intermediate state differences that would be masked by this incomplete verification.

## Recommendation

Modify `DoStateCheckpoint::get_state_checkpoint_hashes()` to verify ALL checkpoint hashes, not just the last one. This requires computing intermediate state checkpoints during execution:

```rust
fn get_state_checkpoint_hashes(
    execution_output: &ExecutionOutput,
    known_state_checkpoints: Option<Vec<Option<HashValue>>>,
    state_summary: &LedgerStateSummary,
) -> Result<Vec<Option<HashValue>>> {
    let num_txns = execution_output.to_commit.len();
    let all_checkpoint_indices = execution_output
        .to_commit
        .state_update_refs()
        .all_checkpoint_versions()
        .iter()
        .map(|v| (v - execution_output.first_version) as usize)
        .collect::<Vec<_>>();
    
    if let Some(known) = known_state_checkpoints {
        ensure!(known.len() == num_txns, "Bad number of known hashes");
        
        // Verify ALL checkpoints, not just the last one
        for &idx in &all_checkpoint_indices {
            let local_hash = compute_checkpoint_at_index(
                state_summary, 
                execution_output, 
                idx
            )?;
            ensure!(
                known[idx] == Some(local_hash),
                "Root hash mismatch at index {}: {:?} vs {:?}",
                idx, known[idx], Some(local_hash)
            );
        }
        Ok(known)
    } else {
        // Existing logic for non-state-sync paths
        // ...
    }
}
```

## Proof of Concept

This vulnerability requires a complex integration test that simulates state sync with chunks spanning multiple blocks. A simplified reproduction scenario:

```rust
// Pseudocode for reproduction test
#[test]
fn test_intermediate_checkpoint_verification() {
    // Setup: Create a chunk with 4 blocks (checkpoints at indices 999, 1999, 2999, 3999)
    let chunk = create_multi_block_chunk(4000);
    
    // Simulate remote peer providing transaction infos with wrong intermediate checkpoint
    let mut remote_txn_infos = execute_and_get_transaction_infos(&chunk);
    remote_txn_infos[1999].state_checkpoint_hash = Some(HashValue::random());
    
    // Execute chunk locally
    let local_output = execute_chunk_locally(&chunk);
    
    // Call DoStateCheckpoint with known (wrong) checkpoints
    let known_checkpoints = extract_checkpoint_hashes(&remote_txn_infos);
    let result = DoStateCheckpoint::run(
        &local_output,
        &parent_state,
        &persisted_state,
        Some(known_checkpoints),
    );
    
    // Bug: This should fail but succeeds because only last checkpoint is verified
    assert!(result.is_ok()); // Currently passes - vulnerability!
    
    // The wrong checkpoint at index 1999 is accepted
    let state_checkpoint_output = result.unwrap();
    assert_eq!(
        state_checkpoint_output.state_checkpoint_hashes[1999],
        remote_txn_infos[1999].state_checkpoint_hash // Wrong hash accepted!
    );
}
```

## Notes

- This vulnerability specifically affects the state sync path in `chunk_executor/mod.rs`, not the normal consensus execution path in `block_executor/mod.rs`
- During consensus, `known_state_checkpoints` is always `None`, so all checkpoints are computed and verified locally
- The incomplete verification defeats the security purpose of re-execution during state sync, which is to detect execution bugs and non-determinism
- State sync chunks being version-based (not block-based) means they commonly span multiple blocks, making this scenario realistic

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

**File:** execution/executor/src/chunk_executor/mod.rs (L346-363)
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

        let ledger_update_output = DoLedgerUpdate::run(
            &output.execution_output,
            &state_checkpoint_output,
            parent_accumulator.clone(),
        )?;
```

**File:** execution/executor-types/src/transactions_with_output.rs (L178-204)
```rust
    fn get_all_checkpoint_indices(
        transactions_with_output: &TransactionsWithOutput,
        must_be_block: bool,
    ) -> (Vec<usize>, bool) {
        let _timer = TIMER.timer_with(&["get_all_checkpoint_indices"]);

        let (last_txn, last_output) = match transactions_with_output.last() {
            Some((txn, output, _)) => (txn, output),
            None => return (Vec::new(), false),
        };
        let is_reconfig = last_output.has_new_epoch_event();

        if must_be_block {
            assert!(last_txn.is_non_reconfig_block_ending() || is_reconfig);
            return (vec![transactions_with_output.len() - 1], is_reconfig);
        }

        (
            transactions_with_output
                .iter()
                .positions(|(txn, output, _)| {
                    txn.is_non_reconfig_block_ending() || output.has_new_epoch_event()
                })
                .collect(),
            is_reconfig,
        )
    }
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L31-34)
```rust
        let (transaction_infos, transaction_info_hashes) = Self::assemble_transaction_infos(
            &execution_output.to_commit,
            state_checkpoint_output.state_checkpoint_hashes.clone(),
        );
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

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L115-146)
```rust
impl VerifiedStateViewAtVersion for Arc<dyn DbReader> {
    fn verified_state_view_at_version(
        &self,
        version: Option<Version>,
        ledger_info: &LedgerInfo,
    ) -> StateViewResult<DbStateView> {
        let db = self.clone();

        if let Some(version) = version {
            let txn_with_proof =
                db.get_transaction_by_version(version, ledger_info.version(), false)?;
            txn_with_proof.verify(ledger_info)?;

            let state_root_hash = txn_with_proof
                .proof
                .transaction_info
                .state_checkpoint_hash()
                .ok_or_else(|| StateViewError::NotFound("state_checkpoint_hash".to_string()))?;

            Ok(DbStateView {
                db,
                version: Some(version),
                maybe_verify_against_state_root_hash: Some(state_root_hash),
            })
        } else {
            Ok(DbStateView {
                db,
                version: None,
                maybe_verify_against_state_root_hash: None,
            })
        }
    }
```
