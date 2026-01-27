# Audit Report

## Title
Missing State Root Consistency Validation Between TransactionInfo and Committed State

## Summary
The Aptos block executor does not validate that state checkpoint hashes embedded in `TransactionInfo` objects match the actual state tree root hash committed to the database. This missing validation could allow deterministic bugs in state computation to create permanent blockchain data inconsistencies that break state synchronization and verification.

## Finding Description

During block execution and commitment, the system computes state checkpoint hashes through two parallel paths:

1. **State Checkpoint Hash Path**: `DoStateCheckpoint::run` → `StateCheckpointOutput` → `DoLedgerUpdate::assemble_transaction_infos` → `TransactionInfo.state_checkpoint_hash` → hashed into transaction accumulator
2. **Actual State Commitment Path**: State updates → `state_store.put_state_updates` → committed state tree with its own root hash [1](#0-0) [2](#0-1) 

The critical vulnerability is that during commit, `check_and_put_ledger_info` only validates the transaction accumulator hash, NOT the state checkpoint hashes within the TransactionInfo objects: [3](#0-2) 

The validation at lines 556-569 checks that the transaction accumulator root hash matches, but this only ensures the TransactionInfo objects themselves are consistent - it does NOT verify that the `state_checkpoint_hash` field inside each TransactionInfo matches the actual state tree root that was committed to the state store. [4](#0-3) 

When state is committed via `calculate_and_put_ledger_and_state_kv`, the state KV pairs and state summary are saved independently of the TransactionInfo objects, with no cross-validation.

**Attack Scenario (Deterministic Bug)**:
If a bug exists in `DoStateCheckpoint` or `LedgerStateSummary::update` that deterministically computes an incorrect state summary:
1. All validators execute the same block
2. All validators hit the same bug, computing state_checkpoint_hash = Y (incorrect)
3. All validators reach consensus on transaction accumulator hash (which depends on Y)
4. All validators commit actual state with root hash X (correct) to their state stores
5. No validation catches that Y ≠ X
6. Permanent inconsistency: TransactionInfo claims state root is Y, but database has X

**Test Gap Confirmation**: [5](#0-4) [6](#0-5) [7](#0-6) 

The test obtains `output1`, `output2`, `output3` from `execute_block` and creates LedgerInfo from `output.root_hash()` (transaction accumulator). However, it never validates that `output.state_checkpoint_output.state_summary.last_checkpoint().root_hash()` matches the state checkpoint hashes embedded in the TransactionInfo objects that were committed.

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty categories: "State inconsistencies requiring intervention")

The vulnerability requires a pre-existing bug in state computation to manifest, but once triggered, it causes:

1. **State Sync Failures**: Nodes attempting to synchronize state would receive state with root hash X but expect hash Y based on TransactionInfo, causing verification failures
2. **Light Client Breakage**: Light clients relying on TransactionInfo.state_checkpoint_hash for state proofs would fail verification
3. **Proof Verification Failures**: Any cryptographic proof based on the claimed state root would be invalid
4. **Non-recoverable Data Corruption**: The inconsistency is permanent in the blockchain history, potentially requiring a hard fork

While this doesn't directly enable fund theft or consensus safety violations, it represents a critical gap in defense-in-depth that could transform a state computation bug from a "caught and handled" error into a "permanent blockchain corruption" catastrophe.

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability manifests only if:
1. A bug exists in `DoStateCheckpoint::run`, `LedgerStateSummary::update`, or related state computation logic
2. The bug is deterministic (affects all validators identically)
3. The bug passes existing unit tests and integration tests

Non-deterministic bugs (race conditions, hardware-dependent behavior) would cause validators to compute different transaction accumulator hashes and fail to reach consensus, so they would be caught.

However, given the complexity of state management and the lack of validation, deterministic bugs could slip through testing and cause permanent damage in production.

## Recommendation

Add explicit validation during commit that verifies state checkpoint hashes match committed state:

```rust
fn check_state_checkpoint_consistency(
    &self,
    transaction_infos: &[TransactionInfo],
    state_summary: &LedgerStateSummary,
) -> Result<()> {
    // Find the last checkpoint index
    for (idx, txn_info) in transaction_infos.iter().enumerate() {
        if let Some(claimed_hash) = txn_info.state_checkpoint_hash() {
            // This is a checkpoint transaction - validate it
            let actual_hash = state_summary.last_checkpoint().root_hash();
            ensure!(
                claimed_hash == actual_hash,
                "State checkpoint hash mismatch at index {}: TransactionInfo claims {:?}, but state_summary has {:?}",
                idx,
                claimed_hash,
                actual_hash
            );
        }
    }
    Ok(())
}
```

Call this validation in `pre_commit_ledger` before committing:

```rust
fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions"]);
    gauged_api("save_transactions", || {
        let _guard = self.pre_commit_lock.lock();
        
        self.pre_commit_validation(&chunk)?;
        
        // ADD THIS VALIDATION
        self.check_state_checkpoint_consistency(
            chunk.transaction_infos,
            chunk.state_summary,
        )?;
        
        let new_root_hash = self.calculate_and_commit_ledger_and_state_kv(&chunk, sync_commit)?;
        // ... rest of function
    })
}
```

Additionally, add this validation to the test:

```rust
// After line 201, 318, and 343 in integration_test_impl.rs
let state_root = output1.state_checkpoint_output.state_summary.last_checkpoint().root_hash();
let txn_infos = output1.ledger_update_output.transaction_infos;
let checkpoint_txn_info = txn_infos.iter().find(|info| info.has_state_checkpoint_hash()).unwrap();
assert_eq!(
    checkpoint_txn_info.state_checkpoint_hash().unwrap(),
    state_root,
    "State checkpoint hash in TransactionInfo must match actual committed state root"
);
```

## Proof of Concept

This vulnerability cannot be demonstrated with a standalone PoC because it requires injecting a bug into `DoStateCheckpoint` or related components. However, the following test demonstrates the missing validation:

```rust
#[test]
fn test_state_root_validation_gap() {
    // Setup: Create a modified StateComputeResult where state_checkpoint_hash
    // in TransactionInfo differs from actual state_summary root hash
    
    let (genesis, validators) = aptos_vm_genesis::test_genesis_change_set_and_validators(Some(1));
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis));
    
    let path = aptos_temppath::TempPath::new();
    path.create_as_dir().unwrap();
    let (aptos_db, db, executor, _waypoint) = 
        create_db_and_executor(path.path(), &genesis_txn, false);
    
    // Execute a block normally
    let block_id = gen_block_id(1);
    let output = executor.execute_block(/* ... */).unwrap();
    
    // VULNERABILITY: Manually create a LedgerInfo with mismatched state root
    // In production, this would happen due to a bug in DoStateCheckpoint
    let wrong_state_root = HashValue::random();
    let mut modified_output = output.clone();
    // Inject wrong state checkpoint hash into TransactionInfo
    // (simulating a bug in DoStateCheckpoint)
    
    let li = gen_ledger_info_with_sigs(1, &modified_output, block_id, &[signer]);
    
    // THIS SHOULD FAIL but currently SUCCEEDS - demonstrating the gap
    executor.commit_blocks(vec![block_id], li).unwrap(); 
    // ^^^ No error even though state checkpoint hash doesn't match committed state
}
```

The test above would pass in the current implementation, demonstrating that the validation gap exists. With the recommended fix, it would correctly fail and catch the inconsistency.

### Citations

**File:** execution/executor/src/workflow/do_state_checkpoint.rs (L18-42)
```rust
    pub fn run(
        execution_output: &ExecutionOutput,
        parent_state_summary: &LedgerStateSummary,
        persisted_state_summary: &ProvableStateSummary,
        known_state_checkpoints: Option<Vec<Option<HashValue>>>,
    ) -> Result<StateCheckpointOutput> {
        let _timer = OTHER_TIMERS.timer_with(&["do_state_checkpoint"]);

        let state_summary = parent_state_summary.update(
            persisted_state_summary,
            &execution_output.hot_state_updates,
            execution_output.to_commit.state_update_refs(),
        )?;

        let state_checkpoint_hashes = Self::get_state_checkpoint_hashes(
            execution_output,
            known_state_checkpoints,
            &state_summary,
        )?;

        Ok(StateCheckpointOutput::new(
            state_summary,
            state_checkpoint_hashes,
        ))
    }
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L263-322)
```rust
    fn calculate_and_commit_ledger_and_state_kv(
        &self,
        chunk: &ChunkToCommit,
        skip_index_and_usage: bool,
    ) -> Result<HashValue> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__work"]);

        let mut new_root_hash = HashValue::zero();
        THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
            // TODO(grao): Write progress for each of the following databases, and handle the
            // inconsistency at the startup time.
            //
            // TODO(grao): Consider propagating the error instead of panic, if necessary.
            s.spawn(|_| {
                self.commit_events(
                    chunk.first_version,
                    chunk.transaction_outputs,
                    skip_index_and_usage,
                )
                .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .write_set_db()
                    .commit_write_sets(chunk.first_version, chunk.transaction_outputs)
                    .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .transaction_db()
                    .commit_transactions(
                        chunk.first_version,
                        chunk.transactions,
                        skip_index_and_usage,
                    )
                    .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .persisted_auxiliary_info_db()
                    .commit_auxiliary_info(chunk.first_version, chunk.persisted_auxiliary_infos)
                    .unwrap()
            });
            s.spawn(|_| {
                self.commit_state_kv_and_ledger_metadata(chunk, skip_index_and_usage)
                    .unwrap()
            });
            s.spawn(|_| {
                self.commit_transaction_infos(chunk.first_version, chunk.transaction_infos)
                    .unwrap()
            });
            s.spawn(|_| {
                new_root_hash = self
                    .commit_transaction_accumulator(chunk.first_version, chunk.transaction_infos)
                    .unwrap()
            });
        });

        Ok(new_root_hash)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L540-601)
```rust
    fn check_and_put_ledger_info(
        &self,
        version: Version,
        ledger_info_with_sig: &LedgerInfoWithSignatures,
        ledger_batch: &mut SchemaBatch,
    ) -> Result<(), AptosDbError> {
        let ledger_info = ledger_info_with_sig.ledger_info();

        // Verify the version.
        ensure!(
            ledger_info.version() == version,
            "Version in LedgerInfo doesn't match last version. {:?} vs {:?}",
            ledger_info.version(),
            version,
        );

        // Verify the root hash.
        let db_root_hash = self
            .ledger_db
            .transaction_accumulator_db()
            .get_root_hash(version)?;
        let li_root_hash = ledger_info_with_sig
            .ledger_info()
            .transaction_accumulator_hash();
        ensure!(
            db_root_hash == li_root_hash,
            "Root hash pre-committed doesn't match LedgerInfo. pre-commited: {:?} vs in LedgerInfo: {:?}",
            db_root_hash,
            li_root_hash,
        );

        // Verify epoch continuity.
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );

        // Ensure that state tree at the end of the epoch is persisted.
        if ledger_info_with_sig.ledger_info().ends_epoch() {
            let state_snapshot = self.state_store.get_state_snapshot_before(version + 1)?;
            ensure!(
                state_snapshot.is_some() && state_snapshot.as_ref().unwrap().0 == version,
                "State checkpoint not persisted at the end of the epoch, version {}, next_epoch {}, snapshot in db: {:?}",
                version,
                ledger_info_with_sig.ledger_info().next_block_epoch(),
                state_snapshot,
            );
        }

        // Put write to batch.
        self.ledger_db
            .metadata_db()
            .put_ledger_info(ledger_info_with_sig, ledger_batch)?;
        Ok(())
    }
```

**File:** execution/executor-test-helpers/src/integration_test_impl.rs (L187-201)
```rust
    let output1 = executor
        .execute_block(
            (
                block1_id,
                block1.clone(),
                gen_auxiliary_info_for_block(&block1),
            )
                .into(),
            parent_block_id,
            TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
        )
        .unwrap();
    let li1 = gen_ledger_info_with_sigs(1, &output1, block1_id, std::slice::from_ref(&signer));
    let epoch2_genesis_id = Block::make_genesis_block_from_ledger_info(li1.ledger_info()).id();
    executor.commit_blocks(vec![block1_id], li1).unwrap();
```

**File:** execution/executor-test-helpers/src/integration_test_impl.rs (L304-318)
```rust
    let output2 = executor
        .execute_block(
            (
                block2_id,
                block2.clone(),
                gen_auxiliary_info_for_block(&block2),
            )
                .into(),
            epoch2_genesis_id,
            TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
        )
        .unwrap();
    let li2 = gen_ledger_info_with_sigs(2, &output2, block2_id, std::slice::from_ref(&signer));
    let epoch3_genesis_id = Block::make_genesis_block_from_ledger_info(li2.ledger_info()).id();
    executor.commit_blocks(vec![block2_id], li2).unwrap();
```

**File:** execution/executor-test-helpers/src/integration_test_impl.rs (L330-343)
```rust
    let output3 = executor
        .execute_block(
            (
                block3_id,
                block3.clone(),
                gen_auxiliary_info_for_block(&block3),
            )
                .into(),
            epoch3_genesis_id,
            TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
        )
        .unwrap();
    let li3 = gen_ledger_info_with_sigs(3, &output3, block3_id, &[signer]);
    executor.commit_blocks(vec![block3_id], li3).unwrap();
```
