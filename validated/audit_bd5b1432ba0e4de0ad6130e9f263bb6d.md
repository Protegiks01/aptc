# Audit Report

## Title
Byzantine State Corruption via Race Condition in Snapshot Verification with Error Masking

## Summary
A critical race condition in the state snapshot restoration process allows malicious network peers to inject permanently corrupted state values into honest nodes. The vulnerability combines parallel KV writes with deferred verification, indiscriminate error masking, and progress-based skip logic to enable persistent state corruption that violates consensus safety guarantees.

## Finding Description

The vulnerability exists in the state snapshot restoration mechanism where key-value (KV) data writes and cryptographic Merkle proof verification execute in parallel threads without proper atomicity guarantees.

**Root Cause 1: Non-Atomic Parallel Processing**

In `StateSnapshotRestore::add_chunk`, KV writes and verification execute concurrently without synchronization: [1](#0-0) 

The `kv_fn` closure (lines 229-236) writes state values to storage via `add_chunk`, while `tree_fn` closure (lines 238-245) performs Merkle proof verification. These execute in parallel via `IO_POOL.join()` at line 251, meaning KV data can commit to storage before verification completes or fails.

The KV write path immediately commits to RocksDB: [2](#0-1) 

Line 1278 calls `self.state_kv_db.commit()`, which atomically persists both the KV batch and progress metadata to disk, making the write durable before tree verification completes.

**Root Cause 2: Indiscriminate Error Masking**

All state snapshot errors, including cryptographic verification failures, are converted to `UnexpectedError`: [3](#0-2) 

Line 1331 wraps all errors in `Error::UnexpectedError`, masking Byzantine attacks as transient network failures. This causes the system to reset the stream and retry with a different peer rather than recognizing a security violation.

**Root Cause 3: Progress-Based Skip Logic**

The KV restoration implements skip logic based on saved progress: [4](#0-3) 

Lines 92-99 skip entries where `hash(key) <= progress.key_hash`. Since progress is saved atomically with corrupted KV data (line 122-126), the skip logic prevents overwriting corrupted values when retrying with an honest peer.

**Root Cause 4: Superficial Root Hash Validation**

The bootstrapper performs only a superficial root hash check before processing chunks: [5](#0-4) 

Lines 1021-1030 only verify that `state_value_chunk_with_proof.root_hash` matches `expected_root_hash`. An attacker can trivially pass this check by copying the correct root hash from the publicly available transaction info, while sending corrupted values with an invalid proof.

**Root Cause 5: Verification Occurs After Write**

The Merkle proof verification in `tree_fn` happens after `kv_fn` has already committed data: [6](#0-5) 

Line 391 calls `self.verify(proof)?` which performs cryptographic verification, but this executes in parallel with KV writes. If verification fails, Thread A (kv_fn) has already persisted corrupted data to RocksDB.

**Root Cause 6: No Final Verification**

Neither the `finish()` method nor `finalize_state_snapshot()` verify that KV storage matches Merkle tree hashes: [7](#0-6) [8](#0-7) 

The finalization process only saves transactions and ledger metadata without verifying KV-to-tree consistency.

**Root Cause 7: No Runtime Verification**

State values read during transaction execution are not verified against Merkle proofs by default: [9](#0-8) 

Line 23 shows `maybe_verify_against_state_root_hash: Option<HashValue>`, and line 102 shows the default state view sets this to `None`, meaning no proof verification occurs during normal execution.

**Attack Execution Flow:**

1. **Malicious Chunk Construction**: Attacker crafts `StateValueChunkWithProof` with corrupted `raw_values`, valid `root_hash` (copied from transaction info), and invalid `SparseMerkleRangeProof`.

2. **Superficial Validation Pass**: Bootstrapper's root hash check (line 1021) passes because attacker copied the correct root hash.

3. **Parallel Execution**: `kv_fn` writes corrupted data to RocksDB while `tree_fn` computes `hash(corrupted_value)` and attempts verification.

4. **Verification Failure**: Merkle proof verification fails at line 391 because proof is for `hash(correct_value)`, not `hash(corrupted_value)`.

5. **Error Masking**: Verification error wrapped in `UnexpectedError` at line 1331, triggering stream reset.

6. **Retry with Skip Logic**: Honest peer retry skips corrupted keys (lines 92-99), while tree verification passes with correct hashes.

7. **Completion**: Node finishes state sync with corrupted KV data but correct Merkle tree hashes.

**Result**: Nodes execute transactions using corrupted state values while maintaining correct state roots, causing deterministic execution violations and consensus divergence.

## Impact Explanation

**Severity: Critical**

This vulnerability meets multiple Critical severity criteria from the Aptos bug bounty program:

1. **Consensus Safety Violation**: Nodes with corrupted state will execute identical transactions differently, producing different state roots. This violates the fundamental consensus invariant that all honest nodes must agree on blockchain state. The divergence can cause:
   - Validators to disagree on block validity
   - Chain splits requiring manual intervention
   - Potential network partition

2. **State Consistency Violation**: The Merkle tree contains cryptographically correct hashes while KV storage contains corrupted values, breaking the invariant that state values must be verifiable via their Merkle proofs. This undermines the entire authenticated data structure.

3. **Permanent Corruption**: The corrupted state persists indefinitely because:
   - No background verification process compares KV data against tree hashes
   - State values are not verified during transaction execution (by default)
   - The corruption is invisible until transactions access the affected keys

4. **Non-Recoverable Network State**: Once multiple nodes have different corrupted state (potentially corrupted at different keys by different malicious peers), the network may require a coordinated hard fork to restore consistency, as there is no automated recovery mechanism.

This directly enables the "Consensus/Safety Violations" and "Non-recoverable Network Partition" categories, both rated as Critical ($1,000,000 severity) in the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely because:

1. **Minimal Prerequisites**:
   - Attacker needs only a malicious network peer capable of serving state sync data
   - No validator privileges or stake required
   - No cryptographic breaks needed
   - Transaction info with root hashes is publicly available

2. **Realistic Attack Vector**:
   - Nodes regularly perform state snapshot sync during bootstrapping
   - Fast sync is a common operation for new nodes joining the network
   - State sync from untrusted peers is the normal protocol operation

3. **Low Detection Risk**:
   - Errors appear as network failures (`UnexpectedError`)
   - No logging distinguishes Byzantine behavior from transient issues
   - Corruption remains dormant until affected state is accessed
   - No alerts or monitoring would detect the attack

4. **Scalability**:
   - Single malicious chunk can corrupt multiple state keys
   - Attacker can target high-value state (governance, staking, coin balances)
   - Attack can be repeated across multiple chunks in a snapshot

5. **Persistence**:
   - Corrupted data survives node restarts
   - No cleanup or verification process removes corruption
   - Impact manifests during transaction execution, potentially long after state sync

The attack complexity is low: construct a chunk with corrupted values, copy the correct root hash, send invalid proof. The impact is severe and permanent.

## Recommendation

Implement atomic verification-before-write by reordering the state snapshot restoration logic:

1. **Sequential Verification**: Perform tree verification BEFORE KV writes, not in parallel:
   ```rust
   // Verify proof first
   tree_fn()?;
   // Only write KV if verification passed
   kv_fn()?;
   ```

2. **Transactional Writes**: Use database transactions to ensure KV writes and progress updates are rolled back if verification fails.

3. **Final Consistency Check**: Add verification in `finish()` that compares KV hashes against tree:
   ```rust
   // After all chunks processed, verify KV consistency
   for (key, value) in kv_store.iter() {
       let tree_hash = merkle_tree.get_value_hash(key)?;
       ensure!(hash(value) == tree_hash, "KV-tree mismatch detected");
   }
   ```

4. **Error Classification**: Distinguish cryptographic verification failures from network errors:
   ```rust
   match error {
       Error::ProofVerificationFailed => ban_peer_and_abort(),
       Error::NetworkTimeout => retry_with_different_peer(),
   }
   ```

5. **Runtime Verification**: Enable proof verification during transaction execution for nodes that completed state sync within a recent window (e.g., 24 hours).

## Proof of Concept

While a complete PoC requires network infrastructure setup, the vulnerability can be demonstrated by constructing a malicious `StateValueChunkWithProof`:

```rust
// Construct malicious chunk
let corrupted_values = vec![
    (StateKey::from(...), corrupted_value_1),
    (StateKey::from(...), corrupted_value_2),
];

// Copy correct root hash from transaction info
let valid_root_hash = transaction_info.state_checkpoint_hash();

// Create invalid proof (doesn't match corrupted values)
let invalid_proof = SparseMerkleRangeProof { /* mismatched siblings */ };

let malicious_chunk = StateValueChunkWithProof {
    raw_values: corrupted_values,
    root_hash: valid_root_hash,  // Passes bootstrapper check
    proof: invalid_proof,         // Will fail tree verification
    // ... other fields
};

// Send to victim node during state sync
// Result: KV writes complete before verification fails
// Skip logic prevents overwriting on retry
```

The attack succeeds because the parallel execution in `IO_POOL.join(kv_fn, tree_fn)` allows `kv_fn` to commit corrupted data before `tree_fn` detects the invalid proof.

---

## Notes

This vulnerability represents a fundamental design flaw in the state snapshot restoration mechanism where security-critical verification is deferred and executed non-atomically with data persistence. The combination of parallel execution, error masking, and skip logic creates a persistent state corruption vector that violates core blockchain invariants. The lack of final verification and optional runtime verification means the corruption can remain undetected indefinitely, manifesting only when transactions access corrupted state, at which point consensus divergence is unavoidable.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L88-127)
```rust
    pub fn add_chunk(&mut self, mut chunk: Vec<(K, V)>) -> Result<()> {
        // load progress
        let progress_opt = self.db.get_progress(self.version)?;

        // skip overlaps
        if let Some(progress) = progress_opt {
            let idx = chunk
                .iter()
                .position(|(k, _v)| CryptoHash::hash(k) > progress.key_hash)
                .unwrap_or(chunk.len());
            chunk = chunk.split_off(idx);
        }

        // quit if all skipped
        if chunk.is_empty() {
            return Ok(());
        }

        // save
        let mut usage = progress_opt.map_or(StateStorageUsage::zero(), |p| p.usage);
        let (last_key, _last_value) = chunk.last().unwrap();
        let last_key_hash = CryptoHash::hash(last_key);

        // In case of TreeOnly Restore, we only restore the usage of KV without actually writing KV into DB
        for (k, v) in chunk.iter() {
            usage.add_item(k.key_size() + v.value_size());
        }

        // prepare the sharded kv batch
        let kv_batch: StateValueBatch<K, Option<V>> = chunk
            .into_iter()
            .map(|(k, v)| ((k, self.version), Some(v)))
            .collect();

        self.db.write_kv_batch(
            self.version,
            &kv_batch,
            StateSnapshotProgress::new(last_key_hash, usage),
        )
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L129-143)
```rust
    pub fn finish(self) -> Result<()> {
        let progress = self.db.get_progress(self.version)?;
        self.db.kv_finish(
            self.version,
            progress.map_or(StateStorageUsage::zero(), |p| p.usage),
        )
    }

    pub fn previous_key_hash(&self) -> Result<Option<HashValue>> {
        Ok(self
            .db
            .get_progress(self.version)?
            .map(|progress| progress.key_hash))
    }
}
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-258)
```rust
    fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
        let kv_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_add_chunk"]);
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk.clone())
        };

        let tree_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["jmt_add_chunk"]);
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)
        };
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => kv_fn()?,
            StateSnapshotRestoreMode::TreeOnly => tree_fn()?,
            StateSnapshotRestoreMode::Default => {
                // We run kv_fn with TreeOnly to restore the usage of DB
                let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
                r1?;
                r2?;
            },
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1244-1279)
```rust
    fn write_kv_batch(
        &self,
        version: Version,
        node_batch: &StateValueBatch,
        progress: StateSnapshotProgress,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_writer_write_chunk"]);
        let mut batch = SchemaBatch::new();
        let mut sharded_schema_batch = self.state_kv_db.new_sharded_native_batches();

        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateSnapshotKvRestoreProgress(version),
            &DbMetadataValue::StateSnapshotProgress(progress),
        )?;

        if self.internal_indexer_db.is_some()
            && self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .statekeys_enabled()
        {
            let keys = node_batch.keys().map(|key| key.0.clone()).collect();
            self.internal_indexer_db
                .as_ref()
                .unwrap()
                .write_keys_to_indexer_db(&keys, version, progress)?;
        }
        self.shard_state_value_batch(
            &mut sharded_schema_batch,
            node_batch,
            self.state_kv_db.enabled_sharding(),
        )?;
        self.state_kv_db
            .commit(version, Some(batch), sharded_schema_batch)
    }
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L1321-1347)
```rust
async fn send_storage_synchronizer_error(
    mut error_notification_sender: mpsc::UnboundedSender<ErrorNotification>,
    notification_id: NotificationId,
    error_message: String,
) {
    // Log the storage synchronizer error
    let error_message = format!("Storage synchronizer error: {:?}", error_message);
    error!(LogSchema::new(LogEntry::StorageSynchronizer).message(&error_message));

    // Update the storage synchronizer error metrics
    let error = Error::UnexpectedError(error_message);
    metrics::increment_counter(&metrics::STORAGE_SYNCHRONIZER_ERRORS, error.get_label());

    // Send an error notification to the driver
    let error_notification = ErrorNotification {
        error: error.clone(),
        notification_id,
    };
    if let Err(error) = error_notification_sender.send(error_notification).await {
        error!(
            LogSchema::new(LogEntry::StorageSynchronizer).message(&format!(
                "Failed to send error notification! Error: {:?}",
                error
            ))
        );
    }
}
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1007-1031)
```rust
        // Verify the chunk root hash matches the expected root hash
        let first_transaction_info = transaction_output_to_sync
            .get_output_list_with_proof()
            .proof
            .transaction_infos
            .first()
            .ok_or_else(|| {
                Error::UnexpectedError("Target transaction info does not exist!".into())
            })?;
        let expected_root_hash = first_transaction_info
            .ensure_state_checkpoint_hash()
            .map_err(|error| {
                Error::UnexpectedError(format!("State checkpoint must exist! Error: {:?}", error))
            })?;
        if state_value_chunk_with_proof.root_hash != expected_root_hash {
            self.reset_active_stream(Some(NotificationAndFeedback::new(
                notification_id,
                NotificationFeedback::InvalidPayloadData,
            )))
            .await?;
            return Err(Error::VerificationError(format!(
                "The states chunk with proof root hash: {:?} didn't match the expected hash: {:?}!",
                state_value_chunk_with_proof.root_hash, expected_root_hash,
            )));
        }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L336-413)
```rust
    /// Restores a chunk of states. This function will verify that the given chunk is correct
    /// using the proof and root hash, then write things to storage. If the chunk is invalid, an
    /// error will be returned and nothing will be written to storage.
    pub fn add_chunk_impl(
        &mut self,
        mut chunk: Vec<(&K, HashValue)>,
        proof: SparseMerkleRangeProof,
    ) -> Result<()> {
        if self.finished {
            info!("State snapshot restore already finished, ignoring entire chunk.");
            return Ok(());
        }

        if let Some(prev_leaf) = &self.previous_leaf {
            let skip_until = chunk
                .iter()
                .find_position(|(key, _hash)| key.hash() > *prev_leaf.account_key());
            chunk = match skip_until {
                None => {
                    info!("Skipping entire chunk.");
                    return Ok(());
                },
                Some((0, _)) => chunk,
                Some((num_to_skip, next_leaf)) => {
                    info!(
                        num_to_skip = num_to_skip,
                        next_leaf = next_leaf,
                        "Skipping leaves."
                    );
                    chunk.split_off(num_to_skip)
                },
            }
        };
        if chunk.is_empty() {
            return Ok(());
        }

        for (key, value_hash) in chunk {
            let hashed_key = key.hash();
            if let Some(ref prev_leaf) = self.previous_leaf {
                ensure!(
                    &hashed_key > prev_leaf.account_key(),
                    "State keys must come in increasing order.",
                )
            }
            self.previous_leaf.replace(LeafNode::new(
                hashed_key,
                value_hash,
                (key.clone(), self.version),
            ));
            self.add_one(key, value_hash);
            self.num_keys_received += 1;
        }

        // Verify what we have added so far is all correct.
        self.verify(proof)?;

        // Write the frozen nodes to storage.
        if self.async_commit {
            self.wait_for_async_commit()?;
            let (tx, rx) = channel();
            self.async_commit_result = Some(rx);

            let mut frozen_nodes = HashMap::new();
            std::mem::swap(&mut frozen_nodes, &mut self.frozen_nodes);
            let store = self.store.clone();

            IO_POOL.spawn(move || {
                let res = store.write_node_batch(&frozen_nodes);
                tx.send(res).unwrap();
            });
        } else {
            self.store.write_node_batch(&self.frozen_nodes)?;
            self.frozen_nodes.clear();
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-241)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let (output_with_proof, persisted_aux_info) = output_with_proof.into_parts();
        gauged_api("finalize_state_snapshot", || {
            // Ensure the output with proof only contains a single transaction output and info
            let num_transaction_outputs = output_with_proof.get_num_outputs();
            let num_transaction_infos = output_with_proof.proof.transaction_infos.len();
            ensure!(
                num_transaction_outputs == 1,
                "Number of transaction outputs should == 1, but got: {}",
                num_transaction_outputs
            );
            ensure!(
                num_transaction_infos == 1,
                "Number of transaction infos should == 1, but got: {}",
                num_transaction_infos
            );

            // TODO(joshlind): include confirm_or_save_frozen_subtrees in the change set
            // bundle below.

            // Update the merkle accumulator using the given proof
            let frozen_subtrees = output_with_proof
                .proof
                .ledger_info_to_transaction_infos_proof
                .left_siblings();
            restore_utils::confirm_or_save_frozen_subtrees(
                self.ledger_db.transaction_accumulator_db_raw(),
                version,
                frozen_subtrees,
                None,
            )?;

            // Create a single change set for all further write operations
            let mut ledger_db_batch = LedgerDbSchemaBatches::new();
            let mut sharded_kv_batch = self.state_kv_db.new_sharded_native_batches();
            let mut state_kv_metadata_batch = SchemaBatch::new();
            // Save the target transactions, outputs, infos and events
            let (transactions, outputs): (Vec<Transaction>, Vec<TransactionOutput>) =
                output_with_proof
                    .transactions_and_outputs
                    .into_iter()
                    .unzip();
            let events = outputs
                .clone()
                .into_iter()
                .map(|output| output.events().to_vec())
                .collect::<Vec<_>>();
            let wsets: Vec<WriteSet> = outputs
                .into_iter()
                .map(|output| output.write_set().clone())
                .collect();
            let transaction_infos = output_with_proof.proof.transaction_infos;
            // We should not save the key value since the value is already recovered for this version
            restore_utils::save_transactions(
                self.state_store.clone(),
                self.ledger_db.clone(),
                version,
                &transactions,
                &persisted_aux_info,
                &transaction_infos,
                &events,
                wsets,
                Some((
                    &mut ledger_db_batch,
                    &mut sharded_kv_batch,
                    &mut state_kv_metadata_batch,
                )),
                false,
            )?;

            // Save the epoch ending ledger infos
            restore_utils::save_ledger_infos(
                self.ledger_db.metadata_db(),
                ledger_infos,
                Some(&mut ledger_db_batch.ledger_metadata_db_batches),
            )?;

            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::LedgerCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;
            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::OverallCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;

            // Apply the change set writes to the database (atomically) and update in-memory state
            //
            // state kv and SMT should use shared way of committing.
            self.ledger_db.write_schemas(ledger_db_batch)?;

            self.ledger_pruner.save_min_readable_version(version)?;
            self.state_store
                .state_merkle_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .epoch_snapshot_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .state_kv_pruner
                .save_min_readable_version(version)?;

            restore_utils::update_latest_ledger_info(self.ledger_db.metadata_db(), ledger_infos)?;
            self.state_store.reset();

            Ok(())
        })
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L17-46)
```rust
#[derive(Clone)]
pub struct DbStateView {
    db: Arc<dyn DbReader>,
    version: Option<Version>,
    /// DB doesn't support returning proofs for buffered state, so only optionally verify proof.
    /// TODO: support returning state proof for buffered state.
    maybe_verify_against_state_root_hash: Option<HashValue>,
}

impl DbStateView {
    fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
        if let Some(version) = self.version {
            if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
                // TODO(aldenhu): sample-verify proof inside DB
                // DB doesn't support returning proofs for buffered state, so only optionally
                // verify proof.
                // TODO: support returning state proof for buffered state.
                if let Ok((value, proof)) =
                    self.db.get_state_value_with_proof_by_version(key, version)
                {
                    proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
                }
            }
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
```
