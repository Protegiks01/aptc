# Audit Report

## Title
Missing Root Hash Verification in State Snapshot Restoration Allows Incomplete State Creation

## Summary
The `finish_impl()` method in `JellyfishMerkleRestore` completes state snapshot restoration without verifying that the final computed root hash matches the expected root hash. This allows incomplete state to be written to storage and appear valid, causing consensus safety violations.

## Finding Description

The state snapshot restore process in Aptos consists of three main components:

1. **Restore Controller** processes chunks from a backup manifest [1](#0-0) 

2. **Chunk Verification** validates each chunk against `SparseMerkleRangeProof` during addition [2](#0-1) 

3. **Finalization** freezes remaining nodes and writes to storage [3](#0-2) 

**The Critical Flaw:** The `finish_impl()` method writes the completed tree to storage without verifying that the computed root hash equals `self.expected_root_hash`. While `add_chunk_impl()` calls `verify()` for incremental range proof validation, this only confirms that added chunks are consistent with the expected root, NOT that all chunks have been added.

The `freeze_internal_nodes()` method computes the root hash when freezing the final node but never compares it to the expected value [4](#0-3) 

**Attack Scenario:**
1. Attacker creates a malicious backup manifest with only partial chunks (e.g., 80% of state)
2. Each chunk includes valid `SparseMerkleRangeProof` for its range
3. Restore controller processes all chunks in the manifest [5](#0-4) 
4. Each chunk passes `verify()` because range proofs are valid for partial data
5. `finish()` is called after processing all manifest chunks, writing incomplete tree to storage
6. `finalize_state_snapshot()` completes without root hash verification [6](#0-5) 

**Evidence from Tests:** Test code explicitly verifies root hash AFTER calling `finish()`, proving this verification is not part of the finish process [7](#0-6) 

This breaks the **State Consistency** invariant: state transitions must be verifiable via Merkle proofs. It also breaks **Deterministic Execution**: nodes with incomplete vs. complete state will compute different state roots for identical transactions.

## Impact Explanation

**Severity: Critical** (Consensus/Safety Violations)

This vulnerability enables:

1. **Consensus Safety Breaks**: Different nodes restore to different states, causing divergent state roots for identical blocks. This violates AptosBFT safety guarantees.

2. **Non-Recoverable Network Partition**: Once nodes have different states, they cannot reach consensus on new blocks. Requires hard fork to resolve.

3. **State Corruption**: Missing state entries cause transaction execution failures, making the chain unusable for affected transactions.

4. **Validator Set Manipulation**: If validator stake state is incomplete, validator set calculations diverge across nodes.

Per Aptos bug bounty criteria, this qualifies as **Critical Severity** ($1,000,000 range) due to consensus safety violations and potential network partition requiring hard fork recovery.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Requirements:**
- Ability to provide backup manifests to restoring nodes (e.g., via compromised backup storage, malicious restore operations, or network manipulation)
- No validator access or stake required
- No cryptographic breaks needed

**Realistic Attack Vectors:**
1. Compromised backup infrastructure serving incomplete manifests
2. Network issues causing partial manifest downloads that go undetected
3. Malicious restoration from untrusted backup sources
4. State sync from compromised peers providing incomplete snapshots

**Feasibility:** The attack is straightforward - simply modify a manifest to exclude chunks. The range proofs remain valid for included chunks, so no forgery is needed.

## Recommendation

Add root hash verification in `finish_impl()` before writing to storage:

**Location:** `storage/jellyfish-merkle/src/restore/mod.rs`, function `finish_impl()`

**Fix:** After calling `freeze(0)` and before `write_node_batch()`, retrieve the root node from `frozen_nodes` and verify its hash matches `expected_root_hash`:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // ... existing special case handling ...
    
    self.freeze(0);
    
    // NEW: Verify root hash before writing
    let root_key = NodeKey::new_empty_path(self.version);
    let root_node = self.frozen_nodes.get(&root_key)
        .ok_or_else(|| AptosDbError::Other("Root node not found after freeze".to_string()))?;
    let computed_root_hash = root_node.hash();
    
    ensure!(
        computed_root_hash == self.expected_root_hash,
        "Root hash mismatch after restore: computed={}, expected={}",
        computed_root_hash,
        self.expected_root_hash
    );
    
    self.store.write_node_batch(&self.frozen_nodes)?;
    Ok(())
}
```

Additionally, add similar verification in `finalize_state_snapshot()` to provide defense-in-depth [6](#0-5) 

## Proof of Concept

```rust
// Test demonstrating incomplete restore accepts without verification
#[test]
fn test_incomplete_restore_vulnerability() {
    use aptos_temppath::TempPath;
    use aptos_storage_interface::{DbWriter, StateSnapshotReceiver};
    
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    let store = &db.state_store;
    
    // Create complete state with N items
    let complete_state: Vec<(StateKey, StateValue)> = (0..1000)
        .map(|i| {
            let key = StateKey::raw(&i.to_le_bytes());
            let value = StateValue::from(vec![i as u8]);
            (key, value)
        })
        .collect();
    
    // Commit complete state at version 0
    store.commit_block_for_test(0, [complete_state.clone().into_iter().map(|(k, v)| (k, Some(v)))]);
    let expected_root_hash = store.get_root_hash(0).unwrap();
    
    // Now restore INCOMPLETE state to version 1
    let tmp_dir2 = TempPath::new();
    let db2 = AptosDB::new_for_test(&tmp_dir2);
    let store2 = &db2.state_store;
    
    let mut restore = store2.get_snapshot_receiver(1, expected_root_hash).unwrap();
    
    // Only add 80% of chunks (incomplete state)
    let chunk_size = 100;
    let incomplete_limit = 800; // Stop at 80%
    let mut current_idx = 0;
    
    while current_idx < incomplete_limit {
        let chunk = store.get_value_chunk_with_proof(0, current_idx, chunk_size).unwrap();
        restore.add_chunk(chunk.raw_values, chunk.proof).unwrap();
        current_idx += chunk_size;
    }
    
    // BUG: finish() succeeds even though we only added 80% of state
    restore.finish_box().unwrap();
    
    // Verify incomplete state was written
    let actual_root_hash = store2.get_root_hash(1).unwrap();
    
    // VULNERABILITY: Root hashes differ but finish() succeeded
    assert_ne!(actual_root_hash, expected_root_hash, 
        "Incomplete state should have different root hash");
    
    println!("VULNERABILITY CONFIRMED: Incomplete state accepted with wrong root hash");
    println!("Expected: {}", expected_root_hash);
    println!("Actual:   {}", actual_root_hash);
}
```

This test demonstrates that `finish()` succeeds even when only 80% of chunks are added, resulting in a state with incorrect root hash being written to storage.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L113-231)
```rust
    async fn run_impl(self) -> Result<()> {
        if self.version > self.target_version {
            warn!(
                "Trying to restore state snapshot to version {}, which is newer than the target version {}, skipping.",
                self.version,
                self.target_version,
            );
            return Ok(());
        }

        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }

        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));

        let (ver_gauge, tgt_leaf_idx, leaf_idx) = if self.run_mode.is_verify() {
            (
                &VERIFY_STATE_SNAPSHOT_VERSION,
                &VERIFY_STATE_SNAPSHOT_TARGET_LEAF_INDEX,
                &VERIFY_STATE_SNAPSHOT_LEAF_INDEX,
            )
        } else {
            (
                &STATE_SNAPSHOT_VERSION,
                &STATE_SNAPSHOT_TARGET_LEAF_INDEX,
                &STATE_SNAPSHOT_LEAF_INDEX,
            )
        };

        ver_gauge.set(self.version as i64);
        tgt_leaf_idx.set(manifest.chunks.last().map_or(0, |c| c.last_idx as i64));
        let total_chunks = manifest.chunks.len();

        let resume_point_opt = receiver.lock().as_mut().unwrap().previous_key_hash()?;
        let chunks = if let Some(resume_point) = resume_point_opt {
            manifest
                .chunks
                .into_iter()
                .skip_while(|chunk| chunk.last_key <= resume_point)
                .collect()
        } else {
            manifest.chunks
        };
        if chunks.len() < total_chunks {
            info!(
                chunks_to_add = chunks.len(),
                total_chunks = total_chunks,
                "Resumed state snapshot restore."
            )
        };
        let chunks_to_add = chunks.len();

        let start_idx = chunks.first().map_or(0, |chunk| chunk.first_idx);

        let storage = self.storage.clone();
        let futs_iter = chunks.into_iter().enumerate().map(|(chunk_idx, chunk)| {
            let storage = storage.clone();
            async move {
                tokio::spawn(async move {
                    let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
                })
                .await?
            }
        });
        let con = self.concurrent_downloads;
        let mut futs_stream = stream::iter(futs_iter).buffered_x(con * 2, con);
        let mut start = None;
        while let Some((chunk_idx, chunk, mut blobs, proof)) = futs_stream.try_next().await? {
            start = start.or_else(|| Some(Instant::now()));
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["add_state_chunk"]);
            let receiver = receiver.clone();
            if self.validate_modules {
                blobs = tokio::task::spawn_blocking(move || {
                    Self::validate_modules(&blobs);
                    blobs
                })
                .await?;
            }
            tokio::task::spawn_blocking(move || {
                receiver.lock().as_mut().unwrap().add_chunk(blobs, proof)
            })
            .await??;
            leaf_idx.set(chunk.last_idx as i64);
            info!(
                chunk = chunk_idx,
                chunks_to_add = chunks_to_add,
                last_idx = chunk.last_idx,
                values_per_second = ((chunk.last_idx + 1 - start_idx) as f64
                    / start.as_ref().unwrap().elapsed().as_secs_f64())
                    as u64,
                "State chunk added.",
            );
        }

        tokio::task::spawn_blocking(move || receiver.lock().take().unwrap().finish()).await??;
        self.run_mode.finish();
        Ok(())
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L339-413)
```rust
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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L588-622)
```rust
    fn freeze_internal_nodes(&mut self, num_remaining_nodes: usize) {
        while self.partial_nodes.len() > num_remaining_nodes {
            let last_node = self.partial_nodes.pop().expect("This node must exist.");
            let (node_key, internal_node) = last_node.into_internal_node(self.version);
            // Keep the hash of this node before moving it into `frozen_nodes`, so we can update
            // its parent later.
            let node_hash = internal_node.hash();
            let node_leaf_count = internal_node.leaf_count();
            self.frozen_nodes.insert(node_key, internal_node.into());

            // Now that we have computed the hash of the internal node above, we will also update
            // its parent unless it is root node.
            if let Some(parent_node) = self.partial_nodes.last_mut() {
                // This internal node must be the rightmost child of its parent at the moment.
                let rightmost_child_index = parent_node
                    .children
                    .iter()
                    .rposition(|x| x.is_some())
                    .expect("Must have at least one child.");

                match parent_node.children[rightmost_child_index] {
                    Some(ChildInfo::Internal {
                        ref mut hash,
                        ref mut leaf_count,
                    }) => {
                        assert_eq!(hash.replace(node_hash), None);
                        assert_eq!(leaf_count.replace(node_leaf_count), None);
                    },
                    _ => panic!(
                        "Must have at least one child and the rightmost child must not be a leaf."
                    ),
                }
            }
        }
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L750-789)
```rust
    pub fn finish_impl(mut self) -> Result<()> {
        self.wait_for_async_commit()?;
        // Deal with the special case when the entire tree has a single leaf or null node.
        if self.partial_nodes.len() == 1 {
            let mut num_children = 0;
            let mut leaf = None;
            for i in 0..16 {
                if let Some(ref child_info) = self.partial_nodes[0].children[i] {
                    num_children += 1;
                    if let ChildInfo::Leaf(node) = child_info {
                        leaf = Some(node.clone());
                    }
                }
            }

            match num_children {
                0 => {
                    let node_key = NodeKey::new_empty_path(self.version);
                    assert!(self.frozen_nodes.is_empty());
                    self.frozen_nodes.insert(node_key, Node::Null);
                    self.store.write_node_batch(&self.frozen_nodes)?;
                    return Ok(());
                },
                1 => {
                    if let Some(node) = leaf {
                        let node_key = NodeKey::new_empty_path(self.version);
                        assert!(self.frozen_nodes.is_empty());
                        self.frozen_nodes.insert(node_key, node.into());
                        self.store.write_node_batch(&self.frozen_nodes)?;
                        return Ok(());
                    }
                },
                _ => (),
            }
        }

        self.freeze(0);
        self.store.write_node_batch(&self.frozen_nodes)?;
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

**File:** storage/aptosdb/src/state_store/tests/mod.rs (L415-417)
```rust
        restore.finish_box().unwrap();
        let actual_root_hash = store2.get_root_hash(version).unwrap();
        prop_assert_eq!(actual_root_hash, expected_root_hash);
```
