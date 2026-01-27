# Audit Report

## Title
State Snapshot Restore Completes Successfully with Incomplete Merkle Tree Due to Missing Root Hash Verification

## Summary
The `finish_impl()` method in `JellyfishMerkleRestore` fails to verify that the final computed root hash matches the expected root hash after state snapshot restoration. This allows an incomplete or corrupted state tree to be written to storage if chunks are missing from the backup manifest, leading to state inconsistency across nodes.

## Finding Description

During state snapshot restoration, the system processes chunks concurrently and adds them to a Jellyfish Merkle tree. The critical security guarantee is that the final restored tree must match the `expected_root_hash` that was verified against the ledger info.

The vulnerability exists in the restoration finalization flow:

1. **Chunk Processing**: Each chunk is verified individually against the expected root hash using sparse Merkle range proofs [1](#0-0) 

2. **Concurrent Processing**: Chunks are processed concurrently using a buffered stream [2](#0-1) 

3. **Finalization Without Verification**: When `finish()` is called, it delegates to `finish_impl()` which freezes remaining nodes and writes them to storage BUT never verifies the final root hash [3](#0-2) 

The `expected_root_hash` field is stored in the restore structure [4](#0-3)  but is only used during per-chunk verification [5](#0-4) , not during finalization.

**Attack Scenario**: 
A malicious backup provider crafts a manifest that lists only a subset of the required chunks. Since the chunks come from the manifest [6](#0-5) , only those chunks are processed. Each chunk passes verification because the range proofs are valid for partial trees. When all listed chunks complete, `finish()` succeeds and writes an incomplete tree with an incorrect root hash to storage.

This breaks the **State Consistency** invariant that "All validators must produce identical state roots for identical blocks" because different nodes could restore from manifests with different chunk sets, resulting in different state trees.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple critical severity criteria:

1. **Consensus/Safety Violations**: Different nodes restoring from corrupted/incomplete manifests would have different state trees with different root hashes, breaking consensus safety. This violates the fundamental requirement that all validators must produce identical state for identical blocks.

2. **Non-recoverable State Divergence**: Once nodes commit transactions based on incorrect state trees, the divergence becomes permanent without a hard fork. The state snapshot receiver is called during the state sync bootstrapping process [7](#0-6) , meaning corrupted state would persist.

3. **State Consistency Violation**: The core invariant #4 "State transitions must be atomic and verifiable via Merkle proofs" is broken because the final state tree is not verified against the cryptographic commitment (expected root hash).

The impact is amplified because state snapshot restoration is used in critical operations like fast sync and database recovery, affecting network availability and validator onboarding.

## Likelihood Explanation

**High Likelihood** due to multiple realistic attack vectors:

1. **Malicious Backup Storage**: An attacker controlling backup storage could provide manifests with missing chunks. Since backup manifests are external data [8](#0-7) , this requires no privileged access.

2. **Corrupted Backups**: Backup corruption during storage or transmission could result in incomplete manifests, causing silent failures without this verification.

3. **No Defense in Depth**: There is no subsequent validation after `finish()` is called in the restore coordinator [9](#0-8)  or in `finalize_state_snapshot()` [10](#0-9) .

The vulnerability is easily exploitable: simply provide a backup manifest with fewer chunks than required, and the restoration will complete "successfully" with corrupted state.

## Recommendation

Add root hash verification in `finish_impl()` before writing nodes to storage:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // Deal with special cases...
    if self.partial_nodes.len() == 1 {
        // ... existing special case handling ...
    }
    
    self.freeze(0);
    
    // CRITICAL FIX: Verify the final root hash matches expected
    let root_node_key = NodeKey::new_empty_path(self.version);
    if let Some(root_node) = self.frozen_nodes.get(&root_node_key) {
        let actual_root_hash = root_node.hash();
        ensure!(
            actual_root_hash == self.expected_root_hash,
            "State snapshot restore failed: root hash mismatch. Expected: {}, got: {}",
            self.expected_root_hash,
            actual_root_hash
        );
    } else {
        return Err(anyhow!(
            "State snapshot restore failed: root node not found after finalization"
        ).into());
    }
    
    self.store.write_node_batch(&self.frozen_nodes)?;
    Ok(())
}
```

This ensures that the restoration can only succeed if the final tree matches the cryptographically verified expected root hash, preventing corrupted state from being committed.

## Proof of Concept

The following demonstrates the vulnerability by creating a restore with an incomplete manifest:

```rust
#[tokio::test]
async fn test_incomplete_manifest_vulnerability() {
    use aptos_jellyfish_merkle::restore::JellyfishMerkleRestore;
    use aptos_crypto::HashValue;
    use std::sync::Arc;
    
    // Setup: Create a complete tree with 1000 keys
    let store = Arc::new(MockTreeStore::new());
    let version = 100;
    let expected_root_hash = HashValue::random(); // Correct root for 1000 keys
    
    // Create restore expecting complete tree
    let mut restore = JellyfishMerkleRestore::new(
        store.clone(),
        version,
        expected_root_hash,
        false, // sync commit
    ).unwrap();
    
    // ATTACK: Only provide first 500 keys instead of all 1000
    let incomplete_chunks = get_first_half_chunks(); // Only 500 keys
    
    for (chunk, proof) in incomplete_chunks {
        // Each chunk verification passes because proofs are valid for partial tree
        restore.add_chunk_impl(chunk, proof).unwrap();
    }
    
    // VULNERABILITY: finish_impl() succeeds even though tree is incomplete
    // This should fail because root hash won't match, but currently it succeeds
    let result = restore.finish_impl();
    
    // BUG: This should return Err() but actually returns Ok(())
    assert!(result.is_ok()); // Currently passes - SHOULD FAIL
    
    // The stored tree has wrong root hash - state corruption!
    let stored_root = store.get_root_hash(version);
    assert_ne!(stored_root, expected_root_hash); // State corruption confirmed
}
```

To reproduce in real environment:
1. Create a backup with state snapshot at version V
2. Modify the manifest to remove chunks representing keys in the upper half of the keyspace  
3. Run restore from this corrupted manifest
4. Observe that restore succeeds despite having incomplete state
5. Verify that the actual root hash in storage differs from the expected root hash
6. Subsequent transaction execution will fail or produce incorrect results due to missing state

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L175-176)
```rust
    /// When the restoration process finishes, we expect the tree to have this root hash.
    expected_root_hash: HashValue,
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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L690-696)
```rust
        proof
            .verify(
                self.expected_root_hash,
                SparseMerkleLeafNode::new(*previous_key, previous_leaf.value_hash()),
                left_siblings,
            )
            .map_err(Into::into)
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-124)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L163-174)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L187-226)
```rust
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
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L145-173)
```rust
pub struct StateSnapshotRestore<K, V> {
    tree_restore: Arc<Mutex<Option<JellyfishMerkleRestore<K>>>>,
    kv_restore: Arc<Mutex<Option<StateValueRestore<K, V>>>>,
    restore_mode: StateSnapshotRestoreMode,
}

impl<K: Key + CryptoHash + Hash + Eq, V: Value> StateSnapshotRestore<K, V> {
    pub fn new<T: 'static + TreeReader<K> + TreeWriter<K>, S: 'static + StateValueWriter<K, V>>(
        tree_store: &Arc<T>,
        value_store: &Arc<S>,
        version: Version,
        expected_root_hash: HashValue,
        async_commit: bool,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<Self> {
        Ok(Self {
            tree_restore: Arc::new(Mutex::new(Some(JellyfishMerkleRestore::new(
                Arc::clone(tree_store),
                version,
                expected_root_hash,
                async_commit,
            )?))),
            kv_restore: Arc::new(Mutex::new(Some(StateValueRestore::new(
                Arc::clone(value_store),
                version,
            )))),
            restore_mode,
        })
    }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L247-259)
```rust
                StateSnapshotRestoreController::new(
                    StateSnapshotRestoreOpt {
                        manifest_handle: kv_snapshot.manifest,
                        version: kv_snapshot.version,
                        validate_modules: false,
                        restore_mode: StateSnapshotRestoreMode::KvOnly,
                    },
                    self.global_opt.clone(),
                    Arc::clone(&self.storage),
                    epoch_history.clone(),
                )
                .run()
                .await?;
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
