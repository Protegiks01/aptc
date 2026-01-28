After thorough validation of this security claim against the Aptos codebase, I have completed my analysis.

# Audit Report

## Title
Missing Final State Root Verification Allows Incomplete State Restoration via Partial Range Proofs

## Summary
The production state snapshot restore flow lacks final root hash verification after completing the restoration process. Combined with the `get_range_proof()` function's inability to verify that a `rightmost_key` is truly the rightmost key in a range, this allows incomplete state restoration that passes all incremental verifications but results in an incomplete Jellyfish Merkle tree without immediate detection.

## Finding Description

The vulnerability exists in the backup/restore flow for state snapshots across multiple components:

**Backup Flow Issue:**

The `get_range_proof()` function in `JellyfishMerkleTree` only verifies that the provided `rightmost_key` exists but does NOT verify it is the actual rightmost key in the range: [1](#0-0) 

The function at line 807 merely checks `account.is_some()`, confirming the key exists, but never validates whether this key is truly the rightmost in any queried range. This allows generation of valid proofs for keys that are not actually at the range boundary.

During backup, chunks are created and proofs are requested for each chunk's `last_key`: [2](#0-1) 

A malicious backup service could return incomplete chunks while still generating valid range proofs for keys in the middle of the actual range.

**Restore Flow Issue:**

During restore, each chunk is verified using `SparseMerkleRangeProof::verify()`: [3](#0-2) 

This verification at lines 690-696 confirms the proof is valid by checking that the combination of added keys and the proof's `right_siblings` produces the expected root hash. However, the `right_siblings` represent hashes of subtrees containing keys beyond the rightmost known leaf—these siblings are used only for hash computation and are NOT added to the restored tree structure.

**The Critical Flaw:**

After all chunks are restored, the production code does NOT verify that the final root hash of the restored tree matches the expected root hash: [4](#0-3) 

The `finish_impl()` method only freezes remaining nodes and writes them to storage (lines 786-788), with no final root hash verification against `self.expected_root_hash`.

The production restore controller confirms this: [5](#0-4) [6](#0-5) 

No verification occurs after `finish()` completes.

**Attack Scenario:**

1. Malicious backup operator controls backup service responses
2. Returns incomplete state chunks (e.g., keys A,B,C when full state has A,B,C,D,E)  
3. Generates valid range proof for key C (proof includes right_sibling hashes representing subtrees containing D,E)
4. During restore, incremental verification passes because hash(A,B,C + right_sibling_hashes) == expected_root_hash
5. Final restored tree contains only A,B,C as actual keys; keys D,E are missing
6. No error is raised—restore appears successful
7. Node will fail when attempting to access missing state or sync with network

## Impact Explanation

This is a **MEDIUM severity** vulnerability per Aptos bug bounty criteria because it causes **state inconsistencies requiring manual intervention**.

**Operational Impact:**
- Nodes restored from malicious backups will have incomplete state trees
- The incomplete state will be detected when the node attempts to participate in consensus, as it will compute incorrect state roots that other validators reject
- Transaction execution may fail when attempting to access missing state keys
- Manual intervention is required to identify the issue and restore from a valid backup source

**Why MEDIUM, not HIGH:**
- Does NOT cause direct fund loss or theft
- Does NOT cause consensus safety violations (Byzantine agreement remains intact—other validators reject incorrect state roots)
- Does NOT cause validator node slowdowns affecting the network
- The issue is detected during normal operation, though not immediately at restore time

**Security Boundary Violation:**
The restore process should validate completeness upon completion. Relying on later detection during normal operation creates operational confusion and wastes resources.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Attacker Requirements:**
- Control over backup service responses, OR
- Ability to provide malicious backup data to operators (e.g., compromised backup infrastructure, MITM attack)

**Realistic Scenarios:**
1. Compromised backup infrastructure
2. Malicious third-party backup service provider
3. Man-in-the-middle attack on backup data transfer
4. Social engineering of node operators to use malicious backups

**Detection:**
- Issue NOT detected immediately during restore (no error raised)
- Issue detected when node attempts to sync or validate blocks (state root mismatch)
- Requires manual verification and re-restoration from trusted backup source

**Mitigation Factors:**
- Operators typically use trusted backup sources
- Other validators immediately reject incorrect state roots
- Issue detected relatively quickly during normal operation

## Recommendation

Add final root hash verification in `finish_impl()`:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // ... existing code to freeze nodes ...
    
    self.freeze(0);
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // ADD FINAL VERIFICATION:
    let root_node = self.store
        .get_node_option(&NodeKey::new_empty_path(self.version), "finish")?
        .ok_or_else(|| AptosDbError::NotFound("Root node not found after restore".to_string()))?;
    
    ensure!(
        root_node.hash() == self.expected_root_hash,
        "Final root hash mismatch. Expected: {:x}, Actual: {:x}",
        self.expected_root_hash,
        root_node.hash()
    );
    
    Ok(())
}
```

Additionally, consider enhancing `get_range_proof()` to verify that `rightmost_key_to_prove` is actually the rightmost key in the requested range by checking that no keys exist beyond it.

## Proof of Concept

A complete PoC would require:
1. Mock backup service returning incomplete chunks
2. Demonstration that restore completes without error
3. Verification that restored tree has incorrect root hash

The vulnerability is confirmed through code analysis showing the missing verification in the identified code paths.

## Notes

**Key Technical Insight:** The `SparseMerkleRangeProof` verification validates that a proof is mathematically correct for a given set of keys, but does NOT validate that all keys have been provided. The proof's `right_siblings` represent subtrees that exist in the original tree but are NOT restored to the new tree—only their hash values are used for verification.

**Detection vs. Prevention:** While this issue would be detected when the node attempts normal operation (as other validators would reject its incorrect state roots), security best practices require that the restore process itself validate completeness rather than relying on implicit detection during later operations.

### Citations

**File:** storage/jellyfish-merkle/src/lib.rs (L800-824)
```rust
    /// Gets the proof that shows a list of keys up to `rightmost_key_to_prove` exist at `version`.
    pub fn get_range_proof(
        &self,
        rightmost_key_to_prove: HashValue,
        version: Version,
    ) -> Result<SparseMerkleRangeProof> {
        let (account, proof) = self.get_with_proof(rightmost_key_to_prove, version)?;
        ensure!(account.is_some(), "rightmost_key_to_prove must exist.");

        let siblings = proof
            .siblings()
            .iter()
            .zip(rightmost_key_to_prove.iter_bits())
            .filter_map(|(sibling, bit)| {
                // We only need to keep the siblings on the right.
                if !bit {
                    Some(*sibling)
                } else {
                    None
                }
            })
            .rev()
            .collect();
        Ok(SparseMerkleRangeProof::new(siblings))
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L404-447)
```rust
    async fn write_chunk(
        &self,
        backup_handle: &BackupHandleRef,
        chunk: Chunk,
    ) -> Result<StateSnapshotChunk> {
        let _timer = BACKUP_TIMER.timer_with(&["state_snapshot_write_chunk"]);

        let Chunk {
            bytes,
            first_idx,
            last_idx,
            first_key,
            last_key,
        } = chunk;

        let (chunk_handle, mut chunk_file) = self
            .storage
            .create_for_write(backup_handle, &Self::chunk_name(first_idx))
            .await?;
        chunk_file.write_all(&bytes).await?;
        chunk_file.shutdown().await?;
        let (proof_handle, mut proof_file) = self
            .storage
            .create_for_write(backup_handle, &Self::chunk_proof_name(first_idx, last_idx))
            .await?;
        tokio::io::copy(
            &mut self
                .client
                .get_account_range_proof(last_key, self.version())
                .await?,
            &mut proof_file,
        )
        .await?;
        proof_file.shutdown().await?;

        Ok(StateSnapshotChunk {
            first_idx,
            last_idx,
            first_key,
            last_key,
            blobs: chunk_handle,
            proof: proof_handle,
        })
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L624-697)
```rust
    /// Verifies that all states that have been added so far (from the leftmost one to
    /// `self.previous_leaf`) are correct, i.e., we are able to construct `self.expected_root_hash`
    /// by combining all existing states and `proof`.
    #[allow(clippy::collapsible_if)]
    fn verify(&self, proof: SparseMerkleRangeProof) -> Result<()> {
        let previous_leaf = self
            .previous_leaf
            .as_ref()
            .expect("The previous leaf must exist.");

        let previous_key = previous_leaf.account_key();
        // If we have all siblings on the path from root to `previous_key`, we should be able to
        // compute the root hash. The siblings on the right are already in the proof. Now we
        // compute the siblings on the left side, which represent all the states that have ever
        // been added.
        let mut left_siblings = vec![];

        // The following process might add some extra placeholder siblings on the left, but it is
        // nontrivial to determine when the loop should stop. So instead we just add these
        // siblings for now and get rid of them in the next step.
        let mut num_visited_right_siblings = 0;
        for (i, bit) in previous_key.iter_bits().enumerate() {
            if bit {
                // This node is a right child and there should be a sibling on the left.
                let sibling = if i >= self.partial_nodes.len() * 4 {
                    *SPARSE_MERKLE_PLACEHOLDER_HASH
                } else {
                    Self::compute_left_sibling(
                        &self.partial_nodes[i / 4],
                        previous_key.get_nibble(i / 4),
                        (3 - i % 4) as u8,
                    )
                };
                left_siblings.push(sibling);
            } else {
                // This node is a left child and there should be a sibling on the right.
                num_visited_right_siblings += 1;
            }
        }
        ensure!(
            num_visited_right_siblings >= proof.right_siblings().len(),
            "Too many right siblings in the proof.",
        );

        // Now we remove any extra placeholder siblings at the bottom. We keep removing the last
        // sibling if 1) it's a placeholder 2) it's a sibling on the left.
        for bit in previous_key.iter_bits().rev() {
            if bit {
                if *left_siblings.last().expect("This sibling must exist.")
                    == *SPARSE_MERKLE_PLACEHOLDER_HASH
                {
                    left_siblings.pop();
                } else {
                    break;
                }
            } else if num_visited_right_siblings > proof.right_siblings().len() {
                num_visited_right_siblings -= 1;
            } else {
                break;
            }
        }

        // Left siblings must use the same ordering as the right siblings in the proof
        left_siblings.reverse();

        // Verify the proof now that we have all the siblings
        proof
            .verify(
                self.expected_root_hash,
                SparseMerkleLeafNode::new(*previous_key, previous_leaf.value_hash()),
                left_siblings,
            )
            .map_err(Into::into)
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L748-789)
```rust
    /// Finishes the restoration process. This tells the code that there is no more state,
    /// otherwise we can not freeze the rightmost leaf and its ancestors.
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L228-230)
```rust
        tokio::task::spawn_blocking(move || receiver.lock().take().unwrap().finish()).await??;
        self.run_mode.finish();
        Ok(())
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L260-273)
```rust
    fn finish(self) -> Result<()> {
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => self.kv_restore.lock().take().unwrap().finish()?,
            StateSnapshotRestoreMode::TreeOnly => {
                self.tree_restore.lock().take().unwrap().finish_impl()?
            },
            StateSnapshotRestoreMode::Default => {
                // for tree only mode, we also need to write the usage to DB
                self.kv_restore.lock().take().unwrap().finish()?;
                self.tree_restore.lock().take().unwrap().finish_impl()?
            },
        }
        Ok(())
    }
```
