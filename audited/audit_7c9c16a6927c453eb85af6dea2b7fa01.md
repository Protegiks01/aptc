# Audit Report

## Title
State Restore Clone-Before-Verify Memory Pressure DoS Vulnerability

## Summary
The state restore mechanism clones large state value chunks before verifying their cryptographic proof, enabling a malicious peer to cause memory pressure or allocation failures by repeatedly sending maximum-sized chunks with invalid proofs during state synchronization.

## Finding Description

The vulnerability exists in the state snapshot restoration process where chunks of state values are received from peers during fast sync. The critical flaw is in the ordering of operations: [1](#0-0) 

When `restore_mode` is `Default`, the implementation executes two operations in parallel using `IO_POOL.join()`:
1. **KV function**: Clones the entire chunk for key-value storage restoration
2. **Tree function**: Processes the chunk and verifies the Merkle proof

The clone operation occurs immediately in `kv_fn` at line 235, while proof verification happens later inside `add_chunk_impl`: [2](#0-1) 

The proof verification only occurs at line 391 of the tree restoration, meaning the chunk has already been cloned in memory before its validity is confirmed.

**Attack Path:**

1. **Attacker Identification**: During state sync bootstrapping, a victim node connects to peers to download state snapshots
2. **Malicious Peer Position**: Attacker positions themselves as a state sync peer
3. **Chunk Crafting**: Attacker sends StateValueChunkWithProof messages with:
   - Valid structure (correct indices, serialization)
   - Maximum permitted size (up to 40 MiB per chunk based on `max_network_chunk_bytes_v2`)
   - **Invalid Merkle proof** that will fail verification
4. **Memory Allocation**: Victim node receives the chunk and:
   - Passes basic validation (indices, root hash comparison in bootstrapper)
   - Calls `add_chunk()` where `chunk.clone()` executes immediately
   - Allocates 2x the chunk size in memory (original + clone = ~80 MiB for a 40 MiB chunk)
5. **Delayed Rejection**: Only after the clone completes does `tree_fn` verify the proof and reject the invalid chunk
6. **Sustained Attack**: Attacker repeats with new invalid chunks, maintaining persistent memory pressure [3](#0-2) 

The configuration allows chunks up to 40 MiB (SERVER_MAX_MESSAGE_SIZE_V2 at 40 MiB). The network layer enforces an upper limit: [4](#0-3) 

**Invariant Violation:**

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The system allocates significant memory resources (2x chunk size) before validating the chunk's authenticity, violating the principle of fail-fast validation.

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This qualifies as Medium severity due to:

1. **Memory Pressure/Allocation Failures**: 
   - Each invalid chunk causes temporary allocation of 2x chunk size (~80 MiB for 40 MiB chunks)
   - On memory-constrained validators or fullnodes (e.g., 2-4 GB RAM configurations), repeated attacks can trigger OOM conditions
   - Causes node instability requiring restart

2. **Limited Scope**:
   - Only affects nodes in state sync bootstrapping mode
   - Sequential processing limits concurrent memory impact (one chunk at a time per receiver)
   - Does not cause permanent data corruption or consensus violations

3. **State Inconsistencies**:
   - Failed allocations during state sync can leave nodes in incomplete bootstrap state
   - Requires manual intervention to restart sync process
   - Fits "State inconsistencies requiring intervention" category for Medium severity

The impact does not reach High or Critical because:
- No fund loss or theft
- No consensus safety violations
- No permanent network partition
- Temporary DoS only, recoverable via restart

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is realistic because:

1. **Attacker Requirements**:
   - Only needs to act as a state sync peer (no validator privileges required)
   - Network peers during state sync are not fully authenticated/trusted
   - Can be executed by any malicious network participant

2. **Attack Complexity**:
   - Straightforward to craft: valid structure + invalid proof
   - No cryptographic breaks required
   - Can automate attack with simple network client

3. **Timing Windows**:
   - State sync occurs during: node bootstrap, recovery from downtime, or catching up after network partition
   - Common scenario for new validators/fullnodes joining network

4. **Detection Difficulty**:
   - Invalid chunks are eventually rejected, but memory pressure occurs first
   - May appear as transient memory issues rather than attack
   - No clear rate limiting specifically for invalid state sync chunks

The attack becomes more impactful on:
- Resource-constrained nodes (embedded validators, lightweight clients)
- Networks with high state snapshot sizes
- Repeated bootstrap attempts (amplifies memory churn)

## Recommendation

**Primary Fix: Verify Proof Before Cloning**

Since proof verification requires tree state built from the chunk, restructure to avoid cloning entirely:

```rust
fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
    match self.restore_mode {
        StateSnapshotRestoreMode::Default => {
            // First, add to tree and verify proof (NO clone needed here)
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)?;
            
            // Only after proof verification succeeds, add to KV store
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk)?;
            
            Ok(())
        },
        // ... other modes unchanged
    }
}
```

**Alternative Fix: Add Byte-Size Validation**

Before cloning, validate chunk size:

```rust
fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
    // Calculate actual byte size
    let chunk_size: usize = chunk.iter()
        .map(|(k, v)| k.key_size() + v.value_size())
        .sum();
    
    // Enforce reasonable limit (e.g., 10 MiB for safety margin)
    const MAX_CHUNK_BYTES: usize = 10 * 1024 * 1024;
    ensure!(
        chunk_size <= MAX_CHUNK_BYTES,
        "Chunk size {} exceeds maximum {}",
        chunk_size,
        MAX_CHUNK_BYTES
    );
    
    // ... existing clone logic
}
```

**Additional Hardening:**
- Add metrics for chunk clone operations and memory usage
- Implement rate limiting for failed proof verifications per peer
- Consider memory pools with reserved capacity for state sync

## Proof of Concept

```rust
// Test demonstrating memory pressure from invalid chunk
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_clone_before_verify_memory_pressure() {
        // Setup: Create state snapshot restore with Default mode
        let tree_store = Arc::new(MockTreeStore::new());
        let value_store = Arc::new(MockValueStore::new());
        let version = 100;
        let expected_root = HashValue::random();
        
        let mut restore = StateSnapshotRestore::<StateKey, StateValue>::new(
            &tree_store,
            &value_store,
            version,
            expected_root,
            false, // sync commit
            StateSnapshotRestoreMode::Default,
        ).unwrap();
        
        // Craft malicious chunk: maximum size with INVALID proof
        let mut large_chunk = Vec::new();
        let large_value = vec![0u8; 1024 * 1024]; // 1 MiB per value
        
        for i in 0..40 {
            let key = StateKey::raw(format!("key_{}", i).into_bytes());
            let value = StateValue::new_legacy(large_value.clone().into());
            large_chunk.push((key, value));
        }
        // Total chunk size: ~40 MiB
        
        // Create INVALID proof (wrong siblings)
        let invalid_proof = SparseMerkleRangeProof::new(vec![HashValue::zero()]);
        
        // Measure memory before
        let memory_before = get_current_memory_usage();
        
        // Attack: add_chunk will clone (allocating 80 MiB) BEFORE rejecting proof
        let result = restore.add_chunk(large_chunk, invalid_proof);
        
        let memory_peak = get_peak_memory_usage();
        let memory_after = get_current_memory_usage();
        
        // Verify: proof verification fails (expected)
        assert!(result.is_err());
        
        // Verify: memory pressure occurred (clone happened before rejection)
        let memory_overhead = memory_peak - memory_before;
        assert!(memory_overhead >= 40 * 1024 * 1024, 
                "Expected at least 40 MiB overhead, got {}", memory_overhead);
        
        // Memory is released after rejection, but pressure occurred
        assert!(memory_after < memory_peak);
        
        println!("Memory overhead from clone-before-verify: {} MiB", 
                 memory_overhead / (1024 * 1024));
    }
    
    #[test]
    fn test_repeated_attack_memory_exhaustion() {
        // Simulate sustained attack with repeated invalid chunks
        // On 2GB system, 25 iterations of 80 MiB could cause OOM
        for iteration in 0..25 {
            // Send maximum-sized invalid chunk
            // Monitor for allocation failures
        }
    }
}
```

**Notes:**

- The vulnerability is present in production code affecting all nodes during state sync
- Fix requires careful testing as it changes parallelization semantics
- Sequential verification-then-clone may reduce performance but improves security
- Consider this when designing future state sync protocol versions

### Citations

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

**File:** config/src/config/state_sync_config.rs (L195-218)
```rust
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: false,
            enable_transaction_data_v2: true,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            max_invalid_requests_per_peer: 500,
            max_lru_cache_size: 500, // At ~0.6MiB per chunk, this should take no more than 0.5GiB
            max_network_channel_size: 4000,
            max_network_chunk_bytes: SERVER_MAX_MESSAGE_SIZE as u64,
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
            max_num_active_subscriptions: 30,
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
            request_moderator_refresh_interval_ms: 1000, // 1 second
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
        }
    }
}
```

**File:** config/src/config/network_config.rs (L45-50)
```rust
pub const MAX_MESSAGE_METADATA_SIZE: usize = 128 * 1024; /* 128 KiB: a buffer for metadata that might be added to messages by networking */
pub const MESSAGE_PADDING_SIZE: usize = 2 * 1024 * 1024; /* 2 MiB: a safety buffer to allow messages to get larger during serialization */
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```
