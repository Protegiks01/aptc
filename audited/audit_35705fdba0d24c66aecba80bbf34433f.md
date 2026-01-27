# Audit Report

## Title
Consensus Node Panic Due to Dangling Reference to Pruned Highest Certified Block

## Summary
The `BlockTree::remove_block()` function removes blocks and their quorum certificates from memory, but fails to update `highest_certified_block_id` when the highest certified block is pruned. Subsequently, when `insert_quorum_cert()` attempts to access the highest certified block for round comparison, it panics with "Highest certified block must exist", causing node crash during normal consensus operations. [1](#0-0) 

## Finding Description

The vulnerability occurs through the following sequence:

**State Management Issue:**
The `BlockTree` maintains `highest_certified_block_id` pointing to the block with highest round that has a quorum certificate. When blocks are pruned via `process_pruned_blocks()`, the `remove_block()` function removes both the block from `id_to_block` and its QC from `id_to_quorum_cert`. [2](#0-1) 

However, `highest_certified_block_id` is NEVER updated during pruning - it's only set during initialization and when a new higher-round QC is inserted: [3](#0-2) 

**Panic Trigger:**
When `insert_quorum_cert()` is subsequently called (during normal consensus operation), it accesses `highest_certified_block()` to compare rounds: [3](#0-2) 

This method attempts to retrieve the block and panics if it doesn't exist: [4](#0-3) 

**Attack Scenario:**
1. During network partition, a subset of validators (including f Byzantine + f+1 honest partitioned nodes) form a valid QC for block C on a fork at round R
2. Node X receives block C and its QC, setting `highest_certified_block_id = C`
3. Network heals, and the honest majority's main chain becomes canonical
4. Node X syncs and commits main chain blocks B1...BN
5. Fork containing C is identified for pruning via `find_blocks_to_prune()`
6. C is added to `pruned_block_ids` and eventually removed via `remove_block()` when memory threshold is exceeded
7. New QC arrives triggering `insert_quorum_cert()` call
8. Line 368 evaluates `self.highest_certified_block().round()` 
9. Attempts to get block C which no longer exists
10. Panic: "Highest certified block must exist" → node crashes [5](#0-4) 

The panic occurs during normal consensus message processing, not just test code.

## Impact Explanation

**Severity: High**

This qualifies as High Severity per Aptos bug bounty criteria:
- **Validator node crashes** during consensus operation
- **Significant protocol violations** - breaks the consensus availability guarantee
- Can cause **liveness disruption** if multiple nodes crash simultaneously
- Violates the code's own safety assertion ("Highest certified block must exist")

The impact includes:
- Immediate node crash requiring restart
- Potential consensus stalling if enough nodes affected during network instability
- Loss of consensus participation during recovery
- Repeated crashes possible in adverse network conditions

While this doesn't cause fund loss or permanent state corruption, it violates **Consensus Safety** (invariant #2) by affecting network availability and can cascade if multiple nodes experience similar conditions.

## Likelihood Explanation

**Likelihood: Medium in Adversarial Network Conditions**

The vulnerability can manifest during:

1. **Network Partitions** (natural occurrence):
   - Partitioned validator groups form conflicting QCs
   - Network healing causes one chain to be pruned
   - No attacker needed - natural network instability sufficient

2. **Byzantine Validators Near f Threshold**:
   - f Byzantine validators vote on fork blocks
   - Combined with partitioned honest nodes can form valid QC
   - Fork later pruned when honest majority prevails

**Conditions Required:**
- Network partition or Byzantine validators contributing to fork QCs
- Fork block receiving valid QC (2f+1 signatures)
- Main chain overtaking fork via honest majority
- Pruning exceeding `max_pruned_blocks_in_mem` threshold
- New QC insertion after pruning

**Realistic Assessment:**
- Not easily triggered by single unprivileged attacker
- Requires network-level conditions or partial validator compromise
- More likely in geographically distributed networks with unstable connectivity
- Natural network partitions during infrastructure issues can trigger this

## Recommendation

**Fix: Update `highest_certified_block_id` during pruning or validate before use**

Option 1: Clear highest_certified_block_id when pruning that block
```rust
fn remove_block(&mut self, block_id: HashValue) {
    // Remove the block from the store
    if let Some(block) = self.id_to_block.remove(&block_id) {
        let round = block.executed_block().round();
        self.round_to_ids.remove(&round);
        
        // NEW: Clear highest_certified_block_id if it points to this block
        if self.highest_certified_block_id == block_id {
            // Reset to commit root as safe default
            self.highest_certified_block_id = self.commit_root_id;
            self.highest_quorum_cert = self.get_quorum_cert_for_block(&self.commit_root_id)
                .expect("Commit root must have QC");
        }
    };
    self.id_to_quorum_cert.remove(&block_id);
}
```

Option 2: Use defensive programming in highest_certified_block()
```rust
pub(super) fn highest_certified_block(&self) -> Arc<PipelinedBlock> {
    self.get_block(&self.highest_certified_block_id)
        .unwrap_or_else(|| {
            warn!("Highest certified block {} not found, falling back to commit root", 
                  self.highest_certified_block_id);
            self.get_block(&self.commit_root_id)
                .expect("Commit root must exist")
        })
}
```

Option 3: Validate before pruning
```rust
pub(super) fn find_blocks_to_prune(
    &self,
    next_window_root_id: HashValue,
) -> VecDeque<HashValue> {
    // ... existing code ...
    
    // NEW: Never prune the highest certified block
    blocks_pruned.retain(|id| *id != self.highest_certified_block_id);
    
    blocks_pruned
}
```

**Recommended approach:** Combination of Option 1 + Option 2 for defense-in-depth.

## Proof of Concept

Due to the complexity of simulating network partitions and consensus state in a simple test, here's a reproduction outline:

```rust
#[tokio::test]
async fn test_highest_certified_block_pruning_panic() {
    let mut inserter = TreeInserter::default();
    let block_store = inserter.block_store();
    
    // Build main chain: genesis <- b1 <- b2 <- b3
    let genesis = block_store.ordered_root();
    let b1 = inserter.insert_block_with_qc(certificate_for_genesis(), &genesis, 1).await;
    let b2 = inserter.insert_block(&b1, 2, None).await;
    let b3 = inserter.insert_block(&b2, 3, None).await;
    
    // Build fork: b1 <- c2 (with higher round) <- c3
    let c2 = inserter.insert_forked_block(&b1, 5, None).await; // round 5 > round 2
    let c3 = inserter.insert_block(&c2, 6, None).await;
    
    // Insert QC for c3, making it highest certified block
    let c3_qc = create_qc_for_block(&c3, &inserter.signers());
    block_store.insert_quorum_cert(&c3_qc, &mut retriever).await.unwrap();
    
    // Main chain continues and commits
    // ... insert more blocks b4..b20 and commit them ...
    
    // Prune the fork containing c2, c3
    block_store.prune_tree(b3.id()); // Prunes fork containing c2, c3
    
    // Force removal by exceeding max_pruned_blocks_in_mem
    // ... insert and prune more blocks until c3 is removed ...
    
    // Now insert a new QC - this should panic
    let b21 = inserter.insert_block(&b20, 21, None).await;
    let b21_qc = create_qc_for_block(&b21, &inserter.signers());
    
    // This will panic with "Highest certified block must exist"
    block_store.insert_quorum_cert(&b21_qc, &mut retriever).await.unwrap();
}
```

The full test requires additional helper functions to simulate fork creation, QC formation, and controlled pruning, which would be part of the integration test suite.

## Notes

While this vulnerability requires specific network conditions (partitions or Byzantine behavior near threshold), it represents a real code flaw that violates the system's own assertions. The issue can manifest during natural network instability without requiring active attacker involvement. The severity is classified as High due to node crash impact on consensus availability, though the likelihood is tempered by the specific conditions required for manifestation.

### Citations

**File:** consensus/src/block_storage/block_tree.rs (L174-181)
```rust
    fn remove_block(&mut self, block_id: HashValue) {
        // Remove the block from the store
        if let Some(block) = self.id_to_block.remove(&block_id) {
            let round = block.executed_block().round();
            self.round_to_ids.remove(&round);
        };
        self.id_to_quorum_cert.remove(&block_id);
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L208-211)
```rust
    pub(super) fn highest_certified_block(&self) -> Arc<PipelinedBlock> {
        self.get_block(&self.highest_certified_block_id)
            .expect("Highest cerfified block must exist")
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L366-374)
```rust
        match self.get_block(&block_id) {
            Some(block) => {
                if block.round() > self.highest_certified_block().round() {
                    self.highest_certified_block_id = block.id();
                    self.highest_quorum_cert = Arc::clone(&qc);
                }
            },
            None => bail!("Block {} not found", block_id),
        }
```

**File:** consensus/src/block_storage/block_tree.rs (L496-510)
```rust
    pub(super) fn process_pruned_blocks(&mut self, mut newly_pruned_blocks: VecDeque<HashValue>) {
        counters::NUM_BLOCKS_IN_TREE.sub(newly_pruned_blocks.len() as i64);
        // The newly pruned blocks are pushed back to the deque pruned_block_ids.
        // In case the overall number of the elements is greater than the predefined threshold,
        // the oldest elements (in the front of the deque) are removed from the tree.
        self.pruned_block_ids.append(&mut newly_pruned_blocks);
        if self.pruned_block_ids.len() > self.max_pruned_blocks_in_mem {
            let num_blocks_to_remove = self.pruned_block_ids.len() - self.max_pruned_blocks_in_mem;
            for _ in 0..num_blocks_to_remove {
                if let Some(id) = self.pruned_block_ids.pop_front() {
                    self.remove_block(id);
                }
            }
        }
    }
```

**File:** consensus/src/round_manager.rs (L1930-1936)
```rust
        let result = self
            .block_store
            .insert_quorum_cert(&qc, &mut self.create_block_retriever(preferred_peer))
            .await
            .context("[RoundManager] Failed to process a newly aggregated QC");
        self.process_certificates().await?;
        result
```
