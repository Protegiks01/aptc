# Audit Report

## Title
Unbounded Memory Allocation in Block Tree Pruning Process

## Summary
The `find_blocks_to_prune()` function in the consensus block storage creates a VecDeque without capacity limits that grows linearly with the number of blocks being pruned. In Byzantine scenarios with delayed commits, this can accumulate millions of block IDs, consuming hundreds of megabytes of memory and potentially causing validator node crashes. [1](#0-0) 

## Finding Description
The vulnerability exists in the block tree pruning mechanism. When blocks are committed, the system must prune old blocks from the tree to maintain memory efficiency. The `find_blocks_to_prune()` function traverses all blocks from the old window root to the new window root, collecting their IDs into a VecDeque for removal.

**Critical Code Path:**

The pruning process begins when a block is committed via `commit_callback()`: [2](#0-1) 

The VecDeque `blocks_pruned` is created without any capacity limits and grows unboundedly as blocks are traversed. Each block inserted into the consensus tree remains until pruning occurs. Byzantine validators (up to f < n/3) can propose multiple equivocating blocks per round, which are all stored: [3](#0-2) 

Notice that equivocating blocks (multiple blocks per round) are accepted and stored with only a warning, not rejected. The validation only checks that the block round is greater than the ordered root round: [4](#0-3) 

**Attack Scenario:**

1. Byzantine validators (< n/3) continuously propose blocks across many rounds
2. Multiple equivocating blocks per round are stored in the tree
3. If commits are delayed due to network issues or Byzantine interference with consensus, blocks accumulate
4. When pruning finally occurs, all accumulated blocks are loaded into the unbounded VecDeque
5. Memory consumption spikes, potentially triggering OOM conditions

**Memory Calculation:**
- HashValue size: 32 bytes per block ID [5](#0-4) 
- VecDeque overhead: ~8-16 bytes per element
- Total: ~40-50 bytes per block
- 1 million blocks = ~40-50 MB
- 10 million blocks = ~400-500 MB (approaching OOM on constrained systems)

The expected number of blocks in normal operation is 3-4, but there is no hard limit: [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria:

- **Validator Node Slowdowns**: The memory spike during pruning can cause significant performance degradation
- **Temporary DoS**: In extreme cases, OOM conditions could crash validator nodes, requiring restart
- **State Inconsistencies**: While not permanent, node crashes during critical consensus operations could temporarily affect network stability

This is not Critical because:
- No funds are at risk
- Consensus safety is not directly violated (no double-spends or forks)
- The issue is recoverable through node restart
- Requires Byzantine behavior combined with liveness delays

However, it exceeds Low severity because:
- Can cause measurable operational impact on validators
- Exploitable in realistic Byzantine scenarios (< n/3 adversaries)
- No explicit protection against this resource exhaustion

## Likelihood Explanation
**Likelihood: Medium to Low**

This vulnerability requires specific conditions:
1. **Byzantine validators** (< n/3) must continuously propose blocks
2. **Delayed commits** due to network partitions or consensus delays
3. **Extended duration** for blocks to accumulate (hours to days)
4. **Accumulation** of millions of blocks before pruning

While AptosBFT is designed to maintain liveness and regular commits, network partitions and Byzantine attacks can delay commits temporarily. During these periods, blocks accumulate. The attack is:
- Feasible within the BFT threat model (< n/3 Byzantine validators)
- Not immediately detectable as blocks appear legitimate (validly signed)
- More likely during network instability or epoch transitions
- Realistic in adversarial scenarios targeting network availability

The default `max_pruned_blocks_in_mem` is only 100, but this limit applies AFTER pruning, not during: [7](#0-6) 

## Recommendation
Implement a capacity limit on the VecDeque in `find_blocks_to_prune()` to prevent unbounded growth:

```rust
pub(super) fn find_blocks_to_prune(
    &self,
    next_window_root_id: HashValue,
) -> VecDeque<HashValue> {
    if next_window_root_id == self.window_root_id {
        return VecDeque::new();
    }

    // Add maximum blocks to prune per operation to prevent memory exhaustion
    const MAX_BLOCKS_TO_PRUNE: usize = 100_000;
    let mut blocks_pruned = VecDeque::with_capacity(MAX_BLOCKS_TO_PRUNE.min(1024));
    let mut blocks_to_be_pruned = vec![self.linkable_window_root()];

    while let Some(block_to_remove) = blocks_to_be_pruned.pop() {
        // Safety check to prevent unbounded growth
        if blocks_pruned.len() >= MAX_BLOCKS_TO_PRUNE {
            warn!(
                "Pruning limit reached: {} blocks. This may indicate Byzantine behavior or extended liveness failure.",
                MAX_BLOCKS_TO_PRUNE
            );
            break;
        }
        
        block_to_remove.executed_block().abort_pipeline();
        for child_id in block_to_remove.children() {
            if next_window_root_id == *child_id {
                continue;
            }
            blocks_to_be_pruned.push(
                self.get_linkable_block(child_id)
                    .expect("Child must exist in the tree"),
            );
        }
        blocks_pruned.push_back(block_to_remove.id());
    }
    blocks_pruned
}
```

Additionally, implement monitoring and alerting when abnormally large numbers of blocks are detected in the tree.

## Proof of Concept
```rust
#[test]
fn test_unbounded_vecdeque_in_pruning() {
    use consensus::block_storage::block_tree::BlockTree;
    use consensus_types::block::Block;
    
    // Setup: Create a block tree
    let (commit_root, window_root, qc, ordered_cert, commit_cert) = setup_test_tree();
    let mut block_tree = BlockTree::new(
        commit_root.id(),
        window_root,
        qc,
        ordered_cert,
        commit_cert,
        100, // max_pruned_blocks_in_mem
        None, // no timeout cert
    );
    
    // Attack: Insert many equivocating blocks across multiple rounds
    // Simulating Byzantine validators proposing multiple blocks per round
    let mut parent_id = commit_root.id();
    const ROUNDS: usize = 1000;
    const BLOCKS_PER_ROUND: usize = 10; // Simulate equivocation
    
    for round in 1..=ROUNDS {
        for fork in 0..BLOCKS_PER_ROUND {
            let block = create_test_block(parent_id, round, fork);
            block_tree.insert_block(block).expect("Insert should succeed");
        }
        // Advance parent to one of the blocks
        parent_id = get_block_id_for_round(round, 0);
    }
    
    // Trigger pruning - this will create a VecDeque with potentially thousands of entries
    let new_window_root = get_block_id_for_round(ROUNDS, 0);
    let blocks_to_prune = block_tree.find_blocks_to_prune(new_window_root);
    
    // Verification: Observe large VecDeque allocation
    println!("Blocks to prune: {}", blocks_to_prune.len());
    // Expected: 1000 rounds * 10 blocks/round = 10,000 blocks
    // Memory: ~400-500 KB (manageable in this test, but scales poorly)
    assert!(blocks_to_prune.len() > 5000, "Should accumulate many blocks");
    
    // In a real Byzantine scenario with extended liveness failure,
    // this could reach millions of blocks and hundreds of MB
}
```

## Notes
This vulnerability is contingent on two factors: (1) Byzantine validators continuously proposing blocks, and (2) delayed consensus commits allowing accumulation. While AptosBFT's liveness guarantees make extended delays unlikely under normal conditions, network partitions, targeted attacks, or implementation bugs in the consensus layer could create windows where large numbers of blocks accumulate. The lack of explicit bounds checking represents a defensive programming gap that could be exploited in adversarial scenarios to degrade validator performance or availability.

### Citations

**File:** consensus/src/block_storage/block_tree.rs (L307-339)
```rust
    pub(super) fn insert_block(
        &mut self,
        block: PipelinedBlock,
    ) -> anyhow::Result<Arc<PipelinedBlock>> {
        let block_id = block.id();
        if let Some(existing_block) = self.get_block(&block_id) {
            debug!("Already had block {:?} for id {:?} when trying to add another block {:?} for the same id",
                       existing_block,
                       block_id,
                       block);
            Ok(existing_block)
        } else {
            match self.get_linkable_block_mut(&block.parent_id()) {
                Some(parent_block) => parent_block.add_child(block_id),
                None => bail!("Parent block {} not found", block.parent_id()),
            };
            let linkable_block = LinkableBlock::new(block);
            let arc_block = Arc::clone(linkable_block.executed_block());
            assert!(self.id_to_block.insert(block_id, linkable_block).is_none());
            // Note: the assumption is that we have/enforce unequivocal proposer election.
            if let Some(old_block_id) = self.round_to_ids.get(&arc_block.round()) {
                warn!(
                    "Multiple blocks received for round {}. Previous block id: {}",
                    arc_block.round(),
                    old_block_id
                );
            } else {
                self.round_to_ids.insert(arc_block.round(), block_id);
            }
            counters::NUM_BLOCKS_IN_TREE.inc();
            Ok(arc_block)
        }
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L405-434)
```rust
    pub(super) fn find_blocks_to_prune(
        &self,
        next_window_root_id: HashValue,
    ) -> VecDeque<HashValue> {
        // Nothing to do if this is the window root
        if next_window_root_id == self.window_root_id {
            return VecDeque::new();
        }

        let mut blocks_pruned = VecDeque::new();
        let mut blocks_to_be_pruned = vec![self.linkable_window_root()];

        while let Some(block_to_remove) = blocks_to_be_pruned.pop() {
            block_to_remove.executed_block().abort_pipeline();
            // Add the children to the blocks to be pruned (if any), but stop when it reaches the
            // new root
            for child_id in block_to_remove.children() {
                if next_window_root_id == *child_id {
                    continue;
                }
                blocks_to_be_pruned.push(
                    self.get_linkable_block(child_id)
                        .expect("Child must exist in the tree"),
                );
            }
            // Track all the block ids removed
            blocks_pruned.push_back(block_to_remove.id());
        }
        blocks_pruned
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L567-600)
```rust
    pub fn commit_callback(
        &mut self,
        storage: Arc<dyn PersistentLivenessStorage>,
        block_id: HashValue,
        block_round: Round,
        finality_proof: WrappedLedgerInfo,
        commit_decision: LedgerInfoWithSignatures,
        window_size: Option<u64>,
    ) {
        let current_round = self.commit_root().round();
        let committed_round = block_round;
        let commit_proof = finality_proof
            .create_merged_with_executed_state(commit_decision)
            .expect("Inconsistent commit proof and evaluation decision, cannot commit block");

        debug!(
            LogSchema::new(LogEvent::CommitViaBlock).round(current_round),
            committed_round = committed_round,
            block_id = block_id,
        );

        let window_root_id = self.find_window_root(block_id, window_size);
        let ids_to_remove = self.find_blocks_to_prune(window_root_id);

        if let Err(e) = storage.prune_tree(ids_to_remove.clone().into_iter().collect()) {
            // it's fine to fail here, as long as the commit succeeds, the next restart will clean
            // up dangling blocks, and we need to prune the tree to keep the root consistent with
            // executor.
            warn!(error = ?e, "fail to delete block");
        }
        self.process_pruned_blocks(ids_to_remove);
        self.update_window_root(window_root_id);
        self.update_highest_commit_cert(commit_proof);
    }
```

**File:** consensus/src/block_storage/block_store.rs (L412-438)
```rust
    pub async fn insert_block(&self, block: Block) -> anyhow::Result<Arc<PipelinedBlock>> {
        if let Some(existing_block) = self.get_block(block.id()) {
            return Ok(existing_block);
        }
        ensure!(
            self.inner.read().ordered_root().round() < block.round(),
            "Block with old round"
        );

        let block_window = self
            .inner
            .read()
            .get_ordered_block_window(&block, self.window_size)?;
        let blocks = block_window.blocks();
        for block in blocks {
            if let Some(payload) = block.payload() {
                self.payload_manager.prefetch_payload_data(
                    payload,
                    block.author().expect("Payload block must have author"),
                    block.timestamp_usecs(),
                );
            }
        }

        let pipelined_block = PipelinedBlock::new_ordered(block, block_window);
        self.insert_block_inner(pipelined_block).await
    }
```

**File:** crates/aptos-crypto/src/hash.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This module defines traits and implementations of
//! [cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
//!
//! It is designed to help authors protect against two types of real world attacks:
//!
//! 1. **Semantic Ambiguity**: imagine that Alice has a private key and is using
//!    two different applications, X and Y. X asks Alice to sign a message saying
//!    "I am Alice". Alice accepts to sign this message in the context of X. However,
//!    unbeknownst to Alice, in application Y, messages beginning with the letter "I"
//!    represent transfers. " am " represents a transfer of 500 coins and "Alice"
//!    can be interpreted as a destination address. When Alice signed the message she
//!    needed to be aware of how other applications might interpret that message.
//!
//! 2. **Format Ambiguity**: imagine a program that hashes a pair of strings.
//!    To hash the strings `a` and `b` it hashes `a + "||" + b`. The pair of
//!    strings `a="foo||", b = "bar"` and `a="foo", b = "||bar"` result in the
//!    same input to the hash function and therefore the same hash. This
//!    creates a collision.
//!
//! Regarding (1), this library makes it easy for developers to create as
//! many new "hashable" Rust types as needed so that each Rust type hashed and signed
//! has a unique meaning, that is, unambiguously captures the intent of a signer.
//!
//! Regarding (2), this library provides the `CryptoHasher` abstraction to easily manage
//! cryptographic seeds for hashing. Hashing seeds aim to ensure that
//! the hashes of values of a given type `MyNewStruct` never collide with hashes of values
//! from another type.
//!
//! Finally, to prevent format ambiguity within a same type `MyNewStruct` and facilitate protocol
//! specifications, we use [Binary Canonical Serialization (BCS)](https://docs.rs/bcs/)
//! as the recommended solution to write Rust values into a hasher.
//!
//! # Quick Start
//!
//! To obtain a `hash()` method for any new type `MyNewStruct`, it is (strongly) recommended to
//! use the derive macros of `serde` and `aptos_crypto_derive` as follows:
//! ```
//! use aptos_crypto::hash::CryptoHash;
//! use aptos_crypto_derive::{CryptoHasher, BCSCryptoHash};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
//! struct MyNewStruct { /*...*/ }
//!
//! let value = MyNewStruct { /*...*/ };
//! value.hash();
//! ```
//!
```

**File:** consensus/src/counters.rs (L829-837)
```rust
/// Counter for the number of blocks in the block tree (including the root).
/// In a "happy path" with no collisions and timeouts, should be equal to 3 or 4.
pub static NUM_BLOCKS_IN_TREE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_consensus_num_blocks_in_tree",
        "Counter for the number of blocks in the block tree (including the root)."
    )
    .unwrap()
});
```

**File:** config/src/config/consensus_config.rs (L220-250)
```rust
impl Default for ConsensusConfig {
    fn default() -> ConsensusConfig {
        ConsensusConfig {
            max_network_channel_size: 1024,
            max_sending_block_txns: MAX_SENDING_BLOCK_TXNS,
            max_sending_block_txns_after_filtering: MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
            max_sending_opt_block_txns_after_filtering: MAX_SENDING_OPT_BLOCK_TXNS_AFTER_FILTERING,
            max_sending_block_bytes: 3 * 1024 * 1024, // 3MB
            max_receiving_block_txns: *MAX_RECEIVING_BLOCK_TXNS,
            max_sending_inline_txns: 100,
            max_sending_inline_bytes: 200 * 1024,       // 200 KB
            max_receiving_block_bytes: 6 * 1024 * 1024, // 6MB
            max_pruned_blocks_in_mem: 100,
            mempool_executed_txn_timeout_ms: 1000,
            mempool_txn_pull_timeout_ms: 1000,
            round_initial_timeout_ms: 1000,
            // 1.2^6 ~= 3
            // Timeout goes from initial_timeout to initial_timeout*3 in 6 steps
            round_timeout_backoff_exponent_base: 1.2,
            round_timeout_backoff_max_exponent: 6,
            safety_rules: SafetyRulesConfig::default(),
            sync_only: false,
            internal_per_key_channel_size: 10,
            quorum_store_pull_timeout_ms: 400,
            quorum_store_poll_time_ms: 300,
            // disable wait_for_full until fully tested
            // We never go above 20-30 pending blocks, so this disables it
            wait_for_full_blocks_above_pending_blocks: 100,
            // Max is 1, so 1.1 disables it.
            wait_for_full_blocks_above_recent_fill_threshold: 1.1,
            intra_consensus_channel_buffer_size: 10,
```
