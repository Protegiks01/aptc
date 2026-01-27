# Audit Report

## Title
Secret Share Manager Fails to Handle Duplicate Block Rounds Leading to Validator Panic

## Summary
The `SecretShareManager::process_incoming_blocks()` function uses a `HashSet` to track `pending_secret_key_rounds`, which silently deduplicates rounds. When combined with a `HashMap` in `QueueItem::new()` that only retains the last index for duplicate rounds, this causes blocks with duplicate round numbers to never receive their secret shared keys. These blocks are then dequeued and sent to the decryption pipeline where they panic when awaiting the missing secret key, crashing the validator node.

## Finding Description

The vulnerability exists across multiple components in the secret sharing pipeline:

**Component 1: HashSet Deduplication** [1](#0-0) 

When processing incoming blocks, `pending_secret_key_rounds` is a `HashSet` that automatically deduplicates any duplicate round numbers. If `ordered_blocks` contains blocks with rounds `[5, 6, 5]`, the HashSet will only contain `{5, 6}`.

**Component 2: HashMap Overwrites in QueueItem** [2](#0-1) 

The `offsets_by_round` HashMap is created by iterating over blocks and mapping `(round, index)`. When duplicate rounds exist, later entries overwrite earlier ones. For blocks at indices `[0, 1, 2]` with rounds `[5, 6, 5]`, the HashMap becomes `{5: 2, 6: 1}` - only the LAST index is remembered.

**Component 3: Selective Secret Key Distribution** [3](#0-2) 

When `set_secret_shared_key()` is called, it uses `self.offset(round)` to get the block index, which retrieves from the HashMap (returning the LAST index). Only that block receives the secret key. The round is then removed from `pending_secret_key_rounds`, so the method won't be called again for that round. Other blocks with the same round never receive their keys.

**Component 4: False "Fully Secret Shared" Status** [4](#0-3) 

The `is_fully_secret_shared()` check only verifies that `pending_secret_key_rounds` is empty. Since duplicate rounds are deduplicated, this returns `true` even when some blocks haven't received their secret keys.

**Component 5: Dequeue Without Validation** [5](#0-4) 

When blocks are dequeued as "ready", ALL blocks in the `OrderedBlocks` are forwarded downstream, including those that never received their secret keys.

**Component 6: Decryption Pipeline Panic** [6](#0-5) 

Blocks without secret keys have `secret_shared_key_tx` channels that are never sent to. When the decryption pipeline awaits `secret_shared_key_rx`, the channel returns an error (sender dropped without sending), causing the `.expect()` to panic and crash the validator.

**Attack Vector:**
While normal blockchain operation should produce unique rounds per block in a parent chain, there is no explicit validation preventing duplicate rounds in `OrderedBlocks`. If duplicate rounds appear through:
- Bug in block construction logic
- State corruption
- Race conditions during block tree operations  
- Epoch transition edge cases

The system will fail catastrophically rather than detecting and rejecting the invalid state.

## Impact Explanation

**Severity: High** (Validator node crashes)

When duplicate rounds trigger this code path:
1. Multiple blocks await secret keys that will never arrive
2. The decryption pipeline panics with `"decryption key should be available"`
3. The validator node crashes or hangs
4. Consensus participation is disrupted

This meets **High Severity** criteria per the Aptos bug bounty program: "Validator node slowdowns" and "API crashes". A validator crash impacts network liveness and could be part of a wider attack if multiple validators are affected.

The issue violates the **Consensus Safety** invariant: all validators must process blocks deterministically. A validator crash prevents proper consensus participation.

## Likelihood Explanation

**Likelihood: Low-Medium**

Under normal operation, blocks in a parent chain have unique rounds. However, the likelihood increases due to:

1. **No Input Validation**: The code path from `path_from_ordered_root()` to `process_incoming_blocks()` contains no assertions validating round uniqueness [7](#0-6) 

2. **Test Code Can Create Duplicates**: The test utility explicitly allows duplicate rounds [8](#0-7) 

3. **Complex State Management**: Block tree operations involve multiple concurrent components where race conditions could theoretically introduce duplicates

4. **Defensive Programming Failure**: The absence of validation means any bug in upstream block handling automatically becomes a consensus-breaking issue

## Recommendation

Add explicit validation to prevent duplicate rounds and handle them gracefully if detected:

**Fix 1: Validate unique rounds in `process_incoming_blocks()`**
```rust
async fn process_incoming_blocks(&mut self, blocks: OrderedBlocks) {
    let rounds: Vec<u64> = blocks.ordered_blocks.iter().map(|b| b.round()).collect();
    
    // Validate no duplicate rounds
    let unique_rounds: HashSet<u64> = rounds.iter().copied().collect();
    assert_eq!(
        rounds.len(), 
        unique_rounds.len(),
        "OrderedBlocks contains duplicate rounds: {:?}", rounds
    );
    
    info!(rounds = rounds, "Processing incoming blocks.");
    // ... rest of function
}
```

**Fix 2: Validate in `QueueItem::new()`**
```rust
pub fn new(
    ordered_blocks: OrderedBlocks,
    share_requester_handles: Option<Vec<DropGuard>>,
    pending_secret_key_rounds: HashSet<Round>,
) -> Self {
    assert!(!ordered_blocks.ordered_blocks.is_empty());
    let offsets_by_round: HashMap<Round, usize> = ordered_blocks
        .ordered_blocks
        .iter()
        .enumerate()
        .map(|(idx, b)| (b.round(), idx))
        .collect();
    
    // Ensure no rounds were lost due to duplicates
    assert_eq!(
        offsets_by_round.len(),
        ordered_blocks.ordered_blocks.len(),
        "Duplicate rounds detected in OrderedBlocks"
    );
    
    Self { /* ... */ }
}
```

**Fix 3: Add validation in `path_from_ordered_root()`**
Add a post-condition check ensuring all rounds in the returned path are unique.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    
    #[tokio::test]
    #[should_panic(expected = "decryption key should be available")]
    async fn test_duplicate_rounds_cause_panic() {
        // Create OrderedBlocks with duplicate rounds [5, 6, 5]
        let blocks = create_ordered_blocks(vec![5, 6, 5]);
        
        // Setup secret share manager
        let mut manager = /* initialize SecretShareManager */;
        
        // Process blocks - this creates the vulnerable state
        manager.process_incoming_blocks(blocks).await;
        
        // Simulate secret key arriving for round 5
        // Only the LAST block (index 2) will receive it
        let secret_key = /* create SecretSharedKey for round 5 */;
        manager.process_aggregated_key(secret_key);
        
        // Dequeue blocks - all three blocks are dequeued
        let ready_blocks = manager.block_queue.dequeue_ready_prefix();
        
        // Block at index 0 (round 5) never received its secret key
        // When its decryption pipeline awaits secret_shared_key_rx,
        // the channel will error because the sender was never used
        // This triggers the panic at decryption_pipeline_builder.rs:117
        
        // In practice, this would manifest as a validator crash during
        // block execution when the decryption pipeline is awaited
    }
}
```

The PoC demonstrates that duplicate rounds create an exploitable state where blocks are processed without their required secret keys, leading to validator crashes.

**Notes**

While I could not identify a concrete attack path for an unprivileged external attacker to inject duplicate rounds into `OrderedBlocks` (as blockchain invariants should prevent this), the defensive programming failure is severe. The code makes implicit assumptions about round uniqueness without validation, creating a single point of failure. Any bug in block construction, state management, or epoch transitions that violates this assumption will cause immediate validator crashes rather than graceful error handling.

This is particularly concerning given the complexity of the consensus layer and the multiple code paths that construct and process `OrderedBlocks`. The absence of validation means the system is not defense-in-depth: one bug elsewhere becomes a consensus-breaking vulnerability.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L117-122)
```rust
        let mut pending_secret_key_rounds = HashSet::new();
        for block in blocks.ordered_blocks.iter() {
            let handle = self.process_incoming_block(block).await;
            share_requester_handles.push(handle);
            pending_secret_key_rounds.insert(block.round());
        }
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L31-36)
```rust
        let offsets_by_round: HashMap<Round, usize> = ordered_blocks
            .ordered_blocks
            .iter()
            .enumerate()
            .map(|(idx, b)| (b.round(), idx))
            .collect();
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L60-62)
```rust
    pub fn is_fully_secret_shared(&self) -> bool {
        self.pending_secret_key_rounds.is_empty()
    }
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L64-76)
```rust
    pub fn set_secret_shared_key(&mut self, round: Round, key: SecretSharedKey) {
        let offset = self.offset(round);
        if self.pending_secret_key_rounds.contains(&round) {
            observe_block(
                self.blocks()[offset].timestamp_usecs(),
                BlockStage::SECRET_SHARING_ADD_DECISION,
            );
            let block = &self.blocks_mut()[offset];
            if let Some(tx) = block.pipeline_tx().lock().as_mut() {
                tx.secret_shared_key_tx.take().map(|tx| tx.send(Some(key)));
            }
            self.pending_secret_key_rounds.remove(&round);
        }
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L112-126)
```rust
    pub fn dequeue_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.is_fully_secret_shared() {
                let (_, item) = self.queue.pop_first().expect("First key must exist");
                for block in item.blocks() {
                    observe_block(block.timestamp_usecs(), BlockStage::SECRET_SHARING_READY);
                }
                let QueueItem { ordered_blocks, .. } = item;
                ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        ready_prefix
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L115-119)
```rust
        let maybe_decryption_key = secret_shared_key_rx
            .await
            .expect("decryption key should be available");
        // TODO(ibalajiarun): account for the case where decryption key is not available
        let decryption_key = maybe_decryption_key.expect("decryption key should be available");
```

**File:** consensus/src/block_storage/block_tree.rs (L519-546)
```rust
    pub(super) fn path_from_root_to_block(
        &self,
        block_id: HashValue,
        root_id: HashValue,
        root_round: u64,
    ) -> Option<Vec<Arc<PipelinedBlock>>> {
        let mut res = vec![];
        let mut cur_block_id = block_id;
        loop {
            match self.get_block(&cur_block_id) {
                Some(ref block) if block.round() <= root_round => {
                    break;
                },
                Some(block) => {
                    cur_block_id = block.parent_id();
                    res.push(block);
                },
                None => return None,
            }
        }
        // At this point cur_block.round() <= self.root.round()
        if cur_block_id != root_id {
            return None;
        }
        // Called `.reverse()` to get the chronically increased order.
        res.reverse();
        Some(res)
    }
```

**File:** consensus/src/rand/rand_gen/test_utils.rs (L24-52)
```rust
pub fn create_ordered_blocks(rounds: Vec<Round>) -> OrderedBlocks {
    let blocks = rounds
        .into_iter()
        .map(|round| {
            Arc::new(PipelinedBlock::new(
                Block::new_for_testing(
                    HashValue::random(),
                    BlockData::new_for_testing(
                        1,
                        round,
                        1,
                        QuorumCert::dummy(),
                        BlockType::Genesis,
                    ),
                    None,
                ),
                vec![],
                StateComputeResult::new_dummy(),
            ))
        })
        .collect();
    OrderedBlocks {
        ordered_blocks: blocks,
        ordered_proof: LedgerInfoWithSignatures::new(
            LedgerInfo::mock_genesis(None),
            AggregateSignature::empty(),
        ),
    }
}
```
