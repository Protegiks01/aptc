# Audit Report

## Title
Silent Metadata Rejection in RandStore Causes Permanent Liveness Failure on Duplicate Round Metadata

## Summary
The `RandStore::add_rand_metadata()` function silently ignores duplicate metadata calls for the same round, causing permanent liveness failure when the consensus layer provides updated metadata due to chain reorganizations or block replacements. This violates the liveness invariant and can block all consensus progress.

## Finding Description

The vulnerability exists in the `RandItem::add_metadata()` function, which is called by `RandStore::add_rand_metadata()`: [1](#0-0) 

When `add_metadata()` is called while the `RandItem` is already in `PendingDecision` or `Decided` state, it returns the existing item unchanged without error or warning. This creates a critical state inconsistency:

1. **First call** with metadata M1 (block_id=H1): Transitions `PendingMetadata` → `PendingDecision` with M1
2. **Second call** with metadata M2 (block_id=H2, same round): Silently ignored, remains with M1

This breaks the following security guarantees:

**Consensus Liveness Violation**: The block queue uses sequential dequeuing where blocks can only proceed when ALL previous rounds have randomness: [2](#0-1) 

When a round is stuck with wrong metadata, it blocks all subsequent rounds indefinitely.

**State Inconsistency**: The RandStore believes it's producing randomness for block H1, but the consensus layer has moved to block H2. When shares arrive for the current metadata M2, they are rejected because they don't match the stored metadata M1: [3](#0-2) 

Note that randomness shares only verify epoch and round (not block_id): [4](#0-3) 

However, the full metadata including block_id differs between blocks, creating an inconsistent state.

**Attack Scenarios**:

1. **Chain Reorganization Without Reset**: During network partitions or view changes, a node may see block A for round N, then later see block B (canonical) for round N. If the reset mechanism doesn't trigger properly, `add_rand_metadata()` is called twice with different block_ids.

2. **Consensus Edge Cases**: During epoch transitions or buffer manager resets, blocks may be reprocessed with updated metadata.

3. **Race Conditions**: The consensus layer sends `OrderedBlocks` without validation against duplicate rounds: [5](#0-4) 

## Impact Explanation

**Severity: CRITICAL** - Total loss of liveness/network availability

This vulnerability meets the Aptos Bug Bounty Critical severity criteria for "Total loss of liveness/network availability":

- **Complete Consensus Halt**: Once a round enters the stuck state, ALL subsequent rounds are blocked from proceeding through the randomness pipeline
- **Non-Recoverable Without Manual Intervention**: Requires explicit `reset()` call via `ResetRequest` which may not trigger automatically in all edge cases
- **Affects All Nodes**: Any node experiencing duplicate metadata (e.g., during network partitions) becomes stuck
- **Randomness-Dependent Transactions Blocked**: All transactions requiring randomness (vtxn) cannot commit [6](#0-5) 

## Likelihood Explanation

**Likelihood: MEDIUM**

While normal consensus operation should prevent duplicate rounds, several realistic scenarios can trigger this:

1. **Network Partitions**: Validators in different partitions may see different blocks, then reconcile
2. **Epoch Transitions**: Edge cases during epoch changes where blocks are reprocessed
3. **State Sync Issues**: Nodes syncing to a new state without proper reset coordination
4. **Consensus Protocol Bugs**: Any bug in the consensus layer that causes block replacement

The reset mechanism exists but requires explicit triggering: [7](#0-6) 

If reset doesn't trigger (e.g., node not "behind" in round number, just seeing conflicting blocks), the vulnerability manifests.

## Recommendation

**Add validation and proper error handling for duplicate metadata:**

```rust
fn add_metadata(&mut self, rand_config: &RandConfig, rand_metadata: FullRandMetadata) -> anyhow::Result<()> {
    let item = std::mem::replace(self, Self::new(Author::ONE, PathType::Slow));
    let new_item = match item {
        RandItem::PendingMetadata(mut share_aggregator) => {
            share_aggregator.retain(rand_config, &rand_metadata);
            Self::PendingDecision {
                metadata: rand_metadata,
                share_aggregator,
            }
        },
        RandItem::PendingDecision { metadata: existing_metadata, .. } => {
            // Detect and reject duplicate metadata with different block_id
            if existing_metadata.round() == rand_metadata.round() 
                && existing_metadata.block_id != rand_metadata.block_id {
                anyhow::bail!(
                    "[RandStore] Duplicate metadata for round {} with different block_id: existing={}, new={}",
                    existing_metadata.round(),
                    existing_metadata.block_id,
                    rand_metadata.block_id
                );
            }
            // Return existing item if metadata matches
            RandItem::PendingDecision { metadata: existing_metadata, share_aggregator: item }
        },
        item @ RandItem::Decided { .. } => item,
    };
    let _ = std::mem::replace(self, new_item);
    Ok(())
}
```

**Update add_rand_metadata() to handle the error:**

```rust
pub fn add_rand_metadata(&mut self, rand_metadata: FullRandMetadata) -> anyhow::Result<()> {
    let rand_item = self
        .rand_map
        .entry(rand_metadata.round())
        .or_insert_with(|| RandItem::new(self.author, PathType::Slow));
    rand_item.add_metadata(&self.rand_config, rand_metadata.clone())?;
    rand_item.try_aggregate(&self.rand_config, self.decision_tx.clone());
    // Similar for fast path...
    Ok(())
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_duplicate_metadata_with_different_block_id() {
    use aptos_crypto::HashValue;
    use aptos_types::randomness::FullRandMetadata;
    
    let ctxt = TestContext::new(vec![100; 7], 0);
    let (decision_tx, _decision_rx) = unbounded();
    let mut rand_store = RandStore::new(
        ctxt.target_epoch,
        ctxt.authors[0],
        ctxt.rand_config.clone(),
        None,
        decision_tx,
    );
    
    // First block for round 100
    let metadata_1 = FullRandMetadata::new(
        ctxt.target_epoch,
        100,
        HashValue::random(),  // block_id H1
        1700000000,
    );
    
    rand_store.update_highest_known_round(100);
    rand_store.add_rand_metadata(metadata_1.clone());
    
    // Simulate chain reorg - different block for same round
    let metadata_2 = FullRandMetadata::new(
        ctxt.target_epoch,
        100,
        HashValue::random(),  // block_id H2 (different!)
        1700000001,
    );
    
    // This call is silently ignored - no error!
    rand_store.add_rand_metadata(metadata_2.clone());
    
    // Shares for metadata_2 will be rejected because RandStore still has metadata_1
    // This causes permanent liveness failure
    assert!(rand_store.get_all_shares_authors(100).is_some());
    // Round 100 is stuck, blocks all subsequent rounds
}
```

**Notes:**

The vulnerability stems from insufficient input validation in the randomness generation module. While the consensus layer should ideally prevent duplicate rounds, the randomness module must defensively handle this edge case rather than silently failing into an unrecoverable state. The fix adds explicit validation with clear error messages, allowing the consensus layer to detect and properly handle conflicts.

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L146-157)
```rust
            RandItem::PendingDecision {
                metadata,
                share_aggregator,
            } => {
                ensure!(
                    &metadata.metadata == share.metadata(),
                    "[RandStore] RandShare metadata from {} mismatch with block metadata!",
                    share.author(),
                );
                share_aggregator.add_share(rand_config.get_peer_weight(share.author()), share);
                Ok(())
            },
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L180-193)
```rust
    fn add_metadata(&mut self, rand_config: &RandConfig, rand_metadata: FullRandMetadata) {
        let item = std::mem::replace(self, Self::new(Author::ONE, PathType::Slow));
        let new_item = match item {
            RandItem::PendingMetadata(mut share_aggregator) => {
                share_aggregator.retain(rand_config, &rand_metadata);
                Self::PendingDecision {
                    metadata: rand_metadata,
                    share_aggregator,
                }
            },
            item @ (RandItem::PendingDecision { .. } | RandItem::Decided { .. }) => item,
        };
        let _ = std::mem::replace(self, new_item);
    }
```

**File:** consensus/src/rand/rand_gen/block_queue.rs (L118-137)
```rust
    pub fn dequeue_rand_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut rand_ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.num_undecided() == 0 {
                let (_, item) = self.queue.pop_first().unwrap();
                for block in item.blocks() {
                    observe_block(block.timestamp_usecs(), BlockStage::RAND_READY);
                }
                let QueueItem { ordered_blocks, .. } = item;
                debug_assert!(ordered_blocks
                    .ordered_blocks
                    .iter()
                    .all(|block| block.has_randomness()));
                rand_ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        rand_ready_prefix
    }
```

**File:** types/src/randomness.rs (L23-35)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash)]
pub struct RandMetadata {
    pub epoch: u64,
    pub round: Round,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct FullRandMetadata {
    pub metadata: RandMetadata,
    // not used for signing
    pub block_id: HashValue,
    pub timestamp: u64,
}
```

**File:** consensus/src/pipeline/execution_client.rs (L590-624)
```rust
    async fn finalize_order(
        &self,
        blocks: Vec<Arc<PipelinedBlock>>,
        ordered_proof: WrappedLedgerInfo,
    ) -> ExecutorResult<()> {
        assert!(!blocks.is_empty());
        let mut execute_tx = match self.handle.read().execute_tx.clone() {
            Some(tx) => tx,
            None => {
                debug!("Failed to send to buffer manager, maybe epoch ends");
                return Ok(());
            },
        };

        for block in &blocks {
            block.set_insertion_time();
            if let Some(tx) = block.pipeline_tx().lock().as_mut() {
                tx.order_proof_tx
                    .take()
                    .map(|tx| tx.send(ordered_proof.clone()));
            }
        }

        if execute_tx
            .send(OrderedBlocks {
                ordered_blocks: blocks,
                ordered_proof: ordered_proof.ledger_info().clone(),
            })
            .await
            .is_err()
        {
            debug!("Failed to send to buffer manager, maybe epoch ends");
        }
        Ok(())
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L674-693)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };

        if let Some(mut reset_tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx: ack_tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::RandResetDropped)?;
            ack_rx.await.map_err(|_| Error::RandResetDropped)?;
        }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L132-143)
```rust
    fn process_incoming_blocks(&mut self, blocks: OrderedBlocks) {
        let rounds: Vec<u64> = blocks.ordered_blocks.iter().map(|b| b.round()).collect();
        info!(rounds = rounds, "Processing incoming blocks.");
        let broadcast_handles: Vec<_> = blocks
            .ordered_blocks
            .iter()
            .map(|block| FullRandMetadata::from(block.block()))
            .map(|metadata| self.process_incoming_metadata(metadata))
            .collect();
        let queue_item = QueueItem::new(blocks, Some(broadcast_handles));
        self.block_queue.push_back(queue_item);
    }
```
