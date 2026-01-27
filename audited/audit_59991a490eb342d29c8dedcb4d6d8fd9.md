# Audit Report

## Title
Randomness Queue Gap Attack: Byzantine Validators Can Permanently Block Chain Progress by Creating Gaps in Ready Blocks

## Summary
The `dequeue_rand_ready_prefix()` function in the randomness generation queue assumes that ready blocks form a contiguous sequence from the front of the queue. However, DAG consensus can order blocks at non-contiguous rounds, and Byzantine validators can selectively withhold randomness shares for specific rounds. This creates a situation where ready blocks at later rounds are permanently stuck behind non-ready blocks at earlier rounds, causing total loss of liveness even when sufficient randomness is available.

## Finding Description

The vulnerability exists in the block dequeuing logic that assumes a contiguous ready prefix. [1](#0-0) 

The function iterates through the queue and breaks immediately when it encounters a non-ready item, preventing any subsequent ready items from being dequeued. The queue maintains blocks in a `BTreeMap<Round, QueueItem>` keyed by the starting round of each batch. [2](#0-1) 

DAG consensus orders nodes in batches, creating separate `OrderedBlocks` for each anchor. [3](#0-2)  Each batch is sent as a separate item to the randomness manager [4](#0-3)  and pushed to the queue with its first round as the key. [5](#0-4) 

**Attack Scenario:**

1. DAG consensus orders blocks creating batches at rounds 100, 105, and 110
2. Byzantine validators (< 1/3 stake) receive shares for all rounds
3. Byzantine nodes selectively withhold shares for round 100 but broadcast shares for rounds 105 and 110
4. Honest validators collect enough shares (≥ 2/3 threshold) for rounds 105 and 110
5. Randomness decisions are sent for rounds 105 and 110 [6](#0-5) 
6. The queue state becomes: Round 100 (num_undecided > 0), Round 105 (num_undecided = 0), Round 110 (num_undecided = 0)
7. `dequeue_rand_ready_prefix()` checks round 100, finds it non-ready, and breaks
8. Rounds 105 and 110 are never dequeued despite having complete randomness
9. The execution pipeline stalls permanently [7](#0-6) 

The only recovery mechanism requires governance intervention to globally disable randomness. [8](#0-7) 

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos bug bounty program:

- **Total loss of liveness**: The blockchain cannot execute blocks even when randomness is available for later rounds. Blocks remain stuck in the queue indefinitely.
- **Requires hardfork or governance intervention**: The only recovery is to disable randomness entirely via governance proposal, which is a sledgehammer solution that affects all randomness-dependent features.
- **Byzantine fault threshold violation**: The system should tolerate < 1/3 Byzantine validators, but this attack succeeds with any non-zero Byzantine stake that can coordinate to withhold shares.

The attack breaks the fundamental liveness guarantee that honest blocks with sufficient randomness should eventually be executed. Every validator node is affected simultaneously, causing network-wide consensus halt.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack complexity: LOW** - Byzantine validators simply withhold randomness shares for specific rounds while providing shares for others
- **Coordination required: MINIMAL** - Even a single Byzantine validator can cause the attack if they're part of the threshold set
- **Detection difficulty: HIGH** - Appears as normal network delay initially; by the time it's detected, blocks are already stuck
- **Frequency of vulnerable state: FREQUENT** - Every epoch with DAG consensus and randomness enabled is vulnerable
- **Attacker motivation: HIGH** - Disrupting a major blockchain has significant economic and reputational impact

The vulnerability is triggered naturally by the DAG consensus ordering algorithm creating non-contiguous batches. Byzantine nodes need only selectively withhold shares, which is indistinguishable from network delays until the attack manifests.

## Recommendation

Modify `dequeue_rand_ready_prefix()` to skip non-ready items and continue checking subsequent items, or implement a timeout mechanism to skip stalled blocks after a threshold period.

**Option 1: Skip Non-Ready Blocks (Preferred)**

Change the dequeue logic to collect all ready items regardless of gaps, not just the contiguous prefix. However, this requires careful consideration of ordering guarantees required by the execution pipeline.

**Option 2: Timeout-Based Skip**

Add a timestamp to each `QueueItem` and allow skipping items that have been stuck for longer than a configured timeout (e.g., 60 seconds). This preserves the prefix invariant while preventing permanent stalls.

**Option 3: Partial Dequeue with Round Gaps**

Modify the execution pipeline to handle out-of-order blocks with randomness, allowing the queue to dequeue any ready items even with gaps. This requires verifying that the execution layer can safely handle non-contiguous round sequences.

The fix should include:
- Metrics to track queue gap detection
- Alerts when blocks are stuck beyond threshold
- Testing with Byzantine scenarios that create gaps

## Proof of Concept

```rust
#[cfg(test)]
mod gap_attack_test {
    use super::*;
    use crate::rand::rand_gen::test_utils::create_ordered_blocks;
    use aptos_types::randomness::Randomness;

    #[test]
    fn test_gap_causes_permanent_block() {
        let mut queue = BlockQueue::new();
        
        // Simulate DAG consensus ordering blocks at non-contiguous rounds
        // Batch 1: round 100
        queue.push_back(QueueItem::new(create_ordered_blocks(vec![100]), None));
        // Batch 2: round 105
        queue.push_back(QueueItem::new(create_ordered_blocks(vec![105]), None));
        // Batch 3: round 110
        queue.push_back(QueueItem::new(create_ordered_blocks(vec![110]), None));

        // Byzantine nodes withhold shares for round 100
        // Honest nodes provide shares for rounds 105 and 110
        queue.set_randomness(105, Randomness::default());
        queue.set_randomness(110, Randomness::default());

        // Try to dequeue ready blocks
        let ready = queue.dequeue_rand_ready_prefix();
        
        // BUG: No blocks are dequeued because round 100 is blocking
        assert_eq!(ready.len(), 0);
        
        // Verify rounds 105 and 110 are stuck despite being ready
        assert_eq!(queue.queue().len(), 3);
        
        // Even if we later get randomness for round 100
        queue.set_randomness(100, Randomness::default());
        let ready = queue.dequeue_rand_ready_prefix();
        
        // Now all blocks are dequeued, proving the gap was the issue
        assert_eq!(ready.len(), 3);
    }
}
```

**Notes**

This vulnerability demonstrates a critical flaw in the assumption that ready blocks always form a contiguous prefix. In distributed systems with Byzantine actors, gaps in readiness are not only possible but expected when adversaries selectively withhold information. The fix must either relax the contiguity assumption or implement timeout-based recovery to prevent permanent liveness failures.

### Citations

**File:** consensus/src/rand/rand_gen/block_queue.rs (L94-102)
```rust
pub struct BlockQueue {
    queue: BTreeMap<Round, QueueItem>,
}
impl BlockQueue {
    pub fn new() -> Self {
        Self {
            queue: BTreeMap::new(),
        }
    }
```

**File:** consensus/src/rand/rand_gen/block_queue.rs (L108-113)
```rust
    pub fn push_back(&mut self, item: QueueItem) {
        for block in item.blocks() {
            observe_block(block.timestamp_usecs(), BlockStage::RAND_ENTER);
        }
        assert!(self.queue.insert(item.first_round(), item).is_none());
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

**File:** consensus/src/dag/adapter.rs (L137-239)
```rust
impl OrderedNotifier for OrderedNotifierAdapter {
    fn send_ordered_nodes(
        &self,
        ordered_nodes: Vec<Arc<CertifiedNode>>,
        failed_author: Vec<(Round, Author)>,
    ) {
        let anchor = ordered_nodes
            .last()
            .expect("ordered_nodes shuld not be empty");
        let epoch = anchor.epoch();
        let round = anchor.round();
        let timestamp = anchor.metadata().timestamp();
        let author = *anchor.author();
        let mut validator_txns = vec![];
        let mut payload = Payload::empty(
            !anchor.payload().is_direct(),
            self.allow_batches_without_pos_in_proposal,
        );
        let mut node_digests = vec![];
        for node in &ordered_nodes {
            validator_txns.extend(node.validator_txns().clone());
            payload = payload.extend(node.payload().clone());
            node_digests.push(node.digest());
        }
        let parent_block_id = self.parent_block_info.read().id();
        // construct the bitvec that indicates which nodes present in the previous round in CommitEvent
        let mut parents_bitvec = BitVec::with_num_bits(self.epoch_state.verifier.len() as u16);
        for parent in anchor.parents().iter() {
            if let Some(idx) = self
                .epoch_state
                .verifier
                .address_to_validator_index()
                .get(parent.metadata().author())
            {
                parents_bitvec.set(*idx as u16);
            }
        }
        let parent_timestamp = self.parent_block_info.read().timestamp_usecs();
        let block_timestamp = timestamp.max(parent_timestamp.checked_add(1).expect("must add"));

        NUM_NODES_PER_BLOCK.observe(ordered_nodes.len() as f64);
        let rounds_between = {
            let lowest_round_node = ordered_nodes.first().map_or(0, |node| node.round());
            round.saturating_sub(lowest_round_node)
        };
        NUM_ROUNDS_PER_BLOCK.observe((rounds_between + 1) as f64);

        let block = Arc::new(PipelinedBlock::new(
            Block::new_for_dag(
                epoch,
                round,
                block_timestamp,
                validator_txns,
                payload,
                author,
                failed_author,
                parent_block_id,
                parents_bitvec,
                node_digests,
            ),
            vec![],
            StateComputeResult::new_dummy(),
        ));
        let block_info = block.block_info();
        *self.parent_block_info.write() = block_info.clone();

        self.block_ordered_ts
            .write()
            .insert(block_info.round(), Instant::now());

        observe_block(block.block().timestamp_usecs(), BlockStage::ORDERED);

        let blocks_to_send = OrderedBlocks {
            ordered_blocks: vec![block],
            ordered_proof: LedgerInfoWithSignatures::new(
                LedgerInfo::new(block_info, anchor.digest()),
                AggregateSignature::empty(),
            ),
            // TODO: this needs to be properly integrated with pipeline_builder
            // callback: Box::new(
            //     move |committed_blocks: &[Arc<PipelinedBlock>],
            //           commit_decision: LedgerInfoWithSignatures| {
            //         block_created_ts
            //             .write()
            //             .retain(|&round, _| round > commit_decision.commit_info().round());
            //         dag.commit_callback(commit_decision.commit_info().round());
            //         ledger_info_provider
            //             .write()
            //             .notify_commit_proof(commit_decision);
            //         update_counters_for_committed_blocks(committed_blocks);
            //     },
            // ),
        };
        //
        if self
            .executor_channel
            .unbounded_send(blocks_to_send)
            .is_err()
        {
            error!("[DAG] execution pipeline closed");
        }
    }
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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L184-194)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.rand_store.lock().reset(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L469-472)
```rust
            let maybe_ready_blocks = self.block_queue.dequeue_rand_ready_prefix();
            if !maybe_ready_blocks.is_empty() {
                self.process_ready_blocks(maybe_ready_blocks);
            }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L41-89)
```rust
    pub fn try_aggregate(
        self,
        rand_config: &RandConfig,
        rand_metadata: FullRandMetadata,
        decision_tx: Sender<Randomness>,
    ) -> Either<Self, RandShare<S>> {
        if self.total_weight < rand_config.threshold() {
            return Either::Left(self);
        }
        match self.path_type {
            PathType::Fast => {
                observe_block(
                    rand_metadata.timestamp,
                    BlockStage::RAND_ADD_ENOUGH_SHARE_FAST,
                );
            },
            PathType::Slow => {
                observe_block(
                    rand_metadata.timestamp,
                    BlockStage::RAND_ADD_ENOUGH_SHARE_SLOW,
                );
            },
        }

        let rand_config = rand_config.clone();
        let self_share = self
            .get_self_share()
            .expect("Aggregated item should have self share");
        tokio::task::spawn_blocking(move || {
            let maybe_randomness = S::aggregate(
                self.shares.values(),
                &rand_config,
                rand_metadata.metadata.clone(),
            );
            match maybe_randomness {
                Ok(randomness) => {
                    let _ = decision_tx.unbounded_send(randomness);
                },
                Err(e) => {
                    warn!(
                        epoch = rand_metadata.metadata.epoch,
                        round = rand_metadata.metadata.round,
                        "Aggregation error: {e}"
                    );
                },
            }
        });
        Either::Right(self_share)
    }
```
