# Audit Report

## Title
Premature State Transition to "Decided" Causes Irrecoverable Liveness Failure in Secret Sharing

## Summary
The `SecretShareAggregator::try_aggregate()` function transitions the secret share state to `Decided` immediately upon reaching the threshold weight, but performs the actual cryptographic aggregation asynchronously. If aggregation fails after the state transition, the node becomes permanently stuck because the share requester task sees the `Decided` state and exits without requesting additional shares, while the block remains in the pending queue indefinitely.

## Finding Description

This is a **logic vulnerability** in the consensus layer's secret sharing state machine. The vulnerability exists in the interaction between three components that create an irrecoverable failure mode:

**1. Premature State Transition**

The `try_aggregate()` method spawns an asynchronous task to perform cryptographic aggregation but immediately returns `Either::Right(self_share)`, causing the state machine to transition to `Decided` before aggregation completes or succeeds. [1](#0-0) 

**2. Immediate State Transition on Return Value**

When `try_aggregate()` returns `Either::Right(self_share)`, the state immediately transitions from `PendingDecision` to `Decided`, regardless of whether the asynchronous aggregation task succeeds or fails. [2](#0-1) 

**3. Share Requester Exit on Decided State**

The share requester task queries `get_all_shares_authors()`, which returns `None` for the `Decided` state. When `None` is returned, the task exits without requesting shares from any peers. [3](#0-2) [4](#0-3) 

**4. Silent Aggregation Failure**

If the asynchronous aggregation task fails, it only logs a warning and does not send any result to `decision_tx`. This means no `SecretSharedKey` is ever produced. [5](#0-4) 

**5. Permanent Block Queue Stall**

Blocks are only dequeued from the `BlockQueue` when `is_fully_secret_shared()` returns true, which requires all rounds in `pending_secret_key_rounds` to have received their secret keys. If aggregation fails, the round remains in this set permanently. [6](#0-5) [7](#0-6) 

**Attack Sequence:**

1. Node processes block and adds self-share to store
2. Share requester task spawned with 300ms delay
3. Byzantine validators (< 1/3 threshold) send shares that pass individual verification but will fail collective aggregation
4. Shares accumulate until threshold weight is reached
5. `try_aggregate()` is called, spawns async aggregation task, returns `Either::Right`
6. State transitions to `Decided` immediately
7. Share requester wakes at 300ms, calls `get_all_shares_authors()`
8. Function returns `None` because state is `Decided`, requester exits
9. Async aggregation executes and fails (Byzantine shares don't reconstruct properly)
10. Failure is logged but no decision sent to `decision_tx`
11. Block remains in `pending_secret_key_rounds` indefinitely
12. **Liveness failure**: Node cannot progress, subsequent blocks also blocked

**Why This is Triggerable:**

Even without a malicious attack, this can occur naturally due to:
- Rare cryptographic edge cases in the FPTX weighted threshold encryption scheme
- Network timing issues causing share corruption
- Precision errors in cryptographic operations

The fundamental issue is the **race condition** created by premature state transition. The system assumes aggregation will succeed once the threshold is reached, but provides no recovery path when this assumption is violated.

## Impact Explanation

**Severity: Medium** - This meets the Medium severity criteria from the Aptos bug bounty program: "State inconsistencies requiring manual intervention."

The vulnerability causes:

1. **Liveness degradation**: Affected nodes cannot advance consensus for the impacted block and all subsequent blocks in the queue
2. **State inconsistency**: The node believes shares are decided (state is `Decided`) but no secret key exists in the decision channel
3. **Requires manual intervention**: Node restart or manual recovery needed to clear the stuck state
4. **Limited scope**: Only affects individual nodes that receive the specific combination of shares, not the entire network

This is **not** Critical severity because:
- It doesn't cause permanent network partition (only affects individual nodes)
- It doesn't violate consensus safety properties (no double-spending or conflicting blocks committed)
- It doesn't result in fund loss or theft
- Other nodes can continue processing blocks normally

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is realistic because:

1. **Natural occurrence possible**: Even without malicious intent, rare cryptographic errors, numerical precision issues, or edge cases in the batch threshold encryption implementation could trigger aggregation failures after individual shares pass verification

2. **Feasible Byzantine attack**: Byzantine validators below the 1/3 threshold can craft shares that individually pass the verification check but collectively fail during reconstruction (e.g., shares from different polynomial evaluations, inconsistent Lagrange coefficients)

3. **No special privileges needed**: Any Byzantine validator can send malicious shares through normal network channels without requiring additional access

4. **Consistent attack window**: The 300ms delay provides a predictable window for the race condition

5. **No recovery mechanism**: Codebase search confirms no retry or timeout mechanism exists to recover from aggregation failures

However, the likelihood is constrained by:
- Requires understanding of threshold cryptography internals
- Must craft shares that pass individual verification but fail collective reconstruction
- Attack complexity is moderate (requires coordination or cryptographic knowledge)

## Recommendation

**Fix the state machine to delay state transition until aggregation succeeds:**

```rust
pub fn try_aggregate(
    self,
    secret_share_config: &SecretShareConfig,
    metadata: SecretShareMetadata,
    decision_tx: Sender<SecretSharedKey>,
) -> Either<Self, SecretShare> {
    if self.total_weight < secret_share_config.threshold() {
        return Either::Left(self);
    }
    
    // Perform aggregation BEFORE state transition
    let maybe_key = SecretShare::aggregate(self.shares.values(), &secret_share_config);
    
    match maybe_key {
        Ok(key) => {
            let dec_key = SecretSharedKey::new(metadata, key);
            let _ = decision_tx.unbounded_send(dec_key);
            
            // Only transition to Decided if aggregation succeeded
            let self_share = self.get_self_share()
                .expect("Aggregated item should have self share");
            Either::Right(self_share)
        },
        Err(e) => {
            warn!(
                epoch = metadata.epoch,
                round = metadata.round,
                "Aggregation error: {e}, remaining in PendingDecision state"
            );
            // Stay in PendingDecision to allow share requester to get more shares
            Either::Left(self)
        }
    }
}
```

Alternatively, implement a timeout mechanism that retries aggregation or re-spawns the share requester task if no decision is received within a reasonable timeframe.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus node in a test environment
2. Having the node process a block and enter the secret sharing phase
3. Sending shares from Byzantine validators that pass individual `verify()` checks but are from inconsistent polynomial evaluations
4. Observing that once threshold is reached, state transitions to `Decided`
5. Share requester task exits at 300ms
6. Aggregation fails in the async task
7. Block remains stuck in `pending_secret_key_rounds` indefinitely
8. Subsequent blocks also cannot be processed

A full Rust test would require mocking the cryptographic primitives to force aggregation failure while allowing individual verification to pass, demonstrating the state machine flaw independent of the cryptographic implementation details.

## Notes

This vulnerability is fundamentally a **design flaw in the state machine**, not solely a cryptographic issue. The premature state transition creates a scenario where:
- The system commits to a decision before confirming it's achievable
- No recovery path exists when the commitment cannot be fulfilled
- The share requester mechanism is disabled at the exact moment it might be needed most

The fix requires ensuring state transitions only occur after operations complete successfully, following standard consensus state machine best practices where irreversible state changes happen only after all prerequisite operations succeed.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L38-72)
```rust
    pub fn try_aggregate(
        self,
        secret_share_config: &SecretShareConfig,
        metadata: SecretShareMetadata,
        decision_tx: Sender<SecretSharedKey>,
    ) -> Either<Self, SecretShare> {
        if self.total_weight < secret_share_config.threshold() {
            return Either::Left(self);
        }
        observe_block(
            metadata.timestamp,
            BlockStage::SECRET_SHARING_ADD_ENOUGH_SHARE,
        );
        let dec_config = secret_share_config.clone();
        let self_share = self
            .get_self_share()
            .expect("Aggregated item should have self share");
        tokio::task::spawn_blocking(move || {
            let maybe_key = SecretShare::aggregate(self.shares.values(), &dec_config);
            match maybe_key {
                Ok(key) => {
                    let dec_key = SecretSharedKey::new(metadata, key);
                    let _ = decision_tx.unbounded_send(dec_key);
                },
                Err(e) => {
                    warn!(
                        epoch = metadata.epoch,
                        round = metadata.round,
                        "Aggregation error: {e}"
                    );
                },
            }
        });
        Either::Right(self_share)
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L130-154)
```rust
    fn try_aggregate(
        &mut self,
        secret_share_config: &SecretShareConfig,
        decision_tx: Sender<SecretSharedKey>,
    ) {
        let item = std::mem::replace(self, Self::new(Author::ONE));
        let new_item = match item {
            SecretShareItem::PendingDecision {
                share_aggregator,
                metadata,
            } => match share_aggregator.try_aggregate(
                secret_share_config,
                metadata.clone(),
                decision_tx,
            ) {
                Either::Left(share_aggregator) => Self::PendingDecision {
                    metadata,
                    share_aggregator,
                },
                Either::Right(self_share) => Self::Decided { self_share },
            },
            item @ (SecretShareItem::Decided { .. } | SecretShareItem::PendingMetadata(_)) => item,
        };
        let _ = std::mem::replace(self, new_item);
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L184-194)
```rust
    fn get_all_shares_authors(&self) -> Option<HashSet<Author>> {
        match self {
            SecretShareItem::PendingDecision {
                share_aggregator, ..
            } => Some(share_aggregator.shares.keys().cloned().collect()),
            SecretShareItem::Decided { .. } => None,
            SecretShareItem::PendingMetadata(_) => {
                unreachable!("Should only be called after block is added")
            },
        }
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L237-277)
```rust
    fn spawn_share_requester_task(&self, metadata: SecretShareMetadata) -> DropGuard {
        let rb = self.reliable_broadcast.clone();
        let aggregate_state = Arc::new(SecretShareAggregateState::new(
            self.secret_share_store.clone(),
            metadata.clone(),
            self.config.clone(),
        ));
        let epoch_state = self.epoch_state.clone();
        let secret_share_store = self.secret_share_store.clone();
        let task = async move {
            // TODO(ibalajiarun): Make this configurable
            tokio::time::sleep(Duration::from_millis(300)).await;
            let maybe_existing_shares = secret_share_store.lock().get_all_shares_authors(&metadata);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestSecretShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
                info!(
                    epoch = epoch,
                    round = metadata.round,
                    "[SecretShareManager] Start broadcasting share request for {}",
                    targets.len(),
                );
                rb.multicast(request, aggregate_state, targets)
                    .await
                    .expect("Broadcast cannot fail");
                info!(
                    epoch = epoch,
                    round = metadata.round,
                    "[SecretShareManager] Finish broadcasting share request",
                );
            }
        };
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(task, abort_registration));
        DropGuard::new(abort_handle)
    }
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L60-77)
```rust
    pub fn is_fully_secret_shared(&self) -> bool {
        self.pending_secret_key_rounds.is_empty()
    }

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
    }
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L112-127)
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
    }
```
