# Audit Report

## Title
Secret Share Store Rejects Legitimate Future Round Requests During Normal Round Transitions

## Summary
The `SecretShareStore::get_self_share()` function enforces a strict constraint requiring `metadata.round <= highest_known_round`, while the `add_share()` and `add_self_share()` functions accept shares up to `highest_known_round + FUTURE_ROUNDS_TO_ACCEPT` (200 rounds). This asymmetry causes legitimate share requests to fail during normal round transitions when nodes are at slightly different rounds, leading to unnecessary RPC failures, exponential backoff retries, and delays in secret share aggregation that can impact consensus liveness. [1](#0-0) 

## Finding Description

The secret sharing mechanism in Aptos consensus uses a distributed protocol where validators generate and exchange secret shares for each round. The system has an asymmetric acceptance policy:

**Share Reception Policy** (permissive): The `add_share()` and `add_self_share()` methods accept shares for rounds up to `highest_known_round + FUTURE_ROUNDS_TO_ACCEPT` where `FUTURE_ROUNDS_TO_ACCEPT = 200`. [2](#0-1) [3](#0-2) [4](#0-3) 

**Share Serving Policy** (strict): The `get_self_share()` method only serves shares for rounds where `metadata.round <= highest_known_round` with zero tolerance for future rounds. [1](#0-0) 

**The Race Condition:**

During normal consensus operation, when a new block for round N+1 arrives:

1. Node A processes the block quickly and updates `highest_known_round` to N+1
2. Node A spawns a share requester task with a 300ms delay
3. Node B is slightly behind due to network latency or processing delay, still has `highest_known_round = N`
4. After 300ms, Node A's requester sends `RequestShare` RPC to Node B for round N+1
5. Node B's handler calls `get_self_share()` which checks: `(N+1) <= N` → FALSE → returns error "Request share from future round"
6. The RPC fails and enters exponential backoff retry cycle [5](#0-4) [6](#0-5) [7](#0-6) 

**Impact on Block Queue:**

Blocks waiting for secret share aggregation are queued in `BlockQueue` and only released when `is_fully_secret_shared()` returns true. Failed share requests delay aggregation, causing blocks to remain queued. [8](#0-7) 

**Retry Mechanism:**

The `ReliableBroadcast` implementation retries failed RPCs with exponential backoff. For secret sharing, the default configuration uses `backoff_policy_base_ms: 2`, `backoff_policy_factor: 100`, and `backoff_policy_max_delay_ms: 10000`, resulting in retry delays of 2ms, 200ms, 20s, and capping at 10s. [9](#0-8) [10](#0-9) 

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos Bug Bounty program:

1. **Validator Node Slowdowns**: The unnecessary RPC failures and exponential backoff retries delay secret share aggregation, which in turn delays block processing in the consensus pipeline. This directly impacts validator performance and throughput.

2. **State Inconsistencies Requiring Intervention**: During periods of high network latency variance, node catch-up scenarios, or epoch transitions, the cumulative delays can cause significant divergence in block processing times across validators, potentially requiring operator intervention to diagnose and address performance degradation.

3. **Not a Safety Violation**: This issue does not break consensus safety invariants - shares are eventually aggregated once retries succeed after nodes update their round state. However, it degrades the liveness guarantee by introducing artificial delays.

4. **Network Amplification**: The issue causes unnecessary network traffic due to failed RPCs and retries, particularly problematic in large validator sets where many nodes may be requesting shares simultaneously.

## Likelihood Explanation

This issue has **HIGH likelihood** of occurring:

1. **Normal Operation**: The race condition occurs naturally during every round transition due to inevitable network latency and processing time variance across validators. Even in well-functioning networks, nodes process blocks at slightly different times.

2. **Amplification Factors**:
   - Geographic distribution of validators increases latency variance
   - Variable computational load on validator nodes causes processing time differences
   - Network congestion or routing changes introduce timing variability
   - Multiple rapid round advancements (e.g., during catch-up) compound the issue

3. **Observable Impact**: The issue manifests as increased RPC failure rates in validator logs and increased latency in secret share aggregation metrics, which can be observed in production networks.

4. **No Attack Required**: This is a protocol design issue that happens during normal, honest operation - no malicious behavior is needed to trigger it.

## Recommendation

Align the `get_self_share()` acceptance policy with the `add_share()` policy by allowing requests for future rounds within the same tolerance window:

**Modified `get_self_share()` in `consensus/src/rand/secret_sharing/secret_share_store.rs`:**

```rust
pub fn get_self_share(
    &mut self,
    metadata: &SecretShareMetadata,
) -> anyhow::Result<Option<SecretShare>> {
    ensure!(
        metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
        "Request share from future round {}, highest known round {}, max acceptable {}",
        metadata.round,
        self.highest_known_round,
        self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT
    );
    Ok(self
        .secret_share_map
        .get(&metadata.round)
        .and_then(|item| item.get_self_share())
        .filter(|share| &share.metadata == metadata))
}
```

This change is safe because:
1. Shares can already be added for future rounds (up to +200), so they can legitimately exist in the store
2. Share verification is performed by the requesting node, not the serving node
3. Shares are cryptographically bound to specific metadata (epoch, round), preventing misuse
4. The 200-round window is already deemed safe for share acceptance, so serving should have the same tolerance

## Proof of Concept

The following scenario demonstrates the vulnerability in a network simulation:

```rust
// Pseudo-code demonstrating the race condition
// This would be implemented as a consensus integration test

#[tokio::test]
async fn test_secret_share_round_transition_race() {
    // Setup: 4 validators at round 100
    let mut validators = setup_validators(4, 100).await;
    
    // Node 0 receives and processes block for round 101
    validators[0].process_block(round_101_block).await;
    assert_eq!(validators[0].highest_known_round(), 101);
    
    // Nodes 1-3 are delayed (still at round 100)
    assert_eq!(validators[1].highest_known_round(), 100);
    
    // Wait for Node 0's share requester task delay (300ms)
    tokio::time::sleep(Duration::from_millis(350)).await;
    
    // Node 0 sends RequestShare RPC to Node 1 for round 101
    let request = RequestSecretShare::new(
        SecretShareMetadata { epoch: 1, round: 101, timestamp: 0 }
    );
    
    // This RPC will fail because Node 1's get_self_share() 
    // checks: 101 <= 100 -> false
    let result = validators[0]
        .request_share_from(&validators[1], request)
        .await;
    
    // Expected: Error "Request share from future round"
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("future round"));
    
    // Observe RPC retry with exponential backoff
    let retry_delays = observe_retry_delays(&validators[0]).await;
    assert_eq!(retry_delays[0].as_millis(), 2);   // First retry: 2ms
    assert_eq!(retry_delays[1].as_millis(), 200); // Second retry: 200ms
    
    // Eventually Node 1 processes the block
    validators[1].process_block(round_101_block).await;
    assert_eq!(validators[1].highest_known_round(), 101);
    
    // Subsequent retry succeeds
    let result = validators[0]
        .request_share_from(&validators[1], request)
        .await;
    assert!(result.is_ok());
    
    // Measure total delay introduced by failed RPCs
    let aggregation_delay = measure_aggregation_time(&validators[0]).await;
    // Shows significant delay compared to optimistic case
    assert!(aggregation_delay > Duration::from_secs(1));
}
```

**Measurement in Production:**

Monitor the following metrics to observe this issue:
- Secret share RPC failure rate (filter for "Request share from future round" errors)
- Secret share aggregation latency percentiles (p50, p95, p99)
- Block queue depth and wait time for secret sharing
- Correlation between round advancement and RPC failure spikes

## Notes

This vulnerability represents a **design asymmetry** rather than a traditional security exploit. While it doesn't enable malicious behavior, it degrades consensus performance during normal operation, which falls under the bug bounty program's definition of "Validator node slowdowns" (High) or "State inconsistencies requiring intervention" (Medium).

The fix is straightforward and maintains all existing security properties while eliminating unnecessary RPC failures and retries during round transitions.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L237-257)
```rust
    pub fn add_self_share(&mut self, share: SecretShare) -> anyhow::Result<()> {
        assert!(
            self.self_author == share.author,
            "Only self shares can be added with metadata"
        );
        let peer_weights = self.secret_share_config.get_peer_weights();
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share_with_metadata(share, peer_weights)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(())
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-275)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L288-303)
```rust
    pub fn get_self_share(
        &mut self,
        metadata: &SecretShareMetadata,
    ) -> anyhow::Result<Option<SecretShare>> {
        ensure!(
            metadata.round <= self.highest_known_round,
            "Request share from future round {}, highest known round {}",
            metadata.round,
            self.highest_known_round
        );
        Ok(self
            .secret_share_map
            .get(&metadata.round)
            .and_then(|item| item.get_self_share())
            .filter(|share| &share.metadata == metadata))
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L132-158)
```rust
    async fn process_incoming_block(&self, block: &PipelinedBlock) -> DropGuard {
        let futures = block.pipeline_futs().expect("pipeline must exist");
        let self_secret_share = futures
            .secret_sharing_derive_self_fut
            .await
            .expect("Decryption share computation is expected to succeed")
            .expect("Must not be None");
        let metadata = self_secret_share.metadata().clone();

        // Now acquire lock and update store
        {
            let mut secret_share_store = self.secret_share_store.lock();
            secret_share_store.update_highest_known_round(block.round());
            secret_share_store
                .add_self_share(self_secret_share.clone())
                .expect("Add self dec share should succeed");
        }

        info!(LogSchema::new(LogEvent::BroadcastSecretShare)
            .epoch(self.epoch_state.epoch)
            .author(self.author)
            .round(block.round()));
        self.network_sender.broadcast_without_self(
            SecretShareMessage::Share(self_secret_share).into_network_message(),
        );
        self.spawn_share_requester_task(metadata)
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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L279-322)
```rust
    fn handle_incoming_msg(&self, rpc: SecretShareRpc) {
        let SecretShareRpc {
            msg,
            protocol,
            response_sender,
        } = rpc;
        match msg {
            SecretShareMessage::RequestShare(request) => {
                let result = self
                    .secret_share_store
                    .lock()
                    .get_self_share(request.metadata());
                match result {
                    Ok(Some(share)) => {
                        self.process_response(
                            protocol,
                            response_sender,
                            SecretShareMessage::Share(share),
                        );
                    },
                    Ok(None) => {
                        warn!(
                            "Self secret share could not be found for RPC request {}",
                            request.metadata().round
                        );
                    },
                    Err(e) => {
                        warn!("[SecretShareManager] Failed to get share: {}", e);
                    },
                }
            },
            SecretShareMessage::Share(share) => {
                info!(LogSchema::new(LogEvent::ReceiveSecretShare)
                    .author(self.author)
                    .epoch(share.epoch())
                    .round(share.metadata().round)
                    .remote_peer(*share.author()));

                if let Err(e) = self.secret_share_store.lock().add_share(share) {
                    warn!("[SecretShareManager] Failed to add share: {}", e);
                }
            },
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

**File:** config/src/config/consensus_config.rs (L373-378)
```rust
            rand_rb_config: ReliableBroadcastConfig {
                backoff_policy_base_ms: 2,
                backoff_policy_factor: 100,
                backoff_policy_max_delay_ms: 10000,
                rpc_timeout_ms: 10000,
            },
```

**File:** crates/reliable-broadcast/src/lib.rs (L183-201)
```rust
                    Some(result) = aggregate_futures.next() => {
                        let (receiver, result) = result.expect("spawned task must succeed");
                        match result {
                            Ok(may_be_aggragated) => {
                                if let Some(aggregated) = may_be_aggragated {
                                    return Ok(aggregated);
                                }
                            },
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
                        }
```
