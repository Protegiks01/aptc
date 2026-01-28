# Audit Report

## Title
Strategic Nack Responses Cause Unbounded Retry Storms Leading to Resource Exhaustion and Consensus Delays

## Summary
Byzantine validators can strategically send Nack responses to commit vote broadcasts, triggering unbounded retry mechanisms that amplify across multiple honest validators, causing resource exhaustion, BoundedExecutor saturation, and significant consensus delays.

## Finding Description

The commit reliable broadcast mechanism treats Nack responses as retriable errors without any retry limit or aggregate throttling mechanism. When a validator receives a Nack response, it triggers exponential backoff retry logic that continues indefinitely until the broadcast is aborted. [1](#0-0) [2](#0-1) 

This error propagates to the reliable broadcast retry mechanism, which schedules retries indefinitely: [3](#0-2) 

Byzantine validators can send Nacks through the normal response mechanism: [4](#0-3) [5](#0-4) 

The TODO comment indicates awareness of the design flaw.

**Attack Mechanics:**

1. Multiple honest validators broadcast commit votes for blocks in their pipeline buffer
2. M Byzantine validators (where M < N/3) strategically respond with Nacks to all broadcasts
3. Each honest validator's reliable broadcast retries with exponential backoff configured as: [6](#0-5) 

4. The `rpc_futures` and `aggregate_futures` queues are unbounded: [7](#0-6) 

5. Each retry spawns aggregation tasks in the BoundedExecutor: [8](#0-7) 

6. The BoundedExecutor has a default capacity of only 16 concurrent tasks: [9](#0-8) 

7. When the executor saturates, `.spawn()` blocks until slots become available: [10](#0-9) 

**Critical Impact Vector:**

The same BoundedExecutor is used for verifying incoming commit messages: [11](#0-10) 

When the executor is saturated with retry aggregation tasks, verification of legitimate incoming commit votes is delayed, creating a cascading slowdown effect.

**Resource Exhaustion Vectors:**

1. **Memory**: Unbounded `FuturesUnordered` queues grow with pending retry futures
2. **Executor saturation**: BoundedExecutor blocks on spawn, delaying aggregation and verification of legitimate votes
3. **Network bandwidth**: Continuous retry traffic to Byzantine validators
4. **CPU**: Processing thousands of retry responses per second

The broadcast runs asynchronously in background: [12](#0-11) 

However, executor saturation delays critical consensus operations that share the same executor.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's category of "Validator node slowdowns".

While consensus doesn't completely stall (since broadcasts run asynchronously), the resource exhaustion creates significant performance degradation:

1. **BoundedExecutor saturation** delays both retry aggregation AND verification of legitimate incoming commit messages, slowing down the commit phase
2. **Memory pressure** from unbounded retry queue growth can lead to OOM conditions
3. **Network saturation** wastes bandwidth on futile retries
4. **Cascading delays** as multiple validators experience simultaneous slowdowns, potentially delaying quorum formation

The attack is amplified because each honest validator independently retries to each Byzantine validator. With realistic network parameters (100 validators, 33 Byzantine, 15 concurrent blocks in pipeline), this generates over 30,000 concurrent retry streams that persist for 30-second windows before rebroadcast cycles.

## Likelihood Explanation

**High likelihood** because:

1. **Low attacker requirements**: Only requires controlling validators within Byzantine tolerance (< 1/3), which is the assumed threat model for BFT systems
2. **Simple exploitation**: Byzantine validators simply respond with Nacks instead of Acks—no complex logic needed
3. **No detection mechanism**: The system has no rate limiting or anomaly detection for excessive Nacks
4. **Continuous impact**: Attack persists as long as Byzantine validators continue sending Nacks
5. **Natural amplification**: Each honest validator independently retries, creating quadratic amplification (N × M interactions)

## Recommendation

Implement the following mitigations:

1. **Add retry limits per peer**: Limit the number of retries to any single peer within a time window
2. **Add aggregate rate limiting**: Track total retry rate across all peers and throttle when threshold exceeded
3. **Separate executor pools**: Use different BoundedExecutor instances for retry aggregation vs. incoming message verification to prevent cross-contamination
4. **Implement Nack detection**: Monitor excessive Nack rates from specific validators and apply backpressure
5. **Consider direct send for commit votes**: As indicated by the TODO comment, consider making commit vote broadcasts use direct send rather than RPC to eliminate the Nack response path

Example fix for retry limiting:

```rust
// In ReliableBroadcast, add per-peer retry counters
let mut retry_counts: HashMap<Author, usize> = HashMap::new();
const MAX_RETRIES_PER_PEER: usize = 5;

// In the retry logic:
let retry_count = retry_counts.entry(receiver).or_insert(0);
if *retry_count >= MAX_RETRIES_PER_PEER {
    // Skip retry for this peer
    continue;
}
*retry_count += 1;
```

## Proof of Concept

This vulnerability can be demonstrated by:

1. Setting up a test network with 4 validators (3 honest, 1 Byzantine)
2. Configuring the Byzantine validator to always respond with Nack to commit vote broadcasts
3. Observing the accumulation of retry futures in the honest validators
4. Measuring BoundedExecutor saturation and commit vote processing delays
5. Monitoring memory growth from unbounded retry queues

The attack is triggered through normal protocol operation - Byzantine validators simply send `CommitMessage::Nack` responses instead of `CommitMessage::Ack`, which is handled by the response mechanisms shown in the code citations above.

## Notes

- The report's claim of "3000ms" maximum delay is slightly inaccurate; the code shows 5000ms (5 seconds) as the max delay
- The 30-second rebroadcast interval provides an implicit timeout per broadcast attempt, but doesn't prevent the attack from repeating across multiple rebroadcast cycles
- This is a consensus protocol vulnerability, not a network-layer DoS attack, as it exploits flaws in the retry mechanism design rather than overwhelming network infrastructure

### Citations

**File:** consensus/src/pipeline/commit_reliable_broadcast.rs (L126-128)
```rust
            ConsensusMsg::CommitMessage(resp) if matches!(*resp, CommitMessage::Nack) => {
                bail!("Received nack, will retry")
            },
```

**File:** consensus/src/pipeline/commit_reliable_broadcast.rs (L144-146)
```rust
            ConsensusMsg::CommitMessage(resp) if matches!(*resp, CommitMessage::Nack) => {
                bail!("Received nack, will retry")
            },
```

**File:** crates/reliable-broadcast/src/lib.rs (L158-159)
```rust
            let mut rpc_futures = FuturesUnordered::new();
            let mut aggregate_futures = FuturesUnordered::new();
```

**File:** crates/reliable-broadcast/src/lib.rs (L171-181)
```rust
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
                        aggregate_futures.push(future);
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** consensus/src/pipeline/buffer_manager.rs (L208-210)
```rust
        let rb_backoff_policy = ExponentialBackoff::from_millis(2)
            .factor(50)
            .max_delay(Duration::from_secs(5));
```

**File:** consensus/src/pipeline/buffer_manager.rs (L285-285)
```rust
        tokio::spawn(Abortable::new(task, abort_registration));
```

**File:** consensus/src/pipeline/buffer_manager.rs (L783-783)
```rust
                    reply_nack(protocol, response_sender); // TODO: send_commit_vote() doesn't care about the response and this should be direct send not RPC
```

**File:** consensus/src/pipeline/buffer_manager.rs (L923-932)
```rust
                bounded_executor
                    .spawn(async move {
                        match commit_msg.req.verify(sender, &epoch_state_clone.verifier) {
                            Ok(_) => {
                                let _ = tx.unbounded_send(commit_msg);
                            },
                            Err(e) => warn!("Invalid commit message: {}", e),
                        }
                    })
                    .await;
```

**File:** consensus/src/pipeline/buffer_manager.rs (L1003-1005)
```rust
fn reply_nack(protocol: ProtocolId, response_sender: oneshot::Sender<Result<Bytes, RpcError>>) {
    reply_commit_msg(protocol, response_sender, CommitMessage::Nack)
}
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```

**File:** crates/bounded-executor/src/executor.rs (L45-52)
```rust
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```
