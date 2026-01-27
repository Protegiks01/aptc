# Audit Report

## Title
Per-Peer RPC Limit Exhaustion in Commit Vote Reliable Broadcast Prevents Communication with Honest Validators

## Summary
Byzantine validators can force an honest validator to accumulate up to 100 concurrent commit vote broadcasts, exhausting the per-peer outbound RPC limit (100 concurrent RPCs) and preventing the honest validator from sending new commit votes to ANY validator, including honest ones. This disrupts consensus participation for the affected validator.

## Finding Description

The commit vote reliable broadcast mechanism sends RPCs concurrently to all validators when broadcasting commit votes. [1](#0-0)  Each broadcast creates one RPC to each validator in the epoch.

Multiple broadcasts can exist concurrently because each is spawned as an independent task. [2](#0-1)  The buffer can hold up to 100 pending rounds worth of items, [3](#0-2)  and each item can have one active broadcast. [4](#0-3) 

The network layer enforces a per-peer limit of 100 concurrent outbound RPCs. [5](#0-4)  When this limit is exceeded, new RPC requests are rejected with `RpcError::TooManyPending`. [6](#0-5) 

**Attack Path:**
1. Byzantine validators (< 1/3) intentionally delay or drop commit vote acknowledgments
2. Honest validator's broadcasts wait for timeout (1500ms) [7](#0-6)  then retry with exponential backoff
3. Meanwhile, consensus continues processing new blocks, triggering new broadcasts
4. If 100 concurrent broadcasts accumulate (one per pending round), each sending 1 RPC to each validator
5. Total concurrent RPCs to each validator = 100 (exactly at the limit)
6. Any attempt to start a 101st broadcast fails because `send_rb_rpc()` cannot send RPCs to any validator (the per-peer limit is exhausted)
7. The honest validator cannot communicate new commit votes to honest validators, disrupting its consensus participation

The vulnerability exists because:
- There is no global limit on concurrent broadcasts (only per-item via DropGuard)
- The buffer can accumulate up to 100 items with pending broadcasts
- The per-peer RPC limit (100) applies equally to honest and Byzantine validators
- Once exhausted, no new RPCs can be sent to ANY peer

## Impact Explanation

This is a **Medium Severity** vulnerability per the Aptos bug bounty program criteria:

- **Validator node slowdown**: The affected honest validator cannot send new commit votes, degrading its participation in consensus
- **Significant protocol violation**: The validator loses ability to communicate with other validators when the RPC limit is exhausted
- **Limited scope**: Requires coordination by Byzantine validators (< 1/3) and high block throughput to accumulate 100 concurrent broadcasts
- **Not consensus safety**: Does not cause double-spending or chain splits (safety is maintained)
- **Not fund loss**: No direct theft or manipulation of funds

The impact is limited to the affected validator's ability to participate in consensus. Other honest validators can still make progress if they don't hit the same limit. However, if multiple validators are affected simultaneously, consensus liveness could be impacted.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements for successful attack:**
1. Byzantine validators control < 1/3 of stake (standard BFT assumption)
2. Byzantine validators coordinate to delay commit vote acknowledgments
3. Block production rate must be high enough to accumulate 100 pending broadcasts before older ones complete
4. Approximately: blocks arriving every ~15ms while broadcasts take 1500ms to timeout = ~100 concurrent broadcasts

**Feasibility:**
- Byzantine validators can easily delay/drop acknowledgments (low technical barrier)
- High block throughput is achievable in Aptos (designed for high performance)
- The attack is repeatable and doesn't require special network conditions
- No validator insider access required (works with < 1/3 stake)

**Mitigating factors:**
- Requires sustained high block throughput
- Broadcasts complete and free up RPC slots eventually (with retries)
- Exponential backoff on retries reduces sustained load
- Only affects validators that accumulate 100 concurrent broadcasts

## Recommendation

Implement a global limit on concurrent reliable broadcast tasks to prevent RPC limit exhaustion:

1. **Add concurrency limit to ReliableBroadcast spawning**: Use the existing `BoundedExecutor` to limit concurrent broadcast tasks, not just aggregation tasks
2. **Rate limit broadcast initiation**: Prevent accumulation of excessive concurrent broadcasts
3. **Separate honest/Byzantine RPC quotas**: Reserve RPC capacity for honest validators
4. **Increase per-peer RPC limit**: Raise `MAX_CONCURRENT_OUTBOUND_RPCS` to accommodate maximum expected broadcasts

**Recommended fix in `consensus/src/pipeline/buffer_manager.rs`:**

Instead of unbounded spawning:
```rust
tokio::spawn(Abortable::new(task, abort_registration));
```

Use the bounded executor:
```rust
self.bounded_executor.spawn(Abortable::new(task, abort_registration));
```

And ensure the `num_bounded_executor_tasks` configuration accounts for maximum concurrent broadcasts (currently 16, should be increased to ~50 or add a separate broadcast executor).

Additionally, in `crates/reliable-broadcast/src/lib.rs`, consider limiting the number of concurrent RPC sends per broadcast to prevent a single broadcast from consuming all RPC slots.

## Proof of Concept

**Scenario Setup:**
```rust
// Simulated attack where Byzantine validators delay commit vote acks
// 1. Start with 100 validators (33 Byzantine, 67 honest)
// 2. Process 100 blocks rapidly (faster than broadcasts complete)
// 3. Byzantine validators never acknowledge commit votes
// 4. Honest validator accumulates 100 concurrent broadcasts
// 5. 101st broadcast fails with RpcError::TooManyPending for all peers
```

**Expected behavior:**
When the honest validator tries to broadcast the 101st commit vote:
- Calls `send_rb_rpc()` for each validator
- Each call goes through network layer's `OutboundRpcs::handle_outbound_request()`
- Hits the limit check: `self.outbound_rpc_tasks.len() == 100`
- Returns `Err(RpcError::TooManyPending(100))`
- Broadcast fails to send to ANY validator (honest or Byzantine)
- Validator cannot participate in consensus for that round

**Verification steps:**
1. Monitor `counters::rpc_messages` with label `DECLINED_LABEL` - should increment when RPC limit exceeded
2. Check buffer manager logs - should show broadcasts failing to initiate
3. Observe consensus liveness - affected validator falls behind in commit votes
4. Network metrics show 100 concurrent outbound RPCs to each peer

The vulnerability can be reproduced in integration tests by:
- Mocking Byzantine validators that never send acknowledgments
- Rapidly proposing blocks to accumulate pending broadcasts
- Observing RPC failures when limit is reached

### Citations

**File:** crates/reliable-broadcast/src/lib.rs (L164-166)
```rust
            for receiver in receivers {
                rpc_futures.push(send_message(receiver, None));
            }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L62-62)
```rust
pub const COMMIT_VOTE_BROADCAST_INTERVAL_MS: u64 = 1500;
```

**File:** consensus/src/pipeline/buffer_manager.rs (L277-286)
```rust
        let task = self.reliable_broadcast.broadcast(
            message,
            AckState::new(
                self.epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter(),
            ),
        );
        tokio::spawn(Abortable::new(task, abort_registration));
        Some(DropGuard::new(abort_handle))
```

**File:** consensus/src/pipeline/buffer_manager.rs (L720-726)
```rust
                let signed_item_mut = signed_item.unwrap_signed_mut();
                let commit_vote = signed_item_mut.commit_vote.clone();
                let commit_vote = Self::generate_commit_message(commit_vote);
                signed_item_mut.rb_handle = self
                    .do_reliable_broadcast(commit_vote)
                    .map(|handle| (Instant::now(), handle));
                self.buffer.set(&current_cursor, signed_item);
```

**File:** config/src/config/consensus_config.rs (L381-381)
```rust
            max_pending_rounds_in_commit_vote_cache: 100,
```

**File:** network/framework/src/constants.rs (L13-13)
```rust
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L463-474)
```rust
        if self.outbound_rpc_tasks.len() == self.max_concurrent_outbound_rpcs as usize {
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                OUTBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            // Notify application that their request was dropped due to capacity.
            let err = Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
            let _ = application_response_tx.send(err);
            return Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
```
