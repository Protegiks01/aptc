# Audit Report

## Title
Stale Commit Vote Retention After State Sync Reset Leading to Memory Inefficiency

## Summary
The `reset()` function in BufferManager fails to clear the `pending_commit_votes` cache when processing `ResetSignal::TargetRound`, causing stale commit votes from before the reset to remain in memory until gradually cleaned up through normal block progression. While this represents inefficient resource management, it does not constitute a security vulnerability.

## Finding Description

The `tokio::select!` in `start()` processes channels concurrently, allowing commit votes to arrive before their corresponding ordered blocks. [1](#0-0) 

When a commit vote arrives before its block, it gets cached in `pending_commit_votes`: [2](#0-1) 

The caching logic accepts votes within a 100-round window: [3](#0-2) 

When ordered blocks eventually arrive, cached votes are retrieved if block IDs match: [4](#0-3) 

**The Issue:** During state sync reset via `ResetSignal::TargetRound`, the `reset()` function does NOT clear `pending_commit_votes`: [5](#0-4) 

While `pending_commit_proofs` IS drained during reset: [6](#0-5) 

Stale votes eventually get cleaned up when blocks are persisted: [7](#0-6) 

However, stale votes from the pre-reset state remain until the system commits blocks at those round numbers again, which could take significant time.

## Impact Explanation

**This does NOT meet Medium severity criteria** because:

1. **No Consensus Safety Violation**: Stale votes are never used incorrectly. The block ID check at line 416 ensures votes only match if block IDs are identical, which won't happen after state sync (different fork).

2. **No Loss of Liveness**: Cleanup happens progressively; the system continues operating normally.

3. **Bounded Resource Usage**: Cache is limited to 100 rounds × validator count, typically tens of megabytes maximum.

4. **Not Externally Exploitable**: Requires valid validator signatures (verified at line 925), and state sync is an internal process.

This is a **code quality and resource management issue**, not a security vulnerability per the Aptos bug bounty categories.

## Likelihood Explanation

This occurs during normal operation whenever state sync happens while commit votes are cached. However:
- It's not attacker-controlled
- Impact is minimal (temporary memory inefficiency)
- System continues functioning correctly
- Cleanup eventually completes

## Recommendation

For consistency and efficiency, clear `pending_commit_votes` during reset, similar to `pending_commit_proofs`:

```rust
async fn reset(&mut self) {
    // ... existing cleanup code ...
    
    // Add this cleanup:
    self.pending_commit_votes.clear();
    
    // ... rest of function ...
}
```

Alternatively, in `process_reset_request()` for `ResetSignal::TargetRound`:

```rust
ResetSignal::TargetRound(round) => {
    self.highest_committed_round = round;
    self.latest_round = round;
    let _ = self.drain_pending_commit_proof_till(round);
    
    // Add: Clear stale commit votes
    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
},
```

## Proof of Concept

This is a code quality issue observable through code inspection rather than an exploitable vulnerability. A reproduction would involve:

1. Running a validator node
2. Triggering state sync while commit votes are cached
3. Observing memory retention (non-harmful)
4. Confirming votes eventually get cleaned up

However, this demonstrates **inefficiency**, not a security exploit, as there is no attacker-controlled trigger and no security impact.

---

**Notes**

After rigorous analysis, this finding does **not** constitute a valid security vulnerability under the Aptos bug bounty program criteria. While the code could be more efficient by clearing stale votes during reset, the security guarantees remain intact:

- Consensus safety is maintained (stale votes never match due to block ID checks)
- No funds at risk
- No exploitable attack path
- Resource consumption is bounded
- Cleanup eventually completes

This is a **code improvement opportunity**, not a reportable security issue.

### Citations

**File:** consensus/src/pipeline/buffer_manager.rs (L335-361)
```rust
    fn try_add_pending_commit_vote(&mut self, vote: CommitVote) -> bool {
        let block_id = vote.commit_info().id();
        let round = vote.commit_info().round();

        // Don't need to store commit vote if we have already committed up to that round
        if round <= self.highest_committed_round {
            true
        } else
        // Store the commit vote only if it is for one of the next 100 rounds.
        if round > self.highest_committed_round
            && self.highest_committed_round + self.max_pending_rounds_in_commit_vote_cache > round
        {
            self.pending_commit_votes
                .entry(round)
                .or_default()
                .insert(vote.author(), vote);
            true
        } else {
            debug!(
                round = round,
                highest_committed_round = self.highest_committed_round,
                block_id = block_id,
                "Received a commit vote not in the next 100 rounds, ignored."
            );
            false
        }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L413-421)
```rust
        if let Some(block) = ordered_blocks.last() {
            if let Some(votes) = self.pending_commit_votes.remove(&block.round()) {
                for (_, vote) in votes {
                    if vote.commit_info().id() == block.id() {
                        unverified_votes.insert(vote.author(), vote);
                    }
                }
            }
        }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L546-576)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
        while let Some(item) = self.buffer.pop_front() {
            for b in item.get_blocks() {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        self.buffer = Buffer::new();
        self.execution_root = None;
        self.signing_root = None;
        self.previous_commit_time = Instant::now();
        self.commit_proof_rb_handle.take();
        // purge the incoming blocks queue
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        // Wait for ongoing tasks to finish before sending back ack.
        while self.ongoing_tasks.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L585-590)
```rust
            ResetSignal::TargetRound(round) => {
                self.highest_committed_round = round;
                self.latest_round = round;

                let _ = self.drain_pending_commit_proof_till(round);
            },
```

**File:** consensus/src/pipeline/buffer_manager.rs (L780-784)
```rust
                } else if self.try_add_pending_commit_vote(vote) {
                    reply_ack(protocol, response_sender);
                } else {
                    reply_nack(protocol, response_sender); // TODO: send_commit_vote() doesn't care about the response and this should be direct send not RPC
                }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L937-994)
```rust
            ::tokio::select! {
                Some(blocks) = self.block_rx.next(), if !self.need_back_pressure() => {
                    self.latest_round = blocks.latest_round();
                    monitor!("buffer_manager_process_ordered", {
                    self.process_ordered_blocks(blocks).await;
                    if self.execution_root.is_none() {
                        self.advance_execution_root();
                    }});
                },
                Some(reset_event) = self.reset_rx.next() => {
                    monitor!("buffer_manager_process_reset",
                    self.process_reset_request(reset_event).await);
                },
                Some(response) = self.execution_schedule_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_schedule_response", {
                    self.process_execution_schedule_response(response).await;
                })},
                Some(response) = self.execution_wait_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_wait_response", {
                    self.process_execution_response(response).await;
                    self.advance_execution_root();
                    if self.signing_root.is_none() {
                        self.advance_signing_root().await;
                    }});
                },
                Some(response) = self.signing_phase_rx.next() => {
                    monitor!("buffer_manager_process_signing_response", {
                    self.process_signing_response(response).await;
                    self.advance_signing_root().await
                    })
                },
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
                Some(rpc_request) = verified_commit_msg_rx.next() => {
                    monitor!("buffer_manager_process_commit_message",
                    if let Some(aggregated_block_id) = self.process_commit_message(rpc_request) {
                        self.advance_head(aggregated_block_id).await;
                        if self.execution_root.is_none() {
                            self.advance_execution_root();
                        }
                        if self.signing_root.is_none() {
                            self.advance_signing_root().await;
                        }
                    });
                }
                _ = interval.tick().fuse() => {
                    monitor!("buffer_manager_process_interval_tick", {
                    self.update_buffer_manager_metrics();
                    self.rebroadcast_commit_votes_if_needed().await
                    });
                },
                // no else branch here because interval.tick will always be available
            }
        }
```
