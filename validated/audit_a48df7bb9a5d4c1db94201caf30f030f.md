# Audit Report

## Title
Race Condition in Randomness Generation Allows Byzantine Validators to Crash Consensus Nodes via unreachable!() Panic

## Summary
A race condition exists between consensus reset operations and asynchronous share aggregation tasks in the randomness generation subsystem. Byzantine validators can exploit this by sending randomness shares immediately after a reset event, causing the `unreachable!()` macro in `RandItem::get_all_shares_authors()` to trigger and panic the entire consensus node.

## Finding Description

The vulnerability stems from an incorrect invariant assumption in the randomness generation code. The function `RandItem::get_all_shares_authors()` contains an `unreachable!()` macro for the `PendingMetadata` state: [1](#0-0) 

This assumption is **not guaranteed** by the code structure due to a race condition in the async task execution model. Here's the vulnerable flow:

**Normal Flow:**

1. When a block arrives, `process_incoming_metadata()` is called, which adds randomness metadata (transitioning the `RandItem` from `PendingMetadata` to `PendingDecision` state) and spawns an async task: [2](#0-1) 

2. The async task sleeps for 300ms, then calls `get_all_shares_authors()`: [3](#0-2) 

3. A `DropGuard` is returned and stored in the block queue to abort the task if needed: [4](#0-3) [5](#0-4) 

**Race Condition Attack:**

1. During the 300ms sleep period, a consensus reset occurs, which clears the block queue (dropping all `DropGuards`) and removes items from `rand_store`: [6](#0-5) [7](#0-6) 

2. Byzantine validators send randomness shares for round R. These shares are accepted because the round check passes: [8](#0-7) [9](#0-8) 

3. A new `RandItem` is created in **PendingMetadata** state: [10](#0-9) 

4. **Critical Issue:** The async task wakes up from sleep and executes synchronous code in a single poll continuation. The code between line 274 (sleep) and line 290 (next await) is entirely synchronous. Once the poll starts executing after the sleep completes, it runs all this code without checking the abort flag again, even though `abort()` was called when the `DropGuard` was dropped during reset.

5. The task acquires the lock and calls `get_all_shares_authors(round)` on the newly created `PendingMetadata` item, triggering the `unreachable!()` macro and panicking the node.

The root cause is that Rust's `Abortable` futures only check the abort flag when polled at await points. If a poll has started executing synchronous code after an await completes, it will run to the next await point even if `abort()` is called during that execution. The lock contention creates a timing window where the item can be removed by reset and re-added by incoming shares while the task's poll is blocked waiting for the lock.

## Impact Explanation

**Severity: HIGH** - Validator node crashes leading to network availability degradation

This vulnerability allows Byzantine validators to crash any consensus node participating in randomness generation. The impact includes:

1. **Individual Node Crashes**: Any validator node can be crashed by exploiting this race condition
2. **Network Availability Impact**: If multiple validators are crashed simultaneously, the network's ability to produce randomness and finalize blocks is degraded
3. **Repeated Attacks**: The attack can be repeated after node restart, causing persistent availability issues
4. **No Recovery Beyond Restart**: While nodes can restart, repeated exploitation could cause prolonged network disruption

Per the Aptos bug bounty criteria, this qualifies as **High Severity** due to:
- "Validator node slowdowns" (crashes are worse than slowdowns)
- "API crashes" (consensus node crashes)
- Degradation of network randomness generation capability

This does NOT reach Critical severity because:
- It doesn't cause permanent network partition (nodes can restart)
- It doesn't violate consensus safety (no fork or double-spend)
- It doesn't cause fund loss or permanent freezing
- It doesn't halt the entire network (only affects individual nodes)

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is feasible with the following characteristics:

1. **Triggerable Conditions**: Consensus resets occur naturally during:
   - Epoch transitions
   - Round synchronization
   - Recovery from temporary network issues
   - Normal consensus operations

2. **Attacker Requirements**: Byzantine validators need to:
   - Monitor for reset events (observable through network activity or by triggering them)
   - Send randomness shares for recently-processed rounds immediately after reset
   - The timing window is narrow (~300ms sleep duration) but exploitable with automated monitoring

3. **Natural Occurrence**: This can also trigger **without malicious intent**:
   - Honest validators may resend shares after observing reset events
   - Network delays could cause shares to arrive in the vulnerable window
   - Makes this a reliability issue even without active attackers

4. **No Special Privileges**: Any validator can send valid randomness shares, no special access required beyond being part of the validator set

5. **Repeatability**: The attack can be repeated indefinitely, making it a serious availability threat

## Recommendation

The issue can be fixed by ensuring that `get_all_shares_authors()` is never called on a `PendingMetadata` item. Several approaches:

1. **Check state before calling**: In the async task, check the item's state after acquiring the lock and gracefully handle the `PendingMetadata` case instead of assuming it's always `PendingDecision`:

```rust
let maybe_existing_shares = {
    let store = rand_store.lock();
    match store.rand_map.get(&round) {
        Some(item) => item.get_all_shares_authors(),
        None => None, // Item was removed by reset
    }
};
```

2. **Use async-aware abort mechanism**: Replace the synchronous `Mutex` with an async-aware lock (like `tokio::sync::Mutex`) so that the abort can be checked during lock acquisition.

3. **Make get_all_shares_authors defensive**: Instead of using `unreachable!()`, return `None` for `PendingMetadata` and handle it gracefully in the caller.

4. **Add abort check after lock acquisition**: Explicitly check if the task should abort after acquiring the lock but before calling `get_all_shares_authors()`.

## Proof of Concept

While a complete end-to-end PoC requires setting up a full consensus environment with precise timing control, the vulnerability can be demonstrated conceptually:

```rust
// Conceptual PoC showing the race condition
// 1. Block arrives, task spawned with 300ms sleep
// 2. Reset occurs at T+200ms, drops DropGuard, removes item
// 3. Share arrives at T+250ms, creates PendingMetadata item
// 4. Task wakes at T+300ms, poll starts, passes abort check
// 5. Task blocks on lock while reset holds it
// 6. Task acquires lock after reset completes
// 7. get_all_shares_authors() called on PendingMetadata → panic!

// The vulnerability relies on:
// - Timing: reset during the 300ms sleep window
// - Share arrival after reset but before task execution
// - Poll executing past abort check before synchronous code completes
```

A full PoC would require:
1. Setting up a test consensus environment
2. Instrumenting timing to trigger reset during the sleep window
3. Sending shares immediately after reset
4. Observing the panic when `unreachable!()` is triggered

The core issue is architectural: the `Abortable` mechanism provides cancellation at await points only, but the code assumes synchronous execution can be aborted mid-flight.

## Notes

This vulnerability highlights a subtle interaction between Rust's async/await model and the abort mechanism. The `DropGuard` pattern is widely used throughout the Aptos consensus codebase for managing long-running tasks, and similar issues may exist in other locations where synchronous code executes between await points after an abortable task is dropped.

The fix should ensure either:
1. All code after an await point in an abortable task completes quickly without blocking operations, OR
2. The code defensively handles cases where invariants assumed at task spawn time may no longer hold due to concurrent operations

This is a legitimate protocol vulnerability affecting consensus node availability, not a network-level DoS attack.

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L195-205)
```rust
    fn get_all_shares_authors(&self) -> Option<HashSet<Author>> {
        match self {
            RandItem::PendingDecision {
                share_aggregator, ..
            } => Some(share_aggregator.shares.keys().cloned().collect()),
            RandItem::Decided { .. } => None,
            RandItem::PendingMetadata(_) => {
                unreachable!("Should only be called after block is added")
            },
        }
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L253-259)
```rust
    pub fn reset(&mut self, round: u64) {
        self.update_highest_known_round(round);
        // remove future rounds items in case they're already decided
        // otherwise if the block re-enters the queue, it'll be stuck
        let _ = self.rand_map.split_off(&round);
        let _ = self.fast_rand_map.as_mut().map(|map| map.split_off(&round));
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L280-288)
```rust
    pub fn add_share(&mut self, share: RandShare<S>, path: PathType) -> anyhow::Result<bool> {
        ensure!(
            share.metadata().epoch == self.epoch,
            "Share from different epoch"
        );
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L302-308)
```rust
            (
                &self.rand_config,
                self.rand_map
                    .entry(rand_metadata.round)
                    .or_insert_with(|| RandItem::new(self.author, PathType::Slow)),
            )
        };
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L145-169)
```rust
    fn process_incoming_metadata(&self, metadata: FullRandMetadata) -> DropGuard {
        let self_share = S::generate(&self.config, metadata.metadata.clone());
        info!(LogSchema::new(LogEvent::BroadcastRandShare)
            .epoch(self.epoch_state.epoch)
            .author(self.author)
            .round(metadata.round()));
        let mut rand_store = self.rand_store.lock();
        rand_store.update_highest_known_round(metadata.round());
        rand_store
            .add_share(self_share.clone(), PathType::Slow)
            .expect("Add self share should succeed");

        if let Some(fast_config) = &self.fast_config {
            let self_fast_share =
                FastShare::new(S::generate(fast_config, metadata.metadata.clone()));
            rand_store
                .add_share(self_fast_share.rand_share(), PathType::Fast)
                .expect("Add self share for fast path should succeed");
        }

        rand_store.add_rand_metadata(metadata.clone());
        self.network_sender
            .broadcast_without_self(RandMessage::<S, D>::Share(self_share).into_network_message());
        self.spawn_aggregate_shares_task(metadata.metadata)
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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L263-303)
```rust
    fn spawn_aggregate_shares_task(&self, metadata: RandMetadata) -> DropGuard {
        let rb = self.reliable_broadcast.clone();
        let aggregate_state = Arc::new(ShareAggregateState::new(
            self.rand_store.clone(),
            metadata.clone(),
            self.config.clone(),
        ));
        let epoch_state = self.epoch_state.clone();
        let round = metadata.round;
        let rand_store = self.rand_store.clone();
        let task = async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Start broadcasting share request for {}",
                    targets.len(),
                );
                rb.multicast(request, aggregate_state, targets)
                    .await
                    .expect("Broadcast cannot fail");
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Finish broadcasting share request",
                );
            }
        };
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(task, abort_registration));
        DropGuard::new(abort_handle)
    }
```

**File:** consensus/src/rand/rand_gen/block_queue.rs (L16-40)
```rust
/// Maintain the ordered blocks received from consensus and corresponding randomness
pub struct QueueItem {
    ordered_blocks: OrderedBlocks,
    offsets_by_round: HashMap<Round, usize>,
    num_undecided_blocks: usize,
    broadcast_handle: Option<Vec<DropGuard>>,
}

impl QueueItem {
    pub fn new(ordered_blocks: OrderedBlocks, broadcast_handle: Option<Vec<DropGuard>>) -> Self {
        let len = ordered_blocks.ordered_blocks.len();
        assert!(len > 0);
        let offsets_by_round: HashMap<Round, usize> = ordered_blocks
            .ordered_blocks
            .iter()
            .enumerate()
            .map(|(idx, b)| (b.round(), idx))
            .collect();
        Self {
            ordered_blocks,
            offsets_by_round,
            num_undecided_blocks: len,
            broadcast_handle,
        }
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L222-236)
```rust
pub struct DropGuard {
    abort_handle: AbortHandle,
}

impl DropGuard {
    pub fn new(abort_handle: AbortHandle) -> Self {
        Self { abort_handle }
    }
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```
