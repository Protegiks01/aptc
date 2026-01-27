# Audit Report

## Title
StateSnapshotCommitter Deadlock on Early Channel Disconnection

## Summary
The `StateSnapshotCommitter::run()` method does not handle gracefully when its input channel's sender is dropped before any messages are sent. While the method itself exits cleanly, the subsequent `Drop` implementation deadlocks indefinitely when attempting to join the spawned `StateMerkleBatchCommitter` thread, as no exit signal is sent to that thread before the join attempt.

## Finding Description

The `StateSnapshotCommitter` spawns a background thread running `StateMerkleBatchCommitter` during construction. [1](#0-0) 

When `run()` is called and the sender of `state_snapshot_commit_receiver` has already been dropped, the receive operation immediately returns `Err`, causing the while loop to exit. [2](#0-1) 

The critical issue occurs in the `Drop` implementation, which attempts to join the spawned thread without first signaling it to exit. [3](#0-2) 

Due to Rust's drop order semantics, the explicit `Drop::drop` implementation runs before struct fields are dropped. At the time `join()` is called, the `state_merkle_batch_commit_sender` field is still alive. The spawned thread remains blocked in `recv()`, waiting for messages that will never arrive. [4](#0-3) 

The spawned thread only exits when it receives a `CommitMessage::Exit`, but this is never sent when the main loop exits due to channel disconnection. In normal operation, the `Exit` message is sent from the parent `BufferedState::quit()` method before the thread join. [5](#0-4) 

However, if `BufferedState` is dropped abnormally (e.g., due to a panic in `sync_commit()` before the Exit message is sent), or in any scenario where the sender is dropped without sending Exit, the deadlock occurs.

## Impact Explanation

This issue qualifies as **Medium to High Severity** based on Aptos bug bounty criteria:

- **Validator node slowdowns/hangs**: The thread deadlock prevents graceful shutdown and causes indefinite resource blocking. If this occurs during node operation, it could prevent the node from shutting down cleanly or responding to management operations.

- **State inconsistencies requiring intervention**: A hung thread could prevent proper state cleanup, potentially requiring manual intervention or node restart.

The impact is limited by the fact that this requires specific error conditions to trigger, but when it does occur, it completely blocks the affected thread indefinitely.

## Likelihood Explanation

The likelihood is **Medium**:

- **Requires error conditions**: The scenario requires the `BufferedState` to be dropped or encounter a panic before sending the Exit message, which should be rare in normal operation.

- **Realistic scenarios**: This can occur during:
  - Node shutdown with concurrent errors
  - Panic in `sync_commit()` or other cleanup paths
  - Testing or edge case scenarios where proper cleanup is not performed
  - State store reset operations with error conditions

- **Not directly exploitable**: An external attacker cannot directly trigger this without first causing other errors in the node's operation.

## Recommendation

Send a `CommitMessage::Exit` to the spawned thread before attempting to join it in the Drop implementation:

```rust
impl Drop for StateSnapshotCommitter {
    fn drop(&mut self) {
        // Signal the spawned thread to exit before joining
        let _ = self.state_merkle_batch_commit_sender.send(CommitMessage::Exit);
        
        self.join_handle
            .take()
            .expect("state merkle batch commit thread must exist.")
            .join()
            .expect("state merkle batch thread should join peacefully.");
    }
}
```

This ensures the spawned thread receives an exit signal even when the main loop exits early due to channel disconnection.

## Proof of Concept

```rust
// This is a conceptual PoC demonstrating the deadlock scenario
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn test_state_snapshot_committer_early_disconnect() {
    // Simulate the construction
    let (sender, receiver) = mpsc::sync_channel(0);
    
    // Create StateSnapshotCommitter with the receiver
    let state_db = Arc::new(create_test_state_db());
    let last_snapshot = create_test_snapshot();
    let persisted_state = create_test_persisted_state();
    
    // Spawn the committer thread (simulating BufferedState::new_at_snapshot)
    let handle = thread::spawn(move || {
        let committer = StateSnapshotCommitter::new(
            state_db,
            receiver,  // Takes ownership of receiver
            last_snapshot,
            persisted_state,
        );
        committer.run();  // Will exit immediately if sender is dropped
    });
    
    // Drop the sender immediately without sending Exit message
    drop(sender);
    
    // Attempt to join with timeout to demonstrate the hang
    match handle.join_timeout(Duration::from_secs(5)) {
        Ok(_) => panic!("Thread should have hung but completed"),
        Err(_) => {
            // Thread is hung - this demonstrates the deadlock
            println!("DEADLOCK CONFIRMED: Thread hung indefinitely");
        }
    }
}
```

**Notes**

This vulnerability is a robustness/reliability issue in error handling rather than a directly exploitable security flaw. It requires internal error conditions to trigger but can cause significant operational issues when it occurs. The fix is straightforward: ensure proper cleanup signals are sent before blocking on thread joins, following the same pattern used in the normal `BufferedState::quit()` path.

### Citations

**File:** storage/aptosdb/src/state_store/state_snapshot_committer.rs (L67-77)
```rust
        let join_handle = std::thread::Builder::new()
            .name("state_batch_committer".to_string())
            .spawn(move || {
                let committer = StateMerkleBatchCommitter::new(
                    arc_state_db,
                    state_merkle_batch_commit_receiver,
                    persisted_state.clone(),
                );
                committer.run();
            })
            .expect("Failed to spawn state merkle batch committer thread.");
```

**File:** storage/aptosdb/src/state_store/state_snapshot_committer.rs (L88-200)
```rust
        while let Ok(msg) = self.state_snapshot_commit_receiver.recv() {
            match msg {
                CommitMessage::Data(snapshot) => {
                    let version = snapshot.version().expect("Cannot be empty");
                    let base_version = self.last_snapshot.version();
                    let previous_epoch_ending_version = self
                        .state_db
                        .ledger_db
                        .metadata_db()
                        .get_previous_epoch_ending(version)
                        .unwrap()
                        .map(|(v, _e)| v);
                    let min_version = self.last_snapshot.next_version();

                    // Element format: (key_hash, Option<(value_hash, key)>)
                    let (hot_updates, all_updates): (Vec<_>, Vec<_>) = snapshot
                        .make_delta(&self.last_snapshot)
                        .shards
                        .iter()
                        .map(|updates| {
                            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["hash_jmt_updates"]);
                            let mut hot_updates = Vec::new();
                            let mut all_updates = Vec::new();
                            for (key, slot) in updates.iter() {
                                if slot.is_hot() {
                                    hot_updates.push((
                                        CryptoHash::hash(&key),
                                        Some((
                                            HotStateValueRef::from_slot(&slot).hash(),
                                            key.clone(),
                                        )),
                                    ));
                                } else {
                                    hot_updates.push((CryptoHash::hash(&key), None));
                                }
                                if let Some(value) = slot.maybe_update_jmt(key, min_version) {
                                    all_updates.push(value);
                                }
                            }
                            (hot_updates, all_updates)
                        })
                        .unzip();

                    // TODO(HotState): for now we use `is_descendant_of` to determine if hot state
                    // summary is computed at all. When it's not enabled everything is
                    // `SparseMerkleTree::new_empty()`.
                    let hot_state_merkle_batch_opt = if snapshot
                        .summary()
                        .hot_state_summary
                        .is_descendant_of(&self.last_snapshot.summary().hot_state_summary)
                    {
                        self.state_db.hot_state_merkle_db.as_ref().map(|db| {
                            Self::merklize(
                                db,
                                base_version,
                                version,
                                &self.last_snapshot.summary().hot_state_summary,
                                &snapshot.summary().hot_state_summary,
                                hot_updates.try_into().expect("Must be 16 shards."),
                                previous_epoch_ending_version,
                            )
                            .expect("Failed to compute JMT commit batch for hot state.")
                            .0
                        })
                    } else {
                        // TODO(HotState): this means that the relevant code path isn't enabled yet.
                        None
                    };
                    let (state_merkle_batch, leaf_count) = Self::merklize(
                        &self.state_db.state_merkle_db,
                        base_version,
                        version,
                        &self.last_snapshot.summary().global_state_summary,
                        &snapshot.summary().global_state_summary,
                        all_updates.try_into().expect("Must be 16 shards."),
                        previous_epoch_ending_version,
                    )
                    .expect("Failed to compute JMT commit batch.");
                    let usage = snapshot.state().usage();
                    if !usage.is_untracked() {
                        assert_eq!(
                            leaf_count,
                            usage.items(),
                            "Num of state items mismatch: jmt: {}, state: {}",
                            leaf_count,
                            usage.items(),
                        );
                    }

                    self.last_snapshot = snapshot.clone();

                    self.state_merkle_batch_commit_sender
                        .send(CommitMessage::Data(StateMerkleCommit {
                            snapshot,
                            hot_batch: hot_state_merkle_batch_opt,
                            cold_batch: state_merkle_batch,
                        }))
                        .unwrap();
                },
                CommitMessage::Sync(finish_sender) => {
                    self.state_merkle_batch_commit_sender
                        .send(CommitMessage::Sync(finish_sender))
                        .unwrap();
                },
                CommitMessage::Exit => {
                    self.state_merkle_batch_commit_sender
                        .send(CommitMessage::Exit)
                        .unwrap();
                    break;
                },
            }
        }
        info!("State snapshot committing thread exit.");
```

**File:** storage/aptosdb/src/state_store/state_snapshot_committer.rs (L263-271)
```rust
impl Drop for StateSnapshotCommitter {
    fn drop(&mut self) {
        self.join_handle
            .take()
            .expect("state merkle batch commit thread must exist.")
            .join()
            .expect("state merkle batch thread should join peacefully.");
    }
}
```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L52-114)
```rust
    pub fn run(self) {
        while let Ok(msg) = self.state_merkle_batch_receiver.recv() {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["batch_committer_work"]);
            match msg {
                CommitMessage::Data(StateMerkleCommit {
                    snapshot,
                    hot_batch,
                    cold_batch,
                }) => {
                    let base_version = self.persisted_state.get_state_summary().version();
                    let current_version = snapshot
                        .version()
                        .expect("Current version should not be None");

                    // commit jellyfish merkle nodes
                    let _timer =
                        OTHER_TIMERS_SECONDS.timer_with(&["commit_jellyfish_merkle_nodes"]);
                    if let Some(hot_state_merkle_batch) = hot_batch {
                        self.commit(
                            self.state_db
                                .hot_state_merkle_db
                                .as_ref()
                                .expect("Hot state merkle db must exist."),
                            current_version,
                            hot_state_merkle_batch,
                        )
                        .expect("Hot state merkle nodes commit failed.");
                    }
                    self.commit(&self.state_db.state_merkle_db, current_version, cold_batch)
                        .expect("State merkle nodes commit failed.");

                    info!(
                        version = current_version,
                        base_version = base_version,
                        root_hash = snapshot.summary().root_hash(),
                        hot_root_hash = snapshot.summary().hot_root_hash(),
                        "State snapshot committed."
                    );
                    LATEST_SNAPSHOT_VERSION.set(current_version as i64);
                    // TODO(HotState): no pruning for hot state right now, since we always reset it
                    // upon restart.
                    self.state_db
                        .state_merkle_pruner
                        .maybe_set_pruner_target_db_version(current_version);
                    self.state_db
                        .epoch_snapshot_pruner
                        .maybe_set_pruner_target_db_version(current_version);

                    self.check_usage_consistency(&snapshot).unwrap();

                    snapshot
                        .summary()
                        .global_state_summary
                        .log_generation("buffered_state_commit");
                    self.persisted_state.set(snapshot);
                },
                CommitMessage::Sync(finish_sender) => finish_sender.send(()).unwrap(),
                CommitMessage::Exit => {
                    break;
                },
            }
        }
        trace!("State merkle batch committing thread exit.")
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L181-189)
```rust
    pub(crate) fn quit(&mut self) {
        if let Some(handle) = self.join_handle.take() {
            self.sync_commit();
            self.state_commit_sender.send(CommitMessage::Exit).unwrap();
            handle
                .join()
                .expect("snapshot commit thread should join peacefully.");
        }
    }
```
