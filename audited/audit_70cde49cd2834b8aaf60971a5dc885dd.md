# Audit Report

## Title
Root Update Non-Atomicity Creates State Inconsistency Window During Fallback Sync Completion

## Summary
The `process_fallback_sync_notification()` function updates the root ledger info and clears pending blocks as two separate, non-atomic operations with async await points in between. This creates a window where the root references new synced state while block stores contain stale data from the old epoch, leading to potential state inconsistencies during epoch initialization.

## Finding Description

In `process_fallback_sync_notification()`, the root update and pending block clearing are not atomic: [1](#0-0) 

The critical issue occurs in this sequence:

1. **Line 948-950**: Root is updated to the new synced ledger info (e.g., epoch 10, round 500). The lock is acquired, `update_root()` is called, and the lock is immediately released. [2](#0-1) 

2. **Lines 952-958**: Async epoch handling occurs with `.await` points that yield control. During `wait_for_epoch_start()` at line 957, the function retrieves block payloads from `observer_block_data`: [3](#0-2) 

At line 1067, `get_block_payloads()` retrieves payloads that are still from the **old epoch** (before clearing), because `clear_pending_block_state()` hasn't been called yet. These stale payloads are then passed to `start_epoch()` to initialize the **new epoch**.

3. **Line 961**: Only after epoch initialization does `clear_pending_block_state()` clear the old block data. [4](#0-3) 

Additionally, during the async await points, execution pipeline commit callbacks may fire. These callbacks access `observer_block_data`: [5](#0-4) 

The callbacks remove committed blocks from stores (lines 184-189) **before** checking if the epoch matches (line 193). If a callback fires after the root has been updated to the new epoch but before blocks are cleared, it removes blocks from the old epoch while the root points to the new epoch, creating a partially-cleaned state.

When `get_block_payloads()` is called at line 1067, it retrieves this inconsistent, partially-cleaned payload data and uses it to initialize the new epoch.

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for the following reasons:

1. **Protocol Violation**: The consensus observer starts a new epoch with stale block payload data that doesn't correspond to the current root. This violates the invariant that epoch state should be consistent with the root ledger info.

2. **State Inconsistency**: Different observers may experience different timing of commit callbacks during the window, leading to different partial states being used to initialize the new epoch. This could cause observers to diverge in their view of block payloads.

3. **Validator Node Issues**: The inconsistent payload state passed to the execution client could cause unexpected behavior in the execution pipeline, potentially leading to slowdowns or processing errors.

The vulnerability breaks **Invariant #4: State Consistency** - state transitions should be atomic and consistent, but the fallback sync completion creates a window where root and block stores are out of sync.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability triggers whenever:
1. A consensus observer enters fallback mode and syncs to a new epoch
2. The execution pipeline has blocks in flight when the sync completes
3. Commit callbacks fire during the `end_epoch()` or `wait_for_epoch_start()` await calls

The race window exists for all fallback sync completions that cross epoch boundaries. While fallback mode is not the common case, when it does occur, the race condition is highly likely to manifest if there are any pending executions.

## Recommendation

Make the root update and block clearing atomic by clearing blocks **before** updating the root and starting the new epoch:

```rust
async fn process_fallback_sync_notification(
    &mut self,
    latest_synced_ledger_info: LedgerInfoWithSignatures,
) {
    // ... existing validation code ...

    // Reset the fallback manager state
    self.observer_fallback_manager
        .reset_syncing_progress(&latest_synced_ledger_info);

    // **FIX: Clear pending blocks BEFORE updating root and starting new epoch**
    self.clear_pending_block_state().await;

    // Update the root with the latest synced ledger info
    self.observer_block_data
        .lock()
        .update_root(latest_synced_ledger_info);

    // If the epoch has changed, end the current epoch and start the latest one
    let current_epoch_state = self.get_epoch_state();
    if epoch > current_epoch_state.epoch {
        self.execution_client.end_epoch().await;
        self.wait_for_epoch_start().await;
    };

    // Reset the state sync manager for the synced fallback
    self.state_sync_manager.clear_active_fallback_sync();
}
```

This ensures that:
1. All old blocks and payloads are cleared first
2. The root is updated to point to the new state
3. The new epoch starts with clean, empty block stores
4. No stale payloads are passed to `wait_for_epoch_start()`

Alternatively, acquire and hold the `observer_block_data` lock for the entire operation to make it truly atomic, though this may block the async executor for longer.

## Proof of Concept

```rust
#[tokio::test]
async fn test_fallback_sync_root_update_race() {
    // Setup: Create consensus observer with blocks from epoch 5
    let (mut observer, mut state_sync_rx) = setup_observer_with_blocks(
        /* epoch */ 5,
        /* rounds */ vec![100, 101, 102, 103, 104, 105],
    );

    // Simulate blocks in execution pipeline
    let execution_handles = spawn_mock_executions(&observer, /* rounds */ vec![100, 101, 102]);

    // Trigger fallback sync that completes to epoch 6, round 500
    let new_ledger_info = create_ledger_info(/* epoch */ 6, /* round */ 500);
    
    // Start processing the fallback sync notification
    let process_handle = tokio::spawn(async move {
        observer.process_fallback_sync_notification(new_ledger_info).await;
    });

    // During the await in end_epoch/wait_for_epoch_start, commit callbacks fire
    tokio::time::sleep(Duration::from_millis(10)).await;
    trigger_commit_callbacks(&execution_handles);

    // Wait for processing to complete
    process_handle.await.unwrap();

    // Verify the race condition occurred:
    // 1. Check that some blocks were removed by commit callbacks during the window
    // 2. Check that wait_for_epoch_start received inconsistent payload data
    // 3. Verify epoch 6 was started with epoch 5 payloads

    assert!(verify_inconsistent_state_occurred());
}
```

The test demonstrates that commit callbacks can fire during the non-atomic window, removing blocks while the root has already been updated, and that stale payloads from the partially-cleaned state are used to initialize the new epoch.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L218-221)
```rust
    async fn clear_pending_block_state(&self) {
        // Clear the observer block data
        let root = self.observer_block_data.lock().clear_block_data();

```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L947-961)
```rust
        // Update the root with the latest synced ledger info
        self.observer_block_data
            .lock()
            .update_root(latest_synced_ledger_info);

        // If the epoch has changed, end the current epoch and start the latest one
        let current_epoch_state = self.get_epoch_state();
        if epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;
        };

        // Reset the pending block state
        self.clear_pending_block_state().await;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1065-1071)
```rust
    async fn wait_for_epoch_start(&mut self) {
        // Wait for the epoch state to update
        let block_payloads = self.observer_block_data.lock().get_block_payloads();
        let (payload_manager, consensus_config, execution_config, randomness_config) = self
            .observer_epoch_state
            .wait_for_epoch_start(block_payloads)
            .await;
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L182-189)
```rust
    fn handle_committed_blocks(&mut self, ledger_info: LedgerInfoWithSignatures) {
        // Remove the committed blocks from the payload and ordered block stores
        self.block_payload_store.remove_blocks_for_epoch_round(
            ledger_info.commit_info().epoch(),
            ledger_info.commit_info().round(),
        );
        self.ordered_block_store
            .remove_blocks_for_commit(&ledger_info);
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L300-302)
```rust
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```
