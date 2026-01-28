# Audit Report

## Title
Validator Node Crash During State Sync Due to Missing SecretShareStore Reset

## Summary
The `SecretShareManager` is not reset during state synchronization, causing validator nodes to crash when reprocessing blocks after `sync_to_target()`. The shared `SecretShareStore` retains stale entries from before the reset, and attempting to add self-shares for previously processed rounds triggers a panic, resulting in validator unavailability.

## Finding Description

The vulnerability exists in how the secret sharing pipeline handles state synchronization. The `SecretShareStore` uses a `HashMap<Round, SecretShareItem>` indexed by round only: [1](#0-0) 

When a block is processed, its self-share is added via `add_self_share()`, which calls `add_share_with_metadata()` to transition the round's entry from `PendingMetadata` to `PendingDecision` state. The critical bug occurs when `add_share_with_metadata()` is called on an item already in `PendingDecision` state - it unconditionally fails: [2](#0-1) 

This failure is treated as fatal and causes a panic in `process_incoming_block()`: [3](#0-2) 

**The vulnerability is triggered during state synchronization:**

When `sync_to_target()` is called, it invokes the `reset()` method which only resets the rand manager and buffer manager: [4](#0-3) 

The `reset()` method retrieves only `reset_tx_to_rand_manager` and `reset_tx_to_buffer_manager`, completely omitting `reset_tx_to_secret_share_manager` even though it exists in the `BufferManagerHandle`: [5](#0-4) 

Even the `SecretShareManager::process_reset()` method only updates `highest_known_round` and clears the block queue, but does NOT clear the `secret_share_map`: [6](#0-5) 

**Attack Scenario:**
1. Validator processes blocks for rounds 100-110, populating `secret_share_map` with entries in `PendingDecision` state
2. State sync is triggered to round 105 (due to network partition, restart, or falling behind)
3. `sync_to_target()` calls `reset()` which resets buffer and rand managers but NOT secret share manager
4. The `secret_share_map` still contains stale entries for rounds 100-110
5. After sync, blocks for rounds 106-110 are sent through the pipeline again
6. For each block, `process_incoming_block()` calls `add_self_share()`
7. Since round 106 entry already exists in `PendingDecision` state, `add_share_with_metadata()` bails
8. The `.expect("Add self dec share should succeed")` panic is triggered
9. Validator node crashes immediately

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

- **Validator node crashes**: The panic causes immediate termination of the validator process, matching the "Validator Node Slowdowns (High)" category which includes DoS through resource exhaustion and process crashes
- **Loss of liveness**: Affected validators cannot participate in consensus until manually restarted
- **Network degradation**: If multiple validators sync simultaneously (common after network partitions or during coordinated upgrades), the network could lose significant consensus power

While this doesn't directly cause fund loss or consensus safety violations, it represents a significant protocol violation that causes validator unavailability during state synchronization - a critical operation for network recovery.

## Likelihood Explanation

**Likelihood: HIGH**

This issue has high probability of occurrence because:

1. **State sync is routine**: Validators frequently sync when joining the network, recovering from downtime, falling behind during network issues, or performing maintenance restarts
2. **No Byzantine behavior required**: This is a legitimate code path that triggers during normal operations
3. **Deterministic trigger**: Any state sync where the validator previously processed rounds beyond the sync target will trigger the panic
4. **Multiple validators affected**: During network partitions or upgrades, many validators may sync simultaneously, causing coordinated crashes

The vulnerability is in the consensus layer's state management, not dependent on any attacker-controlled input.

## Recommendation

Fix the `reset()` method in `ExecutionProxyClient` to include the secret share manager reset:

```rust
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager, reset_tx_to_secret_share_manager) = {
        let handle = self.handle.read();
        (
            handle.reset_tx_to_rand_manager.clone(),
            handle.reset_tx_to_buffer_manager.clone(),
            handle.reset_tx_to_secret_share_manager.clone(),  // ADD THIS
        )
    };

    if let Some(mut reset_tx) = reset_tx_to_rand_manager {
        // ... existing rand manager reset code ...
    }

    if let Some(mut reset_tx) = reset_tx_to_secret_share_manager {  // ADD THIS BLOCK
        let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
        reset_tx
            .send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::TargetRound(target.commit_info().round()),
            })
            .await
            .map_err(|_| Error::SecretShareResetDropped)?;
        ack_rx.await.map_err(|_| Error::SecretShareResetDropped)?;
    }

    if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
        // ... existing buffer manager reset code ...
    }

    Ok(())
}
```

Additionally, modify `SecretShareManager::process_reset()` to clear the secret_share_map:

```rust
fn process_reset(&mut self, request: ResetRequest) {
    let ResetRequest { tx, signal } = request;
    let target_round = match signal {
        ResetSignal::Stop => 0,
        ResetSignal::TargetRound(round) => round,
    };
    self.block_queue = BlockQueue::new();
    
    // ADD: Clear the secret share store
    let mut store = self.secret_share_store.lock();
    store.secret_share_map.clear();  // Clear stale entries
    store.update_highest_known_round(target_round);
    drop(store);
    
    self.stop = matches!(signal, ResetSignal::Stop);
    let _ = tx.send(ResetAck::default());
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a validator node
2. Processing blocks through rounds 100-110 (populating secret_share_map)
3. Triggering `sync_to_target()` to round 105
4. Sending blocks for rounds 106+ through `finalize_order()` after sync
5. Observing the panic when `add_self_share()` fails on line 147

The exact test would require integration test infrastructure to simulate the full consensus pipeline with state sync, but the code paths are clear from the static analysis.

## Notes

This vulnerability is in the consensus layer's execution client reset logic. The root cause is that `reset()` was designed to reset only the rand and buffer managers, while the secret share manager (which was likely added later) was not included in the reset flow. The fix requires coordinating the reset across all three pipeline managers to maintain consistency during state synchronization.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L175-177)
```rust
            SecretShareItem::PendingDecision { .. } => {
                bail!("Cannot add self share in PendingDecision state");
            },
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L207-214)
```rust
pub struct SecretShareStore {
    epoch: u64,
    self_author: Author,
    secret_share_config: SecretShareConfig,
    secret_share_map: HashMap<Round, SecretShareItem>,
    highest_known_round: u64,
    decision_tx: Sender<SecretSharedKey>,
}
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L145-148)
```rust
            secret_share_store
                .add_self_share(self_secret_share.clone())
                .expect("Add self dec share should succeed");
        }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L172-184)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.secret_share_store
            .lock()
            .update_highest_known_round(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L124-131)
```rust
struct BufferManagerHandle {
    pub execute_tx: Option<UnboundedSender<OrderedBlocks>>,
    pub commit_tx:
        Option<aptos_channel::Sender<AccountAddress, (AccountAddress, IncomingCommitRequest)>>,
    pub reset_tx_to_buffer_manager: Option<UnboundedSender<ResetRequest>>,
    pub reset_tx_to_rand_manager: Option<UnboundedSender<ResetRequest>>,
    pub reset_tx_to_secret_share_manager: Option<UnboundedSender<ResetRequest>>,
}
```

**File:** consensus/src/pipeline/execution_client.rs (L674-709)
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

        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }

        Ok(())
    }
```
