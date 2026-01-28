# Audit Report

## Title
State Corruption and Validator Crash in SecretShareStore Due to Unsafe Error Handling in add_share_with_metadata()

## Summary
The `SecretShareStore::add_self_share()` function contains a critical error handling bug that corrupts the secret share aggregator state and causes validator crashes during block reprocessing scenarios. The unsafe use of `std::mem::replace()` in `add_share_with_metadata()` leaves the store in an inconsistent state when errors occur, violating state consistency invariants and triggering node panics.

## Finding Description

The vulnerability exists in the `add_share_with_metadata()` method's error handling pattern in `SecretShareItem`. [1](#0-0) 

The function uses `std::mem::replace(self, Self::new(Author::ONE))` to temporarily move out the current state before checking validity. [2](#0-1)  If the item is in `PendingDecision` state, the function bails with an error without restoring the original state. [3](#0-2)  This leaves the `SecretShareItem` corrupted with a fresh `PendingMetadata` aggregator containing `Author::ONE` instead of the actual validator author, and all previously collected shares are permanently lost. The state restoration at line 180 is never reached when the bail occurs.

The bug is triggered when `add_self_share()` is called on a round that already has metadata (i.e., is in `PendingDecision` state). This occurs during the following realistic scenario:

1. **Normal block processing**: Validator processes block at round R, calling `add_self_share()` which transitions the entry from `PendingMetadata` to `PendingDecision` state. [4](#0-3) 

2. **State sync/reset occurs**: The validator receives a `ResetRequest` (e.g., during state synchronization). The reset clears the `block_queue` but critically does NOT clear the `secret_share_map`. [5](#0-4) 

3. **Block reprocessing**: After reset, consensus re-sends blocks including round R. The `process_incoming_block()` method calls `add_self_share()` again for the same round. [6](#0-5) 

4. **State corruption**: The existing entry is in `PendingDecision` state, causing `add_share_with_metadata()` to bail at line 176, but the state has already been replaced at line 161 and is never restored at line 180.

5. **Validator crash**: The error propagates to the `.expect()` causing the validator node to panic with "Add self dec share should succeed". [7](#0-6) 

This breaks the **State Consistency** invariant (state transitions must be atomic) and can break **Consensus Safety** if different validators experience this at different times, leading to divergent randomness states.

## Impact Explanation

**Severity: HIGH** ($50,000 tier under Aptos bug bounty)

This vulnerability causes:

1. **Validator Node Crashes**: The `.expect()` in the caller immediately panics the validator when the error occurs, causing availability loss and triggering the "Validator node slowdowns / API crashes / Significant protocol violations" category.

2. **State Corruption**: Even if error handling were improved to prevent the crash, the corrupted state persists with wrong author (`Author::ONE`) and lost shares, violating the integrity of the secret sharing aggregator.

3. **Consensus Liveness Failure**: Randomness generation fails for affected rounds, potentially blocking blocks that depend on that randomness and impacting overall network liveness.

4. **Non-Deterministic Failures**: Different validators may experience this at different times during state sync, causing consensus divergence in randomness generation state.

The impact qualifies as **High Severity** under "Validator node slowdowns / API crashes / Significant protocol violations" in the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This bug triggers during common operational scenarios:

- **State synchronization**: Validators regularly perform state sync when catching up after network disruptions or when new validators join
- **Network disruptions**: Temporary network issues trigger resets and block reprocessing
- **Epoch transitions**: Boundary conditions during epoch changes may cause block reprocessing
- **No attacker required**: This is a pure implementation bug requiring no malicious actors

The window of vulnerability occurs when:
- A block has been processed (state is `PendingDecision`)
- A reset occurs before the share reaches `Decided` state
- The same block is reprocessed

Given that `FUTURE_ROUNDS_TO_ACCEPT` is 200 rounds [8](#0-7) , there's a significant window where rounds remain in the map during normal operations, increasing the likelihood of hitting this bug during resets.

## Recommendation

The fix requires ensuring atomicity of the state transition in `add_share_with_metadata()`. The recommended approach is to validate the state **before** performing the `std::mem::replace()`, or to use a proper state restoration mechanism in case of errors:

```rust
fn add_share_with_metadata(
    &mut self,
    share: SecretShare,
    share_weights: &HashMap<Author, u64>,
) -> anyhow::Result<()> {
    // Check state BEFORE moving out
    if matches!(self, SecretShareItem::PendingDecision { .. }) {
        bail!("Cannot add self share in PendingDecision state");
    }
    if matches!(self, SecretShareItem::Decided { .. }) {
        return Ok(());
    }
    
    // Now safe to proceed with state transition
    let item = std::mem::replace(self, Self::new(Author::ONE));
    let share_weight = *share_weights
        .get(share.author())
        .expect("Author must exist in weights");
    
    let new_item = match item {
        SecretShareItem::PendingMetadata(mut share_aggregator) => {
            let metadata = share.metadata.clone();
            share_aggregator.retain(share.metadata(), share_weights);
            share_aggregator.add_share(share, share_weight);
            SecretShareItem::PendingDecision {
                metadata,
                share_aggregator,
            }
        },
        _ => unreachable!("Already checked above"),
    };
    let _ = std::mem::replace(self, new_item);
    Ok(())
}
```

Alternatively, improve error handling in `secret_share_manager.rs` to gracefully handle this error instead of using `.expect()`.

## Proof of Concept

The vulnerability can be demonstrated through the following sequence:

1. Deploy a validator node and process blocks normally
2. Trigger a `ResetRequest` (simulating state sync) after a block has been processed but before randomness is decided
3. Re-send the same block for processing
4. Observe that `add_self_share()` is called on an entry already in `PendingDecision` state
5. The state becomes corrupted with `Author::ONE` and the validator panics with "Add self dec share should succeed"

A unit test demonstrating this would involve:
- Creating a `SecretShareItem` in `PendingMetadata` state
- Calling `add_share_with_metadata()` to transition to `PendingDecision`
- Calling `add_share_with_metadata()` again on the same item
- Verifying that the state is corrupted (has `Author::ONE` instead of original author)

## Notes

This is a legitimate implementation bug in the consensus layer's secret sharing component that can cause validator crashes during normal operational scenarios like state synchronization. The vulnerability affects the randomness generation subsystem which is critical for consensus security. The bug is in production code (not tests), requires no attacker, and has concrete impact on validator availability and state consistency.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L156-182)
```rust
    fn add_share_with_metadata(
        &mut self,
        share: SecretShare,
        share_weights: &HashMap<Author, u64>,
    ) -> anyhow::Result<()> {
        let item = std::mem::replace(self, Self::new(Author::ONE));
        let share_weight = *share_weights
            .get(share.author())
            .expect("Author must exist in weights");
        let new_item = match item {
            SecretShareItem::PendingMetadata(mut share_aggregator) => {
                let metadata = share.metadata.clone();
                share_aggregator.retain(share.metadata(), share_weights);
                share_aggregator.add_share(share, share_weight);
                SecretShareItem::PendingDecision {
                    metadata,
                    share_aggregator,
                }
            },
            SecretShareItem::PendingDecision { .. } => {
                bail!("Cannot add self share in PendingDecision state");
            },
            SecretShareItem::Decided { .. } => return Ok(()),
        };
        let _ = std::mem::replace(self, new_item);
        Ok(())
    }
```

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

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```
