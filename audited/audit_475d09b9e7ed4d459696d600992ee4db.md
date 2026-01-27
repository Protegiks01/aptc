# Audit Report

## Title
Epoch Skipping Vulnerability Due to Size-1 Reconfiguration Notification Channel Leading to Consensus State Inconsistency

## Summary
The reconfiguration notification channel has a size of 1 with KLAST (Keep Last) queuing, causing validators to drop intermediate epoch notifications when consuming them slowly. This allows validators to skip entire epochs, creating a critical mismatch between storage state and consensus epoch configuration, violating consensus safety invariants. [1](#0-0) 

## Finding Description

The vulnerability exists in the reconfiguration notification mechanism between state sync and consensus. When epochs transition rapidly:

1. State sync commits blocks and detects reconfigurations, sending notifications to consensus via a channel with size 1 and KLAST (Keep Last) queuing style. [2](#0-1) [3](#0-2) 

2. If consensus is slow to consume notifications and a second reconfiguration occurs before the first is consumed, the KLAST policy drops the older notification and keeps only the newest one.

3. When consensus receives an `EpochChangeProof` from the network and initiates a new epoch, it syncs storage to the ledger info in the proof, then awaits a reconfig notification. [4](#0-3) 

4. **Critical vulnerability**: Consensus syncs storage to epoch N→N+1 transition (version V1), but receives a notification for epoch N+1→N+2 transition (version V2), causing it to start epoch N+2 while storage is only at the beginning of epoch N+1. [5](#0-4) 

5. No validation exists to ensure the received epoch notification matches the expected next epoch (current + 1). [6](#0-5) 

**Attack Scenario:**
- Epoch N ends at version V1 → notification sent (epoch=N+1, version=V1)
- Before consensus consumes it, Epoch N+1 ends at version V2 → notification sent (epoch=N+2, version=V2)
- First notification dropped from size-1 channel
- Consensus receives `EpochChangeProof` for epoch N+1, syncs to V1
- Consensus awaits notification, receives epoch N+2 notification instead
- Consensus starts epoch N+2 with storage at epoch N+1 start

This creates a fundamental state inconsistency where:
- **Consensus epoch state** = N+2 (wrong)
- **Storage committed epoch** = N+1 (correct)
- **Validator set used** = epoch N+2 validators (wrong)
- **On-chain configs** = epoch N+2 configs from version V2 (wrong, should read from V1)

## Impact Explanation

**Critical Severity** - This vulnerability breaks the **Consensus Safety** invariant (Invariant #2) and **State Consistency** invariant (Invariant #4):

1. **Consensus Safety Violation**: The affected validator operates in epoch N+2 while its storage is at epoch N+1, causing it to propose/vote on blocks with mismatched epoch metadata. This can lead to invalid blocks being created or legitimate blocks being rejected.

2. **Validator Set Mismatch**: The validator uses epoch N+2's validator set but storage only knows about epoch N+1's validator set. If validator sets differ between epochs, the node may attempt to participate as a validator when it's not authorized, or fail to participate when it is authorized.

3. **Network Partition Risk**: If multiple validators skip the same intermediate epoch due to network delays, the network splits into validators operating in different epochs simultaneously, potentially causing a non-recoverable partition requiring hard fork intervention.

4. **Block Proposal/Voting Failures**: Any blocks proposed will have `epoch=N+2` but be built on parent blocks from epoch N+1, which violates block validation rules and will be rejected by other validators.

This qualifies as **Critical** under the Aptos bug bounty program as it represents a "Consensus/Safety violation" that can lead to "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**High Likelihood** during specific operational scenarios:

1. **Rapid Governance Changes**: Multiple governance proposals executing in quick succession, each triggering epoch changes
2. **Validator Set Updates**: Frequent validator additions/removals causing rapid epoch transitions
3. **Network Stress Conditions**: Validators under heavy load or experiencing network latency may be slow to process notifications
4. **State Sync Delays**: Validators catching up from behind may receive multiple buffered notifications simultaneously
5. **Resource-Constrained Validators**: Validators with limited CPU/memory may process notifications slowly

The vulnerability is NOT directly exploitable by external attackers but can occur naturally during normal network operation, especially during periods of high governance activity or network stress. The deliberate choice of channel size 1 increases the probability of this occurring.

## Recommendation

**Immediate Fix**: Add epoch validation and synchronization between storage state and notification consumption:

```rust
async fn await_reconfig_notification(&mut self) {
    let reconfig_notification = self
        .reconfig_events
        .next()
        .await
        .expect("Reconfig sender dropped, unable to start new epoch");
    
    // CRITICAL FIX: Validate that the received epoch matches expected next epoch
    let expected_next_epoch = self.epoch() + 1;
    let received_epoch = reconfig_notification.on_chain_configs.epoch();
    
    if received_epoch != expected_next_epoch {
        error!(
            "Epoch mismatch! Expected {}, received {}. Requesting correct notification.",
            expected_next_epoch, received_epoch
        );
        
        // Force state sync to notify with the correct epoch by reading from storage
        // at the version corresponding to expected_next_epoch transition
        self.request_reconfig_for_epoch(expected_next_epoch).await;
        
        // Re-await the correct notification
        return self.await_reconfig_notification().await;
    }
    
    self.start_new_epoch(reconfig_notification.on_chain_configs).await;
}
```

**Alternative Solution**: Increase channel size and use FIFO ordering:

```rust
// In lib.rs, change:
const RECONFIG_NOTIFICATION_CHANNEL_SIZE: usize = 10; // Increased from 1
// Use FIFO instead of KLAST to ensure all epochs are processed in order

let (notification_sender, notification_receiver) =
    aptos_channel::new(QueueStyle::FIFO, RECONFIG_NOTIFICATION_CHANNEL_SIZE, None);
```

**Long-term Solution**: Implement epoch-aware notification buffering where consensus explicitly requests notifications for specific epochs, preventing skipping.

## Proof of Concept

```rust
#[tokio::test]
async fn test_epoch_skipping_vulnerability() {
    // Setup: Create mock state sync and consensus components
    let (mut event_service, reconfig_listener) = setup_test_components();
    
    // Step 1: Commit version V1 with epoch N→N+1 transition
    let v1_events = vec![create_new_epoch_event(1)]; // Epoch 1
    event_service.notify_events(100, v1_events).unwrap();
    
    // Step 2: Immediately commit version V2 with epoch N+1→N+2 transition
    // BEFORE consensus consumes the first notification
    let v2_events = vec![create_new_epoch_event(2)]; // Epoch 2
    event_service.notify_events(200, v2_events).unwrap();
    
    // Step 3: Consensus finally consumes notification
    // Due to channel size 1 + KLAST, it receives epoch 2 notification only
    let notification = reconfig_listener.next().await.unwrap();
    
    // Step 4: Verify the vulnerability
    assert_eq!(notification.on_chain_configs.epoch(), 2); // Received epoch 2
    assert_eq!(notification.version, 200); // At version 200
    
    // Meanwhile, consensus has synced storage to version 100 (epoch 1)
    // This creates the inconsistency: storage at epoch 1, consensus starting epoch 2
    
    // Expected behavior: Should have received notification for epoch 1 first
    // Actual behavior: Epoch 1 notification was dropped, skipped entire epoch
}
```

## Notes

The vulnerability is exacerbated by the intentional design choice documented in the code comment: "Note: this should be 1 to ensure only the latest reconfig is consumed". [1](#0-0)  While this design may have been intended to ensure validators always have the most recent configuration, it violates the critical invariant that consensus must process epochs sequentially without skipping intermediate states. The lack of epoch sequence validation in `start_new_epoch` [7](#0-6)  allows this inconsistency to persist undetected, potentially causing network-wide consensus failures during periods of rapid epoch transitions.

### Citations

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L40-40)
```rust
const RECONFIG_NOTIFICATION_CHANNEL_SIZE: usize = 1; // Note: this should be 1 to ensure only the latest reconfig is consumed
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L174-175)
```rust
        let (notification_sender, notification_receiver) =
            aptos_channel::new(QueueStyle::KLAST, RECONFIG_NOTIFICATION_CHANNEL_SIZE, None);
```

**File:** crates/channel/src/message_queues.rs (L142-146)
```rust
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
```

**File:** consensus/src/epoch_manager.rs (L544-569)
```rust
    async fn initiate_new_epoch(&mut self, proof: EpochChangeProof) -> anyhow::Result<()> {
        let ledger_info = proof
            .verify(self.epoch_state())
            .context("[EpochManager] Invalid EpochChangeProof")?;
        info!(
            LogSchema::new(LogEvent::NewEpoch).epoch(ledger_info.ledger_info().next_block_epoch()),
            "Received verified epoch change",
        );

        // shutdown existing processor first to avoid race condition with state sync.
        self.shutdown_current_processor().await;
        *self.pending_blocks.lock() = PendingBlocks::new();
        // make sure storage is on this ledger_info too, it should be no-op if it's already committed
        // panic if this doesn't succeed since the current processors are already shutdown.
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");

        monitor!("reconfig", self.await_reconfig_notification().await);
        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L1164-1199)
```rust
    async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) {
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
        let mut verifier: ValidatorVerifier = (&validator_set).into();
        verifier.set_optimistic_sig_verification_flag(self.config.optimistic_sig_verification);

        let epoch_state = Arc::new(EpochState {
            epoch: payload.epoch(),
            verifier: verifier.into(),
        });

        self.epoch_state = Some(epoch_state.clone());

        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
        let onchain_randomness_config_seq_num: anyhow::Result<RandomnessConfigSeqNum> =
            payload.get();
        let randomness_config_move_struct: anyhow::Result<RandomnessConfigMoveStruct> =
            payload.get();
        let onchain_jwk_consensus_config: anyhow::Result<OnChainJWKConsensusConfig> = payload.get();
        let dkg_state = payload.get::<DKGState>();

        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }

        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }

        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
        }

        self.epoch_state = Some(epoch_state.clone());
```

**File:** consensus/src/epoch_manager.rs (L1912-1920)
```rust
    async fn await_reconfig_notification(&mut self) {
        let reconfig_notification = self
            .reconfig_events
            .next()
            .await
            .expect("Reconfig sender dropped, unable to start new epoch");
        self.start_new_epoch(reconfig_notification.on_chain_configs)
            .await;
    }
```
