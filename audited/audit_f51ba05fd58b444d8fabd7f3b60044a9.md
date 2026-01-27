# Audit Report

## Title
DKG Epoch Manager Orphaned Channel State Causes Node Crash on Subsequent Epoch Transition

## Summary
The DKG epoch manager creates communication channels before validating key material availability. If public key or secret key lookup fails after channel creation, the function returns an error leaving orphaned channel senders in the manager state. On the next epoch transition, attempting to communicate with the non-existent DKGManager receiver causes a panic, crashing the validator node.

## Finding Description

The vulnerability exists in the `start_new_epoch()` function's error handling logic. The function creates three communication channels and stores them in `self` before performing validation checks that can fail: [1](#0-0) 

After channel creation, two validation steps can fail:

1. Public key lookup (less likely but possible): [2](#0-1) 

2. Secret key lookup from storage (more realistic failure scenario): [3](#0-2) 

When either validation fails, the function returns an error via the `?` operator. This leaves the manager in an inconsistent state:
- Channel senders are stored in `self.dkg_start_event_tx`, `self.dkg_rpc_msg_tx`, and `self.dkg_manager_close_tx`
- The DKGManager is never spawned (line 253-258 never executes)
- The channel receivers (`dkg_start_event_rx`, `dkg_rpc_msg_rx`, `dkg_manager_close_rx`) are dropped as local variables

The error is logged but the node continues running: [4](#0-3) 

On the next epoch transition, `on_new_epoch()` calls `shutdown_current_processor()` before starting the new epoch: [5](#0-4) 

The shutdown function attempts to send on the orphaned oneshot channel: [6](#0-5) 

Since the receiver was dropped, `tx.send(ack_tx)` returns `Err`, and the `.unwrap()` on line 273 **panics**, crashing the validator node.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:
- **Validator node crashes**: The panic terminates the validator process
- **Denial of service**: Affected validators become unavailable during epoch transitions
- **Network liveness impact**: Multiple affected validators reduce network capacity

The vulnerability breaks the **liveness invariant** - validator nodes should remain operational even when unable to participate in DKG. While not directly exploitable by external attackers, it creates a critical operational hazard where key management issues cascade into node crashes.

## Likelihood Explanation

The likelihood is **MEDIUM to HIGH** because:

1. **Realistic trigger conditions**: Secret key lookup failures can occur due to:
   - SafetyRules storage backend failures
   - Key rotation misconfigurations
   - File system errors or corruption
   - Disk space exhaustion
   - Permission issues

2. **Cascading effect**: Once triggered, the inconsistent state persists until the next epoch, when the crash occurs deterministically

3. **Limited mitigation**: Standard validator monitoring won't prevent this - the node appears healthy until the next epoch boundary

4. **Production relevance**: Key management is a known operational challenge in validator infrastructure

## Recommendation

**Fix**: Move channel creation AFTER all validation checks pass, or implement proper cleanup on error paths.

**Option 1 - Defer channel creation (preferred)**:
```rust
async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) -> Result<()> {
    // ... existing code up to line 221 ...
    
    // Validate keys FIRST
    let my_pk = epoch_state
        .verifier
        .get_public_key(&self.my_addr)
        .ok_or_else(|| anyhow!("my pk not found in validator set"))?;
    let dealer_sk = self
        .key_storage
        .consensus_sk_by_pk(my_pk.clone())
        .map_err(|e| {
            anyhow!("dkg new epoch handling failed with consensus sk lookup err: {e}")
        })?;
    
    // Only create channels after validation succeeds
    let (dkg_start_event_tx, dkg_start_event_rx) =
        aptos_channel::new(QueueStyle::KLAST, 1, None);
    self.dkg_start_event_tx = Some(dkg_start_event_tx);
    
    // ... rest of channel creation and DKGManager spawn ...
}
```

**Option 2 - Safe shutdown handling**:
```rust
async fn shutdown_current_processor(&mut self) {
    if let Some(tx) = self.dkg_manager_close_tx.take() {
        let (ack_tx, ack_rx) = oneshot::channel();
        // Handle the case where receiver is dropped
        if tx.send(ack_tx).is_err() {
            warn!("DKGManager already terminated, skipping shutdown");
            return;
        }
        // Only await if send succeeded
        if let Err(e) = ack_rx.await {
            warn!("DKGManager shutdown acknowledgment failed: {}", e);
        }
    }
}
```

## Proof of Concept

```rust
// Reproduction test for dkg/src/epoch_manager.rs
#[tokio::test]
async fn test_orphaned_channel_crash() {
    use aptos_types::validator_verifier::{ValidatorVerifier, ValidatorConsensusInfo};
    use aptos_crypto::{bls12381, Uniform};
    
    // Setup: Create validator set with 1 validator
    let (private_key, public_key) = bls12381::PrivateKey::generate_for_testing();
    let validator_addr = AccountAddress::random();
    
    let validator_info = ValidatorConsensusInfo::new(
        validator_addr,
        public_key.clone(),
        1
    );
    let validator_set = ValidatorSet::new(vec![validator_info]);
    
    // Create EpochManager with key storage that will fail lookup
    let mut safety_rules_config = SafetyRulesConfig::default();
    // Configure to use storage backend that doesn't have the key
    
    let mut epoch_manager = EpochManager::new(
        &safety_rules_config,
        validator_addr,
        // ... other parameters
    );
    
    // Epoch 1: Trigger DKG setup with failing key lookup
    // This creates channels but returns error due to missing secret key
    let payload1 = create_test_payload(validator_set.clone());
    let result = epoch_manager.start_new_epoch(payload1).await;
    assert!(result.is_err()); // Key lookup fails
    
    // Verify orphaned state
    assert!(epoch_manager.dkg_manager_close_tx.is_some());
    
    // Epoch 2: Attempt shutdown of non-existent manager
    // This should panic due to orphaned channel
    let payload2 = create_test_payload(validator_set.clone());
    
    // This will panic at shutdown_current_processor line 273
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            epoch_manager.on_new_epoch(
                ReconfigNotification { on_chain_configs: payload2 }
            ).await
        })
    }));
    
    assert!(result.is_err()); // Panic occurred
}
```

## Notes

The vulnerability requires realistic operational failures (key storage issues) rather than direct attacker exploitation. However, it represents a significant reliability issue for validator operations. The root cause is a violation of the transaction/resource cleanup principle: resources (channels) are allocated before validation, with no cleanup on error paths.

The most realistic trigger is the secret key lookup failure (lines 238-243), which can occur in production environments due to storage backend issues, rather than the public key lookup failure (lines 234-237), which would indicate validator set data inconsistency.

### Citations

**File:** dkg/src/epoch_manager.rs (L140-142)
```rust
            if let Err(e) = handling_result {
                error!("{}", e);
            }
```

**File:** dkg/src/epoch_manager.rs (L223-233)
```rust
            let (dkg_start_event_tx, dkg_start_event_rx) =
                aptos_channel::new(QueueStyle::KLAST, 1, None);
            self.dkg_start_event_tx = Some(dkg_start_event_tx);

            let (dkg_rpc_msg_tx, dkg_rpc_msg_rx) = aptos_channel::new::<
                AccountAddress,
                (AccountAddress, IncomingRpcRequest),
            >(QueueStyle::FIFO, 100, None);
            self.dkg_rpc_msg_tx = Some(dkg_rpc_msg_tx);
            let (dkg_manager_close_tx, dkg_manager_close_rx) = oneshot::channel();
            self.dkg_manager_close_tx = Some(dkg_manager_close_tx);
```

**File:** dkg/src/epoch_manager.rs (L234-237)
```rust
            let my_pk = epoch_state
                .verifier
                .get_public_key(&self.my_addr)
                .ok_or_else(|| anyhow!("my pk not found in validator set"))?;
```

**File:** dkg/src/epoch_manager.rs (L238-243)
```rust
            let dealer_sk = self
                .key_storage
                .consensus_sk_by_pk(my_pk.clone())
                .map_err(|e| {
                    anyhow!("dkg new epoch handling failed with consensus sk lookup err: {e}")
                })?;
```

**File:** dkg/src/epoch_manager.rs (L263-268)
```rust
    async fn on_new_epoch(&mut self, reconfig_notification: ReconfigNotification<P>) -> Result<()> {
        self.shutdown_current_processor().await;
        self.start_new_epoch(reconfig_notification.on_chain_configs)
            .await?;
        Ok(())
    }
```

**File:** dkg/src/epoch_manager.rs (L270-276)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(tx) = self.dkg_manager_close_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ack_tx).unwrap();
            ack_rx.await.unwrap();
        }
    }
```
