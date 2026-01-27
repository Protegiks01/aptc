# Audit Report

## Title
DKG Epoch Manager Allows Validators to Operate in Zombie State After Storage Key Loading Failures

## Summary
When the DKG epoch manager fails to load a validator's consensus key from storage during epoch transition, it creates channels and updates the epoch state before the failure, then returns an error that is only logged. This leaves the validator in a "zombie" state where it appears active in the new epoch but silently drops all DKG messages, potentially causing DKG threshold failures and randomness generation to stall.

## Finding Description

The vulnerability exists in the error handling logic of the `start_new_epoch()` function in the DKG epoch manager. The critical issue is the order of operations:

1. **Epoch state is updated first** [1](#0-0) 

2. **Message channels are created and assigned to self** [2](#0-1) 

3. **Then consensus key loading is attempted, which can fail** [3](#0-2) 

4. **If key loading fails, the function returns early** - The DKG manager is never spawned [4](#0-3) , but the channel receivers (local variables) are dropped.

5. **The error is caught in the event loop and only logged** [5](#0-4) , allowing the validator to continue running.

6. **When peers send DKG RPC messages, they are silently dropped** [6](#0-5)  - The error from pushing to a closed channel is ignored with `let _ = tx.push(...)`.

The underlying storage operation can fail in multiple ways [7](#0-6) , including when keys are not found or when the stored key doesn't match the expected public key.

When a channel receiver is dropped, subsequent push operations fail [8](#0-7) , but this error is completely ignored in the RPC handling path.

**Contrast with Consensus Module:**
The consensus epoch manager handles the same scenario correctly by panicking when key loading fails [9](#0-8) , ensuring fail-fast behavior rather than degraded operation.

This breaks the **Consensus Safety** and **State Consistency** invariants by allowing validators to operate in an inconsistent state where:
- They believe they're in a new epoch (state updated)
- They have communication channels set up (channels created)
- But they're not actually participating in DKG (manager never started)
- They silently drop messages instead of clearly signaling failure

## Impact Explanation

This qualifies as **HIGH SEVERITY** per the Aptos bug bounty criteria:

1. **Significant Protocol Violations**: DKG is critical for randomness generation. If enough validators (more than f voting power) enter zombie state, DKG cannot reach the required threshold [10](#0-9) , causing randomness generation to fail completely.

2. **Validator Node Operational Issues**: 
   - Zombie validators waste network bandwidth by accepting but dropping messages
   - Peer validators waste computational resources retrying failed communications
   - The silent failure mode makes diagnosis extremely difficult

3. **Cascading Failures**: Storage failures can be correlated (e.g., shared storage backend issues, simultaneous hardware failures in a data center), potentially affecting multiple validators simultaneously.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood:**

1. **Realistic Trigger Conditions**: Storage errors occur in production environments due to:
   - Hardware failures (disk corruption, SSD wear)
   - Storage backend issues (cloud storage outages)
   - File system corruption
   - Insufficient disk space
   - Permission issues

2. **No External Attack Required**: The bug is triggered by operational issues, not malicious actions.

3. **Correlated Failures Amplify Impact**: Validators using similar infrastructure (same cloud provider, same data center) can experience correlated storage failures, causing multiple validators to enter zombie state simultaneously.

4. **Silent Failure Mode**: The lack of clear error signaling means the issue may persist undetected until DKG completion timeouts occur.

## Recommendation

The DKG epoch manager should follow the same pattern as the consensus epoch manager: fail fast and visibly when consensus key loading fails. 

**Fix Option 1 - Panic on Key Loading Failure** (matches consensus module behavior):
```rust
let dealer_sk = self
    .key_storage
    .consensus_sk_by_pk(my_pk.clone())
    .unwrap_or_else(|e| {
        panic!("DKG epoch handling failed: cannot load consensus key: {e}")
    });
```

**Fix Option 2 - Reorder Operations** (safer state management):
```rust
// Load and validate key BEFORE updating any state
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

// Only update state after confirming key is available
self.epoch_state = Some(epoch_state.clone());

// Then create channels and spawn DKG manager
let (dkg_start_event_tx, dkg_start_event_rx) = ...
```

**Recommended Approach**: Use Fix Option 1 for consistency with the consensus module's behavior. Validators cannot participate in DKG without valid keys, so failing fast is the correct approach.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_dkg_epoch_manager_zombie_state() {
    // Setup: Create validator with storage that will fail on key lookup
    let mut storage = InMemoryStorage::new();
    // Intentionally do NOT store the consensus key
    let safety_storage = PersistentSafetyStorage::new(
        Storage::from(storage),
        true
    );
    
    // Create epoch manager
    let mut epoch_manager = EpochManager::new(
        &safety_rules_config,
        validator_addr,
        reconfig_events,
        dkg_start_events,
        self_sender,
        network_sender,
        vtxn_pool,
        rb_config,
        0
    );
    
    // Trigger epoch transition with missing key
    let payload = create_reconfig_payload(new_epoch);
    
    // This should fail but validator continues in zombie state
    let result = epoch_manager.start_new_epoch(payload).await;
    
    // Verify the zombie state:
    // 1. Error was returned
    assert!(result.is_err());
    
    // 2. But epoch state was updated
    assert_eq!(epoch_manager.epoch_state.unwrap().epoch, new_epoch);
    
    // 3. Channels are set but closed (receivers dropped)
    assert!(epoch_manager.dkg_rpc_msg_tx.is_some());
    
    // 4. Attempting to send message fails silently
    let test_request = create_dkg_rpc_request();
    epoch_manager.process_rpc_request(peer_addr, test_request);
    // Message was accepted but dropped - NO ERROR PROPAGATED
    
    // 5. DKG manager was never spawned - validator is non-functional
    // but appears active to peers
}
```

## Notes

This vulnerability specifically addresses the security question: **"Are these errors properly propagated to prevent validator participation with invalid keys, or can partial failures cause protocol inconsistencies?"**

The answer is: **NO, errors are NOT properly propagated**. The validator continues operating in an inconsistent state (zombie mode) rather than failing safely, and partial failures across multiple validators can indeed cause protocol inconsistencies by preventing DKG from reaching threshold.

The inconsistency between the DKG epoch manager's error handling and the consensus epoch manager's error handling suggests this was an oversight rather than an intentional design decision.

### Citations

**File:** dkg/src/epoch_manager.rs (L99-105)
```rust
        if Some(dkg_request.msg.epoch()) == self.epoch_state.as_ref().map(|s| s.epoch) {
            // Forward to DKGManager if it is alive.
            if let Some(tx) = &self.dkg_rpc_msg_tx {
                let _ = tx.push(peer_id, (peer_id, dkg_request));
            }
        }
        Ok(())
```

**File:** dkg/src/epoch_manager.rs (L140-142)
```rust
            if let Err(e) = handling_result {
                error!("{}", e);
            }
```

**File:** dkg/src/epoch_manager.rs (L162-163)
```rust
        let epoch_state = Arc::new(EpochState::new(payload.epoch(), (&validator_set).into()));
        self.epoch_state = Some(epoch_state.clone());
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

**File:** dkg/src/epoch_manager.rs (L238-243)
```rust
            let dealer_sk = self
                .key_storage
                .consensus_sk_by_pk(my_pk.clone())
                .map_err(|e| {
                    anyhow!("dkg new epoch handling failed with consensus sk lookup err: {e}")
                })?;
```

**File:** dkg/src/epoch_manager.rs (L253-258)
```rust
            tokio::spawn(dkg_manager.run(
                in_progress_session,
                dkg_start_event_rx,
                dkg_rpc_msg_rx,
                dkg_manager_close_rx,
            ));
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L106-132)
```rust
    pub fn consensus_sk_by_pk(
        &self,
        pk: bls12381::PublicKey,
    ) -> Result<bls12381::PrivateKey, Error> {
        let _timer = counters::start_timer("get", CONSENSUS_KEY);
        let pk_hex = hex::encode(pk.to_bytes());
        let explicit_storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
        let explicit_sk = self
            .internal_store
            .get::<bls12381::PrivateKey>(explicit_storage_key.as_str())
            .map(|v| v.value);
        let default_sk = self.default_consensus_sk();
        let key = match (explicit_sk, default_sk) {
            (Ok(sk_0), _) => sk_0,
            (Err(_), Ok(sk_1)) => sk_1,
            (Err(_), Err(_)) => {
                return Err(Error::ValidatorKeyNotFound("not found!".to_string()));
            },
        };
        if key.public_key() != pk {
            return Err(Error::SecureStorageMissingDataError(format!(
                "Incorrect sk saved for {:?} the expected pk",
                pk
            )));
        }
        Ok(key)
    }
```

**File:** crates/channel/src/aptos_channel.rs (L97-98)
```rust
        let mut shared_state = self.shared_state.lock();
        ensure!(!shared_state.receiver_dropped, "Channel is closed");
```

**File:** consensus/src/epoch_manager.rs (L1228-1233)
```rust
        let loaded_consensus_key = match self.load_consensus_key(&epoch_state.verifier) {
            Ok(k) => Arc::new(k),
            Err(e) => {
                panic!("load_consensus_key failed: {e}");
            },
        };
```

**File:** dkg/src/transcript_aggregation/mod.rs (L122-134)
```rust
        let threshold = self.epoch_state.verifier.quorum_voting_power();
        let power_check_result = self
            .epoch_state
            .verifier
            .check_voting_power(trx_aggregator.contributors.iter(), true);
        let new_total_power = match &power_check_result {
            Ok(x) => Some(*x),
            Err(VerifyError::TooLittleVotingPower { voting_power, .. }) => Some(*voting_power),
            _ => None,
        };
        let maybe_aggregated = power_check_result
            .ok()
            .map(|_| trx_aggregator.trx.clone().unwrap());
```
