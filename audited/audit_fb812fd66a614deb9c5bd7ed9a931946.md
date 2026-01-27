# Audit Report

## Title
Missing Epoch Validation in CertifiedAugDataAck Response Processing Allows Byzantine Validators to Send Invalid Acknowledgments

## Summary
The `CertifiedAugDataAckState::add()` method in the randomness generation protocol completely ignores the epoch field of incoming `CertifiedAugDataAck` messages, allowing Byzantine validators to send acknowledgments with arbitrary epoch values that will be accepted without validation.

## Finding Description

The randomness generation protocol uses a reliable broadcast mechanism to distribute certified augmented data among validators. When validators receive `CertifiedAugData`, they respond with `CertifiedAugDataAck` messages to confirm receipt.

The `CertifiedAugDataAck` struct contains an `epoch` field: [1](#0-0) 

When these acknowledgments are received, they are processed by `CertifiedAugDataAckState::add()`: [2](#0-1) 

**The vulnerability**: The `_ack` parameter (line 88) is prefixed with underscore and completely unused. The method only validates that the responding peer is in the validator set, but does NOT validate that the ack's epoch matches the expected epoch.

The `CertifiedAugDataAckState` struct itself has no epoch field to store the expected epoch: [3](#0-2) 

When `CertifiedAugDataAck` is created, it captures the current epoch: [4](#0-3) 

However, RPC response messages do not go through the same verification as request messages. The `RandMessage::verify()` method explicitly excludes response types: [5](#0-4) 

**Attack Path**: A Byzantine validator can:
1. Receive a legitimate `CertifiedAugData(epoch=N)` broadcast
2. Craft a `CertifiedAugDataAck(epoch=M)` where M ≠ N
3. Send this malformed ack as an RPC response
4. The ack will be accepted by `CertifiedAugDataAckState::add()` without epoch validation
5. The reliable broadcast will complete with acknowledgments from mismatched epochs

This violates the protocol invariant that acknowledgments should correspond to the epoch of the data being acknowledged.

## Impact Explanation

**Severity: Medium**

This vulnerability breaks the **epoch isolation** principle in the randomness generation protocol:

1. **Protocol Correctness Violation**: The consensus protocol assumes that messages within an epoch are properly validated. Accepting acks from wrong epochs violates this assumption.

2. **Potential State Inconsistencies**: While the immediate impact is limited (acks are primarily completion signals), this could cause inconsistencies in:
   - Protocol state tracking
   - Epoch transition handling
   - Future protocol changes that rely on epoch matching
   - Debugging and observability (logs will show mismatched epochs)

3. **Byzantine Validator Capability**: This expands what a Byzantine validator can do - they can inject epoch-mismatched messages into the protocol flow without detection.

This meets **Medium Severity** criteria per the Aptos bug bounty: "State inconsistencies requiring intervention" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is easily exploitable by any Byzantine validator:
- No special timing or race conditions required
- Simple message crafting (just set wrong epoch field)
- No cryptographic bypasses needed (signatures are on the data, not validated against epoch)
- Affects all reliable broadcasts of certified augmented data

The only requirement is that the attacker must be a validator in the current epoch's validator set. Given that AptosBFT is designed to tolerate up to 1/3 Byzantine validators, this is within the threat model.

## Recommendation

The `CertifiedAugDataAckState` should store the expected epoch and validate incoming acknowledgments against it:

```rust
pub struct CertifiedAugDataAckState {
    validators: Mutex<HashSet<Author>>,
    expected_epoch: u64,  // Add epoch field
}

impl CertifiedAugDataAckState {
    pub fn new(validators: impl Iterator<Item = Author>, epoch: u64) -> Self {
        Self {
            validators: Mutex::new(validators.collect()),
            expected_epoch: epoch,
        }
    }
}

impl<S: TShare, D: TAugmentedData> BroadcastStatus<RandMessage<S, D>, RandMessage<S, D>>
    for Arc<CertifiedAugDataAckState>
{
    type Aggregated = ();
    type Message = CertifiedAugData<D>;
    type Response = CertifiedAugDataAck;

    fn add(&self, peer: Author, ack: Self::Response) -> anyhow::Result<Option<Self::Aggregated>> {
        // Validate epoch matches
        ensure!(
            ack.epoch() == self.expected_epoch,
            "[RandMessage] Epoch mismatch: expected {}, got {}",
            self.expected_epoch,
            ack.epoch()
        );
        
        let mut validators_guard = self.validators.lock();
        ensure!(
            validators_guard.remove(&peer),
            "[RandMessage] Unknown author: {}",
            peer
        );
        if validators_guard.is_empty() {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }
}
```

Update the instantiation in `rand_manager.rs`: [6](#0-5) 

Change line 332 to pass the epoch:
```rust
let ack_state = Arc::new(CertifiedAugDataAckState::new(
    validators.into_iter(),
    certified_data.epoch()  // Pass the expected epoch
));
```

## Proof of Concept

```rust
// Reproduction steps in Rust test context:

#[test]
fn test_epoch_validation_bypass() {
    // Setup: Create CertifiedAugDataAckState for epoch N
    let validators = vec![
        AccountAddress::random(),
        AccountAddress::random(),
    ];
    let ack_state = Arc::new(CertifiedAugDataAckState::new(validators.iter().cloned()));
    
    // Attack: Send ack with wrong epoch (N-1 or N+1 instead of N)
    let wrong_epoch_ack = CertifiedAugDataAck::new(999); // Arbitrary wrong epoch
    
    // Current behavior: This is accepted without epoch validation
    let result = ack_state.add(validators[0], wrong_epoch_ack);
    
    // BUG: This should FAIL but currently SUCCEEDS
    assert!(result.is_ok(), "Wrong epoch ack was accepted!");
    
    // Expected behavior: Should reject with epoch mismatch error
    // assert!(result.is_err());
    // assert!(result.unwrap_err().to_string().contains("Epoch mismatch"));
}
```

## Notes

- The same issue exists in `AugDataSignature` responses, which also have epoch fields that are not validated in `AugDataCertBuilder::add()`
- This vulnerability requires the attacker to be a validator, but Byzantine validators (up to 1/3) are within the threat model of AptosBFT
- The fix is straightforward and should be applied to both `CertifiedAugDataAckState` and similar response handling patterns throughout the codebase
- Epoch validation is correctly implemented for request messages but missing for response messages

### Citations

**File:** consensus/src/rand/rand_gen/types.rs (L565-578)
```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct CertifiedAugDataAck {
    epoch: u64,
}

impl CertifiedAugDataAck {
    pub fn new(epoch: u64) -> Self {
        Self { epoch }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L69-79)
```rust
pub struct CertifiedAugDataAckState {
    validators: Mutex<HashSet<Author>>,
}

impl CertifiedAugDataAckState {
    pub fn new(validators: impl Iterator<Item = Author>) -> Self {
        Self {
            validators: Mutex::new(validators.collect()),
        }
    }
}
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L88-101)
```rust
    fn add(&self, peer: Author, _ack: Self::Response) -> anyhow::Result<Option<Self::Aggregated>> {
        let mut validators_guard = self.validators.lock();
        ensure!(
            validators_guard.remove(&peer),
            "[RandMessage] Unknown author: {}",
            peer
        );
        // If receive from all validators, stop the reliable broadcast
        if validators_guard.is_empty() {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }
```

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L117-131)
```rust
    pub fn add_certified_aug_data(
        &mut self,
        certified_data: CertifiedAugData<D>,
    ) -> anyhow::Result<CertifiedAugDataAck> {
        if self.certified_data.contains_key(certified_data.author()) {
            return Ok(CertifiedAugDataAck::new(self.epoch));
        }
        self.db.save_certified_aug_data(&certified_data)?;
        certified_data
            .data()
            .augment(&self.config, &self.fast_config, certified_data.author());
        self.certified_data
            .insert(*certified_data.author(), certified_data);
        Ok(CertifiedAugDataAck::new(self.epoch))
    }
```

**File:** consensus/src/rand/rand_gen/network_messages.rs (L36-60)
```rust
    pub fn verify(
        &self,
        epoch_state: &EpochState,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        sender: Author,
    ) -> anyhow::Result<()> {
        ensure!(self.epoch() == epoch_state.epoch);
        match self {
            RandMessage::RequestShare(_) => Ok(()),
            RandMessage::Share(share) => share.verify(rand_config),
            RandMessage::AugData(aug_data) => {
                aug_data.verify(rand_config, fast_rand_config, sender)
            },
            RandMessage::CertifiedAugData(certified_aug_data) => {
                certified_aug_data.verify(&epoch_state.verifier)
            },
            RandMessage::FastShare(share) => {
                share.share.verify(fast_rand_config.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("[RandMessage] rand config for fast path not found")
                })?)
            },
            _ => bail!("[RandMessage] unexpected message type"),
        }
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L332-338)
```rust
        let ack_state = Arc::new(CertifiedAugDataAckState::new(validators.into_iter()));
        let task = phase1.then(|certified_data| async move {
            info!(LogSchema::new(LogEvent::BroadcastCertifiedAugData)
                .author(*certified_data.author())
                .epoch(certified_data.epoch()));
            info!("[RandManager] Start broadcasting certified aug data");
            rb2.broadcast(certified_data, ack_state)
```
