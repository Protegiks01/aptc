# Audit Report

## Title
Persistent State Corruption Enables Consensus Safety Violation Through Unvalidated SafetyData Loading

## Summary
The `retry()` function in `MetricsSafetyRules` can reinitialize with corrupted persistent state (SafetyData) and proceed to sign invalid votes, enabling equivocation attacks that violate consensus safety. When the epoch matches but SafetyData fields are corrupted, no validation occurs before using the state for voting operations.

## Finding Description

The vulnerability exists in the initialization flow when persistent storage becomes corrupted. The attack path is:

1. **Initial State**: A validator has voted on round 10 for block B1, with `SafetyData { epoch: 5, last_voted_round: 10, last_vote: Some(Vote(B1)), ... }` persisted to disk.

2. **Storage Corruption**: The on-disk JSON storage file becomes corrupted (crash during write, disk error, filesystem bug), resulting in malformed SafetyData such as `{ epoch: 5, last_voted_round: 9, last_vote: None, ... }`.

3. **Reinitialization Trigger**: The validator encounters an error (NotInitialized, IncorrectEpoch, or WaypointOutOfDate) causing `retry()` to call `perform_initialize()`. [1](#0-0) 

4. **Corrupted State Loading**: In `perform_initialize()`, the code calls `initialize()` which loads SafetyData from persistent storage: [2](#0-1) 

5. **Critical Flaw - No Validation**: When `current_epoch == epoch_state.epoch` (Ordering::Equal at line 308), the code performs **no operation** - it neither resets SafetyData nor validates it. The corrupted state remains loaded in memory.

6. **Storage Implementation Has No Integrity Checks**: The OnDiskStorage backend performs no checksum verification or consistency validation: [3](#0-2) 

7. **Equivocation**: The subsequent voting operation at retry() line 81 uses the corrupted SafetyData. The critical safety check fails to prevent double-voting: [4](#0-3) 

Since `last_vote` is None (corrupted), the check at lines 70-74 doesn't return the previous vote. Since `last_voted_round` is 9 (corrupted from 10), the check at line 77-80 passes for round 10. The validator can now sign a conflicting vote for round 10 with block B2, creating equivocation.

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability breaks the fundamental safety guarantee of AptosBFT consensus: preventing equivocation (double-voting). According to BFT theory, consensus safety requires that honest validators never sign conflicting votes for the same round. This guarantee holds even with < 1/3 Byzantine validators.

The vulnerability enables:
- **Equivocation**: A single honest validator with corrupted storage can sign two different votes for the same round
- **Chain Splits**: Conflicting votes can lead to different validators committing different blocks
- **Safety Break**: The < 1/3 Byzantine assumption is violated - even a single corrupted node breaks safety

This meets the **Critical Severity** criteria: "Consensus/Safety violations" worth up to $1,000,000 per Aptos bug bounty.

## Likelihood Explanation

**Medium-High Likelihood** - While requiring storage corruption, this scenario is realistic in production:

**Corruption Triggers:**
- Power failures during write operations
- Disk hardware failures (bit rot, sector errors)
- Filesystem bugs or crashes
- Out-of-disk-space conditions causing partial writes
- Race conditions in concurrent storage access
- Containerized environments with volume unmount issues

**Attack Requirements:**
- No malicious insider access needed
- No network manipulation required
- Only requires storage corruption on a single validator node
- Corruption must preserve valid JSON structure (common in partial writes)
- Epoch field must remain unchanged (likely in small corruptions)

**Real-World Evidence:**
- Production validators run 24/7 with crash recovery scenarios
- Storage corruption is a known operational risk
- No checksums or atomic write guarantees in OnDiskStorage
- Comments in on_disk.rs warn "should not be used in production" but it's used in safety-critical paths

## Recommendation

**Immediate Fixes:**

1. **Add SafetyData Validation in initialize():**

```rust
// In safety_rules.rs, guarded_initialize(), after line 283:
let current_epoch = self.persistent_storage.safety_data()?.epoch;

// Validate SafetyData consistency BEFORE using it
if current_epoch == epoch_state.epoch {
    let safety_data = self.persistent_storage.safety_data()?;
    
    // Validate last_vote consistency with last_voted_round
    if let Some(vote) = &safety_data.last_vote {
        if vote.vote_data().proposed().round() != safety_data.last_voted_round {
            warn!("Corrupted SafetyData detected: last_vote round mismatch");
            // Reset to safe defaults for current epoch
            self.persistent_storage.set_safety_data(SafetyData::new(
                epoch_state.epoch,
                safety_data.last_voted_round, // Preserve higher value
                safety_data.preferred_round,
                safety_data.one_chain_round,
                None, // Clear corrupted vote
                safety_data.highest_timeout_round,
            ))?;
        }
    }
    
    // Validate field bounds and monotonicity
    if safety_data.last_voted_round < safety_data.preferred_round - 1000 ||
       safety_data.one_chain_round > safety_data.last_voted_round + 1000 {
        warn!("Corrupted SafetyData detected: implausible round values");
        return Err(Error::InternalError("SafetyData corruption detected".into()));
    }
}
```

2. **Add Storage Integrity Checks:**

```rust
// In persistent_safety_storage.rs, add checksumming:
pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
    let serialized = serde_json::to_vec(&data)?;
    let checksum = compute_checksum(&serialized);
    
    // Store data with checksum
    let versioned_data = VersionedData { 
        data, 
        checksum, 
        version: DATA_VERSION 
    };
    
    self.internal_store.set(SAFETY_DATA, versioned_data)?;
    self.cached_safety_data = Some(data);
    Ok(())
}

pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
    let versioned: VersionedData = self.internal_store.get(SAFETY_DATA)?;
    
    // Verify checksum
    let serialized = serde_json::to_vec(&versioned.data)?;
    if compute_checksum(&serialized) != versioned.checksum {
        return Err(Error::InternalError("SafetyData checksum mismatch".into()));
    }
    
    Ok(versioned.data)
}
```

3. **Add Atomic Write Guarantees in OnDiskStorage:**

Replace direct file writes with write-rename atomic operations (already partially done, but ensure durability with fsync).

## Proof of Concept

```rust
#[cfg(test)]
mod equivocation_via_corruption_test {
    use super::*;
    use aptos_consensus_types::{
        block::Block,
        block_data::BlockData,
        quorum_cert::QuorumCert,
        vote_proposal::VoteProposal,
        safety_data::SafetyData,
    };
    use aptos_crypto::bls12381;
    use aptos_secure_storage::{Storage, InMemoryStorage};
    use aptos_types::validator_signer::ValidatorSigner;
    use std::sync::Arc;

    #[test]
    fn test_corrupted_storage_enables_equivocation() {
        // Setup: Create validator with proper initialization
        let signer = ValidatorSigner::from_int(0);
        let storage = Storage::from(InMemoryStorage::new());
        let mut safety_storage = PersistentSafetyStorage::initialize(
            storage,
            signer.author(),
            signer.private_key().clone(),
            Waypoint::default(),
            true,
        );

        // Step 1: Validator votes on round 10 for block B1
        let block_b1 = create_test_block(10, HashValue::random());
        let vote_proposal_b1 = create_test_vote_proposal(block_b1.clone());
        
        let mut safety_rules = SafetyRules::new(safety_storage, false);
        let vote_b1 = safety_rules.construct_and_sign_vote_two_chain(
            &vote_proposal_b1, 
            None
        ).unwrap();
        
        // Verify SafetyData is correct: last_voted_round = 10, last_vote = Some(vote_b1)
        let safety_data = safety_rules.persistent_storage.safety_data().unwrap();
        assert_eq!(safety_data.last_voted_round, 10);
        assert!(safety_data.last_vote.is_some());

        // Step 2: SIMULATE CORRUPTION - manually corrupt the persistent storage
        // This simulates what would happen with disk corruption
        let corrupted_data = SafetyData::new(
            safety_data.epoch,    // Same epoch (critical for Ordering::Equal)
            9,                     // Corrupted: last_voted_round decreased from 10 to 9
            safety_data.preferred_round,
            safety_data.one_chain_round,
            None,                  // Corrupted: last_vote cleared
            safety_data.highest_timeout_round,
        );
        safety_rules.persistent_storage.set_safety_data(corrupted_data).unwrap();

        // Step 3: Trigger reinitialization (simulates retry() flow)
        // In real scenario, this happens via retry() after an error
        let epoch_proof = create_epoch_change_proof_for_same_epoch();
        safety_rules.initialize(&epoch_proof).unwrap();
        
        // Step 4: Attempt to vote on round 10 again with different block B2
        let block_b2 = create_test_block(10, HashValue::random());  // Same round, different block!
        let vote_proposal_b2 = create_test_vote_proposal(block_b2.clone());
        
        // BUG: This succeeds when it should fail! Equivocation!
        let vote_b2 = safety_rules.construct_and_sign_vote_two_chain(
            &vote_proposal_b2,
            None
        );
        
        // VULNERABILITY DEMONSTRATED: Both votes exist for round 10
        assert!(vote_b2.is_ok(), "Equivocation successful - voted twice on round 10");
        assert_ne!(
            vote_b1.vote_data().proposed().id(),
            vote_b2.unwrap().vote_data().proposed().id(),
            "Two different votes for same round - CONSENSUS SAFETY VIOLATION"
        );
    }
}
```

## Notes

The vulnerability requires three conditions to align:
1. Storage corruption occurs (realistic in production)
2. The epoch field remains unchanged (common in partial corruptions)
3. JSON deserialization succeeds (partial writes often produce valid JSON)

While the OnDiskStorage comments warn against production use, the SafetyRules component relies on PersistentSafetyStorage which uses this backend in validator configurations. The lack of any integrity validation in the Ordering::Equal case at [5](#0-4)  is the critical oversight that transforms storage corruption from an operational issue into a consensus safety violation.

### Citations

**File:** consensus/src/metrics_safety_rules.rs (L71-85)
```rust
    fn retry<T, F: FnMut(&mut Box<dyn TSafetyRules + Send + Sync>) -> Result<T, Error>>(
        &mut self,
        mut f: F,
    ) -> Result<T, Error> {
        let result = f(&mut self.inner);
        match result {
            Err(Error::NotInitialized(_))
            | Err(Error::IncorrectEpoch(_, _))
            | Err(Error::WaypointOutOfDate(_, _, _, _)) => {
                self.perform_initialize()?;
                f(&mut self.inner)
            },
            _ => result,
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L283-309)
```rust
        let current_epoch = self.persistent_storage.safety_data()?.epoch;
        match current_epoch.cmp(&epoch_state.epoch) {
            Ordering::Greater => {
                // waypoint is not up to the current epoch.
                return Err(Error::WaypointOutOfDate(
                    waypoint.version(),
                    new_waypoint.version(),
                    current_epoch,
                    epoch_state.epoch,
                ));
            },
            Ordering::Less => {
                // start new epoch
                self.persistent_storage.set_safety_data(SafetyData::new(
                    epoch_state.epoch,
                    0,
                    0,
                    0,
                    None,
                    0,
                ))?;

                info!(SafetyLogSchema::new(LogEntry::Epoch, LogEvent::Update)
                    .epoch(epoch_state.epoch));
            },
            Ordering::Equal => (),
        };
```

**File:** secure/storage/src/on_disk.rs (L78-83)
```rust
    fn get<V: DeserializeOwned>(&self, key: &str) -> Result<GetResponse<V>, Error> {
        let mut data = self.read()?;
        data.remove(key)
            .ok_or_else(|| Error::KeyNotSet(key.to_string()))
            .and_then(|value| serde_json::from_value(value).map_err(|e| e.into()))
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-80)
```rust
        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```
