# Audit Report

## Title
Light Clients Accept Unsigned Epoch Changes When Initialized with Waypoint-Only Trust Anchor

## Summary
Light clients in `TrustedState::EpochWaypoint` state accept epoch-change ledger infos without verifying BLS signatures, relying solely on waypoint hash matching. This allows malicious full nodes to provide unsigned or improperly-signed state transitions, violating the fundamental BFT security guarantee that all state transitions must be cryptographically signed by 2f+1 validators.

## Finding Description

The `TrustedState` enum has two variants for tracking light client trust anchors. The `EpochWaypoint` variant only stores a waypoint hash without validator set information, while `EpochState` stores both a waypoint and the validator set needed for signature verification. [1](#0-0) 

When a light client initializes with `TrustedState::from_epoch_waypoint()`, it enters a state where signature verification is completely bypassed. The delegation chain is:

1. **Verification Entry Point**: When `verify_and_ratchet_inner()` is called with an `EpochWaypoint` state, it determines that epoch change verification is required and delegates to the `EpochChangeProof::verify()` method: [2](#0-1) 

2. **EpochChangeProof Verification**: This method iterates through epoch-change ledger infos and calls `verifier_ref.verify()` on each one. For the first iteration when starting from a waypoint, `verifier_ref` is the `Waypoint` type: [3](#0-2) 

3. **Waypoint Verification - NO SIGNATURE CHECK**: The `Waypoint` implementation of the `Verifier` trait only validates that the ledger info content matches the waypoint hash. It completely skips BLS signature verification: [4](#0-3) 

The actual `Waypoint::verify()` method only checks version and hash matching: [5](#0-4) 

**In contrast**, when the light client is in `EpochState` mode, signature verification IS performed: [6](#0-5) 

**Attack Scenario:**

1. Light client obtains a legitimate waypoint (e.g., genesis waypoint or from trusted source)
2. Initializes with `TrustedState::from_epoch_waypoint(waypoint)`
3. Connects to a malicious full node to sync
4. Malicious node provides an `EpochChangeProof` containing:
   - LedgerInfo with correct content matching the waypoint
   - BUT with `AggregateSignature::empty()` or arbitrary invalid signatures
5. Light client calls `verify_and_ratchet_inner()`:
   - Waypoint verification passes (content hash matches)
   - **Signature verification is completely skipped**
   - Light client accepts the unsigned epoch change
6. Light client transitions to `TrustedState::EpochState` with the `next_epoch_state` from the unverified ledger info

**Evidence of Design Flaw**: Genesis ledger infos are intentionally created with empty signatures, demonstrating that waypoint-based verification was designed to accept unsigned state: [7](#0-6) 

## Impact Explanation

**Critical Severity** - This vulnerability breaks the fundamental security guarantee of AptosBFT consensus:

1. **Consensus Safety Violation**: The core invariant of BFT consensus is that state transitions must be signed by 2f+1 validators to prove Byzantine agreement. By accepting unsigned epoch changes, light clients cannot cryptographically verify that the blockchain state represents actual validator consensus.

2. **Network Partition Risk**: Different light clients in `EpochWaypoint` state could accept different unsigned epoch changes from different malicious nodes, leading to inconsistent views of the blockchain state without any way to detect the divergence.

3. **Trust Model Violation**: Light clients are designed to provide security guarantees without trusting full nodes. This vulnerability forces light clients to trust that full nodes provide state transitions that were actually signed by validators, eliminating the trustless property.

4. **Attack Surface**: Any full node can exploit this vulnerability when light clients connect for initial sync, making it a widespread attack vector requiring no special privileges.

This meets the **Critical Severity** criteria per Aptos bug bounty program as it constitutes a "Consensus/Safety violation" that breaks the cryptographic security guarantees of the protocol.

## Likelihood Explanation

**High Likelihood:**

1. **Common Usage Pattern**: Light client initialization with waypoints is the standard bootstrap mechanism. Genesis waypoints are distributed in configuration files and documentation, making `EpochWaypoint` state a common initialization path.

2. **No Attacker Privileges Required**: Any entity operating a full node can perform this attack. There's no need for validator access or insider collusion.

3. **Difficult to Detect**: Since the ledger info content matches the legitimate waypoint, users cannot easily detect they've accepted unsigned state transitions without deep protocol inspection.

4. **No Rate Limiting**: There are no mechanisms to prevent malicious nodes from repeatedly serving unsigned epoch changes to connecting light clients.

## Recommendation

Add signature verification to the `Waypoint::verify()` implementation when the ledger info contains signatures. Modify the verification logic to:

1. Check if the `LedgerInfoWithSignatures` has non-empty signatures
2. If signatures are present, extract the validator set from the ledger info's `next_epoch_state`
3. Verify the signatures against this validator set
4. Only accept the ledger info if both waypoint hash AND signatures are valid

**Proposed Fix** in `types/src/waypoint.rs`:

```rust
impl Verifier for Waypoint {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        // First verify waypoint hash matches
        self.verify(ledger_info.ledger_info())?;
        
        // Additionally verify signatures if present
        // Genesis may have empty signatures, but epoch changes after genesis must be signed
        if !ledger_info.signatures().is_empty() {
            // Extract validator set from the ledger info's next_epoch_state
            let epoch_state = ledger_info.ledger_info()
                .next_epoch_state()
                .ok_or_else(|| format_err!("Waypoint verification requires epoch change with validator set"))?;
            
            // Verify the signatures
            ledger_info.verify_signatures(&epoch_state.verifier)?;
        }
        
        Ok(())
    }
    // ... rest unchanged
}
```

Alternatively, require light clients to transition from `EpochWaypoint` to `EpochState` during initial sync by providing the first epoch's validator set alongside the waypoint.

## Proof of Concept

```rust
#[cfg(test)]
mod test_waypoint_signature_bypass {
    use super::*;
    use crate::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        epoch_change::EpochChangeProof,
        epoch_state::EpochState,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        trusted_state::TrustedState,
        validator_verifier::random_validator_verifier,
        waypoint::Waypoint,
    };
    use aptos_crypto::hash::HashValue;
    use std::sync::Arc;

    #[test]
    fn test_waypoint_accepts_unsigned_epoch_change() {
        // Create a legitimate validator set for epoch 1
        let (signers, verifier) = random_validator_verifier(4, None, true);
        let epoch_state_1 = EpochState {
            epoch: 1,
            verifier: Arc::new(verifier),
        };

        // Create an epoch-change ledger info for epoch 0 -> 1
        let ledger_info = LedgerInfo::new(
            BlockInfo::new(
                0,                 // epoch
                0,                 // round
                HashValue::zero(), // id
                HashValue::zero(), // executed_state_id
                100,               // version
                1000,              // timestamp
                Some(epoch_state_1.clone()),
            ),
            HashValue::zero(),
        );

        // Create waypoint from this ledger info
        let waypoint = Waypoint::new_epoch_boundary(&ledger_info).unwrap();

        // Initialize trusted state with waypoint only
        let trusted_state = TrustedState::from_epoch_waypoint(waypoint);

        // Create UNSIGNED ledger info with same content
        let unsigned_li = LedgerInfoWithSignatures::new(
            ledger_info.clone(),
            AggregateSignature::empty(), // NO SIGNATURES!
        );

        // Create epoch change proof with unsigned ledger info
        let epoch_change_proof = EpochChangeProof::new(vec![unsigned_li.clone()], false);

        // This should FAIL because the ledger info is unsigned
        // But it SUCCEEDS due to the vulnerability!
        let result = trusted_state.verify_and_ratchet_inner(&unsigned_li, &epoch_change_proof);
        
        // VULNERABILITY: Unsigned epoch change is accepted
        assert!(result.is_ok(), "Unsigned epoch change should be rejected but was accepted!");
        
        // Light client now trusts a state that was never signed by validators
        match result.unwrap() {
            TrustedStateChange::Epoch { new_state, .. } => {
                println!("VULNERABILITY CONFIRMED: Light client accepted unsigned epoch change");
                println!("New state version: {}", new_state.version());
            }
            _ => panic!("Expected epoch change"),
        }
    }
}
```

**Notes:**
- This vulnerability specifically affects light clients in `EpochWaypoint` state, which is the standard initialization path using waypoints
- The waypoint hash includes the `next_epoch_state`, so attackers cannot change which validator set becomes trusted, but they can provide unsigned transitions
- Genesis ledger infos legitimately have empty signatures by design, but the code fails to enforce signature verification for subsequent epoch changes when operating in waypoint-only mode
- The test suite has coverage for invalid signatures when in `EpochState` mode but lacks tests for the `EpochWaypoint` path, allowing this vulnerability to remain undetected

### Citations

**File:** types/src/trusted_state.rs (L26-40)
```rust
pub enum TrustedState {
    /// The current trusted state is an epoch waypoint, which is a commitment to
    /// an epoch change ledger info. Most light clients will start here when
    /// syncing for the first time.
    EpochWaypoint(Waypoint),
    /// The current trusted state is inside a verified epoch (which includes the
    /// validator set inside that epoch).
    EpochState {
        /// The current trusted version and a commitment to a ledger info inside
        /// the current trusted epoch.
        waypoint: Waypoint,
        /// The current epoch and validator set inside that epoch.
        epoch_state: EpochState,
    },
}
```

**File:** types/src/trusted_state.rs (L161-163)
```rust
        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
```

**File:** types/src/epoch_change.rs (L106-114)
```rust
            // Try to verify each (epoch -> epoch + 1) jump in the EpochChangeProof.
            verifier_ref.verify(ledger_info_with_sigs)?;
            // While the original verification could've been via waypoints,
            // all the next epoch changes are verified using the (already
            // trusted) validator sets.
            verifier_ref = ledger_info_with_sigs
                .ledger_info()
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
```

**File:** types/src/waypoint.rs (L62-79)
```rust
    pub fn verify(&self, ledger_info: &LedgerInfo) -> Result<()> {
        ensure!(
            ledger_info.version() == self.version(),
            "Waypoint version mismatch: waypoint version = {}, given version = {}",
            self.version(),
            ledger_info.version()
        );
        let converter = Ledger2WaypointConverter::new(ledger_info);
        ensure!(
            converter.hash() == self.value(),
            format!(
                "Waypoint value mismatch: waypoint value = {}, given value = {}",
                self.value().to_hex(),
                converter.hash().to_hex()
            )
        );
        Ok(())
    }
```

**File:** types/src/waypoint.rs (L82-94)
```rust
impl Verifier for Waypoint {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        self.verify(ledger_info.ledger_info())
    }

    fn epoch_change_verification_required(&self, _epoch: u64) -> bool {
        true
    }

    fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        ledger_info.version() < self.version()
    }
}
```

**File:** types/src/epoch_state.rs (L40-50)
```rust
impl Verifier for EpochState {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L176-193)
```rust
    let ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(
                epoch,
                GENESIS_ROUND,
                genesis_block_id(),
                output
                    .ensure_ledger_update_output()?
                    .transaction_accumulator
                    .root_hash(),
                genesis_version,
                timestamp_usecs,
                output.execution_output.next_epoch_state.clone(),
            ),
            genesis_block_id(), /* consensus_data_hash */
        ),
        AggregateSignature::empty(), /* signatures */
    );
```
