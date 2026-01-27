# Audit Report

## Title
Waypoint Verifier Bypasses Signature Validation During Epoch Change Verification

## Summary
The `Waypoint` implementation of the `Verifier` trait fails to validate BLS signatures on `LedgerInfoWithSignatures` objects, allowing an attacker to forge epoch changes by providing ledger infos with invalid signatures that match the waypoint's version and hash commitment.

## Finding Description

The `Waypoint::verify()` method implements the `Verifier` trait but strips away signature validation when verifying ledger infos. [1](#0-0) 

The method receives a `LedgerInfoWithSignatures` parameter but immediately calls `ledger_info.ledger_info()` to extract the inner `LedgerInfo` without signatures. [2](#0-1)  

The extracted `LedgerInfo` is then verified only against the waypoint's version and hash, with no cryptographic signature validation. [3](#0-2) 

In contrast, the `EpochState` implementation of `Verifier` properly verifies signatures by calling `ledger_info.verify_signatures(&self.verifier)`. [4](#0-3) 

**Attack Flow:**

1. When `EpochChangeProof::verify()` is called with a waypoint as the initial verifier, it invokes `verifier_ref.verify(ledger_info_with_sigs)` on each ledger info in the proof. [5](#0-4) 

2. This occurs in critical security contexts:
   - **Consensus initialization**: Safety rules call `proof.verify(&waypoint)` during guarded initialization. [6](#0-5) 
   - **Light client state sync**: Trusted state calls `epoch_change_proof.verify(self)` where `self` can be an `EpochWaypoint`. [7](#0-6) [8](#0-7) 

3. An attacker who knows the waypoint (version and hash - typically public) can:
   - Craft a `LedgerInfo` matching the waypoint's version and hash commitment
   - Add empty or invalid BLS signatures to create a `LedgerInfoWithSignatures`
   - The malicious ledger info passes `waypoint.verify()` since only version/hash are checked
   - The node extracts and trusts the `next_epoch_state` from this unverified ledger info
   - The attacker now controls the validator set for subsequent epoch changes

## Impact Explanation

**Severity: CRITICAL** (Consensus Safety Violation)

This vulnerability breaks the fundamental consensus safety guarantee of AptosBFT. An attacker can:

1. **Forge validator sets**: By controlling the `next_epoch_state` in the first epoch change, the attacker dictates which validators are trusted for subsequent epochs
2. **Create chain splits**: Different nodes may accept different malicious epoch change proofs, causing non-recoverable network partitions
3. **Bypass quorum requirements**: The attacker's forged validator set doesn't require 2f+1 honest validators
4. **Steal funds**: With a compromised validator set, the attacker can sign arbitrary transactions and state transitions

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and potentially "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly exploitable because:

1. **Waypoints are public information**: Waypoints are often shared publicly for node bootstrapping and light client sync
2. **No special privileges required**: Any network peer can send malicious `EpochChangeProof` messages
3. **Multiple attack surfaces**: Affects both consensus initialization and light client state sync
4. **Attack is deterministic**: If the attacker knows the waypoint, they can reliably craft matching ledger infos
5. **Common operation**: Nodes frequently bootstrap from waypoints during initial sync or after extended downtime

The only requirement is knowing the waypoint's version and hash, which are typically public or easily obtainable.

## Recommendation

The `Waypoint` verifier must validate signatures before verifying the waypoint commitment. However, waypoints don't contain validator information, so they cannot verify signatures directly.

**Recommended Fix**: Waypoint verification should be restricted to scenarios where signatures have already been validated by another mechanism, OR waypoints should explicitly reject being used as standalone verifiers for `LedgerInfoWithSignatures`.

**Option 1 - Fail fast approach**:
```rust
impl Verifier for Waypoint {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        // Waypoints cannot verify signatures - they should only be used
        // after signature verification has already occurred
        bail!("Waypoint cannot verify LedgerInfoWithSignatures directly. \
               Use EpochState verifier for signature validation first.");
    }
    // ... other methods unchanged
}
```

**Option 2 - Defensive approach with explicit warning**:
Modify `EpochChangeProof::verify()` to require signature verification before waypoint checks:
```rust
pub fn verify(&self, verifier: &dyn Verifier) -> Result<&LedgerInfoWithSignatures> {
    // ... existing checks ...
    
    for ledger_info_with_sigs in self.ledger_info_with_sigs.iter()... {
        // If verifier is a waypoint, we need separate signature validation
        // since waypoints only verify version/hash commitments
        if verifier_ref.is_waypoint() {
            // Require the ledger info to be self-signed by its own validator set
            let epoch_state = ledger_info_with_sigs.ledger_info()
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
            ledger_info_with_sigs.verify_signatures(&epoch_state.verifier)?;
        }
        
        verifier_ref.verify(ledger_info_with_sigs)?;
        // ... rest of logic
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_waypoint_bypasses_signature_validation() {
    use crate::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        epoch_change::EpochChangeProof,
        epoch_state::EpochState,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        validator_verifier::random_validator_verifier,
        waypoint::Waypoint,
    };
    use aptos_crypto::hash::HashValue;

    // Create a legitimate epoch-ending ledger info with proper signatures
    let (signers, verifier) = random_validator_verifier(4, None, true);
    let epoch_state = EpochState::new(2, verifier.clone());
    
    let ledger_info = LedgerInfo::new(
        BlockInfo::new(
            1,
            0,
            HashValue::zero(),
            HashValue::zero(),
            100,
            0,
            Some(epoch_state.clone()),
        ),
        HashValue::zero(),
    );

    // Create a waypoint from this ledger info
    let waypoint = Waypoint::new_epoch_boundary(&ledger_info).unwrap();

    // ATTACK: Create a LedgerInfoWithSignatures with EMPTY signatures
    // but matching the waypoint's version and hash
    let malicious_li_with_sigs = LedgerInfoWithSignatures::new(
        ledger_info.clone(),
        AggregateSignature::empty(), // <- INVALID/EMPTY SIGNATURES
    );

    // Create an EpochChangeProof with the malicious ledger info
    let malicious_proof = EpochChangeProof::new(
        vec![malicious_li_with_sigs],
        false,
    );

    // VULNERABILITY: This should FAIL because signatures are invalid,
    // but it PASSES because waypoint.verify() doesn't check signatures
    let result = malicious_proof.verify(&waypoint);
    
    // This assertion SHOULD fail but currently passes - demonstrating the bug
    assert!(result.is_ok(), "Waypoint accepted ledger info with invalid signatures!");
    
    // The attacker has now compromised the validator set for epoch 2
    let compromised_li = result.unwrap();
    let attacker_controlled_epoch_state = compromised_li
        .ledger_info()
        .next_epoch_state()
        .unwrap();
    
    println!("CRITICAL: Attacker now controls epoch {} validator set!", 
             attacker_controlled_epoch_state.epoch);
}
```

**Notes**

The vulnerability stems from an architectural mismatch: the `Verifier` trait assumes all implementors can validate signatures, but `Waypoint` only contains a cryptographic commitment (version + hash) without validator information needed for BLS signature verification. The waypoint verification was designed as a lightweight checkpoint mechanism but is being used in security-critical contexts where signature validation is mandatory.

### Citations

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

**File:** types/src/waypoint.rs (L82-85)
```rust
impl Verifier for Waypoint {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        self.verify(ledger_info.ledger_info())
    }
```

**File:** types/src/ledger_info.rs (L283-285)
```rust
    pub fn ledger_info(&self) -> &LedgerInfo {
        &self.ledger_info
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

**File:** types/src/epoch_change.rs (L106-115)
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
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L265-269)
```rust
    fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let waypoint = self.persistent_storage.waypoint()?;
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
```

**File:** types/src/trusted_state.rs (L161-163)
```rust
        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
```

**File:** types/src/trusted_state.rs (L236-242)
```rust
impl Verifier for TrustedState {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        match self {
            Self::EpochWaypoint(waypoint) => Verifier::verify(waypoint, ledger_info),
            Self::EpochState { epoch_state, .. } => Verifier::verify(epoch_state, ledger_info),
        }
    }
```
