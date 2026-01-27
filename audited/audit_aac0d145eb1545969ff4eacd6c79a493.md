# Audit Report

## Title
Light Client Epoch Synchronization Stall via Partial Epoch Change Proofs

## Summary
The `verify_and_ratchet_inner()` function in `TrustedState` accepts partial epoch change proofs (indicated by `more = true`) and successfully ratchets light clients to intermediate epochs without providing a clear indication that synchronization is incomplete. This can cause light clients to become stuck at intermediate epochs while believing they are fully synchronized, operating with stale validator sets.

## Finding Description

The vulnerability exists in the light client state verification logic where partial epoch change proofs are accepted as valid completion points. [1](#0-0) 

When a light client calls `verify_and_ratchet_inner()` with a `StateProof` containing:
- An `EpochChangeProof` with `more = true` (indicating incomplete proof)
- A `latest_li` from epoch N+200
- Epoch change ledger infos only covering epochs N to N+100

The function accepts this as valid and returns `TrustedStateChange::Epoch` with the new state at epoch N+100, not N+200.

The critical issue is that the `EpochChangeProof` is limited to 100 epochs per request: [2](#0-1) 

When more than 100 epochs need to be traversed: [3](#0-2) 

The server sets `more = true` and returns only the first 100 epochs. The light client then ratchets to epoch 100 instead of the latest epoch 200, with no indication in the return value that the proof was partial. [4](#0-3) 

The `TrustedStateChange::Epoch` return value does not expose the `more` flag, leaving the caller unaware that they are at an intermediate epoch.

## Impact Explanation

This qualifies as **High Severity** under "Significant protocol violations" because:

1. **Stale Validator Set Operation**: Light clients operate with validator sets from intermediate epochs while the network has advanced. This breaks the security model where light clients should track the latest verifiable state.

2. **Eclipse Attack Enhancement**: Combined with network isolation, attackers can permanently trap light clients at old epochs, showing them forked chain views.

3. **State Inconsistency**: Light clients at epoch 100 may accept/reject transactions differently than the network at epoch 200, violating state consistency guarantees.

4. **No Clear Recovery Path**: The API provides no mechanism for callers to detect they are at an intermediate epoch or that additional requests are needed.

While the internal Aptos state sync bootstrapper handles this correctly via `EpochEndingStreamEngine`, the `TrustedState` API is a public interface used by external light client implementations, making this a protocol-level concern.

## Likelihood Explanation

**Likelihood: Medium-High**

This will occur whenever:
- The network has advanced >100 epochs since the light client's last sync
- A light client uses the `TrustedState::verify_and_ratchet()` API directly
- The light client doesn't implement additional checks to compare the final state with the original `latest_li`

The test suite explicitly validates this behavior as expected: [5](#0-4) 

This confirms the behavior is intentional but lacks safeguards against misuse.

## Recommendation

The API should be modified to make partial synchronization explicit:

**Option 1**: Add a `more` field to `TrustedStateChange::Epoch`:
```rust
pub enum TrustedStateChange<'a> {
    Epoch {
        new_state: TrustedState,
        latest_epoch_change_li: &'a LedgerInfoWithSignatures,
        more_epochs_available: bool,  // NEW FIELD
    },
    // ... other variants
}
```

**Option 2**: Fail verification when `more = true` unless the caller explicitly opts in:
```rust
pub fn verify_and_ratchet_inner<'a>(
    &self,
    latest_li: &'a LedgerInfoWithSignatures,
    epoch_change_proof: &'a EpochChangeProof,
) -> Result<TrustedStateChange<'a>> {
    // ... existing checks ...
    
    if epoch_change_proof.more && latest_li.ledger_info().epoch() > new_epoch {
        bail!("Epoch change proof is incomplete. Use verify_and_ratchet_partial() to explicitly allow partial proofs.");
    }
    
    // ... rest of implementation
}
```

**Option 3**: Add documentation and helper methods:
```rust
impl TrustedStateChange<'_> {
    /// Returns true if the state change reached the target ledger info
    pub fn is_complete(&self, target_li: &LedgerInfo) -> bool {
        match self {
            Self::Epoch { new_state, .. } | Self::Version { new_state } => {
                new_state.version() >= target_li.version()
            }
            Self::NoChange => false,
        }
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_light_client_stuck_at_intermediate_epoch() {
    // Setup: Create epoch changes from 1 to 200
    let (signers, lis_with_sigs, latest_li, accumulator) = 
        create_epoch_changes(1, 200);  // Helper function
    
    // Light client starts at epoch 1
    let initial_li = &lis_with_sigs[0];
    let trusted_state = TrustedState::try_from_epoch_change_li(
        initial_li.ledger_info(),
        accumulator.get_accumulator_summary(initial_li.ledger_info().version()),
    ).unwrap();
    
    // Server provides partial proof: only epochs 1-100 (with more = true)
    let partial_proof_lis = lis_with_sigs[0..100].to_vec();
    let partial_epoch_change_proof = EpochChangeProof::new(
        partial_proof_lis, 
        true  // more = true, indicating proof is incomplete
    );
    
    // Light client verifies and ratchets
    let result = trusted_state.verify_and_ratchet_inner(
        &latest_li,  // Latest ledger info is at epoch 200
        &partial_epoch_change_proof
    ).unwrap();
    
    // VULNERABILITY: Client ratchets to epoch 100, NOT epoch 200
    match result {
        TrustedStateChange::Epoch { new_state, .. } => {
            // Client is stuck at epoch 100
            assert_eq!(new_state.version(), lis_with_sigs[99].ledger_info().version());
            
            // Latest network state is at epoch 200
            assert_eq!(latest_li.ledger_info().epoch(), 200);
            
            // Client is 100 epochs behind with NO indication!
            assert!(new_state.version() < latest_li.ledger_info().version());
            
            // The return value provides NO way to detect this is partial
            // Client believes sync is complete
        }
        _ => panic!("Expected Epoch change"),
    }
}
```

## Notes

While the Aptos state sync bootstrapper's `EpochEndingStreamEngine` handles partial proofs correctly by continuing to request additional epochs until reaching the advertised end epoch, this protection is not built into the `TrustedState` API itself. External light client implementations using the public `TrustedState::verify_and_ratchet()` API are vulnerable to this issue. The lack of clear API documentation or return value indicators makes this a significant protocol violation affecting light client security guarantees.

### Citations

**File:** types/src/trusted_state.rs (L183-184)
```rust
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
```

**File:** types/src/trusted_state.rs (L195-198)
```rust
            Ok(TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li: epoch_change_li,
            })
```

**File:** storage/aptosdb/src/common.rs (L9-9)
```rust
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1044-1048)
```rust
        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };
```

**File:** types/src/unit_tests/trusted_state_test.rs (L395-410)
```rust
        // ratcheting with more = true is fine
        change_proof.more = true;
        let trusted_state_change = trusted_state
            .verify_and_ratchet_inner(&latest_li, &change_proof)
            .expect("Should succeed with more in EpochChangeProof");

        match trusted_state_change {
            TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li,
            } => {
                assert_eq!(new_state.version(), expected_latest_version);
                assert_eq!(latest_epoch_change_li, &expected_latest_epoch_change_li);
            }
            _ => panic!("Unexpected ratchet result"),
        };
```
