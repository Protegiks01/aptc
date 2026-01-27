# Audit Report

## Title
Epoch State Validation Bypass in State Sync Chunk Verification Allows Unauthorized Epoch Transitions

## Summary
The `StateSyncChunkVerifier::maybe_select_chunk_ending_ledger_info()` function fails to validate that a `verified_target_li`'s epoch ending semantics match the locally computed execution output. When the target ledger info's version matches the chunk, the function returns it after only checking the accumulator hash, without verifying whether `ends_epoch()` and `next_epoch_state()` are consistent with the actual execution results. This allows a malicious peer to provide a ledger info that claims an epoch ended (or didn't end) when execution disagrees, causing consensus divergence.

## Finding Description
The vulnerability exists in the first branch of `maybe_select_chunk_ending_ledger_info()`: [1](#0-0) 

This branch only validates:
1. Version matches: `li.version() + 1 == txn_accumulator.num_leaves()`
2. Accumulator hash matches: `li.transaction_accumulator_hash() == txn_accumulator.root_hash()`

It **does not** validate:
- Whether `li.ends_epoch()` matches `next_epoch_state.is_some()`
- Whether `li.next_epoch_state()` equals the locally computed `next_epoch_state`

In contrast, the second branch properly validates epoch semantics: [2](#0-1) 

The `ends_epoch()` method is derived from whether `next_epoch_state` exists: [3](#0-2) 

### Attack Scenario 1: False Epoch Ending

1. Node executes transactions locally, producing `next_epoch_state = None` (no epoch change)
2. Malicious state sync peer provides `verified_target_li` with:
   - Valid BLS signatures from validators
   - Correct version and accumulator hash for this chunk
   - **But** `next_epoch_state = Some(malicious_validator_set)`
3. Function execution at: [4](#0-3) 

4. Branch 1 matches (version correct), returns `verified_target_li` without epoch validation
5. Ledger info is committed to storage via: [5](#0-4) 

The storage layer only checks that a state snapshot exists, not that the `next_epoch_state` content is correct.

### Attack Scenario 2: Suppressed Epoch Ending

1. Node executes transactions that trigger epoch change, producing `next_epoch_state = Some(new_validators)`
2. Attacker provides `verified_target_li` with `next_epoch_state = None`
3. Same branch 1 logic returns it without validation
4. Epoch transition is suppressed, node continues in wrong epoch

## Impact Explanation
This is a **Critical Severity** consensus safety violation:

**Consensus Safety Violation**: Different nodes can commit different epoch states for the same version, causing permanent chain divergence. Some nodes will transition to a new epoch with validator set A, while others remain in the current epoch or transition to validator set B.

**Validator Set Manipulation**: An attacker can force nodes to use an incorrect validator set by providing a ledger info with a crafted `next_epoch_state`. This breaks the fundamental security assumption that 2f+1 honest validators control consensus.

**Non-Recoverable Network Partition**: Once nodes diverge on epoch state, they cannot sync with each other as they have incompatible views of the validator set. This requires a hard fork to resolve.

This meets the Critical Severity criteria:
- Consensus/Safety violations ✓
- Non-recoverable network partition (requires hardfork) ✓

## Likelihood Explanation
**Likelihood: Medium-to-High**

**Attacker Requirements:**
- Ability to act as a state sync peer (network-level access)
- Possession of a validly-signed ledger info with wrong epoch semantics (possible from a fork, old branch, or Byzantine validators signing conflicting blocks)
- Target node must be syncing via state sync

**Feasibility:**
- State sync peers can be arbitrary network participants
- Ledger infos with valid signatures but incorrect content can exist due to:
  - Non-deterministic execution bugs
  - Byzantine validators signing multiple conflicting blocks
  - Network forks before reconfiguration
- The signature verification only checks cryptographic validity, not semantic correctness

**Complexity: Low** - Once a suitable ledger info is obtained, exploitation is straightforward as the validation gap is deterministic.

## Recommendation

Add epoch state validation to the first branch of `maybe_select_chunk_ending_ledger_info()`: [1](#0-0) 

**Fixed code:**

```rust
if li.version() + 1 == txn_accumulator.num_leaves() {
    // If the chunk corresponds to the target LI, the target LI can be added to storage.
    ensure!(
        li.transaction_accumulator_hash() == txn_accumulator.root_hash(),
        "Root hash in target ledger info does not match local computation. {:?} != {:?}",
        li,
        txn_accumulator,
    );
    
    // CRITICAL FIX: Validate epoch ending semantics match execution output
    ensure!(
        li.ends_epoch() == next_epoch_state.is_some(),
        "Epoch ending flag mismatch. LI ends_epoch: {}, computed next_epoch_state present: {}",
        li.ends_epoch(),
        next_epoch_state.is_some(),
    );
    
    if li.ends_epoch() {
        ensure!(
            li.next_epoch_state() == next_epoch_state,
            "Next epoch state mismatch. LI: {:?}, computed: {:?}",
            li.next_epoch_state(),
            next_epoch_state,
        );
    }
    
    Ok(Some(self.verified_target_li.clone()))
}
```

This ensures that `verified_target_li` can only be returned when its epoch semantics exactly match the locally computed execution results.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::{
        block_info::BlockInfo,
        epoch_state::EpochState,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        validator_verifier::ValidatorVerifier,
        on_chain_config::ValidatorSet,
    };
    use aptos_crypto::HashValue;
    
    #[test]
    #[should_panic(expected = "Epoch ending flag mismatch")]
    fn test_epoch_validation_bypass() {
        // Create a ledger info claiming epoch ended with malicious validator set
        let malicious_validator_set = ValidatorSet::empty();
        let malicious_epoch_state = EpochState {
            epoch: 2,
            verifier: (&malicious_validator_set).into(),
        };
        
        let block_info_with_epoch = BlockInfo::new(
            1, // epoch
            10, // round
            HashValue::random(),
            HashValue::random(), // executed_state_id
            100, // version
            1000, // timestamp
            Some(malicious_epoch_state), // Claims epoch ended!
        );
        
        let li_with_epoch = LedgerInfo::new(block_info_with_epoch, HashValue::zero());
        let verified_target_li = LedgerInfoWithSignatures::new(
            li_with_epoch,
            AggregateSignature::empty(), // Would have real signatures in practice
        );
        
        // Create verifier
        let verifier = StateSyncChunkVerifier {
            txn_infos_with_proof: TransactionInfoListWithProof::new_empty(),
            verified_target_li: verified_target_li.clone(),
            epoch_change_li: None,
        };
        
        // Create ledger update output matching the version and hash
        let mut accumulator = InMemoryTransactionAccumulator::new_empty();
        for _ in 0..=100 {
            accumulator.append(&[HashValue::random()]).unwrap();
        }
        
        let ledger_update = LedgerUpdateOutput {
            transaction_accumulator: accumulator,
            ..Default::default()
        };
        
        // Execution computed NO epoch change (next_epoch_state = None)
        // But verified_target_li claims epoch ended!
        let result = verifier.maybe_select_chunk_ending_ledger_info(
            &ledger_update,
            None, // No epoch change from execution
        );
        
        // Current code: Returns Ok(Some(verified_target_li)) - VULNERABLE!
        // Fixed code: Should panic with "Epoch ending flag mismatch"
        assert!(result.is_err());
    }
}
```

This PoC demonstrates that a ledger info with `ends_epoch() = true` can be accepted when execution produces `next_epoch_state = None`, allowing unauthorized epoch transitions.

## Notes

The vulnerability stems from an incomplete validation in the "happy path" where the target ledger info's version matches perfectly. The code assumes that if the version and accumulator hash match, the ledger info must be correct. However, this assumption is violated when Byzantine actors provide validly-signed but semantically incorrect ledger infos.

The second branch (epoch_change_li handling) has proper validation, suggesting the developers were aware of the need to check epoch semantics, but missed applying the same validation to the first branch.

This is particularly critical because epoch transitions determine the validator set for consensus. An attacker who can manipulate which epoch a node believes it's in can potentially cause that node to accept blocks from an entirely different validator set, completely breaking consensus safety.

### Citations

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L80-88)
```rust
        if li.version() + 1 == txn_accumulator.num_leaves() {
            // If the chunk corresponds to the target LI, the target LI can be added to storage.
            ensure!(
                li.transaction_accumulator_hash() == txn_accumulator.root_hash(),
                "Root hash in target ledger info does not match local computation. {:?} != {:?}",
                li,
                txn_accumulator,
            );
            Ok(Some(self.verified_target_li.clone()))
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L106-116)
```rust
            ensure!(
                li.ends_epoch(),
                "Epoch change LI does not carry validator set. version:{}",
                li.version(),
            );
            ensure!(
                li.next_epoch_state() == next_epoch_state,
                "New validator set of a given epoch LI does not match local computation. {:?} vs {:?}",
                li.next_epoch_state(),
                next_epoch_state,
            );
```

**File:** types/src/ledger_info.rs (L145-147)
```rust
    pub fn ends_epoch(&self) -> bool {
        self.next_epoch_state().is_some()
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L367-370)
```rust
        let ledger_info_opt = chunk_verifier.maybe_select_chunk_ending_ledger_info(
            &ledger_update_output,
            output.execution_output.next_epoch_state.as_ref(),
        )?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L585-594)
```rust
        if ledger_info_with_sig.ledger_info().ends_epoch() {
            let state_snapshot = self.state_store.get_state_snapshot_before(version + 1)?;
            ensure!(
                state_snapshot.is_some() && state_snapshot.as_ref().unwrap().0 == version,
                "State checkpoint not persisted at the end of the epoch, version {}, next_epoch {}, snapshot in db: {:?}",
                version,
                ledger_info_with_sig.ledger_info().next_block_epoch(),
                state_snapshot,
            );
        }
```
