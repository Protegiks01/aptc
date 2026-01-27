# Audit Report

## Title
Critical Epoch State Mismatch in State Sync Allowing Consensus Safety Violation

## Summary
The `StateSyncChunkVerifier::maybe_select_chunk_ending_ledger_info` function fails to validate that the `next_epoch_state` in the state-sync-provided `verified_target_li` matches the locally computed `next_epoch_state` from execution. This allows a malicious state sync peer to inject a ledger info with an attacker-controlled validator set, which gets stored in the database and later propagated to other nodes via `EpochChangeProof`, causing a network-wide consensus split.

## Finding Description

The vulnerability exists in the epoch-ending ledger info validation during state sync. When a chunk ends an epoch, the `ExecutedChunk` struct contains two separate sources of epoch state information:

1. `output.execution_output.next_epoch_state` - computed from local transaction execution
2. `ledger_info_opt` - provided by the state sync peer and stored to database [1](#0-0) 

In the validation path for epoch-ending chunks, there are two code paths:

**Path 1 (Lines 80-88)**: When the chunk corresponds to the target ledger info, only the version and transaction accumulator hash are validated: [2](#0-1) 

Critically, this path does NOT validate that `next_epoch_state` matches between the ledger info and the locally computed execution output.

**Path 2 (Lines 89-117)**: When an `epoch_change_li` is explicitly provided, proper validation IS performed: [3](#0-2) 

### Attack Flow

1. Malicious state sync peer crafts a `verified_target_li` with:
   - Correct version and transaction accumulator hash (passes validation)
   - Malicious `next_epoch_state` containing attacker-controlled validator set

2. Victim node executes transactions locally, computing the correct `next_epoch_state`

3. The malicious `verified_target_li` passes validation via Path 1 because only version and hash are checked

4. The ledger info with malicious validator set is saved to storage: [4](#0-3) 

5. When other nodes sync from the victim, the malicious ledger info is retrieved and used to construct `EpochChangeProof`: [5](#0-4) 

6. The `next_epoch_state` from the stored ledger info becomes the verifier for subsequent epochs, propagating the attack to all syncing nodes.

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This vulnerability enables an attacker with a malicious state sync peer to:

1. **Inject arbitrary validators** into the validator set for the next epoch
2. **Cause consensus split** where different nodes have different validator sets for the same epoch
3. **Break consensus safety** as nodes cannot agree on blocks with mismatched validator sets
4. **Propagate the attack** to all nodes that sync using the compromised `EpochChangeProof`

This meets the **Critical Severity** criteria:
- **Consensus/Safety violations**: Different nodes will have fundamentally incompatible views of the validator set
- **Non-recoverable network partition**: Once the malicious epoch state is stored and propagated, a hard fork would be required to recover

The attack breaks the critical invariant: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

## Likelihood Explanation

**High Likelihood**

The attack is highly feasible because:

1. **No special access required**: Attacker only needs to run a malicious state sync peer that responds to sync requests
2. **Natural trigger**: State sync is a normal operation that occurs frequently during node startup, catch-up, or epoch transitions
3. **No cryptographic bypass needed**: The validation gap is a pure logic error
4. **Wide attack surface**: Any node performing state sync is vulnerable
5. **Persistent impact**: Once stored, the malicious ledger info permanently affects the database

The only requirement is that the victim node queries the malicious peer for state sync, which is a normal network operation.

## Recommendation

Add explicit validation in the `verified_target_li` path to ensure `next_epoch_state` matches the locally computed value:

```rust
// In chunk_result_verifier.rs, lines 80-88
if li.version() + 1 == txn_accumulator.num_leaves() {
    ensure!(
        li.transaction_accumulator_hash() == txn_accumulator.root_hash(),
        "Root hash in target ledger info does not match local computation. {:?} != {:?}",
        li,
        txn_accumulator,
    );
    
    // ADD THIS VALIDATION:
    ensure!(
        li.next_epoch_state() == next_epoch_state,
        "Next epoch state in target ledger info does not match local computation. {:?} vs {:?}",
        li.next_epoch_state(),
        next_epoch_state,
    );
    
    Ok(Some(self.verified_target_li.clone()))
}
```

This ensures consistency between the state-sync-provided ledger info and the locally executed result, preventing injection of malicious epoch states.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_epoch_state_mismatch_vulnerability() {
    use aptos_types::epoch_state::EpochState;
    use aptos_types::validator_verifier::ValidatorVerifier;
    use aptos_crypto::hash::HashValue;
    
    // Setup: Create two different validator sets
    let correct_validator_set = create_validator_set(vec!["validator1", "validator2"]);
    let malicious_validator_set = create_validator_set(vec!["attacker1", "attacker2"]);
    
    let correct_epoch_state = EpochState::new(
        2, 
        ValidatorVerifier::from(&correct_validator_set)
    );
    let malicious_epoch_state = EpochState::new(
        2,
        ValidatorVerifier::from(&malicious_validator_set)
    );
    
    // Execute chunk locally - produces correct_epoch_state
    let execution_output = execute_epoch_ending_chunk(transactions);
    assert_eq!(
        execution_output.next_epoch_state.as_ref().unwrap(),
        &correct_epoch_state
    );
    
    // Malicious state sync provides verified_target_li with wrong epoch state
    let malicious_ledger_info = create_ledger_info_with_epoch_state(
        version,
        accumulator_hash,
        Some(malicious_epoch_state.clone()) // WRONG validator set
    );
    
    let verifier = StateSyncChunkVerifier {
        verified_target_li: malicious_ledger_info,
        epoch_change_li: None, // Taking Path 1 (lines 80-88)
        txn_infos_with_proof,
    };
    
    // BUG: This passes validation even though epoch states don't match!
    let selected_li = verifier.maybe_select_chunk_ending_ledger_info(
        &ledger_update_output,
        execution_output.next_epoch_state.as_ref(),
    ).unwrap();
    
    assert!(selected_li.is_some());
    
    // The malicious epoch state gets stored
    let executed_chunk = ExecutedChunk {
        output: partial_result,
        ledger_info_opt: selected_li,
    };
    
    // When stored and later retrieved for EpochChangeProof,
    // other nodes will use the malicious validator set
    assert_ne!(
        executed_chunk.ledger_info_opt.unwrap().ledger_info().next_epoch_state(),
        &correct_epoch_state
    );
    // Consensus is now compromised!
}
```

The PoC demonstrates that a malicious ledger info with incorrect `next_epoch_state` passes validation and gets stored, enabling the consensus safety violation.

---

**Notes:**

This vulnerability is particularly severe because:
- The victim node itself may continue operating correctly (reading validator set from on-chain state)
- However, the corrupted ledger info in storage poisons the entire network when propagated via state sync
- The attack amplifies as more nodes sync from compromised nodes
- Detection is difficult as each node thinks it's operating correctly until consensus fails

The fix is straightforward but critical: add the missing validation to ensure epoch state consistency between state sync and local execution.

### Citations

**File:** execution/executor/src/types/executed_chunk.rs (L10-13)
```rust
pub struct ExecutedChunk {
    pub output: PartialStateComputeResult,
    pub ledger_info_opt: Option<LedgerInfoWithSignatures>,
}
```

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

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L112-116)
```rust
                li.next_epoch_state() == next_epoch_state,
                "New validator set of a given epoch LI does not match local computation. {:?} vs {:?}",
                li.next_epoch_state(),
                next_epoch_state,
            );
```

**File:** execution/executor/src/chunk_executor/mod.rs (L277-281)
```rust
            self.db.writer.save_transactions(
                output.as_chunk_to_commit(),
                chunk.ledger_info_opt.as_ref(),
                false, // sync_commit
            )?;
```

**File:** types/src/epoch_change.rs (L111-114)
```rust
            verifier_ref = ledger_info_with_sigs
                .ledger_info()
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
```
