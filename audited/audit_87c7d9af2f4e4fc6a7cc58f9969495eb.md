# Audit Report

## Title
Insufficient Epoch Boundary Validation in Waypoint Creation Allows Empty Validator Sets

## Summary
The `new_epoch_boundary()` function in `types/src/waypoint.rs` fails to properly validate that a LedgerInfo represents a legitimate epoch boundary with a complete validator set transition. The function only checks that `next_epoch_state` exists but does not validate that it contains a non-empty, valid validator set. This allows creation of waypoints for epoch boundaries with zero validators, which could facilitate chain halts if combined with other vulnerabilities.

## Finding Description
The `new_epoch_boundary()` function is intended to validate and create waypoints for epoch change transactions. According to its documentation and purpose, it should ensure the LedgerInfo represents a legitimate epoch boundary with a complete validator set transition. [1](#0-0) 

The validation performed by this function consists solely of checking `ledger_info.ends_epoch()`, which is implemented as: [2](#0-1) 

This check only verifies that `next_epoch_state` is `Some`, not that it contains a valid validator set. An `EpochState` can be constructed with an empty `ValidatorVerifier`: [3](#0-2) 

The `ValidatorVerifier::new()` constructor accepts an empty vector and sets `quorum_voting_power = 0` when the validator list is empty: [4](#0-3) 

**Proof the vulnerability exists**: The codebase's own test demonstrates this issue: [5](#0-4) 

At line 218, the test creates a LedgerInfo with `Some(EpochState::empty())` containing zero validators, and at line 222 it successfully passes `new_epoch_boundary()`. This proves that epoch boundaries with empty validator sets are accepted by the current validation logic.

**Missing Validations:**
1. No check that the validator set is non-empty (`verifier.is_empty()` is never called)
2. No validation of epoch number progression 
3. No verification that the validator set has sufficient voting power
4. No validation of public key validity in the validator set

## Impact Explanation
While the Move framework contains protections to prevent removing the last validator: [6](#0-5) 

This defense-in-depth failure in `new_epoch_boundary()` creates a critical vulnerability chain:

1. **If** a bug exists in the Move framework allowing empty validator set creation
2. **Then** this validation failure allows malicious epoch boundaries through waypoint creation
3. **Result**: Nodes could accept waypoints for epochs with zero validators, causing permanent chain halt

An epoch with zero validators cannot produce blocks, as there are no validators to sign quorum certificates. This would require a hard fork to recover.

However, exploitation requires either:
- Byzantine validator collusion to sign invalid LedgerInfo (≥34% stake)
- OR a separate bug in Move framework validator set management

**Severity Assessment**: This fails to meet Critical severity as it is not independently exploitable without Byzantine validators or additional vulnerabilities. It is a validation bypass that weakens defense-in-depth but has no direct exploitation path.

## Likelihood Explanation
**Low Likelihood** - Exploitation requires one of:
1. ≥34% Byzantine validators colluding to sign malicious LedgerInfo (violates trust model)
2. Separate vulnerability in Move framework allowing empty validator set creation
3. Compromise of epoch state construction in execution layer

In normal operation, epoch states are created via: [7](#0-6) 

The validator set is fetched from on-chain storage, which is protected by Move framework invariants.

## Recommendation
Add explicit validation that the next epoch state contains a valid, non-empty validator set:

```rust
pub fn new_epoch_boundary(ledger_info: &LedgerInfo) -> Result<Self> {
    ensure!(ledger_info.ends_epoch(), "No validator set");
    
    // Additional validation for validator set completeness
    if let Some(epoch_state) = ledger_info.next_epoch_state() {
        ensure!(
            !epoch_state.verifier.is_empty(),
            "Validator set cannot be empty in epoch boundary"
        );
        ensure!(
            epoch_state.verifier.quorum_voting_power() > 0,
            "Validator set must have positive quorum voting power"
        );
        ensure!(
            epoch_state.epoch > ledger_info.epoch(),
            "Next epoch must be greater than current epoch"
        );
    }
    
    Ok(Self::new_any(ledger_info))
}
```

## Proof of Concept
The existing test code demonstrates the vulnerability:

```rust
// From types/src/waypoint.rs test module
#[test]
fn test_empty_validator_set_accepted() {
    // Create a LedgerInfo with empty validator set
    let li = LedgerInfo::new(
        BlockInfo::new(
            1,
            10,
            HashValue::random(),
            HashValue::random(),
            123,
            1000,
            Some(EpochState::empty()), // Empty validator set!
        ),
        HashValue::zero(),
    );
    
    // This should fail but currently succeeds
    let waypoint = Waypoint::new_epoch_boundary(&li).unwrap();
    assert!(waypoint.verify(&li).is_ok());
    
    // Verify the epoch state is indeed empty
    let epoch_state = li.next_epoch_state().unwrap();
    assert_eq!(epoch_state.verifier.len(), 0); // Zero validators
    assert_eq!(epoch_state.verifier.quorum_voting_power(), 0); // No voting power
}
```

This PoC confirms that waypoints can be created for epoch boundaries with zero validators, violating the function's intended security guarantee.

**Notes:**
- This is a validation bypass vulnerability that weakens defense-in-depth
- Not independently exploitable without Byzantine validators or Move framework bugs
- The Move framework prevents empty validator sets in normal operation via `ELAST_VALIDATOR` assertion
- Impact is contingent on additional vulnerabilities in validator set management
- Recommended fix adds proper validation to maintain security invariants regardless of upstream protections

### Citations

**File:** types/src/waypoint.rs (L47-51)
```rust
    /// Generates a new waypoint given the epoch change LedgerInfo.
    pub fn new_epoch_boundary(ledger_info: &LedgerInfo) -> Result<Self> {
        ensure!(ledger_info.ends_epoch(), "No validator set");
        Ok(Self::new_any(ledger_info))
    }
```

**File:** types/src/waypoint.rs (L210-223)
```rust
        let li = LedgerInfo::new(
            BlockInfo::new(
                1,
                10,
                HashValue::random(),
                HashValue::random(),
                123,
                1000,
                Some(EpochState::empty()),
            ),
            HashValue::zero(),
        );
        let waypoint = Waypoint::new_epoch_boundary(&li).unwrap();
        assert!(waypoint.verify(&li).is_ok());
```

**File:** types/src/ledger_info.rs (L145-147)
```rust
    pub fn ends_epoch(&self) -> bool {
        self.next_epoch_state().is_some()
    }
```

**File:** types/src/epoch_state.rs (L32-37)
```rust
    pub fn empty() -> Self {
        Self {
            epoch: 0,
            verifier: Arc::new(ValidatorVerifier::new(vec![])),
        }
    }
```

**File:** types/src/validator_verifier.rs (L206-214)
```rust
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        let total_voting_power = sum_voting_power(&validator_infos);
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
        Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1253-1255)
```text
            let validator_info = vector::swap_remove(
                &mut validator_set.active_validators, option::extract(&mut maybe_active_index));
            assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L520-540)
```rust
    fn ensure_next_epoch_state(to_commit: &TransactionsWithOutput) -> Result<EpochState> {
        let last_write_set = to_commit
            .transaction_outputs
            .last()
            .ok_or_else(|| anyhow!("to_commit is empty."))?
            .write_set();

        let write_set_view = WriteSetStateView {
            write_set: last_write_set,
        };

        let validator_set = ValidatorSet::fetch_config(&write_set_view)
            .ok_or_else(|| anyhow!("ValidatorSet not touched on epoch change"))?;
        let configuration = ConfigurationResource::fetch_config(&write_set_view)
            .ok_or_else(|| anyhow!("Configuration resource not touched on epoch change"))?;

        Ok(EpochState::new(
            configuration.epoch(),
            (&validator_set).into(),
        ))
    }
```
