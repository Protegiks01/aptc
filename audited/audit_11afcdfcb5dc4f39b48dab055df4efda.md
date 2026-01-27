# Audit Report

## Title
Integer Overflow in ValidatorVerifier Quorum Calculation Causes Network-Wide Consensus Failure with Zero-Power Validators

## Summary
The `ValidatorVerifier::new()` function fails to validate that `quorum_voting_power <= total_voting_power`, allowing creation of invalid verifier states when all validators have zero voting power. This triggers an integer underflow panic in `check_aggregated_voting_power()` during consensus operations, causing validator node crashes and complete network liveness failure.

## Finding Description
The vulnerability exists in the quorum calculation and validation logic of `ValidatorVerifier`. When `minimum_stake` is set to 0 through on-chain governance, validators with zero voting power can join the active validator set. [1](#0-0) 

The staking system permits validators with zero voting power if they meet the minimum stake requirement (which can be 0). [2](#0-1) 

When a `ValidatorSet` containing only zero-power validators is converted to a `ValidatorVerifier`, the `From` trait implementation calls `ValidatorVerifier::new()`. [3](#0-2) 

The `new()` function calculates quorum as `total_voting_power * 2 / 3 + 1`. With all validators having zero power, this yields `total_voting_power = 0` and `quorum_voting_power = 1`, violating the fundamental invariant that quorum cannot exceed total power. [4](#0-3) 

Unlike `new_with_quorum_voting_power()` which validates this invariant, `new()` performs no such check. [5](#0-4) 

When consensus code calls `check_aggregated_voting_power()` with `check_super_majority = false` (used for minority/timeout voting power checks), the calculation `self.total_voting_power - self.quorum_voting_power + 1` evaluates to `0 - 1 + 1`. [6](#0-5) 

With Aptos's release profile setting `overflow-checks = true`, this subtraction triggers an integer overflow panic. [7](#0-6) 

This code path is invoked in production consensus during timeout aggregation and DAG ordering. [8](#0-7) [9](#0-8) 

**Attack Scenario:**
1. Governance proposal sets `minimum_stake = 0` (permitted by validation)
2. All active validators reduce their stake to zero or new validators join with zero stake
3. At epoch boundary, `on_new_epoch()` includes all zero-power validators in active set
4. `ValidatorSet` is converted to `ValidatorVerifier` with invalid quorum state
5. During consensus round timeout processing or DAG ordering, `check_aggregated_voting_power(_, false)` is called
6. Integer underflow panic crashes all validator nodes simultaneously
7. Network experiences complete consensus halt requiring emergency intervention

## Impact Explanation
This is a **Critical Severity** vulnerability under the Aptos bug bounty program, specifically qualifying as "Total loss of liveness/network availability" (eligible for up to $1,000,000).

**Consensus Impact:**
- All validator nodes crash simultaneously when processing timeouts or DAG blocks
- Network cannot produce new blocks or finalize transactions
- Requires coordinated manual intervention and potential hardfork to recover

**Broken Invariants:**
- **Consensus Safety**: Network cannot maintain liveness with all validators crashed
- **Deterministic Execution**: Panic violates expected error handling semantics

The impact is total and immediate—once triggered, the entire network halts until manual recovery procedures are implemented.

## Likelihood Explanation
**Likelihood: Medium-High**

**Prerequisites:**
1. Governance proposal to set `minimum_stake = 0` (feasible through standard governance)
2. All validators must have zero voting power simultaneously (could occur through coordinated stake withdrawal or malicious genesis configuration)

**Feasibility:**
- The staking configuration explicitly allows `minimum_stake = 0`, as evidenced by test usage and validation logic
- No upper-layer protection prevents all-zero-power validator sets
- The conversion path from `ValidatorSet` to `ValidatorVerifier` is deterministic and always uses the vulnerable `new()` function

While requiring governance action, this is not an unrealistic scenario, especially:
- During testnet deployments with relaxed parameters
- In malicious genesis configurations
- Through governance attacks where adversaries gain proposal power

## Recommendation
Add invariant validation to `ValidatorVerifier::new()` to match the protection in `new_with_quorum_voting_power()`:

```rust
pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
    let total_voting_power = sum_voting_power(&validator_infos);
    let quorum_voting_power = if validator_infos.is_empty() {
        0
    } else {
        total_voting_power * 2 / 3 + 1
    };
    
    // Add validation to prevent invalid quorum states
    assert!(
        quorum_voting_power <= total_voting_power || validator_infos.is_empty(),
        "Quorum voting power {} cannot exceed total voting power {}",
        quorum_voting_power,
        total_voting_power
    );
    
    Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
}
```

**Additional Hardening:**
1. Add minimum validator voting power enforcement in staking configuration (e.g., `minimum_stake >= 1`)
2. Add validation in `on_new_epoch()` to ensure at least one validator has non-zero power
3. Use saturating arithmetic or explicit bounds checks in `check_aggregated_voting_power()`

## Proof of Concept

```rust
#[cfg(test)]
mod zero_power_validator_poc {
    use super::*;
    use crate::validator_signer::ValidatorSigner;
    
    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn test_zero_power_validators_cause_underflow() {
        // Create 4 validators all with zero voting power
        let mut validator_infos = vec![];
        for i in 0..4 {
            let signer = ValidatorSigner::random([i; 32]);
            validator_infos.push(ValidatorConsensusInfo::new(
                signer.author(),
                signer.public_key(),
                0, // Zero voting power
            ));
        }
        
        // Create verifier - this succeeds but creates invalid state
        // total_voting_power = 0, quorum_voting_power = 1
        let verifier = ValidatorVerifier::new(validator_infos);
        
        assert_eq!(verifier.total_voting_power(), 0);
        assert_eq!(verifier.quorum_voting_power(), 1);
        
        // This panics with integer underflow when check_super_majority = false
        // Simulates consensus timeout aggregation code path
        let _ = verifier.check_aggregated_voting_power(0, false);
        // Panic occurs at: target = 0 - 1 + 1
    }
    
    #[test]
    fn test_normal_validators_work() {
        // Verify normal case works correctly
        let mut validator_infos = vec![];
        for i in 0..4 {
            let signer = ValidatorSigner::random([i; 32]);
            validator_infos.push(ValidatorConsensusInfo::new(
                signer.author(),
                signer.public_key(),
                100, // Normal voting power
            ));
        }
        
        let verifier = ValidatorVerifier::new(validator_infos);
        assert_eq!(verifier.total_voting_power(), 400);
        assert_eq!(verifier.quorum_voting_power(), 267); // 400 * 2/3 + 1
        
        // Minority check works: target = 400 - 267 + 1 = 134
        assert!(verifier.check_aggregated_voting_power(134, false).is_ok());
        assert!(verifier.check_aggregated_voting_power(133, false).is_err());
    }
}
```

**To reproduce:**
1. Add the test to `types/src/validator_verifier.rs`
2. Run: `cargo test test_zero_power_validators_cause_underflow`
3. Observe panic: "attempt to subtract with overflow" in release mode with `overflow-checks = true`

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L372-374)
```text
    fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
        assert!(minimum_stake <= maximum_stake && maximum_stake > 0, error::invalid_argument(EINVALID_STAKE_RANGE));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1390-1397)
```text
            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
            };
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

**File:** types/src/validator_verifier.rs (L217-234)
```rust
    pub fn new_with_quorum_voting_power(
        validator_infos: Vec<ValidatorConsensusInfo>,
        quorum_voting_power: u128,
    ) -> Result<Self> {
        let total_voting_power = sum_voting_power(&validator_infos);
        ensure!(
            quorum_voting_power <= total_voting_power,
            "Quorum voting power is greater than the sum of all voting power of authors: {}, \
             quorum_size: {}.",
            quorum_voting_power,
            total_voting_power
        );
        Ok(Self::build_index(
            validator_infos,
            quorum_voting_power,
            total_voting_power,
        ))
    }
```

**File:** types/src/validator_verifier.rs (L462-480)
```rust
    pub fn check_aggregated_voting_power(
        &self,
        aggregated_voting_power: u128,
        check_super_majority: bool,
    ) -> std::result::Result<u128, VerifyError> {
        let target = if check_super_majority {
            self.quorum_voting_power
        } else {
            self.total_voting_power - self.quorum_voting_power + 1
        };

        if aggregated_voting_power < target {
            return Err(VerifyError::TooLittleVotingPower {
                voting_power: aggregated_voting_power,
                expected_voting_power: target,
            });
        }
        Ok(aggregated_voting_power)
    }
```

**File:** types/src/validator_verifier.rs (L563-586)
```rust
impl From<&ValidatorSet> for ValidatorVerifier {
    fn from(validator_set: &ValidatorSet) -> Self {
        let sorted_validator_infos: BTreeMap<u64, ValidatorConsensusInfo> = validator_set
            .payload()
            .map(|info| {
                (
                    info.config().validator_index,
                    ValidatorConsensusInfo::new(
                        info.account_address,
                        info.consensus_public_key().clone(),
                        info.consensus_voting_power(),
                    ),
                )
            })
            .collect();
        let validator_infos: Vec<_> = sorted_validator_infos.values().cloned().collect();
        for info in validator_set.payload() {
            assert_eq!(
                validator_infos[info.config().validator_index as usize].address,
                info.account_address
            );
        }
        ValidatorVerifier::new(validator_infos)
    }
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** consensus/src/pending_votes.rs (L127-130)
```rust
                verifier
                    .check_aggregated_voting_power(*voting_power, false)
                    .is_ok()
            })
```

**File:** consensus/src/dag/dag_store.rs (L276-278)
```rust
                        || validator_verifier
                            .check_aggregated_voting_power(*aggregated_strong_voting_power, false)
                            .is_ok()
```
