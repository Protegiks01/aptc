# Audit Report

## Title
Total Network Liveness Failure via Division-by-Zero Panic in Rotating Proposer Election with Empty Validator Set

## Summary
The `get_valid_proposer()` function in `RotatingProposer` performs a modulo operation by the length of the proposers vector without validating it is non-empty. If the validator set becomes empty during epoch transitions, all validators will panic simultaneously when attempting to determine the valid proposer, causing irrecoverable total loss of network liveness. [1](#0-0) 

## Finding Description

The vulnerability exists in the proposer election mechanism. The `get_valid_proposer()` function calculates the valid proposer using modulo arithmetic with `self.proposers.len()` as the divisor. When the proposers vector is empty (length = 0), this causes a division-by-zero panic.

**How Empty Validator Sets Can Occur:**

During epoch transitions in the Move framework's staking module, validators are filtered based on minimum stake requirements. The code builds a new validator set by only including validators meeting the threshold: [2](#0-1) 

If ALL validators fail to meet the minimum stake requirement, `next_epoch_validators` remains empty and is assigned to `validator_set.active_validators`. **No validation prevents this empty state.**

**Missing Validation in Rust Layer:**

The Rust consensus code retrieves proposers from the epoch state without checking for emptiness: [3](#0-2) 

The `ValidatorVerifier` itself permits empty validator sets: [4](#0-3) 

**Critical Consensus Path Usage:**

The vulnerable function is called in critical consensus operations:
- Round transitions: [5](#0-4) 
- Timeout handling: [6](#0-5) 
- Proposal generation: [7](#0-6) 

**Attack Execution:**

1. A governance proposal increases the minimum stake requirement above all current validator stakes
2. At the next epoch transition, the staking module filters all validators out
3. The empty validator set propagates to all nodes via epoch change proofs
4. When any validator attempts to advance rounds or handle timeouts, `get_valid_proposer()` is called
5. The modulo-by-zero operation panics, crashing the validator process
6. All validators crash simultaneously → total network halt

## Impact Explanation

**Critical Severity: Total Loss of Liveness**

This meets the **Critical** severity category ($1,000,000 tier) per Aptos bug bounty criteria:
- **Total loss of liveness/network availability**: All validators crash simultaneously
- **Non-recoverable network partition (requires hardfork)**: Recovery requires manual intervention, validator restarts, and likely a hardfork to restore a valid validator set

The impact is catastrophic because:
1. **Simultaneous failure**: All validators receive identical empty validator sets through epoch state synchronization
2. **Immediate trigger**: The first consensus operation (round advance, timeout, proposal) triggers the panic
3. **No automatic recovery**: The empty validator set persists in committed state; nodes will continue crashing on restart
4. **Requires hardfork**: Cannot be resolved through normal consensus mechanisms since consensus itself is broken

## Likelihood Explanation

**Medium-to-Low Likelihood, But Catastrophic When Triggered:**

While the impact is catastrophic, triggering requires specific conditions:

**Realistic Trigger Scenarios:**
1. **Emergency governance action**: A governance proposal dramatically increases minimum stake during a crisis (e.g., responding to a stake-based attack), inadvertently excluding all validators
2. **Coordinated unstaking**: Multiple validators simultaneously reduce stake below threshold during epoch boundary
3. **Economic attack**: Large-scale market manipulation causes validator stake values to drop below minimum
4. **Staking logic bug**: A separate bug in reward/penalty calculation causes mass stake reduction

**Why This Is Still Critical:**
- The code has **zero defensive checks** against this state
- Governance participants may not realize the stake threshold increase will exclude ALL validators
- No warning or validation occurs before the epoch transition commits
- Once triggered, recovery is extremely difficult

The lack of validation violates fundamental defensive programming principles for consensus-critical code.

## Recommendation

**Implement Multi-Layer Validation:**

**1. Move Framework Validation (Primary Defense):**
Add an assertion in `stake.move` after filtering validators:

```move
// After line 1401 in stake.move
assert!(!vector::is_empty(&validator_set.active_validators), 
    error::invalid_state(EEMPTY_VALIDATOR_SET));
```

**2. Rust Validation (Secondary Defense):**
Add validation in `RotatingProposer::new()`:

```rust
pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
    assert!(!proposers.is_empty(), "Proposers vector cannot be empty");
    assert!(contiguous_rounds > 0, "Contiguous rounds must be positive");
    Self {
        proposers,
        contiguous_rounds,
    }
}
```

**3. Epoch Manager Validation (Tertiary Defense):**
Add validation in `create_proposer_election()`:

```rust
let proposers = epoch_state
    .verifier
    .get_ordered_account_addresses_iter()
    .collect::<Vec<_>>();
    
ensure!(!proposers.is_empty(), 
    "Validator set cannot be empty at epoch {}", epoch_state.epoch);
```

**4. Governance Guardrails:**
Implement pre-flight validation for governance proposals that modify staking parameters to ensure at least one validator will remain active.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to calculate the remainder with a divisor of zero")]
fn test_empty_proposers_panic() {
    use crate::liveness::{
        proposer_election::ProposerElection,
        rotating_proposer_election::RotatingProposer,
    };
    
    // Create RotatingProposer with empty proposers vector
    // This simulates the state after epoch transition with empty validator set
    let empty_proposers = vec![];
    let pe = RotatingProposer::new(empty_proposers, 1);
    
    // Any call to get_valid_proposer will panic
    // This represents a validator trying to determine the proposer for round 1
    pe.get_valid_proposer(1); // PANIC: division by zero
}

#[test]
fn test_empty_validator_verifier_creation() {
    use aptos_types::validator_verifier::{ValidatorVerifier, ValidatorConsensusInfo};
    
    // Demonstrates that ValidatorVerifier allows empty validator sets
    let empty_infos: Vec<ValidatorConsensusInfo> = vec![];
    let verifier = ValidatorVerifier::new(empty_infos);
    
    assert_eq!(verifier.len(), 0);
    assert!(verifier.is_empty());
    // This invalid state can propagate through epoch transitions
}
```

**Integration Test Scenario:**
```rust
// Simulates epoch transition with empty validator set
#[test]
#[should_panic]
fn test_epoch_transition_empty_validator_set() {
    // 1. Start with valid validator set
    // 2. Simulate governance proposal increasing min stake above all validators
    // 3. Trigger epoch transition (calls stake.move::on_new_epoch)
    // 4. New epoch state has empty active_validators
    // 5. Consensus attempts to create proposer election
    // 6. First call to get_valid_proposer() -> PANIC
}
```

**Notes:**

This vulnerability demonstrates a critical gap in defensive validation across the consensus stack. The Move framework, Rust consensus layer, and epoch management all lack checks for this invariant violation. While triggering requires governance action or unusual circumstances, the complete absence of validation makes this a time bomb waiting for the right conditions. The fix requires defense-in-depth validation at multiple layers to prevent this catastrophic failure mode.

### Citations

**File:** consensus/src/liveness/rotating_proposer_election.rs (L36-39)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1372-1401)
```text
        let next_epoch_validators = vector::empty();
        let (minimum_stake, _) = staking_config::get_required_stake(&config);
        let vlen = vector::length(&validator_set.active_validators);
        let total_voting_power = 0;
        let i = 0;
        while ({
            spec {
                invariant spec_validators_are_initialized(next_epoch_validators);
                invariant i <= vlen;
            };
            i < vlen
        }) {
            let old_validator_info = vector::borrow_mut(&mut validator_set.active_validators, i);
            let pool_address = old_validator_info.addr;
            let validator_config = borrow_global<ValidatorConfig>(pool_address);
            let stake_pool = borrow_global<StakePool>(pool_address);
            let new_validator_info = generate_validator_info(pool_address, stake_pool, *validator_config);

            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
            };
            i = i + 1;
        };

        validator_set.active_validators = next_epoch_validators;
```

**File:** consensus/src/epoch_manager.rs (L292-299)
```rust
        let proposers = epoch_state
            .verifier
            .get_ordered_account_addresses_iter()
            .collect::<Vec<_>>();
        match &onchain_config.proposer_election_type() {
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
            },
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

**File:** consensus/src/round_manager.rs (L428-430)
```rust
        let prev_proposer = self
            .proposer_election
            .get_valid_proposer(new_round.saturating_sub(1));
```

**File:** consensus/src/round_manager.rs (L1082-1084)
```rust
            warn!(
                round = round,
                remote_peer = self.proposer_election.get_valid_proposer(round),
```

**File:** consensus/src/liveness/proposal_generator.rs (L897-899)
```rust
        for i in start..end_round {
            failed_authors.push((i, proposer_election.get_valid_proposer(i)));
        }
```
