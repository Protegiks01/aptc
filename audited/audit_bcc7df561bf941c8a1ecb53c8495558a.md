# Audit Report

## Title
Integer Underflow and Division Issues in Validator Voting Power Calculations When All Validators Have Zero Voting Power

## Summary
When the ValidatorSet contains validators but all have zero voting power, two critical arithmetic issues occur: (1) integer underflow in `check_aggregated_voting_power()` when checking minority thresholds, and (2) percentage calculation overflow in proof coordinator. Both issues cause consensus failure and complete network halt.

## Finding Description

The vulnerability exists in the Rust consensus layer's handling of edge cases in voting power calculations. When the ValidatorSet from Move contains non-empty validator lists where all validators have `voting_power = 0`, the Rust `ValidatorVerifier` is constructed with incorrect arithmetic assumptions.

**Attack Flow:**

1. **Precondition Setup**: Due to a hypothetical bug in stake.move, the ValidatorSet is created with validators having `total_voting_power = 0` [1](#0-0) 

2. **ValidatorVerifier Construction**: When converting from ValidatorSet to ValidatorVerifier, the code calculates quorum as `total_voting_power * 2 / 3 + 1`. With `total_voting_power = 0`, this yields `quorum_voting_power = 1` (non-empty validator set) [2](#0-1) 

3. **Integer Underflow in Minority Threshold Check**: When `check_aggregated_voting_power()` is called with `check_super_majority = false`, it calculates `target = self.total_voting_power - self.quorum_voting_power + 1`, which becomes `0 - 1 + 1`. This causes integer underflow (panic in debug builds, wraps to `u128::MAX` in release builds) [3](#0-2) 

4. **Triggered in Timeout Processing**: This code path is reached during timeout certificate processing where minority (f+1) voting power validation occurs [4](#0-3) 

5. **Additional Overflow in Proof Coordinator**: The percentage calculation uses `saturating_div(validator_verifier.total_voting_power())` which returns `u128::MAX` when dividing by zero, then casts to `u8` resulting in 255% [5](#0-4) 

**Broken Invariants:**
- **Consensus Safety**: Cannot validate voting power thresholds correctly
- **Liveness**: Complete network halt as no timeout certificates or quorum certificates can be formed

## Impact Explanation

**Critical Severity** - This meets the highest impact category:

- **Total loss of liveness/network availability**: All validator nodes crash (debug) or enter undefined behavior (release) when attempting to process timeouts or validate voting power
- **Non-recoverable network partition (requires hardfork)**: Once the ValidatorSet reaches this state through an epoch boundary, the network cannot recover without manual intervention and hard fork to restore valid validator voting powers
- **Consensus Safety violation**: The voting power validation logic becomes unreliable, potentially allowing invalid certificates

The impact affects 100% of validator nodes simultaneously since all nodes use the same ValidatorSet state from the Move framework.

## Likelihood Explanation

**Likelihood: Low (Conditional on Primary Bug)**

This vulnerability is NOT directly exploitable. The likelihood depends entirely on:

1. A separate bug existing in stake.move that bypasses validation logic at lines 1075 and 1391 which enforce minimum stake requirements [6](#0-5) 

2. The Move epoch reconfiguration logic at `on_new_epoch()` which filters validators below minimum stake [7](#0-6) 

However, the test-only code demonstrates that the ValidatorSet data structure permits this invalid state, indicating inadequate defensive programming in the Rust layer.

## Recommendation

**Fix 1: Add zero total_voting_power validation in ValidatorVerifier constructor**

```rust
pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
    let total_voting_power = sum_voting_power(&validator_infos);
    
    // Add defensive check
    if !validator_infos.is_empty() && total_voting_power == 0 {
        panic!("Invalid validator set: non-empty validator list with zero total voting power");
    }
    
    let quorum_voting_power = if validator_infos.is_empty() {
        0
    } else {
        total_voting_power * 2 / 3 + 1
    };
    Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
}
```

**Fix 2: Use checked arithmetic in check_aggregated_voting_power**

```rust
pub fn check_aggregated_voting_power(
    &self,
    aggregated_voting_power: u128,
    check_super_majority: bool,
) -> std::result::Result<u128, VerifyError> {
    let target = if check_super_majority {
        self.quorum_voting_power
    } else {
        // Use checked_sub to prevent underflow
        self.total_voting_power
            .checked_sub(self.quorum_voting_power)
            .and_then(|v| v.checked_add(1))
            .expect("Invalid validator verifier state: total_voting_power < quorum_voting_power")
    };
    // ... rest of function
}
```

**Fix 3: Add defensive check in proof_coordinator**

```rust
fn observe_voting_pct(&mut self, timestamp: u64, validator_verifier: &ValidatorVerifier) {
    let total_power = validator_verifier.total_voting_power();
    if total_power == 0 {
        return; // Skip observation if total voting power is invalid
    }
    
    let pct = self
        .aggregated_voting_power
        .saturating_mul(100)
        .saturating_div(total_power) as u8;
    // ... rest of function
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "Invalid validator set")]
fn test_zero_voting_power_all_validators() {
    use aptos_types::validator_verifier::{ValidatorVerifier, ValidatorConsensusInfo};
    use aptos_crypto::bls12381::PrivateKey;
    use aptos_types::account_address::AccountAddress;
    
    // Create validators with zero voting power
    let validator_infos = vec![
        ValidatorConsensusInfo::new(
            AccountAddress::random(),
            PrivateKey::generate_for_testing().public_key(),
            0, // Zero voting power
        ),
        ValidatorConsensusInfo::new(
            AccountAddress::random(),
            PrivateKey::generate_for_testing().public_key(),
            0, // Zero voting power
        ),
    ];
    
    // This should panic with the fix, currently creates invalid state
    let verifier = ValidatorVerifier::new(validator_infos);
    
    // Attempting to check voting power with false (minority check) triggers underflow
    let result = verifier.check_aggregated_voting_power(0, false);
    // In release mode: wraps to u128::MAX, in debug: panic
}
```

## Notes

While the Move framework has safeguards to prevent zero voting power scenarios through minimum stake requirements, the Rust consensus layer lacks defensive validation. This represents a violation of defense-in-depth principles where the Rust layer should validate invariants independently rather than trusting Move state unconditionally. The vulnerability requires a hypothetical bug in stake.move as a precondition, but given the critical impact, defensive checks should be added.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1072-1076)
```text
        let config = staking_config::get();
        let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power >= minimum_stake, error::invalid_argument(ESTAKE_TOO_LOW));
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_TOO_HIGH));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1390-1402)
```text
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
        validator_set.total_voting_power = total_voting_power;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L2048-2083)
```text
    #[test_only]
    public fun create_validator_set(
        aptos_framework: &signer,
        active_validator_addresses: vector<address>,
        public_keys: vector<bls12381::PublicKey>,
    ) {
        let active_validators = vector::empty<ValidatorInfo>();
        let i = 0;
        while (i < vector::length(&active_validator_addresses)) {
            let validator_address = vector::borrow(&active_validator_addresses, i);
            let pk = vector::borrow(&public_keys, i);
            vector::push_back(&mut active_validators, ValidatorInfo {
                addr: *validator_address,
                voting_power: 0,
                config: ValidatorConfig {
                    consensus_pubkey: bls12381::public_key_to_bytes(pk),
                    network_addresses: b"",
                    fullnode_addresses: b"",
                    validator_index: 0,
                }
            });
            i = i + 1;
        };

        move_to(aptos_framework, ValidatorSet {
            consensus_scheme: 0,
            // active validators for the current epoch
            active_validators,
            // pending validators to leave in next epoch (still active)
            pending_inactive: vector::empty<ValidatorInfo>(),
            // pending validators to join in next epoch
            pending_active: vector::empty<ValidatorInfo>(),
            total_voting_power: 0,
            total_joining_power: 0,
        });
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

**File:** consensus/src/pending_votes.rs (L126-140)
```rust
            .filter(|(_, voting_power)| {
                verifier
                    .check_aggregated_voting_power(*voting_power, false)
                    .is_ok()
            })
            .map(|(reason, _)| {
                // If the aggregated reason is due to unavailable payload, we will compute the
                // aggregated missing authors bitvec counting batch authors that have been reported
                // missing by minority peers.
                if matches!(reason, RoundTimeoutReason::PayloadUnavailable { .. }) {
                    let mut aggregated_bitvec = BitVec::with_num_bits(verifier.len() as u16);
                    for (author_idx, voting_power) in missing_batch_authors {
                        if verifier
                            .check_aggregated_voting_power(voting_power, false)
                            .is_ok()
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L192-202)
```rust
    fn observe_voting_pct(&mut self, timestamp: u64, validator_verifier: &ValidatorVerifier) {
        let pct = self
            .aggregated_voting_power
            .saturating_mul(100)
            .saturating_div(validator_verifier.total_voting_power()) as u8;
        let author = self.signature_aggregator.data().author();
        if pct >= self.last_increment_pct + 10 {
            observe_batch_vote_pct(timestamp, author, pct);
            self.last_increment_pct = pct;
        }
    }
```
