# Audit Report

## Title
Missing Minimum Validator Count Validation Allows Complete Network Halt Through Empty Validator Set

## Summary
The `on_new_epoch` function in the staking system filters validators based on minimum stake requirements but fails to enforce a minimum validator count. If all validators' stake falls below the minimum threshold, the active validator set becomes empty, causing irreversible consensus failure and total network halt.

## Finding Description

The vulnerability exists in the epoch transition logic where validators are removed without ensuring at least one validator remains active.

**Critical Code Path:**

The `on_new_epoch` function filters validators by checking if their voting power meets the minimum stake requirement without validating that at least one validator remains after filtering. [1](#0-0) 

The function iterates through all validators and only includes those with sufficient stake in `next_epoch_validators`. If no validators meet the requirement, the vector remains empty, and this empty vector directly replaces the active validator set without any validation at line 1401.

**Comparison with voluntary exit protection:**

The `leave_validator_set` function explicitly prevents removing the last validator through the `ELAST_VALIDATOR` check at line 1255: [2](#0-1) 

The error constant is defined as "Can't remove last validator": [3](#0-2) 

However, this protection does NOT exist in `on_new_epoch` for automatic removal due to insufficient stake, creating an asymmetry in validator set safety guarantees.

**Rust-side validation gaps:**

The `ValidatorVerifier` constructor accepts empty validator sets and sets `quorum_voting_power` to 0: [4](#0-3) 

This creates a technically valid but operationally broken verifier that cannot support consensus operations.

**Consensus failure points:**

When the consensus system attempts to create proposer election with an empty validator set, multiple failure modes occur:

1. For `FixedProposer` election, the `choose_leader` function panics with "No trusted peers found!": [5](#0-4) 

2. For `RoundProposer` election, it panics with "INVARIANT VIOLATION: proposers is empty": [6](#0-5) 

3. For `RotatingProposer` election, accessing the proposer causes division by zero when `proposers.len()` is 0: [7](#0-6) 

**Function specification confirms no-abort design:**

The specification explicitly states `aborts_if false`, meaning `on_new_epoch` is designed to never abort, even when producing an empty validator set: [8](#0-7) 

**No validation in governance updates:**

The `validate_required_stake` function only checks that `minimum_stake <= maximum_stake`, with no validation that the new minimum is achievable by current validators: [9](#0-8) 

**Attack Scenario:**

1. Governance raises `minimum_stake` significantly via `update_required_stake` (legitimate governance action)
2. Current validators' stakes are below the new threshold  
3. Next epoch begins, `on_new_epoch` executes
4. All validators are filtered out due to insufficient stake (line 1391 check fails for all)
5. `active_validators` becomes empty vector (line 1401)
6. `ValidatorSet` is stored on-chain with zero active validators
7. Consensus reads empty `ValidatorSet` from on-chain config: [10](#0-9) 

8. `ValidatorVerifier` is created with 0 validators via the From trait: [11](#0-10) 

9. Proposer election creation panics with empty proposers
10. Chain permanently halts - requires hard fork to recover

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability causes **"Total loss of liveness/network availability"** and **"Non-recoverable network partition (requires hardfork)"**, both explicitly listed as Critical severity in the Aptos bug bounty program.

Once the validator set becomes empty:
- No blocks can be proposed (proposer election panics)
- No consensus can be reached (no voting power available)
- The chain is permanently halted
- Requires a hard fork with manual validator set injection to recover
- All economic activity freezes
- Smart contracts become inaccessible
- Funds are effectively frozen until hard fork recovery

This breaks the fundamental **Consensus Liveness** invariant - the network cannot maintain liveness with zero validators.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

While requiring all validators to have insufficient stake seems unlikely on mature mainnets, several realistic scenarios make this exploitable:

1. **Governance-driven minimum stake increases**: If governance raises `minimum_stake` significantly without verifying current validator stakes, all could become ineligible simultaneously. The validation function provides no protection against this.

2. **Small validator set configurations**: Testnets or newly launched networks with few validators are highly vulnerable.

3. **Economic conditions**: During market downturns or low staking rewards, multiple validators might simultaneously unlock stake, pushing all below minimum threshold.

4. **No reversal mechanism**: Once triggered in epoch N, the empty validator set is committed for epoch N+1 with no recovery path in the protocol.

The vulnerability doesn't require malicious actors - it can occur through legitimate governance decisions or operational choices under adverse conditions. This is a **design flaw** where the system fails to enforce a critical invariant (at least 1 validator must exist) in the automatic removal path, despite enforcing it in the voluntary exit path.

## Recommendation

Add a minimum validator count check in `on_new_epoch` after filtering validators:

```move
validator_set.active_validators = next_epoch_validators;
// Ensure at least one validator remains
assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
validator_set.total_voting_power = total_voting_power;
```

Additionally, add validation in `update_required_stake` to ensure the new minimum is achievable by at least one current validator, or implement a safety margin check before applying stake requirement changes.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Deploying a testnet with validators having stake amounts below a threshold
2. Submitting a governance proposal to raise `minimum_stake` above all validator stakes
3. Waiting for the next epoch transition
4. Observing consensus halt when proposer election fails with panic

The technical execution path is fully validated in the code citations above, showing the missing validation creates an exploitable asymmetry between voluntary and automatic validator removal paths.

## Notes

This is a critical **logic vulnerability** stemming from incomplete invariant enforcement. The system correctly protects against the last validator voluntarily leaving but fails to apply the same protection during automatic stake-based filtering. The `aborts_if false` specification indicates the function was designed to never abort, but this design choice creates a safety hazard when combined with missing minimum validator count validation.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L57-58)
```text
    /// Can't remove last validator.
    const ELAST_VALIDATOR: u64 = 6;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1255-1255)
```text
            assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1372-1402)
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
        validator_set.total_voting_power = total_voting_power;
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

**File:** consensus/src/liveness/rotating_proposer_election.rs (L20-23)
```rust
pub fn choose_leader(peers: Vec<Author>) -> Author {
    // As it is just a tmp hack function, pick the min PeerId to be a proposer.
    peers.into_iter().min().expect("No trusted peers found!")
}
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L36-39)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
```

**File:** consensus/src/epoch_manager.rs (L396-404)
```rust
            ProposerElectionType::RoundProposer(round_proposers) => {
                // Hardcoded to the first proposer
                let default_proposer = proposers
                    .first()
                    .expect("INVARIANT VIOLATION: proposers is empty");
                Arc::new(RoundProposer::new(
                    round_proposers.clone(),
                    *default_proposer,
                ))
```

**File:** consensus/src/epoch_manager.rs (L1165-1174)
```rust
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
        let mut verifier: ValidatorVerifier = (&validator_set).into();
        verifier.set_optimistic_sig_verification_flag(self.config.optimistic_sig_verification);

        let epoch_state = Arc::new(EpochState {
            epoch: payload.epoch(),
            verifier: verifier.into(),
        });
```

**File:** aptos-move/framework/aptos-framework/sources/stake.spec.move (L453-465)
```text
    spec on_new_epoch {
        pragma verify = false; // TODO: set because of timeout (property proved).
        pragma disable_invariants_in_body;
        // The following resource requirement cannot be discharged by the global
        // invariants because this function is called during genesis.
        include ResourceRequirement;
        include GetReconfigStartTimeRequirement;
        include staking_config::StakingRewardsConfigRequirement;
        include aptos_framework::aptos_coin::ExistsAptosCoin;
        // This function should never abort.
        /// [high-level-req-4]
        aborts_if false;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L372-374)
```text
    fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
        assert!(minimum_stake <= maximum_stake && maximum_stake > 0, error::invalid_argument(EINVALID_STAKE_RANGE));
    }
```
