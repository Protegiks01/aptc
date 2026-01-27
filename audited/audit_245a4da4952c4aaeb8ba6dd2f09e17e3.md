# Audit Report

## Title
Empty ValidatorSet Can Cause Network-Wide Consensus Halt via Missing Validation in Epoch Transition

## Summary
The `ValidatorSet::new()` function accepts an empty validator list without validation, and the `on_new_epoch()` function in stake.move filters validators by minimum stake without ensuring at least one remains. When converted to `ValidatorVerifier` during epoch changes, this causes consensus to panic when attempting to select a proposer, resulting in complete network halt.

## Finding Description
The vulnerability chain consists of multiple missing validations:

**1. Root Cause - Missing Input Validation:** [1](#0-0) 

The `new()` function creates a ValidatorSet without checking if the payload is empty.

**2. On-Chain Missing Validation:** [2](#0-1) 

During `on_new_epoch()`, validators are filtered by minimum stake into `next_epoch_validators`, which is then assigned to `active_validators` without validation that at least one validator remains.

**3. ValidatorVerifier Creation:** [3](#0-2) 

When an empty ValidatorSet is converted to ValidatorVerifier, it sets `quorum_voting_power = 0` and `total_voting_power = 0`.

**4. Consensus Epoch Initialization:** [4](#0-3) 

The epoch manager creates an EpochState with the empty ValidatorVerifier without validation.

**5. Proposer Election Panic:** [5](#0-4) 

When creating a RotatingProposer with an empty proposers list: [6](#0-5) 

The `get_valid_proposer()` method performs modulo by zero (`% self.proposers.len()` where len is 0), causing a panic.

Similarly for RoundProposer: [7](#0-6) 

This explicitly panics with "INVARIANT VIOLATION: proposers is empty".

**Attack Scenario:**
While this requires governance access or extraordinary economic conditions, it violates the critical invariant that validators must exist post-genesis: [8](#0-7) 

This invariant is only enforced at genesis, not during epoch changes.

## Impact Explanation
**Critical Severity** - Total loss of liveness/network availability:
- All validator nodes crash when attempting to start the new epoch
- Consensus halts permanently across the entire network
- Recovery requires a coordinated hard fork
- Meets Critical severity per bug bounty: "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)"

## Likelihood Explanation
**Low-Medium Likelihood:**
While the bug is real, exploitation requires either:
1. Governance proposal that raises minimum stake above all current validators' stakes
2. Economic conditions where all validators simultaneously fall below minimum stake threshold
3. Operational error during network upgrade/migration

The bug represents a safety gap rather than an easily exploitable attack vector by unprivileged actors.

## Recommendation
Add validation at multiple layers:

**1. In stake.move `on_new_epoch()`:**
```move
// After line 1401
validator_set.active_validators = next_epoch_validators;
assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
```

**2. In ValidatorSet::new():**
```rust
pub fn new(payload: Vec<ValidatorInfo>) -> Self {
    assert!(!payload.is_empty(), "ValidatorSet cannot be empty");
    Self {
        scheme: ConsensusScheme::BLS12381,
        active_validators: payload,
        pending_inactive: vec![],
        pending_active: vec![],
        total_voting_power: 0,
        total_joining_power: 0,
    }
}
```

**3. In EpochManager::start_new_epoch():**
```rust
let verifier: ValidatorVerifier = (&validator_set).into();
assert!(!verifier.is_empty(), "Cannot start epoch with zero validators");
```

## Proof of Concept
```move
#[test(aptos_framework = @0x1)]
fun test_empty_validator_set_halt(aptos_framework: &signer) {
    // Setup: Initialize stake with validators
    stake::initialize_for_test(aptos_framework);
    
    // Add validators with minimum stake
    let minimum_stake = 100000000; // 1 APT
    add_test_validators(aptos_framework, 3, minimum_stake);
    
    // Trigger: Raise minimum stake above all validators
    staking_config::update_required_stake(aptos_framework, minimum_stake * 10, minimum_stake * 100);
    
    // This should cause on_new_epoch to create empty active_validators
    stake::on_new_epoch();
    
    // Verify: active_validators is now empty (this would halt consensus)
    let validator_set = borrow_global<ValidatorSet>(@aptos_framework);
    assert!(vector::length(&validator_set.active_validators) == 0, 0);
    
    // In production, this would cause consensus panic when converting to ValidatorVerifier
}
```

**Notes:**
This vulnerability represents a critical safety gap in epoch transition logic. While exploitation requires governance power or unusual economic conditions rather than being trivially exploitable by unprivileged attackers, the complete absence of validation for the fundamental invariant "at least one validator must exist" represents a serious protocol-level flaw that could lead to irrecoverable network halt.

### Citations

**File:** types/src/on_chain_config/validator_set.rs (L46-55)
```rust
    pub fn new(payload: Vec<ValidatorInfo>) -> Self {
        Self {
            scheme: ConsensusScheme::BLS12381,
            active_validators: payload,
            pending_inactive: vec![],
            pending_active: vec![],
            total_voting_power: 0,
            total_joining_power: 0,
        }
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

**File:** consensus/src/epoch_manager.rs (L292-298)
```rust
        let proposers = epoch_state
            .verifier
            .get_ordered_account_addresses_iter()
            .collect::<Vec<_>>();
        match &onchain_config.proposer_election_type() {
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
```

**File:** consensus/src/epoch_manager.rs (L398-400)
```rust
                let default_proposer = proposers
                    .first()
                    .expect("INVARIANT VIOLATION: proposers is empty");
```

**File:** consensus/src/epoch_manager.rs (L1164-1174)
```rust
    async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) {
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

**File:** consensus/src/liveness/rotating_proposer_election.rs (L36-39)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.spec.move (L148-150)
```text
        // property 4: An initial set of validators should exist before the end of genesis.
        /// [high-level-req-4]
        requires len(global<stake::ValidatorSet>(@aptos_framework).active_validators) >= 1;
```
