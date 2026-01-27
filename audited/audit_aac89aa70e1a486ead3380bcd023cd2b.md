# Audit Report

## Title
Division by Zero Panic in Proposer Election Causes Total Network Halt When All Validators Drop Below Minimum Stake

## Summary
A division by zero panic in `next_in_range()` function can halt all consensus validators if the active validator set becomes empty during epoch transition. This occurs when `on_new_epoch()` filters out all validators that fall below `minimum_stake` without checking that at least one validator remains, resulting in total network liveness failure requiring a hardfork to recover.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Unsafe Division Operation**

The `next_in_range()` function performs a modulo operation without checking for zero: [1](#0-0) 

When `max` is 0, the expression `u128::from_le_bytes(temp) % max` causes a **division by zero panic** in Rust.

**2. Missing Empty Validator Set Check**

The `choose_index()` function calls `next_in_range()` with `total_weight` which becomes 0 when the weights vector is empty: [2](#0-1) 

**3. No Minimum Validator Guarantee in Epoch Transition**

The root cause is in `stake.move::on_new_epoch()` which filters validators by minimum stake without ensuring at least one remains: [3](#0-2) 

The code creates an empty `next_epoch_validators` vector if all validators have `voting_power < minimum_stake`, then assigns it directly to `validator_set.active_validators` without validation.

**4. Propagation to Consensus**

Empty validator sets are explicitly supported: [4](#0-3) [5](#0-4) 

When consensus receives the empty validator set, it creates empty `proposers` and `stake_weights` lists: [6](#0-5) [7](#0-6) 

**Attack Scenarios:**

1. **Governance Attack**: Governance proposal raises `minimum_stake` above all current validators' voting power
2. **Mass Slashing**: Multiple validators get slashed simultaneously, dropping all below minimum stake
3. **Coordinated Withdrawal**: Validators withdraw stake en masse during same epoch
4. **Configuration Error**: Accidental misconfiguration during network upgrade

**Exploitation Path:**

1. Trigger condition where all validators have `voting_power < minimum_stake`
2. `on_new_epoch()` executes at epoch boundary
3. All validators filtered out, `next_epoch_validators = []`
4. Empty validator set written to storage and broadcast
5. Consensus nodes receive new epoch with empty validator set
6. Any attempt to elect proposer calls `choose_index([], state)`
7. `total_weight = 0`, calls `next_in_range(state, 0)`
8. **PANIC**: Division by zero at modulo operation
9. All validator nodes crash simultaneously
10. Network halts completely - no blocks can be proposed or voted on

**Broken Invariants:**
- **Consensus Liveness**: Network cannot make progress (Critical Invariant #2)
- **Deterministic Execution**: Panic is non-deterministic recovery path (Critical Invariant #1)

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This qualifies as **"Total loss of liveness/network availability"** and **"Non-recoverable network partition (requires hardfork)"** for the following reasons:

1. **Complete Network Halt**: All consensus validators crash simultaneously when attempting to elect a proposer
2. **No Automatic Recovery**: The panic occurs deterministically on every restart attempt with the same epoch state
3. **Requires Hardfork**: Recovery requires either:
   - Manual binary patch to bypass the panic
   - Emergency hardfork to restore at least one validator with sufficient stake
   - State rollback to before the problematic epoch
4. **Affects All Nodes**: Every validator running standard Aptos Core software crashes
5. **Permanent Until Fixed**: Unlike transient failures, this persists until manual intervention

The existing `ELAST_VALIDATOR` check only protects against explicit `leave_validator_set` operations: [8](#0-7) 

But provides **no protection** against implicit filtering in `on_new_epoch()`.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

While not trivial to trigger accidentally, this vulnerability has realistic paths:

**High Probability Scenarios:**
1. **Governance Misconfiguration**: Well-intentioned proposal to "strengthen network security" by raising minimum stake could accidentally exceed all validators
2. **Cascading Slashing Event**: Multiple validators experiencing correlated failures in same epoch (network partition, cloud provider outage)
3. **Economic Attack**: Attacker with governance influence could deliberately propose malicious `minimum_stake` increase

**Factors Increasing Likelihood:**
- Governance proposals are routine operations
- No safety checks in Move code prevent this scenario
- Staking config changes don't require unanimous validator consent
- Natural market dynamics could reduce validator stakes simultaneously

**Factors Decreasing Likelihood:**
- Requires governance participation or significant slashing
- Validators typically maintain stake buffers above minimum
- Large stake changes trigger community review

The vulnerability is **exploitable without validator collusion** - a single governance proposal or correlated slashing event suffices.

## Recommendation

Implement multiple layers of defense:

**1. Add Minimum Validator Check in Move (Primary Defense)**

In `stake.move::on_new_epoch()`, add assertion before updating validator set:

```move
// After line 1401
assert!(
    vector::length(&next_epoch_validators) > 0,
    error::invalid_state(EVALIDATOR_SET_EMPTY)
);
validator_set.active_validators = next_epoch_validators;
```

Add new error constant:
```move
const EVALIDATOR_SET_EMPTY: u64 = 13;
```

**2. Add Zero Check in Rust (Defense in Depth)**

In `consensus/src/liveness/proposer_election.rs::next_in_range()`:

```rust
fn next_in_range(state: Vec<u8>, max: u128) -> u128 {
    assert!(max > 0, "next_in_range called with max=0");
    let hash = aptos_crypto::HashValue::sha3_256_of(&state).to_vec();
    let mut temp = [0u8; 16];
    copy_slice_to_vec(&hash[..16], &mut temp).expect("next failed");
    u128::from_le_bytes(temp) % max
}
```

**3. Add Validator Count Check at Epoch Boundary**

In `consensus/src/epoch_manager.rs`, validate before creating proposer election:

```rust
let proposers = epoch_state
    .verifier
    .get_ordered_account_addresses_iter()
    .collect::<Vec<_>>();
    
ensure!(
    !proposers.is_empty(),
    "Cannot start epoch with empty validator set"
);
```

**4. Add Governance Safeguard**

In `staking_config.move`, validate that proposed `minimum_stake` won't eliminate all validators:

```move
public fun validate_required_stake(
    minimum_stake: u64,
    validator_set: &ValidatorSet
): bool {
    let active_count = 0;
    // Count validators that would remain above new minimum
    // Return false if none would remain
}
```

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, validator_1 = @0x123, validator_2 = @0x456)]
public entry fun test_empty_validator_set_panic(
    aptos_framework: &signer,
    validator_1: &signer,
    validator_2: &signer,
) {
    // Setup: Initialize chain with 2 validators having minimum stake
    stake::initialize_for_test(aptos_framework);
    
    // Register validators with exactly minimum_stake (e.g., 1,000,000 APT)
    stake::register_validator_candidate(
        validator_1,
        /* consensus_pubkey */ x"...",
        /* network_addresses */ x"...",
        /* fullnode_addresses */ x"...",
    );
    stake::add_stake(validator_1, 1_000_000);
    stake::join_validator_set(validator_1);
    
    stake::register_validator_candidate(
        validator_2,
        /* consensus_pubkey */ x"...",
        /* network_addresses */ x"...",
        /* fullnode_addresses */ x"...",
    );
    stake::add_stake(validator_2, 1_000_000);
    stake::join_validator_set(validator_2);
    
    // Advance to epoch boundary
    stake::end_epoch();
    
    // Attack: Governance raises minimum_stake above all validators
    staking_config::update_required_stake(
        aptos_framework,
        /* minimum_stake */ 2_000_000,  // Higher than both validators
        /* maximum_stake */ 100_000_000,
    );
    
    // Trigger epoch transition - this causes on_new_epoch()
    // Expected: All validators filtered out, validator_set becomes empty
    stake::on_new_epoch();
    
    let validator_set = borrow_global<ValidatorSet>(@aptos_framework);
    assert!(vector::length(&validator_set.active_validators) == 0, 1);
    
    // When consensus tries to elect proposer with this empty set:
    // -> Calls choose_index([], state)
    // -> total_weight = 0
    // -> next_in_range(state, 0)
    // -> u128::from_le_bytes(temp) % 0
    // -> PANIC: Division by zero
    
    // Result: All consensus nodes crash, network halts permanently
}
```

**Note**: The actual panic occurs in Rust consensus code when processing the empty validator set, not in the Move test itself. The Move test demonstrates the precondition (empty validator set creation) that triggers the Rust panic during normal consensus operation.

---

**Notes**

This vulnerability represents a critical gap in the defense-in-depth approach. While `ELAST_VALIDATOR` prevents explicit removals, the implicit filtering in `on_new_epoch()` has no equivalent protection. The Rust-level panic is a consequence of trusting that the Move layer enforces validator set non-emptiness, but this invariant is not actually enforced. Recovery requires emergency intervention since standard node restart will repeatedly hit the same panic condition.

### Citations

**File:** consensus/src/liveness/proposer_election.rs (L39-46)
```rust
fn next_in_range(state: Vec<u8>, max: u128) -> u128 {
    // hash = SHA-3-256(state)
    let hash = aptos_crypto::HashValue::sha3_256_of(&state).to_vec();
    let mut temp = [0u8; 16];
    copy_slice_to_vec(&hash[..16], &mut temp).expect("next failed");
    // return hash[0..16]
    u128::from_le_bytes(temp) % max
}
```

**File:** consensus/src/liveness/proposer_election.rs (L49-69)
```rust
pub(crate) fn choose_index(mut weights: Vec<u128>, state: Vec<u8>) -> usize {
    let mut total_weight = 0;
    // Create cumulative weights vector
    // Since we own the vector, we can safely modify it in place
    for w in &mut weights {
        total_weight = total_weight
            .checked_add(w)
            .expect("Total stake shouldn't exceed u128::MAX");
        *w = total_weight;
    }
    let chosen_weight = next_in_range(state, total_weight);
    weights
        .binary_search_by(|w| {
            if *w <= chosen_weight {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        })
        .expect_err("Comparison never returns equals, so it's always guaranteed to be error")
}
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1253-1256)
```text
            let validator_info = vector::swap_remove(
                &mut validator_set.active_validators, option::extract(&mut maybe_active_index));
            assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
            vector::push_back(&mut validator_set.pending_inactive, validator_info);
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

**File:** types/src/epoch_state.rs (L32-37)
```rust
    pub fn empty() -> Self {
        Self {
            epoch: 0,
            verifier: Arc::new(ValidatorVerifier::new(vec![])),
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L347-359)
```rust
                let voting_powers: Vec<_> = if weight_by_voting_power {
                    proposers
                        .iter()
                        .map(|p| {
                            epoch_state
                                .verifier
                                .get_voting_power(p)
                                .expect("INVARIANT VIOLATION: proposer not in verifier set")
                        })
                        .collect()
                } else {
                    vec![1; proposers.len()]
                };
```

**File:** consensus/src/liveness/leader_reputation.rs (L710-732)
```rust
        // Multiply weights by voting power:
        let stake_weights: Vec<u128> = weights
            .iter_mut()
            .enumerate()
            .map(|(i, w)| *w as u128 * self.voting_powers[i] as u128)
            .collect();

        let state = if self.use_root_hash {
            [
                root_hash.to_vec(),
                self.epoch.to_le_bytes().to_vec(),
                round.to_le_bytes().to_vec(),
            ]
            .concat()
        } else {
            [
                self.epoch.to_le_bytes().to_vec(),
                round.to_le_bytes().to_vec(),
            ]
            .concat()
        };

        let chosen_index = choose_index(stake_weights, state);
```
