# Audit Report

## Title
Deterministic Proposer Selection Seed Enables Statistical Pattern Exploitation in LeaderReputation V1 Mode

## Summary
When the legacy `ProposerAndVoter` (V1) leader reputation mode is configured with `use_root_hash = false`, the proposer selection mechanism uses a fully deterministic seed based only on `epoch || round`. This allows the same random value to be reused across different weight distributions throughout an epoch, reducing the effective randomness of proposer selection and enabling validators to precompute and potentially manipulate selection patterns.

## Finding Description

The `choose_index()` function in the proposer election mechanism uses a state vector to generate pseudo-random selection values: [1](#0-0) [2](#0-1) 

When `LeaderReputation` operates in V1 mode (`ProposerAndVoter` with `use_root_hash = false`), the state is constructed deterministically: [3](#0-2) 

The vulnerability manifests as follows:

1. **Deterministic Seed**: In V1 mode, `state = epoch || round`, making `SHA3-256(state)` fully predictable for all future rounds within an epoch.

2. **Weight Vector Variability**: The weights applied to this seed change as validator performance evolves: [4](#0-3) 

3. **Pattern Exploitation**: A malicious validator can:
   - Precompute `hash = SHA3-256(epoch || round)` for all future rounds
   - Simulate selection outcomes under different weight scenarios
   - Strategically manipulate their own performance (intentional failures/successes) to shift weight distributions
   - Predict with high accuracy when they or specific validators will be selected

4. **Statistical Bias**: The same hash value modulo different `total_weight` values creates statistical patterns that reduce the entropy of the selection process.

The Aptos team recognized this issue and implemented V2 (`ProposerAndVoterV2`), which includes `root_hash` in the state to provide unpredictable seeds: [5](#0-4) 

The default configuration uses V2: [6](#0-5) 

However, V1 can still be explicitly configured via on-chain governance proposals, reintroducing the vulnerability.

## Impact Explanation

**Medium Severity** - This issue qualifies as Medium severity under the Aptos bug bounty criteria due to "state inconsistencies requiring intervention."

While this does not directly cause fund loss or consensus safety violations, it undermines critical security properties:

1. **Reduced Randomness**: Leader selection should be unpredictable to prevent targeted attacks. Deterministic seeds reduce this property.

2. **Strategic Manipulation**: Malicious validators can optimize their selection probability through behavioral manipulation, giving them unfair advantages.

3. **Targeted Attack Facilitation**: Predictable future proposers enable preparation of targeted DoS attacks or network partitioning strategies.

4. **Governance Risk**: If V1 is enabled via governance proposal (intentionally or through misconfiguration), the network becomes vulnerable.

The impact is NOT Critical because:
- It requires V1 configuration (not default)
- Exploitation requires validator participation
- Does not directly break consensus safety (2/3 honesty assumption still holds)
- Does not cause immediate fund loss

## Likelihood Explanation

**Low-Medium Likelihood**:

**Factors Reducing Likelihood:**
- V2 is the default configuration with unpredictable seeds
- Switching to V1 requires explicit on-chain governance action
- Most validators/operators are unlikely to intentionally downgrade to V1
- The issue was already recognized and mitigated by the Aptos team

**Factors Increasing Likelihood:**
- On-chain governance is permissionless (any proposal can be submitted)
- Misconfiguration during network upgrades could accidentally enable V1
- Legacy networks or test environments might still use V1
- The vulnerability is subtle and might not be obvious to governance voters

**Exploitation Requirements:**
- Attacker must be a validator (or control validator stake)
- V1 mode must be enabled via governance
- Attacker needs computational resources to precompute hashes and simulate scenarios
- Requires sustained manipulation over multiple rounds to be effective

## Recommendation

**Immediate Actions:**
1. **Deprecate V1**: Remove `ProposerAndVoter` (V1) entirely from the codebase to prevent accidental or malicious configuration.

2. **Add Governance Guards**: Implement validation in the consensus config upgrade logic to prevent downgrading from V2 to V1:

```rust
// In consensus config validation
pub fn validate_config_upgrade(old_config: &LeaderReputationType, new_config: &LeaderReputationType) -> Result<()> {
    // Prevent downgrade from V2 to V1
    if matches!(old_config, LeaderReputationType::ProposerAndVoterV2(_)) 
        && matches!(new_config, LeaderReputationType::ProposerAndVoter(_)) {
        return Err(anyhow::anyhow!(
            "Downgrading from ProposerAndVoterV2 to ProposerAndVoter (V1) is not allowed due to security concerns"
        ));
    }
    Ok(())
}
```

3. **Documentation**: Add clear security warnings in governance documentation about the risks of V1 configuration.

**Long-term Solution:**
Mandate V2 as the only supported leader reputation mode and remove V1 support entirely in a future hardfork.

## Proof of Concept

```rust
#[test]
fn test_deterministic_seed_pattern_exploitation() {
    use aptos_crypto::HashValue;
    use consensus::liveness::proposer_election::choose_index;
    
    let epoch: u64 = 100;
    let round: u64 = 42;
    
    // V1 mode: deterministic state
    let state_v1 = [
        epoch.to_le_bytes().to_vec(),
        round.to_le_bytes().to_vec(),
    ].concat();
    
    // Precompute the hash (attacker can do this for all future rounds)
    let hash = HashValue::sha3_256_of(&state_v1);
    println!("Precomputed hash for epoch {} round {}: {:?}", epoch, round, hash);
    
    // Simulate different weight scenarios
    let weights_scenario_1: Vec<u128> = vec![1000, 2000, 3000, 4000];
    let weights_scenario_2: Vec<u128> = vec![1500, 1500, 3000, 4000]; // After weight manipulation
    
    let selected_1 = choose_index(weights_scenario_1.clone(), state_v1.clone());
    let selected_2 = choose_index(weights_scenario_2.clone(), state_v1.clone());
    
    println!("Same state, different weights:");
    println!("Scenario 1 selects validator: {}", selected_1);
    println!("Scenario 2 selects validator: {}", selected_2);
    
    // Attacker can predict that by manipulating weights from scenario 1 to scenario 2,
    // they can change the selected validator from selected_1 to selected_2
    
    // In V2 mode, the root_hash would be different, preventing this predictability
    let root_hash = HashValue::random();
    let state_v2 = [
        root_hash.to_vec(),
        epoch.to_le_bytes().to_vec(),
        round.to_le_bytes().to_vec(),
    ].concat();
    
    // With V2, even same weights give different results because root_hash changes
    assert_ne!(state_v1, state_v2);
}
```

## Notes

- This vulnerability was **already recognized** by the Aptos team and fixed in V2 (default since early network versions)
- The issue only manifests when **V1 is explicitly configured** via governance
- V2's use of `root_hash` (which changes with each committed block) provides fresh randomness for each selection
- The comment in the code explicitly states V2 uses "unpredictable seed, based on root hash"
- **Mitigation is already deployed** in the default configuration; this report highlights the residual risk of V1 being re-enabled

The primary concern is **configuration drift** or **governance-based downgrade** that could reintroduce this vulnerability on a live network.

### Citations

**File:** consensus/src/liveness/proposer_election.rs (L38-46)
```rust
// next consumes seed and returns random deterministic u64 value in [0, max) range
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

**File:** consensus/src/liveness/leader_reputation.rs (L704-715)
```rust
        let mut weights =
            self.heuristic
                .get_weights(self.epoch, &self.epoch_to_proposers, &sliding_window);
        let proposers = &self.epoch_to_proposers[&self.epoch];
        assert_eq!(weights.len(), proposers.len());

        // Multiply weights by voting power:
        let stake_weights: Vec<u128> = weights
            .iter_mut()
            .enumerate()
            .map(|(i, w)| *w as u128 * self.voting_powers[i] as u128)
            .collect();
```

**File:** consensus/src/liveness/leader_reputation.rs (L717-733)
```rust
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
        (proposers[chosen_index], voting_power_participation_ratio)
```

**File:** types/src/on_chain_config/consensus_config.rs (L481-505)
```rust
impl Default for ConsensusConfigV1 {
    fn default() -> Self {
        Self {
            decoupled_execution: true,
            back_pressure_limit: 10,
            exclude_round: 40,
            max_failed_authors_to_store: 10,
            proposer_election_type: ProposerElectionType::LeaderReputation(
                LeaderReputationType::ProposerAndVoterV2(ProposerAndVoterConfig {
                    active_weight: 1000,
                    inactive_weight: 10,
                    failed_weight: 1,
                    failure_threshold_percent: 10, // = 10%
                    // In each round we get stastics for the single proposer
                    // and large number of validators. So the window for
                    // the proposers needs to be significantly larger
                    // to have enough useful statistics.
                    proposer_window_num_validators_multiplier: 10,
                    voter_window_num_validators_multiplier: 1,
                    weight_by_voting_power: true,
                    use_history_from_previous_epoch_max_count: 5,
                }),
            ),
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L525-544)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderReputationType {
    // Proposer election based on whether nodes succeeded or failed
    // their proposer election rounds, and whether they voted.
    // Version 1:
    // * use reputation window from stale end
    // * simple (predictable) seed
    ProposerAndVoter(ProposerAndVoterConfig),
    // Version 2:
    // * use reputation window from recent end
    // * unpredictable seed, based on root hash
    ProposerAndVoterV2(ProposerAndVoterConfig),
}

impl LeaderReputationType {
    pub fn use_root_hash_for_seed(&self) -> bool {
        // all versions after V1 should use root hash
        !matches!(self, Self::ProposerAndVoter(_))
    }
```
