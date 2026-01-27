# Audit Report

## Title
Consensus Divergence Due to Silent Fallback on Database Errors in Leader Reputation

## Summary
When using reputation-based leader election with `use_root_hash` enabled, validators that fail to retrieve the accumulator root hash from their database silently fall back to `HashValue::zero()`, while validators with successful database reads use the actual root hash. This causes non-deterministic leader selection across validators, violating the consensus requirement that all honest validators must agree on the leader for each round.

## Finding Description

The vulnerability exists in the leader reputation mechanism used for consensus proposer election. [1](#0-0) 

When `use_root_hash` is true (ProposerAndVoterV2 configuration), the leader selection seed includes the transaction accumulator root hash. [2](#0-1) 

If `get_accumulator_root_hash()` fails on some validators (due to ledger pruning, database corruption, or temporary unavailability), those validators use `HashValue::zero()` as a silent fallback instead of propagating the error. Meanwhile, validators with successful database access use the actual root hash value.

The `get_accumulator_root_hash()` function checks if the requested version has been pruned. [3](#0-2)  Different validators can have different pruning policies, causing the error to occur non-deterministically across the validator set. [4](#0-3) 

**Attack Scenario:**
1. Validator A has aggressively pruned old data (high `min_readable_version`)
2. Validator B retains more historical data (lower `min_readable_version`)  
3. Leader reputation requests root hash for version V where `V < A.min_readable_version` but `V >= B.min_readable_version`
4. Validator A receives error, uses `HashValue::zero()`
5. Validator B successfully retrieves actual root hash
6. Both validators compute SHA3-256 hashes of their different seeds [5](#0-4) 
7. The `copy_slice_to_vec()` succeeds on both (32-byte hashes) but with different random values
8. Validators run `choose_index()` with different random seeds [6](#0-5) 
9. Validators elect **different leaders** for the same round
10. Consensus cannot reach agreement on which proposal to vote for

## Impact Explanation

**Severity: Critical** - This violates **Consensus Safety** (invariant #2) by causing validators to compute different leaders for the same round. 

When validators disagree on the leader:
- They vote for different blocks at the same round
- The network cannot form a quorum certificate 
- Consensus liveness fails completely
- If the validator set is split differently across rounds, it could lead to competing quorum certificates and potential safety violations

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and potentially "Total loss of liveness/network availability."

## Likelihood Explanation

**Likelihood: High**

This will occur whenever:
1. The network uses ProposerAndVoterV2 leader election (uses `use_root_hash=true`) [7](#0-6) 
2. Validators have different pruning configurations (common in production)
3. Leader reputation looks back at a version that some validators have pruned

Different pruning policies are legitimate operational choices. The likelihood increases as:
- The reputation window size increases
- Network transaction volume increases (filling storage faster)
- Validators with limited storage prune more aggressively

## Recommendation

Replace the silent fallback with explicit error propagation and fail-fast behavior:

```rust
let root_hash = self
    .aptos_db
    .get_accumulator_root_hash(max_version)
    .map_err(|e| {
        error!(
            "CRITICAL: Cannot retrieve accumulator hash for version {} (epoch {}, round {}). 
             This validator cannot safely participate in leader election: {:?}",
            max_version, target_epoch, target_round, e
        );
        e
    })?; // Propagate error instead of silent fallback

// Remove unwrap_or_else fallback to HashValue::zero()
```

Alternative solution: Ensure all validators maintain sufficient history for the reputation window by:
1. Setting minimum retention requirements based on reputation window size
2. Validating that `max_version` is always within the pruning retention window before querying
3. Using epoch-based checkpoints that all validators are guaranteed to have

## Proof of Concept

```rust
// Reproduction scenario (pseudocode for clarity)
// In consensus/src/liveness/leader_reputation_test.rs

#[test]
fn test_pruning_causes_leader_divergence() {
    let epoch = 1;
    let round = 100;
    
    // Validator A: Aggressive pruning, version 50 is min_readable
    let backend_a = MockBackendWithPruning::new(min_readable_version: 50);
    let leader_election_a = LeaderReputation::new(
        epoch,
        epoch_to_proposers,
        voting_powers,
        Arc::new(backend_a),
        heuristic,
        exclude_round: 1,
        use_root_hash: true, // ProposerAndVoterV2
        window_for_chain_health: 10,
    );
    
    // Validator B: Conservative pruning, version 10 is min_readable  
    let backend_b = MockBackendWithPruning::new(min_readable_version: 10);
    let leader_election_b = LeaderReputation::new(
        epoch,
        epoch_to_proposers,
        voting_powers,
        Arc::new(backend_b),
        heuristic,
        exclude_round: 1,
        use_root_hash: true,
        window_for_chain_health: 10,
    );
    
    // Request leader for round 100 (looks back at version 40)
    let leader_a = leader_election_a.get_valid_proposer(round);
    let leader_b = leader_election_b.get_valid_proposer(round);
    
    // VULNERABILITY: Different leaders elected!
    assert_ne!(leader_a, leader_b, "Validators diverged on leader selection");
}
```

## Notes

The `copy_slice_to_vec()` function itself [8](#0-7)  will not fail because SHA3-256 always produces 32-byte outputs. However, the vulnerability lies in the DATABASE ACCESS LAYER preceding this operation, where silent error handling causes validators to use different input seeds, leading to different (but both valid) 32-byte hash outputs that successfully pass through `copy_slice_to_vec()` but represent different random values for leader selection.

The root cause is not the fallible copy operation, but the inappropriate error recovery strategy in the database layer that masks consensus-critical failures.

### Citations

**File:** consensus/src/liveness/leader_reputation.rs (L153-162)
```rust
            let root_hash = self
                .aptos_db
                .get_accumulator_root_hash(max_version)
                .unwrap_or_else(|_| {
                    error!(
                        "We couldn't fetch accumulator hash for the {} version, for {} epoch, {} round",
                        max_version, target_epoch, target_round,
                    );
                    HashValue::zero()
                });
```

**File:** consensus/src/liveness/leader_reputation.rs (L717-730)
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
```

**File:** consensus/src/liveness/leader_reputation.rs (L732-733)
```rust
        let chosen_index = choose_index(stake_weights, state);
        (proposers[chosen_index], voting_power_participation_ratio)
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L832-838)
```rust
    fn get_accumulator_root_hash(&self, version: Version) -> Result<HashValue> {
        gauged_api("get_accumulator_root_hash", || {
            self.error_if_ledger_pruned("Transaction accumulator", version)?;
            self.ledger_db
                .transaction_accumulator_db()
                .get_root_hash(version)
        })
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-270)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
```

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

**File:** types/src/on_chain_config/consensus_config.rs (L541-544)
```rust
    pub fn use_root_hash_for_seed(&self) -> bool {
        // all versions after V1 should use root hash
        !matches!(self, Self::ProposerAndVoter(_))
    }
```

**File:** crates/fallible/src/copy_from_slice.rs (L7-18)
```rust
pub fn copy_slice_to_vec<T>(slice: &[T], vec: &mut [T]) -> Result<(), CopySliceError>
where
    T: Copy,
{
    if slice.len() != vec.len() {
        return Err(CopySliceError);
    }

    vec.copy_from_slice(slice);

    Ok(())
}
```
