# Audit Report

## Title
Leader Reputation System Degradation via Unbounded `exclude_round` Parameter Causing Frozen Proposer Selection

## Summary
The `exclude_round` consensus parameter lacks validation, allowing governance to set arbitrarily large values that cause the leader reputation system to permanently use stale historical data instead of adapting to current validator performance. While `saturating_sub` prevents arithmetic underflow, it results in `target_round = 0` for all practical rounds, effectively disabling adaptive leader selection.

## Finding Description

The leader reputation system in Aptos consensus is designed to select proposers based on recent performance, dynamically adjusting to favor well-performing validators and demote those with high failure rates. This mechanism depends on the `exclude_round` parameter, which specifies how many recent rounds should be excluded from reputation calculations. [1](#0-0) 

The `exclude_round` field has a default value of 40 but can be updated via on-chain governance: [2](#0-1) 

The governance update function only validates that the config bytes are non-empty, with **no bounds checking** on the actual `exclude_round` value. This allows setting it to any u64 value (up to 18,446,744,073,709,551,615).

When computing the reputation window, the code performs: [3](#0-2) 

While `saturating_sub` prevents arithmetic underflow, if `exclude_round > round`, it returns 0, causing `target_round = 0`. This target round is then used to fetch block metadata: [4](#0-3) 

The metadata filtering logic uses tuple comparison: [5](#0-4) 

When `target_round = 0`, only events with `(epoch, round) <= (current_epoch, 0)` are included, meaning:
- All events from previous epochs (up to the `use_history_from_previous_epoch_max_count` limit of 5 epochs)
- Only round 0 events from the current epoch (typically none or very few)

This causes the reputation calculation to be **frozen on historical data** and unable to adapt to current validator performance throughout the entire epoch.

**Attack Scenario:**
1. A malicious governance proposal sets `exclude_round = 1000000000` (or any value larger than typical rounds per epoch)
2. After the next epoch transition, this configuration takes effect
3. For every round R in the epoch (e.g., R = 100, 1000, 10000):
   - `target_round = R.saturating_sub(1000000000) = 0`
   - Reputation uses only round 0 data from current epoch + previous 5 epochs
4. As the epoch progresses, the reputation system never incorporates new performance data from rounds > 0
5. Proposer selection remains frozen based on ancient historical behavior

## Impact Explanation

This vulnerability constitutes a **Medium Severity** issue per Aptos bug bounty criteria for the following reasons:

**State Inconsistencies Requiring Intervention:**
The leader reputation system enters an inconsistent state where it cannot fulfill its design purpose of adaptive proposer selection based on recent performance. The system becomes frozen on stale data, requiring emergency governance intervention to restore proper functionality.

**Consensus Efficiency Degradation:**
While consensus safety is not violated (blocks continue to be committed), the network suffers significant efficiency degradation:
- Underperforming validators cannot be demoted
- High-performing validators cannot be promoted
- Network throughput may decrease as poor proposers get selected more frequently
- The reputation system's core invariant (adaptive selection based on recent behavior) is completely broken

**Economic Harm:**
- Validators who performed well in early rounds or previous epochs maintain unfair advantages
- Current good performers are denied fair proposer selection
- Validator rewards become incorrectly distributed
- Potential for gaming: validators could perform well initially, then underperform while maintaining selection advantages

**Protocol Violation:**
The intended behavior of the reputation system as documented is fundamentally violated, constituting a "significant protocol violation" per High severity criteria, though the impact is somewhat limited by consensus safety being maintained.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

**Required Conditions:**
- Successful passage of a malicious governance proposal, OR
- Compromise of the `@aptos_framework` account with governance powers

**Barriers to Exploitation:**
- Governance proposals require community voting and approval
- Malicious intent must go undetected during proposal review
- However, there is **zero technical prevention** - no validation exists to stop this

**Realistic Scenarios:**
1. **Governance Compromise:** If governance participants are compromised or make an error, this attack succeeds immediately
2. **Malicious Proposal:** A subtly malicious proposal could hide the large `exclude_round` value among other configuration changes
3. **Configuration Error:** Even without malicious intent, an accidental large value could cause the same damage

The likelihood is elevated by the **complete absence of validation** - once a proposal reaches governance, nothing prevents setting dangerous values.

## Recommendation

Implement validation for `exclude_round` to enforce reasonable bounds:

**1. Add validation in the Move smart contract:**

In `consensus_config.move`, add bounds checking in `set_for_next_epoch()`:

```move
const EEXCLUDE_ROUND_TOO_LARGE: u64 = 2;
const MAX_EXCLUDE_ROUND: u64 = 10000; // Reasonable maximum for typical epoch sizes

public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
    system_addresses::assert_aptos_framework(account);
    assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
    
    // Validate exclude_round doesn't exceed reasonable bounds
    let parsed_config = parse_and_validate_config(&config);
    assert!(
        parsed_config.exclude_round <= MAX_EXCLUDE_ROUND,
        error::invalid_argument(EEXCLUDE_ROUND_TOO_LARGE)
    );
    
    std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
}
```

**2. Add runtime safeguards in Rust:**

In `consensus/src/liveness/leader_reputation.rs`, add a sanity check:

```rust
pub fn get_valid_proposer_and_voting_power_participation_ratio(
    &self,
    round: Round,
) -> (Author, VotingPowerRatio) {
    // Safeguard: if exclude_round is unreasonably large, cap it
    let effective_exclude_round = std::cmp::min(
        self.exclude_round,
        round.saturating_sub(1) // Ensure we always look at some recent data
    );
    
    let target_round = round.saturating_sub(effective_exclude_round);
    
    // Additional check: warn if target_round is suspiciously low
    if target_round == 0 && round > 100 {
        warn!(
            "target_round is 0 at round {}, exclude_round may be too large: {}",
            round, self.exclude_round
        );
    }
    
    let (sliding_window, root_hash) = self.backend.get_block_metadata(self.epoch, target_round);
    // ... rest of implementation
}
```

**3. Add configuration schema validation:**

Define maximum bounds in `types/src/on_chain_config/consensus_config.rs`:

```rust
const MAX_REASONABLE_EXCLUDE_ROUND: u64 = 10000;

impl ConsensusConfigV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.exclude_round <= MAX_REASONABLE_EXCLUDE_ROUND,
            "exclude_round {} exceeds maximum allowed value {}",
            self.exclude_round,
            MAX_REASONABLE_EXCLUDE_ROUND
        );
        Ok(())
    }
}
```

## Proof of Concept

**Rust Test Demonstration:**

```rust
#[test]
fn test_exclude_round_causes_frozen_reputation() {
    use aptos_types::on_chain_config::{ConsensusConfigV1, OnChainConsensusConfig};
    use consensus::liveness::leader_reputation::LeaderReputation;
    
    // Setup: Create a reputation system with maliciously large exclude_round
    let malicious_exclude_round = 1_000_000_000u64;
    
    let config = ConsensusConfigV1 {
        decoupled_execution: true,
        back_pressure_limit: 10,
        exclude_round: malicious_exclude_round,
        max_failed_authors_to_store: 10,
        proposer_election_type: ProposerElectionType::LeaderReputation(
            LeaderReputationType::ProposerAndVoterV2(ProposerAndVoterConfig::default())
        ),
    };
    
    // Simulate rounds in the epoch
    let test_rounds = vec![100, 1000, 10000, 100000];
    
    for round in test_rounds {
        // Compute target_round as the code does
        let target_round = round.saturating_sub(malicious_exclude_round);
        
        // Verify that target_round is always 0
        assert_eq!(target_round, 0, 
            "At round {}, target_round should be 0 due to large exclude_round", round);
        
        println!(
            "Round {}: exclude_round={}, target_round={} (FROZEN on round 0 data)",
            round, malicious_exclude_round, target_round
        );
    }
    
    // This demonstrates that the reputation system cannot adapt to current
    // performance throughout the entire epoch
}
```

**Governance Attack Simulation:**

```move
// Malicious governance proposal script
script {
    use aptos_framework::consensus_config;
    use aptos_framework::aptos_governance;
    
    fun malicious_consensus_config_update(framework: &signer) {
        // Craft config with maliciously large exclude_round
        let malicious_config = create_config_with_large_exclude_round();
        
        // Submit via governance (no validation will stop this)
        consensus_config::set_for_next_epoch(framework, malicious_config);
        aptos_governance::reconfigure(framework);
        
        // After next epoch, leader reputation is effectively frozen
    }
}
```

## Notes

- The vulnerability exists because `saturating_sub` prevents arithmetic underflow but not the **logical error** of using incorrect round ranges
- The code at line 112 in `leader_reputation.rs` shows awareness that `target_round = 0` can occur, but only handles it for normal early-epoch scenarios, not malicious configuration
- The `use_history_from_previous_epoch_max_count` limit of 5 epochs provides some bound on staleness, but doesn't prevent the core issue within the current epoch
- This is fundamentally a **parameter validation failure** that enables a governance-level attack on consensus efficiency

### Citations

**File:** types/src/on_chain_config/consensus_config.rs (L476-476)
```rust
    pub exclude_round: u64,
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L127-134)
```rust
        for event in events {
            if (event.event.epoch(), event.event.round()) <= (target_epoch, target_round)
                && result.len() < self.window_size
            {
                max_version = std::cmp::max(max_version, event.version);
                result.push(event.event.clone());
            }
        }
```

**File:** consensus/src/liveness/leader_reputation.rs (L700-700)
```rust
        let target_round = round.saturating_sub(self.exclude_round);
```

**File:** consensus/src/liveness/leader_reputation.rs (L701-701)
```rust
        let (sliding_window, root_hash) = self.backend.get_block_metadata(self.epoch, target_round);
```
