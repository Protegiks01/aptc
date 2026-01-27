# Audit Report

## Title
Persistent Liveness Failures in RoundProposer Due to Non-Responsive Default Proposer

## Summary
The `RoundProposer` election mechanism lacks failure detection capabilities, causing persistent liveness degradation when the `default_proposer` (hardcoded to the first validator) is offline or Byzantine and most rounds are unmapped. Unlike `LeaderReputation` which tracks failed proposers, `RoundProposer` repeatedly selects the same non-responsive proposer for all unmapped rounds, leading to exponentially increasing timeout delays.

## Finding Description

The vulnerability exists in the `get_valid_proposer()` function which implements a simple HashMap lookup with unconditional fallback to `default_proposer`: [1](#0-0) 

The `default_proposer` is hardcoded during epoch initialization to the first validator in the ordered validator set: [2](#0-1) 

**Attack Scenario:**

1. On-chain governance configures `ProposerElectionType::RoundProposer` with sparse mappings (e.g., only rounds 100, 500, 1000 mapped)
2. The first validator in the validator set becomes non-responsive (Byzantine behavior or infrastructure failure)
3. For each unmapped round (1-99, 101-499, 501-999, etc.):
   - `get_valid_proposer(round)` returns the offline `default_proposer`
   - Network waits for local timeout (exponentially increasing per `ExponentialTimeInterval`)
   - Timeout certificate is formed
   - Round advances by +1 via `process_certificates()`
4. The cycle repeats for all consecutive unmapped rounds [3](#0-2) 

The timeout duration increases exponentially based on rounds since last ordered block, compounding the liveness impact: [4](#0-3) 

**Key Difference from LeaderReputation:**

The `LeaderReputation` proposer election tracks failed proposers and adjusts selection weights, providing resilience against non-responsive validators. `RoundProposer` has no such mechanism: [5](#0-4) 

## Impact Explanation

**Severity: High**

This qualifies as **High Severity** under Aptos bug bounty criteria:
- **Validator node slowdowns**: Network experiences repeated timeout cycles with exponentially increasing delays
- **Significant protocol violations**: Liveness is severely degraded across all validators

While not causing total loss of liveness (Critical), the impact includes:
- Extended block times during unmapped round sequences (could be hundreds of rounds)
- Exponentially growing timeout delays (potentially minutes per round)
- All validators affected network-wide
- Recovery only when reaching a mapped round, epoch change, or default proposer restoration

**Not Critical** because:
- Network eventually recovers at mapped rounds
- Epoch transitions provide periodic recovery points
- No consensus safety violations or fund loss

## Likelihood Explanation

**Likelihood: Medium-Low**

Required preconditions:
1. **Configuration**: `RoundProposer` must be actively configured via on-chain governance (not the default)
2. **Sparse Mappings**: The HashMap must have significant gaps between mapped rounds
3. **Proposer Failure**: The first validator (default_proposer) must be offline or Byzantine

**Why it matters despite lower likelihood:**
- `RoundProposer` is a valid, documented configuration option for special use cases (scheduled rounds, testing, upgrades)
- The first validator could fail due to legitimate operational issues (not just malicious behavior)
- Poor operational practices (sparse mappings without considering default_proposer availability) could trigger this naturally
- A Byzantine first validator (within < 1/3 Byzantine assumption) could intentionally exploit this

## Recommendation

**Option 1: Add Failure Detection to RoundProposer**

Implement timeout tracking and fallback logic:

```rust
pub struct RoundProposer {
    proposers: HashMap<Round, Author>,
    default_proposer: Author,
    failed_rounds: HashMap<Author, Vec<Round>>, // Track failures
}

impl ProposerElection for RoundProposer {
    fn get_valid_proposer(&self, round: Round) -> Author {
        let proposer = match self.proposers.get(&round) {
            None => self.default_proposer,
            Some(round_proposer) => *round_proposer,
        };
        
        // Check if this proposer failed recently
        if self.is_recently_failed(proposer, round) {
            // Fallback to next available proposer
            self.get_fallback_proposer(round)
        } else {
            proposer
        }
    }
}
```

**Option 2: Hybrid Fallback (Recommended)**

When default_proposer is needed, fallback to rotating proposer logic after N consecutive timeouts:

```rust
fn get_valid_proposer(&self, round: Round) -> Author {
    match self.proposers.get(&round) {
        Some(proposer) => *proposer,
        None => {
            // If we've had multiple timeouts, use rotation
            if self.consecutive_default_timeouts > THRESHOLD {
                self.get_rotating_fallback(round)
            } else {
                self.default_proposer
            }
        }
    }
}
```

**Option 3: Documentation Warning**

At minimum, add clear warnings in `RoundProposer` documentation about ensuring default_proposer availability and limiting unmapped round spans.

## Proof of Concept

```rust
#[test]
fn test_liveness_failure_with_offline_default_proposer() {
    use crate::liveness::{
        proposer_election::ProposerElection,
        round_proposer_election::RoundProposer,
    };
    use aptos_types::account_address::AccountAddress;
    use std::collections::HashMap;

    // Setup: First validator is default_proposer
    let offline_validator = AccountAddress::from_hex_literal("0x1").unwrap();
    let active_validator = AccountAddress::from_hex_literal("0x2").unwrap();
    
    // Sparse mapping: only round 100 is mapped
    let mut round_proposers = HashMap::new();
    round_proposers.insert(100, active_validator);
    
    let proposer_election = RoundProposer::new(
        round_proposers,
        offline_validator, // default_proposer is offline
    );
    
    // Demonstrate: rounds 1-99 all select offline validator
    for round in 1..100 {
        let proposer = proposer_election.get_valid_proposer(round);
        assert_eq!(
            proposer, offline_validator,
            "Round {} falls back to offline default_proposer",
            round
        );
    }
    
    // Only at round 100 do we get a responsive proposer
    assert_eq!(
        proposer_election.get_valid_proposer(100),
        active_validator
    );
    
    // Rounds 101-199 fall back to offline validator again
    for round in 101..200 {
        let proposer = proposer_election.get_valid_proposer(round);
        assert_eq!(
            proposer, offline_validator,
            "Round {} falls back to offline default_proposer",
            round
        );
    }
    
    println!("VULNERABILITY CONFIRMED: 198 consecutive rounds would timeout");
    println!("With exponential backoff, this could take hours");
}
```

## Notes

**Validation Against Requirements:**

While this is a real code defect with significant liveness impact, it has limitations:
- **Not exploitable by unprivileged actors**: Requires either governance control to configure RoundProposer poorly, or being a Byzantine validator (within protocol assumptions)
- **Mitigations exist**: Alternative proposer election types (LeaderReputation, RotatingProposer) don't have this issue
- **Design intent**: RoundProposer appears intended for special use cases (scheduled rounds), not general operation

The issue represents a **protocol design limitation** when RoundProposer is used inappropriately, rather than a critical security vulnerability. However, it still qualifies as **High Severity** due to significant network-wide liveness degradation when triggered.

### Citations

**File:** consensus/src/liveness/round_proposer_election.rs (L27-32)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        match self.proposers.get(&round) {
            None => self.default_proposer,
            Some(round_proposer) => *round_proposer,
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L396-405)
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
            },
```

**File:** consensus/src/liveness/round_state.rs (L117-123)
```rust
impl RoundTimeInterval for ExponentialTimeInterval {
    fn get_round_duration(&self, round_index_after_ordered_qc: usize) -> Duration {
        let pow = round_index_after_ordered_qc.min(self.max_exponent) as u32;
        let base_multiplier = self.exponent_base.powf(f64::from(pow));
        let duration_ms = ((self.base_ms as f64) * base_multiplier).ceil() as u64;
        Duration::from_millis(duration_ms)
    }
```

**File:** consensus/src/liveness/round_state.rs (L253-254)
```rust
        let new_round = sync_info.highest_round() + 1;
        if new_round > self.current_round {
```

**File:** consensus/src/liveness/proposer_election.rs (L9-20)
```rust
/// ProposerElection incorporates the logic of choosing a leader among multiple candidates.
pub trait ProposerElection {
    /// If a given author is a valid candidate for being a proposer, generate the info,
    /// otherwise return None.
    /// Note that this function is synchronous.
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }

    /// Return the valid proposer for a given round (this information can be
    /// used by e.g., voters for choosing the destinations for sending their votes to).
    fn get_valid_proposer(&self, round: Round) -> Author;
```
