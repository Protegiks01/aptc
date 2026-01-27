# Audit Report

## Title
Division-by-Zero Panic in RotatingProposer Due to Unvalidated Deserialization of Zero contiguous_rounds

## Summary
The `RotatingProposer` consensus component can be instantiated with `contiguous_rounds = 0` via deserialization of on-chain governance configuration, causing all validator nodes to crash with a division-by-zero panic when attempting to determine the next block proposer. This results in total network liveness failure.

## Finding Description

The `RotatingProposer` struct maintains two critical invariants for consensus operation:
1. The `proposers` vector must not be empty
2. The `contiguous_rounds` field must not be zero [1](#0-0) 

However, the constructor provides no validation: [2](#0-1) 

The `get_valid_proposer()` method performs arithmetic that will panic if `contiguous_rounds` is zero: [3](#0-2) 

The expression `round / u64::from(self.contiguous_rounds)` causes a **division-by-zero panic** when `contiguous_rounds` is 0.

**Attack Path:**

1. The `ProposerElectionType::RotatingProposer(u32)` enum variant is serializable and can be set via on-chain governance: [4](#0-3) 

2. The Move consensus_config module only validates that config bytes are non-empty, but performs no semantic validation: [5](#0-4) 

3. When a new epoch starts, the EpochManager deserializes the config and directly instantiates RotatingProposer: [6](#0-5) 

4. When consensus attempts to determine the valid proposer for any round, all validators crash simultaneously with division-by-zero.

**Exploitation Scenario:**

A malicious governance proposal sets `OnChainConsensusConfig` with `ProposerElectionType::RotatingProposer(0)`. After the proposal passes and `aptos_governance::reconfigure()` is called, the next epoch begins. When any validator node attempts to determine the proposer for the first round, it invokes `get_valid_proposer()`, which executes `round / 0`, causing an immediate panic. Since all validators process the same configuration deterministically, **every validator in the network crashes simultaneously**, resulting in complete network halt.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos bug bounty program:
- **Total loss of liveness/network availability**: All validators crash simultaneously and cannot progress consensus
- **Non-recoverable network partition (requires hardfork)**: Recovery requires emergency deployment of a patched validator binary or coordination to revert the malicious config change, potentially requiring a hard fork

The network cannot produce new blocks until all validators are manually updated with fixed code or the configuration is reverted through extraordinary means. This breaks the fundamental **Consensus Safety** invariant requiring continuous liveness under normal Byzantine assumptions.

## Likelihood Explanation

**Likelihood: Medium-Low**

While the technical exploit is trivial once a malicious config is deployed, it requires:
- Crafting a governance proposal with `ProposerElectionType::RotatingProposer(0)`
- Getting the proposal approved through the governance voting mechanism
- Waiting for the next epoch transition

However, several factors increase risk:
- **No validation exists** at any layer (Move, Rust deserialization, or constructor)
- **Accidental triggering**: Even without malicious intent, a configuration error (typo, unit confusion) could cause this
- **Testing gap**: Tests only use values 1 and 3, never testing edge case of 0 [7](#0-6) 

Defense-in-depth principles require validation even for trusted inputs to prevent accidents and reduce attack surface.

## Recommendation

Add validation in multiple layers:

**1. Rust Constructor Validation:**
```rust
pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Result<Self> {
    ensure!(!proposers.is_empty(), "proposers cannot be empty");
    ensure!(contiguous_rounds > 0, "contiguous_rounds must be positive");
    Ok(Self {
        proposers,
        contiguous_rounds,
    })
}
```

**2. On-Chain Config Validation:**

Add native validation function in `consensus_config.move`:
```move
native fun validate_consensus_config_internal(config_bytes: vector<u8>): bool;

public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
    system_addresses::assert_aptos_framework(account);
    assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
    assert!(validate_consensus_config_internal(config), error::invalid_argument(EINVALID_CONFIG));
    std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
}
```

Implement the native function to deserialize and validate that RotatingProposer/FixedProposer contiguous_rounds > 0.

**3. EpochManager Defensive Check:** [6](#0-5) 

Wrap instantiation with validation:
```rust
ProposerElectionType::RotatingProposer(contiguous_rounds) => {
    ensure!(*contiguous_rounds > 0, "contiguous_rounds must be positive");
    Arc::new(RotatingProposer::new(proposers, *contiguous_rounds).unwrap())
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_rotating_proposer_zero_contiguous_rounds_causes_panic() {
    use aptos_types::account_address::AccountAddress;
    use crate::liveness::{
        proposer_election::ProposerElection,
        rotating_proposer_election::RotatingProposer,
    };
    
    // Create RotatingProposer with zero contiguous_rounds
    let proposers = vec![AccountAddress::random(), AccountAddress::random()];
    let pe = RotatingProposer::new(proposers, 0);
    
    // Attempting to get valid proposer will panic with division by zero
    let _ = pe.get_valid_proposer(1);  // PANIC: division by zero
}
```

This test demonstrates that instantiating `RotatingProposer` with `contiguous_rounds = 0` and calling `get_valid_proposer()` causes an immediate panic, confirming the vulnerability.

## Notes

While this vulnerability requires governance-level access to exploit maliciously, it represents a critical gap in defensive programming. Defense-in-depth principles require validation at all trust boundaries, including deserialization of on-chain configurations. The lack of validation could also lead to accidental network failures due to configuration errors, making this a practical concern beyond just malicious attacks.

### Citations

**File:** consensus/src/liveness/rotating_proposer_election.rs (L10-16)
```rust
pub struct RotatingProposer {
    // Ordering of proposers to rotate through (all honest replicas must agree on this)
    proposers: Vec<Author>,
    // Number of contiguous rounds (i.e. round numbers increase by 1) a proposer is active
    // in a row
    contiguous_rounds: u32,
}
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L25-33)
```rust
impl RotatingProposer {
    /// With only one proposer in the vector, it behaves the same as a fixed proposer strategy.
    pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
        Self {
            proposers,
            contiguous_rounds,
        }
    }
}
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L35-40)
```rust
impl ProposerElection for RotatingProposer {
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L508-523)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")] // cannot use tag = "type" as nested enums cannot work, and bcs doesn't support it
pub enum ProposerElectionType {
    // Choose the smallest PeerId as the proposer
    // with specified param contiguous_rounds
    FixedProposer(u32),
    // Round robin rotation of proposers
    // with specified param contiguous_rounds
    RotatingProposer(u32),
    // Committed history based proposer election
    LeaderReputation(LeaderReputationType),
    // Pre-specified proposers for each round,
    // or default proposer if round proposer not
    // specified
    RoundProposer(HashMap<Round, AccountAddress>),
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```

**File:** consensus/src/epoch_manager.rs (L296-299)
```rust
        match &onchain_config.proposer_election_type() {
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
            },
```

**File:** consensus/src/liveness/rotating_proposer_test.rs (L9-25)
```rust
#[test]
fn test_rotating_proposer() {
    let chosen_author = AccountAddress::random();
    let another_author = AccountAddress::random();
    let proposers = vec![chosen_author, another_author];
    let pe = RotatingProposer::new(proposers, 1);

    // Send a proposal from both chosen author and another author, the only winning proposals
    // follow the round-robin rotation.

    assert!(!pe.is_valid_proposer(chosen_author, 1));
    assert!(pe.is_valid_proposer(another_author, 1),);
    assert!(pe.is_valid_proposer(chosen_author, 2));
    assert!(!pe.is_valid_proposer(another_author, 2));
    assert_eq!(pe.get_valid_proposer(1), another_author);
    assert_eq!(pe.get_valid_proposer(2), chosen_author);
}
```
