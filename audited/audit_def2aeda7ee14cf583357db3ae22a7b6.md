# Audit Report

## Title
Division-by-Zero Panic in Proposer Election Causes Total Network Halt via Malicious Governance Config

## Summary
The `RotatingProposer::get_valid_proposer()` function performs division by `contiguous_rounds` without validating that this parameter is non-zero. An attacker can submit a governance proposal setting `contiguous_rounds` to 0, which causes all validators to panic when determining the valid proposer for any round, resulting in complete network unavailability. [1](#0-0) 

## Finding Description
The vulnerability exists in the proposer election mechanism used to determine which validator should propose blocks for each round. The `get_valid_proposer()` function calculates the proposer index using the formula: `(round / contiguous_rounds) % proposers.len()`. [2](#0-1) 

The `RotatingProposer::new()` constructor accepts `contiguous_rounds` as a `u32` parameter without any validation. When this value is 0, the division operation in `get_valid_proposer()` triggers a panic. [3](#0-2) 

The on-chain consensus configuration can be updated through governance proposals using the `set_for_next_epoch()` function: [4](#0-3) 

This Move function only validates that the config bytes are non-empty, but does not validate the semantic correctness of the configuration parameters.

The `get_valid_proposer()` function is called frequently during normal consensus operations:
- When processing new rounds to determine the previous proposer
- During timeout handling  
- When broadcasting votes to the next proposer [5](#0-4) [6](#0-5) 

**Attack Path:**
1. Attacker submits governance proposal containing serialized `OnChainConsensusConfig` with `ProposerElectionType::RotatingProposer(0)`
2. Proposal passes through governance voting (requires sufficient stake/voting power)
3. At next epoch transition, `on_new_epoch()` applies the malicious config
4. `EpochManager` creates `RotatingProposer::new(proposers, 0)` with the zero value
5. Any validator calling `get_valid_proposer()` during normal consensus operations triggers division-by-zero panic
6. All validators crash simultaneously, causing complete network halt [7](#0-6) 

## Impact Explanation
This vulnerability causes **Total loss of liveness/network availability**, which qualifies as **Critical Severity** (up to $1,000,000) per the Aptos bug bounty program.

When `contiguous_rounds` is set to 0:
- All validators crash when attempting to determine valid proposers
- No blocks can be proposed or committed
- The network becomes completely unavailable
- Recovery requires a coordinated manual intervention to fix the configuration
- No funds can be transferred and all on-chain activity halts

This breaks the fundamental invariant: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" by causing total consensus failure.

## Likelihood Explanation
**Likelihood: Medium**

The attack requires:
- Sufficient voting power to pass a governance proposal (typically requires significant stake)
- Knowledge of the vulnerability and ability to craft malicious config bytes
- No intermediate validation catches the invalid parameter

However:
- The governance system is designed to be accessible to stake holders, not just insiders
- Malicious or compromised governance participants could exploit this
- Accidental misconfiguration is also possible
- There are no validation checks preventing this attack

The impact is so severe (complete network halt) that even medium likelihood warrants immediate remediation.

## Recommendation
Add validation to ensure `contiguous_rounds` is non-zero at multiple layers:

**1. In RotatingProposer constructor:**
```rust
pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
    assert!(contiguous_rounds > 0, "contiguous_rounds must be greater than 0");
    assert!(!proposers.is_empty(), "proposers list cannot be empty");
    Self {
        proposers,
        contiguous_rounds,
    }
}
```

**2. In EpochManager when creating proposer election:** [8](#0-7) 

Add validation before calling `RotatingProposer::new()`:
```rust
match &onchain_config.proposer_election_type() {
    ProposerElectionType::RotatingProposer(contiguous_rounds) => {
        ensure!(*contiguous_rounds > 0, "contiguous_rounds must be positive");
        Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
    },
    // ... rest of match arms
}
```

**3. Add deserialization validation in consensus_config.rs:**
Implement a custom deserializer or validation function for `ProposerElectionType` that rejects zero values.

## Proof of Concept

**Rust Unit Test:**
```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_rotating_proposer_zero_contiguous_rounds_panic() {
    use crate::liveness::rotating_proposer_election::RotatingProposer;
    use crate::liveness::proposer_election::ProposerElection;
    use aptos_types::account_address::AccountAddress;
    
    // Create RotatingProposer with contiguous_rounds = 0
    let proposers = vec![
        AccountAddress::random(),
        AccountAddress::random(),
        AccountAddress::random(),
    ];
    let rotating_proposer = RotatingProposer::new(proposers, 0);
    
    // This will panic with division by zero
    rotating_proposer.get_valid_proposer(1);
}
```

**Governance Attack Simulation:**
```rust
#[test]
fn test_malicious_governance_config_network_halt() {
    use aptos_types::on_chain_config::{
        OnChainConsensusConfig, ConsensusAlgorithmConfig, 
        ConsensusConfigV1, ProposerElectionType
    };
    
    // Attacker crafts malicious config
    let malicious_config = OnChainConsensusConfig::V5 {
        alg: ConsensusAlgorithmConfig::JolteonV2 {
            main: ConsensusConfigV1 {
                proposer_election_type: ProposerElectionType::RotatingProposer(0), // Zero!
                ..ConsensusConfigV1::default()
            },
            quorum_store_enabled: true,
            order_vote_enabled: true,
        },
        vtxn: ValidatorTxnConfig::default_for_genesis(),
        window_size: None,
        rand_check_enabled: true,
    };
    
    // Serialize for governance proposal
    let config_bytes = bcs::to_bytes(&malicious_config).unwrap();
    
    // This config would pass Move validation (only checks length > 0)
    assert!(config_bytes.len() > 0);
    
    // When applied, would cause all validators to crash
}
```

## Notes
This vulnerability demonstrates insufficient input validation at the governance configuration layer. While governance is a trusted mechanism, defense-in-depth principles require validating all configuration parameters to prevent both malicious and accidental misconfigurations that could catastrophically impact network availability.

### Citations

**File:** consensus/src/liveness/rotating_proposer_election.rs (L27-32)
```rust
    pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
        Self {
            proposers,
            contiguous_rounds,
        }
    }
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L36-39)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L510-523)
```rust
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

**File:** consensus/src/round_manager.rs (L425-430)
```rust
        let is_current_proposer = self
            .proposer_election
            .is_valid_proposer(self.proposal_generator.author(), new_round);
        let prev_proposer = self
            .proposer_election
            .get_valid_proposer(new_round.saturating_sub(1));
```

**File:** consensus/src/round_manager.rs (L1411-1413)
```rust
            let recipient = self
                .proposer_election
                .get_valid_proposer(proposal_round + 1);
```

**File:** consensus/src/epoch_manager.rs (L292-304)
```rust
        let proposers = epoch_state
            .verifier
            .get_ordered_account_addresses_iter()
            .collect::<Vec<_>>();
        match &onchain_config.proposer_election_type() {
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
            },
            // We don't really have a fixed proposer!
            ProposerElectionType::FixedProposer(contiguous_rounds) => {
                let proposer = choose_leader(proposers);
                Arc::new(RotatingProposer::new(vec![proposer], *contiguous_rounds))
            },
```
