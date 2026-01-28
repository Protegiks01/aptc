# Audit Report

## Title
Division by Zero in Proposer Election Causes Network-Wide Consensus Halt via Malicious Epoch Configuration

## Summary
A critical division by zero vulnerability exists in the `RotatingProposer::get_valid_proposer()` function that causes all validators to simultaneously panic when `contiguous_rounds` is set to 0 through a governance proposal. This results in complete network failure requiring emergency intervention to recover.

## Finding Description

The `RotatingProposer::get_valid_proposer()` function performs an unchecked division operation using `contiguous_rounds` as the divisor, causing a runtime panic when the value is zero. [1](#0-0) 

The `contiguous_rounds` parameter comes from the on-chain consensus configuration via the `ProposerElectionType` enum, which allows both `RotatingProposer(u32)` and `FixedProposer(u32)` variants. [2](#0-1) 

The constructor accepts this parameter without any validation that it must be non-zero. [3](#0-2) 

**Attack Path:**

1. A governance proposal calls `consensus_config::set_for_next_epoch()` with serialized configuration containing zero `contiguous_rounds`. [4](#0-3) 

2. The Move framework only validates that config bytes are non-empty, not the actual parameter values. [5](#0-4) 

3. During epoch reconfiguration, all validators load this configuration through `on_new_epoch()`. [6](#0-5) 

4. Each validator instantiates `RotatingProposer` with `contiguous_rounds = 0`. [7](#0-6) 

5. Critical consensus operations invoke `get_valid_proposer()` in multiple paths:
   - Determining previous proposer during new round processing [8](#0-7) 
   - Logging during timeout broadcast [9](#0-8) 
   - Logging during timeout vote broadcast [10](#0-9) 
   - Sending votes to next round's proposer [11](#0-10) 

6. **All validators panic simultaneously** with identical configuration and execution logic.

This breaks critical consensus invariants: the network cannot make progress, commit blocks, or process transactions.

## Impact Explanation

This qualifies as **Critical Severity** under the "Total Loss of Liveness/Network Availability" category. All validators crash when attempting consensus operations, completely halting the network until coordinated emergency intervention (binary patches or emergency governance override). The network cannot self-recover through normal consensus mechanisms, and transactions cannot be processed during the outage.

## Likelihood Explanation

**Likelihood: Medium**

While this requires governance proposal approval, it has realistic attack vectors:

1. **Accidental Misconfiguration**: Human error during governance proposal construction - no validation catches this mistake
2. **Malicious Governance Attack**: Attacker with sufficient voting power
3. **Compromised Governance Credentials**: If governance keys are compromised

The attack complexity is low - simply serializing a config with zero `contiguous_rounds` using BCS encoding. The lack of validation at all layers (Move framework and Rust implementation) makes this a genuine risk.

## Recommendation

Add validation in multiple layers:

1. **Rust Layer**: In `RotatingProposer::new()`, assert that `contiguous_rounds > 0`:
```rust
pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
    assert!(contiguous_rounds > 0, "contiguous_rounds must be greater than 0");
    Self {
        proposers,
        contiguous_rounds,
    }
}
```

2. **Move Layer**: Add validation in `consensus_config::set_for_next_epoch()` to deserialize and validate the config structure before accepting it.

3. **Deserialization Layer**: Add validation during `OnChainConsensusConfig` deserialization to reject invalid parameter values.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_zero_contiguous_rounds_panic() {
    use aptos_types::account_address::AccountAddress;
    use crate::liveness::{
        proposer_election::ProposerElection,
        rotating_proposer_election::RotatingProposer,
    };
    
    let proposers = vec![AccountAddress::random(), AccountAddress::random()];
    let pe = RotatingProposer::new(proposers, 0);
    
    // This will panic with division by zero
    pe.get_valid_proposer(1);
}
```

## Notes

This vulnerability demonstrates a critical gap in input validation across the governance configuration pipeline. While governance is a trusted mechanism, the lack of validation means that even accidental misconfigurations can cause catastrophic network failure. The issue is particularly severe because it affects all validators simultaneously with no automatic recovery mechanism.

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

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L59-69)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires ConsensusConfig {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<ConsensusConfig>()) {
            let new_config = config_buffer::extract_v2<ConsensusConfig>();
            if (exists<ConsensusConfig>(@aptos_framework)) {
                *borrow_global_mut<ConsensusConfig>(@aptos_framework) = new_config;
            } else {
                move_to(framework, new_config);
            };
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L297-303)
```rust
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
            },
            // We don't really have a fixed proposer!
            ProposerElectionType::FixedProposer(contiguous_rounds) => {
                let proposer = choose_leader(proposers);
                Arc::new(RotatingProposer::new(vec![proposer], *contiguous_rounds))
```

**File:** consensus/src/round_manager.rs (L428-430)
```rust
        let prev_proposer = self
            .proposer_election
            .get_valid_proposer(new_round.saturating_sub(1));
```

**File:** consensus/src/round_manager.rs (L1038-1042)
```rust
            warn!(
                round = round,
                remote_peer = self.proposer_election.get_valid_proposer(round),
                event = LogEvent::Timeout,
            );
```

**File:** consensus/src/round_manager.rs (L1082-1087)
```rust
            warn!(
                round = round,
                remote_peer = self.proposer_election.get_valid_proposer(round),
                voted_nil = is_nil_vote,
                event = LogEvent::Timeout,
            );
```

**File:** consensus/src/round_manager.rs (L1411-1418)
```rust
            let recipient = self
                .proposer_election
                .get_valid_proposer(proposal_round + 1);
            info!(
                self.new_log(LogEvent::Vote).remote_peer(recipient),
                "{}", vote
            );
            self.network.send_vote(vote_msg, vec![recipient]).await;
```
