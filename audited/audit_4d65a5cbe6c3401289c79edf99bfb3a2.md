# Audit Report

## Title
Division by Zero in Proposer Election Causes Network-Wide Consensus Halt via Malicious Epoch Configuration

## Summary
A division by zero vulnerability exists in the `get_valid_proposer()` function that can cause all validators to simultaneously panic when `contiguous_rounds` is set to 0 through a malicious governance proposal. This results in complete network failure requiring emergency intervention to recover.

## Finding Description

The `RotatingProposer::get_valid_proposer()` function performs an unchecked division operation using `contiguous_rounds` as the divisor: [1](#0-0) 

If `contiguous_rounds` is zero, this division causes a **panic** at runtime. This value comes from the on-chain consensus configuration via the `ProposerElectionType` enum: [2](#0-1) 

The configuration is instantiated during epoch initialization without validation: [3](#0-2) 

**Attack Path:**

1. A malicious or compromised governance proposal calls `consensus_config::set_for_next_epoch()` with a serialized `OnChainConsensusConfig` where `ProposerElectionType::RotatingProposer(0)` or `ProposerElectionType::FixedProposer(0)`: [4](#0-3) 

2. The Move framework only validates that the config bytes are non-empty, not the actual parameter values: [5](#0-4) 

3. During the next epoch reconfiguration via `on_new_epoch()`, all validators load this poisoned configuration: [6](#0-5) 

4. Each validator creates a `RotatingProposer` instance with `contiguous_rounds = 0`: [7](#0-6) 

5. When any validator attempts consensus operations, `get_valid_proposer()` is called in critical paths:
   - During new round events (for determining previous proposer)
   - When broadcasting timeout votes 
   - When sending votes to the next round's proposer
   - When computing failed authors for proposals [8](#0-7) [9](#0-8) 

6. **All validators panic simultaneously** as they all have identical configuration and execute the same consensus logic.

**Broken Invariants:**
- **Consensus Safety**: Network cannot make progress or commit blocks
- **Deterministic Execution**: Validators crash instead of producing state
- **Liveness**: Total loss of network availability

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program for the following reasons:

**Total Loss of Liveness/Network Availability** (Critical Category):
- All validators crash when attempting to determine proposers
- No new blocks can be proposed or committed
- Network is completely halted until manual intervention
- Transactions cannot be processed
- Funds are effectively frozen (though not permanently with proper recovery)

**Non-Recoverable via Standard Mechanisms**:
- Requires coordinated emergency response across all validators
- May require binary patches or emergency governance override
- Cannot self-recover through normal consensus mechanisms

The impact affects 100% of the validator set simultaneously, making this a network-wide catastrophic failure.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Requirements:**
- Governance proposal approval (requires governance voting power)
- No validator insider access needed
- No cryptographic breaks required
- Exploitable via standard on-chain governance mechanisms

**Complexity: Low**
- Attack is straightforward - simply set `contiguous_rounds` to 0 in governance proposal
- No sophisticated exploitation techniques required
- Serializing a malicious config is trivial using standard BCS encoding

**Realistic Scenarios:**
1. **Malicious Governance Attack**: Attacker with sufficient governance voting power or through social engineering
2. **Accidental Misconfiguration**: Human error in governance proposal construction
3. **Compromised Governance Key**: If governance keys are compromised

While governance proposals require voting, the lack of input validation makes this a realistic attack vector, especially during governance parameter updates.

## Recommendation

**Immediate Fix: Add Input Validation**

Add validation in `RotatingProposer::new()` to reject zero values:

```rust
impl RotatingProposer {
    pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
        assert!(
            contiguous_rounds > 0,
            "contiguous_rounds must be greater than 0"
        );
        Self {
            proposers,
            contiguous_rounds,
        }
    }
}
```

**Additional Hardening:**

1. **Move-Side Validation**: Add validation in `consensus_config.move` to deserialize and validate configuration before accepting it
2. **Rust-Side Validation**: Add validation during `OnChainConsensusConfig` deserialization
3. **Default Value Protection**: Ensure default configurations always use safe values
4. **Monitoring**: Add alerts when consensus configuration changes are detected

**Recommended Safe Minimum**: `contiguous_rounds >= 1`

## Proof of Concept

**Rust Unit Test:**

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_zero_contiguous_rounds_causes_panic() {
    use crate::liveness::{
        proposer_election::ProposerElection,
        rotating_proposer_election::RotatingProposer,
    };
    use aptos_types::account_address::AccountAddress;

    let proposers = vec![AccountAddress::random(), AccountAddress::random()];
    let pe = RotatingProposer::new(proposers, 0);
    
    // This call will panic with division by zero
    pe.get_valid_proposer(1);
}
```

**Attack Simulation Steps:**

1. Create a malicious `OnChainConsensusConfig`:
```rust
use aptos_types::on_chain_config::{OnChainConsensusConfig, ProposerElectionType};

let malicious_config = OnChainConsensusConfig::V5 {
    alg: ConsensusAlgorithmConfig::JolteonV2 {
        main: ConsensusConfigV1 {
            proposer_election_type: ProposerElectionType::RotatingProposer(0), // ZERO!
            // ... other fields ...
        },
        quorum_store_enabled: true,
        order_vote_enabled: true,
    },
    vtxn: ValidatorTxnConfig::default_enabled(),
    window_size: None,
    rand_check_enabled: true,
};

let config_bytes = bcs::to_bytes(&bcs::to_bytes(&malicious_config).unwrap()).unwrap();
```

2. Submit via governance proposal calling `consensus_config::set_for_next_epoch(config_bytes)`

3. After epoch reconfiguration, all validators will panic on first `get_valid_proposer()` call

**Expected Result**: Complete network halt as all validators crash simultaneously.

---

**Notes**

This vulnerability demonstrates a critical gap in input validation across the governance → configuration → consensus pipeline. The `contiguous_rounds` parameter flows through multiple layers (Move framework → Rust deserialization → Consensus instantiation) without any validation, allowing a mathematically invalid value to reach production consensus code where it causes immediate process termination via panic.

The severity is elevated because:
1. The panic is deterministic and affects all validators identically
2. No exception handling exists around proposer election calls
3. Recovery requires coordinated manual intervention
4. The attack surface is accessible via governance (not requiring validator compromise)

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

**File:** consensus/src/epoch_manager.rs (L296-304)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L23-27)
```text
    public(friend) fun initialize(aptos_framework: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        move_to(aptos_framework, ConsensusConfig { config });
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

**File:** consensus/src/round_manager.rs (L428-430)
```rust
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
