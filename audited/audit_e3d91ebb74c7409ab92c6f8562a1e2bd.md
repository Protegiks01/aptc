# Audit Report

## Title
Division by Zero in RotatingProposer Causes Complete Network Halt via Malicious Governance Proposal

## Summary
The `RotatingProposer::get_valid_proposer()` function performs division by `contiguous_rounds` without validating that the value is non-zero. A malicious governance proposal can set `contiguous_rounds` to 0, causing all validator nodes to panic with division by zero when attempting to determine the proposer for any consensus round, resulting in total network unavailability.

## Finding Description

The vulnerability exists in the rotating proposer election mechanism used by the AptosBFT consensus protocol. The core issue is in the calculation performed by `get_valid_proposer()`: [1](#0-0) 

The `contiguous_rounds` field is defined as a `u32` with no validation to ensure it's non-zero: [2](#0-1) 

**Attack Path:**

1. **Governance Proposal**: An attacker submits a governance proposal calling `consensus_config::set_for_next_epoch()` with maliciously crafted config bytes containing `ProposerElectionType::RotatingProposer(0)` or `FixedProposer(0)`.

2. **Insufficient Validation**: The Move module only validates that the config bytes vector is non-empty, not the actual field values: [3](#0-2) 

3. **Deserialization Succeeds**: The config is successfully deserialized since 0 is a valid `u32` value: [4](#0-3) 

4. **Epoch Transition**: On the next epoch, `create_proposer_election()` directly uses the malicious value without validation: [5](#0-4) 

5. **Consensus Crash**: When any validator attempts to process a consensus round, `get_valid_proposer()` or `is_valid_proposer()` is called: [6](#0-5) 

6. **Division by Zero Panic**: The calculation `round / u64::from(0)` triggers a Rust panic, crashing the validator node. This affects ALL validators simultaneously.

**Invariants Broken:**
- Critical Invariant #2: Consensus Safety - The consensus protocol completely fails
- Total loss of liveness - All validators crash simultaneously, network cannot progress

## Impact Explanation

This vulnerability meets the **CRITICAL severity** criteria per the Aptos bug bounty program:

**Total loss of liveness/network availability**: When `contiguous_rounds` is set to 0, every validator node in the network will panic and crash when attempting to determine the proposer for any round. Since this is consensus-critical code executed by all validators, the entire network halts simultaneously.

**Non-recoverable network partition (requires hardfork)**: Recovery requires either:
- A coordinated hardfork where all validators manually patch the on-chain config before restart
- Emergency governance intervention (impossible if nodes cannot process rounds)
- Manual intervention from all validator operators to override configuration

The vulnerability affects:
- **All validator nodes** (100% of consensus participants)
- **All network users** (no blocks can be produced or transactions processed)
- **Entire blockchain state** (frozen until manual intervention)

Unlike temporary liveness issues, this creates a permanent halt that requires coordinated off-chain action to resolve.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack requires:
1. ✓ Passing a governance proposal (requires sufficient voting power, but achievable through normal governance process)
2. ✓ No technical complexity (simply setting a u32 to 0)
3. ✓ No validator insider access needed
4. ✓ No special privileges beyond governance participation

**Factors increasing likelihood:**
- No validation exists at any layer (Move, Rust deserialization, consensus instantiation)
- The vulnerability is in production code path used by all validators
- Configuration changes are designed to be updateable via governance
- Testing may not catch this if tests never use `contiguous_rounds = 0`

**Factors decreasing likelihood:**
- Requires governance proposal to pass (social/economic barrier)
- Malicious intent would likely be detected during proposal review period
- Setting `contiguous_rounds = 0` has no legitimate use case

However, this could also occur **accidentally** if a governance proposal contains a typo or misconfiguration, making it more likely than purely malicious exploitation.

## Recommendation

Implement validation at multiple defense layers:

**1. Move Module Validation** (strongest protection):

Add validation in `consensus_config::set_for_next_epoch()` to deserialize and check the config before accepting it. This requires adding a native validation function or Move-side checks on the deserialized structure.

**2. Rust Constructor Validation** (defense in depth): [7](#0-6) 

Add validation:
```rust
impl RotatingProposer {
    pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
        assert!(contiguous_rounds > 0, "contiguous_rounds must be greater than 0");
        assert!(!proposers.is_empty(), "proposers list cannot be empty");
        Self {
            proposers,
            contiguous_rounds,
        }
    }
}
```

**3. On-Chain Config Deserialization Validation**:

Add a validation method to `OnChainConsensusConfig` that checks all numeric fields are within valid ranges after deserialization.

**4. Epoch Manager Validation** (last resort): [8](#0-7) 

Add explicit check before creating proposer election to provide better error messages.

## Proof of Concept

**Rust Unit Test** (demonstrates the panic):

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_division_by_zero_with_contiguous_rounds_zero() {
    use crate::liveness::{
        proposer_election::ProposerElection, 
        rotating_proposer_election::RotatingProposer
    };
    use aptos_types::account_address::AccountAddress;

    let proposer1 = AccountAddress::random();
    let proposer2 = AccountAddress::random();
    let proposers = vec![proposer1, proposer2];
    
    // Create RotatingProposer with contiguous_rounds = 0
    let pe = RotatingProposer::new(proposers, 0);
    
    // This will panic with division by zero
    let _ = pe.get_valid_proposer(1);
}
```

**Move Governance Attack Simulation**:

```move
script {
    use aptos_framework::consensus_config;
    use std::vector;
    
    fun exploit_contiguous_rounds_zero(governance: &signer) {
        // Craft malicious config with RotatingProposer(0)
        // This is a simplified representation - actual BCS encoding needed
        let malicious_config: vector<u8> = vector::empty();
        // ... BCS encode OnChainConsensusConfig::V5 with
        // ProposerElectionType::RotatingProposer(0) ...
        
        // This will pass validation (only checks non-empty)
        consensus_config::set_for_next_epoch(governance, malicious_config);
        
        // On next epoch, all validators will crash when processing rounds
    }
}
```

**Exploitation Steps**:
1. Create governance proposal with BCS-encoded `OnChainConsensusConfig` containing `ProposerElectionType::RotatingProposer(0)`
2. Wait for proposal to pass and be executed
3. On next epoch transition, all validators will instantiate `RotatingProposer` with `contiguous_rounds = 0`
4. First round processing triggers division by zero in all validators simultaneously
5. Network halts completely - no blocks can be produced

**Verification**: The panic can be triggered by any call to `get_valid_proposer()` or `is_valid_proposer()` with any round number when `contiguous_rounds = 0`.

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

**File:** consensus/src/liveness/rotating_proposer_election.rs (L36-39)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
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

**File:** types/src/on_chain_config/consensus_config.rs (L510-516)
```rust
pub enum ProposerElectionType {
    // Choose the smallest PeerId as the proposer
    // with specified param contiguous_rounds
    FixedProposer(u32),
    // Round robin rotation of proposers
    // with specified param contiguous_rounds
    RotatingProposer(u32),
```

**File:** consensus/src/epoch_manager.rs (L287-304)
```rust
    fn create_proposer_election(
        &self,
        epoch_state: &EpochState,
        onchain_config: &OnChainConsensusConfig,
    ) -> Arc<dyn ProposerElection + Send + Sync> {
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

**File:** consensus/src/round_manager.rs (L425-430)
```rust
        let is_current_proposer = self
            .proposer_election
            .is_valid_proposer(self.proposal_generator.author(), new_round);
        let prev_proposer = self
            .proposer_election
            .get_valid_proposer(new_round.saturating_sub(1));
```
