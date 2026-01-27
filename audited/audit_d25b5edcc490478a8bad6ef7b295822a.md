# Audit Report

## Title
Missing Validator Set Validation in RoundProposer Constructor Enables Consensus Liveness Degradation

## Summary
The `RoundProposer::new()` constructor fails to validate that the provided proposer AccountAddresses are members of the active validator set, allowing governance to configure rounds with non-validator proposers. This causes affected rounds to timeout without producing blocks, resulting in consensus liveness degradation.

## Finding Description

The `RoundProposer::new()` constructor accepts a `HashMap<Round, Author>` mapping rounds to proposer addresses without performing any validation. [1](#0-0) 

When this is instantiated via `create_proposer_election()`, the validator set is retrieved from `epoch_state.verifier`, but there is no validation that the AccountAddresses in the `round_proposers` HashMap are actually members of this validator set. [2](#0-1) 

The configuration is set through the on-chain consensus config, which only validates that the config bytes are non-empty but performs no structural or semantic validation of the proposer addresses. [3](#0-2) 

**Attack Path:**

1. Malicious governance actors propose a `ProposerElectionType::RoundProposer` configuration containing AccountAddresses that are not in the validator set
2. The proposal passes with 2/3+ voting power approval
3. The config is applied at the next epoch transition
4. When a round arrives that maps to a non-validator:
   - `get_valid_proposer(round)` returns the non-validator address [4](#0-3) 
   - All validators check `is_valid_proposer()` and determine they are not the valid proposer [5](#0-4) 
   - No validator proposes a block for that round
   - The round times out, wasting consensus time and reducing throughput

While the Move framework's `block_prologue_common` would reject blocks from non-validators [6](#0-5) , this check occurs too late—the round has already timed out by the time any hypothetical malicious block would reach execution.

The vulnerability also affects vote routing, as votes are sent to `get_valid_proposer(round + 1)`, potentially sending votes to non-existent or non-validator nodes. [7](#0-6) 

## Impact Explanation

This vulnerability is classified as **Medium Severity** per the Aptos bug bounty program criteria for "State inconsistencies requiring intervention."

**Impact Scale:**
- If all/most rounds are mapped to non-validators: Complete network halt (would escalate to Critical)
- If many rounds are mapped to non-validators: Severe throughput degradation (High)
- If few rounds are mapped to non-validators: Minor slowdown (Medium)

The attack causes consensus liveness degradation rather than safety violations. Each affected round wastes the full timeout period (typically several seconds) before validators can proceed to the next round. With strategic round selection, an attacker could severely impact network performance without causing a complete halt.

The network remains recoverable through governance action to correct the configuration, preventing this from reaching Critical severity. However, during the attack period, transaction confirmation times increase proportionally to the number of affected rounds.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements:**
- Requires 2/3+ governance voting power approval
- Not trivially achievable by a single actor
- Requires coordination among governance participants
- Could occur accidentally through configuration errors

**Feasibility:**
- The attack vector is through standard governance mechanisms, not exploitation of undefined behavior
- No specialized knowledge required beyond understanding the consensus config format
- The lack of validation makes both malicious exploitation and accidental misconfiguration possible
- No rate limiting or special protections exist for consensus config changes

**Detection:**
- Would be immediately visible through increased round timeouts and reduced block production rate
- Network monitoring would detect the anomaly quickly
- However, identifying the root cause requires examining the on-chain consensus config

## Recommendation

Add validation in `RoundProposer::new()` to ensure all proposer addresses are members of the validator set:

```rust
impl RoundProposer {
    pub fn new(
        proposers: HashMap<Round, Author>, 
        default_proposer: Author,
        validator_set: &[Author], // Add validator set parameter
    ) -> anyhow::Result<Self> {
        // Validate default proposer
        ensure!(
            validator_set.contains(&default_proposer),
            "Default proposer {:?} not in validator set",
            default_proposer
        );
        
        // Validate all mapped proposers
        for (round, author) in &proposers {
            ensure!(
                validator_set.contains(author),
                "Proposer {:?} for round {} not in validator set",
                author,
                round
            );
        }
        
        // Optional: validate unique proposer count
        let unique_proposers: HashSet<_> = proposers.values().collect();
        ensure!(
            unique_proposers.len() <= validator_set.len(),
            "Number of unique proposers ({}) exceeds validator set size ({})",
            unique_proposers.len(),
            validator_set.len()
        );
        
        Ok(Self {
            proposers,
            default_proposer,
        })
    }
}
```

Update the call site in `epoch_manager.rs` to pass the validator set and handle the Result type appropriately.

**Additional Defense:** Consider adding on-chain validation in the Move consensus_config module to check proposer addresses against the validator set before accepting the configuration.

## Proof of Concept

```rust
#[cfg(test)]
mod round_proposer_validation_test {
    use super::*;
    use aptos_types::account_address::AccountAddress;
    use std::collections::HashMap;

    #[test]
    #[should_panic(expected = "not in validator set")]
    fn test_non_validator_proposer_rejected() {
        // Validator set with 3 validators
        let validator1 = AccountAddress::random();
        let validator2 = AccountAddress::random();
        let validator3 = AccountAddress::random();
        let validator_set = vec![validator1, validator2, validator3];
        
        // Create mapping with a non-validator
        let non_validator = AccountAddress::random();
        let mut proposers = HashMap::new();
        proposers.insert(1u64, non_validator); // Round 1 -> non-validator
        proposers.insert(2u64, validator1);    // Round 2 -> validator1
        
        // This should fail validation
        let result = RoundProposer::new(
            proposers,
            validator1,
            &validator_set,
        );
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_valid_proposer_mapping_accepted() {
        let validator1 = AccountAddress::random();
        let validator2 = AccountAddress::random();
        let validator_set = vec![validator1, validator2];
        
        let mut proposers = HashMap::new();
        proposers.insert(1u64, validator1);
        proposers.insert(2u64, validator2);
        
        // This should succeed
        let result = RoundProposer::new(
            proposers,
            validator1,
            &validator_set,
        );
        
        assert!(result.is_ok());
    }
    
    #[test]
    #[should_panic(expected = "Default proposer")]
    fn test_invalid_default_proposer_rejected() {
        let validator1 = AccountAddress::random();
        let validator_set = vec![validator1];
        
        let non_validator = AccountAddress::random();
        let proposers = HashMap::new();
        
        // Default proposer not in validator set should fail
        let result = RoundProposer::new(
            proposers,
            non_validator, // Invalid default
            &validator_set,
        );
        
        assert!(result.is_err());
    }
}
```

**Demonstration of Liveness Impact:**

To demonstrate the liveness impact, deploy a local testnet and submit a governance proposal to set `ProposerElectionType::RoundProposer` with a mapping like `{1: 0xDEADBEEF, 2: 0xCAFEBABE}` where these addresses are not validators. Monitor consensus metrics to observe round timeouts when these rounds are reached, confirming that no blocks are produced until the timeout period expires.

### Citations

**File:** consensus/src/liveness/round_proposer_election.rs (L18-23)
```rust
    pub fn new(proposers: HashMap<Round, Author>, default_proposer: Author) -> Self {
        Self {
            proposers,
            default_proposer,
        }
    }
```

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

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```

**File:** consensus/src/liveness/proposer_election.rs (L14-16)
```rust
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L167-171)
```text
        // Blocks can only be produced by a valid proposer or by the VM itself for Nil blocks (no user txs).
        assert!(
            proposer == @vm_reserved || stake::is_current_epoch_validator(proposer),
            error::permission_denied(EINVALID_PROPOSER),
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
