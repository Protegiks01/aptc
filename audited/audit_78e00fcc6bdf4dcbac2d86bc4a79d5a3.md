# Audit Report

## Title
Missing Validator Set Validation in RoundProposer Constructor Enables Consensus Liveness Attack

## Summary
The `RoundProposer::new()` constructor accepts arbitrary `AccountAddress` values in both the `proposers` HashMap and `default_proposer` parameter without verifying that these addresses correspond to actual validators in the validator set. This missing validation allows governance to configure invalid proposers, causing network liveness failures when those rounds are reached.

## Finding Description

The vulnerability exists across two critical points in the consensus configuration system:

**1. Constructor Validation Gap:** [1](#0-0) 

The `RoundProposer::new()` constructor directly accepts and stores the proposers HashMap and default_proposer without any validation.

**2. On-Chain Config Validation Gap:** [2](#0-1) 

The `set_for_next_epoch()` function only validates that the config is non-empty, but performs no semantic validation of the proposer addresses within the configuration.

**3. Configuration Instantiation:** [3](#0-2) 

When creating a RoundProposer instance, the `round_proposers` HashMap comes directly from on-chain config without validation against the validator set obtained from `epoch_state.verifier`.

**Attack Propagation:**

1. Governance calls `consensus_config::set_for_next_epoch()` with a configuration containing `ProposerElectionType::RoundProposer(round_proposers)` where addresses in the HashMap are not in the validator set
2. The configuration passes validation (only checks length > 0)
3. During epoch transition, `EpochManager::create_proposer_election()` creates a `RoundProposer` with these invalid addresses
4. When a round is reached where an invalid proposer is designated:
   - [4](#0-3)  returns the invalid address
   - [5](#0-4)  rejects proposals from actual validators
   - If someone attempts to propose from the invalid address, [6](#0-5)  fails signature verification because the address has no corresponding private key
   - The round times out with no valid proposal

**Broken Invariant:** This violates the **Consensus Liveness** requirement that the network must make progress under normal conditions with honest majority.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program for the following reasons:

- **Total loss of liveness/network availability**: By configuring multiple consecutive rounds with invalid proposers, an attacker can effectively halt block production, preventing any transactions from being processed.
- **Non-recoverable network partition**: Recovery requires governance intervention to update the consensus configuration, but if the configuration causes persistent liveness failures, governance proposals themselves may not be able to execute.

The test file demonstrates that arbitrary addresses are accepted without validation: [7](#0-6) 

## Likelihood Explanation

**Likelihood: Medium-High**

While this requires governance access (aptos_framework signer), the likelihood is elevated because:

1. **Accidental Misconfiguration**: Legitimate governance proposals could contain bugs in address mapping, causing unintentional liveness failures
2. **Governance Compromise**: If governance is compromised (through voting power manipulation or other means), this provides a direct DoS vector
3. **No Defense-in-Depth**: The complete absence of validation means a single error in governance proposal generation causes network-wide impact
4. **Easy to Execute**: Once governance access is obtained, the attack is trivial - simply submit a config with invalid addresses

## Recommendation

Implement validation in both the Rust constructor and the Move configuration setter:

**Rust-side validation in `RoundProposer::new()`:**
```rust
pub fn new(
    proposers: HashMap<Round, Author>,
    default_proposer: Author,
    validator_addresses: &HashSet<AccountAddress>,  // Add validator set parameter
) -> Result<Self> {
    // Validate default proposer
    ensure!(
        validator_addresses.contains(&default_proposer),
        "default_proposer must be in validator set"
    );
    
    // Validate all proposers in HashMap
    for (round, proposer) in &proposers {
        ensure!(
            validator_addresses.contains(proposer),
            "proposer for round {} is not in validator set", round
        );
    }
    
    Ok(Self {
        proposers,
        default_proposer,
    })
}
```

**Update `EpochManager::create_proposer_election()`:**
```rust
ProposerElectionType::RoundProposer(round_proposers) => {
    let validator_set: HashSet<_> = proposers.iter().copied().collect();
    let default_proposer = proposers
        .first()
        .expect("INVARIANT VIOLATION: proposers is empty");
    
    // Validate before construction
    Arc::new(RoundProposer::new(
        round_proposers.clone(),
        *default_proposer,
        &validator_set,
    ).expect("Invalid RoundProposer configuration"))
}
```

**Move-side validation (defense-in-depth):**

Add validation native function in `consensus_config.move` to check proposer addresses against the current validator set before accepting the configuration.

## Proof of Concept

**Scenario: Governance Misconfiguration Leading to Network Halt**

```rust
// In epoch_manager_tests.rs or similar test file

#[test]
fn test_invalid_round_proposer_causes_liveness_failure() {
    // Setup: Create validator set with 4 validators
    let validator_signers = ValidatorSigners::new(vec![
        AccountAddress::from_hex_literal("0x1").unwrap(),
        AccountAddress::from_hex_literal("0x2").unwrap(),
        AccountAddress::from_hex_literal("0x3").unwrap(),
        AccountAddress::from_hex_literal("0x4").unwrap(),
    ]);
    
    // Attack: Configure RoundProposer with invalid address
    let mut round_proposers = HashMap::new();
    let invalid_address = AccountAddress::from_hex_literal("0xDEADBEEF").unwrap();
    
    // Round 1 has invalid proposer
    round_proposers.insert(1, invalid_address);
    
    // This construction succeeds without validation
    let proposer_election = RoundProposer::new(
        round_proposers,
        validator_signers.get_signers()[0].author(),
    );
    
    // Impact: When round 1 is reached
    let round_1_proposer = proposer_election.get_valid_proposer(1);
    assert_eq!(round_1_proposer, invalid_address);
    
    // None of the actual validators are valid proposers for round 1
    for signer in validator_signers.get_signers() {
        assert!(!proposer_election.is_valid_proposer(signer.author(), 1));
    }
    
    // Result: Round 1 will timeout - no valid validator can propose
    // Network liveness is compromised
}
```

**Notes:**

This vulnerability represents a critical gap in defense-in-depth validation. While governance is a trusted component, security best practices dictate that all inputs should be validated, especially those affecting consensus. The complete absence of validation means accidental misconfigurations or governance-level compromises can directly cause network-wide liveness failures without any safety checks.

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

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
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

**File:** consensus/src/liveness/proposer_election.rs (L14-16)
```rust
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }
```

**File:** consensus/consensus-types/src/block.rs (L425-439)
```rust
    pub fn validate_signature(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        match self.block_data.block_type() {
            BlockType::Genesis => bail!("We should not accept genesis from others"),
            BlockType::NilBlock { .. } => self.quorum_cert().verify(validator),
            BlockType::Proposal { author, .. } => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or_else(|| format_err!("Missing signature in Proposal"))?;
                let (res1, res2) = rayon::join(
                    || validator.verify(*author, &self.block_data, signature),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
```

**File:** consensus/src/liveness/round_proposer_test.rs (L13-22)
```rust
    let chosen_author_round1 = AccountAddress::random();
    let chosen_author_round2 = AccountAddress::random();
    let another_author = AccountAddress::random();

    // A map that specifies the proposer per round
    let mut round_proposers: HashMap<Round, Author> = HashMap::new();
    round_proposers.insert(1, chosen_author_round1);
    round_proposers.insert(2, chosen_author_round2);

    let pe = RoundProposer::new(round_proposers, chosen_author_round1);
```
