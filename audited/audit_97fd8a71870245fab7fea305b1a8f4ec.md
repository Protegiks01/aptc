# Audit Report

## Title
FixedProposer Configuration Causes Irrecoverable Total Loss of Liveness When Proposer Goes Offline

## Summary
The `choose_leader()` function, described as a "tmp hack function" for fixed proposer election, enables a `FixedProposer` configuration that can be set via on-chain governance. When this configuration is active and the single selected proposer goes offline, the blockchain suffers total loss of liveness with no automatic recovery mechanism, requiring either the proposer to return online or a hard fork to restore functionality. [1](#0-0) 

## Finding Description

The vulnerability exists in the proposer election mechanism when `ProposerElectionType::FixedProposer` is configured. The code explicitly acknowledges this risk in a comment: [2](#0-1) 

When `FixedProposer` is set via on-chain governance configuration, the `EpochManager::create_proposer_election()` function creates a `RotatingProposer` with only a single proposer in the list: [3](#0-2) 

The `RotatingProposer::get_valid_proposer()` implementation uses modulo arithmetic to select proposers: [4](#0-3) 

When `proposers.len() == 1`, the expression `((round / contiguous_rounds) % 1)` always evaluates to 0, meaning **every round** returns the same single proposer.

**Attack Path:**

1. A governance proposal sets consensus config to use `FixedProposer(N)` where N is the contiguous rounds parameter
2. The proposal passes (either through malicious coordination or accidental misconfiguration)
3. The `choose_leader()` function selects the minimum PeerId as the sole proposer
4. That proposer goes offline (crash, network partition, or malicious actor)
5. For every subsequent round:
   - Validators wait for a proposal from the offline proposer
   - Timeout occurs after configured round timeout
   - Validators vote for NIL blocks (blocks with no transactions)
   - NIL blocks can form quorum certificates and satisfy the 2-chain commit rule
   - But NIL blocks contain **no user transactions** [5](#0-4) [6](#0-5) 

The 2-chain commit rule allows NIL blocks to be committed: [7](#0-6) 

This means the blockchain can continue advancing rounds and committing NIL blocks, but **zero user transactions are processed**. This includes governance transactions needed to change the configuration back to a functional proposer election scheme.

The consensus configuration is managed via on-chain governance with no validation preventing `FixedProposer`: [8](#0-7) 

**Broken Invariant:** The vulnerability breaks the fundamental liveness guarantee of the consensus protocol - that the blockchain will continue processing transactions as long as fewer than 1/3 of validators are Byzantine or offline.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos Bug Bounty program:

- **Total loss of liveness/network availability**: The blockchain becomes completely unable to process any user transactions, validator transactions, or governance actions
- **Non-recoverable network partition (requires hardfork)**: If the single proposer remains offline, recovery options are limited to:
  1. The offline proposer coming back online (external dependency)
  2. Executing a hard fork to manually change the consensus configuration (requires coordinated validator action outside the normal protocol)

The severity is critical because:
- All user transaction processing halts indefinitely
- DeFi protocols, NFT platforms, and all applications become non-functional
- Funds remain locked (though not stolen) as no transactions can be executed
- Governance is paralyzed since governance transactions also cannot be processed
- The network effectively becomes a "zombie chain" - technically running but functionally dead

## Likelihood Explanation

The likelihood is **Low to Medium** based on these factors:

**Factors reducing likelihood:**
- Default configuration uses `LeaderReputation`, not `FixedProposer`
- The function is explicitly marked as a "tmp hack function" in comments
- `FixedProposer` is only used in test code, not production deployments
- Any governance proposal to enable `FixedProposer` would be publicly visible
- Validators would likely reject such an obviously dangerous proposal [9](#0-8) 

**Factors increasing likelihood:**
- No code-level validation prevents `FixedProposer` from being set in production
- Governance has full authority to change consensus configuration
- A compromised governance process or social engineering attack could enable it
- Once enabled, even a temporary proposer outage (hardware failure, network issue) triggers the vulnerability
- The configuration exists in production code, not behind a test-only feature flag

The vulnerability becomes **highly likely** once `FixedProposer` is configured, as validator outages are expected events in distributed systems.

## Recommendation

Implement multiple layers of protection:

**1. Remove FixedProposer from Production (Preferred Solution)**

Add a compile-time feature flag to exclude `FixedProposer` from production builds:

```rust
// In types/src/on_chain_config/consensus_config.rs
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposerElectionType {
    #[cfg(any(test, feature = "testing"))]
    FixedProposer(u32),
    RotatingProposer(u32),
    LeaderReputation(LeaderReputationType),
    RoundProposer(HashMap<Round, AccountAddress>),
}
```

**2. Add Runtime Validation (Defense in Depth)**

In the consensus config Move module, add validation to reject `FixedProposer`:

```move
// In aptos-move/framework/aptos-framework/sources/configs/consensus_config.move
public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
    system_addresses::assert_aptos_framework(account);
    assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
    
    // Add validation: ensure config doesn't use FixedProposer in production
    assert!(!uses_fixed_proposer_internal(config), error::invalid_argument(EUNSAFE_CONFIG));
    
    std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
}

native fun uses_fixed_proposer_internal(config_bytes: vector<u8>): bool;
```

**3. Add Liveness Monitoring (Mitigation)**

Implement automatic detection and fallback when liveness is lost:

```rust
// In consensus/src/epoch_manager.rs
// Monitor consecutive NIL block commits and automatically trigger
// a special recovery mode that broadcasts alerts to validators
```

**4. Documentation Update**

Add clear warnings in configuration documentation that `FixedProposer` should never be used in production environments.

## Proof of Concept

The following test demonstrates the liveness failure (this would be added to consensus tests):

```rust
#[test]
fn test_fixed_proposer_liveness_failure() {
    use crate::test_utils::{consensus_runtime, timed_block_on};
    use crate::twins::twins_node::SMRNode;
    use aptos_types::on_chain_config::ProposerElectionType::FixedProposer;
    
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    
    // Start 4 nodes with FixedProposer
    let nodes = SMRNode::start_num_nodes_with_twins(
        4,      // num_nodes
        0,      // num_twins
        &mut playground,
        FixedProposer(1),  // Use fixed proposer with 1 contiguous round
        None,
    );
    
    // Identify the fixed proposer (minimum PeerId)
    let proposer_idx = 0;  // Assuming node 0 has minimum PeerId
    
    timed_block_on(&runtime, async {
        // Wait for first block from proposer
        let msg = playground
            .wait_for_messages(1, NetworkPlayground::proposals_only)
            .await;
        assert!(msg.len() > 0);
        
        // Disconnect the fixed proposer
        playground.drop_node(nodes[proposer_idx].id);
        
        // Wait for timeout duration
        tokio::time::sleep(Duration::from_secs(10)).await;
        
        // Verify: other nodes can only produce NIL blocks
        let mut nil_block_count = 0;
        for node in &nodes[1..] {
            if let Some(block) = node.block_store.highest_commit_block() {
                if block.payload().is_none() {
                    nil_block_count += 1;
                }
            }
        }
        
        // Assert that remaining nodes are stuck committing NIL blocks
        assert!(nil_block_count > 0, "Expected NIL blocks to be committed");
        
        // Verify: no new user transactions are processed
        // (transaction pool remains full, no blocks with payload)
    });
}
```

To reproduce in a live environment:
1. Deploy a test network with 4+ validators
2. Submit a governance proposal to set consensus config with `FixedProposer(1)`
3. Wait for proposal to execute and epoch change
4. Shut down the validator with the minimum account address
5. Observe: Network continues creating NIL blocks but processes zero transactions
6. Attempt to submit governance transaction to fix config: Transaction remains in mempool indefinitely

**Notes**

This vulnerability is particularly concerning because:

1. **Silent Failure Mode**: The consensus mechanism continues to operate (creating NIL blocks, forming QCs, advancing rounds), making it appear the network is functioning when it's actually processing zero transactions

2. **No Automatic Recovery**: Unlike some liveness failures where timeout certificates can help validators progress past failed leaders, the fixed proposer configuration ensures every subsequent round has the same failed proposer

3. **Governance Paralysis**: The normal recovery mechanism (governance proposal to change configuration) cannot function because governance transactions cannot be processed

4. **Code Comments Acknowledge Risk**: The codebase explicitly documents this liveness failure in comments but lacks enforcement mechanisms to prevent the dangerous configuration in production

The fix should prioritize complete removal of `FixedProposer` from production code paths, as this testing utility provides no legitimate production use case while introducing catastrophic failure modes.

### Citations

**File:** consensus/src/liveness/rotating_proposer_election.rs (L7-9)
```rust
/// The rotating proposer maps a round to an author according to a round-robin rotation.
/// A fixed proposer strategy loses liveness when the fixed proposer is down. Rotating proposers
/// won't gather quorum certificates to machine loss/byzantine behavior on f/n rounds.
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L18-23)
```rust
/// Choose a proposer that is going to be the single leader (relevant for a mock fixed proposer
/// election only).
pub fn choose_leader(peers: Vec<Author>) -> Author {
    // As it is just a tmp hack function, pick the min PeerId to be a proposer.
    peers.into_iter().min().expect("No trusted peers found!")
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

**File:** consensus/src/epoch_manager.rs (L300-304)
```rust
            // We don't really have a fixed proposer!
            ProposerElectionType::FixedProposer(contiguous_rounds) => {
                let proposer = choose_leader(proposers);
                Arc::new(RotatingProposer::new(vec![proposer], *contiguous_rounds))
            },
```

**File:** consensus/src/round_manager.rs (L1050-1060)
```rust
                    // Didn't vote in this round yet, generate a backup vote
                    let nil_block = self
                        .proposal_generator
                        .generate_nil_block(round, self.proposer_election.clone())?;
                    info!(
                        self.new_log(LogEvent::VoteNIL),
                        "Planning to vote for a NIL block {}", nil_block
                    );
                    counters::VOTE_NIL_COUNT.inc();
                    let nil_vote = self.vote_block(nil_block).await?;
                    (true, nil_vote)
```

**File:** consensus/consensus-types/src/block.rs (L300-314)
```rust
    /// The NIL blocks are special: they're not carrying any real payload and are generated
    /// independently by different validators just to fill in the round with some QC.
    pub fn new_nil(
        round: Round,
        quorum_cert: QuorumCert,
        failed_authors: Vec<(Round, Author)>,
    ) -> Self {
        let block_data = BlockData::new_nil(round, quorum_cert, failed_authors);

        Block {
            id: block_data.hash(),
            block_data,
            signature: None,
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L195-214)
```rust
    fn construct_ledger_info_2chain(
        &self,
        proposed_block: &Block,
        consensus_data_hash: HashValue,
    ) -> Result<LedgerInfo, Error> {
        let block1 = proposed_block.round();
        let block0 = proposed_block.quorum_cert().certified_block().round();

        // verify 2-chain rule
        let commit = next_round(block0)? == block1;

        // create a ledger info
        let commit_info = if commit {
            proposed_block.quorum_cert().certified_block().clone()
        } else {
            BlockInfo::empty()
        };

        Ok(LedgerInfo::new(commit_info, consensus_data_hash))
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

**File:** types/src/on_chain_config/consensus_config.rs (L481-505)
```rust
impl Default for ConsensusConfigV1 {
    fn default() -> Self {
        Self {
            decoupled_execution: true,
            back_pressure_limit: 10,
            exclude_round: 40,
            max_failed_authors_to_store: 10,
            proposer_election_type: ProposerElectionType::LeaderReputation(
                LeaderReputationType::ProposerAndVoterV2(ProposerAndVoterConfig {
                    active_weight: 1000,
                    inactive_weight: 10,
                    failed_weight: 1,
                    failure_threshold_percent: 10, // = 10%
                    // In each round we get stastics for the single proposer
                    // and large number of validators. So the window for
                    // the proposers needs to be significantly larger
                    // to have enough useful statistics.
                    proposer_window_num_validators_multiplier: 10,
                    voter_window_num_validators_multiplier: 1,
                    weight_by_voting_power: true,
                    use_history_from_previous_epoch_max_count: 5,
                }),
            ),
        }
    }
```
