# Audit Report

## Title
Inconsistent Transaction Filter Configurations Across Validators Can Cause Consensus Liveness Failures

## Summary
Transaction filters (`BlockTransactionFilter`) are loaded from local node configuration files and are not synchronized across validators. This allows validators to have different filter states, leading to disagreements on block proposal validity and potential consensus liveness failures.

## Finding Description

The `BlockTransactionFilter` configuration is sourced from local node configuration files rather than on-chain consensus parameters, creating a potential for inconsistent filter states across validators.

**Critical Code Paths:**

1. **Filter Initialization** - Each validator loads its filter from local config: [1](#0-0) 

2. **Filter Usage in Proposal Validation** - Validators reject proposals containing transactions denied by their local filter: [2](#0-1) 

3. **Filter Structure** - The filter is not part of on-chain configuration: [3](#0-2) 

4. **Separate Consensus and Execution Filters** - Two independent filters exist: [4](#0-3) 

**Vulnerability Mechanism:**

When validators have different `consensus_filter` configurations:
- Validator A configures a filter denying transactions from address X
- Validator B has no such filter  
- Validator B proposes a block including transaction from X
- Validator A receives the proposal and checks against its filter
- Validator A rejects the proposal and refuses to vote
- If sufficient validators have conflicting filters, blocks cannot achieve 2/3+ quorum

**Invariant Violation:**

This breaks the **Consensus Safety** and **Deterministic Execution** invariants - validators must agree on which transactions belong in valid blocks for consensus to function correctly.

## Impact Explanation

**Severity: High** (up to $50,000 per bug bounty criteria)

The impact is classified as "Significant protocol violations" causing:
- **Consensus liveness failures**: Network cannot make progress if validators cannot agree on valid proposals
- **Validator node operational issues**: Proposals are incorrectly rejected, causing round timeouts
- **Non-deterministic block validation**: Different validators apply different validation rules

While this doesn't directly cause fund loss or permanent network partition, it creates operational failures requiring coordinated manual intervention to resolve filter inconsistencies.

## Likelihood Explanation

**Likelihood: Medium-Low**

This vulnerability requires:
- Configuration errors or intentional divergence by validator operators
- No automated synchronization mechanisms exist to detect filter inconsistencies
- The test suite only validates scenarios where all validators have identical filters [5](#0-4) 

However, likelihood is reduced because:
- Validator operators are trusted parties expected to coordinate configurations
- The issue is limited to operational misconfigurations rather than exploitable bugs
- Filters are typically disabled by default

## Recommendation

**Option 1: Move filters to on-chain configuration (Recommended)**
- Store transaction filter rules as on-chain consensus parameters
- Synchronize via reconfiguration events at epoch boundaries
- Ensures all validators automatically have identical filters

**Option 2: Add validation checks**
- Implement filter hash/checksum exchange during epoch startup
- Validators verify they have matching filter configurations
- Reject epoch participation if filters diverge

**Option 3: Disable or deprecate local filters**
- Remove support for local transaction filters in consensus validation
- Rely exclusively on on-chain governance for transaction restrictions
- Simplifies system and eliminates configuration inconsistency risks

**Implementation sketch for Option 1:**
```rust
// Add filter hash to OnChainConsensusConfig
pub struct OnChainConsensusConfig {
    // ... existing fields
    pub transaction_filter_hash: Option<HashValue>,
}

// Validate filter consistency at epoch start
fn validate_filter_consistency(
    local_filter: &BlockTransactionFilter,
    onchain_hash: &HashValue
) -> Result<()> {
    let local_hash = CryptoHash::hash(local_filter);
    ensure!(local_hash == *onchain_hash, 
        "Local filter does not match on-chain consensus filter");
    Ok(())
}
```

## Proof of Concept

```rust
// Add to consensus/src/round_manager_tests/txn_filter_proposal_test.rs

#[tokio::test]
async fn test_inconsistent_filters_across_validators() {
    // Validator 1 has filter denying address X
    let denied_address = AccountAddress::random();
    let filter_v1 = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![
            BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(denied_address)
            )
        ])
        .add_all_filter(true);
    
    // Validator 2 has no filter
    let filter_v2 = BlockTransactionFilter::empty();
    
    // Create proposal with transaction from denied_address
    let txn = create_signed_transaction_from(denied_address);
    let proposal = create_proposal_with_transactions(vec![txn]);
    
    // Validator 1 rejects proposal
    let config_v1 = BlockTransactionFilterConfig::new(true, filter_v1);
    let result_v1 = check_denied_inline_transactions(&proposal, &config_v1);
    assert!(result_v1.is_err()); // Validator 1 rejects
    
    // Validator 2 accepts proposal  
    let config_v2 = BlockTransactionFilterConfig::new(true, filter_v2);
    let result_v2 = check_denied_inline_transactions(&proposal, &config_v2);
    assert!(result_v2.is_ok()); // Validator 2 accepts
    
    // Consensus failure: validators disagree on proposal validity
}
```

## Notes

While this issue represents a design limitation rather than an exploitable vulnerability by untrusted actors, it creates operational risks and violates the principle that consensus rules should be deterministic and synchronized across all validators. The severity is reduced because it requires trusted validator operators to create the inconsistency through misconfiguration rather than being exploitable by external attackers.

### Citations

**File:** consensus/src/epoch_manager.rs (L211-211)
```rust
        let consensus_txn_filter_config = node_config.transaction_filters.consensus_filter.clone();
```

**File:** consensus/src/round_manager.rs (L1204-1214)
```rust
        if let Err(error) = self
            .block_store
            .check_denied_inline_transactions(&proposal, &self.block_txn_filter_config)
        {
            counters::REJECTED_PROPOSAL_DENY_TXN_COUNT.inc();
            bail!(
                "[RoundManager] Proposal for block {} contains denied inline transactions: {}. Dropping proposal!",
                proposal.id(),
                error
            );
        }
```

**File:** config/src/config/transaction_filters_config.rs (L10-18)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFiltersConfig {
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
}
```

**File:** config/src/config/transaction_filters_config.rs (L90-114)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlockTransactionFilterConfig {
    filter_enabled: bool, // Whether the filter is enabled
    block_transaction_filter: BlockTransactionFilter, // The block transaction filter to apply
}

impl BlockTransactionFilterConfig {
    pub fn new(filter_enabled: bool, block_transaction_filter: BlockTransactionFilter) -> Self {
        Self {
            filter_enabled,
            block_transaction_filter,
        }
    }

    /// Returns true iff the filter is enabled and not empty
    pub fn is_enabled(&self) -> bool {
        self.filter_enabled && !self.block_transaction_filter.is_empty()
    }

    /// Returns a reference to the block transaction filter
    pub fn block_transaction_filter(&self) -> &BlockTransactionFilter {
        &self.block_transaction_filter
    }
}
```

**File:** testsuite/smoke-test/src/transaction_filter.rs (L40-53)
```rust
    let mut swarm = SwarmBuilder::new_local(3)
        .with_aptos()
        .with_init_config(Arc::new(move |_, config, _| {
            filter_inline_transactions(config, sender_address);
        }))
        .with_init_genesis_config(Arc::new(|genesis_config| {
            genesis_config.consensus_config = OnChainConsensusConfig::V4 {
                alg: ConsensusAlgorithmConfig::default_with_quorum_store_disabled(),
                vtxn: ValidatorTxnConfig::default_for_genesis(),
                window_size: DEFAULT_WINDOW_SIZE,
            };
        }))
        .build()
        .await;
```
