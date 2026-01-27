# Audit Report

## Title
Block Transaction Filter Enables Validator Discrimination Through Unvalidated Block Author Matching

## Summary
The `BlockTransactionFilter` system allows validators to configure filters that discriminate against block proposals from specific validators by matching on `block_author`. When combined with consensus voting logic, this creates an unfair competitive advantage where malicious validators can silently reduce the success rate and rewards of targeted validators without any validation, monitoring, or governance oversight.

## Finding Description

The block transaction filtering system contains a `BlockMatcher::Author(AccountAddress)` variant that allows filtering based on the block proposer's address. [1](#0-0) 

When a validator receives a block proposal, the `allows_transaction()` function is called with the `block_author` parameter, which is then matched against configured filter rules. [2](#0-1) 

The block author matching logic explicitly checks if the proposal author matches a target address. [3](#0-2) 

During consensus proposal processing, validators call `check_denied_inline_transactions()` which uses the filter to check if any inline transactions should be denied. [4](#0-3) 

If the filter detects denied transactions, the validator refuses to vote on the proposal and drops it entirely. [5](#0-4) 

**Attack Scenario:**

A malicious validator can configure their node with a discriminatory filter in their `NodeConfig`: [6](#0-5) 

The filter configuration has no validation to prevent author-based discrimination: [7](#0-6) 

The test suite demonstrates that author-based filtering is fully functional and can be used to deny all transactions from specific block authors. [8](#0-7) 

**Exploitation Path:**

1. Malicious validator V1 identifies a competing validator V2
2. V1 configures their node with: `BlockTransactionFilter::empty().add_block_author_filter(false, V2_address)`
3. When V2 proposes a block, V1's node automatically rejects it and refuses to vote
4. V2 needs more rounds to achieve quorum (>2/3 votes), reducing their success rate
5. V2 receives fewer block rewards and lower reputation metrics
6. Multiple validators (<1/3) can collude to significantly harm V2 without breaking consensus safety
7. This discrimination is silent and undetectable on-chain

## Impact Explanation

**Medium Severity** - This vulnerability fits the "Limited funds loss or manipulation" category from the Aptos bug bounty program:

1. **Economic Harm**: Targeted validators receive reduced block proposal rewards due to increased rejection rates
2. **Competitive Advantage**: Malicious validators gain unfair advantages by suppressing competitors
3. **Centralization Risk**: Systematic discrimination can drive smaller validators out of the network
4. **No Consensus Safety Violation**: The attack requires <1/3 Byzantine validators to avoid breaking BFT safety guarantees
5. **Protocol Fairness Violation**: While consensus safety is maintained, the fairness assumption (all honest validators have equal opportunity) is violated

The impact is limited because:
- Consensus safety remains intact (requires >2/3 votes for commitment)
- Network liveness continues (other validators can still propose and commit blocks)
- No direct fund theft or minting

However, it enables systematic economic discrimination against specific validators.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Easy to Execute**: Requires only modifying the node configuration file
2. **No Technical Barriers**: The filtering mechanism is fully implemented and tested
3. **Silent Operation**: Discrimination happens locally without on-chain visibility
4. **No Detection Mechanism**: Victim validators cannot easily detect they're being discriminated against
5. **Economic Incentive**: Validators have financial motivation to reduce competition
6. **No Governance Control**: No on-chain voting or oversight required to configure discriminatory filters

The only barrier is that the attacker must be an active validator, but the question explicitly explores validator-level threats.

## Recommendation

**Immediate Fix**: Remove the ability to filter based on `block_author` in consensus filters, or add strict validation:

```rust
// In config/src/config/config_sanitizer.rs
impl ConfigSanitizer for BlockTransactionFilterConfig {
    fn sanitize(
        &mut self,
        _node_type: NodeType,
        _role: RoleType,
    ) -> Result<(), Error> {
        if !self.is_enabled() {
            return Ok(());
        }
        
        // Validate that consensus filters don't discriminate by block author
        for rule in &self.block_transaction_filter.block_transaction_rules {
            let matchers = match rule {
                BlockTransactionRule::Allow(m) | BlockTransactionRule::Deny(m) => m,
            };
            
            for matcher in matchers {
                if let BlockTransactionMatcher::Block(BlockMatcher::Author(_)) = matcher {
                    return Err(Error::ConfigSanitizerFailed(
                        "consensus_filter".to_string(),
                        "Block author filtering is not allowed in consensus filters".to_string(),
                    ));
                }
            }
        }
        
        Ok(())
    }
}
```

**Additional Recommendations**:
1. Make filter configurations auditable on-chain or through monitoring systems
2. Implement governance controls for sensitive filter rules
3. Remove test-only functions like `add_block_author_filter` from production builds
4. Add metrics to detect validators consistently rejecting proposals from specific authors
5. Document the intended use cases for block-level matchers and restrict them accordingly

## Proof of Concept

The test suite already demonstrates the vulnerability mechanism. [8](#0-7) 

**Configuration-based PoC:**

```rust
// In a validator's node configuration file:
use aptos_config::config::{BlockTransactionFilterConfig, NodeConfig};
use aptos_transaction_filters::block_transaction_filter::{
    BlockTransactionFilter, BlockMatcher, BlockTransactionMatcher
};
use move_core_types::account_address::AccountAddress;

// Target validator to discriminate against
let target_validator = AccountAddress::from_hex_literal("0xTARGET_VALIDATOR_ADDRESS").unwrap();

// Create filter that denies ALL blocks from the target validator
let discriminatory_filter = BlockTransactionFilter::empty()
    .add_multiple_matchers_filter(
        false,  // Deny
        vec![BlockTransactionMatcher::Block(BlockMatcher::Author(target_validator))]
    )
    .add_all_filter(true);  // Allow everything else

// Apply to consensus filter
node_config.transaction_filters.consensus_filter = 
    BlockTransactionFilterConfig::new(true, discriminatory_filter);
```

When this validator receives any block proposal from `target_validator`, it will automatically reject it and refuse to vote, reducing the target's block success rate and rewards. This can be verified by monitoring consensus metrics showing vote patterns.

## Notes

This vulnerability is particularly concerning because:

1. The filtering capability exists with full test coverage, suggesting it may have been intentionally designed, but without proper safeguards against abuse
2. There is no validation in `ConfigSanitizer` to prevent discriminatory rules
3. The impact scales with the number of colluding validators (up to the <1/3 Byzantine threshold)
4. Detection is difficult without specific monitoring for voting patterns
5. While block author filtering might have legitimate uses (e.g., emergency response to a misbehaving validator), the lack of governance oversight makes it vulnerable to abuse

### Citations

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L28-59)
```rust
    /// Returns true iff the filter allows the transaction in the block
    pub fn allows_transaction(
        &self,
        block_id: HashValue,
        block_author: Option<AccountAddress>,
        block_epoch: u64,
        block_timestamp: u64,
        signed_transaction: &SignedTransaction,
    ) -> bool {
        // If the filter is empty, allow the transaction by default
        if self.is_empty() {
            return true;
        }

        // Check if any rule matches the block transaction
        for block_transaction_rule in &self.block_transaction_rules {
            if block_transaction_rule.matches(
                block_id,
                block_author,
                block_epoch,
                block_timestamp,
                signed_transaction,
            ) {
                return match block_transaction_rule {
                    BlockTransactionRule::Allow(_) => true,
                    BlockTransactionRule::Deny(_) => false,
                };
            }
        }

        true // No rules match (allow the block transaction by default)
    }
```

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L252-260)
```rust
pub enum BlockMatcher {
    All,                            // Matches any block
    Author(AccountAddress),         // Matches blocks proposed by the specified author
    BlockId(HashValue),             // Matches blocks with the specified ID
    BlockEpochGreaterThan(u64),     // Matches blocks with epochs greater than the specified value
    BlockEpochLessThan(u64),        // Matches blocks with epochs less than the specified value
    BlockTimeStampGreaterThan(u64), // Matches blocks with timestamps greater than the specified value
    BlockTimeStampLessThan(u64),    // Matches blocks with timestamps less than the specified value
}
```

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L293-303)
```rust
/// Returns true iff the block author matches the target author.
/// Note: if the block author is None, it does not match the target author.
fn matches_block_author(
    block_author: Option<AccountAddress>,
    target_author: &AccountAddress,
) -> bool {
    match block_author {
        Some(block_author) => block_author == *target_author,
        None => false,
    }
}
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L308-347)
```rust
    fn check_denied_inline_transactions(
        &self,
        block: &Block,
        block_txn_filter_config: &BlockTransactionFilterConfig,
    ) -> anyhow::Result<()> {
        // If the filter is disabled, return early
        if !block_txn_filter_config.is_enabled() {
            return Ok(());
        }

        // Get the inline transactions for the block proposal
        let inline_transactions = get_inline_transactions(block);
        if inline_transactions.is_empty() {
            return Ok(());
        }

        // Fetch the block metadata
        let block_id = block.id();
        let block_author = block.author();
        let block_epoch = block.epoch();
        let block_timestamp = block.timestamp_usecs();

        // Identify any denied inline transactions
        let block_transaction_filter = block_txn_filter_config.block_transaction_filter();
        let denied_inline_transactions = block_transaction_filter.get_denied_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp,
            inline_transactions,
        );
        if !denied_inline_transactions.is_empty() {
            return Err(anyhow::anyhow!(
                "Inline transactions for QuorumStorePayload denied by block transaction filter: {:?}",
                denied_inline_transactions
            ));
        }

        Ok(()) // No transactions were denied
    }
```

**File:** consensus/src/round_manager.rs (L1202-1214)
```rust
        // If the proposal contains any inline transactions that need to be denied
        // (e.g., due to filtering) drop the message and do not vote for the block.
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

**File:** config/src/config/node_config_loader.rs (L72-90)
```rust
    pub fn load_and_sanitize_config(&self) -> Result<NodeConfig, Error> {
        // Load the node config from disk
        let mut node_config = NodeConfig::load_config(&self.node_config_path)?;

        // Load the execution config
        let input_dir = RootPath::new(&self.node_config_path);
        node_config.execution.load_from_path(&input_dir)?;

        // Update the data directory. This needs to be done before
        // we optimize and sanitize the node configs (because some optimizers
        // rely on the data directory for file reading/writing).
        node_config.set_data_dir(node_config.get_data_dir().to_path_buf());

        // Optimize and sanitize the node config
        let local_config_yaml = get_local_config_yaml(&self.node_config_path)?;
        optimize_and_sanitize_node_config(&mut node_config, local_config_yaml)?;

        Ok(node_config)
    }
```

**File:** crates/aptos-transaction-filters/src/tests/block_transaction_filter.rs (L48-124)
```rust
#[test]
fn test_block_author_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a block ID, author, epoch, and timestamp
        let (block_id, block_author, block_epoch, block_timestamp) = utils::get_random_block_info();

        // Create a filter that only allows transactions with a specific block author
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = BlockTransactionFilter::empty()
            .add_block_author_filter(true, block_author)
            .add_all_filter(false);

        // Verify that the filter allows transactions with the specified block author
        verify_all_transactions_allowed(
            filter.clone(),
            block_id,
            Some(block_author),
            block_epoch,
            block_timestamp,
            transactions.clone(),
        );

        // Verify that the filter denies transactions with a different block author
        let different_block_author = AccountAddress::random();
        verify_all_transactions_rejected(
            filter.clone(),
            block_id,
            Some(different_block_author),
            block_epoch,
            block_timestamp,
            transactions.clone(),
        );

        // Verify that the filter denies transactions with a missing block author
        verify_all_transactions_rejected(
            filter.clone(),
            block_id,
            None,
            block_epoch,
            block_timestamp,
            transactions.clone(),
        );

        // Create a filter that denies transactions with a specific block author
        let filter = BlockTransactionFilter::empty().add_block_author_filter(false, block_author);

        // Verify that the filter denies transactions with the specified block author
        verify_all_transactions_rejected(
            filter.clone(),
            block_id,
            Some(block_author),
            block_epoch,
            block_timestamp,
            transactions.clone(),
        );

        // Verify that the filter allows transactions with a different block author
        verify_all_transactions_allowed(
            filter.clone(),
            block_id,
            Some(different_block_author),
            block_epoch,
            block_timestamp,
            transactions.clone(),
        );

        // Verify that the filter allows transactions with a missing block author
        verify_all_transactions_allowed(
            filter.clone(),
            block_id,
            None,
            block_epoch,
            block_timestamp,
            transactions.clone(),
        );
    }
}
```
