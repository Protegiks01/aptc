# Audit Report

## Title
Byzantine Validators Can Selectively Censor Transactions via Mismatched Block Transaction Filters

## Summary
Byzantine validators can exploit per-node `BlockTransactionFilterConfig` settings to selectively censor transactions from specific senders while appearing to follow legitimate protocol rules. The vulnerability arises because filter configurations are not consensus-enforced, allowing malicious validators to reject valid blocks containing targeted transactions without detection or penalty.

## Finding Description

The Aptos consensus protocol implements a transaction filtering mechanism through `BlockTransactionFilterConfig`, which is configured independently by each validator node. During block proposal processing, the `check_denied_inline_transactions()` function is invoked to verify that proposals don't contain filtered transactions. [1](#0-0) 

The filter configuration is loaded from each node's local configuration file and stored in the `RoundManager`: [2](#0-1) 

During proposal processing, the `RoundManager` calls `check_denied_inline_transactions()` BEFORE deciding to vote on a block: [3](#0-2) 

The critical vulnerability is that filter configurations are **not part of on-chain consensus state** and are **not synchronized across validators**: [4](#0-3) 

**Attack Scenario:**

1. A Byzantine validator configures their local `consensus_filter` to deny transactions from specific sender addresses using `TransactionMatcher::Sender`
2. The filter rules can match on sender addresses, public keys, module addresses, or other transaction properties
3. When the Byzantine validator is the block proposer, they naturally exclude these transactions from their proposals
4. When honest validators propose blocks containing these transactions, the Byzantine validator invokes `check_denied_inline_transactions()`, which returns an error
5. The Byzantine validator refuses to vote for the block, appearing to follow protocol by "filtering invalid transactions"
6. With f Byzantine validators (where 3f+1 is the total), they can prevent any block containing the censored transactions from achieving 2f+1 votes
7. The targeted transactions can never be committed to the blockchain

The attack is undetectable because:
- No validator knows what filters other validators have configured
- No consensus-level mechanism validates filter consistency
- The rejection appears as legitimate filtering, not malicious behavior
- No slashing or penalties can be applied

This breaks the **transaction liveness invariant**: with <1/3 Byzantine validators, the protocol should guarantee that valid transactions eventually commit. However, this vulnerability allows permanent censorship of specific transactions. [5](#0-4) 

The filter matching logic supports targeting specific senders: [6](#0-5) 

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Significant protocol violations."

The attack enables:
1. **Targeted censorship** of specific users/addresses by Byzantine validators
2. **Liveness violation** for targeted transactions despite <1/3 Byzantine fault tolerance
3. **Undetectable attack** - Byzantine validators appear protocol-compliant
4. **No accountability** - no slashing or penalties possible since behavior appears legitimate
5. **Denial of service** against specific users without affecting network-wide availability

The impact is limited by the Byzantine fault tolerance threshold - attackers need validator status with sufficient voting power. However, the protocol claims Byzantine fault tolerance specifically to defend against malicious validators, making this a clear protocol violation.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:
1. **Simple exploitation** - only requires editing node configuration YAML file
2. **No special capabilities** - any validator can configure arbitrary filters
3. **No coordination required** - single Byzantine validator can censor if they have >1/3 voting power, or small collusion is sufficient
4. **Zero detection risk** - no mechanism exists to detect filter mismatches
5. **No cost** - no stake slashing or penalties
6. **Deniability** - validator can claim they're filtering spam/malicious transactions
7. **Intentional design** - the filtering mechanism exists and is well-tested, just lacks synchronization enforcement

The smoke tests demonstrate that the filtering mechanism is functional and intentionally designed: [7](#0-6) 

However, all validators in the test are configured with identical filters, suggesting the design assumes filter synchronization - an assumption not enforced in production.

## Recommendation

**Option 1: Consensus-Enforce Filter Configuration (Preferred)**
1. Make `BlockTransactionFilterConfig` part of on-chain consensus configuration (similar to `OnChainConsensusConfig`)
2. Store filter configuration in blockchain state and update via governance proposals
3. All validators must use the same filter configuration in each epoch
4. Verify filter consistency during epoch initialization

**Option 2: Remove Filter from Voting Path**
1. Remove the `check_denied_inline_transactions()` call from `RoundManager::process_proposal()`
2. Apply filters only during block execution, not proposal voting
3. This ensures Byzantine validators cannot use filters to reject valid proposals
4. Filtered transactions would still be excluded from execution but wouldn't affect voting

**Option 3: Detection and Monitoring**
1. Add validator reputation tracking for proposal rejections
2. Log detailed reasons when proposals are rejected with denied transactions
3. Monitor for validators that consistently reject valid proposals
4. Implement automated alerts for suspicious filter-based rejections

The preferred solution is Option 1, as it maintains the filtering functionality while ensuring all validators operate under the same rules.

## Proof of Concept

The existing test demonstrates the filtering mechanism works as designed: [8](#0-7) 

To demonstrate the vulnerability, modify the test to create two validators with **different** filter configurations:

```rust
// Validator 1: No filter (default configuration)
let honest_validator = create_validator_with_filter(BlockTransactionFilterConfig::default());

// Validator 2: Filters transactions from specific sender (Byzantine behavior)
let target_sender = transactions[0].sender();
let byzantine_filter = BlockTransactionFilter::empty()
    .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
        TransactionMatcher::Sender(target_sender),
    )])
    .add_all_filter(true);
let byzantine_validator = create_validator_with_filter(
    BlockTransactionFilterConfig::new(true, byzantine_filter)
);

// Honest validator proposes block with all transactions
let proposal = honest_validator.create_proposal(transactions);

// Byzantine validator rejects the proposal
assert!(byzantine_validator.process_proposal(proposal).await.is_err());

// Result: Block cannot achieve quorum if Byzantine validator has >1/3 voting power
// Transactions from target_sender are permanently censored
```

This demonstrates how filter misconfiguration enables selective censorship while appearing to follow protocol rules.

### Citations

**File:** consensus/src/payload_manager/direct_mempool_payload_manager.rs (L30-70)
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

        // Get the inline transactions for the block proposal. Note: all
        // transactions in a direct mempool payload are inline transactions.
        let (inline_transactions, _, _) = get_transactions_from_block(block)?;
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
                "Inline transactions for DirectMempoolPayload denied by block transaction filter: {:?}",
                denied_inline_transactions
            ));
        }

        Ok(()) // No transactions were denied
    }
```

**File:** config/src/config/transaction_filters_config.rs (L90-123)
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

impl Default for BlockTransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                                     // Disable the filter
            block_transaction_filter: BlockTransactionFilter::empty(), // Use an empty filter
        }
    }
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

**File:** consensus/src/epoch_manager.rs (L211-211)
```rust
        let consensus_txn_filter_config = node_config.transaction_filters.consensus_filter.clone();
```

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L68-90)
```rust
    /// Identifies the transactions in the given block that are denied by the filter.
    /// Note: this returns the inverse of `filter_block_transactions`.
    pub fn get_denied_block_transactions(
        &self,
        block_id: HashValue,
        block_author: Option<AccountAddress>,
        block_epoch: u64,
        block_timestamp_usecs: u64,
        transactions: Vec<SignedTransaction>,
    ) -> Vec<SignedTransaction> {
        transactions
            .into_iter()
            .filter(|txn| {
                !self.allows_transaction(
                    block_id,
                    block_author,
                    block_epoch,
                    block_timestamp_usecs,
                    txn,
                )
            })
            .collect()
    }
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L172-180)
```rust
    All,                                           // Matches any transaction
    TransactionId(HashValue),                      // Matches a specific transaction by its ID
    Sender(AccountAddress), // Matches any transaction sent by a specific account address
    ModuleAddress(AccountAddress), // Matches any transaction that calls a module at a specific address
    EntryFunction(AccountAddress, String, String), // Matches any transaction that calls a specific entry function in a module
    AccountAddress(AccountAddress), // Matches any transaction that involves a specific account address
    PublicKey(AnyPublicKey),        // Matches any transaction that involves a specific public key
    EncryptedTransaction,           // Matches any encrypted transaction
}
```

**File:** testsuite/smoke-test/src/transaction_filter.rs (L246-258)
```rust
/// Adds a filter to the consensus config to ignore transactions from the given sender
fn filter_inline_transactions(node_config: &mut NodeConfig, sender_address: AccountAddress) {
    // Create the block transaction filter
    let block_transaction_filter = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
            TransactionMatcher::Sender(sender_address),
        )])
        .add_all_filter(true);

    // Update the node config with the new filter
    node_config.transaction_filters.consensus_filter =
        BlockTransactionFilterConfig::new(true, block_transaction_filter);
}
```

**File:** consensus/src/round_manager_tests/txn_filter_proposal_test.rs (L33-90)
```rust
#[test]
fn test_no_vote_on_denied_inline_transactions() {
    // Test both direct mempool and quorum store payloads
    for use_quorum_store_payloads in [false, true] {
        // Create test transactions
        let transactions = create_test_transactions();

        // Create a block filter config that denies the first transaction sender
        let block_txn_filter = BlockTransactionFilter::empty()
            .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(transactions[0].sender()),
            )])
            .add_all_filter(true);
        let block_txn_filter_config = BlockTransactionFilterConfig::new(true, block_txn_filter);

        // Create a new network playground
        let runtime = consensus_runtime();
        let mut playground = NetworkPlayground::new(runtime.handle().clone());

        // Create a new consensus node. Note: To observe the votes we're
        // going to check proposal processing on the non-proposer node
        // (which will send the votes to the proposer).
        let mut nodes = NodeSetup::create_nodes(
            &mut playground,
            runtime.handle().clone(),
            1,
            None,
            None,
            Some(block_txn_filter_config),
            None,
            None,
            None,
            use_quorum_store_payloads,
        );
        let node = &mut nodes[0];

        // Create a block proposal with inline transactions that will be denied
        let payload = create_payload(transactions, use_quorum_store_payloads);
        let denied_block = Block::new_proposal(
            payload,
            1,
            1,
            certificate_for_genesis(),
            &node.signer,
            Vec::new(),
        )
        .unwrap();

        // Verify that the node does not vote on a block with denied inline transactions
        timed_block_on(&runtime, async {
            assert!(node
                .round_manager
                .process_proposal(denied_block)
                .await
                .is_err());
        });
    }
}
```
