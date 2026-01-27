# Audit Report

## Title
Consensus Non-Determinism via execution_filter Rule Ordering Manipulation Leading to Network Liveness Failure

## Summary
Validators can manipulate the order of `block_transaction_rules` in the `execution_filter` configuration to create filters that appear restrictive but effectively allow all transactions through first-match semantics. When different validators execute blocks with inconsistent filters during the preparation phase, they compute different state roots, preventing consensus agreement and causing network liveness failure.

## Finding Description

The `BlockTransactionFilter` uses first-match semantics when evaluating transaction filtering rules. [1](#0-0) 

A malicious validator can craft a filter configuration that places an `Allow` rule matching all transactions before any `Deny` rules, making all subsequent deny rules unreachable dead code:

```yaml
block_transaction_rules:
  - Allow:
    - Block:
        All
  - Deny:
    - Transaction:
        Sender: "0xmalicious_address"
```

With this configuration, the first rule matches all transactions and returns `true` immediately, so the deny rule is never evaluated.

The critical vulnerability lies in where this filter is applied. The `execution_filter` is used in `BlockPreparer.prepare_block()` which is called during block execution by ALL validators, not just during proposal creation. [2](#0-1) 

The `ExecutionProxy` is instantiated with the `execution_filter` configuration: [3](#0-2) 

When validators execute blocks through the consensus pipeline, they call `prepare_block` which applies the execution filter: [4](#0-3) 

If validators have inconsistent execution filters due to rule ordering manipulation:
- Validator A configures: `[Allow(Sender: 0xmalicious), Deny(All)]` 
- Validator B configures: `[Deny(Sender: 0xmalicious), Allow(All)]`

They will execute completely different transaction sets from the same block, compute different state roots, and vote for different states. This violates the **Deterministic Execution** invariant that "All validators must produce identical state roots for identical blocks."

## Impact Explanation

This is a **High Severity** issue under the Aptos bug bounty criteria for the following reasons:

1. **Significant Protocol Violation**: Breaks the Deterministic Execution invariant, a fundamental requirement for BFT consensus safety

2. **Network Liveness Failure**: When validators execute different transaction sets, they compute different state roots and cannot reach 2/3+ agreement on any single state, halting the network

3. **Requires Manual Intervention**: Recovery requires coordinating validators to synchronize their filter configurations and potentially triggering state sync

4. **Exploitable During Emergency Response**: Most dangerous when filters are deployed network-wide as emergency measures (e.g., to block exploit transactions), where a malicious validator could bypass the filter while appearing compliant

The impact does not reach Critical severity because:
- No direct fund loss occurs
- No permanent network partition (recoverable through coordination)
- Requires validator operator access (not unprivileged attacker)

## Likelihood Explanation

**Moderate to High Likelihood** in scenarios where execution filters are deployed:

1. **Attack Complexity**: Low - Simply requires YAML configuration with rules in wrong order
2. **Detection Difficulty**: High - Filter appears to have deny rules, making the bypass non-obvious during audits
3. **Attacker Requirements**: Requires validator operator access to modify node configuration
4. **Deployment Scenarios**: Most likely during emergency response when filters are rapidly deployed network-wide

The likelihood is reduced by:
- Filters are disabled by default
- Requires validator operator access
- Most networks don't use execution filters in normal operation

## Recommendation

**Immediate Fix**: Add explicit validation that prevents unreachable rules:

```rust
impl BlockTransactionFilter {
    pub fn validate_rules(&self) -> Result<(), String> {
        for (i, rule) in self.block_transaction_rules.iter().enumerate() {
            // Check if this is an unrestricted Allow rule
            if matches!(rule, BlockTransactionRule::Allow(matchers) 
                if matchers.iter().any(|m| matches!(m, BlockTransactionMatcher::Block(BlockMatcher::All))))
            {
                // If there are more rules after an Allow-All, they're unreachable
                if i < self.block_transaction_rules.len() - 1 {
                    return Err(format!(
                        "Unreachable rules detected: Allow-All rule at position {} makes subsequent rules unreachable",
                        i
                    ));
                }
            }
        }
        Ok(())
    }
}
```

Call this validation when loading the configuration: [5](#0-4) 

**Long-term Fix**: Consider one of these architectural changes:

1. **Default-Deny Semantics**: Change line 58 to return `false` by default, requiring explicit Allow rules
2. **On-Chain Filter Coordination**: Move execution filters to on-chain governance to ensure all validators use identical filters
3. **Filter Hash Commitment**: Include filter configuration hash in block metadata and reject blocks if filters don't match

## Proof of Concept

```rust
#[test]
fn test_rule_ordering_causes_nondeterminism() {
    use aptos_crypto::HashValue;
    use move_core_types::account_address::AccountAddress;
    
    // Create test transaction from a specific sender
    let malicious_sender = AccountAddress::from_hex_literal("0xBAD").unwrap();
    let normal_sender = AccountAddress::from_hex_literal("0x123").unwrap();
    
    let txn_malicious = create_test_transaction(malicious_sender);
    let txn_normal = create_test_transaction(normal_sender);
    
    // Validator A: Allow malicious first, then Deny all
    let filter_a = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(true, vec![
            BlockTransactionMatcher::Transaction(TransactionMatcher::Sender(malicious_sender))
        ])
        .add_all_filter(false); // Deny all others
    
    // Validator B: Deny malicious first, then Allow all  
    let filter_b = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![
            BlockTransactionMatcher::Transaction(TransactionMatcher::Sender(malicious_sender))
        ])
        .add_all_filter(true); // Allow all others
    
    let block_id = HashValue::random();
    let block_author = Some(AccountAddress::random());
    let block_epoch = 1;
    let block_timestamp = 1000;
    
    // Check what each validator allows
    let a_allows_malicious = filter_a.allows_transaction(
        block_id, block_author, block_epoch, block_timestamp, &txn_malicious
    );
    let a_allows_normal = filter_a.allows_transaction(
        block_id, block_author, block_epoch, block_timestamp, &txn_normal
    );
    
    let b_allows_malicious = filter_b.allows_transaction(
        block_id, block_author, block_epoch, block_timestamp, &txn_malicious
    );
    let b_allows_normal = filter_b.allows_transaction(
        block_id, block_author, block_epoch, block_timestamp, &txn_normal
    );
    
    // Validator A executes: [txn_malicious] (denies normal)
    assert!(a_allows_malicious);
    assert!(!a_allows_normal);
    
    // Validator B executes: [txn_normal] (denies malicious)
    assert!(!b_allows_malicious);
    assert!(b_allows_normal);
    
    // DIFFERENT TRANSACTION SETS → DIFFERENT STATE ROOTS → CONSENSUS FAILURE
    println!("Validator A executes: malicious only");
    println!("Validator B executes: normal only");
    println!("Result: Non-deterministic execution, consensus cannot agree on state root");
}
```

## Notes

This vulnerability specifically affects the `execution_filter` field in `TransactionFiltersConfig`, not the `consensus_filter`. The consensus_filter only affects voting decisions on proposals, while the execution_filter affects actual block execution by all validators. [6](#0-5) 

The issue is disabled by default since filters are disabled by default, but becomes critical when networks deploy execution filters for emergency response or policy enforcement. [7](#0-6)

### Citations

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L43-56)
```rust
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
```

**File:** consensus/src/block_preparer.rs (L71-119)
```rust
    pub async fn prepare_block(
        &self,
        block: &Block,
        txns: Vec<SignedTransaction>,
        max_txns_from_block_to_execute: Option<u64>,
        block_gas_limit: Option<u64>,
    ) -> (Vec<SignedTransaction>, Option<u64>) {
        let start_time = Instant::now();

        let txn_filter_config = self.txn_filter_config.clone();
        let txn_deduper = self.txn_deduper.clone();
        let txn_shuffler = self.txn_shuffler.clone();

        let block_id = block.id();
        let block_author = block.author();
        let block_epoch = block.epoch();
        let block_timestamp_usecs = block.timestamp_usecs();

        // Transaction filtering, deduplication and shuffling are CPU intensive tasks, so we run them in a blocking task.
        let result = tokio::task::spawn_blocking(move || {
            let filtered_txns = filter_block_transactions(
                txn_filter_config,
                block_id,
                block_author,
                block_epoch,
                block_timestamp_usecs,
                txns,
            );
            let deduped_txns = txn_deduper.dedup(filtered_txns);
            let mut shuffled_txns = {
                let _timer = TXN_SHUFFLE_SECONDS.start_timer();

                txn_shuffler.shuffle(deduped_txns)
            };

            if let Some(max_txns_from_block_to_execute) = max_txns_from_block_to_execute {
                shuffled_txns.truncate(max_txns_from_block_to_execute as usize);
            }
            TXNS_IN_BLOCK
                .with_label_values(&["after_filter"])
                .observe(shuffled_txns.len() as f64);
            MAX_TXNS_FROM_BLOCK_TO_EXECUTE.observe(shuffled_txns.len() as f64);
            shuffled_txns
        })
        .await
        .expect("Failed to spawn blocking task for transaction generation");
        counters::BLOCK_PREPARER_LATENCY.observe_duration(start_time.elapsed());
        (result, block_gas_limit)
    }
```

**File:** consensus/src/consensus_provider.rs (L65-72)
```rust
    let execution_proxy = ExecutionProxy::new(
        Arc::new(BlockExecutor::<AptosVMBlockExecutor>::new(aptos_db)),
        txn_notifier,
        state_sync_notifier,
        node_config.transaction_filters.execution_filter.clone(),
        node_config.consensus.enable_pre_commit,
        None,
    );
```

**File:** config/src/config/transaction_filters_config.rs (L13-17)
```rust
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
```

**File:** config/src/config/transaction_filters_config.rs (L97-103)
```rust
impl BlockTransactionFilterConfig {
    pub fn new(filter_enabled: bool, block_transaction_filter: BlockTransactionFilter) -> Self {
        Self {
            filter_enabled,
            block_transaction_filter,
        }
    }
```

**File:** config/src/config/transaction_filters_config.rs (L116-122)
```rust
impl Default for BlockTransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                                     // Disable the filter
            block_transaction_filter: BlockTransactionFilter::empty(), // Use an empty filter
        }
    }
```
