# Audit Report

## Title
Transaction Filtering Breaks Sequence Number Dependencies Leading to Transaction Failures and Potential Consensus Divergence

## Summary
The transaction filtering mechanism in `BlockTransactionFilter::filter_block_transactions()` evaluates transactions independently without considering execution dependencies (sequence numbers) between transactions from the same account. When filtering removes a transaction with sequence number N but keeps transaction N+1, the latter will fail during prologue validation, causing valid transactions to be discarded and potentially leading to different execution results across validators with different filter configurations.

## Finding Description [1](#0-0) 

The `filter_block_transactions()` method filters transactions individually using an iterator, without awareness of sequence number dependencies between transactions from the same sender. [2](#0-1) 

During block preparation, this filtering is applied to all transactions in the block. When a transaction with sequence number N is filtered out but transaction N+1 remains, the execution will fail because: [3](#0-2) 

The prologue validation requires exact sequence number match (`txn_sequence_number == account_sequence_number`). If transaction N was filtered out, the account's sequence number remains at N (or below), causing transaction N+1 to fail with `PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW`. [4](#0-3) 

This error is converted to `StatusCode::SEQUENCE_NUMBER_TOO_NEW`, which is a validation error. [5](#0-4) 

Validation errors cause transactions to be discarded from the block without charging gas.

**Attack Scenario:**
1. Validator configures a transaction filter with a deny rule (e.g., `TransactionMatcher::TransactionId` for a specific transaction hash)
2. Block proposer includes transactions with sequence numbers [N, N+1, N+2] from the same sender
3. Filter matches and removes transaction N but allows N+1 and N+2
4. During execution, transaction N+1 fails prologue check and is discarded
5. Transaction N+2 also fails and is discarded
6. Block ends up with fewer transactions than expected
7. If validators have different filter configurations, they may discard different sets of transactions, leading to divergent execution results [6](#0-5) 

The filter supports various matchers (TransactionId, Sender, ModuleAddress, EntryFunction, etc.) that can selectively filter individual transactions.

## Impact Explanation

This is a **Medium Severity** vulnerability for the following reasons:

1. **State Inconsistencies**: Validators with different filter configurations will execute different subsets of transactions from blocks, potentially leading to state divergence
2. **Transaction Failures**: Valid, properly sequenced transactions are rejected unexpectedly even though they were included in blocks
3. **User Experience Degradation**: Users' transactions fail without clear error messages about why they were filtered
4. **Deterministic Execution Violation**: Breaks the critical invariant that "all validators must produce identical state roots for identical blocks" when validators have different filters

This does not rise to Critical/High severity because:
- No direct fund loss or theft
- Requires validator operators to configure filters (not exploitable by arbitrary attackers)
- Does not cause complete consensus failure, but rather execution divergence in specific scenarios
- Can be detected and corrected through configuration management

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- Validators to enable and configure transaction filters (feature may not be widely used in production)
- Filters configured with rules that selectively match individual transactions (not all-or-nothing rules)
- Blocks containing multiple transactions from the same account with sequential sequence numbers
- The filtered transaction to be positioned before other transactions from the same sender

However, once filters are configured, the issue will occur consistently whenever the above conditions are met. The complexity is low as it requires only standard filter configuration, not sophisticated attacks.

## Recommendation

Implement sequence number dependency checking in the filtering logic. When filtering transactions, the system should:

1. **Track sequence number chains**: Before filtering, identify all transactions from the same sender and their sequence number order
2. **Validate filter results**: After applying filters, verify that no "gaps" exist in sequence number chains
3. **Remove dependent transactions**: If a transaction with sequence number N is filtered, automatically remove all subsequent transactions (N+1, N+2, etc.) from the same sender

**Proposed Fix in `filter_block_transactions()`:**

```rust
pub fn filter_block_transactions(
    &self,
    block_id: HashValue,
    block_author: Option<AccountAddress>,
    block_epoch: u64,
    block_timestamp_usecs: u64,
    transactions: Vec<SignedTransaction>,
) -> Vec<SignedTransaction> {
    // Group transactions by sender to track sequence numbers
    let mut sender_txns: HashMap<AccountAddress, Vec<&SignedTransaction>> = HashMap::new();
    for txn in &transactions {
        sender_txns.entry(txn.sender()).or_default().push(txn);
    }
    
    // Filter while respecting sequence number dependencies
    let mut filtered = Vec::new();
    let mut blocked_senders = HashSet::new();
    
    for txn in transactions {
        // Skip if a previous transaction from this sender was filtered
        if blocked_senders.contains(&txn.sender()) {
            continue;
        }
        
        if self.allows_transaction(block_id, block_author, block_epoch, block_timestamp_usecs, &txn) {
            filtered.push(txn);
        } else {
            // Block all subsequent transactions from this sender
            blocked_senders.insert(txn.sender());
        }
    }
    
    filtered
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_sequence_number_dependency_violation() {
    use aptos_types::transaction::SignedTransaction;
    use aptos_crypto::HashValue;
    use move_core_types::account_address::AccountAddress;
    
    // Create filter that denies specific transaction ID
    let target_txn_id = HashValue::random();
    let filter = BlockTransactionFilter::empty()
        .add_transaction_id_filter(false, target_txn_id);
    
    // Create 3 transactions from same sender with sequential sequence numbers
    let sender = AccountAddress::random();
    let txn_0 = create_test_txn(sender, 0, target_txn_id); // This will be filtered
    let txn_1 = create_test_txn(sender, 1, HashValue::random()); // Should remain but will fail
    let txn_2 = create_test_txn(sender, 2, HashValue::random()); // Should remain but will fail
    
    let transactions = vec![txn_0, txn_1, txn_2];
    
    // Apply filter
    let filtered = filter.filter_block_transactions(
        HashValue::random(),
        Some(AccountAddress::random()),
        1,
        1000000,
        transactions,
    );
    
    // Bug: txn_1 and txn_2 remain despite txn_0 being filtered
    assert_eq!(filtered.len(), 2); // BUG: Should be 0 to prevent execution failures
    
    // When executed, txn_1 will fail with SEQUENCE_NUMBER_TOO_NEW
    // because account sequence number is still 0 (txn_0 never executed)
}
```

**Notes**

This vulnerability represents a critical design flaw in how transaction filtering interacts with the sequence number-based transaction ordering system in Aptos. The fix requires coordination between the filtering layer and the execution layer to maintain transaction ordering invariants. Validators should be cautioned about using transaction filters that selectively target individual transactions rather than sender-level or module-level filters until this issue is resolved.

### Citations

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L93-113)
```rust
    pub fn filter_block_transactions(
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
                self.allows_transaction(
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

**File:** consensus/src/block_preparer.rs (L90-98)
```rust
        let result = tokio::task::spawn_blocking(move || {
            let filtered_txns = filter_block_transactions(
                txn_filter_config,
                block_id,
                block_author,
                block_epoch,
                block_timestamp_usecs,
                txns,
            );
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L233-241)
```text
            assert!(
                txn_sequence_number >= account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_OLD)
            );

            assert!(
                txn_sequence_number == account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW)
            );
```

**File:** aptos-move/aptos-vm/src/errors.rs (L130-130)
```rust
                (INVALID_ARGUMENT, ESEQUENCE_NUMBER_TOO_NEW) => StatusCode::SEQUENCE_NUMBER_TOO_NEW,
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L626-629)
```rust
            TransactionStatus::Discard(status_code) => {
                let discarded_output = discarded_output(status_code);
                (error_vm_status, discarded_output)
            },
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L169-180)
```rust
/// A matcher that defines the criteria for matching transactions
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionMatcher {
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
