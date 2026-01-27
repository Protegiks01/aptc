# Audit Report

## Title
Sequence Number Validation Bypass in AccountOrderedTransactionsIter Leading to Silent Data Skipping

## Summary
The `AccountOrderedTransactionsIter` initializes `expected_next_seq_num` to `None`, which causes the iterator to skip sequence number validation for the first transaction. When the requested starting sequence number is missing from the database (due to pruning or corruption), the iterator silently returns transactions from a later sequence number without any error, violating documented API guarantees and potentially causing state inconsistencies in client applications. [1](#0-0) 

## Finding Description

The vulnerability exists in the `next_impl` method of `AccountOrderedTransactionsIter`. The sequence number validation logic at lines 85-93 only executes when `expected_next_seq_num` is `Some`: [2](#0-1) 

Since `expected_next_seq_num` is initialized to `None` in the constructor, the first transaction retrieved by the iterator bypasses this validation entirely. The iterator then sets `expected_next_seq_num` to the retrieved sequence number plus one: [3](#0-2) 

**Violated Guarantees:**

1. The `TransactionStore::get_account_ordered_transactions_iter` function explicitly documents: "Guarantees that the returned sequence numbers are sequential, i.e., `seq_num_{i} + 1 = seq_num_{i+1}`" [4](#0-3) 

2. The storage interface contract states the function returns transactions "starting at sequence number `seq_num`": [5](#0-4) 

**Exploitation Scenario:**

When `prune_transaction_by_account` removes old transactions: [6](#0-5) 

Gaps are created in the sequence number space. If a client requests transactions starting from a pruned sequence number:
1. Client calls API with `start_seq_num = 5`
2. Database only contains `seq_num >= 10` (5-9 were pruned)
3. Iterator seeks to `(address, 5)`, finds `(address, 10)` as first result
4. First iteration: `expected_next_seq_num` is `None`, no validation performed
5. Iterator accepts `seq_num = 10` and sets `expected_next_seq_num = 11`
6. Client receives transactions [10, 11, 12...] but believes they received [5, 6, 7...]

**Inconsistent Behavior:**

The similar `lookup_events_by_key` function properly validates the first sequence number: [7](#0-6) 

This explicit check returns an error when the first requested sequence number is missing, with the message "First requested event is probably pruned." The transaction iterator lacks this critical validation.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This qualifies as "State inconsistencies requiring intervention" because:

1. **API Contract Violation**: Clients receive incorrect data without error indication, violating the documented interface contract [8](#0-7) 

2. **Client Application Failures**: Applications relying on transaction history for:
   - Wallet balance calculations
   - Transaction replay detection
   - Account state reconstruction
   - Sequence number tracking for transaction submission
   
   Will operate on incomplete data, leading to incorrect application state.

3. **Information Hiding**: The API implementation discards actual sequence numbers before returning to callers: [9](#0-8) 
   
   Clients cannot detect they received wrong data.

4. **Widespread Impact**: The vulnerability affects both the main database reader and the indexer reader: [10](#0-9) [11](#0-10) 

**Not Critical because:**
- Does not affect consensus or execution layer (sequence number validation in prologue remains intact)
- Does not directly cause fund loss or network partition
- Limited to query/indexer layer

## Likelihood Explanation

**Likelihood: High**

1. **Normal Operations Trigger Vulnerability**: Database pruning is a routine maintenance operation that creates gaps in sequence numbers [6](#0-5) 

2. **No Attacker Required**: Any client querying historical transactions for an account can encounter this issue naturally after pruning

3. **Silent Failure**: No error or warning is returned, making detection difficult until applications experience failures

4. **Common API Usage**: The affected endpoint is a primary method for querying account transaction history: [12](#0-11) 

## Recommendation

Add explicit validation for the first sequence number retrieved, similar to the event lookup implementation:

```rust
fn next_impl(&mut self) -> Result<Option<(u64, Version)>> {
    Ok(match self.inner.next().transpose()? {
        Some(((address, seq_num), version)) => {
            // No more transactions sent by this account.
            if address != self.address {
                return Ok(None);
            }
            if seq_num >= self.end_seq_num {
                return Ok(None);
            }

            // Ensure seq_num_{i+1} == seq_num_{i} + 1
            if let Some(expected_seq_num) = self.expected_next_seq_num {
                ensure!(
                    seq_num == expected_seq_num,
                    "DB corruption: account transactions sequence numbers are not contiguous: \
                 actual: {}, expected: {}",
                    seq_num,
                    expected_seq_num,
                );
            } else {
                // NEW: Validate first sequence number matches seek position
                // This is extracted from the iterator's construction context
                // We need to pass the expected start_seq_num to the constructor
                // and validate here that the first result matches or return an error
            };

            // ... rest of validation ...
        },
        None => None,
    })
}
```

**Better approach**: Modify the constructor to accept and store `start_seq_num`, then validate it:

```rust
pub struct AccountOrderedTransactionsIter<'a> {
    inner: SchemaIterator<'a, OrderedTransactionByAccountSchema>,
    address: AccountAddress,
    start_seq_num: u64,  // NEW: Store expected start
    expected_next_seq_num: Option<u64>,
    end_seq_num: u64,
    prev_version: Option<Version>,
    ledger_version: Version,
}

impl<'a> AccountOrderedTransactionsIter<'a> {
    pub fn new(
        inner: SchemaIterator<'a, OrderedTransactionByAccountSchema>,
        address: AccountAddress,
        start_seq_num: u64,  // NEW: Add parameter
        end_seq_num: u64,
        ledger_version: Version,
    ) -> Self {
        Self {
            inner,
            address,
            start_seq_num,
            end_seq_num,
            ledger_version,
            expected_next_seq_num: Some(start_seq_num),  // CHANGED: Initialize with start
            prev_version: None,
        }
    }
}
```

This ensures the first transaction's sequence number is validated against the requested start position.

## Proof of Concept

```rust
#[test]
fn test_account_ordered_transactions_missing_start_seq_num() {
    use aptos_db_indexer_schemas::schema::ordered_transaction_by_account::OrderedTransactionByAccountSchema;
    use aptos_schemadb::{SchemaBatch, DB};
    use aptos_types::account_address::AccountAddress;
    use tempfile::tempdir;

    let tmpdir = tempdir().unwrap();
    let db = DB::open(
        tmpdir.path(),
        "test_db",
        vec![OrderedTransactionByAccountSchema::COLUMN_FAMILY_NAME],
        &Default::default(),
    )
    .unwrap();

    let address = AccountAddress::random();
    let mut batch = SchemaBatch::new();

    // Write transactions with sequence numbers 10, 11, 12
    // (simulating that 0-9 were pruned)
    batch.put::<OrderedTransactionByAccountSchema>(&(address, 10), &100).unwrap();
    batch.put::<OrderedTransactionByAccountSchema>(&(address, 11), &101).unwrap();
    batch.put::<OrderedTransactionByAccountSchema>(&(address, 12), &102).unwrap();
    db.write_schemas(batch).unwrap();

    // Create iterator requesting from seq_num 5
    let mut iter = db.iter::<OrderedTransactionByAccountSchema>().unwrap();
    iter.seek(&(address, 5)).unwrap();
    
    let mut account_iter = AccountOrderedTransactionsIter::new(
        iter,
        address,
        5 + 10, // end_seq_num = 15
        1000,   // ledger_version
    );

    // BUG: First result is seq_num 10, not 5, but no error is returned!
    let first = account_iter.next().unwrap().unwrap();
    assert_eq!(first.0, 10); // Should be 10, but we requested starting from 5
    
    // Subsequent results are validated correctly
    let second = account_iter.next().unwrap().unwrap();
    assert_eq!(second.0, 11); // This passes validation: 11 == 10 + 1
    
    // The iterator silently skipped seq_nums 5-9 without error!
    // Client receives [10, 11, 12] when they requested starting from 5
}
```

## Notes

This vulnerability affects both the primary storage layer and the indexer layer, as they share the same `AccountOrderedTransactionsIter` implementation. The issue is particularly insidious because:

1. It manifests during normal operations (pruning)
2. Causes silent data corruption at the API layer
3. Has inconsistent behavior compared to similar event lookup code
4. Violates documented guarantees that clients depend on

The fix should ensure the first sequence number returned matches the requested start position, or return a clear error if that sequence number is unavailable (pruned or never existed).

### Citations

**File:** storage/indexer_schemas/src/utils.rs (L66-66)
```rust
            expected_next_seq_num: None,
```

**File:** storage/indexer_schemas/src/utils.rs (L85-93)
```rust
                if let Some(expected_seq_num) = self.expected_next_seq_num {
                    ensure!(
                        seq_num == expected_seq_num,
                        "DB corruption: account transactions sequence numbers are not contiguous: \
                     actual: {}, expected: {}",
                        seq_num,
                        expected_seq_num,
                    );
                };
```

**File:** storage/indexer_schemas/src/utils.rs (L111-111)
```rust
                self.expected_next_seq_num = Some(seq_num + 1);
```

**File:** storage/aptosdb/src/transaction_store/mod.rs (L58-59)
```rust
    /// Guarantees that the returned sequence numbers are sequential, i.e.,
    /// `seq_num_{i} + 1 = seq_num_{i+1}`.
```

**File:** storage/aptosdb/src/transaction_store/mod.rs (L143-156)
```rust
    pub fn prune_transaction_by_account(
        &self,
        transactions: &[(Version, Transaction)],
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
        for (_, transaction) in transactions {
            if let Some(txn) = transaction.try_as_signed_user_txn() {
                if let ReplayProtector::SequenceNumber(seq_num) = txn.replay_protector() {
                    db_batch
                        .delete::<OrderedTransactionByAccountSchema>(&(txn.sender(), seq_num))?;
                }
            }
        }
        Ok(())
```

**File:** storage/storage-interface/src/lib.rs (L323-325)
```rust
        /// Returns the list of ordered transactions (transactions that include a sequence number)
        /// sent by an account with `address` starting
        /// at sequence number `seq_num`. Will return no more than `limit` transactions.
```

**File:** storage/storage-interface/src/lib.rs (L328-335)
```rust
        fn get_account_ordered_transactions(
            &self,
            address: AccountAddress,
            seq_num: u64,
            limit: u64,
            include_events: bool,
            ledger_version: Version,
        ) -> Result<AccountOrderedTransactionsWithProof>;
```

**File:** storage/indexer/src/db_indexer.rs (L232-238)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L187-189)
```rust
                .map(|result| {
                    let (_seq_num, txn_version) = result?;
                    self.get_transaction_with_proof(txn_version, ledger_version, include_events)
```

**File:** api/src/context.rs (L901-907)
```rust
            self.db.get_account_ordered_transactions(
                address,
                start_seq_number,
                limit as u64,
                true,
                ledger_version,
            )
```

**File:** api/src/context.rs (L915-921)
```rust
                .get_account_ordered_transactions(
                    address,
                    start_seq_number,
                    limit as u64,
                    true,
                    ledger_version,
                )
```

**File:** api/src/transactions.rs (L355-375)
```rust
    // Question[Orderless]: Can this operation id and function name be changed to "get_account_ordered_transactions"?
    #[oai(
        path = "/accounts/:address/transactions",
        method = "get",
        operation_id = "get_account_transactions",
        tag = "ApiTags::Transactions"
    )]
    async fn get_accounts_transactions(
        &self,
        accept_type: AcceptType,
        /// Address of account with or without a `0x` prefix
        address: Path<Address>,
        /// Account sequence number to start list of transactions
        ///
        /// If not provided, defaults to showing the latest transactions
        start: Query<Option<U64>>,
        /// Max number of transactions to retrieve.
        ///
        /// If not provided, defaults to default page size
        limit: Query<Option<u16>>,
    ) -> BasicResultWith404<Vec<Transaction>> {
```
