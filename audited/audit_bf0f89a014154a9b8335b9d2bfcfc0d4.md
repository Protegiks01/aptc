# Audit Report

## Title
Sequence Number Race Condition in Benchmark Transaction Submitter Causes Nonce Conflicts

## Summary
The `query_sequence_number()` function in `DbReliableTransactionSubmitter` queries only committed state, ignoring pending transactions. This can cause multiple concurrent operations to generate transactions with duplicate sequence numbers, leading to transaction failures and wasted gas fees in benchmark and load testing scenarios.

## Finding Description
The vulnerability exists in how the benchmark infrastructure queries account sequence numbers when generating transactions for the same account from multiple threads or processes. [1](#0-0) 

The function uses `latest_state_checkpoint_view()` which returns only the committed state, not including pending transactions. This creates a race condition:

1. **Account Creation**: Account X is created with sequence_number=0
2. **First Operation**: Thread A queries sequence_number → gets 0, creates transaction T1 with seq=0, submits it (now pending)
3. **Second Operation**: Thread B queries sequence_number while T1 is pending → still gets 0 (committed state hasn't updated)
4. **Conflict**: Thread B creates transaction T2 with seq=0, creating a duplicate

When accounts are generated, they rely on this query to initialize their sequence numbers: [2](#0-1) 

The `LocalAccount` then uses atomic increment for sequence numbers: [3](#0-2) 

However, if the initial value is stale due to pending transactions, this produces conflicting sequence numbers. The same pattern exists in the REST API-based submitter: [4](#0-3) 

This breaks the invariant that each transaction from an account should have a unique, monotonically increasing sequence number during concurrent benchmark operations.

## Impact Explanation
**Medium Severity** - This qualifies under "State inconsistencies requiring intervention" category with the following impacts:

1. **Transaction Failures**: One transaction will be rejected with SEQUENCE_NUMBER_TOO_OLD error
2. **Wasted Gas Fees**: Failed transactions still consume gas (though in benchmark contexts)
3. **Benchmark Inaccuracy**: Load tests and performance benchmarks produce incorrect results
4. **Operational Issues**: Concurrent account funding/setup operations fail unexpectedly

The blockchain's transaction validation properly enforces sequence number uniqueness: [5](#0-4) 

However, the tooling layer generates conflicting transactions, requiring manual intervention to restart failed benchmark runs or re-submit transactions.

## Likelihood Explanation
**High Likelihood** in benchmark and load testing scenarios:

- Occurs naturally when multiple threads/processes use the same account concurrently
- Common in distributed benchmark setups or parallel transaction generators
- The `QUERY_PARALLELISM` constant shows batched queries are expected: [6](#0-5) 

- Account creation and funding operations inherently create this race condition when parallelized

## Recommendation
Implement sequence number tracking for pending transactions. Options include:

**Option 1: Track Pending Sequence Numbers Locally**
```rust
pub struct DbReliableTransactionSubmitter {
    pub db: DbReaderWriter,
    pub block_sender: mpsc::SyncSender<Vec<Transaction>>,
    // Add tracking for pending sequence numbers
    pending_sequence_numbers: Arc<RwLock<HashMap<AccountAddress, u64>>>,
}

async fn query_sequence_number(&self, address: AccountAddress) -> Result<u64> {
    let db_state_view = self.db.reader.latest_state_checkpoint_view().unwrap();
    let committed_seq = AccountResource::fetch_move_resource(&db_state_view, &address)
        .unwrap()
        .map(|account| account.sequence_number())
        .unwrap_or(0);
    
    // Check if we have pending transactions and return max
    let pending_seq = self.pending_sequence_numbers.read().get(&address).copied().unwrap_or(0);
    Ok(committed_seq.max(pending_seq))
}
```

**Option 2: Wait for Transaction Commit Before Next Query**
Ensure `execute_transactions_with_counter` completes (waits for commits) before allowing the next `query_sequence_number` call for the same account.

**Option 3: Use Account Locks**
Serialize operations on the same account to prevent concurrent sequence number queries.

## Proof of Concept
```rust
// Reproduction steps for the race condition:
// 1. Create benchmark submitter with db access
let db = /* initialize db */;
let (block_sender, _) = mpsc::sync_channel(100);
let submitter = DbReliableTransactionSubmitter {
    db: db.clone(),
    block_sender,
};

// 2. Create account X
let account_x = AccountAddress::random();
// Assume account_x is created via some transaction and exists with seq=0

// 3. Spawn two concurrent tasks querying the same account
let submitter1 = Arc::new(submitter);
let submitter2 = submitter1.clone();

let task1 = tokio::spawn(async move {
    let seq1 = submitter1.query_sequence_number(account_x).await.unwrap();
    println!("Task 1 got sequence number: {}", seq1);
    // Both will get 0 if executed before the other commits
    seq1
});

let task2 = tokio::spawn(async move {
    let seq2 = submitter2.query_sequence_number(account_x).await.unwrap();
    println!("Task 2 got sequence number: {}", seq2);
    seq2
});

let (seq1, seq2) = tokio::join!(task1, task2);
assert_eq!(seq1.unwrap(), seq2.unwrap()); // Both return 0 - CONFLICT!
```

## Notes
This is a **correctness issue in benchmark/testing infrastructure**, not a consensus or security vulnerability in the Aptos blockchain itself. The blockchain properly validates and rejects duplicate sequence numbers. However, the benchmark tooling's inability to track pending state causes operational issues during load testing and concurrent transaction generation, warranting the Medium severity classification for tooling correctness.

### Citations

**File:** execution/executor-benchmark/src/db_reliable_submitter.rs (L36-45)
```rust
    async fn query_sequence_number(&self, address: AccountAddress) -> Result<u64> {
        let db_state_view = self.db.reader.latest_state_checkpoint_view().unwrap();
        Ok(
            AccountResource::fetch_move_resource(&db_state_view, &address)
                .unwrap()
                .map(|account| account.sequence_number())
                .unwrap_or(0),
        )
        //.context("account doesn't exist")
    }
```

**File:** crates/transaction-emitter-lib/src/emitter/local_account_generator.rs (L21-21)
```rust
const QUERY_PARALLELISM: usize = 300;
```

**File:** crates/transaction-emitter-lib/src/emitter/local_account_generator.rs (L81-91)
```rust
        let result_futures = addresses
            .iter()
            .map(|address| txn_executor.query_sequence_number(*address))
            .collect::<Vec<_>>();

        let seq_nums = futures::stream::iter(result_futures)
            .buffered(QUERY_PARALLELISM)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
```

**File:** sdk/src/types.rs (L546-548)
```rust
    pub fn increment_sequence_number(&self) -> u64 {
        self.sequence_number.fetch_add(1, Ordering::SeqCst)
    }
```

**File:** crates/transaction-emitter-lib/src/emitter/transaction_executor.rs (L321-323)
```rust
    async fn query_sequence_number(&self, account_address: AccountAddress) -> Result<u64> {
        query_sequence_number_with_client(self.random_rest_client(), account_address).await
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L230-237)
```text
                error::out_of_range(PROLOGUE_ESEQUENCE_NUMBER_TOO_BIG)
            );

            assert!(
                txn_sequence_number >= account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_OLD)
            );

```
