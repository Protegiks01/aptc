# Audit Report

## Title
Indexer Parallel Processing Causes Transaction Gaps in account_transactions Table During Batch Commits

## Summary
The Aptos indexer's parallel batch processing feature creates temporary gaps in the `account_transactions` table where higher-versioned transactions become visible before lower-versioned transactions complete their database commits. This violates sequential query guarantees and causes external applications querying via Hasura GraphQL to observe incomplete account transaction histories.

## Finding Description

The vulnerability exists in the indexer's parallel processing architecture. When `processor_tasks > 1` is configured, the runtime spawns multiple tasks to process transaction batches concurrently. [1](#0-0) 

Each spawned task independently:
1. Fetches a transaction batch (serialized via mutex on the fetcher)
2. Processes the batch through `AccountTransaction::from_transaction()`
3. Commits the processed data to PostgreSQL in its own database transaction
4. Returns a `ProcessingResult` [2](#0-1) 

The critical issue is that **each batch commits to PostgreSQL independently and asynchronously**. The database transaction for each batch is isolated: [3](#0-2) 

The `account_transactions` insertion uses `on_conflict().do_nothing()`, making it idempotent but not preventing visibility gaps: [4](#0-3) 

**Attack Scenario:**

1. Runtime configured with `processor_tasks = 2`
2. **T0**: Task 1 fetches batch [1000-1999], Task 2 fetches batch [2000-2999]
3. **T1**: Both tasks process in parallel
4. **T2**: Task 2 completes first, commits transactions 2000-2999 to `account_transactions`
5. **T3**: External application queries: `SELECT * FROM account_transactions WHERE account_address = '0xABC' AND transaction_version >= 1000`
6. **T3**: Query returns transactions 2000-2999 but NOT 1000-1999 (gap!)
7. **T4**: Task 1 completes, commits transactions 1000-1999
8. **T5**: Runtime updates `processor_status.last_success_version = 2999`

Between T2 and T4, external queries observe a gap where transaction 2000 appears before transaction 1000 for the same account, violating sequential ordering guarantees.

The `account_transactions` table is exposed via Hasura GraphQL for external consumption: [5](#0-4) 

## Impact Explanation

**High Severity** - This constitutes a significant protocol violation affecting the indexer subsystem, which is critical infrastructure for the Aptos ecosystem.

**Affected Systems:**
- Wallets querying account transaction histories may display incomplete data
- Block explorers may show gaps in transaction sequences
- DApps relying on event ordering may miss critical events
- Analytics platforms may produce incorrect metrics
- Any system querying `account_transactions` between batch commits sees inconsistent state

**Security Guarantees Violated:**
- **State Consistency Invariant**: The indexer should present a consistent view of blockchain state
- **Sequential Query Guarantee**: Account transactions should be queryable in ascending version order without gaps
- **Data Integrity**: External applications expect complete transaction histories when querying up to `last_success_version`

**Concrete Harm:**
- Applications making business logic decisions based on incomplete transaction data could malfunction
- Users may see incorrect account histories, causing confusion or financial decisions based on incomplete information
- Automated systems (trading bots, monitoring tools) may react incorrectly to gapped data
- Requires operational intervention to ensure query consistency

While this does not directly affect consensus or cause immediate fund loss, it undermines trust in the indexer infrastructure and can indirectly lead to application-level security issues.

## Likelihood Explanation

**High Likelihood** - This vulnerability occurs **by design** whenever parallel processing is enabled:

- The `processor_tasks` configuration parameter is commonly set > 1 to improve indexing throughput
- The race condition is not edge-case; it happens naturally during normal operation
- No special attacker action required - simply querying during processing triggers the issue
- Frequency scales with transaction volume and number of parallel tasks

**Attacker Requirements:**
- None - any external user/application can observe the gap by timing queries
- No special privileges needed
- Publicly accessible via Hasura GraphQL endpoint

## Recommendation

Implement **batch-level commit coordination** to ensure atomicity across parallel processors:

**Option 1: Serialize Commits (Simpler)**
Maintain parallel processing but serialize the database commit phase:

```rust
// In runtime.rs, after line 219
let batches = match futures::future::try_join_all(tasks).await { ... };

// NEW: Serialize batch commits to database
let mut results = vec![];
for (num_txn, res) in batches {
    match res {
        None => continue,
        Some(Ok(processing_result)) => {
            // Ensure this batch commits before next batch
            results.push(processing_result);
        }
        Some(Err(tpe)) => panic!(...),
    }
}
```

**Option 2: Global Transaction Wrapper (Better)**
Wrap all batch commits in a single database transaction:

```rust
// In coin_processor.rs process_transactions
let mut conn = self.get_conn();

// Start global transaction for this processing round
conn.build_transaction()
    .read_write()
    .run::<_, Error, _>(|pg_conn| {
        // Process all batches within single transaction
        for batch_data in all_batches {
            insert_to_db_impl(pg_conn, batch_data)?;
        }
        Ok(())
    })
```

**Option 3: Version-Ordered Commit Queue**
Implement a commit queue that ensures batches commit in version order:

```rust
struct CommitQueue {
    pending: BTreeMap<u64, BatchData>,
    next_commit_version: AtomicU64,
}

impl CommitQueue {
    fn commit_when_ready(&mut self, batch: BatchData) {
        // Only commit if this is the next expected version
        // Queue out-of-order batches until their turn
    }
}
```

**Additional Mitigation:**
Update query documentation to instruct clients to respect `processor_status.last_success_version`:

```sql
-- Safe query pattern
SELECT * FROM account_transactions 
WHERE account_address = $1 
  AND transaction_version <= (SELECT last_success_version FROM processor_status WHERE processor = 'coin_processor')
ORDER BY transaction_version
```

## Proof of Concept

```rust
// Integration test demonstrating the gap
// File: crates/indexer/src/processors/test_parallel_gap.rs

#[tokio::test]
async fn test_parallel_processing_creates_gaps() {
    // Setup: Create two batches of transactions
    let batch1 = create_test_transactions(1000, 1999); // 1000 txns
    let batch2 = create_test_transactions(2000, 2999); // 1000 txns
    
    let processor = CoinTransactionProcessor::new(conn_pool.clone());
    
    // Spawn two parallel processing tasks
    let task1 = tokio::spawn({
        let p = processor.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(100)).await; // Delay
            p.process_transactions(batch1, 1000, 1999).await
        }
    });
    
    let task2 = tokio::spawn({
        let p = processor.clone();
        async move {
            // Process immediately (will finish first)
            p.process_transactions(batch2, 2000, 2999).await
        }
    });
    
    // Wait for task2 to complete (task1 still running)
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Query account_transactions during the gap window
    let mut conn = conn_pool.get().unwrap();
    let results: Vec<AccountTransaction> = account_transactions::table
        .filter(account_transactions::account_address.eq("0xTEST_ACCOUNT"))
        .filter(account_transactions::transaction_version.ge(1000))
        .order_by(account_transactions::transaction_version.asc())
        .load(&mut conn)
        .unwrap();
    
    // BUG: Results contain transactions 2000-2999 but NOT 1000-1999
    assert!(!results.is_empty());
    assert_eq!(results[0].transaction_version, 2000); // Gap detected!
    
    // Wait for task1 to complete
    task1.await.unwrap();
    task2.await.unwrap();
    
    // Now query again - gap is closed
    let results_after: Vec<AccountTransaction> = account_transactions::table
        .filter(account_transactions::account_address.eq("0xTEST_ACCOUNT"))
        .filter(account_transactions::transaction_version.ge(1000))
        .order_by(account_transactions::transaction_version.asc())
        .load(&mut conn)
        .unwrap();
    
    assert_eq!(results_after[0].transaction_version, 1000); // Now correct
}
```

**Notes:**
- This vulnerability is specific to the **indexer subsystem**, not the core blockchain consensus
- The blockchain's `AccountTransactionStore` in `storage/aptosdb/` is unaffected - only the PostgreSQL indexer exhibits this issue
- The gap is temporary (closes once all parallel batches complete), but queries during the window see inconsistent state
- Severity is High because the indexer is critical infrastructure serving external applications, and data integrity violations can cascade to application-level security issues

### Citations

**File:** crates/indexer/src/runtime.rs (L209-219)
```rust
    loop {
        let mut tasks = vec![];
        for _ in 0..processor_tasks {
            let other_tailer = tailer.clone();
            let task = tokio::spawn(async move { other_tailer.process_next_batch().await });
            tasks.push(task);
        }
        let batches = match futures::future::try_join_all(tasks).await {
            Ok(res) => res,
            Err(err) => panic!("Error processing transaction batches: {:?}", err),
        };
```

**File:** crates/indexer/src/processors/coin_processor.rs (L86-99)
```rust
    match conn
        .build_transaction()
        .read_write()
        .run::<_, Error, _>(|pg_conn| {
            insert_to_db_impl(
                pg_conn,
                &coin_activities,
                &coin_infos,
                &coin_balances,
                &current_coin_balances,
                &coin_supply,
                &account_transactions,
            )
        }) {
```

**File:** crates/indexer/src/processors/coin_processor.rs (L247-265)
```rust
fn insert_account_transactions(
    conn: &mut PgConnection,
    item_to_insert: &[AccountTransaction],
) -> Result<(), diesel::result::Error> {
    use schema::account_transactions::dsl::*;

    let chunks = get_chunks(item_to_insert.len(), AccountTransaction::field_count());
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::account_transactions::table)
                .values(&item_to_insert[start_ind..end_ind])
                .on_conflict((transaction_version, account_address))
                .do_nothing(),
            None,
        )?;
    }
    Ok(())
}
```

**File:** crates/indexer/src/processors/coin_processor.rs (L273-359)
```rust
    async fn process_transactions(
        &self,
        transactions: Vec<APITransaction>,
        start_version: u64,
        end_version: u64,
    ) -> Result<ProcessingResult, TransactionProcessingError> {
        let mut conn = self.get_conn();
        // get aptos_coin info for supply tracking
        // TODO: This only needs to be fetched once. Need to persist somehow
        let maybe_aptos_coin_info = &CoinInfoQuery::get_by_coin_type(
            AptosCoinType::type_tag().to_canonical_string(),
            &mut conn,
        )
        .unwrap();

        let mut all_coin_activities = vec![];
        let mut all_coin_balances = vec![];
        let mut all_coin_infos: HashMap<String, CoinInfo> = HashMap::new();
        let mut all_current_coin_balances: HashMap<CurrentCoinBalancePK, CurrentCoinBalance> =
            HashMap::new();
        let mut all_coin_supply = vec![];

        let mut account_transactions = HashMap::new();

        for txn in &transactions {
            let (
                mut coin_activities,
                mut coin_balances,
                coin_infos,
                current_coin_balances,
                mut coin_supply,
            ) = CoinActivity::from_transaction(txn, maybe_aptos_coin_info);
            all_coin_activities.append(&mut coin_activities);
            all_coin_balances.append(&mut coin_balances);
            all_coin_supply.append(&mut coin_supply);
            // For coin infos, we only want to keep the first version, so insert only if key is not present already
            for (key, value) in coin_infos {
                all_coin_infos.entry(key).or_insert(value);
            }
            all_current_coin_balances.extend(current_coin_balances);

            account_transactions.extend(AccountTransaction::from_transaction(txn).unwrap());
        }
        let mut all_coin_infos = all_coin_infos.into_values().collect::<Vec<CoinInfo>>();
        let mut all_current_coin_balances = all_current_coin_balances
            .into_values()
            .collect::<Vec<CurrentCoinBalance>>();
        let mut account_transactions = account_transactions
            .into_values()
            .collect::<Vec<AccountTransaction>>();

        // Sort by PK
        all_coin_infos.sort_by(|a, b| a.coin_type.cmp(&b.coin_type));
        all_current_coin_balances.sort_by(|a, b| {
            (&a.owner_address, &a.coin_type).cmp(&(&b.owner_address, &b.coin_type))
        });
        account_transactions.sort_by(|a, b| {
            (&a.transaction_version, &a.account_address)
                .cmp(&(&b.transaction_version, &b.account_address))
        });

        let tx_result = insert_to_db(
            &mut conn,
            self.name(),
            start_version,
            end_version,
            all_coin_activities,
            all_coin_infos,
            all_coin_balances,
            all_current_coin_balances,
            all_coin_supply,
            account_transactions,
        );
        match tx_result {
            Ok(_) => Ok(ProcessingResult::new(
                self.name(),
                start_version,
                end_version,
            )),
            Err(err) => Err(TransactionProcessingError::TransactionCommitError((
                anyhow::Error::from(err),
                start_version,
                end_version,
                self.name(),
            ))),
        }
    }
```

**File:** crates/aptos-localnet/src/hasura_metadata.json (L850-853)
```json
            "table": {
              "name": "account_transactions",
              "schema": "public"
            },
```
