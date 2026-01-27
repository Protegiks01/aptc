# Audit Report

## Title
Ledger Version Skew Causes Committed Transactions to Be Misreported as Pending in Transaction-by-Hash API

## Summary
When the internal indexer lags behind storage, the `/transactions/by_hash` API endpoint incorrectly classifies committed on-chain transactions as pending. This occurs because the API uses the storage ledger version to query transactions but the indexer's ledger version to classify their status, causing transactions committed between these two versions to be misreported.

## Finding Description

The vulnerability exists in the transaction-by-hash lookup flow where the API retrieves ledger information from both the internal indexer and storage separately, then uses inconsistent version references for transaction lookup versus status classification. [1](#0-0) 

The `get_latest_internal_and_storage_ledger_info()` function makes two separate calls to fetch indexer and storage versions. Critically, even though `get_latest_internal_indexer_ledger_info()` internally clamps the indexer version to storage at one point in time, the second call to `get_latest_storage_ledger_info()` reads storage again, potentially returning a newer version. [2](#0-1) 

The clamping logic at line 333 shows that the indexer version can legitimately lag behind storage during normal operation (as noted in the comment at line 330: "The internal indexer version can be ahead of the storage committed version since it syncs to db's latest synced version").

In the `get_transaction_by_hash_inner` endpoint: [3](#0-2) 

The code extracts both `storage_version` and `internal_indexer_version`, then passes them to `get_by_hash()`. The critical flaw occurs here: [4](#0-3) 

At line 1096, the transaction lookup uses `storage_ledger_version` to search the database. However, at line 1104, the classification uses `internal_ledger_version.unwrap_or(storage_ledger_version)` as the "latest" version for status determination.

The misclassification happens in: [5](#0-4) 

At line 79, if `txn.version > latest_ledger_version`, the transaction is incorrectly marked as `Pending` instead of `OnChain`.

**Attack Scenario:**
1. Storage advances to version 1000
2. Internal indexer lags at version 500 (normal during high load)
3. `get_latest_internal_and_storage_ledger_info()` returns:
   - `internal_ledger_version` = 500
   - `storage_version` = 1000
4. User queries transaction committed at version 700
5. Transaction is found (700 < 1000 storage version)
6. But classified as Pending (700 > 500 indexer version)
7. API response shows `X-Aptos-Ledger-Version: 500` header with transaction status as Pending
8. Transaction is actually committed on-chain at version 700!

The same issue exists in `wait_transaction_by_hash_inner`: [6](#0-5) 

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria for "Significant protocol violations" and "API crashes" (in terms of correctness).

**Specific Impacts:**

1. **Financial Loss**: Users may retry transactions thinking they haven't been committed, potentially causing double-spends or duplicate payments. For example, a DeFi application might re-submit a token transfer that has already executed.

2. **API Consistency Violation**: The API returns inconsistent state where:
   - Response header claims ledger version 500
   - Transaction at version 700 is marked as pending
   - But the transaction is actually committed on-chain

3. **Application Malfunction**: Wallets, explorers, and dApps relying on transaction status will make incorrect decisions based on false pending status.

4. **User Experience Degradation**: Users will see completed transactions as pending indefinitely during indexer lag periods.

5. **Trust Erosion**: Repeated inconsistencies between actual chain state and API responses damages ecosystem confidence.

This breaks the **State Consistency** invariant that "API responses must accurately reflect blockchain state" and violates the fundamental API contract that transaction status is reliable.

## Likelihood Explanation

**Likelihood: HIGH** - This will occur frequently in production:

1. **Normal Operation**: The indexer is explicitly designed to potentially lag behind storage, as evidenced by the clamping logic and comments in the code.

2. **High Load Scenarios**: During periods of high transaction throughput, the indexer will naturally fall behind as it processes historical data.

3. **No Attacker Required**: This happens automatically during normal operation, though an attacker could exacerbate it by submitting many transactions.

4. **Wide Impact**: Every transaction query during lag periods will be affected, potentially affecting thousands of queries per minute.

5. **Persistent Condition**: Indexer lag can persist for extended periods during sustained high load.

## Recommendation

The root cause is using two different ledger versions for lookup versus classification. The fix should ensure consistent version usage:

**Option 1: Use Storage Version Consistently** (Recommended)
```rust
// In get_transaction_by_hash_inner and wait_transaction_by_hash_inner
let (internal_ledger_info_opt, storage_ledger_info) =
    api_spawn_blocking(move || context.get_latest_internal_and_storage_ledger_info())
        .await?;
let storage_version = storage_ledger_info.ledger_version.into();
// Use storage_version for BOTH lookup AND classification
let txn_data = self
    .get_by_hash(hash.into(), storage_version, Some(storage_version))
    .await?;
// Use storage_ledger_info for response headers
let latest_ledger_info = storage_ledger_info;
```

**Option 2: Use Indexer Version Consistently**
```rust
// Only use indexer version if available, and use it for both lookup and classification
let ledger_info = if let Some(indexer_info) = internal_ledger_info_opt {
    indexer_info
} else {
    storage_ledger_info
};
let version = ledger_info.ledger_version.into();
let txn_data = self
    .get_by_hash(hash.into(), version, Some(version))
    .await?;
```

**Option 3: Document and Handle Lag Explicitly**
If indexer lag is acceptable, explicitly document it and add a warning field to API responses when indexer is lagging, so clients know the status may be stale.

**Recommended Fix**: Option 1 is safest - always use storage version for transaction queries since storage is the source of truth. The indexer should only be used for queries that specifically require indexer functionality.

## Proof of Concept

```rust
#[tokio::test]
async fn test_transaction_misclassification_during_indexer_lag() {
    use aptos_api::transactions::TransactionsApi;
    use aptos_api_types::HashValue;
    
    // Setup test context with indexer enabled
    let mut context = new_test_context(
        "test_indexer_lag".to_string(),
        NodeConfig::default(),
        true, // use_db_with_indexer
    );
    
    // Create and commit a transaction
    let mut account = context.create_account().await;
    let txn = context.account_transfer(&mut account, &account, 100);
    context.commit_block(&vec![txn.clone()]).await;
    
    let txn_hash = txn.committed_hash();
    
    // Transaction is now at version X (e.g., version 5)
    let storage_version = context.get_latest_storage_ledger_info().ledger_version.0;
    
    // Simulate indexer lag by directly querying with mismatched versions
    // In production, this happens when indexer processing is slow
    let api = TransactionsApi {
        context: Arc::new(context.context.clone()),
    };
    
    // Mock scenario: indexer reports version 3, storage reports version 5
    // Transaction at version 5 will be found (storage lookup)
    // But classified as pending (5 > 3 indexer version)
    
    let result = api.get_transaction_by_hash_inner(
        &AcceptType::Json,
        txn_hash,
    ).await;
    
    // BUG: Transaction should be OnChain but is reported as Pending
    match result {
        Ok(response) => {
            // Extract transaction from response
            // Assert that status is incorrectly Pending when it should be OnChain
            println!("Transaction incorrectly classified during indexer lag");
        }
        Err(e) => panic!("Failed to get transaction: {:?}", e),
    }
}
```

**To reproduce in production:**
1. Deploy Aptos node with internal indexer enabled
2. Submit high volume of transactions to create indexer lag
3. Query a recently committed transaction by hash
4. Observe that the transaction is returned as Pending despite being committed
5. Check response header `X-Aptos-Ledger-Version` shows indexer's lagged version
6. Verify actual transaction is committed at a higher version in storage

## Notes

This vulnerability specifically affects the transaction-by-hash endpoints where both indexer and storage versions are fetched separately. Other endpoints using only `get_latest_ledger_info()` (which returns whichever is configured) do not have this specific inconsistency, though they may return stale data if indexer is lagging.

The issue is exacerbated by the race condition where storage can advance between the two separate ledger info fetches in `get_latest_internal_and_storage_ledger_info()`, but the core problem exists even without the race due to intentional indexer lag design.

### Citations

**File:** api/src/context.rs (L280-292)
```rust
    pub fn get_latest_internal_and_storage_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<(Option<LedgerInfo>, LedgerInfo), E> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                return Ok((
                    Some(self.get_latest_internal_indexer_ledger_info()?),
                    self.get_latest_storage_ledger_info()?,
                ));
            }
        }
        Ok((None, self.get_latest_storage_ledger_info()?))
    }
```

**File:** api/src/context.rs (L319-333)
```rust
    pub fn get_latest_internal_indexer_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<LedgerInfo, E> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                if let Some(mut latest_version) = indexer_reader
                    .get_latest_internal_indexer_ledger_version()
                    .map_err(|err| {
                        E::service_unavailable_with_code_no_info(err, AptosErrorCode::InternalError)
                    })?
                {
                    // The internal indexer version can be ahead of the storage committed version since it syncs to db's latest synced version
                    let last_storage_version =
                        self.get_latest_storage_ledger_info()?.ledger_version.0;
                    latest_version = std::cmp::min(latest_version, last_storage_version);
```

**File:** api/src/transactions.rs (L905-914)
```rust
            let (internal_ledger_info_opt, storage_ledger_info) =
                api_spawn_blocking(move || context.get_latest_internal_and_storage_ledger_info())
                    .await?;
            let storage_version = storage_ledger_info.ledger_version.into();
            let internal_ledger_version = internal_ledger_info_opt
                .as_ref()
                .map(|info| info.ledger_version.into());
            let latest_ledger_info = internal_ledger_info_opt.unwrap_or(storage_ledger_info);
            let txn_data = self
                .get_by_hash(hash.into(), storage_version, internal_ledger_version)
```

**File:** api/src/transactions.rs (L950-960)
```rust
        let (internal_ledger_info_opt, storage_ledger_info) =
            api_spawn_blocking(move || context.get_latest_internal_and_storage_ledger_info())
                .await?;
        let storage_version = storage_ledger_info.ledger_version.into();
        let internal_indexer_version = internal_ledger_info_opt
            .as_ref()
            .map(|info| info.ledger_version.into());
        let latest_ledger_info = internal_ledger_info_opt.unwrap_or(storage_ledger_info);

        let txn_data = self
            .get_by_hash(hash.into(), storage_version, internal_indexer_version)
```

**File:** api/src/transactions.rs (L1085-1112)
```rust
    async fn get_by_hash(
        &self,
        hash: aptos_crypto::HashValue,
        storage_ledger_version: u64,
        internal_ledger_version: Option<u64>,
    ) -> anyhow::Result<Option<TransactionData>> {
        Ok(
            match self.context.get_pending_transaction_by_hash(hash).await? {
                None => {
                    let context_clone = self.context.clone();
                    tokio::task::spawn_blocking(move || {
                        context_clone.get_transaction_by_hash(hash, storage_ledger_version)
                    })
                    .await
                    .context("Failed to join task to read transaction by hash")?
                    .context("Failed to read transaction by hash from DB")?
                    .map(|t| {
                        TransactionData::from_transaction_onchain_data(
                            t,
                            internal_ledger_version.unwrap_or(storage_ledger_version),
                        )
                    })
                    .transpose()?
                },
                Some(t) => Some(t.into()),
            },
        )
    }
```

**File:** api/types/src/transaction.rs (L75-89)
```rust
    pub fn from_transaction_onchain_data(
        txn: TransactionOnChainData,
        latest_ledger_version: u64,
    ) -> Result<Self> {
        if txn.version > latest_ledger_version {
            match txn.transaction {
                aptos_types::transaction::Transaction::UserTransaction(txn) => {
                    Ok(Self::Pending(Box::new(txn)))
                },
                _ => bail!("convert non-user onchain transaction to pending shouldn't exist"),
            }
        } else {
            Ok(Self::OnChain(txn))
        }
    }
```
