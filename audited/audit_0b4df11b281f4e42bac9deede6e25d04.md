# Audit Report

## Title
Race Condition in Transaction Retrieval Causes Committed Transactions to be Misclassified as Pending with Lost Version Information

## Summary
A race condition in `get_transaction_by_hash_inner()` between fetching internal indexer and storage ledger versions causes committed transactions to be incorrectly classified as pending, losing their version information in the API response. This breaks the **State Consistency** invariant by reporting inconsistent transaction states to clients.

## Finding Description

The vulnerability exists in the `get_transaction_by_hash_inner()` function when the internal indexer is enabled. The function calls `get_latest_internal_and_storage_ledger_info()` which has a critical race condition: [1](#0-0) 

The internal indexer info is fetched first, which internally clamps to the storage version at time T1: [2](#0-1) 

Then storage ledger info is fetched separately at time T2. Between T1 and T2, new transactions can be committed to storage, causing:
- `internal_indexer_version` = S1 (storage version at T1)
- `storage_version` = S2 (storage version at T2, where S2 > S1)

In `get_transaction_by_hash_inner()`, these mismatched versions are used: [3](#0-2) 

The transaction search queries storage up to S2, but classification uses S1: [4](#0-3) 

For transactions at version V where S1 < V ≤ S2:
1. Transaction is **found** in storage (searched up to S2)
2. But `from_transaction_onchain_data(txn, S1)` is called
3. Since V > S1, the transaction is **misclassified as Pending**: [5](#0-4) 

The misclassified transaction is then converted to `PendingTransaction` which **lacks a version field**: [6](#0-5) 

The version information is completely lost, as confirmed by the `Transaction::version()` method: [7](#0-6) 

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for "State inconsistencies requiring intervention":

1. **Client Confusion**: Committed transactions appear as pending, breaking transaction tracking systems
2. **Lost Version Data**: Critical version information is absent from API responses
3. **Inconsistent State**: Response header shows ledger version S1, but transaction exists at version V > S1
4. **Indexer Failures**: External indexers relying on the API will miss or misindex transactions
5. **Confirmation Logic Breaks**: Applications waiting for transaction confirmation will fail
6. **Audit Trail Corruption**: Transaction history becomes incomplete and unreliable

While this doesn't directly cause fund loss, it violates the State Consistency invariant and requires manual intervention to detect and remediate affected clients.

## Likelihood Explanation

**Likelihood: Medium to High**

This race condition occurs naturally during normal node operation:
- Occurs whenever transactions are committed between T1 and T2 (microseconds window)
- More likely during high transaction throughput periods
- Internal indexer is typically enabled on full nodes serving API requests
- No attacker action required - happens during routine operation
- Affects real-world deployments continuously

The window is small but transactions are queried frequently, making this issue likely to manifest regularly in production environments.

## Recommendation

**Solution**: Fetch both ledger infos atomically or use consistent snapshot:

```rust
pub fn get_latest_internal_and_storage_ledger_info<E: ServiceUnavailableError>(
    &self,
) -> Result<(Option<LedgerInfo>, LedgerInfo), E> {
    // Fetch storage info first
    let storage_info = self.get_latest_storage_ledger_info()?;
    
    if let Some(indexer_reader) = self.indexer_reader.as_ref() {
        if indexer_reader.is_internal_indexer_enabled() {
            // Get internal indexer version and clamp to the ALREADY FETCHED storage version
            if let Some(mut latest_version) = indexer_reader
                .get_latest_internal_indexer_ledger_version()
                .map_err(|err| {
                    E::service_unavailable_with_code_no_info(err, AptosErrorCode::InternalError)
                })?
            {
                // Use the already-fetched storage version for clamping
                latest_version = std::cmp::min(latest_version, storage_info.ledger_version.0);
                let (_, block_end_version, new_block_event) = self
                    .db
                    .get_block_info_by_version(latest_version)
                    .map_err(|_| {
                        E::service_unavailable_with_code_no_info(
                            "Failed to get block",
                            AptosErrorCode::InternalError,
                        )
                    })?;
                let (oldest_version, oldest_block_height) =
                    self.get_oldest_version_and_block_height()?;
                return Ok((
                    Some(LedgerInfo::new_ledger_info(
                        &self.chain_id(),
                        new_block_event.epoch(),
                        block_end_version,
                        oldest_version,
                        oldest_block_height,
                        new_block_event.height(),
                        new_block_event.proposed_time(),
                    )),
                    storage_info,
                ));
            }
        }
    }
    Ok((None, storage_info))
}
```

This ensures both versions are consistent by fetching storage info once and reusing it for clamping.

## Proof of Concept

```rust
// Rust test demonstrating the race condition
#[tokio::test]
async fn test_transaction_misclassification_race() {
    // Setup: Node with internal indexer enabled
    let (context, storage) = setup_test_node_with_internal_indexer();
    
    // Initial state: both at version 100
    storage.commit_transactions_to_version(100);
    wait_for_indexer_sync();
    
    // Simulate race condition:
    // Thread 1: Start get_transaction_by_hash_inner()
    let api = TransactionsApi { context: context.clone() };
    
    // Concurrent thread 2: Commit new transaction at version 101
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_micros(10)).await;
        storage.commit_transaction_at_version(101, test_transaction());
    });
    
    // Thread 1 continues:
    // - get_latest_internal_indexer_ledger_info() reads version 100
    // - get_latest_storage_ledger_info() reads version 101 (race occurred)
    // - Queries transaction at version 101
    let response = api.get_transaction_by_hash_inner(
        &AcceptType::Json,
        test_transaction().hash(),
    ).await.unwrap();
    
    // Vulnerability: Transaction at v101 is misclassified as Pending
    match response {
        Transaction::PendingTransaction(_) => {
            // BUG: Should be UserTransaction with version 101
            assert!(false, "Transaction at v101 wrongly classified as pending");
        },
        Transaction::UserTransaction(txn) => {
            assert_eq!(txn.info.version.0, 101, "Should have correct version");
        },
        _ => panic!("Unexpected transaction type"),
    }
}
```

**Notes:**
While the security question specifically asks about "internal_ledger_version being None", the actual vulnerability occurs when it's Some but stale due to the race condition. When None (internal indexer disabled), both values consistently use storage_ledger_version and no misclassification occurs. The race between the two separate fetches in `get_latest_internal_and_storage_ledger_info()` is the root cause, allowing the internal indexer version to lag behind storage version within the same API call.

### Citations

**File:** api/src/context.rs (L283-289)
```rust
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                return Ok((
                    Some(self.get_latest_internal_indexer_ledger_info()?),
                    self.get_latest_storage_ledger_info()?,
                ));
            }
```

**File:** api/src/context.rs (L330-333)
```rust
                    // The internal indexer version can be ahead of the storage committed version since it syncs to db's latest synced version
                    let last_storage_version =
                        self.get_latest_storage_ledger_info()?.ledger_version.0;
                    latest_version = std::cmp::min(latest_version, last_storage_version);
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

**File:** api/src/transactions.rs (L1096-1104)
```rust
                        context_clone.get_transaction_by_hash(hash, storage_ledger_version)
                    })
                    .await
                    .context("Failed to join task to read transaction by hash")?
                    .context("Failed to read transaction by hash from DB")?
                    .map(|t| {
                        TransactionData::from_transaction_onchain_data(
                            t,
                            internal_ledger_version.unwrap_or(storage_ledger_version),
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

**File:** api/types/src/transaction.rs (L229-239)
```rust
    pub fn version(&self) -> Option<u64> {
        match self {
            Transaction::UserTransaction(txn) => Some(txn.info.version.into()),
            Transaction::BlockMetadataTransaction(txn) => Some(txn.info.version.into()),
            Transaction::PendingTransaction(_) => None,
            Transaction::GenesisTransaction(txn) => Some(txn.info.version.into()),
            Transaction::StateCheckpointTransaction(txn) => Some(txn.info.version.into()),
            Transaction::BlockEpilogueTransaction(txn) => Some(txn.info.version.into()),
            Transaction::ValidatorTransaction(txn) => Some(txn.transaction_info().version.into()),
        }
    }
```

**File:** api/types/src/transaction.rs (L385-391)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct PendingTransaction {
    pub hash: HashValue,
    #[serde(flatten)]
    #[oai(flatten)]
    pub request: UserTransactionRequest,
}
```
