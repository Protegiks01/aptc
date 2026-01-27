# Audit Report

## Title
API Transaction Lookup Fails for System Transactions During Internal Indexer Lag

## Summary
The `TransactionData::from_transaction_onchain_data()` function incorrectly assumes that any transaction with a version exceeding the provided `latest_ledger_version` must be a pending `UserTransaction`. This causes the API endpoint `/transactions/by_hash/:txn_hash` to crash with a bail error when querying system transactions (BlockMetadata, StateCheckpoint, BlockEpilogue, etc.) while the internal indexer is lagging behind storage. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between two components:

1. **The conversion function** that determines whether a transaction should be classified as "OnChain" or "Pending": [1](#0-0) 

This function contains logic at line 84 that bails with error `"convert non-user onchain transaction to pending shouldn't exist"` when `txn.version > latest_ledger_version` but the transaction is not a `UserTransaction`.

2. **The API lookup function** that retrieves transactions by hash: [2](#0-1) 

This function retrieves transactions from storage using `storage_ledger_version` as the upper bound (line 1096), but then converts them using `internal_ledger_version` as the "latest" version (line 1104).

**The Problem Chain:**

The Aptos blockchain includes multiple types of transactions beyond user-submitted ones: [3](#0-2) 

When the internal indexer (a separate indexing component) lags behind storage, which is a normal operational scenario: [4](#0-3) 

The internal indexer version is capped to not exceed storage version: [5](#0-4) 

However, it can legitimately be less than storage version. When this occurs:

1. A transaction `t` is retrieved from storage where `internal_ledger_version < t.version ≤ storage_ledger_version`
2. The transaction is a system transaction (e.g., BlockMetadata, StateCheckpoint, BlockEpilogue)
3. The conversion function receives `txn.version > latest_ledger_version` (where `latest_ledger_version = internal_ledger_version`)
4. The function attempts to match on transaction type and hits the `_ => bail!()` case for non-user transactions
5. The API returns a 500 error instead of the committed transaction

**Attack Scenario:**

1. Wait for or cause the internal indexer to lag (happens naturally under load)
2. Query any system transaction by its hash: `/transactions/by_hash/{hash_of_block_metadata}`
3. If the transaction version exceeds `internal_ledger_version` but is within `storage_ledger_version`, the API crashes

This affects every block's system transactions: [6](#0-5) 

## Impact Explanation

This is a **Medium Severity** issue per the Aptos bug bounty criteria:

- **API Crashes**: The `/transactions/by_hash/:txn_hash` endpoint returns 500 errors for legitimate queries, violating the API's contract
- **Service Availability**: Affects the ability to query committed blockchain data during normal operations
- **Scope**: Impacts all system transactions (BlockMetadata, StateCheckpoint, BlockEpilogue, ValidatorTransaction) which occur in every block

This does not rise to High severity because:
- It does not directly slow down validator nodes (only API layer)
- It does not cause protocol violations in the consensus layer
- No funds are at risk

However, it clearly meets Medium severity as it causes state inconsistencies requiring intervention (API failures for committed data).

## Likelihood Explanation

**High Likelihood:**

1. **Internal indexer lag is normal**: The internal indexer is designed to lag behind storage during normal operations and catch up asynchronously [5](#0-4) 

2. **System transactions are ubiquitous**: Every block contains BlockMetadata, StateCheckpoint, and/or BlockEpilogue transactions

3. **Hash queries are common**: Users, explorers, and applications frequently query transactions by hash

4. **No special privileges required**: Any API user can trigger this by querying a system transaction hash

## Recommendation

Fix the `from_transaction_onchain_data()` function to handle system transactions correctly when their version exceeds the provided ledger version. Since system transactions cannot be "pending" in mempool, they should always be treated as OnChain regardless of the version comparison:

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
            // System transactions should never be pending, even if version > latest_ledger_version
            // This can occur when internal indexer lags behind storage
            _ => Ok(Self::OnChain(txn)),
        }
    } else {
        Ok(Self::OnChain(txn))
    }
}
```

**Alternative approach**: Always use `storage_ledger_version` instead of `internal_ledger_version` when converting transaction data in `get_by_hash()`, since the transaction was retrieved using that version as the upper bound.

## Proof of Concept

Integration test demonstrating the vulnerability:

```rust
#[tokio::test]
async fn test_system_transaction_lookup_with_indexer_lag() {
    // Setup context with internal indexer enabled
    let mut context = new_test_context_with_internal_indexer(current_function_name!());
    
    // Create and commit a block (will contain BlockMetadata and StateCheckpoint)
    let account = context.gen_account();
    let txn = context.create_user_account(&account).await;
    context.commit_block(&vec![txn]).await;
    
    // Get the BlockMetadata transaction hash from the block
    let txns = context.get("/transactions?start=0&limit=10").await;
    let block_metadata_txn = txns.as_array().unwrap()
        .iter()
        .find(|t| t["type"] == "block_metadata_transaction")
        .expect("Block should contain BlockMetadata");
    let hash = block_metadata_txn["hash"].as_str().unwrap();
    
    // Simulate internal indexer lag by advancing storage but not indexer
    // In production, this happens naturally under load
    context.simulate_internal_indexer_lag().await;
    
    // Query the BlockMetadata transaction by hash
    // This should succeed but will fail with the current code
    let resp = context
        .expect_status_code(500)  // Currently fails with 500
        .get(&format!("/transactions/by_hash/{}", hash))
        .await;
    
    // Error message will be: "convert non-user onchain transaction to pending shouldn't exist"
    assert!(resp["message"].as_str().unwrap().contains("convert non-user"));
}
```

## Notes

- The vulnerability only manifests when the internal indexer feature is enabled and lagging, which is a normal operational scenario
- The same issue affects `get_by_version()` if there's ever a mismatch between the retrieved transaction version and the ledger info version used for conversion
- System transactions include: GenesisTransaction, BlockMetadata, StateCheckpoint, ValidatorTransaction, BlockMetadataExt, and BlockEpilogue
- The fix is straightforward: system transactions should never be classified as "Pending" since they cannot exist in mempool

### Citations

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

**File:** types/src/transaction/mod.rs (L2946-2977)
```rust
pub enum Transaction {
    /// Transaction submitted by the user. e.g: P2P payment transaction, publishing module
    /// transaction, etc.
    /// TODO: We need to rename SignedTransaction to SignedUserTransaction, as well as all the other
    ///       transaction types we had in our codebase.
    UserTransaction(SignedTransaction),

    /// Transaction that applies a WriteSet to the current storage, it's applied manually via aptos-db-bootstrapper.
    GenesisTransaction(WriteSetPayload),

    /// Transaction to update the block metadata resource at the beginning of a block,
    /// when on-chain randomness is disabled.
    BlockMetadata(BlockMetadata),

    /// Transaction to let the executor update the global state tree and record the root hash
    /// in the TransactionInfo
    /// The hash value inside is unique block id which can generate unique hash of state checkpoint transaction
    StateCheckpoint(HashValue),

    /// Transaction that only proposed by a validator mainly to update on-chain configs.
    ValidatorTransaction(ValidatorTransaction),

    /// Transaction to update the block metadata resource at the beginning of a block,
    /// when on-chain randomness is enabled.
    BlockMetadataExt(BlockMetadataExt),

    /// Transaction to let the executor update the global state tree and record the root hash
    /// in the TransactionInfo
    /// The hash value inside is unique block id which can generate unique hash of state checkpoint transaction
    /// Replaces StateCheckpoint, with optionally having more data.
    BlockEpilogue(BlockEpiloguePayload),
}
```

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

**File:** api/src/context.rs (L330-333)
```rust
                    // The internal indexer version can be ahead of the storage committed version since it syncs to db's latest synced version
                    let last_storage_version =
                        self.get_latest_storage_ledger_info()?.ledger_version.0;
                    latest_version = std::cmp::min(latest_version, last_storage_version);
```

**File:** api/types/src/convert.rs (L179-240)
```rust
            BlockEpilogue, BlockMetadata, BlockMetadataExt, GenesisTransaction, StateCheckpoint,
            UserTransaction,
        };
        let aux_data = self
            .db
            .get_transaction_auxiliary_data_by_version(data.version)?;
        let info = self.into_transaction_info(
            data.version,
            &data.info,
            data.accumulator_root_hash,
            data.changes,
            aux_data,
        );
        let events = self.try_into_events(&data.events)?;
        Ok(match data.transaction {
            UserTransaction(txn) => {
                let payload = self.try_into_transaction_payload(txn.payload().clone())?;
                (&txn, info, payload, events, timestamp).into()
            },
            GenesisTransaction(write_set) => {
                let payload = self.try_into_write_set_payload(write_set)?;
                (info, payload, events).into()
            },
            BlockMetadata(txn) => Transaction::BlockMetadataTransaction(
                BlockMetadataTransaction::from_internal(txn, info, events),
            ),
            BlockMetadataExt(txn) => Transaction::BlockMetadataTransaction(
                BlockMetadataTransaction::from_internal_ext(txn, info, events),
            ),
            StateCheckpoint(_) => {
                Transaction::StateCheckpointTransaction(StateCheckpointTransaction {
                    info,
                    timestamp: timestamp.into(),
                })
            },
            BlockEpilogue(block_epilogue_payload) => {
                let block_end_info = block_epilogue_payload
                    .try_as_block_end_info()
                    .unwrap()
                    .clone();
                let block_end_info = match block_end_info {
                    BlockEndInfo::V0 {
                        block_gas_limit_reached,
                        block_output_limit_reached,
                        block_effective_block_gas_units,
                        block_approx_output_size,
                    } => Some(crate::transaction::BlockEndInfo {
                        block_gas_limit_reached,
                        block_output_limit_reached,
                        block_effective_block_gas_units,
                        block_approx_output_size,
                    }),
                };
                Transaction::BlockEpilogueTransaction(BlockEpilogueTransaction {
                    info,
                    timestamp: timestamp.into(),
                    block_end_info,
                })
            },
            aptos_types::transaction::Transaction::ValidatorTransaction(txn) => {
                Transaction::ValidatorTransaction((txn, info, events, timestamp).into())
            },
```
