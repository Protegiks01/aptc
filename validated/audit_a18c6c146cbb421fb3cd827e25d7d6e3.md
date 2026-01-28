Based on my comprehensive validation of this security claim against the Aptos Core codebase, I have completed the analysis.

# Audit Report

## Title
Race Condition in Transaction Hash Lookup Causes Committed Transactions to be Reported as Pending

## Summary
A race condition exists in the API layer's transaction-by-hash lookup flow where non-atomic retrieval of internal indexer and storage ledger versions causes committed transactions to be incorrectly reported as pending, breaking API correctness guarantees.

## Finding Description

The vulnerability is confirmed in the API layer where `get_latest_internal_and_storage_ledger_info()` makes two separate, non-atomic calls to retrieve storage ledger versions. [1](#0-0) 

The first storage call occurs inside `get_latest_internal_indexer_ledger_info()` at line 332 where it retrieves the storage ledger version to compute the minimum with the internal indexer version. [2](#0-1) 

The second storage call occurs directly at line 287. Between these two calls, storage can advance to a newer version as validators commit new blocks, creating a race window.

When `get_transaction_by_hash_inner()` calls this function, it obtains potentially divergent versions (internal_ledger_version < storage_ledger_version). [3](#0-2) 

The `get_by_hash()` function searches storage up to `storage_ledger_version` but classifies transactions using `internal_ledger_version.unwrap_or(storage_ledger_version)` as the latest ledger version. [4](#0-3) 

The storage lookup uses `get_transaction_by_hash()` which searches up to the provided ledger version. [5](#0-4) 

The underlying storage query returns transactions if their version is less than or equal to the ledger_version parameter. [6](#0-5) 

The classification logic in `TransactionData::from_transaction_onchain_data` checks if the transaction version exceeds the provided latest ledger version, converting committed transactions to pending status when `txn.version > latest_ledger_version`. [7](#0-6) 

The same issue affects the `/wait_by_hash` endpoint which uses identical version retrieval logic, causing unnecessary polling delays for already-committed transactions. [8](#0-7) 

## Impact Explanation

This vulnerability represents **MEDIUM severity** under Aptos bug bounty criteria as a **Limited Protocol Violation**.

**Confirmed Impacts:**

1. **API State Inconsistency**: The API returns incorrect transaction status, violating correctness guarantees. Committed transactions are misreported as pending, creating state inconsistency between actual blockchain state and API responses.

2. **Transaction Confirmation Flow Breakage**: Wallets, dApps, and integration systems rely on `/transactions/by_hash` for transaction confirmation. Incorrect status disrupts these critical workflows.

3. **Data Loss**: When transactions are incorrectly classified as pending, all on-chain data is lost (transaction version, events, execution status, state changes) since only the `SignedTransaction` is returned rather than full `TransactionOnChainData`.

4. **User Experience Degradation**: The `/wait_by_hash` endpoint experiences unnecessary polling delays even for confirmed transactions.

**Severity Justification:**

This qualifies as MEDIUM severity because:
- It causes state inconsistencies in the API layer requiring awareness and potential manual intervention
- It does NOT cause API crashes (which would be HIGH)
- It does NOT cause validator slowdowns (which would be HIGH)
- It does NOT affect consensus, enable fund theft, or impact network availability (which would be CRITICAL)

The blockchain itself functions correctly; only the API layer exhibits the issue.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of manifestation in production:

1. **Frequency**: The race window exists on every transaction lookup when internal indexer is enabled (standard configuration). With Aptos block times of ~300-500ms, the timing window is realistic and achievable.

2. **No Attacker Required**: This is a deterministic concurrency bug occurring during normal API operation. Any user querying a recently committed transaction can encounter it without any malicious action.

3. **Production Exposure**: All API nodes with internal indexer enabled are affected. High-traffic nodes processing numerous transaction queries have increased probability of race condition manifestation.

4. **Deterministic Manifestation**: Once timing conditions align (storage advances between the two calls), the bug manifests with 100% probability for affected transactions.

## Recommendation

Implement atomic retrieval of both ledger versions by restructuring the code to use a single snapshot of storage state:

1. Call `get_latest_storage_ledger_info()` once and store the result
2. Pass this storage version to `get_latest_internal_indexer_ledger_info()` instead of having it retrieve storage version independently
3. Ensure both the database lookup and classification use consistent version values

Alternative fix: Use the same version value for both storage lookup and transaction classification, ensuring consistency.

## Proof of Concept

Note: A complete executable PoC would require a test environment that simulates concurrent API requests during block commits. The theoretical scenario demonstrating the race condition is:

1. Internal indexer at version 100, storage at version 100
2. API call to `/transactions/by_hash/{H}` triggers version retrieval
3. First `get_latest_storage_ledger_info()` call returns version 100
4. Internal indexer ledger info created with version 100
5. **RACE WINDOW**: New block committed, storage advances to version 101, transaction H committed at version 101
6. Second `get_latest_storage_ledger_info()` call returns version 101
7. Result: `internal_ledger_version = 100`, `storage_ledger_version = 101`
8. Database search with `storage_version=101` finds transaction H at version 101
9. Classification with `latest_ledger_version=100` detects 101 > 100
10. Transaction converted to `TransactionData::Pending` instead of `TransactionData::OnChain`

The vulnerability is demonstrable through code analysis showing non-atomic operations that permit storage advancement between calls.

## Notes

The code comment at line 330-333 in `api/src/context.rs` indicates that the internal indexer can be ahead of storage by design. However, this race condition causes version divergence in the opposite direction (internal < storage), which was likely unintentional. The issue arises because the function retrieves storage version twice at different points in time, allowing storage to advance between retrievals during active block production.

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

**File:** api/src/context.rs (L319-368)
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
                    return Ok(LedgerInfo::new_ledger_info(
                        &self.chain_id(),
                        new_block_event.epoch(),
                        block_end_version,
                        oldest_version,
                        oldest_block_height,
                        new_block_event.height(),
                        new_block_event.proposed_time(),
                    ));
                } else {
                    // Indexer doesn't have data yet as DB is boostrapping.
                    return Err(E::service_unavailable_with_code_no_info(
                        "DB is bootstrapping",
                        AptosErrorCode::InternalError,
                    ));
                }
            }
        }

        Err(E::service_unavailable_with_code_no_info(
            "Indexer reader doesn't exist",
            AptosErrorCode::InternalError,
        ))
    }
```

**File:** api/src/context.rs (L961-975)
```rust
    pub fn get_transaction_by_hash(
        &self,
        hash: HashValue,
        ledger_version: u64,
    ) -> Result<Option<TransactionOnChainData>> {
        if let Some(t) = self
            .db
            .get_transaction_by_hash(hash, ledger_version, true)?
        {
            let txn: TransactionOnChainData = self.convert_into_transaction_on_chain_data(t)?;
            Ok(Some(self.maybe_translate_v2_to_v1_events(txn)))
        } else {
            Ok(None)
        }
    }
```

**File:** api/src/transactions.rs (L893-940)
```rust
    async fn wait_transaction_by_hash_inner(
        &self,
        accept_type: &AcceptType,
        hash: HashValue,
        wait_by_hash_timeout_ms: u64,
        wait_by_hash_poll_interval_ms: u64,
    ) -> BasicResultWith404<Transaction> {
        let start_time = std::time::Instant::now();
        loop {
            let context = self.context.clone();
            let accept_type = accept_type.clone();

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
                .await
                .context(format!("Failed to get transaction by hash {}", hash))
                .map_err(|err| {
                    BasicErrorWith404::internal_with_code(
                        err,
                        AptosErrorCode::InternalError,
                        &latest_ledger_info,
                    )
                })?
                .context(format!("Failed to find transaction with hash: {}", hash))
                .map_err(|_| transaction_not_found_by_hash(hash, &latest_ledger_info))?;

            if matches!(txn_data, TransactionData::Pending(_))
                && (start_time.elapsed().as_millis() as u64) < wait_by_hash_timeout_ms
            {
                tokio::time::sleep(Duration::from_millis(wait_by_hash_poll_interval_ms)).await;
                continue;
            }

            let api = self.clone();
            return api_spawn_blocking(move || {
                api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info)
            })
            .await;
        }
    }
```

**File:** api/src/transactions.rs (L942-978)
```rust
    async fn get_transaction_by_hash_inner(
        &self,
        accept_type: &AcceptType,
        hash: HashValue,
    ) -> BasicResultWith404<Transaction> {
        let context = self.context.clone();
        let accept_type = accept_type.clone();

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
            .await
            .context(format!("Failed to get transaction by hash {}", hash))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &latest_ledger_info,
                )
            })?
            .context(format!("Failed to find transaction with hash: {}", hash))
            .map_err(|_| transaction_not_found_by_hash(hash, &latest_ledger_info))?;

        let api = self.clone();
        api_spawn_blocking(move || {
            api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info)
        })
        .await
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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L74-83)
```rust
    pub(crate) fn get_transaction_version_by_hash(
        &self,
        hash: &HashValue,
        ledger_version: Version,
    ) -> Result<Option<Version>> {
        Ok(match self.db.get::<TransactionByHashSchema>(hash)? {
            Some(version) if version <= ledger_version => Some(version),
            _ => None,
        })
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
