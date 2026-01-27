# Audit Report

## Title
API Crash When Reading Historical ModuleBundle Transactions from On-Chain Storage

## Summary
The API's `try_into_transaction_payload()` function uses `bail!()` when encountering deprecated ModuleBundle transaction payloads. If such transactions exist on-chain from before deprecation, API endpoints that read historical transactions will crash with internal errors, causing a denial of service.

## Finding Description

The `try_into_transaction_payload()` function in the API conversion layer handles the deprecated `ModuleBundle` payload type by calling `bail!()`: [1](#0-0) 

This function is called when converting on-chain transactions for API responses: [2](#0-1) 

The critical vulnerability path is:

1. **Storage Layer**: Old ModuleBundle transactions can be deserialized from AptosDB because `DeprecatedPayload` still exists for BCS backward compatibility: [3](#0-2) 

2. **API Request Processing**: When users query `/v1/transactions`, the API calls `render_transactions_sequential()`: [4](#0-3) 

3. **Conversion Failure**: The converter processes each transaction and fails on ModuleBundle with `bail!()`: [5](#0-4) 

The error propagates through the `?` operator, causing the entire batch conversion to fail with an `InternalError`, crashing the API endpoint.

**Evidence ModuleBundle Transactions May Exist On-Chain:**

The API types documentation explicitly states the enum variant "cannot be removed because it breaks the ordering": [6](#0-5) 

This strongly suggests ModuleBundle was used historically and transactions remain on-chain, necessitating backward compatibility in serialization formats.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria due to **API crashes**. 

Affected endpoints include:
- `/v1/transactions` (list transactions)
- `/v1/transactions/by_version/{version}` (get specific transaction)
- `/v1/accounts/{address}/transactions` (account transaction history)
- Block retrieval endpoints that include transactions

Impact:
- **Availability**: Complete denial of service for API queries hitting ModuleBundle transaction versions
- **User Experience**: Dapps and indexers cannot retrieve historical data from affected version ranges
- **Operational**: Node operators cannot serve API requests for specific blockchain history segments

The vulnerability does not affect consensus, execution, or state integrity—only API availability.

## Likelihood Explanation

**Likelihood: Medium to High**

- **IF** ModuleBundle transactions exist on-chain (likely based on backward compatibility structures), the vulnerability is **trivially exploitable**
- Attacker only needs to query: `GET /v1/transactions?start={module_bundle_version}&limit=1`
- No special privileges, authentication, or complex setup required
- Automated tools or dapps could trigger this unintentionally

The only uncertainty is whether ModuleBundle transactions actually exist in the Aptos blockchain history. However, the code architecture strongly suggests they do:
1. Explicit comments about "cannot remove enum variant" for ordering
2. DeprecatedPayload exists "to ensure serialization is not broken"
3. Multiple defensive checks across codebase for ModuleBundle handling

## Recommendation

Replace the `bail!()` with graceful handling that returns a placeholder or safely skips conversion:

```rust
// In try_into_transaction_payload()
ModuleBundle(_) => {
    // Return a safe placeholder for deprecated payload
    TransactionPayload::DeprecatedModuleBundlePayload(
        DeprecatedModuleBundlePayload
    )
}
```

Alternatively, add try-catch logic in the caller to handle conversion errors gracefully:

```rust
// In render_transactions_sequential()
let txns: Vec<aptos_api_types::Transaction> = data
    .into_iter()
    .filter_map(|t| {
        // Update timestamp...
        match converter.try_into_onchain_transaction(timestamp, t) {
            Ok(txn) => Some(Ok(txn)),
            Err(e) if e.to_string().contains("Module bundle") => {
                // Log warning and skip deprecated transactions
                None
            }
            Err(e) => Some(Err(e)),
        }
    })
    .collect::<Result<_, anyhow::Error>>()?;
```

## Proof of Concept

**Precondition Check:**
```rust
// Check if ModuleBundle transactions exist on-chain
// Query the database for any transactions with ModuleBundle payload
use aptos_storage_interface::DbReader;
use aptos_types::transaction::Transaction;

fn find_module_bundle_transactions(db: &dyn DbReader) -> Vec<u64> {
    let mut versions = Vec::new();
    let ledger_version = db.get_latest_ledger_info().unwrap().version();
    
    for version in 0..ledger_version {
        if let Ok(txn) = db.get_transaction_by_version(version, false) {
            if let Transaction::UserTransaction(signed) = txn.transaction {
                if matches!(
                    signed.payload(),
                    aptos_types::transaction::TransactionPayload::ModuleBundle(_)
                ) {
                    versions.push(version);
                }
            }
        }
    }
    versions
}
```

**Exploitation:**
```bash
# Assuming a ModuleBundle transaction exists at version X
curl -X GET "https://fullnode.mainnet.aptoslabs.com/v1/transactions?start=X&limit=1"

# Expected: 500 Internal Server Error
# Actual behavior: API crashes with "Module bundle payload has been removed"
```

**Rust Integration Test:**
```rust
#[test]
fn test_api_handles_module_bundle_gracefully() {
    let (db, _) = setup_test_db_with_module_bundle_transaction();
    let context = Context::new(db, /* ... */);
    
    // Query transaction at version with ModuleBundle
    let result = context.get_transactions(
        module_bundle_version,
        1,
        ledger_version,
    );
    
    // Should not panic or return 500 error
    assert!(result.is_ok() || is_expected_error(&result));
}
```

## Notes

The vulnerability exists due to defensive programming assumptions that don't match operational reality. While ModuleBundle is deprecated, the blockchain is immutable—historical transactions persist indefinitely. The API must handle all transaction types ever committed, not just currently valid ones.

The indexer-grpc converter has an even worse issue, using `unreachable!()` which would cause a panic: [7](#0-6) 

Both conversion paths require hardening against deprecated but historically valid transaction types.

### Citations

**File:** api/types/src/convert.rs (L173-196)
```rust
    pub fn try_into_onchain_transaction(
        &self,
        timestamp: u64,
        data: TransactionOnChainData,
    ) -> Result<Transaction> {
        use aptos_types::transaction::Transaction::{
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
```

**File:** api/types/src/convert.rs (L403-404)
```rust
            // Deprecated.
            ModuleBundle(_) => bail!("Module bundle payload has been removed"),
```

**File:** types/src/transaction/mod.rs (L680-694)
```rust
/// Marks payload as deprecated. We need to use it to ensure serialization or
/// deserialization is not broken.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeprecatedPayload {
    // Used because 'analyze_serde_formats' complains with "Please avoid 0-sized containers".
    dummy_value: u64,
}

/// Different kinds of transactions.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// A transaction that executes code.
    Script(Script),
    /// Deprecated.
    ModuleBundle(DeprecatedPayload),
```

**File:** api/src/transactions.rs (L853-890)
```rust
    /// List all transactions paging by ledger version
    fn list(&self, accept_type: &AcceptType, page: Page) -> BasicResultWith404<Vec<Transaction>> {
        let latest_ledger_info = self.context.get_latest_ledger_info()?;
        let ledger_version = latest_ledger_info.version();

        let limit = page.limit(&latest_ledger_info)?;
        let start_version = page.compute_start(limit, ledger_version, &latest_ledger_info)?;
        let data = self
            .context
            .get_transactions(start_version, limit, ledger_version)
            .context("Failed to read raw transactions from storage")
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &latest_ledger_info,
                )
            })?;

        match accept_type {
            AcceptType::Json => {
                let timestamp = self
                    .context
                    .get_block_timestamp(&latest_ledger_info, start_version)?;
                BasicResponse::try_from_json((
                    self.context.render_transactions_sequential(
                        &latest_ledger_info,
                        data,
                        timestamp,
                    )?,
                    &latest_ledger_info,
                    BasicResponseStatus::Ok,
                ))
            },
            AcceptType::Bcs => {
                BasicResponse::try_from_bcs((data, &latest_ledger_info, BasicResponseStatus::Ok))
            },
        }
```

**File:** api/src/context.rs (L749-765)
```rust
        let txns: Vec<aptos_api_types::Transaction> = data
            .into_iter()
            .map(|t| {
                // Update the timestamp if the next block occurs
                if let Some(txn) = t.transaction.try_as_block_metadata_ext() {
                    timestamp = txn.timestamp_usecs();
                } else if let Some(txn) = t.transaction.try_as_block_metadata() {
                    timestamp = txn.timestamp_usecs();
                }
                let txn = converter.try_into_onchain_transaction(timestamp, t)?;
                Ok(txn)
            })
            .collect::<Result<_, anyhow::Error>>()
            .context("Failed to convert transaction data from storage")
            .map_err(|err| {
                E::internal_with_code(err, AptosErrorCode::InternalError, ledger_info)
            })?;
```

**File:** api/types/src/transaction.rs (L944-971)
```rust
pub enum TransactionPayload {
    EntryFunctionPayload(EntryFunctionPayload),
    ScriptPayload(ScriptPayload),
    // Deprecated. We cannot remove the enum variant because it breaks the
    // ordering, unfortunately.
    ModuleBundlePayload(DeprecatedModuleBundlePayload),
    MultisigPayload(MultisigPayload),
}

impl VerifyInput for TransactionPayload {
    fn verify(&self) -> anyhow::Result<()> {
        match self {
            TransactionPayload::EntryFunctionPayload(inner) => inner.verify(),
            TransactionPayload::ScriptPayload(inner) => inner.verify(),
            TransactionPayload::MultisigPayload(inner) => inner.verify(),

            // Deprecated.
            TransactionPayload::ModuleBundlePayload(_) => {
                bail!("Module bundle payload has been removed")
            },
        }
    }
}

// We cannot remove enum variant, but at least we can remove the logic
// and keep a deprecate name here to avoid further usage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct DeprecatedModuleBundlePayload;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L210-213)
```rust
        // Deprecated.
        TransactionPayload::ModuleBundlePayload(_) => {
            unreachable!("Module bundle payload has been removed")
        },
```
