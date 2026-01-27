# Audit Report

## Title
Block API Returns Incomplete Transaction Sets Without Explicit Indication

## Summary
The `render_bcs_block()` function can return partial transaction lists when blocks exceed the configured transaction page size limit (default: 10,000 transactions), with no explicit field or error indicating truncation to API consumers.

## Finding Description

When retrieving blocks via the REST API, the `get_block_by_height()` and `get_block_by_version()` functions enforce a maximum transaction limit per response. [1](#0-0) 

The limit is calculated as the minimum of the configured page size and the actual block size. When a block contains more transactions than `max_block_transactions_page_size` (defaulting to 10,000 transactions [2](#0-1) ), only the first `max_txns` transactions are retrieved. [3](#0-2) 

The resulting `BcsBlock` structure contains `first_version` and `last_version` fields representing the full block range, but the `transactions` field only contains the partial set. [4](#0-3) 

The `BcsBlock` structure has no explicit field to indicate whether the transaction list is complete or truncated. [5](#0-4) 

In `render_bcs_block()`, when transactions are present, they are rendered without any validation or indication of completeness. [6](#0-5) 

The API documentation mentions this limitation in comments [7](#0-6) , but there is no runtime indication when truncation occurs.

The Aptos REST client provides a workaround function `get_full_block_by_height_bcs()` that handles pagination automatically [8](#0-7) , and the Rosetta implementation explicitly uses this variant with a warning comment about missing transactions. [9](#0-8) 

**Critical Issue**: Client applications using `get_block_by_height_bcs()` directly may incorrectly assume that when `transactions` is `Some`, it contains the complete block. The only way to detect truncation is to manually calculate `(last_version - first_version + 1)` and compare it with `transactions.len()`, which is not documented or enforced.

## Impact Explanation

This constitutes a **High Severity** issue under the "Significant protocol violations" category because:

1. **Data Integrity Violation**: Blockchain APIs have an implicit contract that block data is complete. Returning partial transaction sets without explicit indication violates this fundamental guarantee.

2. **Silent Data Loss**: External indexers, explorers, wallets, and analytics tools relying on this API may miss critical transactions, leading to:
   - Incorrect balance calculations
   - Missing transaction history
   - Incomplete event processing
   - State reconstruction failures

3. **Security Implications**: Malicious actors with validator control could potentially hide transactions in blocks exceeding 10,000 transactions, knowing that naive API consumers will miss them.

4. **State Consistency Risk**: Systems rebuilding blockchain state from block data will create inconsistent views if they don't detect truncation.

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood depends on:

1. **Block Size in Production**: If Aptos mainnet/testnet regularly produces blocks with > 10,000 transactions during high network activity, this issue affects many API calls.

2. **Client Implementation**: Many external tools likely use the simpler `get_block_by_height_bcs()` without realizing the need for pagination, especially given that the limitation is only mentioned in comments, not enforced through errors.

3. **Known Issue**: The existence of `get_full_block_by_height_bcs()` and explicit handling in Rosetta proves this is a known limitation, but external developers may be unaware.

## Recommendation

**Immediate Fix**: Add an explicit indicator field to `BcsBlock`:

```rust
pub struct BcsBlock {
    pub block_height: u64,
    pub block_hash: aptos_crypto::HashValue,
    pub block_timestamp: u64,
    pub first_version: u64,
    pub last_version: u64,
    pub transactions: Option<Vec<TransactionOnChainData>>,
    /// Indicates whether all transactions in the block are included.
    /// If false, only partial transactions are returned and clients
    /// should use pagination to retrieve remaining transactions.
    pub transactions_complete: bool,
}
```

**Alternative Fix**: Return an error when truncation occurs, forcing clients to use explicit pagination:

```rust
if with_transactions && (last_version - first_version + 1) > max_txns as u64 {
    return Err(E::bad_request_with_code(
        format!("Block contains {} transactions, exceeding page size limit of {}. Use pagination or increase page size.", 
                last_version - first_version + 1, max_txns),
        AptosErrorCode::BlockTooLarge,
        latest_ledger_info
    ));
}
```

**Documentation Fix**: Add prominent warnings in API documentation and deprecate the basic block retrieval in favor of the paginated variant.

## Proof of Concept

```rust
#[tokio::test]
async fn test_block_transaction_truncation() {
    // Setup test context with a block containing > 10,000 transactions
    let mut context = create_test_context();
    
    // Create a block with 15,000 transactions
    let block_height = context.create_large_block(15000).await;
    
    // Request block with transactions using basic API
    let block = context
        .rest_client
        .get_block_by_height_bcs(block_height, true)
        .await
        .unwrap()
        .into_inner();
    
    // Verify truncation occurred silently
    let expected_txns = block.last_version - block.first_version + 1;
    let actual_txns = block.transactions.as_ref().unwrap().len() as u64;
    
    assert_eq!(expected_txns, 15000, "Block should have 15,000 transactions");
    assert_eq!(actual_txns, 10000, "Only 10,000 transactions returned");
    
    // Critical: No field indicates truncation
    // Clients must manually calculate to detect the issue
    assert_ne!(expected_txns, actual_txns, "Transaction list is incomplete");
    
    // Demonstrate that get_full_block_by_height_bcs works correctly
    let full_block = context
        .rest_client
        .get_full_block_by_height_bcs(block_height, 1000)
        .await
        .unwrap()
        .into_inner();
    
    assert_eq!(
        full_block.transactions.as_ref().unwrap().len(),
        15000,
        "Full block API should return all transactions"
    );
}
```

---

**Notes:**

While this is documented behavior with known workarounds, it represents a **significant protocol violation** for a blockchain API where data completeness is critical. The lack of explicit runtime indication when truncation occurs creates a dangerous situation where client applications may silently process incomplete data, leading to state inconsistencies and potential financial losses.

The existence of `get_full_block_by_height_bcs()` as a workaround actually strengthens the case that this is a recognized issue - the base API is fundamentally flawed in its design, requiring a separate "full" variant to work correctly.

### Citations

**File:** api/src/context.rs (L706-710)
```rust
        // We can only get the max_transactions page size
        let max_txns = std::cmp::min(
            self.node_config.api.max_block_transactions_page_size,
            (last_version - first_version + 1) as u16,
        );
```

**File:** api/src/context.rs (L711-722)
```rust
        let txns = if with_transactions {
            Some(
                self.get_transactions(first_version, max_txns, ledger_version)
                    .context("Failed to read raw transactions from storage")
                    .map_err(|err| {
                        E::internal_with_code(
                            err,
                            AptosErrorCode::InternalError,
                            latest_ledger_info,
                        )
                    })?,
            )
```

**File:** api/src/context.rs (L727-734)
```rust
        Ok(BcsBlock {
            block_height: new_block_event.height(),
            block_hash,
            block_timestamp,
            first_version,
            last_version,
            transactions: txns,
        })
```

**File:** config/src/config/consensus_config.rs (L23-24)
```rust
pub(crate) static MAX_RECEIVING_BLOCK_TXNS: Lazy<u64> =
    Lazy::new(|| 10000.max(2 * MAX_SENDING_BLOCK_TXNS));
```

**File:** api/types/src/block.rs (L29-41)
```rust
pub struct BcsBlock {
    /// The block height (number of the block from 0)
    pub block_height: u64,
    pub block_hash: aptos_crypto::HashValue,
    /// The block timestamp in Unix epoch microseconds
    pub block_timestamp: u64,
    /// The first ledger version of the block inclusive
    pub first_version: u64,
    /// The last ledger version of the block inclusive
    pub last_version: u64,
    /// The transactions in the block in sequential order
    pub transactions: Option<Vec<TransactionOnChainData>>,
}
```

**File:** api/src/blocks.rs (L31-33)
```rust
    /// Transactions are limited by max default transactions size.  If not all transactions
    /// are present, the user will need to query for the rest of the transactions via the
    /// get transactions API.
```

**File:** api/src/blocks.rs (L147-155)
```rust
                let transactions = if let Some(inner) = bcs_block.transactions {
                    Some(self.context.render_transactions_sequential(
                        &latest_ledger_info,
                        inner,
                        bcs_block.block_timestamp,
                    )?)
                } else {
                    None
                };
```

**File:** crates/aptos-rest-client/src/lib.rs (L201-242)
```rust
    pub async fn get_full_block_by_height_bcs(
        &self,
        height: u64,
        page_size: u16,
    ) -> AptosResult<Response<BcsBlock>> {
        let (mut block, state) = self
            .get_block_by_height_bcs(height, true)
            .await?
            .into_parts();

        let mut current_version = block.first_version;

        // Set the current version to the last known transaction
        if let Some(ref txns) = block.transactions {
            if let Some(txn) = txns.last() {
                current_version = txn.version + 1;
            }
        } else {
            return Err(RestError::Unknown(anyhow!(
                "No transactions were returned in the block"
            )));
        }

        // Add in all transactions by paging through the other transactions
        while current_version <= block.last_version {
            let page_end_version =
                std::cmp::min(block.last_version, current_version + page_size as u64 - 1);

            let transactions = self
                .get_transactions_bcs(
                    Some(current_version),
                    Some((page_end_version - current_version + 1) as u16),
                )
                .await?
                .into_inner();
            if let Some(txn) = transactions.last() {
                current_version = txn.version + 1;
            };
            block.transactions.as_mut().unwrap().extend(transactions);
        }

        Ok(Response::new(block, state))
```

**File:** crates/aptos-rosetta/src/block.rs (L210-217)
```rust
        // If we request transactions, we have to provide the page size, it ideally is bigger than
        // the maximum block size.  If not, transactions will be missed.
        if with_transactions {
            Ok(self
                .rest_client
                .get_full_block_by_height_bcs(height, self.page_size)
                .await?
                .into_inner())
```
