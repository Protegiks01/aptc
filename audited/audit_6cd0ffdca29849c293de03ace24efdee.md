# Audit Report

## Title
Inconsistent Error Handling in Rosetta Historical Balance Lookup for Pruned Data

## Summary
The Rosetta API advertises support for historical balance lookups via `historical_balance_lookup: true`, but the `get_sequence_number()` function incorrectly handles pruned version errors, converting them to misleading `InternalError` responses instead of proper `VersionPruned` errors. This violates API consistency expectations when querying near the pruning boundary.

## Finding Description

The `network_options()` function advertises that historical balance lookups are supported: [1](#0-0) 

However, when a client requests historical account balances for blocks near the pruning boundary, the error handling is inconsistent. The account balance flow is:

1. Client calls `/account/balance` with a historical block identifier
2. The block info is successfully retrieved if the block height ≥ `oldest_block_height`
3. The system then queries account resources at the block's `last_version`
4. If that version has been pruned (version < `oldest_ledger_version`), the REST API returns `AptosErrorCode::VersionPruned` [2](#0-1) 

The REST API properly converts this to a 410 Gone response: [3](#0-2) 

The Rosetta error conversion correctly maps these codes: [4](#0-3) 

**However**, the `get_sequence_number()` function in the balance lookup path has flawed error handling: [5](#0-4) 

The function only explicitly handles `AccountNotFound` and `ResourceNotFound` errors (lines 176-193). The catch-all pattern on line 195 converts **all other errors**, including `VersionPruned`, into a generic `InternalError` with the message "Failed to retrieve account sequence number".

This breaks the API contract where the comment explicitly states "pruning is handled on the API": [6](#0-5) 

## Impact Explanation

This is a **Low Severity** issue (non-critical implementation bug) that causes misleading error responses but does not result in:
- Crashes or panics
- Funds loss or manipulation  
- Consensus violations
- State inconsistencies
- API unavailability

The impact is limited to user experience degradation where clients receive confusing error messages when querying pruned historical data. While this violates API consistency expectations, it does not meet the Medium+ severity threshold as it causes no direct security harm to the blockchain or its users.

## Likelihood Explanation

This occurs whenever:
1. A Rosetta client queries historical balances near the pruning boundary
2. The block info is still available (`block_height ≥ oldest_block_height`)
3. But the account state at that version is pruned (`version < oldest_ledger_version`)

This can happen due to the relationship between `oldest_block_height` (derived from `min_viable_version`) and `oldest_ledger_version` (equal to `min_readable_version`): [7](#0-6) 

The likelihood is **moderate** as it naturally occurs at the pruning boundary during normal node operation.

## Recommendation

Explicitly handle `VersionPruned` errors in the `get_sequence_number()` function:

```rust
async fn get_sequence_number(
    rest_client: &Client,
    owner_address: AccountAddress,
    version: u64,
) -> ApiResult<u64> {
    let sequence_number = match rest_client
        .get_account_resource_at_version_bcs(owner_address, "0x1::account::Account", version)
        .await
    {
        Ok(response) => {
            let account: AccountResource = response.into_inner();
            account.sequence_number()
        },
        Err(RestError::Api(AptosErrorResponse {
            error:
                AptosError {
                    error_code: AptosErrorCode::AccountNotFound,
                    ..
                },
            ..
        }))
        | Err(RestError::Api(AptosErrorResponse {
            error:
                AptosError {
                    error_code: AptosErrorCode::ResourceNotFound,
                    ..
                },
            ..
        })) => 0,
        // Properly propagate VersionPruned errors
        Err(e) => return Err(e.into()),
    };

    Ok(sequence_number)
}
```

This change ensures that `VersionPruned` errors are properly propagated as `ApiError::VersionPruned` instead of being converted to `InternalError`.

## Proof of Concept

```rust
#[tokio::test]
async fn test_pruned_version_error_handling() {
    // Setup: Start a node with pruning enabled
    let mut node = setup_test_node_with_pruning().await;
    
    // Step 1: Generate enough transactions to trigger pruning
    for _ in 0..200000 {
        node.execute_transaction(create_test_transaction()).await;
    }
    
    // Step 2: Wait for pruning to occur
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Step 3: Get the current oldest_block_height
    let status = node.rosetta_client.network_status().await.unwrap();
    let oldest_height = status.oldest_block_identifier.index;
    
    // Step 4: Query account balance at the oldest block
    // This should return VersionPruned error but currently returns InternalError
    let result = node.rosetta_client
        .account_balance(
            test_account_address(),
            Some(BlockIdentifier {
                index: oldest_height,
                hash: status.oldest_block_identifier.hash,
            })
        )
        .await;
    
    // Expected: ApiError::VersionPruned or ApiError::BlockPruned
    // Actual: ApiError::InternalError("Failed to retrieve account sequence number")
    match result {
        Err(e) => {
            assert!(
                matches!(e, ApiError::VersionPruned(_) | ApiError::BlockPruned(_)),
                "Expected VersionPruned or BlockPruned, got: {:?}", e
            );
        }
        Ok(_) => panic!("Expected error for pruned data"),
    }
}
```

## Notes

While this is a valid implementation bug that causes inconsistent API behavior, it does **not** meet the Medium severity threshold as defined by the Aptos Bug Bounty program. It does not cause crashes, funds loss, consensus issues, or state inconsistencies. The impact is limited to misleading error messages for historical queries at the pruning boundary. This would be classified as **Low Severity** (up to $1,000) in the bounty program as a "non-critical implementation bug."

### Citations

**File:** crates/aptos-rosetta/src/network.rs (L113-114)
```rust
        // Historical balances are allowed to be looked up (pruning is handled on the API)
        historical_balance_lookup: true,
```

**File:** api/src/context.rs (L309-313)
```rust
        } else if requested_ledger_version < latest_ledger_info.oldest_ledger_version.0 {
            return Err(version_pruned(
                requested_ledger_version,
                &latest_ledger_info,
            ));
```

**File:** api/src/response.rs (L664-669)
```rust
pub fn version_pruned<E: GoneError>(ledger_version: u64, ledger_info: &LedgerInfo) -> E {
    E::gone_with_code(
        format!("Ledger version({}) has been pruned", ledger_version),
        AptosErrorCode::VersionPruned,
        ledger_info,
    )
```

**File:** crates/aptos-rosetta/src/error.rs (L296-297)
```rust
                AptosErrorCode::VersionPruned => ApiError::VersionPruned(Some(err.error.message)),
                AptosErrorCode::BlockPruned => ApiError::BlockPruned(Some(err.error.message)),
```

**File:** crates/aptos-rosetta/src/account.rs (L168-200)
```rust
    let sequence_number = match rest_client
        .get_account_resource_at_version_bcs(owner_address, "0x1::account::Account", version)
        .await
    {
        Ok(response) => {
            let account: AccountResource = response.into_inner();
            account.sequence_number()
        },
        Err(RestError::Api(AptosErrorResponse {
            error:
                AptosError {
                    error_code: AptosErrorCode::AccountNotFound,
                    ..
                },
            ..
        }))
        | Err(RestError::Api(AptosErrorResponse {
            error:
                AptosError {
                    error_code: AptosErrorCode::ResourceNotFound,
                    ..
                },
            ..
        })) => {
            // If the account or resource doesn't exist, set the sequence number to 0
            0
        },
        _ => {
            // Any other error we can't retrieve the sequence number
            return Err(ApiError::InternalError(Some(
                "Failed to retrieve account sequence number".to_string(),
            )));
        },
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L52-63)
```rust
    fn get_min_viable_version(&self) -> Version {
        let min_version = self.get_min_readable_version();
        if self.is_pruner_enabled() {
            let adjusted_window = self
                .prune_window
                .saturating_sub(self.user_pruning_window_offset);
            let adjusted_cutoff = self.latest_version.lock().saturating_sub(adjusted_window);
            std::cmp::max(min_version, adjusted_cutoff)
        } else {
            min_version
        }
    }
```
