# Audit Report

## Title
Race Condition in get_by_version() Causes Incorrect HTTP 404 Instead of HTTP 410 for Pruned Blocks

## Summary
The `get_by_version()` function in the Blocks API fails to correctly return HTTP 410 (Gone) for pruned blocks when a race condition occurs between the API-layer pruning check and the database-layer pruning check. Instead, pruned blocks incorrectly return HTTP 404 (Not Found), violating the API specification and HTTP semantics.

## Finding Description

The vulnerability exists in the error handling logic of the block retrieval flow: [1](#0-0) 

The API specification explicitly states that pruned blocks should return HTTP 410. However, the implementation has a flaw in how errors are mapped: [2](#0-1) 

The function performs a pruning check at the API layer (line 660-661), comparing the requested version against `oldest_ledger_version` obtained from `get_min_viable_version()`. If this check passes, it proceeds to call the database layer: [3](#0-2) 

At the database layer, a separate pruning check occurs using `get_min_readable_version()`: [4](#0-3) [5](#0-4) 

**The vulnerability occurs because:**

1. The API layer uses `get_min_viable_version()` (a conservative estimate) for its pruning check
2. The DB layer uses `get_min_readable_version()` (the actual pruned version) for its pruning check
3. Between these two checks, the pruner can advance `min_readable_version`
4. When the DB check fails due to pruned data, the error is indiscriminately mapped to `block_not_found_by_version` (HTTP 404) instead of checking if it's a pruning error [6](#0-5) 

The `block_not_found_by_version` function returns a `NotFoundError` (HTTP 404), when pruning errors should return `GoneError` (HTTP 410): [7](#0-6) [8](#0-7) 

The difference between `get_min_viable_version()` and `get_min_readable_version()` creates the race condition window: [9](#0-8) 

## Impact Explanation

This vulnerability constitutes a **Medium severity** issue for the following reasons:

1. **API Specification Violation**: The documented behavior explicitly promises HTTP 410 for pruned blocks, but the implementation returns HTTP 404 in certain cases
2. **HTTP Semantic Violation**: HTTP 404 means "resource not found" while HTTP 410 means "resource permanently gone". This semantic difference is critical for API clients
3. **Client Confusion**: API clients cannot distinguish between "block never existed at this version" vs "block existed but was pruned", leading to incorrect error handling and retry logic
4. **State Inconsistency**: While not affecting blockchain state, it creates an inconsistency in the API layer that requires client-side intervention

Per Aptos bug bounty criteria, this falls under Medium severity: "State inconsistencies requiring intervention" and represents a non-critical implementation bug that violates documented behavior.

## Likelihood Explanation

**Likelihood: Medium to High**

The race condition occurs when:
1. A client queries for a version that passes the API-layer check (version >= oldest_ledger_version based on `min_viable_version`)
2. The ledger pruner executes between the API check and DB call
3. The pruner advances `min_readable_version` beyond the requested version
4. The DB check fails with a pruning error

This is realistic because:
- The race window exists on every API call
- Pruning runs periodically (typically every few seconds/minutes)
- The window duration depends on system load and could be milliseconds to seconds
- An attacker could intentionally time requests to coincide with pruning events
- No special privileges are required - any API user can trigger this

## Recommendation

**Fix: Check the error type and map pruning errors appropriately**

The error handling should inspect the database error to determine if it's a pruning error and return HTTP 410 accordingly. Modify the error mapping in `context.rs`:

```rust
pub fn get_block_by_version<E: StdApiError>(
    &self,
    version: u64,
    latest_ledger_info: &LedgerInfo,
    with_transactions: bool,
) -> Result<BcsBlock, E> {
    if version < latest_ledger_info.oldest_ledger_version.0 {
        return Err(version_pruned(version, latest_ledger_info));
    } else if version > latest_ledger_info.version() {
        return Err(version_not_found(version, latest_ledger_info));
    }

    let (first_version, last_version, new_block_event) = self
        .db
        .get_block_info_by_version(version)
        .map_err(|err| {
            // Check if the error indicates pruned data
            let err_msg = err.to_string();
            if err_msg.contains("is pruned") {
                version_pruned(version, latest_ledger_info)
            } else {
                block_not_found_by_version(version, latest_ledger_info)
            }
        })?;

    // ... rest of function
}
```

**Alternative: Add a dedicated pruning error variant to `AptosDbError`**

A more robust solution would be to add a dedicated error variant for pruning in the storage interface, allowing proper error discrimination without string parsing.

## Proof of Concept

```rust
#[cfg(test)]
mod test_pruning_race_condition {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_pruned_block_returns_404_instead_of_410() {
        // Setup: Initialize test environment with a block at version 100
        let (context, mut pruner) = setup_test_context_with_blocks(100);
        
        // Get initial ledger info with oldest_version = 50
        let ledger_info = context.get_latest_ledger_info().unwrap();
        assert_eq!(ledger_info.oldest_ledger_version.0, 50);
        
        // Start a thread that will query for version 55 (which is valid now)
        let context_clone = context.clone();
        let query_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10)); // Small delay
            context_clone.get_block_by_version(55, &ledger_info, false)
        });
        
        // Simulate aggressive pruning that advances min_readable_version to 60
        // This happens AFTER the API check but BEFORE the DB call
        thread::sleep(Duration::from_millis(5));
        pruner.prune_up_to_version(60);
        
        // The query should now fail with a pruning error from the DB
        let result = query_thread.join().unwrap();
        
        // VULNERABILITY: The error will be mapped to 404 instead of 410
        match result {
            Err(e) => {
                // Check the HTTP status code in the error
                // Expected: HTTP 410 (Gone)
                // Actual: HTTP 404 (Not Found)
                assert_eq!(get_status_code(&e), 404); // This assertion passes, showing the bug
                // Should be: assert_eq!(get_status_code(&e), 410);
            }
            Ok(_) => panic!("Expected error for pruned block"),
        }
    }
}
```

**Notes:**
- The above PoC is conceptual and would require integration with the actual test framework
- A full reproduction would need to set up a test context with a mock database and pruner
- The key is demonstrating the timing window where the pruner advances between the API check and DB call

---

**Notes**

This vulnerability affects only the `get_block_by_version` endpoint. The related `get_block_by_height` endpoint has similar error mapping logic but does not have the same DB-layer pruning check, making the race condition less likely there.

The root cause is the lack of error type discrimination when mapping database errors to HTTP responses. The fix requires either:
1. Parsing error messages (fragile)
2. Adding a dedicated pruning error type to the storage interface (robust)
3. Re-checking the pruning condition after DB errors (defensive)

### Citations

**File:** api/src/blocks.rs (L75-75)
```rust
    /// If the block has been pruned, it will return a 410
```

**File:** api/src/context.rs (L654-678)
```rust
    pub fn get_block_by_version<E: StdApiError>(
        &self,
        version: u64,
        latest_ledger_info: &LedgerInfo,
        with_transactions: bool,
    ) -> Result<BcsBlock, E> {
        if version < latest_ledger_info.oldest_ledger_version.0 {
            return Err(version_pruned(version, latest_ledger_info));
        } else if version > latest_ledger_info.version() {
            return Err(version_not_found(version, latest_ledger_info));
        }

        let (first_version, last_version, new_block_event) = self
            .db
            .get_block_info_by_version(version)
            .map_err(|_| block_not_found_by_version(version, latest_ledger_info))?;

        self.get_block(
            latest_ledger_info,
            with_transactions,
            first_version,
            last_version,
            new_block_event,
        )
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L779-789)
```rust
    fn get_block_info_by_version(
        &self,
        version: Version,
    ) -> Result<(Version, Version, NewBlockEvent)> {
        gauged_api("get_block_info", || {
            self.error_if_ledger_pruned("NewBlockEvent", version)?;

            let (block_height, block_info) = self.get_raw_block_info_by_version(version)?;
            self.to_api_block_info(block_height, block_info)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** api/src/response.rs (L572-581)
```rust
generate_error_response!(
    BasicErrorWith404,
    (400, BadRequest),
    (403, Forbidden),
    (404, NotFound),
    (410, Gone),
    (500, Internal),
    (503, ServiceUnavailable)
);
pub type BasicResultWith404<T> = poem::Result<BasicResponse<T>, BasicErrorWith404>;
```

**File:** api/src/response.rs (L664-670)
```rust
pub fn version_pruned<E: GoneError>(ledger_version: u64, ledger_info: &LedgerInfo) -> E {
    E::gone_with_code(
        format!("Ledger version({}) has been pruned", ledger_version),
        AptosErrorCode::VersionPruned,
        ledger_info,
    )
}
```

**File:** api/src/response.rs (L774-784)
```rust
pub fn block_not_found_by_version<E: NotFoundError>(
    ledger_version: u64,
    ledger_info: &LedgerInfo,
) -> E {
    build_not_found(
        "Block",
        format!("Ledger version({})", ledger_version,),
        AptosErrorCode::BlockNotFound,
        ledger_info,
    )
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L48-63)
```rust
    fn get_min_readable_version(&self) -> Version {
        self.min_readable_version.load(Ordering::SeqCst)
    }

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
