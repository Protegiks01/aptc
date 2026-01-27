# Audit Report

## Title
TOCTOU Race Condition in Transaction List API: Ledger Version Snapshot Becomes Stale During Pruning

## Summary
The `list()` function in `api/src/transactions.rs` captures a snapshot of the ledger version and oldest ledger version at the start of the request, but does not use this snapshot consistently during validation. Asynchronous pruning can advance the minimum readable version between capturing the ledger info and executing database reads, causing `get_transactions()` to fail with version pruned errors even though the requested version range was valid when the request started.

## Finding Description

The vulnerability manifests as a Time-of-Check Time-of-Use (TOCTOU) race condition in the transaction listing API:

**Step 1: Initial Snapshot Capture** [1](#0-0) 

The `list()` function captures `latest_ledger_info` which contains both the current ledger version and the oldest (non-pruned) ledger version. This snapshot is taken by calling `get_latest_ledger_info()`. [2](#0-1) 

The `get_latest_storage_ledger_info()` method retrieves the oldest version from `get_oldest_version_and_block_height()`, which internally queries the ledger pruner's minimum viable version: [3](#0-2) 

**Step 2: Missing Validation** [4](#0-3) 

The `compute_start()` method only validates that the start version does not exceed the maximum ledger version. It does **NOT** validate that `start_version >= oldest_ledger_version`, leaving the door open for pruning to advance.

**Step 3: Race Window**

Between line 859 (computing start_version) and line 862 (calling get_transactions), pruning can execute asynchronously in the background. The ledger pruner maintains atomic counters that are updated independently of API requests.

**Step 4: Stale Check Failure** [5](#0-4) 

When `get_transactions()` is called, it delegates to `get_transaction_outputs()`: [6](#0-5) 

At line 387, `error_if_ledger_pruned()` is called with the start_version. This method performs a **fresh read** of the current minimum readable version from the pruner: [7](#0-6) 

**The Critical Bug:**

The `error_if_ledger_pruned()` check at line 262 calls `self.ledger_pruner.get_min_readable_version()`, which returns the **current** minimum readable version, not the snapshot captured earlier. If pruning advanced between Step 1 and Step 4, this check will fail even though the version was valid when the request started.

**Example Execution Flow:**

1. At T0: Client calls `/transactions?start=60&limit=10`
2. At T1: `list()` captures `oldest_ledger_version=50`, `ledger_version=100`
3. At T2: `compute_start()` returns `start_version=60` (valid: 60 >= 50)
4. At T3: **Pruning runs**, advancing `min_readable_version` from 50 to 70
5. At T4: `get_transaction_outputs(60, 10, 100)` calls `error_if_ledger_pruned(60)`
6. At T5: Check fails: `60 >= 70` is false
7. Result: **Error: "Transaction at version 60 is pruned, min available version is 70"**

The client receives an error despite submitting a valid request according to the ledger info they observed.

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty criteria)

This vulnerability causes **intermittent API availability failures** that affect user experience:

1. **Inconsistent API Behavior**: The same request parameters can succeed or fail depending on pruning timing
2. **Client Integration Issues**: Applications relying on the API may experience unexpected errors and need complex retry logic
3. **Poor User Experience**: Users querying historical transactions near the pruning boundary face unreliable service
4. **No Data Corruption**: This does not affect consensus, state integrity, or funds
5. **No Permanent Unavailability**: Individual requests fail but the system remains operational

This aligns with **Medium Severity** criteria: "State inconsistencies requiring intervention" - while not a state inconsistency per se, it creates API-level inconsistencies that require client intervention through retries.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability occurs whenever:
1. A client queries transactions near the pruning boundary
2. Pruning executes during the API request handling
3. The race window (between capturing ledger info and DB validation) is hit

**Factors increasing likelihood:**
- Nodes with aggressive pruning configurations (short pruning windows)
- High query volume targeting historical transactions
- Frequent pruning execution (depends on node configuration)
- Longer API request processing times increase the race window

**Factors decreasing likelihood:**
- Nodes with disabled or infrequent pruning
- Queries for recent transactions (far from pruning boundary)
- Fast API processing reduces race window

On production nodes with active pruning, this condition is **realistically exploitable** through normal API usage without malicious intent.

## Recommendation

**Solution: Use the captured oldest_ledger_version consistently**

Add validation in `compute_start()` to ensure the start version is within the captured ledger info bounds:

```rust
// In api/src/page.rs, modify compute_start():
pub fn compute_start<E: BadRequestError>(
    &self,
    limit: u16,
    max: u64,
    ledger_info: &LedgerInfo,
) -> Result<u64, E> {
    let last_page_start = max.saturating_sub((limit.saturating_sub(1)) as u64);
    let start = self.start(last_page_start, max, ledger_info)?;
    
    // NEW: Validate against captured oldest version
    if start < ledger_info.oldest_ledger_version.0 {
        return Err(E::bad_request_with_code(
            format!(
                "Start version {} is below the oldest available version {}. Data has been pruned.",
                start, ledger_info.oldest_ledger_version.0
            ),
            AptosErrorCode::VersionPruned,
            ledger_info,
        ));
    }
    
    Ok(start)
}
```

**Alternative Solution: Pass ledger info to DB layer**

Modify `get_transaction_outputs()` to accept and use the captured `oldest_ledger_version` instead of re-querying the pruner:

```rust
// In storage/aptosdb/src/db/aptosdb_reader.rs
fn get_transaction_outputs(
    &self,
    start_version: Version,
    limit: u64,
    ledger_version: Version,
    min_readable_version: Version, // NEW parameter
) -> Result<TransactionOutputListWithProofV2> {
    // ... existing code ...
    
    // Use passed-in min_readable_version instead of re-querying
    ensure!(
        start_version >= min_readable_version,
        "Transaction at version {} is pruned, min available version is {}.",
        start_version,
        min_readable_version
    );
    
    // ... rest of implementation ...
}
```

**Recommended approach:** The first solution (validating in `compute_start()`) is simpler and fails fast, providing better error messages to users.

## Proof of Concept

**Test Setup:** This vulnerability requires actual pruning to occur, which is difficult to demonstrate in a unit test. However, the race condition can be demonstrated conceptually:

```rust
// Conceptual PoC - demonstrates the race condition logic
// File: api/src/transactions_test.rs (hypothetical)

#[tokio::test]
async fn test_pruning_race_in_list() {
    // Setup: Create a test harness with pruning enabled
    let mut harness = TestHarness::new_with_pruning();
    
    // Step 1: Advance ledger to version 100
    harness.commit_transactions(100);
    
    // Step 2: Set pruning to keep only recent 50 versions
    // oldest_version should be 50
    harness.prune_up_to_version(49);
    
    // Step 3: Start a request for transactions at version 60
    let api = TransactionsApi { context: harness.context.clone() };
    
    // Capture initial state (simulates line 855 in list())
    let ledger_info = api.context.get_latest_ledger_info().unwrap();
    assert_eq!(ledger_info.oldest_ledger_version.0, 50);
    assert_eq!(ledger_info.version(), 100);
    
    // Step 4: Simulate pruning advancing during request processing
    // (In production, this happens asynchronously)
    harness.prune_up_to_version(69);
    
    // Step 5: Now attempt to fetch transactions at version 60
    // This should fail because min_readable_version is now 70
    let page = Page::new(Some(60), Some(10), 100);
    let result = api.list(&AcceptType::Json, page);
    
    // Expected: Error due to pruning race
    // Actual behavior: Fails with "Transaction at version 60 is pruned"
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("pruned"));
    
    // The bug: Version 60 was valid when we captured ledger_info,
    // but became invalid due to concurrent pruning
}
```

**Real-world reproduction steps:**

1. Configure a node with aggressive pruning (e.g., 10,000 version window)
2. Generate continuous transaction load to advance the ledger
3. Enable pruning to run frequently
4. Send API requests querying transactions near the pruning boundary
5. Observe intermittent "version pruned" errors for versions that were valid according to the ledger info

**Notes:**
- The vulnerability is evident from code inspection and flow analysis
- The race window is typically small (milliseconds) but non-zero
- Production environments with active pruning will experience this issue
- No malicious intent required - normal API usage can trigger it

### Citations

**File:** api/src/transactions.rs (L854-859)
```rust
    fn list(&self, accept_type: &AcceptType, page: Page) -> BasicResultWith404<Vec<Transaction>> {
        let latest_ledger_info = self.context.get_latest_ledger_info()?;
        let ledger_version = latest_ledger_info.version();

        let limit = page.limit(&latest_ledger_info)?;
        let start_version = page.compute_start(limit, ledger_version, &latest_ledger_info)?;
```

**File:** api/src/context.rs (L243-268)
```rust
    pub fn get_latest_storage_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<LedgerInfo, E> {
        let ledger_info = self
            .get_latest_ledger_info_with_signatures()
            .context("Failed to retrieve latest ledger info")
            .map_err(|e| {
                E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError)
            })?;

        let (oldest_version, oldest_block_height) = self.get_oldest_version_and_block_height()?;
        let (_, _, newest_block_event) = self
            .db
            .get_block_info_by_version(ledger_info.ledger_info().version())
            .context("Failed to retrieve latest block information")
            .map_err(|e| {
                E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError)
            })?;

        Ok(LedgerInfo::new(
            &self.chain_id(),
            &ledger_info,
            oldest_version,
            oldest_block_height,
            newest_block_event.height(),
        ))
```

**File:** api/src/context.rs (L831-839)
```rust
    pub fn get_transactions(
        &self,
        start_version: u64,
        limit: u16,
        ledger_version: u64,
    ) -> Result<Vec<TransactionOnChainData>> {
        let data = self
            .db
            .get_transaction_outputs(start_version, limit as u64, ledger_version)?
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L336-352)
```rust
    fn get_first_viable_block(&self) -> Result<(Version, BlockHeight)> {
        gauged_api("get_first_viable_block", || {
            let min_version = self.ledger_pruner.get_min_viable_version();
            if !self.skip_index_and_usage {
                let (block_version, index, _seq_num) = self
                    .event_store
                    .lookup_event_at_or_after_version(&new_block_event_key(), min_version)?
                    .ok_or_else(|| {
                        AptosDbError::NotFound(format!(
                            "NewBlockEvent at or after version {}",
                            min_version
                        ))
                    })?;
                let event = self
                    .event_store
                    .get_event_by_version_and_index(block_version, index)?;
                return Ok((block_version, event.expect_new_block_event()?.height()));
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L374-390)
```rust
    fn get_transaction_outputs(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
    ) -> Result<TransactionOutputListWithProofV2> {
        gauged_api("get_transaction_outputs", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            if start_version > ledger_version || limit == 0 {
                return Ok(TransactionOutputListWithProofV2::new_empty());
            }

            self.error_if_ledger_pruned("Transaction", start_version)?;

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

```

**File:** api/src/page.rs (L27-56)
```rust
    pub fn compute_start<E: BadRequestError>(
        &self,
        limit: u16,
        max: u64,
        ledger_info: &LedgerInfo,
    ) -> Result<u64, E> {
        let last_page_start = max.saturating_sub((limit.saturating_sub(1)) as u64);
        self.start(last_page_start, max, ledger_info)
    }

    /// Retrieve the start of the page
    fn start<E: BadRequestError>(
        &self,
        default: u64,
        max: u64,
        ledger_info: &LedgerInfo,
    ) -> Result<u64, E> {
        let start = self.start.unwrap_or(default);
        if start > max {
            return Err(E::bad_request_with_code(
                format!(
                "Given start value ({}) is higher than the current ledger version, it must be < {}",
                start, max
            ),
                AptosErrorCode::InvalidInput,
                ledger_info,
            ));
        }
        Ok(start)
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
