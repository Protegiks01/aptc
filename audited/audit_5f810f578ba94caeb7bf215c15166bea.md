# Audit Report

## Title
RwLock Poisoning in Gas Estimation API Causes Permanent Service Denial

## Summary
The gas estimation API (`/estimate_gas_price`) uses `.unwrap()` when acquiring RwLock guards, making it vulnerable to permanent lock poisoning if a panic occurs during gas estimation computation. Two panic points exist within the critical section: an assertion that assumes exactly one BlockEpilogue per block, and an `.unwrap()` on an iterator minimum that assumes non-empty transaction data.

## Finding Description
The vulnerability exists in the gas estimation logic that serves the public `/estimate_gas_price` API endpoint [1](#0-0) . The core issue is improper panic handling in concurrent code.

The `estimate_gas_price` function acquires an RwLock write guard using `.unwrap()` [2](#0-1) , and all read operations also use `.unwrap()` [3](#0-2) . If any panic occurs while holding this lock, Rust's RwLock will become poisoned, causing all future lock acquisitions to fail.

Two critical panic points exist within the locked section:

**Panic Point 1**: An assertion assumes exactly one BlockEpilogue transaction exists when `block_end_infos` is non-empty [4](#0-3) . This assertion would fail if database corruption or a block production bug causes multiple BlockEpilogues in a single block range.

**Panic Point 2**: An `.unwrap()` call on `.min()` assumes the prices vector is non-empty [5](#0-4) . This can panic if a block is marked as "full" (via limit_reached flag) but contains no user transactions, resulting in an empty `prices_and_used` vector.

Additionally, there is an off-by-one error in the range calculation where `last - first` is used as the limit [6](#0-5) , which should be `last - first + 1` to include all transactions in the inclusive range [first, last]. This may cause the last transaction in each block to be excluded from gas price analysis.

Once the RwLock is poisoned, all subsequent API calls will panic immediately when attempting to acquire the lock, as seen in multiple locations [7](#0-6) [8](#0-7) [9](#0-8) .

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category. Once triggered, the gas estimation endpoint becomes permanently unavailable until node restart, affecting all clients that depend on gas price discovery. While the node continues processing transactions and participating in consensus, the API service degradation impacts user experience and transaction submission efficiency.

The impact is limited to API availability rather than consensus or funds because:
- No blockchain state is corrupted
- Consensus operations are unaffected
- Transaction processing continues normally
- Only the gas estimation API endpoint fails

## Likelihood Explanation
The likelihood is **Low to Medium** because triggering requires specific blockchain state conditions:

1. For the assertion panic: Multiple BlockEpilogues in a single block, which would require either database corruption or a separate bug in block production
2. For the `.min()` panic: A block marked with limits reached but containing no user transactions, which appears contradictory under normal operation

However, the conditions are not entirely impossible:
- Database corruption from hardware failures or software bugs could create malformed block data
- Race conditions or bugs in block execution could produce unexpected BlockEndInfo states
- The off-by-one error may create edge cases during block boundary scanning

The vulnerability is **not directly exploitable** by external attackers, as it requires specific blockchain state rather than malicious input. It represents a reliability and robustness issue rather than a deliberate attack vector.

## Recommendation
Replace all `.unwrap()` calls on RwLock operations with proper error handling:

```rust
// Instead of:
let cache = self.gas_estimation_cache.read().unwrap();

// Use:
let cache = self.gas_estimation_cache.read()
    .map_err(|e| E::internal_with_code(
        format!("Gas estimation cache lock poisoned: {}", e),
        AptosErrorCode::InternalError,
        ledger_info
    ))?;
```

Replace the assertion with proper error handling:

```rust
// Instead of:
assert_eq!(1, block_end_infos.len());

// Use:
if block_end_infos.len() != 1 {
    error!("Unexpected block_end_infos count: {}", block_end_infos.len());
    return None; // Fall back to default estimation
}
```

Handle the empty vector case:

```rust
// Instead of:
prices_and_used.iter().map(|(price, _)| *price).min().unwrap()

// Use:
prices_and_used.iter().map(|(price, _)| *price).min()
    .unwrap_or(min_gas_unit_price)
```

Fix the off-by-one error:

```rust
// Change from:
self.get_gas_prices_and_used(first, last - first, ...)

// To:
self.get_gas_prices_and_used(first, last - first + 1, ...)
```

## Proof of Concept
Due to the nature of this vulnerability requiring specific blockchain state (corrupted blocks or edge cases in block production), a realistic PoC cannot be constructed without either:
1. Deliberately corrupting the AptosDB database
2. Mocking the database layer to return malformed block data
3. Exploiting a separate bug in block production

A minimal reproduction would require:
```rust
// This would require database mocking to inject malformed blocks
#[test]
fn test_rwlock_poisoning_from_multiple_block_epilogues() {
    // Setup: Create a mock database that returns a block with 2 BlockEpilogues
    // Expected: Gas estimation should handle gracefully, not panic
    // Actual: Assertion fails, RwLock is poisoned
}
```

**Note**: While the architectural flaw is clear (improper panic handling in locked sections), the practical exploitability is limited by the need for blockchain state anomalies that are outside normal attacker control.

### Citations

**File:** api/src/transactions.rs (L812-826)
```rust
        path = "/estimate_gas_price",
        method = "get",
        operation_id = "estimate_gas_price",
        tag = "ApiTags::Transactions"
    )]
    async fn estimate_gas_price(&self, accept_type: AcceptType) -> BasicResult<GasEstimation> {
        fail_point_poem("endpoint_encode_submission")?;
        self.context
            .check_api_output_enabled("Estimate gas price", &accept_type)?;

        let context = self.context.clone();
        api_spawn_blocking(move || {
            let latest_ledger_info = context.get_latest_ledger_info()?;
            let gas_estimation = context.estimate_gas_price(&latest_ledger_info)?;
            Self::log_gas_estimation(&gas_estimation);
```

**File:** api/src/context.rs (L1241-1245)
```rust
        match self.get_gas_prices_and_used(
            first,
            last - first,
            ledger_info.ledger_version.0,
            user_use_case_spread_factor.is_some(),
```

**File:** api/src/context.rs (L1255-1257)
```rust
                    } else if !block_end_infos.is_empty() {
                        assert_eq!(1, block_end_infos.len());
                        block_end_infos.first().unwrap().limit_reached()
```

**File:** api/src/context.rs (L1268-1276)
```rust
                    Some(
                        self.next_bucket(
                            prices_and_used
                                .iter()
                                .map(|(price, _)| *price)
                                .min()
                                .unwrap(),
                        ),
                    )
```

**File:** api/src/context.rs (L1306-1306)
```rust
        let cache = self.gas_estimation_cache.read().unwrap();
```

**File:** api/src/context.rs (L1313-1313)
```rust
        let mut cache = self.gas_estimation_cache.write().unwrap();
```

**File:** api/src/context.rs (L1468-1468)
```rust
            let cache = self.gas_schedule_cache.read().unwrap();
```

**File:** api/src/context.rs (L1548-1548)
```rust
            let cache = self.gas_limit_cache.read().unwrap();
```

**File:** api/src/context.rs (L1605-1612)
```rust
        self.gas_schedule_cache.read().unwrap().last_updated_epoch
    }

    pub fn last_updated_gas_estimation_cache_size(&self) -> usize {
        self.gas_estimation_cache
            .read()
            .unwrap()
            .min_inclusion_prices
```
