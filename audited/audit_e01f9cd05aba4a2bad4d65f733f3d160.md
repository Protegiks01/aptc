# Audit Report

## Title
Panic on Empty User Transaction Blocks with Gas Limit Reached in Gas Estimation API

## Summary
The gas estimation endpoint `/estimate_gas_price` can panic and crash the API server when processing a block that contains zero user transactions but has `limit_reached()` flag set to true in its `BlockEndInfo`. This occurs due to an unchecked `.unwrap()` call on an empty iterator in the `block_min_inclusion_price` function. [1](#0-0) 

## Finding Description

The vulnerability exists in the gas price estimation logic that analyzes historical blocks to compute recommended gas prices. The `block_min_inclusion_price` function determines the minimum gas price needed for transaction inclusion by examining user transactions in each block.

The problematic code path is:
1. The function calls `get_gas_prices_and_used()` which only populates `prices_and_used` with `UserTransaction` types [2](#0-1) 

2. It checks if a block is "full" by examining `block_end_infos.first().unwrap().limit_reached()` [3](#0-2) 

3. The `limit_reached()` method returns true if either gas or output limits were reached [4](#0-3) 

4. When `is_full_block` is true but `prices_and_used` is empty, the code attempts to find the minimum price and calls `.unwrap()` on a `None` value, causing a panic [5](#0-4) 

**Scenario for exploitation:**
Aptos blocks always contain at least a `BlockMetadataTransaction`, but may contain zero user transactions during periods of low network activity or at bootstrap. [6](#0-5)  confirms empty blocks (with only metadata) are valid.

If such a block has its gas/output limit reached (due to metadata transaction overhead, misconfigured limits set to 0, or a bug in the block executor), then:
- `prices_and_used` will be empty (no user transactions)
- `is_full_block` will be true (`limit_reached()` returns true)
- `.min()` returns `None`
- `.unwrap()` panics with "called `Option::unwrap()` on a `None` value"

## Impact Explanation

**Severity: Medium-to-High**

This qualifies as **High Severity** under Aptos Bug Bounty criteria: "API crashes"

When triggered, the vulnerability causes:
- Immediate panic and crash of the API server thread handling the gas estimation request
- Denial of Service for clients using the `/estimate_gas_price` endpoint
- Potential cascading failures if the API server doesn't properly recover
- Disruption to wallets, dApps, and other services relying on gas price estimation

However, this does NOT affect:
- Consensus layer (validators continue operating normally)
- Blockchain state or transaction processing
- Fund security

## Likelihood Explanation

**Likelihood: Low**

While the bug is real, triggering it requires specific conditions:

1. **Empty blocks with limit reached**: A block must have 0 user transactions AND have `BlockEndInfo.limit_reached()` return true

2. **Why this is unlikely:**
   - Normal empty blocks have `limit_reached()` = false (as evidenced by passing test `test_gas_estimation_ten_empty_blocks`) [7](#0-6) 
   - Gas/output limits are set to reasonable non-zero values by default
   - Metadata transactions typically consume minimal gas

3. **Possible triggers:**
   - Configuration error setting gas/output limits to 0
   - Bug in `BlockGasLimitProcessor` incorrectly setting limit flags [8](#0-7) 
   - Unusual network conditions during bootstrap

4. **Not directly exploitable**: External attackers cannot force this condition as they cannot:
   - Control block production (validators only)
   - Set on-chain gas limits (governance only)
   - Inject malicious metadata transactions

## Recommendation

Add defensive checking before calling `.unwrap()`:

```rust
if is_full_block {
    if let Some(min_price) = prices_and_used
        .iter()
        .map(|(price, _)| *price)
        .min()
    {
        Some(self.next_bucket(min_price))
    } else {
        // Block marked as full but has no user transactions
        // Return minimum gas price as fallback
        Some(min_gas_unit_price)
    }
} else {
    None
}
```

Alternatively, log an error and return `None`:

```rust
if is_full_block {
    match prices_and_used.iter().map(|(price, _)| *price).min() {
        Some(min_price) => Some(self.next_bucket(min_price)),
        None => {
            error!(
                "Block marked as full but contains no user transactions. \
                first={}, last={}, limit_reached={:?}",
                first, last, block_end_infos.first().map(|b| b.limit_reached())
            );
            None
        }
    }
} else {
    None
}
```

## Proof of Concept

The existing test framework doesn't expose a way to create blocks with `limit_reached()` = true and 0 user transactions. A full PoC would require:

1. **Configuration-based reproduction:**
```rust
// In a test environment, set gas limit to 0
let mut node_config = NodeConfig::default();
node_config.execution.block_gas_limit_type = 
    BlockGasLimitType::ComplexLimitV1 {
        effective_block_gas_limit: 0,  // Force limit reached
        // ... other params
    };

// Create empty blocks
for _ in 0..15 {
    context.commit_block(&[]).await;
}

// This should trigger the panic
let resp = context.get("/estimate_gas_price").await;
```

2. **Direct unit test for the vulnerable function:**
```rust
#[test]
#[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
fn test_block_min_inclusion_price_panic() {
    // Mock scenario where:
    // - prices_and_used is empty (no user transactions)
    // - block_end_infos contains info with limit_reached() = true
    // This should panic on .min().unwrap()
}
```

**Note:** The actual exploitation in production would require either misconfiguration or a bug in the block executor, making it difficult to reliably reproduce outside of artificial test conditions.

---

**Notes:**

This vulnerability represents a defensive programming issue rather than a directly exploitable attack vector. While the panic is real and the code path exists, the conditions required to trigger it are edge cases that don't occur during normal operation, as confirmed by the passing `test_gas_estimation_ten_empty_blocks` test. The primary risk is operational (API server crashes) rather than security-critical (funds/consensus compromise).

### Citations

**File:** api/src/context.rs (L1190-1198)
```rust
            match txn.as_ref() {
                Ok(Transaction::UserTransaction(txn)) => {
                    if let Ok(info) = info.as_ref() {
                        gas_prices.push((txn.gas_unit_price(), info.gas_used()));
                        if count_majority_use_case {
                            let use_case_key = txn.parse_use_case();
                            *count_by_use_case.entry(use_case_key).or_insert(0) += 1;
                        }
                    }
```

**File:** api/src/context.rs (L1255-1257)
```rust
                    } else if !block_end_infos.is_empty() {
                        assert_eq!(1, block_end_infos.len());
                        block_end_infos.first().unwrap().limit_reached()
```

**File:** api/src/context.rs (L1267-1276)
```rust
                if is_full_block {
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

**File:** types/src/transaction/block_epilogue.rs (L86-94)
```rust
    pub fn limit_reached(&self) -> bool {
        match self {
            BlockEndInfo::V0 {
                block_gas_limit_reached,
                block_output_limit_reached,
                ..
            } => *block_gas_limit_reached || *block_output_limit_reached,
        }
    }
```

**File:** api/src/tests/transactions_test.rs (L2286-2312)
```rust
async fn test_gas_estimation_ten_empty_blocks(
    use_txn_payload_v2_format: bool,
    use_orderless_transactions: bool,
) {
    let mut node_config = NodeConfig::default();
    node_config.api.gas_estimation.enabled = true;
    let mut context = new_test_context_with_config(
        current_function_name!(),
        node_config,
        use_txn_payload_v2_format,
        use_orderless_transactions,
    );

    let ctx = &mut context;
    // First block is ignored in gas estimate, so make 11
    for _i in 0..11 {
        ctx.commit_block(&[]).await;
    }

    let resp = context.get("/estimate_gas_price").await;
    // multiple times, to exercise cache
    for _i in 0..2 {
        let cached = context.get("/estimate_gas_price").await;
        assert_eq!(resp, cached);
    }
    context.check_golden_output(resp);
}
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L271-292)
```rust
    pub(crate) fn get_block_end_info(&self) -> TBlockEndInfoExt<T::Key> {
        let inner = BlockEndInfo::V0 {
            block_gas_limit_reached: self
                .block_gas_limit()
                .map(|per_block_gas_limit| {
                    self.get_effective_accumulated_block_gas() >= per_block_gas_limit
                })
                .unwrap_or(false),
            block_output_limit_reached: self
                .block_gas_limit_type
                .block_output_limit()
                .map(|per_block_output_limit| {
                    self.get_accumulated_approx_output_size() >= per_block_output_limit
                })
                .unwrap_or(false),
            block_effective_block_gas_units: self.get_effective_accumulated_block_gas(),
            block_approx_output_size: self.get_accumulated_approx_output_size(),
        };

        let to_make_hot = self.get_keys_to_make_hot();
        TBlockEndInfoExt::new(inner, to_make_hot)
    }
```
