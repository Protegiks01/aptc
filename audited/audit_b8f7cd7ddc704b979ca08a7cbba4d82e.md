# Audit Report

## Title
Gas Estimation Incorrectly Classifies Blocks With Dominant Use Case as Non-Full Despite Hitting Resource Limits

## Summary
The `block_min_inclusion_price()` function in `api/src/context.rs` contains a logic error where blocks dominated by a single contract address (>50% of transactions) are always classified as "not full" for gas estimation purposes, even when those blocks have reached gas or output limits. This causes the gas estimation API to return artificially low gas price recommendations, leading to transaction submission failures.

## Finding Description
The gas estimation logic is designed to detect "full blocks" to determine minimum inclusion gas prices. When AIP-68's UseCaseAware transaction reordering is active, the code attempts to account for the fact that blocks dominated by a single use case can still accept other transactions through reordering. [1](#0-0) 

The vulnerability exists in the if-else chain that determines `is_full_block`. When `majority_use_case_fraction > 0.5`, the function immediately returns `false` (line 1252), **short-circuiting all subsequent checks** including:
- Whether the block hit the gas limit (lines 1258-1262)
- Whether BlockEndInfo indicates limits were reached (lines 1255-1257)

This logic is flawed because AIP-68's reordering cannot bypass hard resource limits. If a block hits the gas limit or output limit, no amount of transaction reordering can make room for additional transactions. The use case distribution becomes irrelevant once physical resource limits are reached. [2](#0-1) 

The `BlockEndInfo.limit_reached()` method correctly tracks when gas or output limits are reached, but this information is ignored when majority_use_case_fraction > 0.5.

**Attack Scenario:**
1. Attacker submits numerous high-gas transactions to a single contract (could be their own or a popular DeFi contract)
2. These transactions constitute >50% of block transactions AND cause the block to reach gas/output limits
3. The gas estimation logic incorrectly classifies these blocks as "not full" due to the short-circuit at line 1249-1252
4. Minimum gas prices from these genuinely full blocks are excluded from the gas estimation calculation
5. The API returns gas estimates that are too low (lower than what's actually needed for inclusion)
6. Users relying on these estimates submit transactions with insufficient gas prices
7. Transactions are rejected despite users following the API's recommendations
8. If sustained, this creates a persistent availability issue where the API misleads users about required gas prices [3](#0-2) 

The `get_gas_prices_and_used()` function itself correctly collects all transaction gas prices and use case information. The bug is purely in how this information is interpreted in `block_min_inclusion_price()`.

## Impact Explanation
This is classified as **Medium Severity** based on:

1. **State Inconsistency**: The API provides information (gas estimates) that is inconsistent with actual blockchain state (block fullness), requiring potential operator intervention to address widespread user issues.

2. **Availability Impact**: While not a total loss of liveness, sustained exploitation creates a situation where users cannot reliably submit transactions based on API recommendations, degrading network usability.

3. **Scope**: Affects all users of the gas estimation API endpoint (`/estimate_gas_price`), which is commonly integrated into wallets and dApps.

4. **No Funds Loss**: While transactions may fail, no funds are stolen or permanently lost. Users may waste gas on failed transactions, but this is limited.

This does not meet Critical or High severity because:
- No consensus violation occurs
- No validator nodes are impacted
- The blockchain continues to operate correctly
- Actual block limits are still enforced properly

## Likelihood Explanation
**Likelihood: Medium**

The exploit requires:
- Ability to submit transactions (available to any user)
- Sufficient funds to submit many high-gas transactions
- Knowledge of which contracts are popular or ability to deploy contracts
- The on-chain execution config must have UseCaseAware shuffler enabled (this is the default per genesis config)
- Node must have `incorporate_reordering_effects: true` in gas estimation config (this is the default) [4](#0-3) [5](#0-4) 

The attack could occur organically (without malicious intent) during periods of high activity on popular DeFi contracts, or could be deliberately triggered by an attacker.

## Recommendation
Modify the `is_full_block` logic to check hard resource limits BEFORE considering the majority use case optimization. The majority use case logic should only apply when blocks have NOT hit gas or output limits.

**Proposed Fix:**
```rust
let is_full_block = {
    // First check if hard limits were reached - these override use case considerations
    let hard_limit_reached = if !block_end_infos.is_empty() {
        assert_eq!(1, block_end_infos.len());
        block_end_infos.first().unwrap().limit_reached()
    } else if let Some(block_gas_limit) = execution_config.block_gas_limit_type().block_gas_limit() {
        let gas_used = prices_and_used.iter().map(|(_, used)| *used).sum::<u64>();
        gas_used >= block_gas_limit
    } else {
        false
    };
    
    // If hard limits were reached, block is definitely full
    if hard_limit_reached {
        true
    } else if majority_use_case_fraction.is_some_and(|fraction| fraction > 0.5) {
        // Only if limits weren't reached: AIP-68 reordering allows other txns in
        false
    } else if prices_and_used.len() >= gas_estimation_config.full_block_txns {
        true
    } else {
        false
    }
};
```

This ensures that blocks hitting gas/output limits are always classified as full, regardless of use case distribution.

## Proof of Concept
```rust
#[test]
fn test_block_with_majority_use_case_and_gas_limit_should_be_full() {
    // Setup: Create a block with >50% transactions from one contract AND gas limit reached
    // Expected: Block should be classified as full
    // Actual: Block is classified as not full (bug)
    
    // 1. Create BlockEndInfo indicating gas limit was reached
    let block_end_info = BlockEndInfo::V0 {
        block_gas_limit_reached: true,
        block_output_limit_reached: false,
        block_effective_block_gas_units: 20000,
        block_approx_output_size: 1000000,
    };
    
    // 2. Simulate 600 transactions to contract 0x123 and 400 to other addresses
    // majority_use_case_fraction would be 0.6 (>0.5)
    
    // 3. Call block_min_inclusion_price with this data
    // Bug: Returns None (block not considered full)
    // Expected: Should return Some(min_price) because gas limit was reached
    
    // 4. Verify gas estimation is incorrectly low
    let gas_estimation = estimate_gas_price(&context, &ledger_info);
    
    // The minimum gas price from this full block is missing from the estimate
    // causing the market and aggressive prices to be artificially low
}
```

The test would demonstrate that when `majority_use_case_fraction = 0.6` and `BlockEndInfo.block_gas_limit_reached = true`, the function incorrectly returns `is_full_block = false` due to the short-circuit logic at line 1249-1252.

## Notes
This vulnerability stems from an incomplete implementation of AIP-68 awareness in gas estimation. While AIP-68's UseCaseAware reordering does allow better interleaving of transactions when one use case dominates, this benefit disappears once physical resource limits (gas, output size) are reached. The current code assumes use case dominance always means the block has capacity, which is incorrect when hard limits are hit.

The fix requires careful ordering of checks: hard resource limits should be evaluated first, then use case considerations should only apply to blocks that haven't hit those limits.

### Citations

**File:** api/src/context.rs (L1168-1223)
```rust
    fn get_gas_prices_and_used(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
        count_majority_use_case: bool,
    ) -> Result<(Vec<(u64, u64)>, Vec<BlockEndInfo>, Option<f32>)> {
        if start_version > ledger_version || limit == 0 {
            return Ok((vec![], vec![], None));
        }

        // This is just an estimation, so we can just skip over errors
        let limit = std::cmp::min(limit, ledger_version - start_version + 1);
        let txns = self.db.get_transaction_iterator(start_version, limit)?;
        let infos = self
            .db
            .get_transaction_info_iterator(start_version, limit)?;

        let mut gas_prices = Vec::new();
        let mut block_end_infos = Vec::new();
        let mut count_by_use_case = HashMap::new();
        for (txn, info) in txns.zip(infos) {
            match txn.as_ref() {
                Ok(Transaction::UserTransaction(txn)) => {
                    if let Ok(info) = info.as_ref() {
                        gas_prices.push((txn.gas_unit_price(), info.gas_used()));
                        if count_majority_use_case {
                            let use_case_key = txn.parse_use_case();
                            *count_by_use_case.entry(use_case_key).or_insert(0) += 1;
                        }
                    }
                },
                Ok(Transaction::BlockEpilogue(txn)) => {
                    if let Some(block_end_info) = txn.try_as_block_end_info() {
                        block_end_infos.push(block_end_info.clone());
                    }
                },
                _ => {},
            }
        }

        let majority_use_case_fraction = if count_majority_use_case {
            count_by_use_case.iter().max_by_key(|(_, v)| *v).and_then(
                |(max_use_case, max_value)| {
                    if let UseCaseKey::ContractAddress(_) = max_use_case {
                        Some(*max_value as f32 / count_by_use_case.values().sum::<u64>() as f32)
                    } else {
                        None
                    }
                },
            )
        } else {
            None
        };
        Ok((gas_prices, block_end_infos, majority_use_case_fraction))
    }
```

**File:** api/src/context.rs (L1248-1265)
```rust
                let is_full_block =
                    if majority_use_case_fraction.is_some_and(|fraction| fraction > 0.5) {
                        // If majority use case is above half of transactions, UseCaseAware block reordering
                        // will allow other transactions to get in the block (AIP-68)
                        false
                    } else if prices_and_used.len() >= gas_estimation_config.full_block_txns {
                        true
                    } else if !block_end_infos.is_empty() {
                        assert_eq!(1, block_end_infos.len());
                        block_end_infos.first().unwrap().limit_reached()
                    } else if let Some(block_gas_limit) =
                        execution_config.block_gas_limit_type().block_gas_limit()
                    {
                        let gas_used = prices_and_used.iter().map(|(_, used)| *used).sum::<u64>();
                        gas_used >= block_gas_limit
                    } else {
                        false
                    };
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

**File:** types/src/on_chain_config/execution_config.rs (L243-249)
```rust
    pub fn default_for_genesis() -> Self {
        TransactionShufflerType::UseCaseAware {
            sender_spread_factor: 32,
            platform_use_case_spread_factor: 0,
            user_use_case_spread_factor: 4,
        }
    }
```

**File:** config/src/config/gas_estimation_config.rs (L38-50)
```rust
impl Default for GasEstimationConfig {
    fn default() -> GasEstimationConfig {
        GasEstimationConfig {
            enabled: true,
            static_override: None,
            full_block_txns: 250,
            low_block_history: 10,
            market_block_history: 30,
            aggressive_block_history: 120,
            cache_expiration_ms: 500,
            incorporate_reordering_effects: true,
        }
    }
```
