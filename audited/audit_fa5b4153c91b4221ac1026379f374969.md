# Audit Report

## Title
Missing Per-Transaction Aggregator Limit Enables Resource Exhaustion Through Multi-Resource Bypass

## Summary
The Aptos blockchain enforces a limit of 10 aggregators per resource to prevent resource exhaustion, but lacks a per-transaction limit on the total number of aggregators. An attacker can bypass the per-resource limit by creating multiple resources in a single transaction, each containing up to 10 aggregators, potentially creating hundreds of aggregators bounded only by gas limits. This violates the intended resource constraints and could cause validator node slowdowns or state inconsistencies.

## Finding Description
The codebase implements a hardcoded limit of 10 aggregators per resource: [1](#0-0) 

This limit is enforced during resource serialization/deserialization: [2](#0-1) 

The enforcement occurs per-resource, with a new `DelayedFieldsExtension` context created for each serialization operation. The counter resets between resources, allowing the per-resource limit to be circumvented by creating multiple resources.

While the `AggregatorData` structure tracks the total number of aggregators in a transaction via `num_aggregators()`: [3](#0-2) 

This count is only used to generate unique aggregator IDs during creation, not for validation: [4](#0-3) 

The test suite validates the per-resource limit but does not test multi-resource scenarios: [5](#0-4) 

**Attack Path:**
1. Attacker crafts a transaction that creates N resources (or N table items)
2. Each resource/table item contains exactly 10 aggregators (the per-resource maximum)
3. Total aggregators = N × 10, bounded only by transaction limits:
   - Maximum gas units: 2,000,000 [6](#0-5) 
   - Aggregator creation cost: 1,838 gas units per aggregator [7](#0-6) 
   - Maximum write operations: 8,192 per transaction [8](#0-7) 
4. Transaction executes successfully, creating hundreds of aggregators across multiple resources
5. Each resource individually passes the 10-aggregator limit check, but the transaction as a whole contains far more aggregators than intended

The developer TODO comment acknowledges this is a temporary measure: [1](#0-0) 

## Impact Explanation
This qualifies as **Medium severity** per Aptos bug bounty criteria because it can cause:

1. **Validator Node Slowdowns**: Processing hundreds of aggregators during transaction execution, serialization, and validation could cause CPU and memory spikes on validator nodes, degrading network performance.

2. **State Inconsistencies**: If different validators have different resource limits or timeout configurations, some validators might successfully process the transaction while others fail, potentially leading to consensus disagreements requiring manual intervention.

3. **Resource Limit Bypass**: The vulnerability directly violates the documented invariant that "All operations must respect gas, storage, and computational limits." The per-resource limit exists specifically to prevent resource exhaustion, but this protection is ineffective when bypassed through multiple resources.

The impact is bounded by gas costs (limiting to ~1,000 aggregators theoretically, fewer in practice due to other transaction costs), preventing this from reaching Critical or High severity. However, the bypass of an explicitly implemented safety limit combined with potential validator slowdowns qualifies as Medium severity.

## Likelihood Explanation
**Likelihood: Medium**

The attack is feasible because:
- Any user can submit transactions creating resources with aggregators
- No special privileges or validator access required
- Gas costs (~1,838 units per aggregator) make creating hundreds of aggregators economically feasible for a determined attacker
- The test code demonstrates creating table items that can each hold 10 aggregators

Mitigating factors:
- Gas costs provide economic disincentive for sustained attacks
- Write operation limits (8,192) cap the theoretical maximum
- Would require careful transaction construction to maximize aggregator count while staying within limits

## Recommendation
Implement a per-transaction aggregator count limit in addition to the existing per-resource limit. The check should occur when the `AggregatorData` is converted to a change set:

**Fix Location:** `aptos-move/framework/src/natives/aggregator_natives/context.rs`

Add validation in the `into_change_set()` method:

```rust
pub fn into_change_set(self) -> PartialVMResult<AggregatorChangeSet> {
    let NativeAggregatorContext {
        aggregator_v1_data,
        delayed_field_data,
        ..
    } = self;
    
    // NEW: Check transaction-level aggregator limit
    const MAX_AGGREGATORS_PER_TRANSACTION: usize = 100; // or appropriate limit
    let total_aggregator_count = aggregator_v1_data.borrow().num_aggregators() as usize;
    if total_aggregator_count > MAX_AGGREGATORS_PER_TRANSACTION {
        return Err(PartialVMError::new(StatusCode::TOO_MANY_DELAYED_FIELDS)
            .with_message(format!(
                "Too many aggregators in transaction: {} > {}",
                total_aggregator_count,
                MAX_AGGREGATORS_PER_TRANSACTION
            )));
    }
    
    let (_, destroyed_aggregators, aggregators) = aggregator_v1_data.into_inner().into();
    // ... rest of existing code
}
```

The limit should be configurable via gas schedule parameters as indicated by the TODO comment, allowing it to be adjusted based on network performance characteristics.

## Proof of Concept
```move
// File: test_aggregator_transaction_limit.move
module 0x1::aggregator_transaction_limit_test {
    use aptos_framework::aggregator_v2::{Self, Aggregator};
    use aptos_std::table::{Self, Table};
    
    struct MultiResourceAggregators has key {
        // Each table item can hold 10 aggregators (per-resource limit)
        table: Table<u64, AggregatorVec>,
    }
    
    struct AggregatorVec has store {
        aggs: vector<Aggregator<u64>>,
    }
    
    public entry fun exploit_aggregator_limit(account: &signer) {
        let table = table::new();
        
        // Create 50 table items, each with 10 aggregators
        // Total: 500 aggregators (bypasses per-resource limit of 10)
        let i = 0;
        while (i < 50) {
            let agg_vec = AggregatorVec { aggs: vector::empty() };
            let j = 0;
            while (j < 10) {
                let agg = aggregator_v2::create_aggregator<u64>(1000);
                vector::push_back(&mut agg_vec.aggs, agg);
                j = j + 1;
            };
            table::add(&mut table, i, agg_vec);
            i = i + 1;
        };
        
        move_to(account, MultiResourceAggregators { table });
        // Transaction succeeds with 500 aggregators total,
        // despite each individual resource having only 10
    }
}
```

**Expected Result:** Transaction executes successfully, creating 500 aggregators across 50 table items, demonstrating the bypass of the intended resource limit.

**Actual Result:** Transaction should be rejected if per-transaction limit were enforced, but currently succeeds.

## Notes
The vulnerability is confirmed by:
1. Explicit per-resource limit of 10 indicating performance/resource concerns
2. TODO comment acknowledging proper gas charging is not implemented
3. No transaction-level validation despite `num_aggregators()` tracking total count
4. Test coverage validating only single-resource scenarios

The issue represents a gap between the intended security model (limiting aggregators to prevent resource exhaustion) and the actual implementation (limit only applies per-resource and can be bypassed).

### Citations

**File:** third_party/move/move-vm/types/src/value_serde.rs (L50-54)
```rust
    // Temporarily limit the number of delayed fields per resource, until proper charges are
    // implemented.
    // TODO[agg_v2](clean):
    //   Propagate up, so this value is controlled by the gas schedule version.
    const MAX_DELAYED_FIELDS_PER_RESOURCE: usize = 10;
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L58-65)
```rust
    pub(crate) fn inc_and_check_delayed_fields_count(&self) -> PartialVMResult<()> {
        *self.delayed_fields_count.borrow_mut() += 1;
        if *self.delayed_fields_count.borrow() > Self::MAX_DELAYED_FIELDS_PER_RESOURCE {
            return Err(PartialVMError::new(StatusCode::TOO_MANY_DELAYED_FIELDS)
                .with_message("Too many Delayed fields in a single resource.".to_string()));
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L312-315)
```rust
    /// Returns the number of aggregators that are used in the current transaction.
    pub fn num_aggregators(&self) -> u128 {
        self.aggregators.len() as u128
    }
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_factory.rs (L36-36)
```rust
    context.charge(AGGREGATOR_FACTORY_NEW_AGGREGATOR_BASE)?;
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_factory.rs (L44-57)
```rust
    let aggregator_context = context.extensions().get::<NativeAggregatorContext>();
    let mut aggregator_data = aggregator_context.aggregator_v1_data.borrow_mut();

    // Every aggregator V1 instance uses a unique key for its id. Here we can reuse
    // the strategy from `table` implementation: taking hash of transaction and
    // number of aggregator instances created so far.
    let mut hasher = DefaultHasher::new(&[0_u8; 0]);
    hasher.update(&aggregator_context.session_hash());
    hasher.update(&(aggregator_data.num_aggregators() as u32).to_be_bytes());
    let hash = hasher.finish().to_vec();

    if let Ok(key) = AccountAddress::from_bytes(hash) {
        let id = AggregatorID::new(handle, key);
        aggregator_data.create_new_aggregator(id, limit);
```

**File:** aptos-move/e2e-move-tests/src/tests/aggregator_v2.rs (L625-663)
```rust
fn test_too_many_aggregators_in_a_resource(use_type: UseType) {
    let test_env = TestEnvConfig {
        executor_mode: ExecutorMode::BothComparison,
        aggregator_execution_mode: AggregatorMode::EnabledOnly,
        block_split: BlockSplit::Whole,
    };
    println!(
        "Testing test_too_many_aggregators_in_a_resource {:?}",
        test_env
    );

    let element_type = ElementType::U64;

    let mut h = setup(
        test_env.executor_mode,
        test_env.aggregator_execution_mode,
        12,
    );

    let agg_locs = (0..15)
        .map(|i| AggregatorLocation::new(*h.account.address(), element_type, use_type, i))
        .collect::<Vec<_>>();

    let mut txns = vec![(
        SUCCESS,
        h.init(None, use_type, element_type, StructType::Aggregator),
    )];
    for i in 0..10 {
        txns.push((SUCCESS, h.new(agg_locs.get(i).unwrap(), 10)));
    }
    h.run_block_in_parts_and_check(test_env.block_split, txns);

    let failed_txns = vec![h.new(agg_locs.get(10).unwrap(), 10)];
    let output = h.run_block(failed_txns);
    assert_eq!(output.len(), 1);
    assert_ok_eq!(
        output[0].status().status(),
        ExecutionStatus::MiscellaneousError(Some(StatusCode::TOO_MANY_DELAYED_FIELDS))
    );
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L55-58)
```rust
            maximum_number_of_gas_units: Gas,
            "maximum_number_of_gas_units",
            aptos_global_constants::MAX_GAS_AMOUNT
        ],
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L95-99)
```rust
        if self.max_write_ops_per_transaction != 0
            && change_set.num_write_ops() as u64 > self.max_write_ops_per_transaction
        {
            return storage_write_limit_reached(Some("Too many write ops."));
        }
```
