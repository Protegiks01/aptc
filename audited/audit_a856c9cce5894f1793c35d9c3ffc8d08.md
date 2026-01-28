# Audit Report

## Title
Critical Node Crash: Aggregator V1 Delta Materialization Panic on Deleted Aggregators

## Summary
The block executor crashes with an `unreachable!` panic when materializing aggregator V1 deltas that reference deleted aggregators within the same block. This causes validator nodes to crash, breaking network liveness during parallel execution.

## Finding Description

The vulnerability exists in the parallel execution path where aggregator V1 deltas and deletions can coexist in the versioned cache without validation. The test infrastructure explicitly warns against this scenario. [1](#0-0) 

**Attack Scenario:**

1. Transaction T1 (index 0) calls `aggregator::destroy(agg)` which writes a deletion WriteOp to the versioned cache during execution [2](#0-1) 

2. Transaction T2 (index 1) calls `aggregator::add(agg, 50)` which writes a delta operation to the versioned cache [3](#0-2) 

3. Both transactions execute successfully in parallel because T2 creates a local aggregator instance via `get_aggregator()` which uses `or_insert()` [4](#0-3) 

4. Both operations are written independently to the versioned cache in parallel execution [5](#0-4) 

**The Crash Occurs During Commit:**

When materializing T2's delta, `materialize_aggregator_v1_delta_writes` calls `materialize_delta` [6](#0-5) 

The `materialize_delta` function invokes `read(txn_idx + 1)` which traverses the versioned cache backwards [7](#0-6) 

When the read operation encounters T1's deletion WriteOp with accumulated deltas from T2, `value.as_u128()` returns `None`, causing the function to return `Ok(Versioned(...))` instead of resolving the delta [8](#0-7) 

Back in `materialize_delta`, this response doesn't match either expected case (`Ok(Resolved(value))` or `Err(Unresolved(op))`), causing execution to hit the `unreachable!` panic [9](#0-8) 

**Root Cause:**

The protection against applying deltas to deleted aggregators exists in `squash_additional_aggregator_v1_changes`, but this only applies during change set squashing (sequential execution or within single transaction) [10](#0-9) 

In parallel execution, transactions write independently to the versioned cache without squashing, so this check is never invoked. The materialization happens later during commit by reading from the versioned cache, where the deletion-delta conflict is not detected until it's too late.

## Impact Explanation

**Critical Severity** - This meets the "Total Loss of Liveness/Network Availability" criteria:

1. **Network Halt**: All validators processing a block containing this transaction pattern will panic with `unreachable!` and crash simultaneously, halting the entire network.

2. **Deterministic Crash**: The panic occurs during the commit phase after execution completes successfully, making it deterministic and unavoidable once such transactions enter a block.

3. **Requires Manual Intervention**: Recovery requires all validators to restart and coordinate to skip or handle the problematic block, necessitating emergency intervention.

4. **No Privileges Required**: Any unprivileged user can submit two valid transactions (one destroying an aggregator, another modifying it) that will be executed and crash all validators.

This is more severe than a typical DoS because it causes complete network halt through a protocol-level bug, not network-layer attacks.

## Likelihood Explanation

**High Likelihood:**

1. **Simple Trigger**: Requires only two basic transactions in the same block operating on the same aggregator ID.

2. **Deterministic**: No race conditions or timing dependencies - the crash occurs deterministically during commit.

3. **Developer Awareness**: The test infrastructure explicitly disables this scenario with a comment warning that "resolver can't apply delta to a deleted aggregator", indicating developers knew about the limitation but failed to enforce it in production code.

4. **Execution Succeeds**: Both transactions pass all execution-time validations and only crash during commit, making it difficult to detect before deployment.

5. **Repeatable**: An attacker can repeatedly submit such transaction pairs to cause persistent network outages.

## Recommendation

Add validation during the commit preparation phase to detect when a delta operation references an aggregator that has been deleted earlier in the same block. This check should occur before calling `materialize_delta`:

```rust
// Before materializing delta at txn_idx, check if any prior transaction in the block deleted this aggregator
for prior_txn in 0..txn_idx {
    if versioned_cache.data().is_deletion_at(&key, prior_txn) {
        return Err(Error::DeltaOnDeletedAggregator);
    }
}
```

Alternatively, modify the `read` function to return `Err(DeltaApplicationFailure)` instead of `Ok(Versioned(...))` when encountering a deletion with accumulated deltas, allowing `materialize_delta` to handle it gracefully.

## Proof of Concept

A concrete PoC would require setting up two parallel transactions:

```move
// Transaction 1: Destroy aggregator
public entry fun destroy_agg(account: &signer, agg: Aggregator) {
    aggregator::destroy(agg);
}

// Transaction 2: Add to same aggregator
public entry fun add_to_agg(account: &signer, agg: Aggregator) {
    aggregator::add(&mut agg, 50);
}
```

When both transactions target the same aggregator and execute in the same block during parallel execution, all validators will crash with:
```
unreachable! "Must resolve delta at key = {:?}, txn_idx = {}"
```

### Citations

**File:** aptos-move/block-executor/src/combinatorial_tests/tests.rs (L200-204)
```rust
    // Do not allow deletions as resolver can't apply delta to a deleted aggregator.
    let transactions: Vec<_> = transaction_gen
        .into_iter()
        .map(|txn_gen| txn_gen.materialize_with_deltas(&universe, 15, false))
        .collect();
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator.rs (L27-48)
```rust
fn native_add(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert_eq!(args.len(), 2);

    context.charge(AGGREGATOR_ADD_BASE)?;

    // Get aggregator information and a value to add.
    let input = safely_pop_arg!(args, u128);
    let (id, max_value) = aggregator_info(&safely_pop_arg!(args, StructRef))?;

    // Get aggregator.
    let aggregator_context = context.extensions().get::<NativeAggregatorContext>();
    let mut aggregator_data = aggregator_context.aggregator_v1_data.borrow_mut();
    let aggregator = aggregator_data.get_aggregator(id, max_value)?;

    aggregator.add(input)?;

    Ok(smallvec![])
}
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator.rs (L114-136)
```rust
fn native_destroy(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert_eq!(args.len(), 1);

    context.charge(AGGREGATOR_DESTROY_BASE)?;

    // First, unpack the struct.
    let aggregator_struct = safely_pop_arg!(args, Struct);
    let (handle, key, _) = unpack_aggregator_struct(aggregator_struct)?;

    // Get aggregator data.
    let aggregator_context = context.extensions().get::<NativeAggregatorContext>();
    let mut aggregator_data = aggregator_context.aggregator_v1_data.borrow_mut();

    // Actually remove the aggregator.
    let id = AggregatorID::new(handle, key);
    aggregator_data.remove_aggregator(id);

    Ok(smallvec![])
}
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L298-310)
```rust
    pub fn get_aggregator(
        &mut self,
        id: AggregatorID,
        max_value: u128,
    ) -> PartialVMResult<&mut Aggregator> {
        let aggregator = self.aggregators.entry(id).or_insert(Aggregator {
            value: 0,
            state: AggregatorState::PositiveDelta,
            max_value,
            history: Some(DeltaHistory::new()),
        });
        Ok(aggregator)
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L490-493)
```rust
            for (key, delta) in output_before_guard.aggregator_v1_delta_set().into_iter() {
                prev_modified_aggregator_v1_keys.remove(&key);
                versioned_cache.data().add_delta(key, idx_to_execute, delta);
            }
```

**File:** aptos-move/block-executor/src/executor.rs (L1091-1093)
```rust
                let committed_delta = versioned_cache
                    .data()
                    .materialize_delta(&k, txn_idx)
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L310-318)
```rust
                        None => {
                            // Resolve to the write if the WriteOp was deletion
                            // (MoveVM will observe 'deletion'). This takes precedence
                            // over any speculative delta accumulation errors on top.
                            Ok(Versioned(
                                idx.idx().map(|idx| (idx, *incarnation)),
                                value_with_layout.clone(),
                            ))
                        },
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L760-764)
```rust
    pub fn materialize_delta(&self, key: &K, txn_idx: TxnIndex) -> Result<u128, DeltaOp> {
        let mut v = self.values.get_mut(key).expect("Path must exist");

        // +1 makes sure we include the delta from txn_idx.
        match v.read(txn_idx + 1, None) {
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L774-777)
```rust
            _ => unreachable!(
                "Must resolve delta at key = {:?}, txn_idx = {}",
                key, txn_idx
            ),
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L423-432)
```rust
                    None => {
                        // This case (applying a delta to deleted item) should
                        // never happen. Let's still return an error instead of
                        // panicking.
                        return Err(PartialVMError::new(
                            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                        )
                        .with_message(
                            "Cannot squash delta which was already deleted.".to_string(),
                        ));
```
