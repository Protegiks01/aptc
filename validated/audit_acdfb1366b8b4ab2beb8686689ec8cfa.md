# Audit Report

## Title
Native Function Gas Charging Timing Vulnerability Allows Resource Exhaustion Before Out-of-Gas Detection

## Summary
Table native functions in Aptos perform expensive operations (key serialization and storage I/O) before charging the corresponding gas costs. Even with modern gas metering (gas_feature_version >= 36), attackers can trigger these expensive operations with insufficient gas, causing validator resource exhaustion before the out-of-gas condition is detected.

## Finding Description

The Aptos Move VM charges gas for native functions in two phases: before execution and after execution. The `charge_native_function_before_execution` method in `StandardGasMeter` is a no-op that simply returns `Ok(())` without performing any gas charges. [1](#0-0) 

Table native functions explicitly disable incremental gas charging by wrapping all native function creation with `builder.with_incremental_gas_charging(false, ...)`. [2](#0-1) 

In the `native_add_box` function, the execution order creates a critical timing vulnerability:

1. Base gas cost is charged first [3](#0-2) 

2. Expensive key serialization operation occurs [4](#0-3) 

3. Expensive storage I/O operation via `get_or_create_global_value` [5](#0-4) 

4. Key cost is charged AFTER these operations [6](#0-5) 

The code contains an explicit TODO comment acknowledging this timing issue: "TODO(Gas): Figure out a way to charge this earlier." [7](#0-6) 

The same pattern exists in `native_borrow_box` [8](#0-7) , `native_contains_box` [9](#0-8) , and `native_remove_box` [10](#0-9) , all with TODO comments acknowledging the timing issue.

With modern gas metering (gas_feature_version >= 36), while individual `charge()` calls check the gas budget immediately [11](#0-10) , the timing of when charges occur remains unchanged. The Move VM interpreter calls native functions and then charges the accumulated gas after execution completes. [12](#0-11) 

**Attack Flow:**
1. Attacker submits a transaction calling `table::add()` with a large serializable key
2. Transaction gas is precisely calculated: sufficient for `ADD_BOX_BASE` but insufficient for full execution including key serialization costs
3. Native function charges base cost (succeeds)
4. `serialize_key()` performs expensive CPU work serializing the large key
5. `get_or_create_global_value()` performs expensive storage I/O
6. Native attempts to charge `key_cost`
7. Out-of-gas error occurs, transaction aborts
8. **Critical Issue**: Validator has already consumed CPU cycles and performed I/O operations without receiving payment for this work

## Impact Explanation

This vulnerability enables a **resource exhaustion attack** against validator nodes through a gas metering bypass:

- **Validator CPU Exhaustion**: Attackers can force validators to perform expensive serialization operations with keys up to transaction size limits before detecting insufficient gas, consuming CPU cycles without proper payment.

- **Validator I/O Exhaustion**: Attackers can trigger expensive storage lookups (`get_or_create_global_value`) that complete before gas charges are applied, consuming I/O resources without proper payment.

- **Deterministic Execution**: While the transaction ultimately fails with out-of-gas, all validators waste identical resources processing it, causing synchronized performance degradation.

This qualifies as **High Severity** per Aptos bug bounty criteria under category 8 "Validator Node Slowdowns":
- Causes significant performance degradation affecting consensus through resource exhaustion
- Represents DoS through resource exhaustion via a gas calculation bug
- Breaks the critical invariant that all operations must respect gas limits before consuming resources

The impact is bounded by transaction size limits and base gas costs, but an attacker with modest funds can submit many such transactions to create sustained validator resource consumption, causing measurable slowdowns in block processing.

## Likelihood Explanation

**Likelihood: HIGH**

Attack requirements:
- **No special privileges**: Any Aptos user can submit transactions calling table operations
- **Straightforward execution**: Standard table operations accessible through the Move API
- **Deterministic gas calculation**: Attacker can precisely compute gas requirements to trigger the vulnerability
- **Universal exploitability**: Affects all networks and validators processing these transactions

Attack complexity:
- **LOW**: Simple to execute and reproduce
- **Automatable**: Can be scripted to submit many malicious transactions
- **Broad impact**: Affects all validators processing transactions from mempool
- **No timing constraints**: No race conditions or precise timing requirements

The vulnerability is currently present in production code, as evidenced by the TODO comments acknowledging the issue across multiple table operations but not yet implementing a fix.

## Recommendation

Implement one of the following mitigations:

**Option 1**: Charge gas for key serialization before performing the serialization. This requires refactoring to calculate the key size before serialization or using a two-pass approach.

**Option 2**: Enable incremental gas charging for table natives by changing line 301 in `table-natives/src/lib.rs` from `builder.with_incremental_gas_charging(false, ...)` to `builder.with_incremental_gas_charging(true, ...)`. This ensures gas budget checks occur during expensive operations rather than after.

**Option 3**: Pre-charge a conservative upper bound for key serialization costs before serialization, then refund excess charges after determining the actual cost.

**Preferred solution**: Option 2 combined with reordering gas charges to occur before their corresponding operations, as this provides immediate gas budget validation without requiring major refactoring.

## Proof of Concept

```move
// Test demonstrating the vulnerability
module test_addr::gas_exhaustion_poc {
    use std::table;
    use std::vector;
    
    public entry fun exploit_table_add(sender: &signer) {
        // Create a table
        let t = table::new<vector<u8>, u64>();
        
        // Create a large key to maximize unpaid serialization work
        let large_key = vector::empty<u8>();
        let i = 0;
        while (i < 10000) {  // Large key near transaction size limits
            vector::push_back(&mut large_key, (i % 256 as u8));
            i = i + 1;
        };
        
        // This transaction should be submitted with gas limit calculated to:
        // - Cover ADD_BOX_BASE cost
        // - NOT cover ADD_BOX_PER_BYTE_SERIALIZED * 10000
        // Result: serialize_key() executes but key_cost charge fails
        table::add(&mut t, large_key, 42);
        
        table::destroy_empty(t);
    }
}
```

To exploit: Submit the above transaction with `max_gas_amount` set to slightly above `ADD_BOX_BASE` but below `ADD_BOX_BASE + ADD_BOX_PER_BYTE_SERIALIZED * 10000`. The validator will serialize the 10KB key before detecting insufficient gas.

## Notes

This is a gas metering implementation issue, not a network DoS attack. The distinction is critical: this exploits a protocol bug (incorrect gas charging timing) rather than simply flooding the network with transactions. The vulnerability breaks the fundamental invariant that validators should never perform expensive work without first confirming sufficient gas payment.

### Citations

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L208-214)
```rust
    fn charge_native_function_before_execution(
        &mut self,
        _ty_args: impl ExactSizeIterator<Item = impl TypeView>,
        _args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        Ok(())
    }
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L301-322)
```rust
    builder.with_incremental_gas_charging(false, |builder| {
        builder
            .make_named_natives([
                ("new_table_handle", native_new_table_handle as RawSafeNative),
                ("add_box", native_add_box),
                ("borrow_box", native_borrow_box),
                ("borrow_box_mut", native_borrow_box),
                ("remove_box", native_remove_box),
                ("contains_box", native_contains_box),
                ("destroy_empty_box", native_destroy_empty_box),
                ("drop_unchecked_box", native_drop_unchecked_box),
            ])
            .map(|(func_name, func)| {
                (
                    table_addr,
                    Identifier::new("table").unwrap(),
                    Identifier::new(func_name).unwrap(),
                    func,
                )
            })
            .collect()
    })
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L394-394)
```rust
    context.charge(ADD_BOX_BASE)?;
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L411-411)
```rust
    let key_bytes = serialize_key(&function_value_extension, &table.key_layout, &key)?;
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L414-415)
```rust
    let (gv, loaded) =
        table.get_or_create_global_value(&function_value_extension, table_context, key_bytes)?;
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L437-438)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
    context.charge(key_cost)?;
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L497-497)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L551-551)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L611-611)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L86-102)
```rust
        if self.has_direct_gas_meter_access_in_native_context() {
            self.gas_meter()
                .charge_native_execution(amount)
                .map_err(LimitExceededError::from_err)?;
            Ok(())
        } else {
            self.legacy_gas_used += amount;
            if self.legacy_gas_used > self.legacy_gas_budget()
                && self.legacy_enable_incremental_gas_charging
            {
                Err(SafeNativeError::LimitExceeded(
                    LimitExceededError::LegacyOutOfGas,
                ))
            } else {
                Ok(())
            }
        }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1106-1115)
```rust
        let result = native_function(&mut native_context, ty_args, args)?;

        // Note(Gas): The order by which gas is charged / error gets returned MUST NOT be modified
        //            here or otherwise it becomes an incompatible change!!!
        match result {
            NativeResult::Success {
                cost,
                ret_vals: return_values,
            } => {
                gas_meter.charge_native_function(cost, Some(return_values.iter()))?;
```
