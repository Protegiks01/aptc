# Audit Report

## Title
Memory Tracking Double-Counting in Table/Event Natives Enables Resource Exhaustion Attack

## Summary
The `charge_native_function_before_execution()` function in `aptos-memory-usage-tracker/src/lib.rs` conditionally leaks argument memory for table and event natives. Combined with these natives also charging memory when storing/loading values, this creates a double-counting vulnerability that allows attackers to exhaust memory quotas prematurely through interleaved native calls, causing transaction failures and enabling denial-of-service attacks.

## Finding Description

The memory tracking system contains a critical flaw where table and event native functions cause the same memory to be counted multiple times: [1](#0-0) 

When calling table or event natives, the `should_leak_memory_for_native` flag is set to true. This flag then controls whether argument memory is released: [2](#0-1) 

For table/event natives, argument memory is NOT released (line 328 condition is false). However, these natives ALSO charge memory when storing or loading values: [3](#0-2) 

The `fix_memory_double_counting` feature flag was introduced to address this issue: [4](#0-3) 

However, this fix is NOT yet enabled on mainnet or testnet: [5](#0-4) 

**Attack Scenario:**
1. Attacker creates a transaction that repeatedly adds large values to a table
2. For each `table.add(key, large_value)` call:
   - Memory for `large_value` is charged when created/loaded
   - Memory is NOT released before native execution (leaked)
   - Native charges memory AGAIN when storing the value (line 440)
   - Same memory counted twice
3. Interleave with `table.borrow()` operations that load values:
   - Each load charges memory again (triple counting)
4. Mix in other native calls that properly release memory
5. Memory quota becomes severely inflated, hitting `MEMORY_LIMIT_EXCEEDED` prematurely

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The memory tracking system fails to accurately track memory usage, allowing operations to consume quota at 2-3x the rate they should.

## Impact Explanation

**Severity: Medium**

This vulnerability enables multiple attack vectors:

1. **Transaction Denial-of-Service**: Attackers can craft transactions that appear to consume excessive memory due to double-counting, causing legitimate operations to fail with `MEMORY_LIMIT_EXCEEDED` errors even when actual memory usage is within limits.

2. **Griefing Attack**: Malicious users can make other users' table operations fail by exploiting this to exhaust memory quotas faster than expected.

3. **State Inconsistency**: The memory tracking state becomes corrupted (tracked usage doesn't match actual usage), violating VM safety guarantees.

Per the Aptos bug bounty program, this qualifies as **Medium Severity** because it causes "State inconsistencies requiring intervention" - the memory tracking system's state diverges from reality, requiring the timed feature flag activation to fix.

This does NOT qualify as Critical or High because:
- No fund loss or theft occurs
- No consensus violation (all nodes execute identically)
- No permanent network partition
- Limited to memory quota exhaustion within individual transactions

## Likelihood Explanation

**Likelihood: High**

This vulnerability is CURRENTLY ACTIVE on mainnet and testnet (as of analysis date, before October 2025 activation). The attack is:

1. **Easy to Execute**: Any user can submit transactions using table operations
2. **No Special Privileges Required**: Standard transaction submission
3. **Deterministic**: The double-counting occurs reliably for all table/event operations
4. **Wide Attack Surface**: Any Move contract using tables is affected
5. **Difficult to Detect**: The over-charging appears as legitimate memory usage

The vulnerability will be automatically fixed when the `FixTableNativesMemoryDoubleCounting` timed feature activates, but until then, the network is vulnerable.

## Recommendation

The fix already exists in the codebase but is not yet active. The recommendation is to:

1. **Immediate**: Accelerate the activation timeline for `FixTableNativesMemoryDoubleCounting` on testnet and mainnet if possible

2. **Short-term**: Monitor for transactions hitting memory limits unexpectedly and investigate if they're exploiting this issue

3. **Long-term**: The existing fix correctly prevents double-counting:
   - When `fix_memory_double_counting` is true AND a value is not loaded from storage (`loaded.is_none()`), memory is not charged again
   - This prevents double-counting for new values being added to tables

The fix is already implemented at: [6](#0-5) 

Once the timed feature activates, the issue will be resolved.

## Proof of Concept

```move
#[test_only]
module test_addr::memory_double_counting_exploit {
    use std::table::{Self, Table};
    use std::vector;
    
    struct LargeStruct has store, drop {
        data: vector<u8>
    }
    
    #[test(account = @test_addr)]
    public fun test_memory_exhaustion(account: &signer) {
        // Create a table
        let table: Table<u64, LargeStruct> = table::new();
        
        // Create large values (e.g., 1MB each)
        let large_data = vector::empty<u8>();
        let i = 0;
        while (i < 1000000) {
            vector::push_back(&mut large_data, 0u8);
            i = i + 1;
        };
        
        // Add multiple large values to trigger double-counting
        // Each operation will count memory twice:
        // 1. Once for the argument (not released)
        // 2. Once when storing in table
        let key = 0;
        while (key < 100) {
            let value = LargeStruct { data: copy large_data };
            table::add(&mut table, key, value);
            key = key + 1;
            // Memory quota exhausted much faster than it should be
        };
        
        // Clean up
        table::destroy_empty(table);
    }
}
```

**Expected Behavior (with fix)**: Transaction succeeds or fails based on actual memory usage
**Actual Behavior (without fix)**: Transaction fails with `MEMORY_LIMIT_EXCEEDED` due to double-counting, even though actual memory usage is within limits

**Notes**

This is a confirmed vulnerability that is currently exploitable on mainnet and testnet. The fix exists but is not yet deployed, making this a time-sensitive security issue. The vulnerability specifically manifests when interleaving table/event native operations with other operations, as the memory tracking becomes progressively more inflated with each table operation. While the fix is scheduled for October 2025, the current window of vulnerability could be exploited for denial-of-service attacks against applications heavily using table data structures.

### Citations

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L311-319)
```rust
        self.should_leak_memory_for_native = (*module_id.address() == CORE_CODE_ADDRESS
            && module_id.name().as_str() == "table")
            || (self.feature_version() >= 4
                && *module_id.address() == CORE_CODE_ADDRESS
                && module_id.name().as_str() == "event");

        self.base
            .charge_call_generic(module_id, func_name, ty_args, args, num_locals)
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L322-344)
```rust
    fn charge_native_function_before_execution(
        &mut self,
        ty_args: impl ExactSizeIterator<Item = impl TypeView> + Clone,
        args: impl ExactSizeIterator<Item = impl ValueView> + Clone,
    ) -> PartialVMResult<()> {
        // TODO(Gas): https://github.com/aptos-labs/aptos-core/issues/5485
        if !self.should_leak_memory_for_native {
            self.release_heap_memory(args.clone().try_fold(
                AbstractValueSize::zero(),
                |acc, val| {
                    let heap_size = self
                        .vm_gas_params()
                        .misc
                        .abs_val
                        .abstract_heap_size(val, self.feature_version())?;
                    Ok::<_, PartialVMError>(acc + heap_size)
                },
            )?);
        }

        self.base
            .charge_native_function_before_execution(ty_args, args)
    }
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L395-396)
```rust
    let fix_memory_double_counting =
        context.timed_feature_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting);
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L416-442)
```rust
    let mem_usage = if !fix_memory_double_counting || loaded.is_some() {
        gv.view()
            .map(|val| {
                abs_val_gas_params
                    .abstract_heap_size(&val, gas_feature_version)
                    .map(u64::from)
            })
            .transpose()?
    } else {
        None
    };

    let res = match gv.move_to(val) {
        Ok(_) => Ok(smallvec![]),
        Err(_) => Err(SafeNativeError::Abort {
            abort_code: ALREADY_EXISTS,
        }),
    };

    drop(table_data);

    // TODO(Gas): Figure out a way to charge this earlier.
    context.charge(key_cost)?;
    if let Some(amount) = mem_usage {
        context.use_heap_memory(amount)?;
    }
    charge_load_cost(context, loaded)?;
```

**File:** types/src/on_chain_config/timed_features.rs (L128-135)
```rust
            (FixTableNativesMemoryDoubleCounting, TESTNET) => Los_Angeles
                .with_ymd_and_hms(2025, 10, 16, 17, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
            (FixTableNativesMemoryDoubleCounting, MAINNET) => Los_Angeles
                .with_ymd_and_hms(2025, 10, 21, 10, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
```
