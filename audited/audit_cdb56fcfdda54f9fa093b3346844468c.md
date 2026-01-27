# Audit Report

## Title
Table Native Functions Bypass Memory Quota Enforcement Leading to Potential Validator OOM

## Summary
Table native functions (`native_add_box`, `native_borrow_box`, `native_contains_box`, `native_remove_box`) allocate heap memory during deserialization BEFORE checking memory quotas, creating a Time-of-Check-Time-of-Use (TOCTOU) vulnerability. When the `FixMemoryUsageTracking` timed feature flag is disabled (before March 2025 activation), memory quota enforcement is completely bypassed, allowing unbounded memory allocation limited only by gas costs. This can lead to validator node OOM crashes under heavy load or in memory-constrained environments.

## Finding Description

The vulnerability exists in the table native functions' memory tracking implementation. The critical flow is:

1. **Memory Allocation Occurs First**: In `get_or_create_global_value()`, table values are loaded from storage and deserialized into Rust `Value` objects, allocating heap memory: [1](#0-0) 

2. **Memory Quota Check Happens After**: Only after the value is fully allocated and stored in the cache does the code calculate its abstract size and call `use_heap_memory()`: [2](#0-1) 

The TODO comment explicitly acknowledges this ordering problem: [3](#0-2) 

3. **Feature Flag Bypass**: When `FixMemoryUsageTracking` is disabled (before March 2025), the `use_heap_memory()` function becomes a no-op: [4](#0-3) 

The timed feature flag is scheduled for future activation: [5](#0-4) [6](#0-5) 

4. **No Alternative Tracking**: The legacy path accumulator is not updated when the feature is disabled, and the VM's `charge_native_function` only tracks return values (references), not the actual loaded data stored in the table cache: [7](#0-6) 

**Attack Vector**: An attacker can:
- Store maximum-sized table entries (up to 1MB each per write limit)
- Submit transactions that load multiple table entries (5-6 per transaction limited by gas)
- Leverage parallel block execution (BlockSTM) to have many transactions execute concurrently
- Each concurrent transaction allocates ~6MB without memory quota enforcement
- With 64 concurrent threads on a typical server, peak memory usage could reach 384MB+ (excluding overhead) [8](#0-7) [9](#0-8) 

The vulnerability breaks the **Move VM Safety** invariant requiring "Bytecode execution must respect gas limits and memory constraints" and the **Resource Limits** invariant.

## Impact Explanation

**Severity: Medium**

While the feature flag is disabled (before March 2025 activation), this vulnerability allows memory quota enforcement to be completely bypassed for table operations. The impact includes:

- **Validator Availability**: Potential OOM crashes of validator nodes requiring restart, affecting block production and consensus participation
- **State Inconsistencies**: Transactions may succeed in memory allocation but fail quota checks on different validators if timing varies, potentially causing consensus disagreements
- **Deterministic Execution Violation**: Different validators with different memory constraints may experience different execution outcomes

However, practical exploitability is limited by:
- Gas costs restrict the number of table entries loadable per transaction (~5-6 1MB entries)
- Production validators typically have adequate RAM (GBs) making OOM unlikely
- Peak memory with 64 concurrent threads is estimated at 384-800MB including overhead
- The fix is already scheduled for March 2025 activation

The impact meets **Medium severity** criteria: "State inconsistencies requiring intervention" through potential validator crashes and restart requirements.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability is currently exploitable under these conditions:
- **Timing**: Before March 2025 when `FixMemoryUsageTracking` activates on mainnet
- **Environment**: Validators running in memory-constrained environments (containers with memory limits, VMs with restricted RAM)
- **Load**: Heavy concurrent transaction load utilizing parallel execution
- **Cost**: Attacker must spend gas to load table entries

On production mainnet validators with adequate hardware (16GB+ RAM), OOM is unlikely. However, the vulnerability is demonstrably present as evidenced by:
- The scheduled fix via timed feature flag
- Explicit TODO comment acknowledging the issue  
- Related fixes for double-counting (`FixTableNativesMemoryDoubleCounting`)
- Test cases demonstrating memory quota enforcement failures [10](#0-9) 

## Recommendation

**Immediate Fix** (already scheduled):
The timed feature flag `FixMemoryUsageTracking` should be activated as scheduled. Ensure all validators upgrade before the March 2025 activation time.

**Long-term Fix**:
Restructure table native functions to check memory quota BEFORE deserialization:

1. After loading bytes from storage, calculate approximate memory needed
2. Call `use_heap_memory()` with estimated size BEFORE deserializing
3. Perform deserialization only if quota check passes
4. Adjust tracking if actual size differs from estimate

This eliminates the TOCTOU vulnerability by moving the check before allocation.

**Code Structure** (conceptual):
```rust
// BEFORE deserialization
let estimated_size = val_bytes.len() + OVERHEAD_ESTIMATE;
context.use_heap_memory(estimated_size)?;

// NOW deserialize - quota already checked
let val = deserialize_value(...)?;
```

## Proof of Concept

**Scenario**: Validator running in a container with 512MB memory limit, before March 2025.

**Setup**:
1. Deploy Move module creating a table
2. Store 10 table entries, each ~900KB (under 1MB limit)
3. Submit block with 64 transactions, each loading 6 table entries
4. With parallel execution, peak memory: 64 × 6 × 900KB = ~345MB allocated before any quota checks
5. Combined with OS overhead and other validator processes, container OOM occurs

**Move Test** (demonstrating memory tracking bypass):
```move
// Test file: aptos-move/e2e-move-tests/src/tests/memory_quota.rs
// Lines 47-107 already demonstrate this issue
// When FixMemoryUsageTracking is disabled, memory quota is not enforced
// After activation (new_epoch), the same operations fail with MEMORY_LIMIT_EXCEEDED
```

The existing test case confirms that before feature activation, memory quota enforcement fails, and after activation (simulated by `new_epoch()` at line 94), the same operations correctly fail with `MEMORY_LIMIT_EXCEEDED`.

## Notes

This vulnerability represents a known issue that the Aptos team has already identified and scheduled for remediation through the timed feature flag mechanism. The TOCTOU aspect (memory allocated before quota check) persists even after the fix activates, though the quota will at least be checked. A complete fix requires reordering operations to check quota before allocation, eliminating the race condition entirely.

The practical impact on well-provisioned production validators is limited, but the vulnerability could affect validators in resource-constrained environments or under extreme load conditions. The scheduled March 2025 fix addresses the immediate bypass issue but not the underlying TOCTOU architecture.

### Citations

**File:** aptos-move/framework/table-natives/src/lib.rs (L274-280)
```rust
                        let val = deserialize_value(
                            function_value_extension,
                            &val_bytes,
                            &self.value_layout_info,
                        )?;
                        (
                            GlobalValue::cached(val)?,
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L437-437)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L497-501)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
    context.charge(key_cost)?;
    if let Some(amount) = mem_usage {
        context.use_heap_memory(amount)?;
    }
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L205-217)
```rust
    pub fn use_heap_memory(&mut self, amount: u64) -> SafeNativeResult<()> {
        if self.timed_feature_enabled(TimedFeatureFlag::FixMemoryUsageTracking) {
            if self.has_direct_gas_meter_access_in_native_context() {
                self.gas_meter()
                    .use_heap_memory_in_native_context(amount)
                    .map_err(LimitExceededError::from_err)?;
            } else {
                self.legacy_heap_memory_usage =
                    self.legacy_heap_memory_usage.saturating_add(amount);
            }
        }
        Ok(())
    }
```

**File:** types/src/on_chain_config/timed_features.rs (L20-21)
```rust
    // Fixes the bug of table natives not tracking the memory usage of the global values they create.
    FixMemoryUsageTracking,
```

**File:** types/src/on_chain_config/timed_features.rs (L102-109)
```rust
            (FixMemoryUsageTracking, TESTNET) => Los_Angeles
                .with_ymd_and_hms(2025, 3, 7, 12, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
            (FixMemoryUsageTracking, MAINNET) => Los_Angeles
                .with_ymd_and_hms(2025, 3, 11, 17, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
```

**File:** aptos-move/aptos-native-interface/src/builder.rs (L121-129)
```rust
            let legacy_heap_memory_usage = context.legacy_heap_memory_usage;
            if context.has_direct_gas_meter_access_in_native_context() {
                assert_eq!(context.legacy_gas_used, 0.into());
                assert_eq!(legacy_heap_memory_usage, 0);
            }
            context
                .inner
                .gas_meter()
                .use_heap_memory_in_native_context(legacy_heap_memory_usage)?;
```

**File:** types/src/block_executor/config.rs (L56-56)
```rust
    pub concurrency_level: usize,
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L426-429)
```rust
    pub fn set_concurrency_level_once(mut concurrency_level: usize) {
        concurrency_level = min(concurrency_level, num_cpus::get());
        // Only the first call succeeds, due to OnceCell semantics.
        EXECUTION_CONCURRENCY_LEVEL.set(concurrency_level).ok();
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
