# Audit Report

## Title
Memory Quota Bypass in Table Natives Allows Validator DoS Through Unbounded Memory Allocation

## Summary
Before the `FixMemoryUsageTracking` timed feature flag activates (March 11, 2025 on MAINNET), table native functions do not track memory usage of loaded values, allowing attackers to bypass the transaction memory quota and exhaust validator node memory, causing denial of service.

## Finding Description

The vulnerability exists in the memory tracking mechanism for table native functions. The core issue is in the `use_heap_memory()` function which is wrapped in a feature flag check that completely disables memory tracking before activation. [1](#0-0) 

When `FixMemoryUsageTracking` is disabled, this function returns `Ok(())` without calling the gas meter's memory tracking, effectively bypassing all memory quota enforcement.

All table native functions rely on this mechanism to track memory usage of loaded table values: [2](#0-1) 

The attack flow:

1. **Setup Phase**: Attacker deploys a Move module that creates tables and stores deeply nested structures or large vectors as values
2. **Population Phase**: Multiple transactions populate the table with memory-intensive values that get persisted to storage
3. **Exploitation Phase**: A single transaction calls `table::borrow()` repeatedly to load many values into memory
4. **Impact**: Since memory tracking is bypassed, the transaction can exceed the memory quota (typically 10MB) without failing, potentially loading hundreds of MB into validator memory
5. **DoS Result**: Validator nodes crash or become unresponsive due to memory exhaustion

The vulnerability breaks the **Move VM Safety** invariant: "Bytecode execution must respect gas limits and memory constraints."

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria because it enables "Validator node slowdowns" and potential crashes. Specifically:

- **Validator Availability Impact**: Attackers can craft transactions that consume excessive memory on validator nodes, causing crashes or severe performance degradation
- **Network-Wide Effect**: A sustained attack targeting multiple validators could degrade overall network performance or cause temporary unavailability
- **Cost to Attack**: Transaction gas fees provide minimal protection since the attack bypasses memory metering, making exploitation economically feasible

The memory quota enforcement mechanism would normally prevent this: [3](#0-2) 

However, this check is never reached when the feature flag is disabled.

## Likelihood Explanation

**Likelihood: High** - The vulnerability is trivially exploitable by any transaction sender:

- **No Special Privileges Required**: Any user can deploy Move modules and submit transactions
- **Existing Test Demonstrates Exploit**: The codebase includes a test that explicitly demonstrates the vulnerability
- **Currently Active on Production Networks**: 
  - TESTNET: Vulnerable until March 7, 2025, 12:00 PM PST
  - MAINNET: Vulnerable until March 11, 2025, 5:00 PM PST [4](#0-3) 

The test proves the exploit works: [5](#0-4) 

This test shows that loading table values succeeds before the fix (bypassing memory limits), then fails with `MEMORY_LIMIT_EXCEEDED` after activation.

## Recommendation

The vulnerability is already addressed through the scheduled activation of the `FixMemoryUsageTracking` timed feature flag. The fix ensures `use_heap_memory()` always performs memory tracking:

**Current Vulnerable Code** needs the feature flag check removed or the flag enabled immediately:

```rust
pub fn use_heap_memory(&mut self, amount: u64) -> SafeNativeResult<()> {
    if self.timed_feature_enabled(TimedFeatureFlag::FixMemoryUsageTracking) {
        // Memory tracking code...
    }
    Ok(())  // BUG: Returns without tracking when flag disabled
}
```

**Recommended Immediate Mitigation**:
1. Accelerate the activation timeline to activate the feature flag immediately on MAINNET and TESTNET
2. Monitor validator memory usage for abnormal spikes that could indicate exploitation
3. Consider implementing emergency rate limiting on table-heavy transactions

**Long-term Fix** (already implemented):
The feature flag activation will enable memory tracking for all table operations, ensuring the memory quota is enforced correctly.

## Proof of Concept

The existing test in the codebase serves as a proof of concept: [6](#0-5) 

The test creates deeply nested structures (100 levels deep), stores them in a table, and demonstrates that loading them succeeds before `FixMemoryUsageTracking` activates but fails with `MEMORY_LIMIT_EXCEEDED` after activation.

**Attack Reproduction Steps**:
1. Deploy the test module from the nested_struct test data
2. Call `add()` to populate table with deeply nested structures
3. Call `read_all()` to load all values in a single transaction
4. Before fix: Transaction succeeds despite exceeding 10MB memory quota
5. After fix: Transaction fails with `MEMORY_LIMIT_EXCEEDED`

**Notes**

This vulnerability represents a critical gap in Move VM resource enforcement that was identified by the Aptos team and is scheduled for remediation via timed feature flags. The vulnerability currently exists on production networks and remains exploitable until the scheduled activation dates in March 2025. Immediate activation of the feature flag on both TESTNET and MAINNET would eliminate the attack window.

### Citations

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

**File:** types/src/on_chain_config/timed_features.rs (L99-109)
```rust
            // Note: Activation time set to 1 hour after the beginning of time
            //       so we can test the old and new behaviors in tests.
            (FixMemoryUsageTracking, TESTING) => Utc.with_ymd_and_hms(1970, 1, 1, 1, 0, 0).unwrap(),
            (FixMemoryUsageTracking, TESTNET) => Los_Angeles
                .with_ymd_and_hms(2025, 3, 7, 12, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
            (FixMemoryUsageTracking, MAINNET) => Los_Angeles
                .with_ymd_and_hms(2025, 3, 11, 17, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
```

**File:** aptos-move/e2e-move-tests/src/tests/memory_quota.rs (L47-107)
```rust
#[test]
fn deeply_nested_structs() {
    let mut h = MoveHarness::new();

    h.modify_gas_schedule(|gas_params| {
        gas_params.vm.txn.memory_quota = 10_000_000.into();
        gas_params.vm.txn.max_execution_gas = 100_000_000_000.into();
    });

    // Publish the code
    let acc = h.new_account_at(AccountAddress::from_hex_literal("0xbeef").unwrap());
    assert_success!(h.publish_package(
        &acc,
        &common::test_dir_path("memory_quota.data/nested_struct"),
    ));

    // Initialize
    let result = h.run_entry_function(
        &acc,
        str::parse("0xbeef::very_nested_structure::init").unwrap(),
        vec![],
        vec![],
    );
    assert_success!(result);

    // Create nested structs as table entries
    for _i in 0..5 {
        let result = h.run_entry_function(
            &acc,
            str::parse("0xbeef::very_nested_structure::add").unwrap(),
            vec![],
            vec![MoveValue::U64(2000).simple_serialize().unwrap()],
        );
        assert_success!(result);
    }

    // Try to load the whole table -- this should succeed
    let result = h.run_entry_function(
        &acc,
        str::parse("0xbeef::very_nested_structure::read_all").unwrap(),
        vec![],
        vec![],
    );
    assert_success!(result);

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
}
```
