# Audit Report

## Title
Consensus-Breaking Hash Divergence at RELEASE_V1_38 Boundary Due to propagate_dependency_limit_error Error Code Variation

## Summary
At the RELEASE_V1_38 version boundary, validators running different gas feature versions will produce different `TransactionInfo` hashes for transactions that exceed dependency limits, causing a consensus break. This occurs because the `propagate_dependency_limit_error` flag changes how `DEPENDENCY_LIMIT_REACHED` errors are reported, resulting in different `StatusCode` values being embedded in the hashed `ExecutionStatus`.

## Finding Description

The vulnerability stems from error code remapping behavior that changes at the v1.38 boundary.

When `gas_feature_version >= RELEASE_V1_38`, the `propagate_dependency_limit_error` flag is set to `true`: [1](#0-0) 

This flag controls error remapping in the Move VM interpreter: [2](#0-1) 

**Pre-v1.38 Behavior** (`propagate_dependency_limit_error = false`):
- Transaction exceeds dependency limit → `DEPENDENCY_LIMIT_REACHED` (1124) [3](#0-2) 
- Interpreter remaps to `VERIFICATION_ERROR` (2006) [4](#0-3) 
- `VERIFICATION_ERROR` has `StatusType::InvariantViolation` [5](#0-4) 

**Post-v1.38 Behavior** (`propagate_dependency_limit_error = true`):
- Transaction exceeds dependency limit → `DEPENDENCY_LIMIT_REACHED` (1124) - no remapping occurs
- `DEPENDENCY_LIMIT_REACHED` has `StatusType::Verification` [6](#0-5) 

The critical issue is that both error types are **kept** when `CHARGE_INVARIANT_VIOLATION` is enabled (which is in the default features): [7](#0-6) 

Verification errors are kept as MiscellaneousError: [8](#0-7) 

InvariantViolation errors are kept when CHARGE_INVARIANT_VIOLATION is enabled: [9](#0-8) 

The status code is captured in ExecutionStatus: [10](#0-9) 

This results in different `ExecutionStatus::MiscellaneousError` values: [11](#0-10) 
- Pre-v1.38: `MiscellaneousError(Some(2006))`
- Post-v1.38: `MiscellaneousError(Some(1124))`

The `ExecutionStatus` is embedded in `TransactionInfoV0`: [12](#0-11) 

The `#[derive(CryptoHasher, BCSCryptoHash)]` on TransactionInfoV0: [13](#0-12) 

This means all fields, including the `status` field with its embedded `StatusCode`, are BCS-serialized and hashed. Different status codes produce **different `TransactionInfo` hashes**, which cascade to different transaction accumulator roots and ledger info hashes.

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This vulnerability breaks the fundamental invariant that all validators must produce identical state roots for identical blocks.

When validators are split across the v1.38 boundary (some pre-upgrade, some post-upgrade) and process blocks containing transactions that exceed dependency limits:

1. Pre-v1.38 validators compute: `hash(TransactionInfo with status=MiscellaneousError(Some(2006)))`
2. Post-v1.38 validators compute: `hash(TransactionInfo with status=MiscellaneousError(Some(1124)))`
3. These produce **different hashes** for the same transaction
4. Transaction accumulator roots diverge
5. Ledger info signatures fail to match
6. **Consensus halts or chain forks**

This meets the **Critical Severity** criteria from the Aptos bug bounty program: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood** during the v1.38 rollout period:

1. **Triggering Condition**: Any transaction that loads modules exceeding either:
   - `max_num_dependencies` (768 modules)
   - `max_total_dependency_size` (1.8 MB) [14](#0-13) 

2. **Rollout Scenario**: During validator upgrades, the network inevitably has mixed versions
3. **Attack Amplification**: Malicious actors can craft transactions that deliberately exceed these limits
4. **Testing Confirms**: The codebase contains tests explicitly demonstrating this error is triggerable: [15](#0-14) 

## Recommendation

The issue requires careful coordination to fix. The recommended approach is:

1. **Immediate mitigation**: Ensure v1.38 rollout is coordinated so all validators upgrade atomically at an epoch boundary
2. **Long-term fix**: Modify the error handling to ensure deterministic status codes across versions:
   - Either always remap `DEPENDENCY_LIMIT_REACHED` to `VERIFICATION_ERROR` (keep old behavior)
   - Or never remap it (use new behavior) but require all validators be on v1.38+
3. **Prevent future occurrences**: Add consensus-critical testing that verifies hash determinism across gas feature versions for all error paths

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up two validator nodes with different gas feature versions (pre and post v1.38)
2. Submitting a transaction that exceeds dependency limits (e.g., loading >768 modules)
3. Observing that both validators keep the transaction but compute different TransactionInfo hashes
4. Verifying the transaction accumulator roots diverge

The test at: [16](#0-15) 

demonstrates that `DEPENDENCY_LIMIT_REACHED` errors are generated and kept. To reproduce the consensus break, this test would need to be extended to run with different gas feature versions and compare resulting hashes.

## Notes

This is a time-sensitive vulnerability that becomes critical during the v1.38 rollout window. Once all validators are on v1.38 or later, the immediate threat is resolved, but the underlying issue of version-dependent error handling remains a concern for future upgrades.

### Citations

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L262-262)
```rust
        propagate_dependency_limit_error: gas_feature_version >= RELEASE_V1_38,
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1568-1575)
```rust
        if err.status_type() == StatusType::Verification {
            // Make sure we propagate dependency limit errors.
            if !self.vm_config.propagate_dependency_limit_error
                || err.major_status() != StatusCode::DEPENDENCY_LIMIT_REACHED
            {
                err.set_major_status(StatusCode::VERIFICATION_ERROR);
            }
        }
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L301-301)
```rust
                    StatusType::Verification => Ok(KeptVMStatus::MiscellaneousError),
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L799-799)
```rust
    DEPENDENCY_LIMIT_REACHED = 1124,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L840-840)
```rust
    VERIFICATION_ERROR = 2006,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L989-992)
```rust
        if major_status_number >= VERIFICATION_STATUS_MIN_CODE
            && major_status_number <= VERIFICATION_STATUS_MAX_CODE
        {
            return StatusType::Verification;
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L995-998)
```rust
        if major_status_number >= INVARIANT_VIOLATION_STATUS_MIN_CODE
            && major_status_number <= INVARIANT_VIOLATION_STATUS_MAX_CODE
        {
            return StatusType::InvariantViolation;
```

**File:** types/src/on_chain_config/aptos_features.rs (L194-194)
```rust
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
```

**File:** types/src/transaction/mod.rs (L1502-1502)
```rust
    MiscellaneousError(Option<StatusCode>),
```

**File:** types/src/transaction/mod.rs (L1634-1636)
```rust
                KeptVMStatus::MiscellaneousError => {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(status_code)))
                },
```

**File:** types/src/transaction/mod.rs (L1640-1646)
```rust
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
```

**File:** types/src/transaction/mod.rs (L2023-2023)
```rust
#[derive(Clone, CryptoHasher, BCSCryptoHash, Debug, Eq, PartialEq, Serialize, Deserialize)]
```

**File:** types/src/transaction/mod.rs (L2032-2032)
```rust
    status: ExecutionStatus,
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L251-258)
```rust
            max_num_dependencies: NumModules,
            { RELEASE_V1_10.. => "max_num_dependencies" },
            768,
        ],
        [
            max_total_dependency_size: NumBytes,
            { RELEASE_V1_10.. => "max_total_dependency_size" },
            1024 * 1024 * 18 / 10, // 1.8 MB
```

**File:** aptos-move/e2e-move-tests/src/tests/dependencies.rs (L15-22)
```rust
fn assert_dependency_limit_reached(status: TransactionStatus) {
    assert!(matches!(
        status,
        TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(
            StatusCode::DEPENDENCY_LIMIT_REACHED
        )))
    ));
}
```

**File:** aptos-move/e2e-move-tests/src/tests/dependencies.rs (L28-85)
```rust
fn exceeding_max_num_dependencies_on_publish(
    enable_lazy_loading: bool,
    change_max_num_dependencies: bool,
) {
    let mut h = MoveHarness::new_with_lazy_loading(enable_lazy_loading);
    let acc = h.new_account_at(AccountAddress::from_hex_literal("0xcafe").unwrap());

    if change_max_num_dependencies {
        h.modify_gas_schedule(|gas_params| {
            gas_params.vm.txn.max_num_dependencies = 2.into();
        });
    } else {
        // Enough to cover for 2 modules combined: p1 and p2 or p2 and p3.
        h.modify_gas_schedule(|gas_params| {
            gas_params.vm.txn.max_total_dependency_size = 330.into();
        });
    }

    assert_success!(
        h.publish_package_cache_building(&acc, &common::test_dir_path("dependencies.data/p1"))
    );
    assert_success!(
        h.publish_package_cache_building(&acc, &common::test_dir_path("dependencies.data/p2"))
    );

    // Since lazy loading only checks immediate dependencies, and p3 depends on p2 only, publishing
    // should succeed.
    let res =
        h.publish_package_cache_building(&acc, &common::test_dir_path("dependencies.data/p3"));
    if enable_lazy_loading {
        assert_success!(res);
    } else {
        assert_dependency_limit_reached(res);

        // Publishing should succeed if we increase the limit.
        if change_max_num_dependencies {
            h.modify_gas_schedule(|gas_params| {
                gas_params.vm.txn.max_num_dependencies = 3.into();
            });
        } else {
            h.modify_gas_schedule(|gas_params| {
                gas_params.vm.txn.max_total_dependency_size = 1000000.into();
            });
        }

        assert_success!(
            h.publish_package_cache_building(&acc, &common::test_dir_path("dependencies.data/p3"))
        );
    }

    // Should be able to use module in both cases.
    assert_success!(h.run_entry_function(
        &acc,
        str::parse("0xcafe::m3::noop").unwrap(),
        vec![],
        vec![],
    ));
}
```
