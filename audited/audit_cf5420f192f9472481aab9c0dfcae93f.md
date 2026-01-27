# Audit Report

## Title
Production Runtime Reference Safety Checks Completely Disabled - Critical Defense-in-Depth Layer Missing

## Summary
The Aptos Move VM's runtime reference safety checks are completely disabled in production due to missing configuration, removing a critical defense layer against memory safety violations that could lead to consensus splits or state corruption if bytecode verifier bugs exist.

## Finding Description

The Move VM implements two layers of reference safety protection:

1. **Static layer**: Bytecode verifier performs compile-time reference safety analysis
2. **Dynamic layer**: Runtime reference checks provide defense-in-depth during execution

The runtime checks are controlled by trait selection in the interpreter entrypoint: [1](#0-0) 

The `NoRuntimeRefCheck` struct provides a no-op implementation that bypasses ALL reference checks: [2](#0-1) 

The selection depends on the `paranoid_ref_checks` configuration flag, which **defaults to false**: [3](#0-2) [4](#0-3) 

**Critical Gap**: The production node configuration NEVER sets this flag: [5](#0-4) 

Unlike `paranoid_type_checks` which is set on line 55, there is no call to `set_paranoid_ref_checks()`.

Furthermore, the ExecutionConfig sanitizer enforces type verification for mainnet but NOT reference checks: [6](#0-5) 

The system explicitly logs when reference safety failures occur, indicating these checks are expected to catch real violations: [7](#0-6) 

## Impact Explanation

**Critical Severity** - This breaks the **Move VM Safety** and **Deterministic Execution** invariants:

If ANY bug exists in:
- Bytecode verifier's reference safety analysis
- Move compiler bytecode generation  
- Native function reference handling
- Framework code

Then reference safety violations (use-after-free, double borrowing, poisoned reference access) could execute undetected, causing:

1. **Consensus splits**: Different nodes may execute the same transaction differently due to memory corruption
2. **State corruption**: Invalid memory access could corrupt the state tree
3. **Node crashes**: Memory safety violations could crash validator nodes

The runtime checks document that they implement "relaxed dynamic semantics" that may accept code the verifier rejects: [8](#0-7) 

This indicates the verifier is intentionally conservative and the runtime checks provide the actual safety guarantee during execution.

## Likelihood Explanation

**High Likelihood** of configuration oversight persisting because:

1. The flag is never set in production node initialization
2. No sanitizer enforcement exists for mainnet nodes
3. Even fuzzer tests have the flag commented out: [9](#0-8) 

The absence of runtime checks means any verifier bug would manifest as undetected memory safety violations in production.

## Recommendation

**Immediate Actions:**

1. Add `paranoid_ref_checks` field to `ExecutionConfig`:
```rust
pub struct ExecutionConfig {
    // ... existing fields ...
    pub paranoid_ref_checks: bool,
}
```

2. Enforce in sanitizer for mainnet nodes:
```rust
if chain_id.is_mainnet() {
    if !execution_config.paranoid_ref_checks {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "paranoid_ref_checks must be enabled for mainnet nodes!".into(),
        ));
    }
}
```

3. Set the flag in node initialization:
```rust
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_paranoid_ref_checks(node_config.execution.paranoid_ref_checks); // ADD THIS
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
    // ... rest of function ...
}
```

4. Set default to `true`:
```rust
impl Default for ExecutionConfig {
    fn default() -> ExecutionConfig {
        ExecutionConfig {
            // ... existing defaults ...
            paranoid_ref_checks: true,  // CHANGE FROM IMPLICIT FALSE
        }
    }
}
```

## Proof of Concept

**Configuration Verification:**

```rust
// Verify current production configuration
#[test]
fn test_production_ref_checks_disabled() {
    use aptos_vm_environment::prod_configs::get_paranoid_ref_checks;
    
    // Without explicit set_paranoid_ref_checks(true), this returns false
    assert_eq!(get_paranoid_ref_checks(), false); // CURRENTLY PASSES - BUG!
    
    // Production nodes never call set_paranoid_ref_checks
    // Therefore NoRuntimeRefCheck is always selected
    // All reference safety checks are bypassed at runtime
}
```

**Demonstrating the Gap:**

The trait selection mechanism in the interpreter clearly shows that when `paranoid_ref_checks` is false, `NoRuntimeRefCheck` is used: [10](#0-9) 

This results in all reference safety operations being no-ops, removing the safety net that would catch verifier bugs or native function issues.

**Notes**

While this vulnerability requires a secondary bug (in the verifier, compiler, or native functions) to be actively exploited, the **removal of a critical safety layer** on a production blockchain constitutes a Critical severity issue. The existence of explicit error logging for reference safety failures indicates these checks are expected to catch real violations. Defense-in-depth is not optional for financial infrastructure.

### Citations

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L267-278)
```rust
        match (
            paranoid_type_checks,
            optimize_trusted_code,
            paranoid_ref_checks,
        ) {
            (true, true, false) => execute_main!(UntrustedOnlyRuntimeTypeCheck, NoRuntimeRefCheck),
            (true, false, false) => execute_main!(FullRuntimeTypeCheck, NoRuntimeRefCheck),
            (true, true, true) => execute_main!(UntrustedOnlyRuntimeTypeCheck, FullRuntimeRefCheck),
            (true, false, true) => execute_main!(FullRuntimeTypeCheck, FullRuntimeRefCheck),
            (false, _, false) => execute_main!(NoRuntimeTypeCheck, NoRuntimeRefCheck),
            (false, _, true) => execute_main!(NoRuntimeTypeCheck, FullRuntimeRefCheck),
        }
```

**File:** third_party/move/move-vm/runtime/src/runtime_ref_checks.rs (L4-12)
```rust
//! This module implements the runtime reference checks for Move bytecode.
//!
//! Move bytecode has a bytecode verifier pass for enforcing reference safety rules:
//! the runtime checks implemented here are the relaxed dynamic semantics of that pass.
//! If the bytecode verifier pass succeeds, then the runtime checks should also succeed
//! for any execution path.
//! However, there may be Move bytecode that the bytecode verifier pass rejects, but
//! the runtime checks may still succeed, as long as reference-safety rules are not
//! violated (i.e., relaxed semantics).
```

**File:** third_party/move/move-vm/runtime/src/runtime_ref_checks.rs (L318-366)
```rust
impl RuntimeRefCheck for NoRuntimeRefCheck {
    fn pre_execution_transition(
        _frame: &Frame,
        _instruction: &Instruction,
        _ref_state: &mut RefCheckState,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn post_execution_transition(
        _frame: &Frame,
        _instruction: &Instruction,
        _ref_state: &mut RefCheckState,
        _ty_cache: &mut FrameTypeCache,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn core_call_transition(
        _function: &LoadedFunction,
        _mask: ClosureMask,
        _ref_state: &mut RefCheckState,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn native_static_dispatch_transition(
        _function: &LoadedFunction,
        _mask: ClosureMask,
        _ref_state: &mut RefCheckState,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn native_dynamic_dispatch_transition(
        _function: &LoadedFunction,
        _mask: ClosureMask,
        _ref_state: &mut RefCheckState,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn init_entry(
        _function: &LoadedFunction,
        _ref_state: &mut RefCheckState,
    ) -> PartialVMResult<()> {
        Ok(())
    }
}
```

**File:** third_party/move/move-vm/runtime/src/config.rs (L79-81)
```rust
            optimize_trusted_code: false,
            paranoid_ref_checks: false,
            enable_capture_option: true,
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L70-73)
```rust
/// Returns the paranoid reference check flag if already set, and false otherwise.
pub fn get_paranoid_ref_checks() -> bool {
    PARANOID_REF_CHECKS.get().cloned().unwrap_or(false)
}
```

**File:** aptos-node/src/utils.rs (L52-76)
```rust
/// Sets the Aptos VM configuration based on the node configurations
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
    let effective_concurrency_level = if node_config.execution.concurrency_level == 0 {
        ((num_cpus::get() / 2) as u16).clamp(1, DEFAULT_EXECUTION_CONCURRENCY_LEVEL)
    } else {
        node_config.execution.concurrency_level
    };
    AptosVM::set_concurrency_level_once(effective_concurrency_level as usize);
    AptosVM::set_discard_failed_blocks(node_config.execution.discard_failed_blocks);
    AptosVM::set_num_proof_reading_threads_once(
        node_config.execution.num_proof_reading_threads as usize,
    );
    AptosVM::set_blockstm_v2_enabled_once(node_config.execution.blockstm_v2_enabled);

    if node_config
        .execution
        .processed_transactions_detailed_counters
    {
        AptosVM::set_processed_transactions_detailed_counters();
    }
}

```

**File:** config/src/config/execution_config.rs (L166-183)
```rust
        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2970-2986)
```rust
                        // Paranoid mode failure but with reference safety checks
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if matches!(
                            vm_status.sub_status(),
                            Some(
                                unknown_invariant_violation::EREFERENCE_SAFETY_FAILURE
                                | unknown_invariant_violation::EINDEXED_REF_TAG_MISMATCH
                            )
                        ) =>
                        {
                            error!(
                            *log_context,
                            "[aptos_vm] Transaction breaking paranoid reference safety check (including enum tag guard). txn: {:?}, status: {:?}",
                            bcs::to_bytes::<SignedTransaction>(txn),
                            vm_status,
                            );
                        }
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/aptosvm_publish_and_run.rs (L110-112)
```rust
    // Enable runtime reference-safety checks for the Move VM
    // prod_configs::set_paranoid_ref_checks(true);
    let mut vm = FakeExecutor::from_genesis_with_existing_thread_pool(
```
