# Audit Report

## Title
Configuration Sanitizer Bypass Enables Consensus Divergence Through Disabled Paranoid Type Checks

## Summary
A malicious validator can bypass all configuration security checks by setting `skip_config_sanitizer: true` in their node startup configuration, allowing them to disable critical VM safety features like paranoid type verification. This leads to deterministic execution failures where different validators produce different state roots for identical blocks, causing consensus divergence and potential chain splits.

## Finding Description

The configuration sanitizer in Aptos validates that all validators run with secure settings, particularly enforcing that mainnet validators enable paranoid type and hot potato verification. However, this entire sanitization process can be completely bypassed. [1](#0-0) 

When a validator sets `skip_config_sanitizer: true` in their `NodeStartupConfig`, the sanitizer returns immediately without performing any validation checks. This bypass allows disabling critical execution safety features. [2](#0-1) 

The execution config sanitizer normally requires `paranoid_hot_potato_verification` and `paranoid_type_verification` to be enabled for mainnet nodes. These checks ensure deterministic execution across all validators. When bypassed, a validator can disable these flags. [3](#0-2) 

The disabled `paranoid_type_verification` flag is propagated to the global VM configuration, causing the Move VM to use `NoRuntimeTypeCheck` instead of `FullRuntimeTypeCheck`. [4](#0-3) 

The `FullRuntimeTypeCheck` implementation enforces critical invariants including function visibility (preventing cross-module calls to private functions), type safety checks, and ability constraints. It returns `EPARANOID_FAILURE` errors when these invariants are violated. [5](#0-4) 

In contrast, `NoRuntimeTypeCheck` performs zero validation, always returning `Ok(())`. This fundamental difference causes execution divergence.

**Attack Scenario:**
1. Attacker becomes a validator through permissionless staking (via `stake.move`)
2. Attacker configures their validator node with:
   ```yaml
   node_startup:
     skip_config_sanitizer: true
   execution:
     paranoid_type_verification: false
   ```
3. Node starts successfully, bypassing all safety validations
4. A transaction containing bytecode that violates type safety or visibility rules is executed
5. Honest validators (with paranoid checks enabled): Transaction aborts with `EPARANOID_FAILURE`
6. Malicious validator (with paranoid checks disabled): Transaction succeeds or fails differently
7. Different execution outcomes produce different state roots
8. Consensus cannot reach agreement on the block's state → chain split [6](#0-5) 

The VM explicitly logs paranoid failures as critical errors because they indicate determinism violations.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos bug bounty)

This vulnerability directly violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

**Impact Category: Consensus/Safety Violations**
- Different validators execute transactions with different safety checks enabled
- Transactions that should fail on all validators succeed on the malicious validator
- State root divergence prevents consensus agreement
- Results in non-recoverable network partition requiring manual intervention or hardfork

**Affected Systems:**
- All validators participating in consensus
- Entire network state consistency
- Block finalization and commitment
- State synchronization for new nodes

This breaks the fundamental security guarantee of blockchain consensus: that all honest validators agree on the canonical state. A single malicious validator with bypassed configuration checks can cause the entire network to halt or fork.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Sufficient stake to become a validator (permissionless operation via `stake.move`)
- Control over their own validator node's configuration file
- Basic knowledge of YAML configuration format

**No Special Prerequisites:**
- No need for code execution exploits
- No need for validator collusion
- No need for special permissions beyond standard validator onboarding
- Configuration files are operator-controlled by design

**Ease of Exploitation:**
- Simple two-line configuration change
- No complex timing requirements
- No need to craft malicious bytecode (can exploit naturally occurring verifier bugs)
- Detection is difficult since configuration is not publicly visible

**Realistic Scenario:**
Even without malicious intent, a validator operator might disable paranoid checks for "performance optimization" without understanding the security implications. The lack of on-chain validation of off-chain configuration creates a trust assumption that can be violated.

## Recommendation

**Primary Fix: Remove the skip_config_sanitizer option entirely**

The ability to bypass configuration sanitization should not exist in production code. Remove the early return: [1](#0-0) 

Delete these lines and make sanitization mandatory for all node types.

**Secondary Fix: Runtime consensus verification**

Add runtime validation that all validators are using compatible execution configurations. During block execution, include configuration attestations:

1. Validators should commit to their execution config hash during epoch changes
2. Consensus should verify all validators have compatible configurations
3. Reject blocks from validators with incompatible configurations

**Tertiary Fix: Make critical safety flags immutable**

For mainnet deployments, hardcode critical flags like `paranoid_type_verification` to `true` using conditional compilation:

```rust
pub fn get_paranoid_type_checks() -> bool {
    #[cfg(feature = "mainnet")]
    return true; // Immutable for mainnet
    
    #[cfg(not(feature = "mainnet"))]
    PARANOID_TYPE_CHECKS.load(Ordering::Relaxed)
}
```

## Proof of Concept

**Setup Phase:**
1. Deploy two validator nodes: one honest, one malicious
2. Malicious validator config (`validator_malicious.yaml`):
```yaml
node_startup:
  skip_config_sanitizer: true
execution:
  paranoid_type_verification: false
  paranoid_hot_potato_verification: false
```

3. Honest validator config (`validator_honest.yaml`): uses default settings with sanitization enabled

**Exploitation Phase:**

Deploy a Move module with a private function:
```move
module 0xBAD::Private {
    fun private_function(): u64 { 42 }
}
```

Deploy a transaction that attempts to call the private function from another module:
```move
script {
    use 0xBAD::Private;
    fun main() {
        // This cross-module call to a private function should fail
        Private::private_function();
    }
}
```

**Expected Result:**
- Honest validator: Transaction aborts with `UNKNOWN_INVARIANT_VIOLATION_ERROR` (sub-status: `EPARANOID_FAILURE`)
- Malicious validator: Transaction succeeds (visibility check bypassed)
- State roots diverge
- Consensus fails to reach agreement
- Network halts or splits

**Verification:**
Monitor validator logs for the distinctive error message: [7](#0-6) 

The honest validator will log: `[aptos_vm] Transaction breaking paranoid mode`

The malicious validator will not log this error and will produce a different state root.

## Notes

This vulnerability is particularly severe because:

1. **Silent failure**: The misconfiguration produces no warnings until actual consensus divergence occurs
2. **Cascading impact**: Even one malicious validator can halt the entire network
3. **Difficult detection**: Configuration files are private to each operator
4. **No on-chain enforcement**: The staking system cannot prevent this attack
5. **Permanent damage**: Chain splits may require hardforks to resolve

The root cause is the fundamental design flaw of allowing operators to opt-out of critical security validations through a simple configuration flag.

### Citations

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
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

**File:** aptos-node/src/utils.rs (L53-56)
```rust
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L247-252)
```rust
    fn check_cross_module_regular_call_visibility(
        _caller: &LoadedFunction,
        _callee: &LoadedFunction,
    ) -> PartialVMResult<()> {
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L946-981)
```rust
        caller: &LoadedFunction,
        callee: &LoadedFunction,
    ) -> PartialVMResult<()> {
        if callee.is_private() {
            let msg = format!(
                "Function {}::{} cannot be called because it is private",
                callee.module_or_script_id(),
                callee.name()
            );
            return Err(
                PartialVMError::new_invariant_violation(msg).with_sub_status(EPARANOID_FAILURE)
            );
        }

        if callee.is_friend() {
            let callee_module = callee.owner_as_module().map_err(|err| err.to_partial())?;
            if !caller
                .module_id()
                .is_some_and(|id| callee_module.friends.contains(id))
            {
                let msg = format!(
                    "Function {}::{} cannot be called because it has friend visibility, but {} \
                     is not {}'s friend",
                    callee.module_or_script_id(),
                    callee.name(),
                    caller.module_or_script_id(),
                    callee.module_or_script_id()
                );
                return Err(
                    PartialVMError::new_invariant_violation(msg).with_sub_status(EPARANOID_FAILURE)
                );
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2946-2957)
```rust
                        // Paranoid mode failure. We need to be alerted about this ASAP.
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(unknown_invariant_violation::EPARANOID_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode: {:?}\ntxn: {:?}",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                            },
```
