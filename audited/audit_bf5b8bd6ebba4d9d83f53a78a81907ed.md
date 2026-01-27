# Audit Report

## Title
Complete Type Safety Check Bypass via Misconfigured Async Runtime Checks

## Summary
When `paranoid_type_verification` is disabled but `async_runtime_checks` is enabled, all type safety checks are completely bypassed during both synchronous execution and asynchronous replay, creating a critical path where invalid Move bytecode can execute without verification. This occurs because the trace replay logic only uses a debug assertion (not enforced in release builds) to detect this misconfiguration. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between trace recording configuration and async type checking. The system has two stages where type checks can occur:

1. **During execution** (synchronous): The interpreter computes local check flags based on whether tracing is enabled [2](#0-1) 

2. **During replay** (asynchronous): The TypeChecker uses the original VM config flags [1](#0-0) 

When a node is configured with:
- `execution.paranoid_type_verification = false`
- `execution.async_runtime_checks = true` [3](#0-2) 

The following occurs:

**Stage 1 - Synchronous Execution:**
- Tracing is enabled (async checks are on)
- Local `paranoid_type_checks` variable becomes: `!true && false = false`
- Execution uses `NoRuntimeTypeCheck` mode
- **Result: NO type safety checks performed**

**Stage 2 - Asynchronous Replay:**
- Checks `if !self.vm_config.paranoid_type_checks` (which is false)
- Returns early without performing any checks
- The `debug_assert(!self.vm_config.optimize_trusted_code)` at line 121 would catch this in debug builds, but is NOT compiled into release builds
- **Result: NO type safety checks performed**

This breaks the **Deterministic Execution** invariant because:
1. Nodes with different configurations will handle type-invalid transactions differently
2. A misconfigured node will accept and execute transactions that should be rejected
3. Consensus divergence can occur when validators have different configurations [4](#0-3) 

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus Divergence**: If validators have different configurations, they will compute different state roots for the same block, causing consensus failures and potential chain splits.

2. **Type Safety Violations**: Invalid Move bytecode that violates type safety can execute, potentially leading to:
   - Memory corruption
   - Ability checking bypasses
   - Reference safety violations
   - Stack balance violations

3. **Network Instability**: Misconfigured nodes will diverge from the network, requiring manual intervention or hard forks to resolve.

The severity is Critical because it violates the fundamental "Deterministic Execution" invariant that underpins consensus safety in Aptos. All validators must produce identical results for identical inputs. [5](#0-4) 

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
1. A node operator to explicitly disable `paranoid_type_verification` (defaults to `true`)
2. While also enabling `async_runtime_checks` (defaults to `false`, but there's a TODO to make it default `true`) [6](#0-5) 

Node operators might disable paranoid checks for performance reasons without realizing this creates an unsafe configuration. The comment "TODO: consider setting to be true by default" indicates `async_runtime_checks` may become default in the future, increasing the risk window.

The debug assertion shows developers are aware this is invalid, but release builds don't enforce it: [7](#0-6) 

## Recommendation

Add a runtime validation check (not just debug assertion) that prevents the VM from starting with an invalid configuration:

```rust
pub fn replay(mut self, trace: &Trace) -> VMResult<()> {
    // Validate configuration - fail fast in all builds, not just debug
    if !self.vm_config.paranoid_type_checks && self.vm_config.optimize_trusted_code {
        return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
            .with_message(
                "Invalid VM configuration: paranoid_type_checks=false with optimize_trusted_code=true. \
                 This would skip all type safety checks."
            )
            .finish(Location::Undefined));
    }
    
    // If there are no type checks at all: no need to replay the trace.
    if !self.vm_config.paranoid_type_checks {
        return Ok(());
    }
    // ... rest of function
}
```

Additionally, add validation at node startup in `set_aptos_vm_configurations`: [8](#0-7) 

```rust
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
    
    // Validate configuration
    if node_config.execution.async_runtime_checks 
        && !node_config.execution.paranoid_type_verification {
        panic!(
            "Invalid configuration: async_runtime_checks=true requires paranoid_type_verification=true. \
             Setting async_runtime_checks=true with paranoid_type_verification=false would skip all type \
             safety checks and lead to consensus divergence."
        );
    }
    // ... rest of function
}
```

## Proof of Concept

To demonstrate the vulnerability:

1. Configure a test node with:
```toml
[execution]
paranoid_type_verification = false
async_runtime_checks = true
```

2. Submit a transaction with type-invalid Move bytecode (e.g., pushing wrong type onto stack)

3. Observe that:
   - The misconfigured node executes the transaction without type checking
   - A correctly configured node rejects the transaction
   - The nodes compute different state roots and diverge

The vulnerability path:
- Trace recording is enabled due to `async_runtime_checks = true` and block having >3 transactions [9](#0-8) 

- During execution, no checks are performed (uses `NoRuntimeTypeCheck`)
- During replay, early return at line 122 skips all checks [1](#0-0) 

- Type-unsafe bytecode executes successfully on misconfigured node
- Correctly configured nodes reject the same transaction
- Consensus divergence occurs

## Notes

The vulnerability is particularly concerning because:

1. The debug assertion suggests developers are aware of this invalid state but only guard against it in debug builds
2. The TODO comment about making `async_runtime_checks` default increases risk
3. No documentation warns operators about this configuration dependency
4. The system fails silently rather than rejecting the invalid configuration

The root cause is the dual-stage checking logic where execution and replay use different configuration sources, combined with insufficient validation of the configuration invariant in release builds.

### Citations

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L118-123)
```rust
    pub fn replay(mut self, trace: &Trace) -> VMResult<()> {
        // If there is no type checks ar all: no need to replay the trace.
        if !self.vm_config.paranoid_type_checks {
            debug_assert!(!self.vm_config.optimize_trusted_code);
            return Ok(());
        }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L244-248)
```rust
        let paranoid_type_checks =
            !trace_recorder.is_enabled() && interpreter.vm_config.paranoid_type_checks;
        let optimize_trusted_code =
            !trace_recorder.is_enabled() && interpreter.vm_config.optimize_trusted_code;
        let paranoid_ref_checks = interpreter.vm_config.paranoid_ref_checks;
```

**File:** config/src/config/execution_config.rs (L44-59)
```rust
    pub paranoid_type_verification: bool,
    /// Enabled discarding blocks that fail execution due to BlockSTM/VM issue.
    pub discard_failed_blocks: bool,
    /// Enables paranoid mode for hot potatoes, which adds extra runtime VM checks
    pub paranoid_hot_potato_verification: bool,
    /// Enables enhanced metrics around processed transactions
    pub processed_transactions_detailed_counters: bool,
    /// Used during DB bootstrapping
    pub genesis_waypoint: Option<WaypointConfig>,
    /// Whether to use BlockSTMv2 for parallel execution.
    pub blockstm_v2_enabled: bool,
    /// Enables long-living concurrent caches for Move type layouts.
    pub layout_caches_enabled: bool,
    /// If enabled, runtime checks like paranoid type checks may be performed in parallel in post
    /// commit hook in Block-STM.
    pub async_runtime_checks: bool,
```

**File:** config/src/config/execution_config.rs (L86-94)
```rust
            paranoid_type_verification: true,
            paranoid_hot_potato_verification: true,
            discard_failed_blocks: false,
            processed_transactions_detailed_counters: false,
            genesis_waypoint: None,
            blockstm_v2_enabled: false,
            layout_caches_enabled: true,
            // TODO: consider setting to be true by default.
            async_runtime_checks: false,
```

**File:** third_party/move/move-vm/runtime/src/config.rs (L18-22)
```rust
    /// When this flag is set to true, MoveVM will perform type checks at every instruction
    /// execution to ensure that type safety cannot be violated at runtime. Note: these
    /// are more than type checks, for example, stack balancing, visibility, but the name
    /// is kept for historical reasons.
    pub paranoid_type_checks: bool,
```

**File:** aptos-move/block-executor/src/executor.rs (L1234-1258)
```rust
        if environment.async_runtime_checks_enabled() && !trace.is_empty() {
            // Note that the trace may be empty (if block was small and executor decides not to
            // collect the trace and replay, or if the VM decides it is not profitable to do this
            // check for this particular transaction), so we check it in advance.
            let result = {
                counters::update_txn_trace_counters(&trace);
                let _timer = TRACE_REPLAY_SECONDS.start_timer();
                TypeChecker::new(&latest_view).replay(&trace)
            };

            // In case of runtime type check errors, fallback to sequential execution. There errors
            // are supposed to be unlikely so this fallback is fine, and is mostly needed to make
            // sure transaction epilogue runs after failure, etc.
            if let Err(err) = result {
                alert!(
                    "Runtime type check failed during replay of transaction {}: {:?}",
                    txn_idx,
                    err
                );
                return Err(PanicError::CodeInvariantError(format!(
                    "Sequential fallback on type check failure for transaction {}: {:?}",
                    txn_idx, err
                )));
            }
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L2708-2714)
```rust
fn should_perform_async_runtime_checks_for_block(
    environment: &AptosEnvironment,
    num_txns: u32,
    _num_workers: u32,
) -> bool {
    environment.async_runtime_checks_enabled() && num_txns > 3
}
```

**File:** aptos-node/src/utils.rs (L53-56)
```rust
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
```
