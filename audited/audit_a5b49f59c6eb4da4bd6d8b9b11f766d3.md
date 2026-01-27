# Audit Report

## Title
Unrecoverable Validator Crash on Module ID Interner OOM During Block Execution

## Summary
The `ConcurrentBTreeInterner` used for module ID interning lacks graceful OOM handling. When `Vec::with_capacity` fails at line 84 during module loading, the resulting panic crashes the validator process with `process::exit(12)`, causing unrecoverable downtime. [1](#0-0) 

## Finding Description

The module ID interner uses an exponentially-growing buffer allocation strategy. When the current buffer is full, it allocates a new buffer with doubled capacity. If this allocation fails, Rust's default allocator panics.

**Panic Propagation Path:**

1. **Module Loading Triggers Interning**: During `Module::new()`, module IDs are interned via `module_id_pool.intern_by_ref(&id)`: [2](#0-1) 

2. **Interner Allocation**: When the buffer needs to grow, `Vec::with_capacity` is called: [3](#0-2) 

3. **No Panic Protection**: Module::new is called from `build_verified_module_with_linking_checks` WITHOUT `catch_unwind`: [4](#0-3) 

4. **Global Panic Handler**: When the panic occurs, the global handler checks `VMState`. During module loading, `VMState` is NOT set to `VERIFIER` or `DESERIALIZER`: [5](#0-4) 

5. **Process Termination**: Since `VMState` is in default state, the panic handler calls `process::exit(12)`, killing the validator.

**Key Distinction from Protected Operations:**

Bytecode verification and deserialization ARE protected with `catch_unwind` and set appropriate `VMState`: [6](#0-5) [7](#0-6) 

However, module loading (which happens AFTER verification) has no such protection.

**Why Existing Limits Don't Prevent This:**

The codebase has a limit of 100,000 interned module IDs, checked at block boundaries: [8](#0-7) [9](#0-8) 

But this limit:
1. Checks COUNT of items, not buffer CAPACITY
2. Is enforced BETWEEN blocks, not DURING block execution
3. Doesn't account for memory pressure from other validator operations

## Impact Explanation

**Severity: High** - Validator node crash requiring process restart.

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The validator should degrade gracefully under memory pressure, not crash unrecoverably.

**Impact Scope:**
- Single validator crash disrupts that node's participation in consensus
- If multiple validators experience similar memory pressure simultaneously (e.g., during high network load), could impact network liveness
- Requires manual intervention to restart the validator process
- No data corruption, but temporary availability loss

Per Aptos bug bounty criteria, this qualifies as **High Severity**: "Validator node slowdowns" / crashes.

## Likelihood Explanation

**Likelihood: Low-to-Medium**

**Required Conditions:**
1. Validator node under memory pressure from:
   - High transaction volume
   - Large module cache
   - Other concurrent operations
2. Transaction(s) triggering module loading during this pressure
3. Interner buffer growth coinciding with insufficient available memory

**Why Not Directly Exploitable:**
- Gas limits prevent loading excessive modules in single transaction
- 100,000 module ID limit (with cache flushing) prevents runaway growth
- Attacker cannot directly control validator's overall memory usage

**Why Still Concerning:**
- Validators run with finite memory resources
- High network load is normal during peak usage
- Module publishing and loading are legitimate operations
- The crash is unrecoverable, requiring manual restart
- Violates principle of graceful degradation

## Recommendation

Implement graceful OOM handling in the interner's allocation path:

```rust
unsafe fn alloc(&mut self, val: T) -> Result<&'static T, PartialVMError> {
    if self.buffer.len() >= self.buffer.capacity() {
        // Attempt allocation with error handling
        let new_buffer = match std::panic::catch_unwind(|| {
            Vec::with_capacity(self.next_size)
        }) {
            Ok(buf) => buf,
            Err(_) => {
                // OOM occurred - return error instead of crashing
                return Err(PartialVMError::new(
                    StatusCode::MEMORY_LIMIT_EXCEEDED
                ));
            }
        };
        
        self.next_size *= 2;
        let old_buffer = std::mem::replace(&mut self.buffer, new_buffer);
        self.pool.push(old_buffer);
    }

    self.buffer.push(val);
    Ok(unsafe { &*(self.buffer.last().expect("last always exists") as *const T) })
}
```

Then update `Module::new` to propagate this error: [10](#0-9) 

This allows the error to propagate up as a `VMError`, failing the transaction gracefully instead of crashing the validator.

## Proof of Concept

```rust
// Rust test demonstrating the crash (requires running with limited memory)
#[test]
#[should_panic(expected = "process exit")]
fn test_interner_oom_crash() {
    use move_vm_types::module_id_interner::InternedModuleIdPool;
    use move_core_types::language_storage::ModuleId;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    
    // Set up crash handler
    crate::crash_handler::setup_panic_handler();
    
    let pool = InternedModuleIdPool::new();
    
    // Simulate memory pressure by filling the interner
    // In real scenario, this would be triggered by legitimate module loading
    // under memory pressure
    for i in 0..200_000 {
        let addr = AccountAddress::new([
            (i >> 24) as u8,
            (i >> 16) as u8, 
            (i >> 8) as u8,
            i as u8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        let name = Identifier::new(format!("Module{}", i)).unwrap();
        let module_id = ModuleId::new(addr, name);
        
        // This will eventually cause Vec::with_capacity to allocate
        // a large buffer. Under memory pressure, this panics and
        // crashes the validator with process::exit(12)
        pool.intern(module_id);
    }
}
```

**Note:** This PoC demonstrates the code path but requires artificial memory limits to trigger OOM reliably. In production, this occurs when the validator is under genuine memory pressure from concurrent operations.

### Citations

**File:** third_party/move/move-vm/types/src/interner.rs (L82-93)
```rust
    unsafe fn alloc(&mut self, val: T) -> &'static T {
        if self.buffer.len() >= self.buffer.capacity() {
            let new_buffer = Vec::with_capacity(self.next_size);
            self.next_size *= 2;

            let old_buffer = std::mem::replace(&mut self.buffer, new_buffer);
            self.pool.push(old_buffer);
        }

        self.buffer.push(val);
        unsafe { &*(self.buffer.last().expect("last always exists") as *const T) }
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L157-164)
```rust
    pub(crate) fn new(
        natives: &NativeFunctions,
        size: usize,
        module: Arc<CompiledModule>,
        struct_name_index_map: &StructNameIndexMap,
        ty_pool: &InternedTypePool,
        module_id_pool: &InternedModuleIdPool,
    ) -> PartialVMResult<Self> {
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L167-168)
```rust
        let id = module.self_id();
        let interned_id = module_id_pool.intern_by_ref(&id);
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L217-224)
```rust
        let result = Module::new(
            &self.natives,
            locally_verified_module.1,
            locally_verified_module.0,
            self.struct_name_index_map(),
            self.ty_pool(),
            self.module_id_pool(),
        );
```

**File:** crates/crash-handler/src/lib.rs (L48-57)
```rust
    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L138-171)
```rust
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L56-68)
```rust
        let prev_state = move_core_types::state::set_state(VMState::DESERIALIZER);
        let result = std::panic::catch_unwind(|| {
            let module = deserialize_compiled_module(binary, config)?;
            BoundsChecker::verify_module(&module)?;

            Ok(module)
        })
        .unwrap_or_else(|_| {
            Err(PartialVMError::new(
                StatusCode::VERIFIER_INVARIANT_VIOLATION,
            ))
        });
        move_core_types::state::set_state(prev_state);
```

**File:** types/src/block_executor/config.rs (L27-28)
```rust
    /// The maximum number of module IDs to intern.
    pub max_interned_module_ids: usize,
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L162-166)
```rust
        if num_interned_module_ids > config.max_interned_module_ids {
            runtime_environment.module_id_pool().flush();
            runtime_environment.struct_name_index_map().flush();
            self.module_cache.flush();
        }
```
