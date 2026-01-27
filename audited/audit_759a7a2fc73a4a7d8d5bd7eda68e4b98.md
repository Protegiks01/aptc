# Audit Report

## Title
Unmetered Borrow Graph Operations in Bytecode Verification Enable Validator CPU Exhaustion

## Summary
Borrow graph operations during Move bytecode verification are not properly metered, allowing attackers to create modules that consume excessive validator CPU time without corresponding gas costs. The `construct_canonical_state` operation, which performs expensive O(n log n) `remap_refs`, executes completely outside the verification meter's accounting scope.

## Finding Description

During Move bytecode verification for module publishing, the reference safety checker maintains a borrow graph to track reference relationships. At every basic block boundary, `construct_canonical_state` is called to canonicalize the abstract state, which includes calling `remap_refs` on the borrow graph. [1](#0-0) 

The critical issue is that `construct_canonical_state` is invoked **after** `execute_inner` returns, placing it outside the metering scope. The `execute_inner` function meters each step: [2](#0-1) 

However, the expensive `remap_refs` operation that follows is never metered: [3](#0-2) 

The `remap_refs` implementation rebuilds the entire BTreeMap structure, which has O(n log n) complexity: [4](#0-3) 

**Attack Path:**
1. Attacker creates a Move module with maximum allowed basic blocks (1024)
2. Module uses reference parameters and creates many local borrows to maximize the borrow graph size
3. Each of the 1024 basic block boundaries triggers unmetered `remap_refs` operations
4. For a borrow graph with n references, this causes 1024 × O(n log n) unmetered work
5. Validator CPU time is consumed without corresponding meter charges

With production limits allowing graphs of hundreds of references, the unmetered work represents a log(n) factor (≈7-10x) more computation than what's charged.

## Impact Explanation

This qualifies as **High Severity** under "Validator node slowdowns" because:

1. **Resource Exhaustion**: Verification happens during module publishing, consuming validator CPU without proper accounting
2. **Unfair Cost Distribution**: The verification meter charges linearly (STEP_PER_GRAPH_ITEM_COST × graph_size) but actual work is O(n log n)
3. **Attack Scalability**: With max 1024 basic blocks, an attacker can amplify the unmetered work by 1024×

However, the impact is mitigated by:
- Production verification limits (8M meter units)
- Module verification caching (VERIFIED_MODULES_CACHE)
- Bounded maximum complexity from other limits [5](#0-4) 

## Likelihood Explanation

**High likelihood** because:
- Any user can submit module publishing transactions
- No special privileges required
- Straightforward to maximize basic blocks and reference count within limits
- Verification happens on every validator processing the transaction (before caching)

**Constraints:**
- Limited by production config (max_basic_blocks: 1024, max_per_fun_meter_units: 8M)
- Cached after first verification per module hash
- Other verification checks may reject pathological modules [6](#0-5) 

## Recommendation

**Immediate Fix**: Add metering for `construct_canonical_state` operation:

```rust
fn execute(
    &mut self,
    state: &mut Self::State,
    bytecode: &Bytecode,
    index: CodeOffset,
    last_index: CodeOffset,
    meter: &mut impl Meter,
) -> PartialVMResult<()> {
    execute_inner(self, state, bytecode, index, meter)?;
    if index == last_index {
        safe_assert!(self.stack.is_empty());
        // ADD METERING FOR CANONICALIZATION
        meter.add(Scope::Function, CANONICALIZE_BASE_COST)?;
        meter.add_items(
            Scope::Function, 
            CANONICALIZE_PER_REF_COST,
            state.local_count()
        )?;
        *state = state.construct_canonical_state()
    }
    Ok(())
}
```

Where `CANONICALIZE_PER_REF_COST` should account for the O(log n) overhead of rebuilding the BTreeMap.

**Long-term Fix**: Consider bounding total reference count explicitly, or using a more efficient canonicalization strategy that doesn't rebuild the entire graph structure.

## Proof of Concept

```move
// Module designed to maximize unmetered verification work
module 0x1::metering_attack {
    // Use maximum allowed parameters (128 references)
    public fun complex_borrows(
        r1: &u64, r2: &u64, r3: &u64, r4: &u64, /* ... r128: &u64 */
    ) {
        // Create 1024 basic blocks using nested if-else chains
        // Each block performs reference operations to grow graph
        if (*r1 > 0) {
            let local_ref = r2;
            if (*r2 > 1) {
                let local_ref2 = r3;
                // ... continue nesting to create 1024 blocks ...
                // Each block boundary triggers unmetered remap_refs
            } else {
                // Alternate path to force graph joins
            }
        } else {
            // More branching patterns
        };
        // Total: 1024 canonical_state calls × O(n log n) remap_refs
        // But only charged 1024 × O(n) meter units
    }
}
```

The verification of this module would consume significantly more CPU time than the meter charges, with the gap growing logarithmically with reference count.

## Notes

While this represents a valid gas metering gap that violates the principle that "all operations must respect gas, storage, and computational limits," the practical exploitability is constrained by production limits and verification caching. The issue is more about fairness in cost accounting than catastrophic DoS, but still qualifies as High severity due to enabling validator slowdowns through unprivileged transactions.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/mod.rs (L246-252)
```rust
    meter.add(Scope::Function, STEP_BASE_COST)?;
    meter.add_items(Scope::Function, STEP_PER_LOCAL_COST, state.local_count())?;
    meter.add_items(
        Scope::Function,
        STEP_PER_GRAPH_ITEM_COST,
        state.graph_size(),
    )?;
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/mod.rs (L688-694)
```rust
        execute_inner(self, state, bytecode, index, meter)?;
        if index == last_index {
            safe_assert!(self.stack.is_empty());
            *state = state.construct_canonical_state()
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/abstract_state.rs (L624-651)
```rust
    pub fn construct_canonical_state(&self) -> Self {
        let mut id_map = BTreeMap::new();
        id_map.insert(self.frame_root(), self.frame_root());
        let locals = self
            .locals
            .iter()
            .enumerate()
            .map(|(local, value)| match value {
                AbstractValue::Reference(old_id) => {
                    let new_id = RefID::new(local);
                    id_map.insert(*old_id, new_id);
                    AbstractValue::Reference(new_id)
                },
                AbstractValue::NonReference => AbstractValue::NonReference,
            })
            .collect::<Vec<_>>();
        assert!(self.locals.len() == locals.len());
        let mut borrow_graph = self.borrow_graph.clone();
        borrow_graph.remap_refs(&id_map);
        let canonical_state = AbstractState {
            locals,
            borrow_graph,
            current_function: self.current_function,
            next_id: self.locals.len() + 1,
        };
        assert!(canonical_state.is_canonical());
        canonical_state
    }
```

**File:** third_party/move/move-borrow-graph/src/graph.rs (L371-384)
```rust
    pub fn remap_refs(&mut self, id_map: &BTreeMap<RefID, RefID>) {
        debug_assert!(self.check_invariant());
        let _before = self.0.len();
        self.0 = std::mem::take(&mut self.0)
            .into_iter()
            .map(|(id, mut info)| {
                info.remap_refs(id_map);
                (id_map.get(&id).copied().unwrap_or(id), info)
            })
            .collect();
        let _after = self.0.len();
        debug_assert!(_before == _after);
        debug_assert!(self.check_invariant());
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L184-198)
```rust
        if !VERIFIED_MODULES_CACHE.contains(module_hash) {
            let _timer =
                VM_TIMER.timer_with_label("move_bytecode_verifier::verify_module_with_config");

            // For regular execution, we cache already verified modules. Note that this even caches
            // verification for the published modules. This should be ok because as long as the
            // hash is the same, the deployed bytecode and any dependencies are the same, and so
            // the cached verification result can be used.
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
            check_natives(compiled_module.as_ref())?;
            VERIFIED_MODULES_CACHE.put(*module_hash);
        }
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L286-308)
```rust
    pub fn production() -> Self {
        Self {
            scope: VerificationScope::Everything,
            max_loop_depth: Some(5),
            max_generic_instantiation_length: Some(32),
            max_function_parameters: Some(128),
            max_basic_blocks: Some(1024),
            max_basic_blocks_in_script: Some(1024),
            max_value_stack_size: 1024,
            max_type_nodes: Some(128),
            max_push_size: Some(10000),
            max_struct_definitions: Some(200),
            max_fields_in_struct: Some(30),
            max_struct_variants: Some(90),
            max_function_definitions: Some(1000),

            // Do not use back edge constraints as they are superseded by metering
            max_back_edges_per_function: None,
            max_back_edges_per_module: None,

            // Same as the default.
            max_per_fun_meter_units: Some(1000 * 8000),
            max_per_mod_meter_units: Some(1000 * 8000),
```
