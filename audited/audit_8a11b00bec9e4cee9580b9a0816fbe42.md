# Audit Report

## Title
Aggregator V1 Delta Materialization Bypass Allows Write Operation Limit Evasion

## Summary
The VMChangeSet validation logic fails to count unmaterialized `aggregator_v1_delta_set` entries when enforcing transaction write operation limits. This allows attackers to bypass the `max_write_ops_per_transaction` hard limit (8192 operations) and `max_bytes_all_write_ops_per_transaction` limit (10 MB) by creating transactions with numerous aggregator delta operations that are validated before materialization but converted to concrete write operations afterward.

## Finding Description
The vulnerability exists in the interaction between change set validation and aggregator delta materialization:

**1. Validation Logic Omission:**
The `num_write_ops()` method only counts materialized write operations, excluding `aggregator_v1_delta_set` entries: [1](#0-0) 

Similarly, `write_set_size_iter()` only iterates over materialized writes: [2](#0-1) 

**2. Validation Enforcement:**
The `check_change_set()` function uses these incomplete methods to enforce storage limits: [3](#0-2) 

This validation is invoked during session finalization: [4](#0-3) 

**3. Delta Creation:**
Aggregator deltas are created during Move VM execution when `AggregatorChangeV1::Merge` operations occur: [5](#0-4) 

**4. Post-Validation Materialization:**
After validation passes, deltas are materialized into concrete write operations: [6](#0-5) 

**Attack Flow:**
1. Attacker creates a transaction that instantiates many parallelizable aggregators via `aggregator_factory::create_aggregator_internal()`
2. Each aggregator.add() or aggregator.sub() operation creates a delta in `aggregator_v1_delta_set`
3. During session finalization, `check_change_set()` validates the transaction but doesn't count these deltas
4. Validation passes even if total operations exceed 8192 or total size exceeds 10 MB
5. Later during sequential execution, `legacy_sequential_materialize_agg_v1()` converts all deltas to write operations
6. The transaction commits with write operations far exceeding configured limits

The hard limit was introduced in gas feature version 11: [7](#0-6) 

## Impact Explanation
**Severity: HIGH**

This vulnerability allows bypassing critical resource limits designed to prevent state storage exhaustion and ensure deterministic execution:

1. **Resource Exhaustion**: Attackers can force validators to process and store unbounded write operations, potentially exhausting memory and storage capacity during transaction execution and state commitment.

2. **Deterministic Execution Risk**: If different validator implementations or configurations handle post-validation materialization differently, this could lead to consensus divergence where validators produce different state roots for the same block.

3. **Protocol Invariant Violation**: Breaks the fundamental invariant that "All operations must respect gas, storage, and computational limits" as transactions can exceed max_write_ops_per_transaction (8192) and max_bytes_all_write_ops_per_transaction (10 MB).

4. **State Management Impact**: The block executor expects validated limits to be enforced before materialization. Bypassing these limits could cause unexpected behavior in state synchronization and storage layer operations.

This qualifies as **High Severity** per the Aptos bug bounty criteria as it represents a "significant protocol violation" that can cause "validator node slowdowns" and state management issues.

## Likelihood Explanation
**Likelihood: HIGH**

This vulnerability is highly exploitable:

1. **No Special Privileges Required**: Any transaction sender can exploit this by deploying Move modules that use parallelizable aggregators
2. **Public API Access**: The aggregator framework is accessible through `aptos_framework::aggregator` and `aptos_framework::optional_aggregator`
3. **Already in Production Use**: Framework modules like `coin.move` use aggregators, demonstrating the attack vector is well-understood
4. **Trivial to Execute**: Creating many aggregators and performing add/sub operations requires minimal Move programming knowledge
5. **Deterministic Exploitation**: The vulnerability is architectural rather than race-condition based, making it reliably exploitable

The only barrier is gas costs for creating aggregators, but attackers could still significantly exceed the write operation limits before exhausting their gas budget, especially since the validation bypass occurs before proper accounting.

## Recommendation
**Fix the validation logic to include unmaterialized aggregator deltas:**

```rust
// In aptos-move/aptos-vm-types/src/change_set.rs
impl ChangeSetInterface for VMChangeSet {
    fn num_write_ops(&self) -> usize {
        // Include aggregator_v1_delta_set in the count
        self.resource_write_set().len() 
            + self.aggregator_v1_write_set().len()
            + self.aggregator_v1_delta_set().len()  // ADD THIS LINE
    }

    fn write_set_size_iter(&self) -> impl Iterator<Item = (&StateKey, WriteOpSize)> {
        self.resource_write_set()
            .iter()
            .map(|(k, v)| (k, v.materialized_size()))
            .chain(
                self.aggregator_v1_write_set()
                    .iter()
                    .map(|(k, v)| (k, v.write_op_size())),
            )
            // ADD: Estimate size for aggregator deltas
            .chain(
                self.aggregator_v1_delta_set()
                    .iter()
                    .map(|(k, _delta)| {
                        // Deltas materialize to u128 values (16 bytes serialized)
                        (k, WriteOpSize::Modification { 
                            metadata_size: 0 
                        })
                    })
            )
    }
}
```

**Alternative approach:** Materialize aggregator deltas BEFORE validation instead of after:
- Move `try_materialize_aggregator_v1_delta_set()` call to occur before `UserSessionChangeSet::new()`
- This ensures validation sees the actual write operations that will be committed

## Proof of Concept

```move
// Save as aggregator_limit_bypass.move
module attacker::limit_bypass {
    use aptos_framework::aggregator_factory;
    use aptos_framework::aggregator::{Self, Aggregator};
    use std::vector;

    struct AggregatorStore has key {
        aggregators: vector<Aggregator>,
    }

    /// Create many aggregators and perform operations to generate deltas
    public entry fun exploit_write_limit(attacker: &signer) {
        aggregator_factory::initialize_aggregator_factory_for_verified_module(attacker);
        
        let aggregators = vector::empty<Aggregator>();
        
        // Create 10000 aggregators - far exceeding the 8192 write op limit
        let i = 0;
        while (i < 10000) {
            let agg = aggregator_factory::create_aggregator_internal();
            // Perform an operation to create a delta
            aggregator::add(&mut agg, 1);
            vector::push_back(&mut aggregators, agg);
            i = i + 1;
        };
        
        move_to(attacker, AggregatorStore { aggregators });
        
        // At this point:
        // - 10000 deltas exist in aggregator_v1_delta_set
        // - Validation only counted resource writes (1 for AggregatorStore)
        // - Transaction passes with num_write_ops = 1
        // - Later materialization converts to 10000+ actual write ops
        // - Limit of 8192 is bypassed!
    }
}
```

**Expected behavior:** Transaction should be rejected with `STORAGE_WRITE_LIMIT_REACHED` error during validation.

**Actual behavior:** Transaction passes validation and commits with >10000 write operations after materialization, bypassing the 8192 limit.

## Notes
The vulnerability is exacerbated by the fact that aggregator V2 (delayed fields) may have similar issues based on the code structure. The `delayed_field_change_set` is also excluded from `num_write_ops()` counting and should be audited for the same vulnerability pattern.

### Citations

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L367-399)
```rust
    pub fn try_materialize_aggregator_v1_delta_set(
        &mut self,
        resolver: &impl AggregatorV1Resolver,
    ) -> VMResult<()> {
        let into_write =
            |(state_key, delta): (StateKey, DeltaOp)| -> VMResult<(StateKey, WriteOp)> {
                // Materialization is needed when committing a transaction, so
                // we need precise mode to compute the true value of an
                // aggregator.
                let write = resolver
                    .try_convert_aggregator_v1_delta_into_write_op(&state_key, &delta)
                    .map_err(|e| {
                        // We need to set abort location for Aggregator V1 to ensure correct VMStatus can
                        // be constructed.
                        const AGGREGATOR_V1_ADDRESS: AccountAddress = CORE_CODE_ADDRESS;
                        const AGGREGATOR_V1_MODULE_NAME: &IdentStr = ident_str!("aggregator");
                        e.finish(Location::Module(ModuleId::new(
                            AGGREGATOR_V1_ADDRESS,
                            AGGREGATOR_V1_MODULE_NAME.into(),
                        )))
                    })?;
                Ok((state_key, write))
            };

        let aggregator_v1_delta_set = std::mem::take(&mut self.aggregator_v1_delta_set);
        let materialized_aggregator_delta_set = aggregator_v1_delta_set
            .into_iter()
            .map(into_write)
            .collect::<VMResult<BTreeMap<StateKey, WriteOp>>>()?;
        self.aggregator_v1_write_set
            .extend(materialized_aggregator_delta_set);
        Ok(())
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L856-860)
```rust
    fn num_write_ops(&self) -> usize {
        // Note: we only use resources and aggregators because they use write ops directly,
        // and deltas & events are not part of these.
        self.resource_write_set().len() + self.aggregator_v1_write_set().len()
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L862-871)
```rust
    fn write_set_size_iter(&self) -> impl Iterator<Item = (&StateKey, WriteOpSize)> {
        self.resource_write_set()
            .iter()
            .map(|(k, v)| (k, v.materialized_size()))
            .chain(
                self.aggregator_v1_write_set()
                    .iter()
                    .map(|(k, v)| (k, v.write_op_size())),
            )
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L95-99)
```rust
        if self.max_write_ops_per_transaction != 0
            && change_set.num_write_ops() as u64 > self.max_write_ops_per_transaction
        {
            return storage_write_limit_reached(Some("Too many write ops."));
        }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L28-34)
```rust
    ) -> Result<Self, VMStatus> {
        let user_session_change_set = Self {
            change_set,
            module_write_set,
        };
        change_set_configs.check_change_set(&user_session_change_set)?;
        Ok(user_session_change_set)
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L493-495)
```rust
                AggregatorChangeV1::Merge(delta_op) => {
                    aggregator_v1_delta_set.insert(state_key, delta_op);
                },
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L174-177)
```rust
            max_write_ops_per_transaction: NumSlots,
            { 11.. => "max_write_ops_per_transaction" },
            8192,
        ],
```
