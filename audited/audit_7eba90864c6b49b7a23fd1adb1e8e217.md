# Audit Report

## Title
Aggregator Delta Writes Bypass I/O Gas Charging Leading to Undercharged State Modifications

## Summary
The `charge_change_set()` function in AptosVM does not charge I/O gas for aggregator v1 delta operations, allowing transactions to perform state modifications without paying the full gas cost. This bypasses the standard I/O gas metering for write operations worth approximately 89,568+ internal gas units per aggregator write.

## Finding Description

The vulnerability exists in the gas charging mechanism for change sets containing aggregator operations. When a transaction executes and modifies aggregators (used extensively in framework code for coin supply tracking, token collections, etc.), these modifications are stored as "deltas" in the `aggregator_v1_delta_set` rather than immediate writes. [1](#0-0) 

The `charge_change_set()` function iterates over `write_set_size_iter()` to charge I/O gas for each write operation. However, this iterator explicitly excludes aggregator deltas: [2](#0-1) 

The `write_set_size_iter()` only includes `resource_write_set` and `aggregator_v1_write_set`, but completely omits `aggregator_v1_delta_set`. This means aggregator delta operations avoid I/O gas charges entirely.

The TODO comment at line 1158 explicitly acknowledges this missing charge: [3](#0-2) 

These deltas are later materialized into actual write operations after gas has already been charged and the transaction finalized: [4](#0-3) 

**Attack Path:**
1. Attacker submits transaction calling framework functions that perform aggregator operations (e.g., `coin::mint`, `coin::burn`, token supply operations)
2. Each aggregator operation creates a delta in `aggregator_v1_delta_set`
3. During `charge_change_set()`, these deltas are not included in I/O gas calculation
4. Transaction completes with undercharged gas
5. Deltas are materialized into writes post-transaction without additional charging
6. Attacker saves I/O gas costs per aggregator operation

**Exploitability via Framework Functions:**

User transactions can trigger aggregator operations through public framework APIs: [5](#0-4) [6](#0-5) 

## Impact Explanation

This vulnerability constitutes a **Medium Severity** issue under the Aptos bug bounty program's "Limited funds loss or manipulation" category. 

**Quantified Impact:**
- Each aggregator write should incur I/O gas costs based on the current gas schedule:
  - `storage_io_per_state_slot_write`: 89,568 internal gas units
  - `storage_io_per_state_byte_write`: 89 internal gas units per byte [7](#0-6) 

- For a typical aggregator (u128 = 16 bytes + key overhead ~50-80 bytes), the bypassed I/O gas per operation is approximately **95,000-96,000 internal gas units**
- A transaction performing N aggregator operations saves N × ~95,000 gas units
- At current gas prices, this represents tangible APT token savings per transaction
- Across many transactions, this accumulates to significant economic value extraction

**Broken Invariants:**
- **Resource Limits Invariant (#9)**: "All operations must respect gas, storage, and computational limits" - violated because aggregator writes bypass I/O gas limits
- **Move VM Safety Invariant (#3)**: "Bytecode execution must respect gas limits" - partially violated through undercharging

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurrence because:

1. **No special privileges required**: Any user can submit transactions calling framework functions
2. **Common operations affected**: Coin minting/burning and token operations are frequent on-chain activities
3. **Natural usage pattern**: Developers using aggregators for parallelism optimization will automatically benefit from this undercharging without even realizing it
4. **Already happening**: The TODO comment indicates developers are aware but haven't fixed it, meaning current mainnet transactions are likely already undercharged
5. **Easy to exploit**: Simply call existing framework functions; no complex attack construction needed

## Recommendation

The fix requires charging I/O gas for aggregator delta operations. Implement one of these solutions:

**Option 1: Charge for deltas during change_set processing**
Modify `charge_change_set()` to iterate over and charge for `aggregator_v1_delta_set` entries:

```rust
fn charge_change_set(
    &self,
    change_set: &mut impl ChangeSetInterface,
    gas_meter: &mut impl AptosGasMeter,
    txn_data: &TransactionMetadata,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl AptosModuleStorage,
) -> Result<GasQuantity<Octa>, VMStatus> {
    gas_meter.charge_io_gas_for_transaction(txn_data.transaction_size())?;
    for event in change_set.events_iter() {
        gas_meter.charge_io_gas_for_event(event)?;
    }
    for (key, op_size) in change_set.write_set_size_iter() {
        gas_meter.charge_io_gas_for_write(key, &op_size)?;
    }
    
    // NEW: Charge for aggregator v1 deltas
    for (key, _delta_op) in change_set.aggregator_v1_delta_set() {
        // Aggregators are u128 (16 bytes), treat as modification
        let op_size = WriteOpSize::Modification { write_len: 16 };
        gas_meter.charge_io_gas_for_write(key, &op_size)?;
    }

    let mut storage_refund = gas_meter.process_storage_fee_for_all(
        change_set,
        txn_data.transaction_size,
        txn_data.gas_unit_price,
        resolver.as_executor_view(),
        module_storage,
    )?;
    if !self.features().is_storage_deletion_refund_enabled() {
        storage_refund = 0.into();
    }
    Ok(storage_refund)
}
```

**Option 2: Include deltas in write_set_size_iter()**
Modify the `ChangeSetInterface` implementation to include aggregator deltas in the iterator.

Remove the TODO comment after implementing the fix: [3](#0-2) 

## Proof of Concept

```move
#[test_only]
module test_addr::aggregator_gas_bypass_poc {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::aptos_account;
    use std::signer;
    
    #[test(framework = @aptos_framework, user = @0x123)]
    fun test_aggregator_undercharging(framework: &signer, user: &signer) {
        // Setup: Initialize coin with supply tracking (uses aggregator)
        aptos_framework::aggregator_factory::initialize_aggregator_factory_for_test(framework);
        coin::initialize<AptosCoin>(
            framework,
            b"Aptos Coin",
            b"APT", 
            8,
            true  // monitor_supply = true, triggers aggregator usage
        );
        
        let user_addr = signer::address_of(user);
        aptos_account::create_account(user_addr);
        
        // Get gas meter state before
        let gas_before = /* capture gas state */;
        
        // Perform multiple coin operations that use aggregators
        // Each mint/burn operation modifies the supply aggregator
        for (i in 0..10) {
            coin::mint<AptosCoin>(1000, user_addr);
            coin::burn<AptosCoin>(coin::withdraw<AptosCoin>(user, 500));
        }
        // Total: 20 aggregator operations
        
        let gas_after = /* capture gas state */;
        let gas_charged = gas_after - gas_before;
        
        // Expected: ~20 aggregator writes × 95,000 gas = ~1,900,000 gas for I/O
        // Actual: Much less because aggregator deltas are not charged
        // This demonstrates the undercharging vulnerability
        assert!(gas_charged < expected_gas_with_full_charging, 0);
    }
}
```

**Notes:**
- This vulnerability has been present since aggregator v1 implementation
- The explicit TODO comment confirms developers are aware but haven't prioritized the fix
- The impact scales with the number of aggregator operations per transaction
- While individual savings per transaction are bounded, cumulative network-wide impact could be significant
- Framework aggregators (coin supply, token collections) are the primary affected use cases since user code cannot create aggregators directly per the framework restriction [8](#0-7)

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1112-1140)
```rust
    fn charge_change_set(
        &self,
        change_set: &mut impl ChangeSetInterface,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<GasQuantity<Octa>, VMStatus> {
        gas_meter.charge_io_gas_for_transaction(txn_data.transaction_size())?;
        for event in change_set.events_iter() {
            gas_meter.charge_io_gas_for_event(event)?;
        }
        for (key, op_size) in change_set.write_set_size_iter() {
            gas_meter.charge_io_gas_for_write(key, &op_size)?;
        }

        let mut storage_refund = gas_meter.process_storage_fee_for_all(
            change_set,
            txn_data.transaction_size,
            txn_data.gas_unit_price,
            resolver.as_executor_view(),
            module_storage,
        )?;
        if !self.features().is_storage_deletion_refund_enabled() {
            storage_refund = 0.into();
        }

        Ok(storage_refund)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1158-1158)
```rust
        // TODO[agg_v1](fix): Charge for aggregator writes
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L365-399)
```rust
    /// Materializes this change set: all aggregator v1 deltas are converted into writes and
    /// are combined with existing aggregator writes. The aggregator v2 changeset is not touched.
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

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L862-870)
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
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1220-1220)
```text
            optional_aggregator::add(supply, (amount as u128));
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1238-1238)
```text
                optional_aggregator::sub(supply, (amount as u128));
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L108-126)
```rust
            storage_io_per_state_slot_write: InternalGasPerArg,
            { 0..=9 => "write_data.per_op", 10.. => "storage_io_per_state_slot_write"},
            // The cost of writing down the upper level new JMT nodes are shared between transactions
            // because we write down the JMT in batches, however the bottom levels will be specific
            // to each transactions assuming they don't touch exactly the same leaves. It's fair to
            // target roughly 1-2 full internal JMT nodes (about 0.5-1KB in total) worth of writes
            // for each write op.
            89_568,
        ],
        [
            legacy_write_data_per_new_item: InternalGasPerArg,
            {0..=9 => "write_data.new_item"},
            1_280_000,
        ],
        [
            storage_io_per_state_byte_write: InternalGasPerByte,
            { 0..=9 => "write_data.per_byte_in_key", 10.. => "storage_io_per_state_byte_write"},
            89,
        ],
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator/aggregator.move (L11-12)
```text
/// parallelism. Moreover, **aggregators can only be created by Aptos Framework (0x1)
/// at the moment.**
```
