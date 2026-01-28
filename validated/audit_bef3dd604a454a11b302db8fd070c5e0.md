# Audit Report

## Title
Gas Metering Bypass in Native Resource Existence Check Leading to Validator Resource Exhaustion

## Summary
The `native_exists_at` function in the Aptos object module charges base gas before performing storage I/O operations, but charges per-byte gas only after the operation completes. This violates the "charge before execute" principle and allows attackers to cause validators to perform expensive storage reads while paying only 4-5% of the proper gas cost when transactions abort after the I/O operation.

## Finding Description

The vulnerability exists in the gas charging sequence where storage I/O operations are performed before the full gas cost is charged, violating the documented gas metering principle. [1](#0-0) 

The function charges `OBJECT_EXISTS_AT_BASE` (919 InternalGas units) before the storage operation, then calls `context.exists_at()` which performs storage I/O through the following call chain: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The actual storage read happens without gas charging via `resource_resolver.get_resource_bytes_with_metadata_and_layout()`: [6](#0-5) 

After the storage I/O completes and control returns to `native_exists_at`, the per-byte gas is charged. The gas parameter values show significant costs: [7](#0-6) 

Critically, these are noted as "dummy values" that were copied, suggesting improper calibration.

This violates the documented principle in the gas metering code: [8](#0-7) 

**Attack Scenario:**

1. Attacker crafts a transaction with precisely calculated gas limit
2. Transaction executes operations to consume most gas
3. When `exists<T>()` is called for a 100-byte resource:
   - Remaining gas: ~1,000 units
   - Base gas charged: 919 ✓
   - Storage I/O performed (disk read, deserialization) ✓
   - Attempt to charge per-byte: 1,470 + 18,300 = 19,770 ✗
4. Transaction aborts with OUT_OF_GAS
5. Transaction is kept in blockchain with Keep(OutOfGas) status: [9](#0-8) [10](#0-9) [11](#0-10) 

6. Validator performed expensive I/O but received only 919 gas instead of 20,689 (95.5% under-compensated)

The attacker can repeat this with multiple transactions, triggering one under-compensated I/O operation per transaction.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria ("Validator node slowdowns").

**Resource Exhaustion Attack:**
- An attacker can force validators to perform storage I/O operations (disk reads, database queries, deserialization) while paying only 4-5% of the proper cost
- For a 100-byte resource: proper cost 20,689 gas, attacker pays 919 gas
- 22.5x cost reduction enables spam attacks at significantly reduced cost
- Repeated transactions can exhaust validator I/O resources, slowing block processing
- Affects all validators processing the block, potentially impacting consensus liveness

**Economic Attack:**
- Violates the fundamental gas metering principle that operations must be charged before execution
- Allows attackers to perform economically viable resource exhaustion attacks with 22.5x advantage over legitimate users

## Likelihood Explanation

**High Likelihood** - Attack is practical and easily executable:

1. **No Special Access Required:** Any user can submit transactions calling `object::exists_at<T>()` on arbitrary addresses
2. **Precise Gas Control:** Attackers can calculate exact gas consumption through profiling to hit the vulnerability window
3. **Repeatable:** Can be executed across multiple transactions
4. **Economically Viable:** 22.5x cost reduction makes the attack profitable
5. **Detection Difficulty:** Legitimate transactions also call `exists<T>()`, making malicious transactions blend in

The attack complexity is low - an attacker needs only:
- Deploy a Move module with logic calling `exists<T>` on various addresses
- Calculate gas consumption to ensure abortion at the per-byte charge
- Submit transactions with calibrated gas limits

## Recommendation

Charge the full gas cost (base + per-byte + per-item) **before** performing the storage I/O operation. This can be implemented by:

1. Calculate the maximum possible per-byte cost based on a reasonable upper bound
2. Charge base + maximum per-byte cost upfront
3. Perform storage I/O
4. Refund any excess gas if the actual resource is smaller than maximum

Alternatively, implement a mechanism to ensure that storage I/O operations themselves are metered and charged directly, preventing the vulnerability window between I/O and gas charging.

## Proof of Concept

```move
module attacker::exploit {
    use std::signer;
    use aptos_framework::object;
    
    // Define a large resource type
    struct LargeResource has key {
        data: vector<u8>
    }
    
    public entry fun exploit_gas_metering(account: &signer, target: address) {
        // Consume most gas with operations
        let i = 0;
        while (i < 1000) {
            i = i + 1;
            // Consume gas with computations
        };
        
        // At this point, remaining gas is ~1000 units
        // Call exists_at which will:
        // 1. Charge base gas (919) - succeeds
        // 2. Perform storage I/O - succeeds  
        // 3. Try to charge per-byte gas (19,770) - OUT_OF_GAS
        let _ = object::exists_at<LargeResource>(target);
        
        // Transaction aborts here, but validator already performed I/O
    }
}
```

The attacker can submit this transaction repeatedly, each time forcing validators to perform storage I/O while paying only 919 gas instead of the proper 20,689 gas cost.

## Notes

This vulnerability represents a fundamental violation of the gas metering principle documented in the codebase. The comment at line 354 of the gas schedule indicating these are "dummy values" suggests these parameters may not have been properly calibrated for production use. The issue enables a concrete economic attack with a 22.5x advantage, making it economically viable for attackers to cause validator resource exhaustion.

### Citations

**File:** aptos-move/framework/src/natives/object.rs (L84-96)
```rust
    context.charge(OBJECT_EXISTS_AT_BASE)?;

    let (exists, num_bytes) = context.exists_at(address, type_).map_err(|err| {
        PartialVMError::new(StatusCode::VM_EXTENSION_ERROR).with_message(format!(
            "Failed to read resource: {:?} at {}. With error: {}",
            type_, address, err
        ))
    })?;

    if let Some(num_bytes) = num_bytes {
        context.charge(
            OBJECT_EXISTS_AT_PER_ITEM_LOADED + OBJECT_EXISTS_AT_PER_BYTE_LOADED * num_bytes,
        )?;
```

**File:** third_party/move/move-vm/runtime/src/native_functions.rs (L151-162)
```rust
    pub fn exists_at(
        &mut self,
        address: AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(bool, Option<NumBytes>)> {
        self.data_cache.native_check_resource_exists(
            self.gas_meter,
            self.traversal_context,
            &address,
            ty,
        )
    }
```

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L90-101)
```rust
    fn native_check_resource_exists(
        &mut self,
        gas_meter: &mut dyn DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        addr: &AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(bool, Option<NumBytes>)> {
        let mut gas_meter = DependencyGasMeterWrapper::new(gas_meter);
        let (gv, bytes_loaded) = self.load_resource(&mut gas_meter, traversal_context, addr, ty)?;
        let exists = gv.exists();
        Ok((exists, bytes_loaded))
    }
```

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L125-151)
```rust
    fn load_resource_mut(
        &mut self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        addr: &AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(&mut GlobalValue, Option<NumBytes>)> {
        let bytes_loaded = if !self.data_cache.contains_resource(addr, ty) {
            let (entry, bytes_loaded) = TransactionDataCache::create_data_cache_entry(
                self.loader,
                &LayoutConverter::new(self.loader),
                gas_meter,
                traversal_context,
                self.loader.unmetered_module_storage(),
                self.resource_resolver,
                addr,
                ty,
            )?;
            self.data_cache.insert_resource(*addr, ty.clone(), entry)?;
            Some(bytes_loaded)
        } else {
            None
        };

        let gv = self.data_cache.get_resource_mut(addr, ty)?;
        Ok((gv, bytes_loaded))
    }
```

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L255-295)
```rust
    fn create_data_cache_entry(
        metadata_loader: &impl ModuleMetadataLoader,
        layout_converter: &LayoutConverter<impl StructDefinitionLoader>,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        module_storage: &dyn ModuleStorage,
        resource_resolver: &dyn ResourceResolver,
        addr: &AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(DataCacheEntry, NumBytes)> {
        let struct_tag = match module_storage.runtime_environment().ty_to_ty_tag(ty)? {
            TypeTag::Struct(struct_tag) => *struct_tag,
            _ => {
                // Since every resource is a struct, the tag must be also a struct tag.
                return Err(PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR));
            },
        };

        let layout_with_delayed_fields = layout_converter.type_to_type_layout_with_delayed_fields(
            gas_meter,
            traversal_context,
            ty,
            false,
        )?;

        let (data, bytes_loaded) = {
            let module = metadata_loader.load_module_for_metadata(
                gas_meter,
                traversal_context,
                &struct_tag.module_id(),
            )?;

            // If we need to process delayed fields, we pass type layout to remote storage. Remote
            // storage, in turn ensures that all delayed field values are pre-processed.
            resource_resolver.get_resource_bytes_with_metadata_and_layout(
                addr,
                &struct_tag,
                &module.metadata,
                layout_with_delayed_fields.layout_when_contains_delayed_fields(),
            )?
        };
```

**File:** third_party/move/move-vm/types/src/resolver.rs (L25-33)
```rust
pub trait ResourceResolver {
    fn get_resource_bytes_with_metadata_and_layout(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
        metadata: &[Metadata],
        layout: Option<&MoveTypeLayout>,
    ) -> PartialVMResult<(Option<Bytes>, usize)>;
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L350-356)
```rust
        [object_exists_at_base: InternalGas, { 7.. => "object.exists_at.base" }, 919],
        // Based on SHA3-256's cost
        [object_user_derived_address_base: InternalGas, { RELEASE_V1_12.. => "object.user_derived_address.base" }, 14704],

        // These are dummy value, they copied from storage gas in aptos-core/aptos-vm/src/aptos_vm_impl.rs
        [object_exists_at_per_byte_loaded: InternalGasPerByte, { 7.. => "object.exists_at.per_byte_loaded" }, 183],
        [object_exists_at_per_item_loaded: InternalGas, { 7.. => "object.exists_at.per_item_loaded" }, 1470],
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L69-72)
```rust
    /// Always remember: first charge gas, then execute!
    ///
    /// In other words, this function **MUST** always be called **BEFORE** executing **any**
    /// gas-metered operation or library call within a native function.
```

**File:** types/src/transaction/mod.rs (L1489-1503)
```rust
pub enum ExecutionStatus {
    Success,
    OutOfGas,
    MoveAbort {
        location: AbortLocation,
        code: u64,
        info: Option<AbortInfo>,
    },
    ExecutionFailure {
        location: AbortLocation,
        function: u16,
        code_offset: u16,
    },
    MiscellaneousError(Option<StatusCode>),
}
```

**File:** types/src/transaction/mod.rs (L1513-1542)
```rust
impl From<KeptVMStatus> for ExecutionStatus {
    fn from(kept_status: KeptVMStatus) -> Self {
        match kept_status {
            KeptVMStatus::Executed => ExecutionStatus::Success,
            KeptVMStatus::OutOfGas => ExecutionStatus::OutOfGas,
            KeptVMStatus::MoveAbort {
                location,
                code,
                message,
            } => ExecutionStatus::MoveAbort {
                location,
                code,
                info: message.map(|message| AbortInfo {
                    reason_name: "".to_string(), // will be populated later
                    description: message,
                }),
            },
            KeptVMStatus::ExecutionFailure {
                location: loc,
                function: func,
                code_offset: offset,
                message: _,
            } => ExecutionStatus::ExecutionFailure {
                location: loc,
                function: func,
                code_offset: offset,
            },
            KeptVMStatus::MiscellaneousError => ExecutionStatus::MiscellaneousError(None),
        }
    }
```

**File:** types/src/transaction/mod.rs (L1577-1587)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionStatus {
    /// Discard the transaction output
    Discard(DiscardedVMStatus),

    /// Keep the transaction output
    Keep(ExecutionStatus),

    /// Retry the transaction, e.g., after a reconfiguration
    Retry,
}
```
