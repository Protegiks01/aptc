# Audit Report

## Title
Gas Metering Bypass in Native Resource Existence Check Leading to Validator Resource Exhaustion

## Summary
The `native_exists_at` function in the Aptos object module charges base gas before performing storage I/O operations, but charges per-byte gas only after the operation completes. This violates the "charge before execute" principle and allows attackers to cause validators to perform expensive storage reads while paying only 4-5% of the proper gas cost when transactions abort after the I/O operation.

## Finding Description

The vulnerability exists in the gas charging sequence of the `native_exists_at` function. [1](#0-0) 

The function charges `OBJECT_EXISTS_AT_BASE` (919 InternalGas units) before the storage operation at line 84, then calls `context.exists_at()` at line 86 which performs storage I/O through the following call chain:

1. `context.exists_at()` delegates to `native_check_resource_exists()` [2](#0-1) 

2. Which calls `load_resource()` that performs actual storage access [3](#0-2) 

3. Through `load_resource_mut()` [4](#0-3) 

4. Which calls `create_data_cache_entry()` that performs unmetered storage I/O via `resource_resolver.get_resource_bytes_with_metadata_and_layout()` [5](#0-4) 

5. The actual storage read happens in `StorageAdapter::get_any_resource_with_layout()` [6](#0-5) 

After the storage I/O completes and control returns to `native_exists_at`, the per-byte gas is charged at lines 93-96. The gas parameter values show significant costs [7](#0-6) 

Critically, these are noted as "dummy values" that were copied, suggesting improper calibration.

This violates the documented principle in the gas metering code [8](#0-7) 

**Attack Scenario:**

1. Attacker crafts a transaction with precisely calculated gas limit
2. Transaction executes operations to consume most gas
3. When `exists<T>()` is called for a large resource (e.g., 100 bytes):
   - Remaining gas: ~1,000 units
   - Base gas charged: 919 ✓
   - Storage I/O performed (disk read, deserialization) ✓
   - Attempt to charge per-byte: 1,470 + 18,300 = 19,770 ✗
4. Transaction aborts with OUT_OF_GAS [9](#0-8) 
5. Transaction is kept in blockchain with Keep(OutOfGas) status [10](#0-9) 
6. Validator performed expensive I/O but received only 919 gas instead of 20,689 (95.5% under-compensated)

The attacker can repeat this with multiple transactions or loop multiple `exists<T>` calls within a transaction.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria ("Validator node slowdowns"). 

**Resource Exhaustion Attack:**
- An attacker can force validators to perform storage I/O operations (disk reads, database queries, deserialization) while paying only 4-5% of the proper cost
- With max gas of 2,000,000 per transaction, an attacker can trigger ~2,176 such under-compensated storage reads
- Repeated transactions can exhaust validator I/O resources, slowing block processing
- Affects all validators processing the block, potentially impacting consensus liveness

**Economic Attack:**
- For a 100-byte resource: proper cost 20,689 gas, attacker pays 919 gas
- 22.5x cost reduction enables spam attacks
- Violates the fundamental gas metering principle that operations must be charged before execution

## Likelihood Explanation

**High Likelihood** - Attack is practical and easily executable:

1. **No Special Access Required:** Any user can submit transactions calling `object::exists_at<T>()` on arbitrary addresses
2. **Precise Gas Control:** Attackers can calculate exact gas consumption through profiling to hit the vulnerability window
3. **Repeatable:** Can be executed in loops within transactions or across multiple transactions
4. **Economically Viable:** 22.5x cost reduction makes the attack profitable
5. **Detection Difficulty:** Legitimate transactions also call `exists<T>()`, making malicious transactions blend in

The attack complexity is low - an attacker needs only:
- Deploy a Move module with a loop calling `exists<T>` on various addresses
- Calculate gas consumption to ensure abortion at the per-byte charge
- Submit transactions with calibrated gas limits

## Recommendation

Charge all gas costs (base + per-item + per-byte) BEFORE performing the storage I/O operation. This requires either:

1. **Pessimistic Charging:** Charge for a maximum expected resource size upfront, then refund excess gas after the operation
2. **Two-Phase Approach:** Perform a lightweight metadata-only check to determine size, charge appropriately, then perform the full load
3. **Caching with Upfront Charge:** Modify the storage resolver interface to return size information without loading the full resource data

Example fix for approach 1:
```rust
fn native_exists_at(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // ... existing setup ...
    
    // Charge pessimistically for maximum expected size (e.g., 1KB)
    let max_estimated_bytes = NumBytes::new(1024);
    context.charge(
        OBJECT_EXISTS_AT_BASE + 
        OBJECT_EXISTS_AT_PER_ITEM_LOADED + 
        OBJECT_EXISTS_AT_PER_BYTE_LOADED * max_estimated_bytes
    )?;
    
    let (exists, num_bytes) = context.exists_at(address, type_)?;
    
    // Refund excess gas if resource was smaller
    if let Some(actual_bytes) = num_bytes {
        if actual_bytes < max_estimated_bytes {
            let excess = OBJECT_EXISTS_AT_PER_BYTE_LOADED * (max_estimated_bytes - actual_bytes);
            context.refund(excess)?;
        }
    } else {
        // Resource doesn't exist or was cached, refund per-item + per-byte
        context.refund(
            OBJECT_EXISTS_AT_PER_ITEM_LOADED + 
            OBJECT_EXISTS_AT_PER_BYTE_LOADED * max_estimated_bytes
        )?;
    }
    
    Ok(smallvec![Value::bool(exists)])
}
```

## Proof of Concept

```move
module attacker::exploit {
    use std::signer;
    use aptos_framework::object;
    
    struct LargeResource has key {
        data: vector<u8>
    }
    
    public entry fun setup_target(account: &signer) {
        let data = vector::empty<u8>();
        let i = 0;
        while (i < 100) {
            vector::push_back(&mut data, 0u8);
            i = i + 1;
        };
        move_to(account, LargeResource { data });
    }
    
    public entry fun exploit_exists_at(account: &signer, target: address) {
        // Consume gas to leave just enough for base charge
        let i = 0;
        while (i < 1000) {
            i = i + 1;
        };
        
        // This will charge 919 base gas, perform I/O, then abort on per-byte charge
        // Validator does 20,689 gas worth of work but only gets paid 919
        let _ = object::exists_at<LargeResource>(target);
    }
}
```

**Notes:**
- The vulnerability is specific to the `object::exists_at` native function, not the general Move VM `exists<T>` bytecode operation which only charges a flat fee [11](#0-10) 
- Resource caching in the data cache means subsequent accesses to the same resource within a transaction won't trigger additional I/O, but attackers can target different resources to maximize impact
- The comment noting these as "dummy values" suggests the gas parameters may not be properly calibrated for production use

### Citations

**File:** aptos-move/framework/src/natives/object.rs (L73-100)
```rust
fn native_exists_at(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    safely_assert_eq!(ty_args.len(), 1);
    safely_assert_eq!(args.len(), 1);

    let type_ = &ty_args[0];
    let address = safely_pop_arg!(args, AccountAddress);

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
    }

    Ok(smallvec![Value::bool(exists)])
}
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

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L255-327)
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

        let function_value_extension = FunctionValueExtensionAdapter { module_storage };
        let (layout, contains_delayed_fields) = layout_with_delayed_fields.unpack();
        let value = match data {
            Some(blob) => {
                let max_value_nest_depth = function_value_extension.max_value_nest_depth();
                let val = ValueSerDeContext::new(max_value_nest_depth)
                    .with_func_args_deserialization(&function_value_extension)
                    .with_delayed_fields_serde()
                    .deserialize(&blob, &layout)
                    .ok_or_else(|| {
                        let msg = format!(
                            "Failed to deserialize resource {} at {}!",
                            struct_tag.to_canonical_string(),
                            addr
                        );
                        PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_RESOURCE)
                            .with_message(msg)
                    })?;
                GlobalValue::cached(val)?
            },
            None => GlobalValue::none(),
        };

        let entry = DataCacheEntry {
            struct_tag,
            layout,
            contains_delayed_fields,
            value,
        };
        Ok((entry, NumBytes::new(bytes_loaded as u64)))
    }
```

**File:** aptos-move/aptos-vm/src/data_cache.rs (L98-129)
```rust
    fn get_any_resource_with_layout(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
        metadata: &[Metadata],
        maybe_layout: Option<&MoveTypeLayout>,
    ) -> PartialVMResult<(Option<Bytes>, usize)> {
        let resource_group = get_resource_group_member_from_metadata(struct_tag, metadata);
        if let Some(resource_group) = resource_group {
            let key = StateKey::resource_group(address, &resource_group);
            let buf =
                self.resource_group_view
                    .get_resource_from_group(&key, struct_tag, maybe_layout)?;

            let first_access = self.accessed_groups.borrow_mut().insert(key.clone());
            let group_size = if first_access {
                self.resource_group_view.resource_group_size(&key)?.get()
            } else {
                0
            };

            let buf_size = resource_size(&buf);
            Ok((buf, buf_size + group_size as usize))
        } else {
            let state_key = resource_state_key(address, struct_tag)?;
            let buf = self
                .executor_view
                .get_resource_bytes(&state_key, maybe_layout)?;
            let buf_size = resource_size(&buf);
            Ok((buf, buf_size))
        }
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

**File:** aptos-move/aptos-native-interface/src/context.rs (L69-78)
```rust
    /// Always remember: first charge gas, then execute!
    ///
    /// In other words, this function **MUST** always be called **BEFORE** executing **any**
    /// gas-metered operation or library call within a native function.
    #[must_use = "must always propagate the error returned by this function to the native function that called it using the ? operator"]
    #[inline(always)]
    pub fn charge(
        &mut self,
        abstract_amount: impl GasExpression<NativeGasParameters, Unit = InternalGasUnit>,
    ) -> SafeNativeResult<()> {
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L86-90)
```rust
        if self.has_direct_gas_meter_access_in_native_context() {
            self.gas_meter()
                .charge_native_execution(amount)
                .map_err(LimitExceededError::from_err)?;
            Ok(())
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

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L444-454)
```rust
    fn charge_exists(
        &mut self,
        is_generic: bool,
        _ty: impl TypeView,
        _exists: bool,
    ) -> PartialVMResult<()> {
        match is_generic {
            false => self.algebra.charge_execution(EXISTS_BASE),
            true => self.algebra.charge_execution(EXISTS_GENERIC_BASE),
        }
    }
```
