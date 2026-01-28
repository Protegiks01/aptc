# Audit Report

## Title
Variant Field Instantiations Bypass Module Complexity Budget Checks

## Summary
The module complexity metering system fails to account for `variant_field_instantiations` and `struct_variant_instantiations` tables, allowing attackers to publish modules with unbounded complexity that bypass intended resource limits, leading to validator node slowdowns through resource exhaustion during module loading.

## Finding Description

The Move binary format complexity checker in `check_module_complexity()` is responsible for ensuring published modules do not exceed complexity budgets to prevent resource exhaustion. However, this function has a critical omission in its metering logic. [1](#0-0) 

The function meters regular `field_instantiations` via `meter_field_instantiations()` at line 411, but completely omits metering for `variant_field_instantiations` and `struct_variant_instantiations` tables, despite these tables existing in the module structure. [2](#0-1) 

Each entry in these tables contains a `type_parameters: SignatureIndex` field that can point to arbitrarily complex nested type signatures: [3](#0-2) [4](#0-3) 

While individual variant field instantiations ARE metered when used in bytecode instructions: [5](#0-4) [6](#0-5) [7](#0-6) 

The tables themselves are never iterated and metered during the module-level complexity check, unlike regular field instantiations which have a dedicated table-level metering function: [8](#0-7) 

During module publishing, the complexity check is invoked with a budget based on blob size: [9](#0-8) 

Critically, during module loading, these unmetered tables ARE processed, iterating through all entries and cloning complex type signatures: [10](#0-9) [11](#0-10) 

An attacker can exploit this by creating a module with many entries in these tables (e.g., 1000+ entries), each pointing to deeply nested generic type signatures. The module passes complexity checks since only the signatures themselves are metered once, but during loading at lines 256 and 366, each table entry causes the complex signature to be cloned and processed, multiplying the resource consumption by the number of table entries.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program as it enables **validator node slowdowns through resource exhaustion**.

The complexity budget exists specifically to prevent modules from consuming excessive resources during loading and verification. By bypassing this check, an attacker can cause memory exhaustion and excessive CPU usage on validator nodes processing the module publish transaction, potentially causing validator crashes or severe performance degradation affecting consensus.

This breaks the Resource Limits invariant requiring all operations to respect computational limits, and the Move VM Safety invariant requiring bytecode to respect memory constraints.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

1. **Low barrier to entry**: Any user can publish a module
2. **Easy to exploit**: Creating modules with many variant field instantiations is straightforward using Move compiler tools
3. **Hard to detect**: Malicious modules appear normal in size but hide complexity in unmetered tables
4. **Network-wide impact**: All validators processing the transaction are affected
5. **No special privileges required**: Standard module publishing capability

The only cost is the transaction fee for module publishing, minimal compared to potential network disruption.

## Recommendation

Add table-level metering functions for variant field and struct variant instantiations, similar to the existing `meter_field_instantiations()` pattern:

```rust
fn meter_variant_field_instantiations(&self) -> PartialVMResult<()> {
    let variant_field_insts = self.resolver.variant_field_instantiations().ok_or_else(|| ...)?;
    for idx in 0..variant_field_insts.len() {
        self.meter_variant_field_instantiation(VariantFieldInstantiationIndex(idx as u16))?;
    }
    Ok(())
}

fn meter_struct_variant_instantiations(&self) -> PartialVMResult<()> {
    let struct_variant_insts = self.resolver.struct_variant_instantiations().ok_or_else(|| ...)?;
    for idx in 0..struct_variant_insts.len() {
        self.meter_struct_variant_instantiation(StructVariantInstantiationIndex(idx as u16))?;
    }
    Ok(())
}
```

Then call these functions in `check_module_complexity()` after line 411.

## Proof of Concept

A PoC would construct a `CompiledModule` with 1000+ entries in `variant_field_instantiations`, each referencing a signature with deeply nested types (100+ levels of `Vec<Vec<...>>`). The module would pass `check_module_complexity()` but cause significant resource consumption during `Module::new()` when loading, demonstrating the bypass.

## Notes

This is a logic vulnerability where the metering system has an architectural gap - the individual metering functions exist but are never called at the table level during module complexity checks, only during bytecode instruction processing. This creates an exploitable asymmetry between what is checked and what is processed during loading.

### Citations

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L139-153)
```rust
    fn meter_struct_variant_instantiation(
        &self,
        struct_inst_idx: StructVariantInstantiationIndex,
    ) -> PartialVMResult<()> {
        let struct_variant_insts =
            self.resolver
                .struct_variant_instantiations()
                .ok_or_else(|| {
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                        "Can't get enum type instantiation -- not a module.".to_string(),
                    )
                })?;
        let struct_variant_inst = safe_get_table(struct_variant_insts, struct_inst_idx.0)?;
        self.meter_signature(struct_variant_inst.type_parameters)
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L180-195)
```rust
    fn meter_variant_field_instantiation(
        &self,
        variant_field_inst_idx: VariantFieldInstantiationIndex,
    ) -> PartialVMResult<()> {
        let variant_field_insts =
            self.resolver
                .variant_field_instantiations()
                .ok_or_else(|| {
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                        "Can't get variant field instantiations -- not a module.".to_string(),
                    )
                })?;
        let field_inst = safe_get_table(variant_field_insts, variant_field_inst_idx.0)?;

        self.meter_signature(field_inst.type_parameters)
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L197-207)
```rust
    fn meter_field_instantiations(&self) -> PartialVMResult<()> {
        let field_insts = self.resolver.field_instantiations().ok_or_else(|| {
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("Can't get field instantiations -- not a module.".to_string())
        })?;

        for field_inst_idx in 0..field_insts.len() {
            self.meter_field_instantiation(FieldInstantiationIndex(field_inst_idx as u16))?;
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L272-287)
```rust
                PackVariantGeneric(idx) | UnpackVariantGeneric(idx) | TestVariantGeneric(idx) => {
                    self.meter_struct_variant_instantiation(*idx)?;
                },
                ExistsGeneric(idx)
                | MoveFromGeneric(idx)
                | MoveToGeneric(idx)
                | ImmBorrowGlobalGeneric(idx)
                | MutBorrowGlobalGeneric(idx) => {
                    self.meter_struct_instantiation(*idx)?;
                },
                ImmBorrowFieldGeneric(idx) | MutBorrowFieldGeneric(idx) => {
                    self.meter_field_instantiation(*idx)?;
                },
                ImmBorrowVariantFieldGeneric(idx) | MutBorrowVariantFieldGeneric(idx) => {
                    self.meter_variant_field_instantiation(*idx)?;
                },
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L401-420)
```rust
pub fn check_module_complexity(module: &CompiledModule, budget: u64) -> PartialVMResult<u64> {
    let meter = BinaryComplexityMeter {
        resolver: BinaryIndexedView::Module(module),
        cached_signature_costs: RefCell::new(BTreeMap::new()),
        balance: RefCell::new(budget),
    };

    meter.meter_signatures()?;
    meter.meter_function_instantiations()?;
    meter.meter_struct_def_instantiations()?;
    meter.meter_field_instantiations()?;

    meter.meter_function_handles()?;
    meter.meter_struct_handles()?;
    meter.meter_function_defs()?;
    meter.meter_struct_defs()?;

    let used = budget - *meter.balance.borrow();
    Ok(used)
}
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L541-544)
```rust
pub struct StructVariantInstantiation {
    pub handle: StructVariantHandleIndex,
    pub type_parameters: SignatureIndex,
}
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L585-588)
```rust
pub struct VariantFieldInstantiation {
    pub handle: VariantFieldHandleIndex,
    pub type_parameters: SignatureIndex,
}
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L3474-3479)
```rust
    /// Since bytecode version 7: variant related handle tables
    pub struct_variant_handles: Vec<StructVariantHandle>,
    pub struct_variant_instantiations: Vec<StructVariantInstantiation>,
    pub variant_field_handles: Vec<VariantFieldHandle>,
    pub variant_field_instantiations: Vec<VariantFieldInstantiation>,
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1554-1559)
```rust
        for (module, blob) in modules.iter().zip(bundle.iter()) {
            // TODO(Gas): Make budget configurable.
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
        }
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L250-259)
```rust
        for struct_variant_inst in module.struct_variant_instantiations() {
            let variant = &struct_variant_infos[struct_variant_inst.handle.0 as usize];
            struct_variant_instantiation_infos.push(StructVariantInfo {
                field_count: variant.field_count,
                variant: variant.variant,
                definition_struct_type: variant.definition_struct_type.clone(),
                instantiation: signature_table[struct_variant_inst.type_parameters.0 as usize]
                    .clone(),
            })
        }
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L361-380)
```rust
        for variant_inst in module.variant_field_instantiations() {
            let variant_info = &variant_field_infos[variant_inst.handle.0 as usize];
            let definition_struct_type = variant_info.definition_struct_type.clone();
            let variants = variant_info.variants.clone();
            let offset = variant_info.offset;
            let instantiation = signature_table[variant_inst.type_parameters.0 as usize].clone();
            // We can select one representative variant for finding the field type, all
            // must have the same type as the verifier ensured.
            let uninstantiated_ty = definition_struct_type
                .field_at(Some(variants[0]), offset)?
                .1
                .clone();
            variant_field_instantiation_infos.push(VariantFieldInfo {
                offset,
                uninstantiated_field_ty: uninstantiated_ty,
                variants,
                definition_struct_type,
                instantiation,
            });
        }
```
