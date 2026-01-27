# Audit Report

## Title
Move Prover Boogie Backend: Multiple Dereference Bug in GetVariantField Code Generation

## Summary
The Move Prover's Boogie backend contains a code generation bug in the `GetVariantField` operation handler. When generating verification conditions for variant field access with multiple allowed variants, the source dereference operation is incorrectly placed inside the variant iteration loop, causing cumulative multiple dereferences in the generated Boogie code. This produces semantically incorrect verification conditions that could lead to false positives (rejecting valid code) or false negatives (accepting invalid code with type confusion vulnerabilities).

## Finding Description
The `EliminateImmRefsProcessor` transforms `BorrowVariantField` operations into `GetVariantField` operations when the destination is an immutable reference. [1](#0-0) 

Both operations are designed to validate that the struct's variant tag matches one of the expected variants before accessing the field. The transformation correctly preserves all parameters including the `variants` list.

However, there is a critical bug in how the Boogie backend generates verification conditions for `GetVariantField`. In the `BorrowVariantField` implementation, the source is dereferenced once before the variant loop: [2](#0-1) 

But in the `GetVariantField` implementation, the dereference check occurs **inside** the loop: [3](#0-2) 

This causes `src_str` (a mutable variable declared at line 2311) to be repeatedly modified on each iteration when the source is a reference type. For example, with variants [V1, V2]:
- Iteration 1: `src_str` becomes `"$Dereference(src_0)"`
- Iteration 2: `src_str` becomes `"$Dereference($Dereference(src_0))"` ← **incorrect**

This generates semantically invalid Boogie code that double-dereferences the same value.

The bug triggers when:
1. Code borrows an immutable reference to a variant field (which gets transformed to `GetVariantField`)
2. The struct definition has multiple variants with the same field at the same offset
3. The Move Prover runs and generates Boogie verification conditions

This scenario is realistic and documented: [4](#0-3) 

## Impact Explanation
**Severity: Medium** (within the context of verification tooling soundness)

This is **not** a runtime vulnerability in the Aptos blockchain execution. The Move Prover is a development-time verification tool, not part of the consensus, execution, or state management layers. Therefore, this bug cannot be directly exploited by attackers to steal funds, compromise consensus, or cause network partitions.

However, the bug undermines the **soundness of formal verification**:
- **False negatives**: The prover might incorrectly verify code that has type confusion vulnerabilities, potentially allowing unsafe code to be deployed
- **False positives**: The prover might incorrectly reject valid code, causing developer friction

While this could indirectly lead to vulnerable smart contracts being deployed if developers rely solely on the prover, this does not meet the **Critical/High/Medium** severity criteria defined in the Aptos bug bounty program, which focus on direct runtime exploits (funds loss, consensus violations, availability).

## Likelihood Explanation
**Likelihood: High** (for code using multi-variant enums)

The bug will trigger whenever:
- A Move module contains an enum with multiple variants sharing a field at the same offset
- Code borrows an immutable reference to that shared field
- The Move Prover is run on that module

This is a common pattern in Move code with enums, making the bug likely to manifest during verification of real-world contracts.

## Recommendation
Move the dereference check outside the variant iteration loop in `GetVariantField`, matching the pattern used in `BorrowVariantField`:

```rust
GetVariantField(mid, sid, variants, inst, field_offset) => {
    let inst = &self.inst_slice(inst);
    let src = srcs[0];
    let mut src_str = str_local(src);
    // FIX: Dereference ONCE before the loop
    if self.get_local_type(src).is_reference() {
        src_str = format!("$Dereference({})", src_str);
    }
    let dest_str = str_local(dests[0]);
    let struct_env = env.get_module(*mid).into_struct(*sid);
    self.check_intrinsic_select(attr_id, &struct_env);
    let mut else_symbol = "";
    for variant in variants {
        emit!(writer, "{} if (", else_symbol);
        let struct_variant_name = boogie_struct_variant_name(&struct_env, inst, *variant);
        let field_env = struct_env.get_field_by_offset_optional_variant(
            Some(*variant),
            *field_offset,
        );
        let field_sel = boogie_field_sel(&field_env);
        emit!(writer, "{} is {}) {{", src_str, struct_variant_name);
        emitln!(writer, "{} := {}->{};", dest_str, src_str, field_sel);
        emitln!(writer, "}");
        if else_symbol.is_empty() {
            else_symbol = " else ";
        }
    }
    emitln!(writer, "else { call $ExecFailureAbort(); }");
}
```

## Proof of Concept
Create a Move module with a multi-variant enum:

```move
module 0x1::test_enum {
    enum MyEnum {
        V1 { x: u64, y: bool },
        V2 { x: u64, z: address },
    }

    public fun borrow_shared_field(e: &MyEnum): &u64 {
        &e.x  // Field 'x' exists in both V1 and V2 at the same offset
    }
}
```

Run the Move Prover on this module. The generated Boogie code for `borrow_shared_field` will contain double dereferences when checking multiple variants, producing invalid verification conditions.

**Note**: While this is a genuine bug in the Move Prover's Boogie backend, it does **not** constitute a runtime security vulnerability in the Aptos blockchain under the bug bounty criteria. The transformation in `eliminate_imm_refs.rs` itself is semantically correct—both `BorrowVariantField` and `GetVariantField` validate variant tags before field access. The issue is purely in the verification tooling's code generation.

### Citations

**File:** third_party/move/move-prover/bytecode-pipeline/src/eliminate_imm_refs.rs (L110-120)
```rust
                BorrowVariantField(mid, sid, variants, type_actuals, offset)
                    if self.is_imm_ref(dests[0]) =>
                {
                    self.builder.emit(Call(
                        attr_id,
                        dests,
                        GetVariantField(mid, sid, variants, type_actuals, offset),
                        srcs,
                        aa,
                    ));
                },
```

**File:** third_party/move/move-prover/boogie-backend/src/bytecode_translator.rs (L2260-2294)
```rust
                    BorrowVariantField(mid, sid, variants, inst, field_offset) => {
                        let inst = &self.inst_slice(inst);
                        let src_str = str_local(srcs[0]);
                        let deref_src_str = format!("$Dereference({})", src_str);
                        let dest_str = str_local(dests[0]);
                        let struct_env = env.get_module(*mid).into_struct(*sid);
                        self.check_intrinsic_select(attr_id, &struct_env);
                        let mut else_symbol = "";
                        // Need to go through all variants to find the correct field
                        for variant in variants {
                            emit!(writer, "{} if (", else_symbol);
                            let struct_variant_name =
                                boogie_struct_variant_name(&struct_env, inst, *variant);
                            let field_env = struct_env.get_field_by_offset_optional_variant(
                                Some(*variant),
                                *field_offset,
                            );
                            let field_sel = boogie_field_sel(&field_env);
                            emitln!(writer, "{} is {}) {{", deref_src_str, struct_variant_name);
                            emitln!(
                                writer,
                                "{} := $ChildMutation({}, {}, {}->{});",
                                dest_str,
                                src_str,
                                field_offset,
                                deref_src_str,
                                field_sel,
                            );
                            emitln!(writer, "}");
                            if else_symbol.is_empty() {
                                else_symbol = " else ";
                            }
                        }
                        emitln!(writer, "else { call $ExecFailureAbort(); }");
                    },
```

**File:** third_party/move/move-prover/boogie-backend/src/bytecode_translator.rs (L2308-2337)
```rust
                    GetVariantField(mid, sid, variants, inst, field_offset) => {
                        let inst = &self.inst_slice(inst);
                        let src = srcs[0];
                        let mut src_str = str_local(src);
                        let dest_str = str_local(dests[0]);
                        let struct_env = env.get_module(*mid).into_struct(*sid);
                        self.check_intrinsic_select(attr_id, &struct_env);
                        let mut else_symbol = "";
                        // Need to go through all variants to find the correct field
                        for variant in variants {
                            emitln!(writer, "{} if (", else_symbol);
                            if self.get_local_type(src).is_reference() {
                                src_str = format!("$Dereference({})", src_str);
                            };
                            let struct_variant_name =
                                boogie_struct_variant_name(&struct_env, inst, *variant);
                            let field_env = struct_env.get_field_by_offset_optional_variant(
                                Some(*variant),
                                *field_offset,
                            );
                            let field_sel = boogie_field_sel(&field_env);
                            emit!(writer, "{} is {}) {{", src_str, struct_variant_name);
                            emitln!(writer, "{} := {}->{};", dest_str, src_str, field_sel);
                            emitln!(writer, "}");
                            if else_symbol.is_empty() {
                                else_symbol = " else ";
                            }
                        }
                        emitln!(writer, "else { call $ExecFailureAbort(); }");
                    },
```

**File:** third_party/move/move-compiler-v2/src/bytecode_generator.rs (L1718-1748)
```rust
    /// Generate field borrow for fields at the same offset.
    fn gen_borrow_field_same_offset(
        &mut self,
        id: NodeId,
        dest: TempIndex,
        str: QualifiedInstId<StructId>,
        fields: &[FieldId],
        offset: usize,
        src: TempIndex,
    ) {
        let struct_env = self.env().get_struct(str.to_qualified_id());
        debug_assert!(fields
            .iter()
            .all(|id| struct_env.get_field(*id).get_offset() == offset));
        let oper = if struct_env.has_variants() {
            let variants = fields
                .iter()
                .map(|id| {
                    struct_env
                        .get_field(*id)
                        .get_variant()
                        .expect("variant field has variant name")
                })
                .collect_vec();
            BytecodeOperation::BorrowVariantField(str.module_id, str.id, variants, str.inst, offset)
        } else {
            // Regular BorrowField
            BytecodeOperation::BorrowField(str.module_id, str.id, str.inst, offset)
        };
        self.emit_call(id, vec![dest], oper, vec![src])
    }
```
