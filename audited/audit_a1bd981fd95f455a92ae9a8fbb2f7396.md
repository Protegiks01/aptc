> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** third_party/move/move-model/bytecode/src/function_target.rs (L435-450)
```rust
    /// Returns all the mentioned locals (in non-spec-only bytecode instructions).
    pub fn get_mentioned_locals(&self) -> BTreeSet<TempIndex> {
        let mut res = BTreeSet::new();
        for bc in self.get_bytecode() {
            if bc.is_spec_only() {
                continue;
            }
            bc.sources()
                .iter()
                .chain(bc.dests().iter())
                .for_each(|local| {
                    res.insert(*local);
                });
        }
        res
    }
```

**File:** third_party/move/move-model/bytecode/src/stackless_bytecode.rs (L607-640)
```rust
    pub fn sources(&self) -> Vec<TempIndex> {
        match self {
            Bytecode::Assign(_, _, src, _) => {
                vec![*src]
            },
            Bytecode::Call(_, _, _, srcs, _) => srcs.clone(),
            Bytecode::Ret(_, srcs) => srcs.clone(),
            Bytecode::Branch(_, _, _, cond) => {
                vec![*cond]
            },
            Bytecode::Abort(_, src, None) => {
                vec![*src]
            },
            Bytecode::Abort(_, src0, Some(src1)) => {
                vec![*src0, *src1]
            },
            Bytecode::Load(_, _, _)
            | Bytecode::Jump(_, _)
            | Bytecode::Label(_, _)
            | Bytecode::Nop(_) => {
                vec![]
            },
            Bytecode::SpecBlock(_, _) => {
                // Specifications are not contributing to read variables
                vec![]
            },
            // Note that for all spec-only instructions, we currently return no sources.
            Bytecode::SaveMem(_, _, _)
            | Bytecode::SaveSpecVar(_, _, _)
            | Bytecode::Prop(_, _, _) => {
                unimplemented!("should not be called on spec-only instructions")
            },
        }
    }
```

**File:** third_party/move/move-model/bytecode/src/stackless_bytecode.rs (L643-669)
```rust
    pub fn dests(&self) -> Vec<TempIndex> {
        match self {
            Bytecode::Assign(_, dst, _, _) => {
                vec![*dst]
            },
            Bytecode::Load(_, dst, _) => {
                vec![*dst]
            },
            Bytecode::Call(_, dsts, _, _, on_abort) => {
                let mut result = dsts.clone();
                if let Some(AbortAction(_, dst)) = on_abort {
                    result.push(*dst);
                }
                result
            },
            Bytecode::Ret(_, _)
            | Bytecode::Branch(_, _, _, _)
            | Bytecode::Jump(_, _)
            | Bytecode::Label(_, _)
            | Bytecode::Abort(_, _, _)
            | Bytecode::Nop(_)
            | Bytecode::SaveMem(_, _, _)
            | Bytecode::SaveSpecVar(_, _, _)
            | Bytecode::SpecBlock(..)
            | Bytecode::Prop(_, _, _) => Vec::new(),
        }
    }
```

**File:** third_party/move/move-model/bytecode/src/stackless_bytecode.rs (L924-1010)
```rust

    /// Return the temporaries this instruction modifies and how the temporaries are modified.
    ///
    /// For a temporary with TempIndex $t, if $t is modified by the instruction and
    /// 1) $t is a value or an immutable reference, it will show up in the first Vec
    /// 2) $t is a mutable reference and only its value is modified, not the reference itself,
    ///    it will show up in the second Vec as ($t, false).
    /// 3) $t is a mutable reference and the reference itself is modified (i.e., the location and
    ///    path it is pointing to), it will show up in the second Vec as ($t, true).
    pub fn modifies(
        &self,
        func_target: &FunctionTarget<'_>,
    ) -> (Vec<TempIndex>, Vec<(TempIndex, bool)>) {
        use BorrowNode::*;
        use Bytecode::*;
        use Operation::*;
        let add_abort = |mut res: Vec<TempIndex>, aa: &Option<AbortAction>| {
            if let Some(AbortAction(_, dest)) = aa {
                res.push(*dest)
            }
            res
        };

        match self {
            Assign(_, dest, _, _) => {
                if func_target.get_local_type(*dest).is_mutable_reference() {
                    // reference assignment completely distorts the reference (value + pointer)
                    (vec![], vec![(*dest, true)])
                } else {
                    // value assignment
                    (vec![*dest], vec![])
                }
            },
            Load(_, dest, _) => {
                // constants can only be values, hence no modifications on the reference
                (vec![*dest], vec![])
            },
            Call(_, _, Operation::WriteBack(LocalRoot(dest), ..), _, aa) => {
                // write-back to a local variable distorts the value
                (add_abort(vec![*dest], aa), vec![])
            },
            Call(_, _, Operation::WriteBack(Reference(dest), ..), _, aa) => {
                // write-back to a reference only distorts the value, but not the pointer itself
                (add_abort(vec![], aa), vec![(*dest, false)])
            },
            Call(_, _, Operation::WriteRef, srcs, aa) => {
                // write-ref only distorts the value of the reference, but not the pointer itself
                (add_abort(vec![], aa), vec![(srcs[0], false)])
            },
            Call(_, dests, Function(..), srcs, aa) => {
                let mut val_targets = vec![];
                let mut mut_targets = vec![];
                for src in srcs {
                    if func_target.get_local_type(*src).is_mutable_reference() {
                        // values in mutable references can be distorted, but pointer stays the same
                        mut_targets.push((*src, false));
                    }
                }
                for dest in dests {
                    if func_target.get_local_type(*dest).is_mutable_reference() {
                        // similar to reference assignment
                        mut_targets.push((*dest, true));
                    } else {
                        // similar to value assignment
                        val_targets.push(*dest);
                    }
                }
                (add_abort(val_targets, aa), mut_targets)
            },
            // *** Double-check that this is in Wolfgang's code
            Call(_, dests, _, _, aa) => {
                let mut val_targets = vec![];
                let mut mut_targets = vec![];
                for dest in dests {
                    if func_target.get_local_type(*dest).is_mutable_reference() {
                        // similar to reference assignment
                        mut_targets.push((*dest, true));
                    } else {
                        // similar to value assignment
                        val_targets.push(*dest);
                    }
                }
                (add_abort(val_targets, aa), mut_targets)
            },
            _ => (vec![], vec![]),
        }
    }
```

**File:** third_party/move/move-model/bytecode/src/reaching_def_analysis.rs (L110-121)
```rust
    fn borrowed_locals(&self, code: &[Bytecode]) -> BTreeSet<TempIndex> {
        use Bytecode::*;
        code.iter()
            .filter_map(|bc| match bc {
                Call(_, _, Operation::BorrowLoc, srcs, _) => Some(srcs[0]),
                Call(_, _, Operation::WriteBack(BorrowNode::LocalRoot(src), ..), ..)
                | Call(_, _, Operation::IsParent(BorrowNode::LocalRoot(src), ..), ..) => Some(*src),
                Call(_, _, Operation::WriteBack(BorrowNode::Reference(src), ..), ..)
                | Call(_, _, Operation::IsParent(BorrowNode::Reference(src), ..), ..) => Some(*src),
                _ => None,
            })
            .collect()
```
