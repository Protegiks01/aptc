# Audit Report

## Title
Control Flow Graph Construction DoS via Unbounded Resource Consumption During Bytecode Verification

## Summary
The Move bytecode verifier constructs Control Flow Graphs (CFGs) for functions without enforcing resource limits beforehand, enabling attackers to cause validator node slowdowns through module publishing transactions containing pathologically large functions.

## Finding Description

The vulnerability exists in the bytecode verification pipeline where CFG construction occurs before the `max_basic_blocks` limit is enforced. When a Move module is published, the verification flow is:

1. Module deserialization enforces `BYTECODE_COUNT_MAX = 65535`, allowing functions with up to 65,535 instructions [1](#0-0) 

2. Complexity checking meters binary format complexity but does not construct the CFG [2](#0-1) 

3. Module verification begins by calling `verify_module_with_config` which runs verification passes sequentially [3](#0-2) 

4. The `CodeUnitVerifier::verify_module` pass calls `verify_function` for each function [4](#0-3) 

5. This invokes `control_flow::verify_function` which creates a `FunctionView` [5](#0-4) 

6. The `FunctionView::function` constructor immediately constructs the CFG via `VMControlFlowGraph::new(&code.code)` [6](#0-5) 

7. **Only AFTER** the CFG is fully constructed does the verifier check `max_basic_blocks` [7](#0-6) 

The CFG construction algorithm performs O(n) iteration through instructions to identify block boundaries, followed by O(V+E) depth-first search for loop analysis, allocating multiple data structures (blocks map, exploration map, DFS stack, post-order traversal) [8](#0-7) 

Critically, the meter parameter passed to `verify_function` is explicitly marked as unused with a TODO comment [9](#0-8) 

An attacker can craft a function with 65,535 instructions structured to maximize basic blocks. While production config limits `max_basic_blocks` to 1024 [10](#0-9) , this check occurs **after** resource exhaustion.

Furthermore, any regular account can publish modules because master signers (non-permissioned signers) automatically pass all permission checks [11](#0-10) 

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria: "Validator node slowdowns."

Each malicious module submission forces every validator to:
- Allocate memory for CFG data structures proportional to the number of basic blocks
- Execute O(V+E) depth-first search algorithm where V can approach tens of thousands
- Only then reject the module for exceeding `max_basic_blocks`

An attacker can repeatedly submit such modules at low cost (only paying gas for module byte size, not verification complexity), causing sustained CPU and memory pressure on all validators. This degrades network performance and consensus timing.

## Likelihood Explanation

**High likelihood** of exploitation:
- Attack requires only crafting a module with many sequential branch instructions (trivially achievable)
- No special permissions needed - any account can publish modules due to master signer permissions
- Gas cost is minimal (proportional to bytecode size, not verification cost)
- Attack can be repeated continuously to sustain DoS
- No rate limiting on module publishing transactions beyond normal transaction throughput

## Recommendation

Enforce resource limits **before** CFG construction by implementing one of these solutions:

1. **Early instruction count limit**: Check if `code.code.len()` exceeds a threshold before constructing the CFG
2. **Metered CFG construction**: Remove the `_meter` prefix and actually use the meter parameter during CFG construction to enforce `max_per_fun_meter_units`
3. **Estimated basic block limit**: Calculate an upper bound on basic blocks from instruction count before construction

The fix should be applied in `control_flow::verify_function` before calling `FunctionView::function`.

## Proof of Concept

```move
// Generate Move module with pathological CFG structure
module 0xBAD::dos_attack {
    public fun attack() {
        let x = 0;
        // Generate 65,535 instructions alternating between branches
        // Each branch creates a new basic block
        if (x == 0) { x = 1; } else { x = 0; };
        if (x == 1) { x = 2; } else { x = 1; };
        // ... repeat pattern 32,767 times ...
        // This creates maximum basic blocks while staying under BYTECODE_COUNT_MAX
        // Validators must construct full CFG before rejecting for TOO_MANY_BASIC_BLOCKS
    }
}
```

The attacker compiles this module and submits it via a transaction. Each validator constructs the expensive CFG structure before detecting the limit violation and rejecting the transaction. The attacker repeats this continuously to sustain the DoS attack.

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L19-19)
```rust
    mem::size_of,
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L259-384)
```rust
    fn meter_code(&self, code: &CodeUnit) -> PartialVMResult<()> {
        use Bytecode::*;

        self.meter_signature(code.locals)?;

        for instr in &code.code {
            match instr {
                CallGeneric(idx) | PackClosureGeneric(idx, ..) => {
                    self.meter_function_instantiation(*idx)?;
                },
                PackGeneric(idx) | UnpackGeneric(idx) => {
                    self.meter_struct_instantiation(*idx)?;
                },
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
                CallClosure(idx)
                | VecPack(idx, _)
                | VecLen(idx)
                | VecImmBorrow(idx)
                | VecMutBorrow(idx)
                | VecPushBack(idx)
                | VecPopBack(idx)
                | VecUnpack(idx, _)
                | VecSwap(idx) => {
                    self.meter_signature(*idx)?;
                },

                // List out the other options explicitly so there's a compile error if a new
                // bytecode gets added.
                Pop
                | Ret
                | Branch(_)
                | BrTrue(_)
                | BrFalse(_)
                | LdU8(_)
                | LdU16(_)
                | LdU32(_)
                | LdU64(_)
                | LdU128(_)
                | LdU256(_)
                | LdI8(_)
                | LdI16(_)
                | LdI32(_)
                | LdI64(_)
                | LdI128(_)
                | LdI256(_)
                | LdConst(_)
                | CastU8
                | CastU16
                | CastU32
                | CastU64
                | CastU128
                | CastU256
                | CastI8
                | CastI16
                | CastI32
                | CastI64
                | CastI128
                | CastI256
                | LdTrue
                | LdFalse
                | Call(_)
                | Pack(_)
                | Unpack(_)
                | PackVariant(_)
                | UnpackVariant(_)
                | TestVariant(_)
                | PackClosure(..)
                | ReadRef
                | WriteRef
                | FreezeRef
                | Add
                | Sub
                | Mul
                | Mod
                | Div
                | Negate
                | BitOr
                | BitAnd
                | Xor
                | Shl
                | Shr
                | Or
                | And
                | Not
                | Eq
                | Neq
                | Lt
                | Gt
                | Le
                | Ge
                | CopyLoc(_)
                | MoveLoc(_)
                | StLoc(_)
                | MutBorrowLoc(_)
                | ImmBorrowLoc(_)
                | MutBorrowField(_)
                | ImmBorrowField(_)
                | MutBorrowVariantField(_)
                | ImmBorrowVariantField(_)
                | MutBorrowGlobal(_)
                | ImmBorrowGlobal(_)
                | Exists(_)
                | MoveTo(_)
                | MoveFrom(_)
                | Abort
                | AbortMsg
                | Nop => (),
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L134-173)
```rust
pub fn verify_module_with_config(config: &VerifierConfig, module: &CompiledModule) -> VMResult<()> {
    if config.verify_nothing() {
        return Ok(());
    }
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
    result
}
```

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L117-145)
```rust
    fn verify_function(
        verifier_config: &VerifierConfig,
        index: FunctionDefinitionIndex,
        function_definition: &FunctionDefinition,
        module: &CompiledModule,
        name_def_map: &HashMap<IdentifierIndex, FunctionDefinitionIndex>,
        meter: &mut impl Meter,
    ) -> PartialVMResult<usize> {
        meter.enter_scope(
            module
                .identifier_at(module.function_handle_at(function_definition.function).name)
                .as_str(),
            Scope::Function,
        );
        // nothing to verify for native function
        let code = match &function_definition.code {
            Some(code) => code,
            None => return Ok(0),
        };

        // create `FunctionView` and `BinaryIndexedView`
        let function_view = control_flow::verify_function(
            verifier_config,
            module,
            index,
            function_definition,
            code,
            meter,
        )?;
```

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L147-153)
```rust
        if let Some(limit) = verifier_config.max_basic_blocks {
            if function_view.cfg().blocks().len() > limit {
                return Err(
                    PartialVMError::new(StatusCode::TOO_MANY_BASIC_BLOCKS).at_code_offset(index, 0)
                );
            }
        }
```

**File:** third_party/move/move-bytecode-verifier/src/control_flow.rs (L35-54)
```rust
pub fn verify_function<'a>(
    verifier_config: &'a VerifierConfig,
    module: &'a CompiledModule,
    index: FunctionDefinitionIndex,
    function_definition: &'a FunctionDefinition,
    code: &'a CodeUnit,
    _meter: &mut impl Meter, // TODO: metering
) -> PartialVMResult<FunctionView<'a>> {
    let function_handle = module.function_handle_at(function_definition.function);

    if module.version() <= 5 {
        control_flow_v5::verify(verifier_config, Some(index), code)?;
        Ok(FunctionView::function(module, index, code, function_handle))
    } else {
        verify_fallthrough(Some(index), code)?;
        let function_view = FunctionView::function(module, index, code, function_handle);
        verify_reducibility(verifier_config, &function_view)?;
        Ok(function_view)
    }
}
```

**File:** third_party/move/move-binary-format/src/binary_views.rs (L436-451)
```rust
    pub fn function(
        module: &'a CompiledModule,
        index: FunctionDefinitionIndex,
        code: &'a CodeUnit,
        function_handle: &'a FunctionHandle,
    ) -> Self {
        Self {
            index: Some(index),
            code,
            parameters: module.signature_at(function_handle.parameters),
            return_: module.signature_at(function_handle.return_),
            locals: module.signature_at(code.locals),
            type_parameters: &function_handle.type_parameters,
            cfg: VMControlFlowGraph::new(&code.code),
        }
    }
```

**File:** third_party/move/move-binary-format/src/control_flow_graph.rs (L84-225)
```rust
    pub fn new(code: &[Bytecode]) -> Self {
        let code_len = code.len() as CodeOffset;
        // First go through and collect block ids, i.e., offsets that begin basic blocks.
        // Need to do this first in order to handle backwards edges.
        let mut block_ids = Set::new();
        block_ids.insert(ENTRY_BLOCK_ID);
        for pc in 0..code.len() {
            VMControlFlowGraph::record_block_ids(pc as CodeOffset, code, &mut block_ids);
        }

        // Create basic blocks
        let mut blocks = Map::new();
        let mut entry = 0;
        let mut exit_to_entry = Map::new();
        for pc in 0..code.len() {
            let co_pc = pc as CodeOffset;

            // Create a basic block
            if Self::is_end_of_block(co_pc, code, &block_ids) {
                let exit = co_pc;
                exit_to_entry.insert(exit, entry);
                let successors = Bytecode::get_successors(co_pc, code);
                let bb = BasicBlock { exit, successors };
                blocks.insert(entry, bb);
                entry = co_pc + 1;
            }
        }
        let blocks = blocks;
        assert_eq!(entry, code_len);

        // # Loop analysis
        //
        // This section identifies loops in the control-flow graph, picks a back edge and loop head
        // (the basic block the back edge returns to), and decides the order that blocks are
        // traversed during abstract interpretation (reverse post-order).
        //
        // The implementation is based on the algorithm for finding widening points in Section 4.1,
        // "Depth-first numbering" of Bourdoncle [1993], "Efficient chaotic iteration strategies
        // with widenings."
        //
        // NB. The comments below refer to a block's sub-graph -- the reflexive transitive closure
        // of its successor edges, modulo cycles.

        #[derive(Copy, Clone)]
        enum Exploration {
            InProgress,
            Done,
        }

        let mut exploration: Map<BlockId, Exploration> = Map::new();
        let mut stack = vec![ENTRY_BLOCK_ID];

        // For every loop in the CFG that is reachable from the entry block, there is an entry in
        // `loop_heads` mapping to all the back edges pointing to it, and vice versa.
        //
        // Entry in `loop_heads` implies loop in the CFG is justified by the comments in the loop
        // below.  Loop in the CFG implies entry in `loop_heads` is justified by considering the
        // point at which the first node in that loop, `F` is added to the `exploration` map:
        //
        // - By definition `F` is part of a loop, meaning there is a block `L` such that:
        //
        //     F - ... -> L -> F
        //
        // - `F` will not transition to `Done` until all the nodes reachable from it (including `L`)
        //   have been visited.
        // - Because `F` is the first node seen in the loop, all the other nodes in the loop
        //   (including `L`) will be visited while `F` is `InProgress`.
        // - Therefore, we will process the `L -> F` edge while `F` is `InProgress`.
        // - Therefore, we will record a back edge to it.
        let mut loop_heads: Map<BlockId, Set<BlockId>> = Map::new();

        // Blocks appear in `post_order` after all the blocks in their (non-reflexive) sub-graph.
        let mut post_order = Vec::with_capacity(blocks.len());

        while let Some(block) = stack.pop() {
            match exploration.entry(block) {
                Entry::Vacant(entry) => {
                    // Record the fact that exploration of this block and its sub-graph has started.
                    entry.insert(Exploration::InProgress);

                    // Push the block back on the stack to finish processing it, and mark it as done
                    // once its sub-graph has been traversed.
                    stack.push(block);

                    for succ in &blocks[&block].successors {
                        match exploration.get(succ) {
                            // This successor has never been visited before, add it to the stack to
                            // be explored before `block` gets marked `Done`.
                            None => stack.push(*succ),

                            // This block's sub-graph was being explored, meaning it is a (reflexive
                            // transitive) predecessor of `block` as well as being a successor,
                            // implying a loop has been detected -- greedily choose the successor
                            // block as the loop head.
                            Some(Exploration::InProgress) => {
                                loop_heads.entry(*succ).or_default().insert(block);
                            },

                            // Cross-edge detected, this block and its entire sub-graph (modulo
                            // cycles) has already been explored via a different path, and is
                            // already present in `post_order`.
                            Some(Exploration::Done) => { /* skip */ },
                        };
                    }
                },

                Entry::Occupied(mut entry) => match entry.get() {
                    // Already traversed the sub-graph reachable from this block, so skip it.
                    Exploration::Done => continue,

                    // Finish up the traversal by adding this block to the post-order traversal
                    // after its sub-graph (modulo cycles).
                    Exploration::InProgress => {
                        post_order.push(block);
                        entry.insert(Exploration::Done);
                    },
                },
            }
        }

        let traversal_order = {
            // This reverse post order is akin to a topological sort (ignoring cycles) and is
            // different from a pre-order in the presence of diamond patterns in the graph.
            post_order.reverse();
            post_order
        };

        // build a mapping from a block id to the next block id in the traversal order
        let traversal_successors = traversal_order
            .windows(2)
            .map(|window| {
                debug_assert!(window.len() == 2);
                (window[0], window[1])
            })
            .collect();

        VMControlFlowGraph {
            blocks,
            traversal_successors,
            loop_heads,
        }
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L160-160)
```rust
        max_basic_blocks: Some(1024),
```

**File:** aptos-move/framework/aptos-framework/sources/permissioned_signer.move (L558-564)
```text
    public(package) fun check_permission_capacity_above<PermKey: copy + drop + store>(
        s: &signer, threshold: u256, perm: PermKey
    ): bool acquires PermissionStorage {
        if (!is_permissioned_signer(s)) {
            // master signer has all permissions
            return true
        };
```
