# Audit Report

## Title
VerifierConfig `max_basic_blocks` Limit Bypass Enables Resource Exhaustion via Expensive Pre-Check Operations

## Summary
The `max_basic_blocks` limit in `VerifierConfig` is enforced AFTER expensive control flow graph analysis operations have already been performed. An attacker can submit Move modules with arbitrarily large numbers of basic blocks that exceed configured limits, causing validators to perform costly memory allocations and graph traversals before the limit check rejects the module.

## Finding Description
The Move bytecode verification pipeline enforces limits through `VerifierConfig` to prevent resource exhaustion. However, the `max_basic_blocks` limit is applied AFTER expensive operations, creating a resource exhaustion vector.

**Vulnerable Execution Flow:**

1. `CodeUnitVerifier::verify_function` calls `control_flow::verify_function` without checking basic block limits first [1](#0-0) 

2. Inside `control_flow::verify_function`, for bytecode version > 5, it creates a `FunctionView` and calls `verify_reducibility` [2](#0-1) 

3. `verify_reducibility` immediately creates `LoopSummary::new(function_view.cfg())` [3](#0-2) 

4. `LoopSummary::new` performs expensive operations on the UNCHECKED CFG:
   - Allocates four vectors sized to `num_blocks` (blocks, descs, backs, preds)
   - Performs complete depth-first traversal of the entire CFG
   - Builds spanning tree and categorizes all edges [4](#0-3) 

5. ONLY AFTER `control_flow::verify_function` returns does the code check `max_basic_blocks` [5](#0-4) 

**Attack Scenario:**
An attacker crafts a Move module with 100,000 basic blocks (chain of Branch instructions). Production configuration sets `max_basic_blocks = 1024` [6](#0-5) 

When validators verify this module:
- `LoopSummary::new` allocates 4 vectors × 100,000 elements = significant memory
- DFS traversal processes all 100,000 blocks with full edge categorization
- Loop analysis iterates through nodes
- THEN the check rejects with `TOO_MANY_BASIC_BLOCKS`

The expensive operations occur before limit enforcement, enabling resource exhaustion.

**Critical Finding:** The meter parameter passed to `control_flow::verify_function` is unused (prefixed with underscore, marked as `TODO: metering`) [7](#0-6) 

## Impact Explanation
This vulnerability qualifies as **High Severity** per Aptos Bug Bounty program criteria.

**Direct Match to High Severity Category:**
"Validator Node Slowdowns (High): Significant performance degradation affecting consensus, DoS through resource exhaustion"

**Concrete Impact:**
1. **Resource Exhaustion:** Validators waste CPU cycles and memory on modules that will be rejected
2. **DoS Vector:** Attacker can repeatedly submit oversized modules, forcing expensive verification on each attempt
3. **Network Degradation:** Multiple validators performing expensive verification simultaneously affects block production times
4. **Limit Bypass:** The purpose of `VerifierConfig` limits is defeated when expensive operations precede enforcement

**Why Not Critical:**
- Does not cause consensus violations or safety breaks
- Does not enable fund theft or state corruption
- Validators eventually reject the module (self-healing)
- Does not require hardfork to recover

**Why High (Not Medium):**
- Affects core validator operations (bytecode verification)
- Can impact multiple validators simultaneously
- Enables sustained resource exhaustion attacks
- Affects network-critical verification path

## Likelihood Explanation
**High Likelihood:**

1. **Low Attacker Complexity:** Creating modules with excessive basic blocks is trivial - chain Branch instructions
2. **No Privileged Access Required:** Any account with sufficient gas to submit a module publishing transaction can exploit
3. **Guaranteed Trigger:** Vulnerability triggers deterministically on every verification attempt
4. **Production Configuration Vulnerable:** Production config sets `max_basic_blocks = 1024` but expensive operations happen before this check
5. **No Metering Protection:** Control flow verification does not utilize the meter parameter (marked with underscore and TODO)
6. **Multiple Attack Vectors:** Same issue exists for scripts with `max_basic_blocks_in_script` check

## Recommendation
**Fix 1: Early Limit Check**
Check `max_basic_blocks` BEFORE calling expensive operations. In `control_flow::verify_function`, immediately after creating `FunctionView`, check the CFG size:

```rust
pub fn verify_function<'a>(
    verifier_config: &'a VerifierConfig,
    module: &'a CompiledModule,
    index: FunctionDefinitionIndex,
    function_definition: &'a FunctionDefinition,
    code: &'a CodeUnit,
    _meter: &mut impl Meter,
) -> PartialVMResult<FunctionView<'a>> {
    // ... existing code ...
    let function_view = FunctionView::function(module, index, code, function_handle);
    
    // CHECK BEFORE EXPENSIVE OPERATIONS
    if let Some(limit) = verifier_config.max_basic_blocks {
        if function_view.cfg().blocks().len() > limit {
            return Err(PartialVMError::new(StatusCode::TOO_MANY_BASIC_BLOCKS)
                .at_code_offset(index, 0));
        }
    }
    
    verify_reducibility(verifier_config, &function_view)?;
    Ok(function_view)
}
```

**Fix 2: Implement Metering**
Implement the TODO for metering in `control_flow::verify_function` to charge for CFG operations before they occur.

## Proof of Concept
A complete PoC would require:
1. Crafting a Move module with 100,000 basic blocks (chain of conditional branches)
2. Serializing and submitting via module publishing transaction
3. Measuring validator resource consumption during verification
4. Observing rejection only after expensive LoopSummary operations complete

The vulnerability is confirmed through code analysis showing the ordering of operations.

## Notes
This is a design flaw where defensive limits are applied too late in the verification pipeline. The expensive CFG analysis operations (O(n) memory allocation and O(n) DFS traversal where n = number of basic blocks) occur before limit checks, defeating the purpose of `max_basic_blocks`. While validators eventually reject oversized modules, the resource consumption has already occurred, enabling repeated DoS attacks.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L138-145)
```rust
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

**File:** third_party/move/move-bytecode-verifier/src/control_flow.rs (L41-41)
```rust
    _meter: &mut impl Meter, // TODO: metering
```

**File:** third_party/move/move-bytecode-verifier/src/control_flow.rs (L48-53)
```rust
    } else {
        verify_fallthrough(Some(index), code)?;
        let function_view = FunctionView::function(module, index, code, function_handle);
        verify_reducibility(verifier_config, &function_view)?;
        Ok(function_view)
    }
```

**File:** third_party/move/move-bytecode-verifier/src/control_flow.rs (L126-126)
```rust
    let summary = LoopSummary::new(function_view.cfg());
```

**File:** third_party/move/move-bytecode-verifier/src/loop_summary.rs (L74-146)
```rust
        let num_blocks = cfg.num_blocks() as usize;

        // Fields in LoopSummary that are filled via a depth-first traversal of `cfg`.
        let mut blocks = vec![0; num_blocks];
        let mut descs = vec![0; num_blocks];
        let mut backs = vec![vec![]; num_blocks];
        let mut preds = vec![vec![]; num_blocks];

        let mut next_node = NodeId(0);

        let root_block = cfg.entry_block_id();
        let root_node = next_node.bump();

        let mut exploration = BTreeMap::new();
        blocks[usize::from(root_node)] = root_block;
        exploration.insert(root_block, InProgress(root_node));

        let mut stack: Vec<Frontier> = cfg
            .successors(root_block)
            .iter()
            .map(|succ| Visit {
                from_node: root_node,
                to_block: *succ,
            })
            .collect();

        while let Some(action) = stack.pop() {
            match action {
                Finish {
                    block,
                    node_id,
                    parent,
                } => {
                    descs[usize::from(parent)] += 1 + descs[usize::from(node_id)];
                    *exploration.get_mut(&block).unwrap() = Done(node_id);
                },

                Visit {
                    from_node,
                    to_block,
                } => match exploration.entry(to_block) {
                    Entry::Occupied(entry) => match entry.get() {
                        // Cyclic back edge detected by re-visiting `to` while still processing its
                        // children.
                        InProgress(to_node) => backs[usize::from(*to_node)].push(from_node),

                        // Cross edge detected by re-visiting `to` after it and its children have
                        // been processed.
                        Done(to_node) => preds[usize::from(*to_node)].push(from_node),
                    },

                    // Visiting `to` for the first time: `from` must be its parent in the depth-
                    // -first spanning tree, and we should continue exploring its successors.
                    Entry::Vacant(entry) => {
                        let to_node = next_node.bump();
                        entry.insert(InProgress(to_node));
                        blocks[usize::from(to_node)] = to_block;
                        preds[usize::from(to_node)].push(from_node);

                        stack.push(Finish {
                            block: to_block,
                            node_id: to_node,
                            parent: from_node,
                        });

                        stack.extend(cfg.successors(to_block).iter().map(|succ| Visit {
                            from_node: to_node,
                            to_block: *succ,
                        }));
                    },
                },
            }
        }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L160-160)
```rust
        max_basic_blocks: Some(1024),
```
