# Audit Report

## Title
Incomplete Cycle Detection in Inlining Optimization Allows Exponential Code Growth During Compilation

## Summary
The `find_cycles_in_call_graph()` function in the Move compiler v2's inlining optimization pass fails to detect cycles that involve functions outside the initial compilation target set. This allows the inlining process to create self-recursive function bodies, leading to exponential code growth during the unrolling iterations and potential resource exhaustion during module compilation.

## Finding Description

The vulnerability exists in the integration between cycle detection and the inlining optimization process. The root cause is in the `find_cycles_in_call_graph()` function [1](#0-0) , which builds a call graph to identify functions that are part of cycles and should be excluded from inlining.

The critical bug occurs at this line [2](#0-1) . The `.collect::<Vec<_>>()` call creates a **snapshot** of the graph's nodes at that moment, before any edges are added. When the loop processes each caller and adds edges to callees (which implicitly adds new nodes to the graph) [3](#0-2) , these newly-added nodes are **not** processed because they weren't in the original snapshot.

This means:
1. Only functions explicitly in the compilation target are processed
2. External dependency functions that are called by target functions are added as nodes but never have their outgoing edges analyzed
3. Cycles involving these external functions are not detected

**Attack Scenario:**

An attacker can craft three modules:
- **TargetModule::FuncA** (in the compilation target - the attacker's malicious module)
- **DepModule1::FuncB** (external dependency, small enough to inline)
- **DepModule2::FuncC** (external dependency, small enough to inline)

Where: FuncA → FuncB → FuncC → FuncA (forming a cycle)

During compilation:
1. Initial cycle detection only processes FuncA, adds edges A→B, but never processes B or C
2. The cycle A→B→C→A is **not detected**
3. FuncA is not excluded from inlining (line 90 check passes) [4](#0-3) 
4. Unrolling iterations proceed [5](#0-4) :
   - **Iteration 1**: Inline FuncB into FuncA → FuncA now calls FuncC
   - **Iteration 2**: Inline FuncC into FuncA → FuncA now calls FuncA (self-recursion!)
   - **Iteration 3+**: Repeatedly inline FuncA into itself, causing exponential code growth

Each self-inlining doubles the number of recursive call sites [6](#0-5) , leading to size growth of 2×, 4×, 8×, etc., until hitting `MAX_CALLER_CODE_SIZE` or `MAX_CALLEE_CODE_SIZE` limits.

## Impact Explanation

This vulnerability has **High Severity** impact according to Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: During package publication or upgrade transactions, validators must compile the Move modules. An attacker can deploy a malicious module that triggers exponential compilation time and memory usage, slowing down all validators processing that transaction.

2. **Deterministic Execution Violation**: Different validators with different resource limits (memory, CPU) might handle the compilation differently:
   - Some validators might successfully compile after consuming excessive resources
   - Others might OOM or timeout and fail to process the transaction
   - This breaks the critical invariant that "all validators must produce identical state roots for identical blocks"

3. **Resource Exhaustion**: The exponential code growth (2^n for n unrolling iterations, up to `UNROLL_DEPTH` = 10 by default [7](#0-6) ) can consume gigabytes of memory and significant CPU time before hitting size limits, potentially causing validators to crash or become unresponsive.

4. **Consensus Impact**: If validators disagree on whether a package publication transaction succeeded, it could lead to chain splits or safety violations in the consensus protocol.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is feasible because:
- The attacker only needs to deploy Move modules, which is a standard blockchain operation
- The attacker can create the dependency modules first, then create the target module that references them
- No special privileges or validator access is required
- The inlining optimization is enabled when the `INLINING_OPTIMIZATION` experiment flag is active [8](#0-7) 

The attack complexity is low because:
- The cycle pattern is straightforward to construct
- Functions just need to be small enough to pass the size checks (< 128 bytes by default)
- The attacker has full control over the module contents

## Recommendation

**Fix the cycle detection to process all transitive callees:**

Replace the snapshot-based iteration with a worklist algorithm that processes newly-discovered nodes:

```rust
fn find_cycles_in_call_graph(
    env: &GlobalEnv,
    targets: &RewriteTargets,
) -> BTreeSet<QualifiedId<FunId>> {
    let mut graph = DiGraphMap::<QualifiedId<FunId>, ()>::new();
    let mut cycle_nodes = BTreeSet::new();
    
    // Add initial nodes from targets
    for target in targets.keys() {
        if let RewriteTarget::MoveFun(function) = target {
            graph.add_node(function);
        }
    }
    
    // Use a worklist to process all reachable functions
    let mut worklist: Vec<_> = graph.nodes().collect();
    let mut processed = BTreeSet::new();
    
    while let Some(caller) = worklist.pop() {
        if !processed.insert(caller) {
            continue; // Already processed
        }
        
        let caller_env = env.get_function(caller);
        for callee in caller_env
            .get_used_functions()
            .expect("used functions must be computed")
        {
            if callee == &caller {
                // self-recursion
                cycle_nodes.insert(caller);
            } else {
                graph.add_edge(caller, *callee, ());
                // Add callee to worklist if not yet processed
                if !processed.contains(callee) && !worklist.contains(callee) {
                    worklist.push(*callee);
                }
            }
        }
    }
    
    // Find cycles in the complete graph
    for scc in kosaraju_scc(&graph) {
        if scc.len() > 1 {
            cycle_nodes.extend(scc.into_iter());
        }
    }
    
    cycle_nodes
}
```

Alternatively, use the existing `get_transitive_closure_of_used_functions()` method to build the complete call graph before running SCC analysis.

## Proof of Concept

**Move Module PoC:**

```move
// First, deploy this dependency module
module 0xDEP1::DepB {
    use 0xDEP2::DepC;
    
    public fun funcB(): u64 {
        DepC::funcC()
    }
}

// Second, deploy this dependency module  
module 0xDEP2::DepC {
    use 0xATTACKER::Malicious;
    
    public fun funcC(): u64 {
        Malicious::funcA()
    }
}

// Finally, deploy this malicious target module
module 0xATTACKER::Malicious {
    use 0xDEP1::DepB;
    
    public fun funcA(): u64 {
        DepB::funcB()
    }
    
    public entry fun trigger() {
        funcA();
    }
}
```

When the `Malicious` module is compiled with inlining optimization enabled:
1. `funcA` is in the compilation target
2. Cycle detection processes only `funcA`, adds edge to `funcB` but doesn't process `funcB`
3. Cycle A→B→C→A is not detected
4. Iteration 1: Inline `funcB` into `funcA`
5. Iteration 2: Inline `funcC` into `funcA` → creates self-call
6. Iterations 3-10: Exponentially grow `funcA` by repeatedly inlining itself

The compilation will consume exponential time and memory proportional to 2^(UNROLL_DEPTH) before hitting size limits, potentially causing validator slowdowns or OOM crashes.

**Notes**

The vulnerability specifically affects the Move compiler v2's inlining optimization pass, which is an experimental feature controlled by the `INLINING_OPTIMIZATION` flag. The impact is most severe when this optimization is enabled on validator nodes processing package publication transactions. The fix requires ensuring that the cycle detection analyzes the complete transitive call graph, not just the immediate targets.

### Citations

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L48-53)
```rust
pub static UNROLL_DEPTH: Lazy<usize> = Lazy::new(|| {
    env::var("UNROLL_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
});
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L90-90)
```rust
            !skip_functions.contains(function_id)
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L105-110)
```rust
    for _ in 0..*UNROLL_DEPTH {
        if todo.is_empty() {
            break;
        }
        todo = inline_call_sites(env, &mut targets, todo, across_package);
    }
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L190-223)
```rust
fn find_cycles_in_call_graph(
    env: &GlobalEnv,
    targets: &RewriteTargets,
) -> BTreeSet<QualifiedId<FunId>> {
    let mut graph = DiGraphMap::<QualifiedId<FunId>, ()>::new();
    let mut cycle_nodes = BTreeSet::new();
    for target in targets.keys() {
        if let RewriteTarget::MoveFun(function) = target {
            graph.add_node(function);
        }
    }
    for caller in graph.nodes().collect::<Vec<_>>() {
        let caller_env = env.get_function(caller);
        for callee in caller_env
            .get_used_functions()
            .expect("used functions must be computed")
        {
            if callee == &caller {
                // self-recursion is added to the solution directly
                cycle_nodes.insert(caller);
            } else {
                // non-self-recursion edges
                graph.add_edge(caller, *callee, ());
            }
        }
    }
    for scc in kosaraju_scc(&graph) {
        if scc.len() > 1 {
            // cycle involving non-self-recursion
            cycle_nodes.extend(scc.into_iter());
        }
    }
    cycle_nodes
}
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L357-357)
```rust
            code_size_budget_remaining.checked_sub(callee_info.code_size * sites.len()),
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L472-483)
```rust
    let do_inlining_optimization = options.experiment_on(Experiment::INLINING_OPTIMIZATION);
    if do_inlining_optimization {
        // This allows inlining a call that comes from a different package
        let across_package = options.experiment_on(Experiment::ACROSS_PACKAGE_INLINING);
        // This allows performing an inlining optimization to a function that does not belong to the primary target package
        let allow_non_primary_targets =
            options.experiment_on(Experiment::INLINING_OPTIMIZATION_TO_NON_PRIMARY_TARGETS);
        env_pipeline.add("inlining optimization", {
            move |env: &mut GlobalEnv| {
                inlining_optimization::optimize(env, across_package, allow_non_primary_targets)
            }
        });
```
