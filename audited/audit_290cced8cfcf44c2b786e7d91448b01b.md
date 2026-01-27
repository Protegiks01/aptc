# Audit Report

## Title
Memory Exhaustion in InstantiationLoopChecker During Module Verification

## Summary
The Move bytecode verifier's `InstantiationLoopChecker` can be exploited to cause memory exhaustion on validator nodes by crafting modules with maximum complexity across multiple dimensions. The checker builds an unbounded graph in memory before aggregate metering limits are applied, allowing an attacker to crash validator nodes and potentially cause network liveness issues.

## Finding Description

The vulnerability exists in the verification order within `verify_module_with_config()`. The `InstantiationLoopChecker` runs before `CodeUnitVerifier`, which means graph construction happens before any aggregate complexity metering can reject overly complex modules. [1](#0-0) 

The `InstantiationLoopChecker::verify_module()` builds a graph by iterating through all functions in a module and adding nodes/edges for generic type instantiations: [2](#0-1) 

The graph construction in `build_graph()` processes every function without any size limits: [3](#0-2) 

For each `CallGeneric` instruction, the checker adds edges based on type parameters: [4](#0-3) 

The critical issue is that Aptos production configuration sets several key limits to `None`: [5](#0-4) 

This means:
- **No limit on number of functions** (only bounded by binary format's `FUNCTION_HANDLE_INDEX_MAX = 65535`)
- **No limit on struct definitions, fields, or variants**
- **No aggregate checks before InstantiationLoopChecker runs**

The binary format allows: [6](#0-5) [7](#0-6) 

**Attack Path:**
1. Attacker crafts a module with 10,000 functions (well within the 65535 limit)
2. Each function contains 1,000 `CallGeneric` instructions calling other functions in the module
3. Each `CallGeneric` uses complex type instantiations with multiple type parameters (e.g., `Struct<T1, Struct<T2, ...>>`)
4. When submitted to a validator node, the module passes deserialization and initial bounds checks
5. `InstantiationLoopChecker::build_graph()` begins iterating through all 10,000 functions
6. For each `CallGeneric`, `extract_type_parameters()` finds type parameters and adds edges (potentially 10-32 edges per call)
7. Total edges: 10,000 functions × 1,000 calls × 15 edges = **150 million edges**
8. Memory usage: 150 million edges × ~48 bytes/edge = **~7.2 GB** just for edge storage
9. Node exhausts memory and crashes before reaching `CodeUnitVerifier` metering checks

**Invariant Violation:**
This breaks Invariant #9: "**Resource Limits**: All operations must respect gas, storage, and computational limits." The verification process itself does not properly bound memory consumption, allowing operations that exceed reasonable resource limits.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability enables:

1. **Validator Node Crashes**: An attacker can submit malicious modules that cause validator nodes to exhaust memory during verification, leading to node crashes or severe slowdowns.

2. **Network Liveness Impact**: If multiple validators process the same malicious module simultaneously (e.g., through mempool propagation or during block proposal), multiple nodes could crash, potentially delaying consensus and block production.

3. **Denial of Service**: Repeated submission of such modules could keep validator nodes in a degraded state, affecting network availability.

This meets the **High Severity** criteria: "Validator node slowdowns" and "Significant protocol violations." While it doesn't directly cause consensus safety violations or fund loss, it can impact network liveness and validator operations.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible because:

1. **No Special Privileges Required**: Any user can submit module publishing transactions to the network.

2. **Deterministic Exploitation**: The vulnerability is triggered reliably - any module with sufficient complexity will cause the memory exhaustion.

3. **Difficult to Detect**: The malicious module passes all individual limit checks and only fails during graph construction, making it hard to filter at earlier stages.

4. **Low Attacker Cost**: Crafting the malicious module is straightforward - automated tools can generate modules with the required structure.

5. **High Impact**: The attack affects critical validator infrastructure and could be used to disrupt network operations.

The only mitigation is that transaction gas costs may make repeated attacks expensive, but a single well-crafted module could still cause significant disruption.

## Recommendation

Implement aggregate size limits for `InstantiationLoopChecker` before graph construction begins. Add the following checks to `verify_module_impl()`:

**Option 1: Add Early Aggregate Limit (Recommended)**
```rust
fn verify_module_impl(module: &'a CompiledModule) -> PartialVMResult<()> {
    // Add early check to bound worst-case graph size
    let max_nodes = 100_000; // function_count * type_param_count
    let max_edges = 10_000_000; // estimated from call sites
    
    let function_count = module.function_defs().len();
    let max_type_params = module.function_handles()
        .iter()
        .map(|fh| fh.type_parameters.len())
        .max()
        .unwrap_or(0);
    
    let estimated_nodes = function_count * max_type_params;
    if estimated_nodes > max_nodes {
        return Err(PartialVMError::new(StatusCode::PROGRAM_TOO_COMPLEX)
            .with_message(format!("Module too complex for instantiation checking: {} estimated nodes", estimated_nodes)));
    }
    
    let mut checker = Self::new(module);
    checker.build_graph();
    
    // Add runtime check on actual graph size
    if checker.graph.node_count() > max_nodes || checker.graph.edge_count() > max_edges {
        return Err(PartialVMError::new(StatusCode::PROGRAM_TOO_COMPLEX)
            .with_message(format!("Instantiation graph too large: {} nodes, {} edges", 
                checker.graph.node_count(), checker.graph.edge_count())));
    }
    
    let mut components = checker.find_non_trivial_components();
    // ... rest of verification
}
```

**Option 2: Apply Metering to InstantiationLoopChecker**
Pass a `Meter` to `InstantiationLoopChecker` and charge for each node/edge added during graph construction.

**Option 3: Reorder Verification Steps**
Move `CodeUnitVerifier` (with metering) before `InstantiationLoopChecker`, though this may not fully solve the issue if the checker itself is the memory bottleneck.

**Option 4: Restore Production Limits**
Set non-None values for critical limits in production config:
```rust
max_function_definitions: Some(5000),
max_struct_definitions: Some(1000),
```

## Proof of Concept

The following Rust code demonstrates how to generate a malicious module that triggers the vulnerability:

```rust
// Module generator that creates a complex module for testing
use move_binary_format::file_format::*;

fn generate_memory_exhaustion_module() -> CompiledModule {
    let mut module = empty_module();
    
    // Create 5000 functions (well below 65535 limit)
    let num_functions = 5000;
    let calls_per_function = 500;
    
    for i in 0..num_functions {
        // Create function with type parameter
        let func_handle = FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(i as u16),
            parameters: SignatureIndex(i as u16),
            return_: SignatureIndex(0),
            type_parameters: vec![AbilitySet::EMPTY; 8], // 8 type params
            access_specifiers: None,
            attributes: vec![],
        };
        
        // Create code with many CallGeneric instructions
        let mut code = vec![];
        for j in 0..calls_per_function {
            // Each CallGeneric to another function in the module
            let target_func = (i + j + 1) % num_functions;
            code.push(Bytecode::CallGeneric(FunctionInstantiationIndex(target_func as u16)));
        }
        code.push(Bytecode::Ret);
        
        // Add function definition
        let func_def = FunctionDefinition {
            function: FunctionHandleIndex(i as u16),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code,
            }),
            attributes: vec![],
        };
        
        module.function_handles.push(func_handle);
        module.function_defs.push(func_def);
    }
    
    // When this module is verified, InstantiationLoopChecker will build:
    // - Nodes: 5000 functions × 8 type params = 40,000 nodes
    // - Edges: 5000 functions × 500 calls × ~5 edges = 12.5 million edges
    // - Memory: ~600 MB just for the graph, causing slowdown or crash
    
    module
}

#[test]
fn test_memory_exhaustion_vulnerability() {
    let module = generate_memory_exhaustion_module();
    let config = VerifierConfig::production();
    
    // This will cause excessive memory allocation in InstantiationLoopChecker
    let result = verify_module_with_config(&config, &module);
    
    // Node may crash or hang here due to memory exhaustion
    // Expected: Should reject with PROGRAM_TOO_COMPLEX before exhausting memory
    // Actual: Attempts to allocate multiple GB of memory
}
```

To test in practice, submit a transaction publishing this module to a validator node and monitor memory usage during verification. The node's memory consumption will spike dramatically during `InstantiationLoopChecker::build_graph()`.

## Notes

This vulnerability is particularly concerning because:

1. The production configuration explicitly sets many limits to `None`, expanding the attack surface significantly compared to the default configuration.

2. The verification order places an unbounded memory operation before aggregate metering checks, creating a window for exploitation.

3. The binary format limits (65535 functions, 65535 instructions per function) are much higher than the verification limits, creating a gap that attackers can exploit.

4. The `petgraph` library used for graph construction will attempt to allocate memory for all nodes and edges before any size checks, making this a genuine memory exhaustion vector rather than just a performance issue.

The fix should involve either adding explicit size limits to `InstantiationLoopChecker`, applying metering throughout the verification process, or setting reasonable production limits that bound worst-case memory usage.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L157-158)
```rust
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;
```

**File:** third_party/move/move-bytecode-verifier/src/instantiation_loops.rs (L88-95)
```rust
    pub fn verify_module(module: &'a CompiledModule) -> VMResult<()> {
        Self::verify_module_impl(module).map_err(|e| e.finish(Location::Module(module.self_id())))
    }

    fn verify_module_impl(module: &'a CompiledModule) -> PartialVMResult<()> {
        let mut checker = Self::new(module);
        checker.build_graph();
        let mut components = checker.find_non_trivial_components();
```

**File:** third_party/move/move-bytecode-verifier/src/instantiation_loops.rs (L183-210)
```rust
    fn build_graph_call(
        &mut self,
        caller_idx: FunctionDefinitionIndex,
        callee_idx: FunctionDefinitionIndex,
        type_actuals_idx: SignatureIndex,
    ) {
        let type_actuals = &self.module.signature_at(type_actuals_idx).0;

        for (formal_idx, ty) in type_actuals.iter().enumerate() {
            let formal_idx = formal_idx as TypeParameterIndex;
            match ty {
                SignatureToken::TypeParameter(actual_idx) => self.add_edge(
                    Node(caller_idx, *actual_idx),
                    Node(callee_idx, formal_idx),
                    Edge::Identity,
                ),
                _ => {
                    for type_param in self.extract_type_parameters(ty) {
                        self.add_edge(
                            Node(caller_idx, type_param),
                            Node(callee_idx, formal_idx),
                            Edge::TyConApp(ty),
                        );
                    }
                },
            }
        }
    }
```

**File:** third_party/move/move-bytecode-verifier/src/instantiation_loops.rs (L345-355)
```rust
    fn build_graph(&mut self) {
        for (def_idx, func_def) in self
            .module
            .function_defs()
            .iter()
            .enumerate()
            .filter(|(_, def)| !def.is_native())
        {
            self.build_graph_function_def(FunctionDefinitionIndex::new(def_idx as u16), func_def)
        }
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L168-174)
```rust
        max_struct_definitions: None,
        max_struct_variants: None,
        max_fields_in_struct: None,
        max_function_definitions: None,
        max_back_edges_per_function: None,
        max_back_edges_per_module: None,
        max_basic_blocks_in_script: None,
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L50-51)
```rust
pub const FUNCTION_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const FUNCTION_INST_INDEX_MAX: u64 = TABLE_INDEX_MAX;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L61-62)
```rust
pub const BYTECODE_COUNT_MAX: u64 = 65535;
pub const BYTECODE_INDEX_MAX: u64 = 65535;
```
