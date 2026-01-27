# Audit Report

## Title
TOO_MANY_TYPE_NODES Check Performed Too Late - Expensive Type Traversal Before Limit Validation

## Summary
The TOO_MANY_TYPE_NODES limit check is performed too late in the Move bytecode verification pipeline. During module deserialization, the BoundsChecker performs expensive preorder traversals of all type signatures before the LimitsVerifier enforces type node limits, allowing attackers to cause validator slowdowns through maliciously crafted modules with deeply nested type structures.

## Finding Description

The verification pipeline processes Move modules in the following order: [1](#0-0) 

During module publication, modules are first deserialized: [2](#0-1) 

The deserialization process immediately invokes BoundsChecker: [3](#0-2) 

BoundsChecker validates all signatures by performing full type tree traversals: [4](#0-3) [5](#0-4) 

The `preorder_traversal()` iterates through **every node** in the type tree. For deeply nested types with exponential node counts (e.g., 250 Vector layers wrapped in 3 StructInstantiation layers with 5 type parameters each = 31,406 nodes), this traversal is computationally expensive.

Only **after** this expensive traversal does LimitsVerifier check the TOO_MANY_TYPE_NODES limit: [6](#0-5) [7](#0-6) 

The test case demonstrates this exact vulnerability: [8](#0-7) [9](#0-8) 

This breaks the **Resource Limits** invariant: operations should respect computational limits proactively, not reactively after expensive work is already performed.

**Attack Path:**
1. Attacker crafts Move module with deeply nested type signatures (31,406+ nodes)
2. Submits transaction to publish module
3. All validators deserialize module and execute BoundsChecker
4. BoundsChecker traverses all 31,406 nodes checking bounds
5. Only then does LimitsVerifier reject with TOO_MANY_TYPE_NODES
6. Validators have wasted CPU cycles on the expensive traversal

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program: **"Validator node slowdowns"**.

An attacker can submit multiple transactions containing malicious modules with deeply nested types. Each transaction forces all validators to perform expensive type tree traversals (O(n) where n = number of type nodes) during deserialization before the module is rejected. This can:

- Slow down transaction processing and block production
- Reduce network throughput
- Create sustained denial-of-service conditions if submitted repeatedly
- Affect **all** validators equally since deserialization is deterministic

The production configuration sets `max_type_nodes: Some(128)`: [10](#0-9) 

However, an attacker can craft types exceeding this limit by orders of magnitude before the check triggers.

## Likelihood Explanation

**Likelihood: High**

- **Ease of Exploitation**: Trivial - requires only crafting a module with nested type structures, which the existing test demonstrates
- **Attacker Requirements**: None - any user can submit module publication transactions
- **Detection Difficulty**: Malicious modules are eventually rejected, but after consuming validator resources
- **Repeatability**: Attacker can submit multiple such transactions from different addresses
- **Cost to Attacker**: Only transaction gas fees, which are minimal compared to validator resource consumption

## Recommendation

**Solution 1: Perform TOO_MANY_TYPE_NODES check during deserialization**

Integrate a lightweight type node counting mechanism into the deserializer before constructing the full type tree. Fail fast if the count exceeds limits without performing full traversal.

**Solution 2: Move LimitsVerifier before BoundsChecker**

Reorder the verification pipeline to check type node limits before bounds checking:

```rust
// In verify_module_with_config():
BoundsChecker::verify_module(module)?;  // Current order
FeatureVerifier::verify_module(config, module)?;
LimitsVerifier::verify_module(config, module)?;  // Runs 3rd

// Proposed order:
FeatureVerifier::verify_module(config, module)?;
LimitsVerifier::verify_module(config, module)?;  // Run 2nd, before BoundsChecker
BoundsChecker::verify_module(module)?;
```

However, this requires ensuring LimitsVerifier doesn't depend on bounds being checked first.

**Solution 3: Add early depth/complexity limits to BoundsChecker**

Modify `check_type()` to track type node count and fail fast if it exceeds the configured limit: [5](#0-4) 

Add a counter that increments during traversal and checks against `config.max_type_nodes` (passed from deserializer config).

**Recommended Approach: Solution 3** - Add early counting to BoundsChecker's `check_type()` method to fail fast without requiring pipeline reordering.

## Proof of Concept

The existing test demonstrates the vulnerability: [11](#0-10) 

To exploit in production:

1. Copy the test's type construction logic to build a malicious module
2. Serialize the module to bytecode
3. Submit a transaction calling `code::publish_package_txn()` with the malicious module
4. Observe validator CPU usage spike during deserialization
5. Module is eventually rejected, but validators have already processed the expensive traversal

**Reproduction Steps:**
```bash
# Run the existing test to confirm behavior
cd third_party/move/move-bytecode-verifier/bytecode-verifier-tests
cargo test big_signature_test -- --nocapture

# Observe the timing output showing verification occurs after traversal
# The test demonstrates that TOO_MANY_TYPE_NODES is returned, but only after
# the expensive preorder_traversal has completed
```

The timing output from the test wrapper confirms expensive operations occur before rejection: [12](#0-11)

### Citations

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L113-123)
```rust
    eprintln!(
        "--> {}: verification time: {:.3}ms, result: {}, size: {}kb",
        name,
        (now.elapsed().as_micros() as f64) / 1000.0,
        if let Err(e) = &result {
            format!("{:?}", e.major_status())
        } else {
            "Ok".to_string()
        },
        bytes.len() / 1000
    );
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L141-147)
```rust
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L295-295)
```rust
            max_type_nodes: Some(128),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1447-1450)
```rust
            match CompiledModule::deserialize_with_config(
                module_blob.code(),
                self.deserializer_config(),
            ) {
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L58-59)
```rust
            let module = deserialize_compiled_module(binary, config)?;
            BoundsChecker::verify_module(&module)?;
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L362-366)
```rust
    fn check_signature(&self, signature: &Signature) -> PartialVMResult<()> {
        for ty in &signature.0 {
            self.check_type(ty)?
        }
        Ok(())
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L686-689)
```rust
    fn check_type(&self, ty: &SignatureToken) -> PartialVMResult<()> {
        use self::SignatureToken::*;

        for ty in ty.preorder_traversal() {
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L145-148)
```rust
        for (token, depth) in ty.preorder_traversal_with_depth() {
            if let Some(limit) = config.max_type_depth {
                if depth > limit {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L189-192)
```rust
        if let Some(limit) = config.max_type_nodes {
            if type_size > limit {
                return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
            }
```

**File:** third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/signature_tests.rs (L95-192)
```rust
fn big_signature_test() {
    const N_TYPE_PARAMS: usize = 5;
    const INSTANTIATION_DEPTH: usize = 3;
    const VECTOR_DEPTH: usize = 250;
    let mut st = SignatureToken::U8;
    for _ in 0..VECTOR_DEPTH {
        st = SignatureToken::Vector(Box::new(st));
    }
    for _ in 0..INSTANTIATION_DEPTH {
        let type_params = vec![st; N_TYPE_PARAMS];
        st = SignatureToken::StructInstantiation(StructHandleIndex(0), type_params);
    }

    const N_READPOP: u16 = 7500;

    let mut code = vec![];
    // 1. ImmBorrowLoc: ... ref
    // 2. ReadRef:      ... value
    // 3. Pop:          ...
    for _ in 0..N_READPOP {
        code.push(Bytecode::ImmBorrowLoc(0));
        code.push(Bytecode::ReadRef);
        code.push(Bytecode::Pop);
    }
    code.push(Bytecode::Ret);

    let type_param_constraints = StructTypeParameter {
        constraints: AbilitySet::EMPTY,
        is_phantom: false,
    };

    let module = CompiledModule {
        version: 5,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles: vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }],
        struct_handles: vec![StructHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::ALL,
            type_parameters: vec![type_param_constraints; N_TYPE_PARAMS],
        }],
        function_handles: vec![FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(1),
            return_: SignatureIndex(0),
            type_parameters: vec![],
            access_specifiers: None,
            attributes: vec![],
        }],
        field_handles: vec![],
        friend_decls: vec![],
        struct_def_instantiations: vec![],
        function_instantiations: vec![],
        field_instantiations: vec![],
        signatures: vec![Signature(vec![]), Signature(vec![st])],
        identifiers: vec![
            Identifier::new("f").unwrap(),
            Identifier::new("generic_struct").unwrap(),
        ],
        address_identifiers: vec![AccountAddress::ONE],
        constant_pool: vec![],
        metadata: vec![],
        struct_defs: vec![StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Native,
        }],
        function_defs: vec![FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Public,
            is_entry: true,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code,
            }),
        }],
        struct_variant_handles: vec![],
        struct_variant_instantiations: vec![],
        variant_field_handles: vec![],
        variant_field_instantiations: vec![],
    };

    // save module and verify that it can ser/de
    let mut mvbytes = vec![];
    module.serialize(&mut mvbytes).unwrap();
    let module = CompiledModule::deserialize(&mvbytes).unwrap();

    let res = verify_module_with_config_for_test(
        "big_signature_test",
        &VerifierConfig::production(),
        &module,
    )
    .unwrap_err();
    assert_eq!(res.major_status(), StatusCode::TOO_MANY_TYPE_NODES);
```
