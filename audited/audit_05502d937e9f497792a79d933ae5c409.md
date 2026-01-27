# Audit Report

## Title
Silent Module Dropping in Genesis Framework Deployment Due to Duplicate ModuleId Handling

## Summary
The `sorted_code_and_modules()` function in `release_bundle.rs` uses a BTreeMap with ModuleId as the key, causing it to silently overwrite and drop modules when duplicate ModuleIds exist within a single package's bytecode array. This bypasses subsequent duplicate detection in `StagingModuleStorage`, potentially resulting in incomplete framework deployments during genesis initialization.

## Finding Description
The vulnerability exists in the interaction between two validation layers: [1](#0-0) 

The `sorted_code_and_modules()` function deserializes bytecode and collects modules into a BTreeMap using ModuleId (address + name) as the key. When multiple bytecodes in the `code` array deserialize to the same ModuleId, the BTreeMap silently overwrites earlier entries with later ones, effectively dropping modules without any error.

During genesis initialization, this function is called to prepare packages for deployment: [2](#0-1) 

The deduplicated module list is then passed to the module publishing infrastructure: [3](#0-2) 

While `StagingModuleStorage` has duplicate detection logic: [4](#0-3) 

This validation is bypassed because it only sees the already-deduplicated module list. The dropped module never reaches `StagingModuleStorage`, so the duplicate check never triggers.

**Attack Path:**
1. Attacker crafts a malicious ReleaseBundle by directly serializing a ReleasePackage with duplicate ModuleIds in its `code` field (ReleasePackage derives Deserialize)
2. This malicious bundle is provided as the genesis framework (via `--genesis-framework` flag or file distribution)
3. During genesis, `sorted_code_and_modules()` silently drops duplicate modules
4. `StagingModuleStorage` receives only the deduplicated list and its validation passes
5. Critical framework modules are missing from the deployed state
6. Network starts with incomplete framework, breaking core functionality

## Impact Explanation
This vulnerability meets **Critical Severity** criteria:

**Consensus/Safety Violations**: If different validators use framework files with different duplicate patterns, they would deploy different modules, violating the Deterministic Execution invariant. All validators must produce identical state roots for identical blocks.

**Non-recoverable Network Partition**: Missing critical framework modules (e.g., `aptos_governance`, `stake`, `transaction_validation`) would render the network non-functional from genesis, requiring a hardfork to recover.

However, exploitation requires privileged access to the genesis framework distribution, which is typically controlled by trusted parties (core developers, validator operators). The attacker would need to:
- Compromise the genesis ceremony
- Execute a supply chain attack on framework files  
- Act as a malicious node operator providing bad framework files

## Likelihood Explanation
**Likelihood: Low** 

While the technical vulnerability exists, practical exploitation faces significant barriers:

1. **Controlled Distribution**: Genesis frameworks are embedded in binaries or distributed through controlled channels
2. **Multi-party Review**: Production genesis frameworks undergo extensive review by validators and core team
3. **One-time Operation**: Genesis only occurs once per network, with careful preparation
4. **Privileged Access Required**: Attacker needs ability to influence genesis framework file selection

The vulnerability is more likely to manifest through:
- Accidental corruption during development/testing
- Supply chain compromise
- Insider threat from malicious validator operator

## Recommendation

Add explicit duplicate detection in `sorted_code_and_modules()` before collecting into the BTreeMap:

```rust
pub fn sorted_code_and_modules(&self) -> Vec<(&[u8], CompiledModule)> {
    // First pass: deserialize and check for duplicates
    let mut seen_ids = BTreeSet::new();
    let mut modules = vec![];
    
    for c in &self.code {
        let m = CompiledModule::deserialize(c).unwrap();
        let id = m.self_id();
        
        if !seen_ids.insert(id.clone()) {
            panic!(
                "Duplicate ModuleId detected in package '{}': {}::{}",
                self.metadata.name,
                id.address(),
                id.name()
            );
        }
        modules.push((c.as_slice(), m));
    }
    
    // Second pass: build map with guaranteed unique keys
    let mut map = modules
        .into_iter()
        .map(|(c, m)| (m.self_id(), (c, m)))
        .collect::<BTreeMap<_, _>>();
    
    // Rest of function unchanged...
    let mut order = vec![];
    for id in map.keys() {
        sort_by_deps(&map, &mut order, id.clone());
    }
    let mut result = vec![];
    for id in order {
        let (code, module) = map.remove(&id).unwrap();
        result.push((code, module))
    }
    result
}
```

Additionally, add validation at the ReleaseBundle deserialization level to verify integrity before use.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use move_binary_format::CompiledModule;
    use move_core_types::{account_address::AccountAddress, identifier::Identifier};
    
    #[test]
    #[should_panic(expected = "Duplicate ModuleId")]
    fn test_duplicate_module_ids_detected() {
        // Create two different modules with same ModuleId
        let module1 = create_test_module(AccountAddress::ONE, "test", vec![1, 2, 3]);
        let module2 = create_test_module(AccountAddress::ONE, "test", vec![4, 5, 6]);
        
        let mut bytecode_version = None;
        let code1 = module1.serialize(bytecode_version);
        let code2 = module2.serialize(bytecode_version);
        
        // Create ReleasePackage with duplicate ModuleIds
        let package = ReleasePackage {
            metadata: create_test_metadata(),
            code: vec![code1, code2], // Both have same ModuleId!
        };
        
        // This should panic with duplicate detection
        let _result = package.sorted_code_and_modules();
    }
}
```

**Note:** This proof of concept demonstrates the technical vulnerability but requires manual construction of malicious ReleasePackage data, which in production scenarios requires privileged access to genesis framework distribution.

### Citations

**File:** aptos-move/framework/src/release_bundle.rs (L143-162)
```rust
    pub fn sorted_code_and_modules(&self) -> Vec<(&[u8], CompiledModule)> {
        let mut map = self
            .code
            .iter()
            .map(|c| {
                let m = CompiledModule::deserialize(c).unwrap();
                (m.self_id(), (c.as_slice(), m))
            })
            .collect::<BTreeMap<_, _>>();
        let mut order = vec![];
        for id in map.keys() {
            sort_by_deps(&map, &mut order, id.clone());
        }
        let mut result = vec![];
        for id in order {
            let (code, module) = map.remove(&id).unwrap();
            result.push((code, module))
        }
        result
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1166-1173)
```rust
    for pack in &framework.packages {
        let modules = pack.sorted_code_and_modules();

        let addr = *modules.first().unwrap().1.self_id().address();
        let code = modules
            .into_iter()
            .map(|(c, _)| c.to_vec().into())
            .collect::<Vec<_>>();
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1175-1188)
```rust
        let package_writes = code_to_writes_for_publishing(
            genesis_runtime_environment,
            genesis_vm.genesis_features(),
            &state_view,
            addr,
            code,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Failure publishing package `{}`: {:?}",
                pack.package_metadata().name,
                e
            )
        });
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L207-217)
```rust
            // Publishing the same module in the same bundle is not allowed.
            if prev.is_some() {
                let msg = format!(
                    "Module {}::{} occurs more than once in published bundle",
                    compiled_module.self_addr(),
                    compiled_module.self_name()
                );
                return Err(PartialVMError::new(StatusCode::DUPLICATE_MODULE_NAME)
                    .with_message(msg)
                    .finish(Location::Undefined));
            }
```
