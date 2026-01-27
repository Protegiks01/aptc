# Audit Report

## Title
Move Compiler V2 Silent Module Shadowing During Compilation Allows Supply Chain Attacks

## Summary
The Move Compiler V2 allows source modules to silently shadow dependency modules during compilation when `sources_shadow_deps()` is enabled, which is hardcoded in `Flags::model_compilation()`. This creates a supply chain vulnerability where malicious packages can replace legitimate dependency code during the compilation phase, potentially leading to developers testing with incorrect code and distributing compromised bytecode.

## Finding Description
The vulnerability exists in the module merging logic during the expansion phase: [1](#0-0) 

When duplicate modules are detected between `source_definitions` and `lib_definitions`, the compiler checks the `sources_shadow_deps()` flag. If this flag is `true`, the source module **silently shadows** the library module without any error or warning. The `duplicate_module()` function that would report the error is only called when the flag is `false`.

The critical issue is that Move Compiler V2 **always** uses `Flags::model_compilation()` which hardcodes `shadow: true`: [2](#0-1) 

This flag is used throughout the v2 compilation pipeline: [3](#0-2) 

**Attack Scenario:**
1. Attacker creates a malicious package that declares standard dependencies (e.g., AptosFramework)
2. Attacker defines their own module with the same identifier as a dependency module (e.g., `0x1::coin`)
3. During compilation, the malicious module shadows the legitimate dependency module
4. Developer tests with the malicious code, believing they're using the real framework
5. Compiled bytecode contains wrong module references and implementations

**Partial Mitigation:**
The VM enforces address verification at deployment time: [4](#0-3) 

This prevents deploying modules to addresses not owned by the sender, but does NOT prevent:
- Testing with shadowed malicious code in development
- Compiling packages with wrong dependency implementations
- Distributing compiled bytecode with incorrect linkage expectations

## Impact Explanation
This is a **Medium Severity** vulnerability according to Aptos bug bounty criteria:

- **No Direct On-Chain Exploitation**: The address verification prevents deploying shadowed modules to framework addresses (0x1, etc.), preventing direct theft of funds or consensus violations
  
- **Supply Chain Attack Surface**: Developers unknowingly compile and test with malicious code, potentially leading to:
  - Deployment of packages with subtle bugs introduced during testing with wrong dependencies
  - Distribution of compromised development tools or SDKs
  - False confidence in security testing that used shadowed implementations

- **State Inconsistencies**: Packages compiled against shadowed dependencies may have linking mismatches when deployed, causing runtime failures requiring intervention

## Likelihood Explanation
**Medium to High Likelihood:**

- **Easy to Execute**: Any attacker can create a package with shadowing modules
- **Silent Failure**: No compiler warnings or errors are generated
- **Common Development Practice**: Developers regularly add dependencies without verifying module definitions
- **Limited by Deployment Check**: Actual on-chain exploitation is prevented by runtime address verification
- **Developer Impact**: High likelihood of affecting development environments and CI/CD pipelines

## Recommendation
Implement mandatory duplicate module detection regardless of compilation mode:

```rust
// In translate.rs, lines 242-248, modify to:
for (mident, module) in lib_module_map {
    if let Err((mident, old_loc)) = source_module_map.add(mident, module) {
        // Always report duplicate modules, even in verification mode
        duplicate_module(&mut context, &source_module_map, mident, old_loc);
        
        // If sources_shadow_deps is enabled, still use the source module
        // but emit a warning so developers are aware
        if context.env.flags().sources_shadow_deps() {
            context.env.add_diag(diag!(
                Declarations::ShadowedModule,
                (mident.loc, format!("Warning: Source module '{}' shadows dependency module", mident)),
                (old_loc, "Dependency module defined here")
            ));
        }
    }
}
```

Additionally, add a compiler flag to disable shadowing in production compilations:
- Keep `shadow: true` only for verification/prover modes
- Use `shadow: false` for package compilation intended for deployment
- Add explicit warnings in documentation about dependency shadowing risks

## Proof of Concept
**Step 1**: Create a malicious package structure:

```
malicious_package/
├── Move.toml
└── sources/
    └── malicious_coin.move
```

**Move.toml:**
```toml
[package]
name = "MaliciousPackage"
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/aptos-framework", rev = "main" }

[addresses]
std = "0x1"
```

**sources/malicious_coin.move:**
```move
module 0x1::coin {
    // Malicious implementation that shadows the real coin module
    public entry fun transfer<CoinType>(
        from: &signer,
        to: address,
        amount: u64,
    ) {
        // Instead of transferring, do nothing (steal coins)
        // In reality, this would fail at deployment due to address check,
        // but during compilation and testing, this code replaces the real coin module
    }
}
```

**Step 2**: Compile the package using Move Compiler V2:
```bash
aptos move compile --save-metadata
```

**Expected Result**: 
- Compilation succeeds without any errors or warnings
- The malicious `0x1::coin` module shadows the real framework coin module during compilation
- Developer tests pass using the malicious implementation
- Bytecode is generated with references to the shadowed module

**Actual Security Impact**:
- At deployment time, the address check prevents publishing to 0x1
- However, the developer has already tested with malicious code
- Any local testing or integration tests use the wrong implementation
- Supply chain is compromised at the development level

## Notes
While the deployment-time address verification prevents direct on-chain exploitation, this vulnerability violates the **Deterministic Execution** invariant during development by allowing different module implementations to be used during compilation versus runtime. It also represents a significant supply chain security risk that could affect the broader Aptos ecosystem through compromised development practices.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/translate.rs (L242-248)
```rust
    for (mident, module) in lib_module_map {
        if let Err((mident, old_loc)) = source_module_map.add(mident, module) {
            if !context.env.flags().sources_shadow_deps() {
                duplicate_module(&mut context, &source_module_map, mident, old_loc)
            }
        }
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L438-446)
```rust
    pub fn model_compilation() -> Self {
        Self {
            test: false,
            verify: true,
            shadow: true, // allows overlapping between sources and deps
            keep_testing_functions: true,
            lang_v2: true,
            ..Self::empty()
        }
```

**File:** third_party/move/move-model/src/lib.rs (L102-108)
```rust
        Flags::model_compilation()
            .set_warn_of_deprecation_use(warn_of_deprecation_use)
            .set_warn_of_deprecation_use_in_aptos_libs(warn_of_deprecation_use_in_aptos_libs)
            .set_skip_attribute_checks(skip_attribute_checks)
            .set_verify(compile_verify_code)
            .set_keep_testing_functions(compile_test_code)
            .set_language_version(language_version.into()),
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L156-171)
```rust
            // Make sure all modules' addresses match the sender. The self address is
            // where the module will actually be published. If we did not check this,
            // the sender could publish a module under anyone's account.
            if addr != sender {
                let msg = format!(
                    "Compiled modules address {} does not match the sender {}",
                    addr, sender
                );
                return Err(verification_error(
                    StatusCode::MODULE_ADDRESS_DOES_NOT_MATCH_SENDER,
                    IndexKind::AddressIdentifier,
                    compiled_module.self_handle_idx().0,
                )
                .with_message(msg)
                .finish(Location::Undefined));
            }
```
