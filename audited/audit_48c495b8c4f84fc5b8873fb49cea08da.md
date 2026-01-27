# Audit Report

## Title
Reserved '$' Identifier Enforcement Bypass via Move IR Compiler

## Summary
The Move compiler reserves identifiers starting with '$' for internal/compiler use, but this reservation is not properly enforced at the bytecode level. Users can create modules with '$'-prefixed identifiers by using the Move IR compiler or crafting bytecode directly, violating the documented security boundary and potentially causing tooling confusion or name conflicts with compiler-generated identifiers.

## Finding Description

The Aptos Move implementation states that dollar sign (`$`) is reserved for compiler or runtime intrinsic identifiers and cannot be reached from the Move language. However, this restriction is only enforced at the Move language parser level, not at the bytecode level. [1](#0-0) 

The Move language compiler's lexer correctly rejects '$' characters in identifiers: [2](#0-1) 

However, the Move IR compiler explicitly allows '$' in identifiers: [3](#0-2) [4](#0-3) 

At the bytecode level, identifiers with '$' are allowed for version 9 and later: [5](#0-4) 

Bytecode version 9 explicitly enables '$' in identifiers and is the default version: [6](#0-5) [7](#0-6) 

The compiler itself generates internal identifiers with '$' prefix, assuming they cannot conflict with user code: [8](#0-7) [9](#0-8) 

During module publishing, there is no additional validation to reject user-defined '$'-prefixed identifiers: [10](#0-9) 

**Attack Scenario:**
1. Attacker writes Move IR code (.mvir) containing identifiers like `$internal_function`, `$temp`, or `$t0`
2. The Move IR compiler accepts these identifiers
3. Module is compiled to bytecode version 9
4. Module passes all verification checks
5. Module is successfully published
6. The attacker's '$'-prefixed identifiers now exist in the blockchain state, violating the stated security boundary

## Impact Explanation

This is a **Medium severity** issue per the Aptos bug bounty criteria, as it violates a documented security invariant but does not directly lead to fund theft or consensus breaks. The impacts include:

1. **Security Boundary Violation**: The documented guarantee that '$' identifiers are reserved for compiler/runtime use is broken
2. **Tooling Confusion**: Debuggers, disassemblers, and analysis tools that assume '$' identifiers are compiler-generated may malfunction
3. **Potential Name Conflicts**: User-defined identifiers could collide with compiler-generated internal names
4. **State Inconsistencies**: If compiler or runtime code makes assumptions about '$' identifiers being internal-only, these assumptions may be violated

While not immediately exploitable for critical impacts, this weakens the security boundaries between user code and compiler-generated code, which is the foundation for deterministic execution across all validators.

## Likelihood Explanation

**Likelihood: Low to Medium**

While the Move IR compiler is documented as a testing tool, it is technically accessible and users can compile Move IR files. Additionally, sophisticated attackers could craft bytecode directly with '$'-prefixed identifiers. The barrier to exploitation is the requirement to:
1. Understand the bytecode format internals
2. Use the Move IR compiler or craft bytecode manually
3. Publish the module on-chain

However, once discovered, this bypass is straightforward to execute and could become more widely exploited.

## Recommendation

Implement additional validation during module publishing to enforce the '$' reservation:

1. Add a check in the bytecode verifier or publishing validation that scans all identifiers in user-submitted modules
2. Reject any module containing identifiers starting with '$' unless it's from a trusted system address
3. Alternatively, remove '$' support from the Move IR compiler for user-facing code

**Code Fix Suggestion:**

In `aptos-move/aptos-vm/src/aptos_vm.rs`, add to `validate_publish_request()`:

```rust
fn validate_reserved_identifiers(module: &CompiledModule) -> VMResult<()> {
    // Check all identifiers in the module
    for ident in module.identifiers() {
        if ident.as_str().starts_with('$') {
            return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                .with_message(format!(
                    "User modules cannot use reserved identifier: '{}'", 
                    ident
                ))
                .finish(Location::Module(module.self_id())));
        }
    }
    Ok(())
}
```

And call this in the validation flow before module publishing.

## Proof of Concept

**Step 1:** Create a Move IR file `malicious.mvir`:

```
module 0xCAFE.Malicious {
    struct $InternalState has key { value: u64 }
    
    public fun $compiler_internal(): u64 {
        return 42;
    }
    
    public fun create_internal(account: &signer) {
        move_to<$InternalState>(account, $InternalState { value: 123 });
    }
}
```

**Step 2:** Compile using Move IR compiler:

```bash
move-ir-compiler malicious.mvir --output malicious.mv
```

**Step 3:** Publish the module using Aptos CLI:

```bash
aptos move publish --bytecode-path malicious.mv --assume-yes
```

**Expected Result:** Module publishes successfully with '$'-prefixed identifiers, violating the stated invariant.

**Verification:** Query the published module and observe that `$InternalState` and `$compiler_internal` are accessible as regular public identifiers, breaking the security boundary between compiler-generated and user-defined code.

## Notes

The Move IR compiler README documents it as "a testing tool for the bytecode verifier," but there is no technical barrier preventing its use for module publishing. The bytecode format's explicit support for '$' in identifiers (VERSION_9) combined with lack of enforcement at publishing time creates this vulnerability.

### Citations

**File:** third_party/move/move-core/types/src/identifier.rs (L14-15)
```rust
//! Notice that dollar (`$`) is reserved for compiler or runtime intrinsic identifiers
//! and cannot be reached from the Move language.
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/lexer.rs (L711-715)
```rust
fn get_name_len(text: &str) -> usize {
    text.chars()
        .position(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '_' | '0'..='9'))
        .unwrap_or(text.len())
}
```

**File:** third_party/move/move-ir-compiler/move-ir-to-bytecode/syntax/src/lexer.rs (L245-246)
```rust
            'a'..='z' | 'A'..='Z' | '$' | '_' => {
                let len = get_name_len(text);
```

**File:** third_party/move/move-ir-compiler/move-ir-to-bytecode/syntax/src/lexer.rs (L403-413)
```rust
// Return the length of the substring matching [a-zA-Z$_][a-zA-Z0-9$_]
fn get_name_len(text: &str) -> usize {
    // If the first character is 0..=9 or EOF, then return a length of 0.
    let first_char = text.chars().next().unwrap_or('0');
    if first_char.is_ascii_digit() {
        return 0;
    }
    text.chars()
        .position(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '$' | '_' | '0'..='9'))
        .unwrap_or(text.len())
}
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L986-998)
```rust
    let ident = Identifier::from_utf8(buffer).map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED).with_message("Invalid Identifier".to_string())
    })?;
    if cursor.version() < VERSION_9 && ident.as_str().contains('$') {
        Err(
            PartialVMError::new(StatusCode::MALFORMED).with_message(format!(
                "`$` in identifiers not supported in bytecode version {}",
                cursor.version()
            )),
        )
    } else {
        Ok(ident)
    }
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L552-555)
```rust
/// Version 9: changes compared to version 8
/// + signed integers
/// + allow `$` in identifiers
pub const VERSION_9: u32 = 9;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L571-571)
```rust
pub const VERSION_DEFAULT: u32 = VERSION_9;
```

**File:** third_party/move/move-model/src/builder/exp_builder.rs (L5245-5248)
```rust
                    // starts with $ for internal generated vars
                    let var_name = self
                        .symbol_pool()
                        .make(&format!("${}", field_name.display(self.symbol_pool())));
```

**File:** third_party/move/move-model/src/model.rs (L5152-5152)
```rust
        self.module_env.env.symbol_pool.make(&format!("$t{}", idx))
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1680-1739)
```rust
    fn validate_publish_request(
        &self,
        module_storage: &impl AptosModuleStorage,
        traversal_context: &mut TraversalContext,
        gas_meter: &mut impl GasMeter,
        modules: &[CompiledModule],
        mut expected_modules: BTreeSet<String>,
        allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
    ) -> VMResult<()> {
        self.reject_unstable_bytecode(modules)?;
        native_validation::validate_module_natives(modules)?;

        for m in modules {
            if !expected_modules.remove(m.self_id().name().as_str()) {
                return Err(Self::metadata_validation_error(&format!(
                    "unregistered module: '{}'",
                    m.self_id().name()
                )));
            }
            if let Some(allowed) = &allowed_deps {
                for dep in m.immediate_dependencies() {
                    if !allowed
                        .get(dep.address())
                        .map(|modules| {
                            modules.contains("") || modules.contains(dep.name().as_str())
                        })
                        .unwrap_or(false)
                    {
                        return Err(Self::metadata_validation_error(&format!(
                            "unregistered dependency: '{}'",
                            dep
                        )));
                    }
                }
            }
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
        }

        resource_groups::validate_resource_groups(
            self.features(),
            module_storage,
            traversal_context,
            gas_meter,
            modules,
        )?;
        event_validation::validate_module_events(
            self.features(),
            module_storage,
            traversal_context,
            modules,
        )?;

        if !expected_modules.is_empty() {
            return Err(Self::metadata_validation_error(
                "not all registered modules published",
            ));
        }
        Ok(())
    }
```
