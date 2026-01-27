# Audit Report

## Title
Paranoid Type Check Bypass in Non-Mainnet Configurations Enables Type Confusion via Storage Corruption

## Summary
The `paranoid_type_checks` flag can be disabled in non-mainnet production configurations, removing a critical defense-in-depth mechanism that validates module identity during loading. If disabled and combined with a storage-layer bug or corruption, mismatched modules could be loaded, causing type confusion and potential privilege escalation through capability bypass.

## Finding Description

The `paranoid_check_module_address_and_name()` function performs a critical validation check during module loading from storage: [1](#0-0) 

This check is **conditionally executed** based on the `paranoid_type_checks` configuration flag. When disabled, the function returns immediately without validation: [2](#0-1) 

The flag defaults to `false` in the base `VMConfig`: [3](#0-2) 

For production, the flag is controlled via node configuration: [4](#0-3) [5](#0-4) 

While mainnet enforces this flag through a configuration sanitizer: [6](#0-5) 

**Non-mainnet networks (testnet, devnet, etc.) have NO such enforcement**, allowing operators to disable the flag.

The vulnerability surfaces when modules are loaded from storage. The storage adapter fetches module bytes by constructing a `StateKey` from the requested address and name: [7](#0-6) 

If a storage bug or corruption causes the wrong module bytes to be returned, the loader will use the module's **self-reported** identity for type construction: [8](#0-7) 

The `module_id_for_handle()` function extracts the module ID from the module's internal data structures: [9](#0-8) 

**Attack Scenario:**
1. Testnet node runs with `paranoid_type_verification: false`
2. Storage corruption or sync bug causes module `0xA::Authentic` bytes to be replaced with module `0xB::Malicious` bytes (which internally claims to be `0xA::Authentic`)
3. When code requests `0xA::Authentic`, storage returns the malicious module
4. Without paranoid check, the VM loads it silently
5. The loader creates struct types using the self-reported module ID (`0xA::Authentic`)
6. Type confusion occurs: malicious structs masquerade as authentic ones
7. **Capability bypass**: Fake `Cap<Feature>` tokens are treated as real capabilities
8. **Privilege escalation**: Attacker gains unauthorized access to protected operations

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for the following reasons:

**Broken Invariants:**
- **Type Safety**: Move's type system relies on module identity for type equality. Type confusion violates this fundamental guarantee.
- **Deterministic Execution**: Different nodes could load different modules for the same ID if storage corruption varies, causing consensus divergence.
- **Access Control**: Capability-based security in Move depends on unforgeable type identity. Type confusion enables capability forgery. [10](#0-9) 

**Potential Impact:**
- Consensus safety violations if validators have different storage states
- Privilege escalation through fake capabilities
- Resource manipulation through struct layout mismatches
- State inconsistencies requiring manual intervention

However, exploitation requires:
1. Non-mainnet configuration with disabled flag
2. A separate storage vulnerability causing module mismatches

## Likelihood Explanation

**Likelihood: Low to Medium**

**Enabling Factors:**
- Testnet/devnet operators may disable paranoid checks for performance testing
- The flag can be legitimately disabled via configuration
- Storage corruption can occur through multiple vectors:
  - State sync bugs during fast sync
  - Database corruption (hardware failures, bugs)
  - Race conditions in concurrent storage operations
  - Malicious state sync peers in permissionless networks

**Mitigating Factors:**
- Mainnet is protected by configuration sanitizer
- Requires a separate storage-layer vulnerability
- Module publishing includes address validation
- No evidence of existing storage bugs that cause module mismatches [11](#0-10) 

The paranoid check exists precisely as a defense-in-depth mechanism against such scenarios.

## Recommendation

**1. Enforce paranoid checks on all production networks:**

Extend the configuration sanitizer to reject disabled paranoid checks on ALL production networks (not just mainnet):

```rust
// config/src/config/execution_config.rs
fn sanitize(
    node_config: &NodeConfig,
    node_type: NodeType,
    chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let execution_config = &node_config.execution;
    
    // Enforce for mainnet AND testnet
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() || chain_id.is_testnet() {
            if !execution_config.paranoid_type_verification {
                return Err(Error::ConfigSanitizerFailed(
                    Self::get_sanitizer_name(),
                    "paranoid_type_verification must be enabled for production networks!".into(),
                ));
            }
        }
    }
    Ok(())
}
```

**2. Make paranoid checks always-on:**

Remove the configuration option entirely and make paranoid checks unconditional in the VM:

```rust
// third_party/move/move-vm/runtime/src/storage/environment.rs
pub fn paranoid_check_module_address_and_name(
    &self,
    module: &CompiledModule,
    expected_address: &AccountAddress,
    expected_module_name: &IdentStr,
) -> VMResult<()> {
    // Always perform the check - remove conditional
    let actual_address = module.self_addr();
    let actual_module_name = module.self_name();
    if expected_address != actual_address || expected_module_name != actual_module_name {
        return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
            .with_message(format!("Module identity mismatch..."))
            .with_sub_status(EPARANOID_FAILURE)
            .finish(Location::Undefined));
    }
    Ok(())
}
```

**3. Add storage-level validation:**

Implement additional validation at the storage layer to detect module identity mismatches before they reach the VM.

## Proof of Concept

Due to the defense-in-depth nature of this issue, a complete PoC requires simulating storage corruption, which cannot be done through normal transaction execution. However, the vulnerability can be demonstrated through a Rust integration test:

```rust
// Conceptual PoC - requires mocking storage corruption
#[test]
fn test_type_confusion_via_disabled_paranoid_checks() {
    // 1. Create VM with paranoid_type_checks disabled
    let mut vm_config = VMConfig::default();
    vm_config.paranoid_type_checks = false;
    
    // 2. Create malicious module bytes claiming to be 0xA::Authentic
    let malicious_module = create_module_with_fake_identity(
        actual_address: 0xB,
        claimed_address: 0xA,
        claimed_name: "Authentic"
    );
    
    // 3. Simulate storage corruption by storing malicious module
    //    at location 0xA::Authentic
    storage.corrupt_module_at(
        address: 0xA,
        name: "Authentic",
        bytes: malicious_module
    );
    
    // 4. Request module 0xA::Authentic
    let loaded_module = vm.load_module(0xA, "Authentic");
    
    // 5. Verify that without paranoid check, wrong module is loaded
    assert_eq!(loaded_module.self_addr(), 0xA); // Claims to be 0xA
    // But internal structures actually from 0xB
    
    // 6. Demonstrate type confusion in struct types
    // Types created will use wrong module ID, enabling fake capabilities
}
```

## Notes

This vulnerability represents a **configuration weakness** combined with a **defense-in-depth failure**. While mainnet is protected, testnet and other production-like environments remain vulnerable if operators disable paranoid checks for performance reasons. The paranoid check serves as critical protection against storage-layer bugs and should be mandatory across all production networks, not just mainnet.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L274-297)
```rust
    pub fn paranoid_check_module_address_and_name(
        &self,
        module: &CompiledModule,
        expected_address: &AccountAddress,
        expected_module_name: &IdentStr,
    ) -> VMResult<()> {
        if self.vm_config().paranoid_type_checks {
            let actual_address = module.self_addr();
            let actual_module_name = module.self_name();
            if expected_address != actual_address || expected_module_name != actual_module_name {
                let msg = format!(
                    "Expected module {}::{}, but got {}::{}",
                    expected_address, expected_module_name, actual_address, actual_module_name
                );
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(msg)
                        .with_sub_status(EPARANOID_FAILURE)
                        .finish(Location::Undefined),
                );
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/config.rs (L22-22)
```rust
    pub paranoid_type_checks: bool,
```

**File:** third_party/move/move-vm/runtime/src/config.rs (L66-66)
```rust
            paranoid_type_checks: false,
```

**File:** aptos-node/src/utils.rs (L55-55)
```rust
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
```

**File:** config/src/config/execution_config.rs (L44-44)
```rust
    pub paranoid_type_verification: bool,
```

**File:** config/src/config/execution_config.rs (L176-181)
```rust
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
```

**File:** aptos-move/aptos-vm-types/src/module_and_script_storage/state_view_adapter.rs (L56-65)
```rust
    fn fetch_module_bytes(
        &self,
        address: &AccountAddress,
        module_name: &IdentStr,
    ) -> VMResult<Option<Bytes>> {
        let state_key = StateKey::module(address, module_name);
        self.state_view
            .get_state_value_bytes(&state_key)
            .map_err(|e| module_storage_error!(address, module_name, e))
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L198-200)
```rust
            let module_id = module.module_id_for_handle(module_handle);
            let struct_name =
                StructIdentifier::new(module_id_pool, module_id, struct_name.to_owned());
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L3655-3660)
```rust
    pub fn module_id_for_handle(&self, module_handle: &ModuleHandle) -> ModuleId {
        ModuleId::new(
            *self.address_identifier_at(module_handle.address),
            self.identifier_at(module_handle.name).to_owned(),
        )
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/capability.move (L1-50)
```text
/// A module which defines the basic concept of
/// [*capabilities*](https://en.wikipedia.org/wiki/Capability-based_security) for managing access control.
///
/// EXPERIMENTAL
///
/// # Overview
///
/// A capability is a unforgeable token which testifies that a signer has authorized a certain operation.
/// The token is valid during the transaction where it is obtained. Since the type `capability::Cap` has
/// no ability to be stored in global memory, capabilities cannot leak out of a transaction. For every function
/// called within a transaction which has a capability as a parameter, it is guaranteed that the capability
/// has been obtained via a proper signer-based authorization step previously in the transaction's execution.
///
/// ## Usage
///
/// Initializing and acquiring capabilities is usually encapsulated in a module with a type
/// tag which can only be constructed by this module.
///
/// ```
/// module Pkg::Feature {
///   use std::capability::Cap;
///
///   /// A type tag used in Cap<Feature>. Only this module can create an instance,
///   /// and there is no public function other than Self::acquire which returns a value of this type.
///   /// This way, this module has full control how Cap<Feature> is given out.
///   struct Feature has drop {}
///
///   /// Initializes this module.
///   public fun initialize(s: &signer) {
///     // Create capability. This happens once at module initialization time.
///     // One needs to provide a witness for being the owner of Feature
///     // in the 2nd parameter.
///     <<additional conditions allowing to initialize this capability>>
///     capability::create<Feature>(s, &Feature{});
///   }
///
///   /// Acquires the capability to work with this feature.
///   public fun acquire(s: &signer): Cap<Feature> {
///     <<additional conditions allowing to acquire this capability>>
///     capability::acquire<Feature>(s, &Feature{});
///   }
///
///   /// Does something related to the feature. The caller must pass a Cap<Feature>.
///   public fun do_something(_cap: Cap<Feature>) { ... }
/// }
/// ```
///
/// ## Delegation
///
/// Capabilities come with the optional feature of *delegation*. Via `Self::delegate`, an owner of a capability
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
