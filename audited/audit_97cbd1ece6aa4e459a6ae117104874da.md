# Audit Report

## Title
TOCTOU Vulnerability in Module Extension Creation Enables Cache Poisoning via Mismatched Bytecode

## Summary
The `into_verified_module_code_iter()` function creates `AptosModuleExtension` objects from StateValue data fetched independently from the verified module bytecode, without validating that the extension bytes match the verified code. This Time-of-Check-Time-of-Use (TOCTOU) vulnerability allows malicious or buggy StateView implementations to inject extensions with arbitrary bytes/hashes that differ from the verified module, breaking cache consistency invariants. [1](#0-0) 

## Finding Description

The vulnerability exists in the module cache population flow where verified modules are transferred from local cache to global cache:

**Step 1: Initial Module Loading & Verification**
When modules are first loaded, the `ModuleCodeBuilder::build()` method fetches module bytes, deserializes them, computes a hash, and creates a `BytesWithHash` extension containing those exact bytes: [2](#0-1) 

These modules are then verified using the Move bytecode verifier, which validates the bytecode structure and safety properties: [3](#0-2) 

**Step 2: Extension Re-creation Without Validation**
Later, when draining verified modules to the global cache via `into_verified_module_code_iter()`, the code:
1. Retrieves verified modules that were previously validated
2. Calls `state_view.get_state_value()` to fetch StateValue **again**
3. Creates a **new** `AptosModuleExtension` from this second fetch
4. Combines the old verified code with the new extension via `ModuleCode::from_arced_verified()` [4](#0-3) 

**The Critical Flaw:**
The `AptosModuleExtension::new()` constructor blindly accepts any StateValue and computes a hash from its bytes without validation: [5](#0-4) 

There is **no validation** that these bytes match the verified module bytecode. The `ModuleCode::from_arced_verified()` function also performs no validation: [6](#0-5) 

**Attack Vector:**
StateView implementations like `DeltaStateStore` use interior mutability (RwLock) and can be modified between the initial fetch and the extension creation: [7](#0-6) [8](#0-7) 

**Exploitation Scenario:**
1. Attacker controls execution environment using `DeltaStateStore` (e.g., in simulation/testing contexts)
2. Framework prefetch loads transaction_validation module with valid bytes B1
3. Module is verified from B1, cached with hash H1 = SHA3-256(B1)
4. Between verification and `into_verified_module_code_iter()`, attacker calls `set_state_value()` to inject malicious StateValue with bytes B2
5. Extension is created with bytes B2 and hash H2 = SHA3-256(B2) where B1 ≠ B2
6. Global cache now contains: verified code (from B1) + extension (with B2, H2)

**Invariant Violated:**
This breaks the fundamental assumption that module extensions contain the same bytes as the verified code. The extension's hash no longer corresponds to the verified bytecode, enabling cache poisoning.

## Impact Explanation

**Severity: Medium**

While this does not directly cause consensus divergence (since execution uses the verified `Module` struct, not extension bytes), it creates state inconsistencies that violate critical code invariants:

1. **Cache Consistency Violation**: Extension bytes/hash mismatch with verified code breaks the assumption that `extension.hash()` corresponds to the verified bytecode, as evidenced by its use in verification caching: [9](#0-8) 

2. **Data Integrity Issues**: When `unmetered_get_module_bytes()` retrieves module bytes, it returns unverified bytes from the extension: [10](#0-9) 

3. **Potential Future Exploits**: Code that assumes hash consistency could be exploited if the hash mismatch is not detected.

This qualifies as **Medium severity** per the bug bounty criteria: "State inconsistencies requiring intervention" - the global module cache contains inconsistent data requiring cache flush/reset.

## Likelihood Explanation

**Likelihood: Low-Medium**

Exploitation requires:
1. **Control over StateView implementation**: Attacker needs a mutable StateView (like `DeltaStateStore`) rather than production's immutable database-backed views
2. **Timing window**: Modification must occur between verification and extension creation
3. **Specific execution context**: Most likely in simulation/testing environments where `DeltaStateStore` is used

Production environments typically use immutable `DbStateView` or `CachedStateView` backed by database snapshots, making exploitation unlikely. However, the vulnerability exists in the code and could be triggered in:
- Transaction simulation endpoints
- Testing frameworks
- Custom execution environments
- Future code changes that introduce mutable state views

## Recommendation

Add validation in `into_verified_module_code_iter()` to ensure extension bytes match the verified module bytecode:

```rust
pub fn into_verified_module_code_iter(
    self,
) -> Result<...> {
    let (state_view, verified_modules_iter) = self
        .storage
        .into_module_storage()
        .unpack_into_verified_modules_iter();

    Ok(verified_modules_iter
        .map(|(key, verified_code)| {
            let extension = state_view
                .get_state_value(&StateKey::module_id(&key))
                .map_err(|err| { ... })?
                .map_or_else(|| { ... }, |state_value| {
                    let extension = AptosModuleExtension::new(state_value);
                    
                    // VALIDATION: Ensure extension bytes match verified code
                    let mut verified_bytes = Vec::new();
                    verified_code.as_ref().as_ref().serialize(&mut verified_bytes)
                        .map_err(|e| PanicError::CodeInvariantError(
                            format!("Failed to serialize verified module: {:?}", e)
                        ))?;
                    
                    if extension.bytes() != &Bytes::from(verified_bytes) {
                        return Err(PanicError::CodeInvariantError(format!(
                            "Extension bytes mismatch for module {}::{}. Hash in extension: {:?}, Expected verified code.",
                            key.address(), key.name(), extension.hash()
                        )));
                    }
                    
                    Ok(extension)
                })?;

            let module = ModuleCode::from_arced_verified(verified_code, Arc::new(extension));
            Ok((key, Arc::new(module)))
        })
        .collect::<Result<Vec<_>, PanicError>>()?
        .into_iter())
}
```

## Proof of Concept

```rust
#[test]
fn test_extension_toctou_vulnerability() {
    use aptos_types::state_store::{state_key::StateKey, state_value::StateValue};
    use aptos_transaction_simulation::DeltaStateStore;
    use move_core_types::{account_address::AccountAddress, identifier::Identifier};
    
    // Create DeltaStateStore with valid module
    let mut delta_store = DeltaStateStore::new();
    let module_id = ModuleId::new(AccountAddress::ONE, Identifier::new("test").unwrap());
    
    // Store valid module bytes
    let valid_module_bytes = compile_test_module(); // Hypothetical helper
    delta_store.set_state_value(
        StateKey::module_id(&module_id),
        StateValue::new_legacy(valid_module_bytes.clone().into())
    ).unwrap();
    
    // Load and verify module - this uses valid_module_bytes
    let code_storage = delta_store.as_aptos_code_storage(&runtime_env);
    code_storage.unmetered_get_eagerly_verified_module(
        module_id.address(),
        module_id.name()
    ).unwrap();
    
    // ATTACK: Modify DeltaStateStore with different bytes
    let malicious_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF]; // Invalid module bytes
    delta_store.set_state_value(
        StateKey::module_id(&module_id),
        StateValue::new_legacy(malicious_bytes.clone().into())
    ).unwrap();
    
    // Extract verified modules - extension created from malicious_bytes
    let verified_iter = code_storage.into_verified_module_code_iter().unwrap();
    
    for (_, module_code) in verified_iter {
        // VULNERABILITY: Extension contains malicious_bytes
        // but verified code is from valid_module_bytes
        assert_ne!(module_code.extension().bytes(), &Bytes::from(malicious_bytes));
        // This assertion would FAIL, proving the mismatch
    }
}
```

**Notes:**
- This vulnerability requires specific conditions (mutable StateView) that are uncommon in production
- The verified Module itself remains secure - only the extension metadata is affected
- While module behavior is not modified (behavior comes from verified code, not extensions), the cache consistency violation could enable future attacks or cause debugging difficulties
- Production deployments using immutable database-backed StateViews are largely protected, but the code should still enforce this invariant

### Citations

**File:** aptos-move/aptos-vm-types/src/module_and_script_storage/state_view_adapter.rs (L111-158)
```rust
    pub fn into_verified_module_code_iter(
        self,
    ) -> Result<
        impl Iterator<
            Item = (
                ModuleId,
                Arc<ModuleCode<CompiledModule, Module, AptosModuleExtension>>,
            ),
        >,
        PanicError,
    > {
        let (state_view, verified_modules_iter) = self
            .storage
            .into_module_storage()
            .unpack_into_verified_modules_iter();

        Ok(verified_modules_iter
            .map(|(key, verified_code)| {
                // We have cached the module previously, so we must be able to find it in storage.
                let extension = state_view
                    .get_state_value(&StateKey::module_id(&key))
                    .map_err(|err| {
                        let msg = format!(
                            "Failed to retrieve module {}::{} from storage {:?}",
                            key.address(),
                            key.name(),
                            err
                        );
                        PanicError::CodeInvariantError(msg)
                    })?
                    .map_or_else(
                        || {
                            let msg = format!(
                                "Module {}::{} should exist, but it does not anymore",
                                key.address(),
                                key.name()
                            );
                            Err(PanicError::CodeInvariantError(msg))
                        },
                        |state_value| Ok(AptosModuleExtension::new(state_value)),
                    )?;

                let module = ModuleCode::from_arced_verified(verified_code, Arc::new(extension));
                Ok((key, Arc::new(module)))
            })
            .collect::<Result<Vec<_>, PanicError>>()?
            .into_iter())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/implementations/unsync_module_storage.rs (L136-160)
```rust
    fn build(
        &self,
        key: &Self::Key,
    ) -> VMResult<Option<ModuleCode<Self::Deserialized, Self::Verified, Self::Extension>>> {
        let mut bytes = match self.ctx.fetch_module_bytes(key.address(), key.name())? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        // TODO: remove this once framework on mainnet is using the new option module
        if let Some(replaced_bytes) = self
            .ctx
            .runtime_environment()
            .get_module_bytes_override(key.address(), key.name())
        {
            bytes = replaced_bytes;
        }
        let compiled_module = self
            .ctx
            .runtime_environment()
            .deserialize_into_compiled_module(&bytes)?;
        let hash = sha3_256(&bytes);
        let extension = Arc::new(BytesWithHash::new(bytes, hash));
        let module = ModuleCode::from_deserialized(compiled_module, extension);
        Ok(Some(module))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L178-201)
```rust
    pub fn build_locally_verified_module(
        &self,
        compiled_module: Arc<CompiledModule>,
        module_size: usize,
        module_hash: &[u8; 32],
    ) -> VMResult<LocallyVerifiedModule> {
        if !VERIFIED_MODULES_CACHE.contains(module_hash) {
            let _timer =
                VM_TIMER.timer_with_label("move_bytecode_verifier::verify_module_with_config");

            // For regular execution, we cache already verified modules. Note that this even caches
            // verification for the published modules. This should be ok because as long as the
            // hash is the same, the deployed bytecode and any dependencies are the same, and so
            // the cached verification result can be used.
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
            check_natives(compiled_module.as_ref())?;
            VERIFIED_MODULES_CACHE.put(*module_hash);
        }

        Ok(LocallyVerifiedModule(compiled_module, module_size))
    }
```

**File:** types/src/vm/modules.rs (L22-32)
```rust
impl AptosModuleExtension {
    /// Creates new extension based on [StateValue].
    pub fn new(state_value: StateValue) -> Self {
        let (state_value_metadata, bytes) = state_value.unpack();
        let hash = sha3_256(&bytes);
        Self {
            bytes,
            hash,
            state_value_metadata,
        }
    }
```

**File:** third_party/move/move-vm/types/src/code/cache/module_cache.rs (L38-44)
```rust
    /// Creates new [ModuleCode] from [Arc]ed verified code.
    pub fn from_arced_verified(verified_code: Arc<VC>, extension: Arc<E>) -> Self {
        Self {
            code: Code::from_arced_verified(verified_code),
            extension,
        }
    }
```

**File:** aptos-move/aptos-transaction-simulation/src/state_store.rs (L440-461)
```rust
pub struct DeltaStateStore<V> {
    base: V,
    states: RwLock<HashMap<StateKey, Option<StateValue>>>,
}

impl<V> TStateView for DeltaStateStore<V>
where
    V: TStateView<Key = StateKey>,
{
    type Key = StateKey;

    fn get_state_slot(&self, state_key: &Self::Key) -> StateViewResult<StateSlot> {
        let value_opt = self.get_state_value(state_key)?.map(|value| (0, value));
        Ok(StateSlot::from_db_get(value_opt))
    }

    fn get_state_value(&self, state_key: &Self::Key) -> StateViewResult<Option<StateValue>> {
        if let Some(res) = self.states.read().get(state_key) {
            return Ok(res.clone());
        }
        self.base.get_state_value(state_key)
    }
```

**File:** aptos-move/aptos-transaction-simulation/src/state_store.rs (L486-489)
```rust
    fn set_state_value(&self, state_key: StateKey, state_val: StateValue) -> Result<()> {
        self.states.write().insert(state_key, Some(state_val));
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L200-209)
```rust
    fn unmetered_get_module_bytes(
        &self,
        address: &AccountAddress,
        module_name: &IdentStr,
    ) -> VMResult<Option<Bytes>> {
        let id = ModuleId::new(*address, module_name.to_owned());
        Ok(self
            .get_module_or_build_with(&id, self)?
            .map(|(module, _)| module.extension().bytes().clone()))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L315-319)
```rust
        let locally_verified_code = runtime_environment.build_locally_verified_module(
            module.code().deserialized().clone(),
            module.extension().size_in_bytes(),
            module.extension().hash(),
        )?;
```
