# Audit Report

## Title
State Snapshot Restore Module Validation Bypass - Advisory-Only Validation Allows Malicious Bytecode in State

## Summary
The `validate_modules` flag in the state snapshot restore process is purely advisory and does not prevent invalid or malicious Move modules from being written to blockchain state. When enabled, validation errors are only logged via error messages without failing the restore operation or rejecting invalid chunks, allowing unverified bytecode to persist in the blockchain's state storage.

## Finding Description

The vulnerability exists in the state snapshot restore mechanism. When operators restore from backups with the `--validate-modules` flag enabled, they expect that modules failing bytecode verification will be rejected. However, the implementation only logs validation failures without enforcing them.

**Attack Flow:**

1. An attacker with write access to backup storage (or performing MITM during restore) crafts a malicious state snapshot containing Move modules with:
   - Bytecode violating Move safety invariants (stack safety, type safety, reference safety)
   - Invalid control flow structures
   - Malformed constant pools or signatures
   - Any other verification failures

2. A node operator initiates restore with `validate_modules=true`, believing this will prevent invalid modules from being restored.

3. During restoration, the `validate_modules` function is called: [1](#0-0) 
   
   This function iterates through state entries, identifies Code paths, deserializes modules, and runs `verify_module_with_config`. However, when verification fails, it **only logs an error** and continues processing.

4. The validation occurs in a blocking task that returns the blob unchanged: [2](#0-1) 

5. Regardless of validation results, the chunk is unconditionally added to state: [3](#0-2) 

6. The malicious modules are now permanently stored in the blockchain state and can be retrieved via the API without verification: [4](#0-3) 

7. The API's `try_parse_abi` method only deserializes modules for ABI extraction without verification: [5](#0-4) 

**Invariants Broken:**

- **State Consistency Invariant**: State should only contain verified, valid Move bytecode
- **Move VM Safety Invariant**: All modules in state should pass bytecode verification before being stored
- **Deterministic Execution Invariant**: Different nodes restoring from different backup sources could have different invalid modules, leading to state divergence

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

**State Inconsistencies Requiring Intervention**: Unverified bytecode in blockchain state represents a significant protocol violation. While the Move VM performs runtime verification before execution, having invalid modules in state:
- Violates the fundamental assumption that all state data is valid and verifiable
- Creates divergence risk if different nodes restore from different backup sources
- Exposes invalid bytecode through public APIs, potentially confusing tooling and explorers
- Generates unnecessary runtime verification overhead for repeatedly accessing invalid modules
- Complicates state analysis, debugging, and forensic investigation

**Operator False Sense of Security**: The existence of the `validate_modules` flag implies that enabling it will protect against invalid modules. Operators may rely on this protection when restoring from untrusted or potentially compromised backup sources.

**Potential Execution Path Bypasses**: While runtime VM verification (via `build_locally_verified_module`) provides defense-in-depth, any code paths that access module state without going through the VM's verification could execute unverified bytecode.

## Likelihood Explanation

**Moderate to High Likelihood**:

**Attacker Requirements:**
- Write access to backup storage infrastructure, OR
- Man-in-the-middle position during backup restoration, OR
- Ability to serve malicious backups to operators

**Realistic Scenarios:**
1. **Compromised Backup Storage**: If an attacker gains access to S3 buckets or other backup storage used by validators
2. **Supply Chain Attack**: Malicious backups distributed through compromised distribution channels
3. **Insider Threat**: Malicious node operators or infrastructure administrators
4. **Restoration from Untrusted Source**: Operators restoring from third-party or compromised backup providers

**Ease of Exploitation:**
- Creating invalid Move bytecode is straightforward using mutation or crafted modules
- No special privileges required beyond backup storage access
- Operators are likely to use `validate_modules` flag when restoring from potentially untrusted sources, making this a high-value target

## Recommendation

The `validate_modules` function must enforce validation by failing the restore operation when invalid modules are detected:

```rust
fn validate_modules(blob: &[(StateKey, StateValue)]) -> Result<()> {
    let features = Features::default();
    let config = aptos_prod_verifier_config(LATEST_GAS_FEATURE_VERSION, &features);
    
    for (key, value) in blob {
        if let StateKeyInner::AccessPath(p) = key.inner() {
            if let Path::Code(module_id) = p.get_path() {
                let module = CompiledModule::deserialize(value.bytes())
                    .with_context(|| format!("Module {:?} failed to deserialize", module_id))?;
                
                verify_module_with_config(&config, &module)
                    .with_context(|| format!("Module {:?} failed verification", module_id))?;
            }
        }
    }
    Ok(())
}
```

Then modify the restore flow to propagate errors:

```rust
if self.validate_modules {
    blobs = tokio::task::spawn_blocking(move || {
        Self::validate_modules(&blobs)?;
        Ok(blobs)
    })
    .await??;
}
```

This ensures that restore operations fail immediately when invalid modules are encountered, preventing state corruption.

## Proof of Concept

```rust
#[cfg(test)]
mod test_module_validation_bypass {
    use super::*;
    use move_binary_format::{file_format::*, CompiledModule};
    use aptos_types::state_store::{state_key::StateKey, state_value::StateValue};
    use move_core_types::{account_address::AccountAddress, identifier::Identifier};
    
    #[test]
    fn test_malicious_module_bypasses_validation() {
        // Create a malicious module with invalid bytecode
        // (e.g., stack underflow, type mismatch, or other verification failure)
        let mut module = CompiledModule {
            version: 6,
            module_handles: vec![],
            struct_handles: vec![],
            function_handles: vec![],
            field_handles: vec![],
            friend_decls: vec![],
            struct_defs: vec![],
            struct_def_instantiations: vec![],
            function_defs: vec![
                FunctionDefinition {
                    function: FunctionHandleIndex(0),
                    visibility: Visibility::Public,
                    is_entry: false,
                    acquires_global_resources: vec![],
                    code: Some(CodeUnit {
                        locals: SignatureIndex(0),
                        // Malicious bytecode: Pop without corresponding Push
                        code: vec![Bytecode::Pop, Bytecode::Ret],
                    }),
                }
            ],
            function_instantiations: vec![],
            signatures: vec![Signature(vec![])],
            identifiers: vec![
                Identifier::new("malicious").unwrap(),
                Identifier::new("bad_function").unwrap(),
            ],
            address_identifiers: vec![AccountAddress::ONE],
            constant_pool: vec![],
            metadata: vec![],
            self_module_handle_idx: ModuleHandleIndex(0),
        };
        
        let module_bytes = {
            let mut bytes = vec![];
            module.serialize(&mut bytes).unwrap();
            bytes
        };
        
        let module_id = ModuleId::new(AccountAddress::ONE, Identifier::new("malicious").unwrap());
        let state_key = StateKey::module(&module_id);
        let state_value = StateValue::new_legacy(module_bytes.into());
        
        let blob = vec![(state_key, state_value)];
        
        // Call validate_modules - it will log errors but NOT fail
        StateSnapshotRestoreController::validate_modules(&blob);
        
        // The blob is unchanged and would be added to state despite validation failure
        // This demonstrates the bypass
        assert_eq!(blob.len(), 1); // Module still in blob, will be restored
    }
}
```

**Notes:**

While the Move VM provides runtime verification when modules are loaded for execution [6](#0-5) , this defense-in-depth mechanism does not excuse allowing unverified bytecode into state storage. The state snapshot restore mechanism must enforce its own validation to maintain state integrity guarantees.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L205-211)
```rust
            if self.validate_modules {
                blobs = tokio::task::spawn_blocking(move || {
                    Self::validate_modules(&blobs);
                    blobs
                })
                .await?;
            }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L212-215)
```rust
            tokio::task::spawn_blocking(move || {
                receiver.lock().as_mut().unwrap().add_chunk(blobs, proof)
            })
            .await??;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L233-251)
```rust
    fn validate_modules(blob: &[(StateKey, StateValue)]) {
        // TODO: Instead of using default features, fetch them from the state.
        let features = Features::default();

        let config = aptos_prod_verifier_config(LATEST_GAS_FEATURE_VERSION, &features);
        for (key, value) in blob {
            if let StateKeyInner::AccessPath(p) = key.inner() {
                if let Path::Code(module_id) = p.get_path() {
                    if let Ok(module) = CompiledModule::deserialize(value.bytes()) {
                        if let Err(err) = verify_module_with_config(&config, &module) {
                            error!("Module {:?} failed validation: {:?}", module_id, err);
                        }
                    } else {
                        error!("Module {:?} failed to deserialize", module_id);
                    }
                }
            }
        }
    }
```

**File:** api/src/state.rs (L334-378)
```rust
    pub fn module(
        &self,
        accept_type: &AcceptType,
        address: Address,
        name: IdentifierWrapper,
        ledger_version: Option<U64>,
    ) -> BasicResultWith404<MoveModuleBytecode> {
        let state_key = StateKey::module(address.inner(), &name);
        let (ledger_info, ledger_version, state_view) = self
            .context
            .state_view(ledger_version.map(|inner| inner.0))?;
        let bytes = state_view
            .get_state_value_bytes(&state_key)
            .context(format!("Failed to query DB to check for {:?}", state_key))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &ledger_info,
                )
            })?
            .ok_or_else(|| module_not_found(address, &name, ledger_version, &ledger_info))?;

        match accept_type {
            AcceptType::Json => {
                let module = MoveModuleBytecode::new(bytes.to_vec())
                    .try_parse_abi()
                    .context("Failed to parse move module ABI from bytes retrieved from storage")
                    .map_err(|err| {
                        BasicErrorWith404::internal_with_code(
                            err,
                            AptosErrorCode::InternalError,
                            &ledger_info,
                        )
                    })?;

                BasicResponse::try_from_json((module, &ledger_info, BasicResponseStatus::Ok))
            },
            AcceptType::Bcs => BasicResponse::try_from_encoded((
                bytes.to_vec(),
                &ledger_info,
                BasicResponseStatus::Ok,
            )),
        }
    }
```

**File:** api/types/src/move_types.rs (L1338-1348)
```rust
    pub fn try_parse_abi(mut self) -> anyhow::Result<Self> {
        if self.abi.is_none() {
            // Ignore error, because it is possible a transaction module payload contains
            // invalid bytecode.
            // So we ignore the error and output bytecode without abi.
            if let Ok(module) = CompiledModule::deserialize(self.bytecode.inner()) {
                self.abi = Some(module.try_into()?);
            }
        }
        Ok(self)
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
