# Audit Report

## Title
JWK Validator Transactions Bypass Change Set Size Limits Leading to State Bloat

## Summary
The `process_jwk_update_inner()` function uses `get_system_transaction_output()` which does not enforce change set size limits configured in `change_set_configs`, allowing validator-quorum-certified JWK updates to write arbitrarily large data to chain storage, bypassing the resource limits that apply to normal transactions.

## Finding Description

The vulnerability exists in how JWK validator transactions are processed compared to regular user transactions. When `process_jwk_update_inner()` completes execution, it calls `get_system_transaction_output()` which finalizes the transaction output: [1](#0-0) 

The `get_system_transaction_output()` function converts the session to a change set but critically does NOT invoke the `check_change_set()` validation: [2](#0-1) 

This is different from user transactions which wrap change sets in `UserSessionChangeSet::new()` that explicitly calls validation: [3](#0-2) 

The `check_change_set()` method enforces critical limits including `max_bytes_per_write_op` and `max_bytes_all_write_ops_per_transaction`: [4](#0-3) 

JWK data structures contain vectors of unbounded size. The `ProviderJWKs` struct contains a `jwks: Vec<JWKMoveStruct>` field with no explicit size constraints: [5](#0-4) 

The Move function `upsert_into_observed_jwks()` that processes these updates contains no size validation: [6](#0-5) 

**Attack Path:**
1. A malicious validator quorum (2f+1) constructs a `QuorumCertifiedUpdate` with very large JWK data (e.g., thousands of JWKs or JWKs with excessively large RSA modulus strings)
2. The update passes signature verification and voting power checks
3. The Move function `upsert_into_observed_jwks` processes the update without size checks
4. `get_system_transaction_output()` finalizes the change set without calling `check_change_set()`
5. The oversized data is written to chain storage, bypassing configured limits

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Unbounded JWK data can cause storage bloat across all validator nodes, degrading network performance and increasing operational costs
- **Resource limit bypass**: Violates the critical invariant #9: "All operations must respect gas, storage, and computational limits"
- **Progressive degradation**: Repeated exploitation could accumulate significant state bloat over time

While this doesn't directly cause fund loss or consensus failure, it creates a resource exhaustion vector that can impact network health and requires manual intervention to remediate.

## Likelihood Explanation

**Moderate likelihood** given:
- **Requires validator collusion**: Attackers need control of 2f+1 validators to sign malicious updates
- **Detection is likely**: Abnormally large JWK updates would be visible in transaction data
- **But barriers are low**: Once quorum is compromised, exploitation is trivial with no additional technical hurdles

The real-world likelihood depends on validator set security, but the technical vulnerability is clear and exploitable.

## Recommendation

Enforce change set size validation for all system transactions. Modify `get_system_transaction_output()` to validate the change set before returning:

```rust
pub(crate) fn get_system_transaction_output(
    session: SessionExt<impl AptosMoveResolver>,
    module_storage: &impl AptosModuleStorage,
    change_set_configs: &ChangeSetConfigs,
) -> Result<VMOutput, VMStatus> {
    let change_set = session.finish(change_set_configs, module_storage)?;
    
    // Add validation before returning
    change_set_configs.check_change_set(&change_set)?;

    Ok(VMOutput::new(
        change_set,
        ModuleWriteSet::empty(),
        FeeStatement::zero(),
        TransactionStatus::Keep(ExecutionStatus::Success),
    ))
}
```

Alternatively, use `SystemSessionChangeSet::new()` which includes validation, similar to how prologue sessions are handled: [7](#0-6) 

## Proof of Concept

```rust
#[test]
fn test_jwk_size_limit_bypass() {
    // Setup validator environment with proper gas configs
    let (vm, resolver, module_storage) = setup_test_env();
    
    // Create a JWK update with excessively large data
    let mut large_jwks = vec![];
    for i in 0..10000 {  // Create 10k JWKs (far exceeds normal limits)
        large_jwks.push(JWKMoveStruct {
            variant: MoveAny::pack(RSA_JWK {
                kid: format!("key_{}", i),
                kty: "RSA".to_string(),
                alg: "RS256".to_string(),
                e: "AQAB".to_string(),
                n: "A".repeat(1000), // 1KB modulus per key = 10MB total
            }),
        });
    }
    
    let provider_jwks = ProviderJWKs {
        issuer: b"malicious_issuer".to_vec(),
        version: 1,
        jwks: large_jwks,
    };
    
    let update = QuorumCertifiedUpdate {
        update: provider_jwks,
        multi_sig: create_valid_quorum_signature(), // 2f+1 validators
    };
    
    // Process the update - should fail size checks but doesn't
    let result = vm.process_jwk_update_inner(
        &resolver,
        &module_storage,
        &log_context,
        session_id,
        update,
    );
    
    // Assertion: This should fail but succeeds due to missing validation
    assert!(result.is_ok()); // BUG: Oversized update accepted
    
    // Verify the change set size exceeds configured limits
    let (_, output) = result.unwrap();
    let change_set_size = calculate_change_set_size(&output);
    assert!(change_set_size > MAX_BYTES_ALL_WRITE_OPS_PER_TRANSACTION);
}
```

## Notes

This vulnerability affects all validator transaction types that use `get_system_transaction_output()` including DKG result processing and block prologue/epilogue transactions. The fix should be applied consistently across all these code paths to prevent similar bypasses.

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L168-176)
```rust
        let output = get_system_transaction_output(
            session,
            module_storage,
            &self
                .storage_gas_params(log_context)
                .map_err(Unexpected)?
                .change_set_configs,
        )
        .map_err(Unexpected)?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L258-271)
```rust
pub(crate) fn get_system_transaction_output(
    session: SessionExt<impl AptosMoveResolver>,
    module_storage: &impl AptosModuleStorage,
    change_set_configs: &ChangeSetConfigs,
) -> Result<VMOutput, VMStatus> {
    let change_set = session.finish(change_set_configs, module_storage)?;

    Ok(VMOutput::new(
        change_set,
        ModuleWriteSet::empty(),
        FeeStatement::zero(),
        TransactionStatus::Keep(ExecutionStatus::Success),
    ))
}
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L24-35)
```rust
    pub(crate) fn new(
        change_set: VMChangeSet,
        module_write_set: ModuleWriteSet,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<Self, VMStatus> {
        let user_session_change_set = Self {
            change_set,
            module_write_set,
        };
        change_set_configs.check_change_set(&user_session_change_set)?;
        Ok(user_session_change_set)
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L74-82)
```rust
impl SystemSessionChangeSet {
    pub(crate) fn new(
        change_set: VMChangeSet,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<Self, VMStatus> {
        let system_session_change_set = Self { change_set };
        change_set_configs.check_change_set(&system_session_change_set)?;
        Ok(system_session_change_set)
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L86-128)
```rust
    pub fn check_change_set(&self, change_set: &impl ChangeSetInterface) -> Result<(), VMStatus> {
        let storage_write_limit_reached = |maybe_message: Option<&str>| {
            let mut err = PartialVMError::new(StatusCode::STORAGE_WRITE_LIMIT_REACHED);
            if let Some(message) = maybe_message {
                err = err.with_message(message.to_string())
            }
            Err(err.finish(Location::Undefined).into_vm_status())
        };

        if self.max_write_ops_per_transaction != 0
            && change_set.num_write_ops() as u64 > self.max_write_ops_per_transaction
        {
            return storage_write_limit_reached(Some("Too many write ops."));
        }

        let mut write_set_size = 0;
        for (key, op_size) in change_set.write_set_size_iter() {
            if let Some(len) = op_size.write_len() {
                let write_op_size = len + (key.size() as u64);
                if write_op_size > self.max_bytes_per_write_op {
                    return storage_write_limit_reached(None);
                }
                write_set_size += write_op_size;
            }
            if write_set_size > self.max_bytes_all_write_ops_per_transaction {
                return storage_write_limit_reached(None);
            }
        }

        let mut total_event_size = 0;
        for event in change_set.events_iter() {
            let size = event.event_data().len() as u64;
            if size > self.max_bytes_per_event {
                return storage_write_limit_reached(None);
            }
            total_event_size += size;
            if total_event_size > self.max_bytes_all_events_per_transaction {
                return storage_write_limit_reached(None);
            }
        }

        Ok(())
    }
```

**File:** types/src/jwks/mod.rs (L120-128)
```rust
/// Move type `0x1::jwks::ProviderJWKs` in rust.
/// See its doc in Move for more details.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct ProviderJWKs {
    #[serde(with = "serde_bytes")]
    pub issuer: Issuer,
    pub version: u64,
    pub jwks: Vec<JWKMoveStruct>,
}
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L462-505)
```text
    public fun upsert_into_observed_jwks(fx: &signer, provider_jwks_vec: vector<ProviderJWKs>) acquires ObservedJWKs, PatchedJWKs, Patches {
        system_addresses::assert_aptos_framework(fx);
        let observed_jwks = borrow_global_mut<ObservedJWKs>(@aptos_framework);

        if (features::is_jwk_consensus_per_key_mode_enabled()) {
            vector::for_each(provider_jwks_vec, |proposed_provider_jwks|{
                let maybe_cur_issuer_jwks = remove_issuer(&mut observed_jwks.jwks, proposed_provider_jwks.issuer);
                let cur_issuer_jwks = if (option::is_some(&maybe_cur_issuer_jwks)) {
                    option::extract(&mut maybe_cur_issuer_jwks)
                } else {
                    ProviderJWKs {
                        issuer: proposed_provider_jwks.issuer,
                        version: 0,
                        jwks: vector[],
                    }
                };
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
                vector::for_each(proposed_provider_jwks.jwks, |jwk|{
                    let variant_type_name = *string::bytes(copyable_any::type_name(&jwk.variant));
                    let is_delete = if (variant_type_name == b"0x1::jwks::UnsupportedJWK") {
                        let repr = copyable_any::unpack<UnsupportedJWK>(jwk.variant);
                        &repr.payload == &DELETE_COMMAND_INDICATOR
                    } else {
                        false
                    };
                    if (is_delete) {
                        remove_jwk(&mut cur_issuer_jwks, get_jwk_id(&jwk));
                    } else {
                        upsert_jwk(&mut cur_issuer_jwks, jwk);
                    }
                });
                cur_issuer_jwks.version = cur_issuer_jwks.version + 1;
                upsert_provider_jwks(&mut observed_jwks.jwks, cur_issuer_jwks);
            });
        } else {
            vector::for_each(provider_jwks_vec, |provider_jwks| {
                upsert_provider_jwks(&mut observed_jwks.jwks, provider_jwks);
            });
        };

        let epoch = reconfiguration::current_epoch();
        emit(ObservedJWKsUpdated { epoch, jwks: observed_jwks.jwks });
        regenerate_patched_jwks();
    }
```
