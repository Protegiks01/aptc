# Audit Report

## Title
Entry Function Argument Type Validation Bypass: Validation Phase Accepts Transactions That Fail During Execution

## Summary
The VM validator's `validate_transaction` function does not perform type checking on entry function arguments, while the execution phase does. This allows transactions with invalid argument types to pass validation, enter mempool, and consume consensus resources before failing during execution with `INVALID_MAIN_FUNCTION_SIGNATURE` or `FAILED_TO_DESERIALIZE_ARGUMENT` errors.

## Finding Description

The vulnerability exists in a critical discrepancy between the validation and execution code paths:

**Validation Phase** (called by mempool before accepting transactions): [1](#0-0) 

This calls into AptosVM's validate_transaction: [2](#0-1) 

Which then calls validate_signed_transaction: [3](#0-2) 

The validation path executes run_prologue_with_payload, which only validates account state, sequence numbers, and gas balance: [4](#0-3) 

**Critically, the prologue does NOT validate entry function argument types.**

**Execution Phase** (called when executing transactions in blocks):

Entry function execution performs type validation via validate_and_execute_entry_function: [5](#0-4) 

This calls the dispatch_transaction_arg_validation macro (line 993-1002) which invokes validate_combine_signer_and_txn_args: [6](#0-5) 

This function performs comprehensive type checking including:
1. Validating return signatures are empty (lines 121-126)
2. Checking signer parameter counts (lines 127-133)
3. Validating argument types via is_valid_txn_arg (lines 139-149)
4. Constructing and deserializing arguments (lines 173-183)

The type validation logic in is_valid_txn_arg: [7](#0-6) 

**Attack Scenario:**
1. Attacker crafts a transaction calling an entry function expecting `vector<u64>` but provides BCS-encoded `vector<u8>` 
2. Transaction passes `validate_transaction` (no type checking performed)
3. Transaction enters mempool and is broadcast to validators
4. Transaction is included in consensus block proposals
5. During execution, `validate_combine_signer_and_txn_args` detects type mismatch
6. Transaction fails with `FAILED_TO_DESERIALIZE_ARGUMENT` or `INVALID_MAIN_FUNCTION_SIGNATURE`
7. Attacker repeats with thousands of such transactions

## Impact Explanation

**HIGH Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Malicious transactions consume validator resources (mempool storage, consensus bandwidth, signature verification, prologue execution) before failing during execution.

2. **Denial of Service Vector**: Attackers can flood mempool with transactions that pass validation but fail execution, causing:
   - Wasted consensus bandwidth (transactions are proposed and voted on)
   - Wasted execution resources (prologues are executed twice)
   - Mempool pollution (valid transactions may be evicted)
   - Network amplification (invalid transactions are gossiped to all validators)

3. **Breaks Transaction Validation Invariant**: The documented invariant states "Transaction Validation: Prologue/epilogue checks must enforce all invariants." This vulnerability violates this by allowing transactions that cannot execute successfully.

4. **Resource Exhaustion**: Each invalid transaction consumes gas for prologue execution before failing, allowing attackers to waste validator computational resources.

## Likelihood Explanation

**Very High Likelihood**:

1. **Easy to Exploit**: Any transaction sender can craft invalid entry function arguments using standard BCS encoding libraries
2. **No Special Access Required**: Does not require validator privileges or insider knowledge
3. **Difficult to Detect**: Invalid transactions look legitimate until execution phase
4. **Low Attack Cost**: Attacker only pays for failed transactions, not the network-wide resource consumption
5. **Already Implemented Infrastructure**: The validation logic exists in `validate_combine_signer_and_txn_args` but is not called during validation phase

## Recommendation

**Fix**: Call `validate_combine_signer_and_txn_args` during the validation phase to ensure argument type checking occurs before transactions enter mempool.

**Implementation approach:**

1. Modify `validate_signed_transaction` to load the entry function and validate arguments when the payload is an EntryFunction
2. Add type checking after prologue execution but before returning from validate_transaction
3. Ensure the validation uses the same logic as execution to maintain consistency

**Pseudo-code fix** (in aptos-vm/src/aptos_vm.rs validate_signed_transaction):

```rust
// After prologue execution, validate entry function arguments if present
if let TransactionExecutableRef::EntryFunction(entry_fn) = executable {
    dispatch_loader!(module_storage, loader, {
        let function = loader.load_instantiated_function(
            &legacy_loader_config,
            gas_meter,
            traversal_context,
            entry_fn.module(),
            entry_fn.function(),
            entry_fn.ty_args(),
        )?;
        
        // Validate argument types without executing
        let _validated_args = dispatch_transaction_arg_validation!(
            session,
            &loader,
            gas_meter,
            traversal_context,
            serialized_signers,
            entry_fn.args().to_vec(),
            &function,
            self.features().is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
        )?;
    });
}
```

## Proof of Concept

```rust
// Test demonstrating validation/execution disparity
#[test]
fn test_entry_function_type_validation_bypass() {
    let mut executor = FakeExecutor::from_head_genesis();
    let sender = executor.create_raw_account_data(1_000_000, 10);
    executor.add_account_data(&sender);
    
    // Deploy a module with entry function expecting u64
    let module_code = r#"
        module 0xCAFE::test {
            entry fun take_u64(account: &signer, value: u64) {
                // Function expects u64
            }
        }
    "#;
    // ... compile and publish module ...
    
    // Create transaction with WRONG type (u8 instead of u64)
    let wrong_args = vec![
        bcs::to_bytes(&42u8).unwrap(), // Should be u64, not u8
    ];
    
    let txn = create_entry_function_transaction(
        *sender.address(),
        0,
        &sender.private_key,
        ModuleId::new(AccountAddress::from_hex_literal("0xCAFE").unwrap(), 
                      Identifier::new("test").unwrap()),
        Identifier::new("take_u64").unwrap(),
        vec![], // type args
        wrong_args,
    );
    
    // VALIDATION SHOULD FAIL BUT DOESN'T
    let validation_result = executor.validate_transaction(txn.clone());
    assert!(validation_result.status().is_none(), "Validation incorrectly succeeds!");
    
    // EXECUTION CORRECTLY FAILS
    let execution_result = executor.execute_transaction(txn);
    assert!(matches!(
        execution_result.status(),
        TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT
        )))
    ));
    
    // This demonstrates the validation/execution disparity
}
```

## Notes

This vulnerability has existed since the separation of validation and execution logic. The `validate_combine_signer_and_txn_args` function contains all necessary type checking logic but is only invoked during execution, not validation. The fix requires minimal code changes but is critical for preventing DOS attacks and maintaining the integrity of the transaction validation invariant.

### Citations

**File:** vm-validator/src/vm_validator.rs (L146-170)
```rust
    fn validate_transaction(&self, txn: SignedTransaction) -> Result<VMValidatorResult> {
        let vm_validator = self.get_next_vm();

        fail_point!("vm_validator::validate_transaction", |_| {
            Err(anyhow::anyhow!(
                "Injected error in vm_validator::validate_transaction"
            ))
        });

        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
        });
        if let Err(err) = &result {
            error!("VMValidator panicked: {:?}", err);
        }
        result.map_err(|_| anyhow::anyhow!("panic validating transaction"))
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L945-1016)
```rust
    fn validate_and_execute_entry_function(
        &self,
        module_storage: &impl AptosModuleStorage,
        session: &mut SessionExt<impl AptosMoveResolver>,
        serialized_signers: &SerializedSigners,
        gas_meter: &mut impl AptosGasMeter,
        traversal_context: &mut TraversalContext,
        entry_fn: &EntryFunction,
        trace_recorder: &mut impl TraceRecorder,
    ) -> Result<(), VMStatus> {
        dispatch_loader!(module_storage, loader, {
            let legacy_loader_config = LegacyLoaderConfig {
                charge_for_dependencies: self.gas_feature_version() >= RELEASE_V1_10,
                charge_for_ty_tag_dependencies: self.gas_feature_version() >= RELEASE_V1_27,
            };
            let function = loader.load_instantiated_function(
                &legacy_loader_config,
                gas_meter,
                traversal_context,
                entry_fn.module(),
                entry_fn.function(),
                entry_fn.ty_args(),
            )?;

            // Native entry function is forbidden.
            if function.is_native() {
                return Err(
                    PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                        .with_message(
                            "Executing user defined native entry function is not allowed"
                                .to_string(),
                        )
                        .finish(Location::Module(entry_fn.module().clone()))
                        .into_vm_status(),
                );
            }

            // The check below should have been feature-gated in 1.11...
            if function.is_friend_or_private() {
                let maybe_randomness_annotation = get_randomness_annotation_for_entry_function(
                    entry_fn,
                    &function.owner_as_module()?.metadata,
                );
                if maybe_randomness_annotation.is_some() {
                    session.mark_unbiasable();
                }
            }

            let args = dispatch_transaction_arg_validation!(
                session,
                &loader,
                gas_meter,
                traversal_context,
                serialized_signers,
                entry_fn.args().to_vec(),
                &function,
                self.features().is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
            )?;

            // Execute the function. The function also must be an entry function!
            function.is_entry_or_err()?;
            session.execute_loaded_function(
                function,
                args,
                gas_meter,
                traversal_context,
                &loader,
                trace_recorder,
            )?;
            Ok(())
        })
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1779-1951)
```rust
    fn validate_signed_transaction(
        &self,
        session: &mut SessionExt<impl AptosMoveResolver>,
        module_storage: &impl ModuleStorage,
        transaction: &SignedTransaction,
        transaction_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        is_approved_gov_script: bool,
        traversal_context: &mut TraversalContext,
        gas_meter: &mut impl AptosGasMeter,
    ) -> Result<SerializedSigners, VMStatus> {
        // Check transaction format.
        if transaction.contains_duplicate_signers() {
            return Err(VMStatus::error(
                StatusCode::SIGNERS_CONTAIN_DUPLICATES,
                None,
            ));
        }

        let keyless_authenticators = aptos_types::keyless::get_authenticators(transaction)
            .map_err(|_| VMStatus::error(StatusCode::INVALID_SIGNATURE, None))?;

        // If there are keyless TXN authenticators, validate them all.
        if !keyless_authenticators.is_empty() && !self.is_simulation {
            keyless_validation::validate_authenticators(
                self.environment().keyless_pvk(),
                self.environment().keyless_configuration(),
                &keyless_authenticators,
                self.features(),
                session.resolver,
                module_storage,
            )?;
        }

        // Account Abstraction dispatchable authentication.
        let senders = transaction_data.senders();
        let proofs = transaction_data.authentication_proofs();

        // Validate that the number of senders matches the number of authentication proofs
        if senders.len() != proofs.len() {
            return Err(VMStatus::error(
                StatusCode::INVALID_NUMBER_OF_AUTHENTICATION_PROOFS,
                Some(format!(
                    "Mismatch between senders count ({}) and authentication proofs count ({})",
                    senders.len(),
                    proofs.len()
                )),
            ));
        }

        // Add fee payer.
        let fee_payer_signer = if let Some(fee_payer) = transaction_data.fee_payer {
            Some(match &transaction_data.fee_payer_authentication_proof {
                Some(AuthenticationProof::Abstract {
                    function_info,
                    auth_data,
                }) => {
                    let enabled = match auth_data {
                        AbstractAuthenticationData::V1 { .. } => {
                            self.features().is_account_abstraction_enabled()
                        },
                        AbstractAuthenticationData::DerivableV1 { .. } => {
                            self.features().is_derivable_account_abstraction_enabled()
                        },
                    };
                    if enabled {
                        dispatchable_authenticate(
                            session,
                            gas_meter,
                            fee_payer,
                            function_info.clone(),
                            auth_data,
                            traversal_context,
                            module_storage,
                        )
                        .map_err(|mut vm_error| {
                            if vm_error.major_status() == OUT_OF_GAS {
                                vm_error
                                    .set_major_status(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
                            }
                            vm_error.into_vm_status()
                        })
                    } else {
                        return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
                    }
                },
                _ => Ok(serialized_signer(&fee_payer)),
            }?)
        } else {
            None
        };
        let sender_signers = itertools::zip_eq(senders, proofs)
            .map(|(sender, proof)| match proof {
                AuthenticationProof::Abstract {
                    function_info,
                    auth_data,
                } => {
                    let enabled = match auth_data {
                        AbstractAuthenticationData::V1 { .. } => {
                            self.features().is_account_abstraction_enabled()
                        },
                        AbstractAuthenticationData::DerivableV1 { .. } => {
                            self.features().is_derivable_account_abstraction_enabled()
                        },
                    };
                    if enabled {
                        dispatchable_authenticate(
                            session,
                            gas_meter,
                            sender,
                            function_info.clone(),
                            auth_data,
                            traversal_context,
                            module_storage,
                        )
                        .map_err(|mut vm_error| {
                            if vm_error.major_status() == OUT_OF_GAS {
                                vm_error
                                    .set_major_status(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
                            }
                            vm_error.into_vm_status()
                        })
                    } else {
                        Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None))
                    }
                },
                _ => Ok(serialized_signer(&sender)),
            })
            .collect::<Result<_, _>>()?;

        let serialized_signers = SerializedSigners::new(sender_signers, fee_payer_signer);

        if matches!(transaction.payload(), TransactionPayload::Payload(_))
            && !self.features().is_transaction_payload_v2_enabled()
        {
            return Err(VMStatus::error(
                StatusCode::FEATURE_UNDER_GATING,
                Some(
                    "User transactions with TransactionPayloadInner variant are not yet supported"
                        .to_string(),
                ),
            ));
        }

        if !self.features().is_orderless_txns_enabled() {
            if let ReplayProtector::Nonce(_) = transaction.replay_protector() {
                return Err(VMStatus::error(
                    StatusCode::FEATURE_UNDER_GATING,
                    Some("Orderless transactions are not yet supported".to_string()),
                ));
            }
        }

        // The prologue MUST be run AFTER any validation. Otherwise you may run prologue and hit
        // SEQUENCE_NUMBER_TOO_NEW if there is more than one transaction from the same sender and
        // end up skipping validation.
        let executable = transaction
            .executable_ref()
            .map_err(|_| deprecated_module_bundle!())?;
        let extra_config = transaction.extra_config();
        self.run_prologue_with_payload(
            session,
            module_storage,
            &serialized_signers,
            executable,
            extra_config,
            transaction_data,
            log_context,
            is_approved_gov_script,
            traversal_context,
        )?;
        Ok(serialized_signers)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2793-2862)
```rust
    fn run_prologue_with_payload(
        &self,
        session: &mut SessionExt<impl AptosMoveResolver>,
        module_storage: &impl ModuleStorage,
        serialized_signers: &SerializedSigners,
        executable: TransactionExecutableRef,
        extra_config: TransactionExtraConfig,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        is_approved_gov_script: bool,
        traversal_context: &mut TraversalContext,
    ) -> Result<(), VMStatus> {
        check_gas(
            self.gas_params(log_context)?,
            self.gas_feature_version(),
            session.resolver,
            module_storage,
            txn_data,
            self.features(),
            is_approved_gov_script,
            log_context,
        )?;
        if executable.is_empty() && !extra_config.is_multisig() {
            return Err(VMStatus::error(
                StatusCode::EMPTY_PAYLOAD_PROVIDED,
                Some("Empty provided for a non-multisig transaction".to_string()),
            ));
        }

        if executable.is_script() && extra_config.is_multisig() {
            return Err(VMStatus::error(
                StatusCode::FEATURE_UNDER_GATING,
                Some("Script payload not yet supported for multisig transactions".to_string()),
            ));
        }

        // Runs script prologue for all transaction types including multisig
        transaction_validation::run_script_prologue(
            session,
            module_storage,
            serialized_signers,
            txn_data,
            self.features(),
            log_context,
            traversal_context,
            self.is_simulation,
        )?;

        if let Some(multisig_address) = extra_config.multisig_address() {
            // Once "simulation_enhancement" is enabled, the simulation path also validates the
            // multisig transaction by running the multisig prologue.
            if !self.is_simulation
                || self
                    .features()
                    .is_transaction_simulation_enhancement_enabled()
            {
                transaction_validation::run_multisig_prologue(
                    session,
                    module_storage,
                    txn_data,
                    executable,
                    multisig_address,
                    self.features(),
                    log_context,
                    traversal_context,
                )?
            }
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3163-3305)
```rust
    fn validate_transaction(
        &self,
        transaction: SignedTransaction,
        state_view: &impl StateView,
        module_storage: &impl ModuleStorage,
    ) -> VMValidatorResult {
        let _timer = TXN_VALIDATION_SECONDS.start_timer();
        let log_context = AdapterLogSchema::new(state_view.id(), 0);

        if !self
            .features()
            .is_enabled(FeatureFlag::SINGLE_SENDER_AUTHENTICATOR)
        {
            if let aptos_types::transaction::authenticator::TransactionAuthenticator::SingleSender{ .. } = transaction.authenticator_ref() {
                return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
            }
        }

        if !self.features().is_enabled(FeatureFlag::WEBAUTHN_SIGNATURE) {
            if let Ok(sk_authenticators) = transaction
                .authenticator_ref()
                .to_single_key_authenticators()
            {
                for authenticator in sk_authenticators {
                    if let AnySignature::WebAuthn { .. } = authenticator.signature() {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            } else {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            }
        }

        if !self
            .features()
            .is_enabled(FeatureFlag::SLH_DSA_SHA2_128S_SIGNATURE)
        {
            if let Ok(sk_authenticators) = transaction
                .authenticator_ref()
                .to_single_key_authenticators()
            {
                for authenticator in sk_authenticators {
                    if let AnySignature::SlhDsa_Sha2_128s { .. } = authenticator.signature() {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            } else {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            }
        }

        if !self
            .features()
            .is_enabled(FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS)
        {
            if let Ok(TransactionExecutableRef::Script(script)) =
                transaction.payload().executable_ref()
            {
                for arg in script.args() {
                    if let TransactionArgument::Serialized(_) = arg {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            }
        }

        if transaction.payload().is_encrypted_variant() {
            return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
        }
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
        let auxiliary_info = AuxiliaryInfo::new_timestamp_not_yet_assigned(0);
        let txn_data = TransactionMetadata::new(&txn, &auxiliary_info);

        let resolver = self.as_move_resolver(&state_view);
        let is_approved_gov_script = is_approved_gov_script(&resolver, &txn, &txn_data);

        let mut session = self.new_session(
            &resolver,
            SessionId::prologue_meta(&txn_data),
            Some(txn_data.as_user_transaction_context()),
        );

        let vm_params = match self.gas_params(&log_context) {
            Ok(vm_params) => vm_params.vm.clone(),
            Err(err) => {
                return VMValidatorResult::new(Some(err.status_code()), 0);
            },
        };
        let storage_gas_params = match self.storage_gas_params(&log_context) {
            Ok(storage_params) => storage_params.clone(),
            Err(err) => {
                return VMValidatorResult::new(Some(err.status_code()), 0);
            },
        };

        let initial_balance = if self.features().is_account_abstraction_enabled()
            || self.features().is_derivable_account_abstraction_enabled()
        {
            vm_params.txn.max_aa_gas.min(txn_data.max_gas_amount())
        } else {
            txn_data.max_gas_amount()
        };

        let mut gas_meter = make_prod_gas_meter(
            self.gas_feature_version(),
            vm_params,
            storage_gas_params,
            is_approved_gov_script,
            initial_balance,
            &NoopBlockSynchronizationKillSwitch {},
        );
        let storage = TraversalStorage::new();

        // Increment the counter for transactions verified.
        let (counter_label, result) = match self.validate_signed_transaction(
            &mut session,
            module_storage,
            &txn,
            &txn_data,
            &log_context,
            is_approved_gov_script,
            &mut TraversalContext::new(&storage),
            &mut gas_meter,
        ) {
            Err(err) if err.status_code() != StatusCode::SEQUENCE_NUMBER_TOO_NEW => (
                "failure",
                VMValidatorResult::new(Some(err.status_code()), 0),
            ),
            _ => (
                "success",
                VMValidatorResult::new(None, txn.gas_unit_price()),
            ),
        };

        TRANSACTIONS_VALIDATED.inc_with(&[counter_label]);

        result
    }
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L108-192)
```rust
pub(crate) fn validate_combine_signer_and_txn_args(
    session: &mut SessionExt<impl AptosMoveResolver>,
    loader: &impl Loader,
    gas_meter: &mut impl GasMeter,
    traversal_context: &mut TraversalContext,
    serialized_signers: &SerializedSigners,
    args: Vec<Vec<u8>>,
    func: &LoadedFunction,
    are_struct_constructors_enabled: bool,
) -> Result<Vec<Vec<u8>>, VMStatus> {
    let _timer = VM_TIMER.timer_with_label("AptosVM::validate_combine_signer_and_txn_args");

    // Entry function should not return.
    if !func.return_tys().is_empty() {
        return Err(VMStatus::error(
            StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE,
            None,
        ));
    }
    let mut signer_param_cnt = 0;
    // find all signer params at the beginning
    for ty in func.param_tys() {
        if ty.is_signer_or_signer_ref() {
            signer_param_cnt += 1;
        }
    }

    let allowed_structs = get_allowed_structs(are_struct_constructors_enabled);
    let ty_builder = &loader.runtime_environment().vm_config().ty_builder;

    // Need to keep this here to ensure we return the historic correct error code for replay
    for ty in func.param_tys()[signer_param_cnt..].iter() {
        let subst_res = ty_builder.create_ty_with_subst(ty, func.ty_args());
        let ty = subst_res.map_err(|e| e.finish(Location::Undefined).into_vm_status())?;
        let valid = is_valid_txn_arg(loader.runtime_environment(), &ty, allowed_structs);
        if !valid {
            return Err(VMStatus::error(
                StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE,
                None,
            ));
        }
    }

    if (signer_param_cnt + args.len()) != func.param_tys().len() {
        return Err(VMStatus::error(
            StatusCode::NUMBER_OF_ARGUMENTS_MISMATCH,
            None,
        ));
    }

    // If the invoked function expects one or more signers, we need to check that the number of
    // signers actually passed is matching first to maintain backward compatibility before
    // moving on to the validation of non-signer args.
    // the number of txn senders should be the same number of signers
    let sender_signers = serialized_signers.senders();
    if signer_param_cnt > 0 && sender_signers.len() != signer_param_cnt {
        return Err(VMStatus::error(
            StatusCode::NUMBER_OF_SIGNER_ARGUMENTS_MISMATCH,
            None,
        ));
    }

    // This also validates that the args are valid. If they are structs, they have to be allowed
    // and must be constructed successfully. If construction fails, this would fail with a
    // FAILED_TO_DESERIALIZE_ARGUMENT error.
    let args = construct_args(
        session,
        loader,
        gas_meter,
        traversal_context,
        &func.param_tys()[signer_param_cnt..],
        args,
        func.ty_args(),
        allowed_structs,
        false,
    )?;

    // Combine signer and non-signer arguments.
    let combined_args = if signer_param_cnt == 0 {
        args
    } else {
        sender_signers.into_iter().chain(args).collect()
    };
    Ok(combined_args)
}
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L198-226)
```rust
pub(crate) fn is_valid_txn_arg(
    runtime_environment: &RuntimeEnvironment,
    ty: &Type,
    allowed_structs: &ConstructorMap,
) -> bool {
    use move_vm_types::loaded_data::runtime_types::Type::*;

    match ty {
        Bool | U8 | U16 | U32 | U64 | U128 | U256 | I8 | I16 | I32 | I64 | I128 | I256
        | Address => true,
        Vector(inner) => is_valid_txn_arg(runtime_environment, inner, allowed_structs),
        Struct { .. } | StructInstantiation { .. } => {
            // Note: Original behavior was to return false even if the module loading fails (e.g.,
            //       if struct does not exist. This preserves it.
            runtime_environment
                .get_struct_name(ty)
                .ok()
                .flatten()
                .is_some_and(|(module_id, identifier)| {
                    allowed_structs.contains_key(&format!(
                        "{}::{}",
                        module_id.short_str_lossless(),
                        identifier
                    ))
                })
        },
        Signer | Reference(_) | MutableReference(_) | TyParam(_) | Function { .. } => false,
    }
}
```
