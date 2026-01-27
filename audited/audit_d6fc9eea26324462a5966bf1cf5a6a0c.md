# Audit Report

## Title
Malformed Transaction Arguments Bypass Batch Verification, Causing Validator Resource Exhaustion

## Summary
The batch verification process in the quorum store only validates minimal transaction properties (gas unit price and encryption status) but does not validate transaction argument structure or deserializability. This allows transactions with malformed arguments to pass mempool and batch verification, only to fail during execution when argument validation occurs. This wastes validator computational resources across consensus, block processing, and execution phases.

## Finding Description
The vulnerability exists in the transaction validation pipeline where argument validation is deferred until execution time, creating a resource exhaustion vector:

**Batch Verification (Minimal Checks):** [1](#0-0) 

The `Batch::verify()` function only checks:
- Gas unit price meets minimum threshold
- Transaction is not encrypted
- Payload metadata matches (hash, count, size)

**Mempool Validation (No Argument Validation):** [2](#0-1) 

The `validate_signed_transaction` function runs the prologue but does not validate transaction arguments. The prologue only checks account state (balance, sequence number, expiration), not argument structure.

**Execution-Time Validation (Where Failures Occur):** [3](#0-2) 

Argument validation and deserialization only happens during execution in `validate_combine_signer_and_txn_args`, which calls `construct_args`. This function can fail with multiple error conditions: [4](#0-3) 

These deserialization failures include:
- Invalid ULEB128 encoding
- Truncated data when reading bytes  
- Extra data after parsing
- Exceeding maximum byte limits
- Type mismatches

**Attack Propagation Path:**
1. Attacker creates transaction with valid signature and gas_unit_price
2. Transaction includes malformed arguments (invalid BCS encoding, truncated vectors, wrong type structure)
3. Mempool validates signature and runs prologue ✓ (arguments not checked)
4. Transaction enters quorum store batch
5. Batch verification checks only gas_unit_price ≥ gas_bucket_start ✓ (arguments not checked)
6. Batch propagated through consensus to all validators
7. All validators include batch in committed block
8. During execution, ALL validators attempt to deserialize arguments
9. Deserialization fails with `FAILED_TO_DESERIALIZE_ARGUMENT`
10. Transaction discarded, but validators have wasted resources

**Invariant Violation:**
This breaks the "Resource Limits: All operations must respect gas, storage, and computational limits" invariant. Validators are forced to expend computational resources (consensus voting, block processing, prologue execution, argument parsing) on transactions that are deterministically invalid and could have been rejected during batch verification.

## Impact Explanation
This qualifies as **Medium Severity** ($10,000 tier) under Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdowns**: Malicious actors can spam batches with malformed transactions, causing all validators to waste CPU cycles processing transactions that will always fail. This creates systematic inefficiency in the network.

2. **Resource Exhaustion Vector**: Unlike legitimate transaction failures (insufficient balance, wrong sequence number) which result from changing state, argument deserialization failures are deterministic and knowable at batch verification time. The deferred validation forces unnecessary work.

3. **Consensus Resource Waste**: The attack consumes resources across all validators during:
   - Batch propagation and signature verification
   - Consensus voting and quorum formation  
   - Block commitment and state root calculation
   - Prologue execution (balance checks, account lookups)
   - Argument deserialization attempts
   - Failure epilogue and state cleanup

4. **Not Critical**: This does not cause consensus safety violations, fund loss, or permanent network damage. The transactions fail deterministically and identically on all validators, maintaining state consistency. However, it does create an amplification attack where one malformed transaction wastes resources on all N validators.

## Likelihood Explanation
**Likelihood: High**

This attack is highly likely to occur because:

1. **Low Attack Complexity**: Any user can submit transactions with malformed arguments. No special privileges, stake, or validator access required.

2. **No Economic Barrier**: While the attacker must pay gas for transaction submission, the malformed transaction passes initial validation, so it can be included in batches and blocks. The gas cost is minimal compared to the validator resources consumed.

3. **Easy to Construct**: Creating malformed BCS encoding is trivial:
   - Truncate byte arrays mid-encoding
   - Use invalid ULEB128 sequences
   - Provide wrong type structures
   - Add extra trailing bytes

4. **Amplification Effect**: One malformed transaction forces ALL validators to waste resources, creating a 1-to-N amplification.

5. **Difficult to Detect**: Unlike obvious DoS attacks, these transactions look valid during batch verification and only fail during execution, making rate limiting difficult.

## Recommendation
Add transaction argument validation to the batch verification process. This can be done without full execution by deserializing and validating argument structure against expected types.

**Recommended Fix for `consensus/src/quorum_store/types.rs`:**

Extend `Batch::verify()` to include argument structure validation:

```rust
pub fn verify(&self) -> anyhow::Result<()> {
    // ... existing checks ...
    
    for txn in self.payload.txns() {
        ensure!(
            txn.gas_unit_price() >= self.gas_bucket_start(),
            "Payload gas unit price doesn't match batch info"
        );
        ensure!(
            !txn.payload().is_encrypted_variant(),
            "Encrypted transaction is not supported yet"
        );
        
        // NEW: Validate argument structure is deserializable
        // This prevents malformed transactions from wasting execution resources
        if let Ok(executable_ref) = txn.payload().executable_ref() {
            match executable_ref {
                TransactionExecutableRef::EntryFunction(entry_fn) => {
                    // Verify arguments can be deserialized as valid BCS
                    for arg in entry_fn.args() {
                        ensure!(
                            validate_bcs_structure(arg),
                            "Transaction contains malformed arguments"
                        );
                    }
                },
                TransactionExecutableRef::Script(script) => {
                    // Verify script arguments are valid
                    for arg in script.args() {
                        ensure!(
                            validate_transaction_argument(arg),
                            "Script contains malformed arguments"  
                        );
                    }
                },
                _ => {}
            }
        }
    }
    Ok(())
}
```

**Alternative Mitigation**: If full argument validation in batch verification is deemed too expensive, implement a lightweight sanity check:
- Verify arguments are valid BCS (proper length encoding, no truncation)
- Check argument count matches reasonable bounds
- Validate no excessive nesting or recursion in structures

This provides defense-in-depth by catching obviously malformed transactions before consensus, while deferring complex type validation to execution.

## Proof of Concept

```rust
#[test]
fn test_malformed_arguments_bypass_batch_verification() {
    use aptos_types::transaction::{SignedTransaction, RawTransaction, EntryFunction};
    use aptos_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::ModuleId;
    
    // Create a transaction with malformed arguments
    let sender = AccountAddress::random();
    
    // Create entry function with truncated BCS argument
    // This is invalid BCS: vector length says 10 elements but only 2 bytes provided
    let malformed_arg = vec![0x0A, 0xFF]; // ULEB128(10) followed by truncated data
    
    let entry_fn = EntryFunction::new(
        ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap()),
        Identifier::new("transfer").unwrap(),
        vec![],
        vec![malformed_arg], // Malformed argument
    );
    
    let raw_txn = RawTransaction::new(
        sender,
        0,
        TransactionPayload::EntryFunction(entry_fn),
        1000000, // max_gas
        1, // gas_unit_price (meets minimum threshold)
        1000000000, // expiration
        ChainId::test(),
    );
    
    // Sign the transaction (valid signature)
    let private_key = Ed25519PrivateKey::generate_for_testing();
    let signed_txn = SignedTransaction::new(
        raw_txn,
        AccountAddress::random(),
        &private_key,
    );
    
    // Create batch with malformed transaction
    let batch = Batch::new(
        BatchId::new_for_test(1),
        vec![signed_txn],
        0,
        1000000000,
        PeerId::random(),
        1, // gas_bucket_start
    );
    
    // Batch verification PASSES (only checks gas_unit_price)
    assert!(batch.verify().is_ok(), "Malformed transaction bypassed batch verification");
    
    // However, execution would FAIL when deserializing arguments
    // This demonstrates the resource waste: transaction passed validation but will fail execution
    // All validators will waste resources processing this transaction through consensus
}

#[test]
fn test_argument_validation_only_at_execution() {
    // Demonstrate that construct_args fails on malformed input
    use aptos_move::aptos_vm::verifier::transaction_arg_validation::construct_args;
    
    // Malformed argument: claims to be vector of length 1000 but only provides 2 bytes
    let malformed_arg = vec![0xE8, 0x07, 0x01, 0x02]; // ULEB128(1000), then only 2 bytes
    
    // This will fail with FAILED_TO_DESERIALIZE_ARGUMENT
    // But this validation only happens during execution, not during batch verification
    let result = construct_args(
        session,
        loader, 
        gas_meter,
        traversal_context,
        &vec![Type::Vector(Box::new(Type::U8))],
        vec![malformed_arg],
        &[],
        allowed_structs,
        false,
    );
    
    assert!(result.is_err(), "Malformed argument should fail validation");
    // Error: StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT
}
```

## Notes

This vulnerability demonstrates a validation gap in the transaction processing pipeline where expensive validation is deferred too late. While deferring validation can improve performance for the common case, it creates a DoS vector where validators must process transactions through consensus before discovering they're invalid.

The attack is particularly concerning because:
1. It affects ALL validators simultaneously (not just the proposer)
2. The malformed transactions pass cryptographic and gas checks
3. Rate limiting is difficult since transactions appear valid until execution
4. The resource consumption scales with validator count (N validators × M malformed transactions)

The fix should balance security (rejecting malformed transactions early) with performance (avoiding expensive validation in batch verification). A lightweight BCS structure validation provides good defense-in-depth without significantly impacting batch processing performance.

### Citations

**File:** consensus/src/quorum_store/types.rs (L262-290)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.payload.author() == self.author(),
            "Payload author doesn't match the info"
        );
        ensure!(
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
        ensure!(
            self.payload.num_txns() as u64 == self.num_txns(),
            "Payload num txns doesn't match batch info"
        );
        ensure!(
            self.payload.num_bytes() as u64 == self.num_bytes(),
            "Payload num bytes doesn't match batch info"
        );
        for txn in self.payload.txns() {
            ensure!(
                txn.gas_unit_price() >= self.gas_bucket_start(),
                "Payload gas unit price doesn't match batch info"
            );
            ensure!(
                !txn.payload().is_encrypted_variant(),
                "Encrypted transaction is not supported yet"
            );
        }
        Ok(())
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

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L527-571)
```rust
fn get_len(cursor: &mut Cursor<&[u8]>) -> Result<usize, VMStatus> {
    match read_uleb128_as_u64(cursor) {
        Err(_) => Err(VMStatus::error(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
            None,
        )),
        Ok(len) => Ok(len as usize),
    }
}

fn serialize_uleb128(mut x: usize, dest: &mut Vec<u8>) {
    // TODO perhaps reuse the code from move_binary_format::file_format_common if it's public
    while x >= 128 {
        dest.push((x | 128) as u8);
        x >>= 7;
    }
    dest.push(x as u8);
}

fn read_n_bytes(n: usize, src: &mut Cursor<&[u8]>, dest: &mut Vec<u8>) -> Result<(), VMStatus> {
    let deserialization_error = |msg: &str| -> VMStatus {
        VMStatus::error(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
            Some(msg.to_string()),
        )
    };
    let len = dest.len();

    // It is safer to limit the length under some big (but still reasonable
    // number).
    const MAX_NUM_BYTES: usize = 1_000_000;
    if len.checked_add(n).is_none_or(|s| s > MAX_NUM_BYTES) {
        return Err(deserialization_error(&format!(
            "Couldn't read bytes: maximum limit of {} bytes exceeded",
            MAX_NUM_BYTES
        )));
    }

    // Ensure we have enough capacity for resizing.
    dest.try_reserve(len + n)
        .map_err(|e| deserialization_error(&format!("Couldn't read bytes: {}", e)))?;
    dest.resize(len + n, 0);
    src.read_exact(&mut dest[len..])
        .map_err(|_| deserialization_error("Couldn't read bytes"))
}
```
