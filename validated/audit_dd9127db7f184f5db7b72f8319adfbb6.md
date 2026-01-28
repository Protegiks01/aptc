# Audit Report

## Title
Feature Flag Bypass: Mempool Transactions Evade Post-Upgrade Cryptographic Restrictions

## Summary
Transactions validated under enabled feature flags remain in the mempool across epoch boundaries and execute successfully even after those feature flags are disabled. This allows deprecated or vulnerable cryptographic signature schemes to continue being accepted post-upgrade, bypassing security improvements.

## Finding Description

The Aptos blockchain uses feature flags to gate cryptographic signature schemes like `SLH_DSA_SHA2_128S_SIGNATURE`. When governance disables a signature scheme due to security concerns, the intent is to reject all transactions using that scheme. However, a critical architectural gap exists in the validation flow.

**Feature Flag Check Location Mismatch:**

During mempool admission, the `validate_transaction` method checks signature scheme feature flags including `WEBAUTHN_SIGNATURE` and `SLH_DSA_SHA2_128S_SIGNATURE`: [1](#0-0) 

However, during block execution, transactions are converted to `SignatureVerifiedTransaction` via cryptographic signature verification only: [2](#0-1) [3](#0-2) 

The consensus pipeline performs this signature-only conversion without feature flag rechecks: [4](#0-3) 

Critically, when execution validates transactions via `validate_signed_transaction`, it checks account abstraction and other features but **does NOT re-check signature scheme feature flags**: [5](#0-4) 

Meanwhile, mempool retrieves transactions without re-validation: [6](#0-5) 

And mempool does NOT flush on epoch changes - only the validator is restarted: [7](#0-6) [8](#0-7) 

When feature flags change at epoch boundaries: [9](#0-8) 

Pre-validated transactions in mempool continue executing because block execution only checks for invalid signatures: [10](#0-9) 

**Attack Scenario:**
1. Epoch N: `SLH_DSA_SHA2_128S_SIGNATURE` feature enabled
2. Attacker submits transactions with SLH-DSA signatures
3. Mempool validates transactions (feature flag check at lines 3196-3212 passes)
4. Governance disables feature for epoch N+1 due to discovered vulnerability
5. Epoch change applies feature changes but mempool is not flushed
6. Attacker's pre-validated transactions remain in mempool
7. Consensus pulls transactions without re-validation
8. Block execution converts to `SignatureVerifiedTransaction` (signature-only check)
9. Execution validates via `validate_signed_transaction` which lacks signature scheme feature checks
10. Transactions execute successfully, bypassing the disabled feature flag

## Impact Explanation

**HIGH Severity** - This vulnerability constitutes a protocol invariant violation:

1. **Security Bypass**: If a cryptographic scheme is disabled due to discovered vulnerabilities (e.g., signature malleability, weak parameters), attackers can continue exploiting it by pre-loading the mempool before the epoch change
2. **Protocol Invariant Violation**: Breaks the guarantee that disabled features are immediately rejected network-wide
3. **Governance Ineffectiveness**: Undermines the security upgrade mechanism, as feature flag disabling does not immediately stop vulnerable signature schemes from executing

While this does not cause immediate fund loss or consensus split (all validators execute the same transactions), it significantly weakens the blockchain's ability to respond to cryptographic vulnerabilities through the feature flag mechanism - a core security control.

## Likelihood Explanation

**HIGH Likelihood** - This will occur automatically in every protocol upgrade that disables a signature scheme:

1. **Automatic Occurrence**: Normal mempool behavior causes the bypass - no sophisticated attack needed
2. **Advance Notice**: Attackers have the governance proposal period to flood mempool with transactions
3. **No Special Privileges**: Any transaction sender can submit transactions normally
4. **Realistic Scenario**: Cryptographic upgrades are common when new vulnerabilities are discovered

The only requirement is that transactions exist in mempool when the epoch change occurs, which is guaranteed during normal network operation.

## Recommendation

Implement feature flag re-validation at execution time by adding signature scheme feature flag checks to `validate_signed_transaction`:

1. Add the same `SLH_DSA_SHA2_128S_SIGNATURE`, `WEBAUTHN_SIGNATURE`, and `SINGLE_SENDER_AUTHENTICATOR` checks from `validate_transaction` (lines 3172-3212) into `validate_signed_transaction` (around lines 1779-1950)

2. Alternatively, flush mempool on epoch changes when feature flags are modified, though this is more disruptive

3. Document that feature flag changes take effect only at epoch boundaries and may allow a small window where pre-validated transactions can still execute

## Proof of Concept

```rust
// Test demonstrating the bypass:
// 1. Enable SLH_DSA feature flag
// 2. Submit transaction with SLH-DSA signature to mempool
// 3. Mempool validates and accepts it
// 4. Disable SLH_DSA feature flag for next epoch
// 5. Trigger epoch change via features::on_new_epoch
// 6. Consensus pulls transaction from mempool
// 7. Block execution converts to SignatureVerifiedTransaction (passes - signature valid)
// 8. Transaction executes successfully despite feature now disabled
```

## Notes

The vulnerability exists because signature scheme feature flags are architectural controls split across two validation points:
- Mempool admission (`validate_transaction`) - checks feature flags
- Execution time (`validate_signed_transaction`) - does NOT check signature scheme feature flags

This split, combined with mempool persistence across epochs and no re-validation during execution, creates a bypass window for disabled cryptographic schemes.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1779-1950)
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2881-2885)
```rust
        if let SignatureVerifiedTransaction::Invalid(_) = txn {
            let vm_status = VMStatus::error(StatusCode::INVALID_SIGNATURE, None);
            let discarded_output = discarded_output(vm_status.status_code());
            return Ok((vm_status, discarded_output));
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3172-3212)
```rust
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
```

**File:** types/src/transaction/mod.rs (L1315-1318)
```rust
    pub fn verify_signature(&self) -> Result<()> {
        self.authenticator.verify(&self.raw_txn)?;
        Ok(())
    }
```

**File:** types/src/transaction/signature_verified_transaction.rs (L133-138)
```rust
                Ok(_) => SignatureVerifiedTransaction::Valid(Transaction::UserTransaction(txn)),
                Err(_) => SignatureVerifiedTransaction::Invalid(Transaction::UserTransaction(txn)),
            },
            _ => SignatureVerifiedTransaction::Valid(txn),
        }
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L670-677)
```rust
        let sig_verified_txns: Vec<SignatureVerifiedTransaction> = SIG_VERIFY_POOL.install(|| {
            let num_txns = input_txns.len();
            input_txns
                .into_par_iter()
                .with_min_len(optimal_min_len(num_txns, 32))
                .map(|t| Transaction::UserTransaction(t).into())
                .collect::<Vec<_>>()
        });
```

**File:** mempool/src/core_mempool/mempool.rs (L425-538)
```rust
    pub(crate) fn get_batch(
        &self,
        max_txns: u64,
        max_bytes: u64,
        return_non_full: bool,
        exclude_transactions: BTreeMap<TransactionSummary, TransactionInProgress>,
    ) -> Vec<SignedTransaction> {
        let start_time = Instant::now();
        let exclude_size = exclude_transactions.len();
        let mut inserted = HashSet::new();

        let gas_end_time = start_time.elapsed();

        let mut result = vec![];
        // Helper DS. Helps to mitigate scenarios where account submits several transactions
        // with increasing gas price (e.g. user submits transactions with sequence number 1, 2
        // and gas_price 1, 10 respectively)
        // Later txn has higher gas price and will be observed first in priority index iterator,
        // but can't be executed before first txn. Once observed, such txn will be saved in
        // `skipped` DS and rechecked once it's ancestor becomes available
        let mut skipped = HashSet::new();
        let mut total_bytes = 0;
        let mut txn_walked = 0usize;
        // iterate over the queue of transactions based on gas price
        'main: for txn in self.transactions.iter_queue() {
            txn_walked += 1;
            let txn_ptr = TxnPointer::from(txn);

            // TODO: removed gas upgraded logic. double check if it's needed
            if exclude_transactions.contains_key(&txn_ptr) {
                continue;
            }
            let txn_replay_protector = txn.replay_protector;
            match txn_replay_protector {
                ReplayProtector::SequenceNumber(txn_seq) => {
                    let txn_in_sequence = txn_seq > 0
                        && Self::txn_was_chosen(
                            txn.address,
                            txn_seq - 1,
                            &inserted,
                            &exclude_transactions,
                        );
                    let account_sequence_number =
                        self.transactions.get_account_sequence_number(&txn.address);
                    // include transaction if it's "next" for given account or
                    // we've already sent its ancestor to Consensus.
                    if txn_in_sequence || account_sequence_number == Some(&txn_seq) {
                        inserted.insert((txn.address, txn_replay_protector));
                        result.push((txn.address, txn_replay_protector));
                        if (result.len() as u64) == max_txns {
                            break;
                        }
                        // check if we can now include some transactions
                        // that were skipped before for given account
                        let (skipped_txn_sender, mut skipped_txn_seq_num) =
                            (txn.address, txn_seq + 1);
                        while skipped.remove(&(skipped_txn_sender, skipped_txn_seq_num)) {
                            inserted.insert((
                                skipped_txn_sender,
                                ReplayProtector::SequenceNumber(skipped_txn_seq_num),
                            ));
                            result.push((
                                skipped_txn_sender,
                                ReplayProtector::SequenceNumber(skipped_txn_seq_num),
                            ));
                            if (result.len() as u64) == max_txns {
                                break 'main;
                            }
                            skipped_txn_seq_num += 1;
                        }
                    } else {
                        skipped.insert((txn.address, txn_seq));
                    }
                },
                ReplayProtector::Nonce(_) => {
                    inserted.insert((txn.address, txn_replay_protector));
                    result.push((txn.address, txn_replay_protector));
                    if (result.len() as u64) == max_txns {
                        break;
                    }
                },
            };
        }
        let result_size = result.len();
        let result_end_time = start_time.elapsed();
        let result_time = result_end_time.saturating_sub(gas_end_time);

        let mut block = Vec::with_capacity(result_size);
        let mut full_bytes = false;
        for (sender, replay_protector) in result {
            if let Some((txn, ranking_score)) = self
                .transactions
                .get_with_ranking_score(&sender, replay_protector)
            {
                let txn_size = txn.txn_bytes_len() as u64;
                if total_bytes + txn_size > max_bytes {
                    full_bytes = true;
                    break;
                }
                total_bytes += txn_size;
                block.push(txn);
                if total_bytes == max_bytes {
                    full_bytes = true;
                }
                counters::core_mempool_txn_ranking_score(
                    counters::CONSENSUS_PULLED_LABEL,
                    counters::CONSENSUS_PULLED_LABEL,
                    self.transactions
                        .get_bucket(ranking_score, &sender)
                        .as_str(),
                    ranking_score,
                );
            }
        }
```

**File:** mempool/src/shared_mempool/tasks.rs (L762-794)
```rust
pub(crate) async fn process_config_update<V, P>(
    config_update: OnChainConfigPayload<P>,
    validator: Arc<RwLock<V>>,
    broadcast_within_validator_network: Arc<RwLock<bool>>,
) where
    V: TransactionValidation,
    P: OnChainConfigProvider,
{
    info!(LogSchema::event_log(
        LogEntry::ReconfigUpdate,
        LogEvent::Process
    ));

    if let Err(e) = validator.write().restart() {
        counters::VM_RECONFIG_UPDATE_FAIL_COUNT.inc();
        error!(LogSchema::event_log(LogEntry::ReconfigUpdate, LogEvent::VMUpdateFail).error(&e));
    }

    let consensus_config: anyhow::Result<OnChainConsensusConfig> = config_update.get();
    match consensus_config {
        Ok(consensus_config) => {
            *broadcast_within_validator_network.write() =
                !consensus_config.quorum_store_enabled() && !consensus_config.is_dag_enabled()
        },
        Err(e) => {
            error!(
                "Failed to read on-chain consensus config, keeping value broadcast_within_validator_network={}: {}",
                *broadcast_within_validator_network.read(),
                e
            );
        },
    }
}
```

**File:** vm-validator/src/vm_validator.rs (L70-74)
```rust
    fn restart(&mut self) -> Result<()> {
        let db_state_view = self.db_state_view();
        self.state.reset_all(db_state_view.into());
        Ok(())
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L834-844)
```text
    public fun on_new_epoch(framework: &signer) acquires Features, PendingFeatures {
        ensure_framework_signer(framework);
        if (exists<PendingFeatures>(@std)) {
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            if (exists<Features>(@std)) {
                Features[@std].features = features;
            } else {
                move_to(framework, Features { features })
            }
        }
    }
```
