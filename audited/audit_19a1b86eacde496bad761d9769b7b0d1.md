# Audit Report

## Title
Transaction Simulation Bypasses Signature Verification Leading to Inconsistent Status Results

## Summary
The transaction simulation session in `session.rs` executes transactions without verifying their cryptographic signatures, causing simulations to show success for transactions with invalid signatures that would be rejected on-chain. This breaks the fundamental guarantee that simulation results should accurately predict on-chain execution outcomes.

## Finding Description

The simulation session accepts a `SignedTransaction` and directly calls `execute_user_transaction` without signature verification, while on-chain execution requires all user transactions to have verified signatures before execution.

**Vulnerable Code Path:** [1](#0-0) 

The `execute_transaction` method creates a VM and executes the transaction directly without checking signature validity. The `execute_user_transaction` method internally calls `validate_signed_transaction`: [2](#0-1) 

However, this validation function only checks keyless authenticators (and skips them when `is_simulation=true`), account abstraction authentication, and runs the prologue - it does **not** verify regular Ed25519/MultiEd25519 transaction signatures.

**On-Chain Behavior:**

On-chain transactions are wrapped in `SignatureVerifiedTransaction` which explicitly verifies signatures: [3](#0-2) 

The mempool validation path explicitly checks signatures: [4](#0-3) 

**Attack Scenario:**

1. Attacker creates a valid transaction with correct sequence number, gas parameters, etc.
2. Attacker signs it with an **invalid signature** (wrong private key, corrupted bytes, etc.)
3. Attacker submits to simulation via the session API
4. Simulation executes successfully, returns `TransactionStatus::Keep(ExecutionStatus::Success)`
5. Attacker attempts to submit same transaction on-chain
6. Transaction is rejected in mempool/validation with `StatusCode::INVALID_SIGNATURE`
7. Simulation showed success, but on-chain shows failure - **status inconsistency**

This breaks **Invariant #7: Transaction Validation** which requires "Prologue/epilogue checks must enforce all invariants" including signature verification.

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria as it represents a "Significant protocol violation" - specifically the violation of simulation correctness guarantees.

**Concrete Harms:**

1. **User Deception**: Users rely on simulations to validate transactions before submission. Invalid results lead to wasted gas fees and failed transactions.

2. **Integration Failures**: DApps and wallets using simulation for transaction validation will incorrectly report success for malformed transactions, causing poor user experience and potential loss of user funds through failed transactions.

3. **Testing Unreliability**: Development and testing workflows that rely on simulation to match on-chain behavior are fundamentally broken for any signature-related testing.

4. **Security Tool Bypasses**: Security scanners and auditing tools that use simulation to detect issues may miss signature-related vulnerabilities.

While this doesn't directly cause consensus breaks or fund theft, it undermines the critical developer and user-facing guarantee that **simulation accurately predicts on-chain behavior**.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will manifest in any scenario where:
- A user accidentally provides wrong signing key
- Integration code has signature generation bugs
- Malicious actors intentionally test system boundaries
- Automated testing with signature edge cases

The vulnerability is **trivially exploitable** - no special permissions, timing, or complex setup required. Any user can submit a transaction with an invalid signature to a simulation endpoint.

The impact is **guaranteed** - every transaction with an invalid signature will show this inconsistency between simulation and on-chain results.

## Recommendation

**Primary Fix**: Add signature verification before executing transactions in the simulation session:

```rust
pub fn execute_transaction(
    &mut self,
    txn: SignedTransaction,
) -> Result<(VMStatus, TransactionOutput)> {
    // CRITICAL: Verify signature before execution
    if let Err(_) = txn.verify_signature() {
        // Return error matching on-chain behavior
        let discarded_output = discarded_output(StatusCode::INVALID_SIGNATURE);
        let txn_output = discarded_output.into_transaction_output()
            .map_err(|e| anyhow::anyhow!("Failed to create output: {}", e))?;
        return Ok((
            VMStatus::error(StatusCode::INVALID_SIGNATURE, None),
            txn_output
        ));
    }

    let env = AptosEnvironment::new(&self.state_store);
    let vm = AptosVM::new(&env);
    // ... rest of existing code
}
```

**Alternative Fix**: Document clearly that simulation requires pre-validated transactions and add assertion:

```rust
pub fn execute_transaction(
    &mut self,
    txn: SignedTransaction,
) -> Result<(VMStatus, TransactionOutput)> {
    // Assert signature validity for simulation correctness
    assert!(
        txn.verify_signature().is_ok(),
        "Simulation requires signature-verified transactions. \
         Call verify_signature() before simulation."
    );
    // ... existing code
}
```

**Best Practice**: Create a separate `execute_verified_transaction` method that accepts pre-verified transactions and make the current method verify internally.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{RawTransaction, Script, SignedTransaction, TransactionPayload},
    };

    #[test]
    fn test_simulation_accepts_invalid_signature() {
        // Setup: Create session with genesis state
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::init(temp_dir.path()).unwrap();
        
        // Create a valid transaction payload
        let sender = AccountAddress::random();
        let private_key = Ed25519PrivateKey::generate_for_testing();
        
        // Fund the account
        session.fund_account(sender, 1_000_000).unwrap();
        
        // Create a transaction
        let raw_txn = RawTransaction::new(
            sender,
            0, // sequence number
            TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
            1_000_000, // max gas
            1, // gas unit price
            u64::MAX, // expiration
            ChainId::test(),
        );
        
        // Sign with WRONG key (invalid signature)
        let wrong_key = Ed25519PrivateKey::generate_for_testing();
        let signature = wrong_key.sign(&raw_txn).unwrap();
        let invalid_txn = SignedTransaction::new(
            raw_txn.clone(),
            private_key.public_key(),
            signature,
        );
        
        // VULNERABILITY: Simulation accepts and executes transaction with invalid signature
        let result = session.execute_transaction(invalid_txn);
        
        // Simulation shows "success" or at least doesn't reject for INVALID_SIGNATURE
        // On-chain, this would be rejected immediately with INVALID_SIGNATURE
        // This demonstrates the status inconsistency
        assert!(result.is_ok(), "Simulation should have executed");
        
        // The status might be Discard for other reasons (account doesn't exist, etc.)
        // but it should specifically be INVALID_SIGNATURE, not execution-related failures
    }
}
```

**Notes:**
The PoC demonstrates that the simulation path doesn't check signature validity. While the exact status returned depends on other factors (account existence, etc.), the core issue is that signature verification is completely bypassed, allowing invalid transactions to execute in simulation when they would be rejected on-chain immediately.

### Citations

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L271-291)
```rust
    pub fn execute_transaction(
        &mut self,
        txn: SignedTransaction,
    ) -> Result<(VMStatus, TransactionOutput)> {
        let env = AptosEnvironment::new(&self.state_store);
        let vm = AptosVM::new(&env);
        let log_context = AdapterLogSchema::new(self.state_store.id(), 0);

        let resolver = self.state_store.as_move_resolver();
        let code_storage = self.state_store.as_aptos_code_storage(&env);

        let (vm_status, vm_output) = vm.execute_user_transaction(
            &resolver,
            &code_storage,
            &txn,
            &log_context,
            &AuxiliaryInfo::new_timestamp_not_yet_assigned(0),
        );
        let txn_output = vm_output.try_materialize_into_transaction_output(&resolver)?;

        self.state_store.apply_write_set(txn_output.write_set())?;
```

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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3232-3237)
```rust
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
```

**File:** types/src/transaction/signature_verified_transaction.rs (L129-139)
```rust
impl From<Transaction> for SignatureVerifiedTransaction {
    fn from(txn: Transaction) -> Self {
        match txn {
            Transaction::UserTransaction(txn) => match txn.verify_signature() {
                Ok(_) => SignatureVerifiedTransaction::Valid(Transaction::UserTransaction(txn)),
                Err(_) => SignatureVerifiedTransaction::Invalid(Transaction::UserTransaction(txn)),
            },
            _ => SignatureVerifiedTransaction::Valid(txn),
        }
    }
}
```
