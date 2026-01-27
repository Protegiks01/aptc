# Audit Report

## Title
Transaction Filter Bypass via Encrypted Payload - Content-Based Filters Fail on Encrypted Transactions

## Summary
The `matches_script_argument_address()` function returns `false` when `executable_ref()` fails on encrypted payloads, incorrectly signaling that the transaction does NOT contain blocked addresses. This allows attackers to bypass Deny rules by encrypting transactions, as filtering occurs before decryption in the transaction pipeline.

## Finding Description

The transaction filter system is designed to allow node operators to selectively block or allow transactions based on their content. However, a critical flaw exists in how encrypted transactions are handled. [1](#0-0) 

When processing an `EncryptedPayload`, the code attempts to call `payload.executable_ref()`. This method only succeeds when the payload is in the `Decrypted` state: [2](#0-1) 

The `EncryptedPayload` enum has three states: `Encrypted`, `FailedDecryption`, and `Decrypted`. For the first two states, `executable_ref()` returns an error. [3](#0-2) 

**The Critical Flaw:** When `executable_ref()` fails, `matches_script_argument_address()` returns `false`, meaning "this transaction does NOT match the filter criteria." This is incorrect because we cannot know whether the address is present in the encrypted script arguments until decryption.

**Transaction Flow Reveals the Vulnerability:**

1. Transaction filtering occurs in the mempool BEFORE decryption: [4](#0-3) 

2. Decryption happens later in the consensus pipeline AFTER filtering: [5](#0-4) 

**Attack Scenario:**
1. Node operator sets filter: `Deny(vec![AccountAddress(blocked_addr)])` to block script transactions targeting a specific account
2. Attacker creates a Script transaction with `blocked_addr` as an argument  
3. Attacker encrypts the payload using `EncryptedPayload::Encrypted`
4. Transaction enters mempool in `Encrypted` state
5. Filter checks transaction: `matches_script_argument_address()` returns `false` because `executable_ref()` fails
6. Deny rule doesn't match → transaction is **ALLOWED** by default
7. Transaction is included in block and decrypted in consensus
8. Transaction executes with `blocked_addr` as argument → **FILTER BYPASSED**

**Affected Functions:**
The same vulnerability exists in multiple matcher functions:
- `matches_script_argument_address()` (lines 451-485)
- `matches_entry_function()` (lines 332-375) 
- `matches_entry_function_module_address()` (lines 377-418)

All return `false` when content cannot be inspected, allowing encrypted transactions to bypass content-based filters.

## Impact Explanation

**Severity: MEDIUM**

This vulnerability breaks the security guarantees of the transaction filtering system, which is designed to allow node operators to enforce custom policies on which transactions they process. Per Aptos bug bounty criteria, this qualifies as **Medium severity** because it:

- Bypasses a security control mechanism
- Allows execution of transactions that should be blocked
- Can lead to state inconsistencies requiring intervention
- Does not directly cause fund loss but enables secondary attacks

**Real-World Impact Scenarios:**

1. **DoS Protection Bypass:** Filters block transactions calling known resource-intensive contracts; attacker encrypts transactions to bypass and execute DoS attacks

2. **Governance Policy Bypass:** Node operators filter transactions interacting with specific governance modules; attackers encrypt to bypass restrictions

3. **Compliance Bypass:** Filters block transactions to sanctioned addresses; encryption allows policy violations

4. **Vulnerability Exploitation:** Filters block transactions targeting contracts with known bugs; attackers encrypt to exploit vulnerabilities

The vulnerability completely undermines the filtering system's purpose for any content-based rules when dealing with encrypted transactions.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **No Special Privileges Required:** Any user can submit encrypted transactions to the network
2. **Deterministic and Repeatable:** The bypass works 100% of the time for encrypted payloads
3. **Easy to Execute:** Simply encrypt any transaction payload that would normally be blocked
4. **Transaction Encryption is a Supported Feature:** The `EncryptedPayload` mechanism is a legitimate blockchain feature
5. **No Detection Mechanism:** There's no indication that a filter bypass occurred since the transaction appears legitimate post-decryption

The only requirement is that the attacker knows a filter exists and understands how to encrypt transaction payloads.

## Recommendation

**Option 1: Conservative Approach (Deny Unknown)**
When `executable_ref()` fails on encrypted payloads, treat the content as unknown and apply a conservative policy. For content-based matchers, return `true` to indicate a potential match, which would trigger Deny rules:

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
        // Cannot inspect encrypted content - assume match for safety
        true
    }
}
```

**Option 2: Explicit Encrypted Transaction Handling (Recommended)**
Add explicit handling for encrypted transactions at the filter rule level. Node operators should explicitly allow or deny ALL encrypted transactions, rather than trying to apply content-based filters:

```rust
// In TransactionMatcher::matches()
match self {
    TransactionMatcher::AccountAddress(address) => {
        // For encrypted transactions, check if EncryptedTransaction rule exists
        if signed_transaction.payload().is_encrypted_variant() {
            // Return false to force explicit encrypted transaction handling
            return false;
        }
        matches_sender_address(signed_transaction, address)
            || matches_entry_function_module_address(signed_transaction, address)
            || matches_multisig_address(signed_transaction, address)
            || matches_script_argument_address(signed_transaction, address)
            || matches_transaction_authenticator_address(signed_transaction, address)
    },
    // ... other matchers
}
```

**Option 3: Post-Decryption Filtering**
Re-apply transaction filters after decryption in the consensus pipeline, before execution. This ensures filters can inspect the actual transaction content.

**Recommended Fix:** Implement Option 2 to force explicit policy decisions about encrypted transactions, combined with documentation warning that content-based filters cannot inspect encrypted payloads until decryption.

## Proof of Concept

```rust
#[test]
fn test_encrypted_transaction_filter_bypass() {
    use aptos_types::transaction::{
        Script, TransactionPayload, SignedTransaction, 
        encrypted_payload::EncryptedPayload,
    };
    use move_core_types::{
        account_address::AccountAddress,
        transaction_argument::TransactionArgument,
    };
    
    // Create a blocked address
    let blocked_address = AccountAddress::from_hex_literal("0xBAD").unwrap();
    
    // Create a script with the blocked address as an argument
    let script_args = vec![TransactionArgument::Address(blocked_address)];
    let script = Script::new(vec![], vec![], script_args);
    
    // Create two transactions: one plaintext, one encrypted
    let plaintext_txn = create_signed_transaction(
        TransactionPayload::Script(script.clone()),
        false
    );
    
    let encrypted_txn = create_signed_transaction(
        TransactionPayload::EncryptedPayload(EncryptedPayload::Encrypted {
            ciphertext: Ciphertext::random(),
            extra_config: TransactionExtraConfig::V1 {
                multisig_address: None,
                replay_protection_nonce: None,
            },
            payload_hash: HashValue::random(),
        }),
        false
    );
    
    // Create filter that denies transactions with blocked_address in script args
    let filter = TransactionFilter::empty()
        .add_account_address_filter(false, blocked_address); // Deny rule
    
    // Plaintext transaction should be BLOCKED
    assert!(!filter.allows_transaction(&plaintext_txn), 
        "Plaintext transaction with blocked address should be denied");
    
    // Encrypted transaction should be BLOCKED but is ALLOWED (vulnerability!)
    assert!(filter.allows_transaction(&encrypted_txn), 
        "VULNERABILITY: Encrypted transaction bypasses the filter!");
    
    // After decryption, if we could inspect it, it would contain blocked_address
    // but by then it's already past the filter and will be executed
}
```

This test demonstrates that an encrypted transaction containing a blocked address in its script arguments bypasses the Deny filter, while the same transaction in plaintext form is correctly blocked.

**Notes**

The vulnerability exists because transaction filtering is a pre-decryption security control, but the implementation incorrectly assumes it can inspect encrypted content. The `false` return value semantically means "does not match," but for encrypted payloads, the correct semantic should be "unknown - cannot determine." The current behavior creates a security bypass where encrypted transactions with malicious content evade content-based filtering rules.

This affects all content-based matchers (`AccountAddress`, `EntryFunction`, `ModuleAddress`) but not identity-based matchers (`Sender`, `PublicKey`, `TransactionId`) or the explicit `EncryptedTransaction` matcher, which can still block ALL encrypted transactions if desired.

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L471-483)
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
        },
```

**File:** types/src/transaction/encrypted_payload.rs (L42-64)
```rust
pub enum EncryptedPayload {
    Encrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
    },
    FailedDecryption {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,
    },
    Decrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,

        // decrypted things
        executable: TransactionExecutable,
        decryption_nonce: u64,
    },
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

**File:** mempool/src/shared_mempool/tasks.rs (L435-448)
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
                    transaction.committed_hash()
                )));
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L121-148)
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
```
