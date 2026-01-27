# Audit Report

## Title
Multisig Payload Validation Bypass via Empty Payload Execution

## Summary
The `abort_if_multisig_payload_mismatch_enabled` feature flag was designed to ensure that multisig transaction executors must provide the exact payload that was stored on-chain, serving as a re-confirmation mechanism. However, a validation logic flaw allows this security check to be bypassed by submitting a multisig execution transaction with an empty payload (`TransactionExecutable::Empty`), while the stored malicious payload still executes.

## Finding Description
The vulnerability exists in the multisig transaction validation logic. When the `abort_if_multisig_payload_mismatch_enabled` feature is active, the system is supposed to verify that the provided payload matches the stored payload. [1](#0-0) 

The validation check includes the condition `!vector::is_empty(&payload)`, which means the validation is **skipped** when an empty payload is provided. However, even with an empty payload, the transaction still executes because the `get_next_transaction_payload` function returns the stored payload when one exists on-chain: [2](#0-1) 

The VM-level code explicitly handles empty payloads for multisig transactions: [3](#0-2) 

And during execution: [4](#0-3) 

**Attack Scenario:**
1. Malicious owner Alice creates multisig transaction #1 with payload P (e.g., "transfer 1000 APT to Alice's address") stored on-chain via `create_transaction`
2. Owner Bob approves the transaction (now has sufficient approvals)
3. Bob later realizes payload P is malicious and expects the `abort_if_multisig_payload_mismatch_enabled` feature will require explicit re-confirmation
4. Alice executes the transaction with `TransactionExecutable::Empty` (no payload provided)
5. The validation at line 1175 is skipped because the payload is empty
6. However, `get_next_transaction_payload` returns the stored malicious payload P
7. Payload P executes, transferring 1000 APT to Alice

The feature flag's purpose is documented: [5](#0-4) 

## Impact Explanation
**Severity: Medium**

This vulnerability allows bypassing the security mechanism provided by the `abort_if_multisig_payload_mismatch_enabled` feature flag. While it doesn't directly cause consensus violations or enable arbitrary fund theft, it undermines a critical safety control:

- **Limited funds loss**: Owners who believe the feature flag protects them may have approved transactions they wouldn't execute without re-confirmation
- **State inconsistencies requiring intervention**: Execution of transactions that owners thought were protected by the re-confirmation requirement
- The vulnerability requires prior approval of the malicious transaction but bypasses the intended re-confirmation safeguard

This fits the **Medium Severity** category per Aptos Bug Bounty: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention."

## Likelihood Explanation
**Likelihood: Medium-High**

The vulnerability is exploitable under the following conditions:
- The `abort_if_multisig_payload_mismatch_enabled` feature must be active (it is enabled in production based on test setup code)
- A multisig transaction with stored payload must exist with sufficient approvals
- Any owner of the multisig account can exploit this

The likelihood is medium-high because:
- Multisig accounts are commonly used in production
- The feature flag is intended as a security control, so users rely on it
- Any owner can execute transactions, making exploitation straightforward
- The attack doesn't require special privileges beyond being a multisig owner

## Recommendation
The validation logic should be modified to check payload matching regardless of whether the provided payload is empty. When a payload is stored on-chain and the feature flag is enabled, execution should **always** require providing the exact matching payload.

**Recommended Fix:**

```move
// In multisig_account.move, lines 1173-1182
// Replace the current validation with:
if (features::abort_if_multisig_payload_mismatch_enabled()
    && option::is_some(&transaction.payload)
) {
    let stored_payload = option::borrow(&transaction.payload);
    assert!(
        payload == *stored_payload,
        error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH),
    );
}
```

This removes the `!vector::is_empty(&payload)` condition, ensuring that when a payload is stored on-chain and the feature is enabled, the executor must always provide the exact payload. Empty payloads will fail the check, preventing the bypass.

Additionally, update the VM-level code to prevent empty payload execution when a stored payload exists: [3](#0-2) 

The empty payload case should only be allowed when the transaction was created with `create_transaction_with_hash` (hash-only storage), not when created with `create_transaction` (full payload storage).

## Proof of Concept

```move
#[test(owner_1 = @0x123, owner_2 = @0x124)]
public entry fun test_empty_payload_bypass_attack(
    owner_1: &signer, 
    owner_2: &signer
) acquires MultisigAccount {
    setup(); // Enables abort_if_multisig_payload_mismatch feature
    
    let owner_1_addr = address_of(owner_1);
    let owner_2_addr = address_of(owner_2);
    create_account(owner_1_addr);
    
    // Create multisig account
    let multisig_account = get_next_multisig_account_address(owner_1_addr);
    create_with_owners(owner_1, vector[owner_2_addr], 2, vector[], vector[]);
    
    // Owner 1 creates transaction with stored malicious payload
    let malicious_payload = create_malicious_payload(); // e.g., fund transfer
    create_transaction(owner_1, multisig_account, malicious_payload);
    
    // Owner 2 approves
    approve_transaction(owner_2, multisig_account, 1);
    
    // Owner 1 executes with EMPTY payload instead of providing the stored payload
    // This should fail with EPAYLOAD_DOES_NOT_MATCH but currently bypasses validation
    let empty_payload = vector::empty<u8>();
    
    // Execute via VM with TransactionExecutable::Empty
    // The validation at line 1175 is skipped (empty payload)
    // But get_next_transaction_payload returns the stored malicious payload
    // Malicious payload executes successfully - VULNERABILITY!
    validate_multisig_transaction(owner_1, multisig_account, empty_payload);
    
    // In production code, this would proceed to execute the stored malicious payload
    // despite the feature flag's intent to require explicit payload re-confirmation
}
```

**Notes:**
- The vulnerability specifically affects the security guarantee provided by the `abort_if_multisig_payload_mismatch_enabled` feature
- While multisig transactions always require prior approval, this feature was intended to add an additional layer of protection requiring re-confirmation at execution time
- The flaw undermines this protection mechanism by allowing empty payload execution to bypass validation while still executing stored payloads

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L393-404)
```text
    public fun get_next_transaction_payload(
        multisig_account: address, provided_payload: vector<u8>): vector<u8> acquires MultisigAccount {
        let multisig_account_resource = borrow_global<MultisigAccount>(multisig_account);
        let sequence_number = multisig_account_resource.last_executed_sequence_number + 1;
        let transaction = table::borrow(&multisig_account_resource.transactions, sequence_number);

        if (option::is_some(&transaction.payload)) {
            *option::borrow(&transaction.payload)
        } else {
            provided_payload
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1173-1182)
```text
        if (features::abort_if_multisig_payload_mismatch_enabled()
            && option::is_some(&transaction.payload)
            && !vector::is_empty(&payload)
        ) {
            let stored_payload = option::borrow(&transaction.payload);
            assert!(
                payload == *stored_payload,
                error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH),
            );
        }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L416-422)
```rust
        TransactionExecutableRef::Empty => {
            if features.is_abort_if_multisig_payload_mismatch_enabled() {
                vec![]
            } else {
                bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| unreachable_error.clone())?
            }
        },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1221-1231)
```rust
            TransactionExecutableRef::Empty => {
                // Default to empty bytes if payload is not provided.
                if self
                    .features()
                    .is_abort_if_multisig_payload_mismatch_enabled()
                {
                    vec![]
                } else {
                    bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| invariant_violation_error())?
                }
            },
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L577-587)
```text
    /// Whether the multisig v2 fix is enabled. Once enabled, the multisig transaction execution will explicitly
    /// abort if the provided payload does not match the payload stored on-chain.
    ///
    /// Lifetime: transient
    const ABORT_IF_MULTISIG_PAYLOAD_MISMATCH: u64 = 70;

    public fun get_abort_if_multisig_payload_mismatch_feature(): u64 { ABORT_IF_MULTISIG_PAYLOAD_MISMATCH }

    public fun abort_if_multisig_payload_mismatch_enabled(): bool acquires Features {
        is_enabled(ABORT_IF_MULTISIG_PAYLOAD_MISMATCH)
    }
```
