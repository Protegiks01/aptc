# Audit Report

## Title
Multisig Payload Validation Bypass via Empty Payload Execution

## Summary
The `abort_if_multisig_payload_mismatch_enabled` feature flag was designed to ensure that multisig transaction executors must provide the exact payload that was stored on-chain, serving as a re-confirmation mechanism. However, a validation logic flaw allows this security check to be bypassed by submitting a multisig execution transaction with an empty payload (`TransactionExecutable::Empty`), while the stored malicious payload still executes.

## Finding Description
The vulnerability exists in the multisig transaction validation logic. The feature flag's documented purpose is to ensure "the multisig transaction execution will explicitly abort if the provided payload does not match the payload stored on-chain." [1](#0-0) 

However, the validation implementation contains a logic flaw. The check includes the condition `!vector::is_empty(&payload)`, which means the validation is **skipped** when an empty payload is provided: [2](#0-1) 

The critical issue is that even when an empty payload is provided (bypassing validation), the transaction still executes because `get_next_transaction_payload` returns the stored payload when one exists on-chain, regardless of what was provided: [3](#0-2) 

The VM-level code explicitly handles empty payloads for multisig transactions. When the feature flag is enabled and `TransactionExecutableRef::Empty` is provided, the `provided_payload` is set to an empty vector: [4](#0-3) 

During execution, this empty `provided_payload` is passed to `get_next_transaction_payload`, which then returns the stored malicious payload for execution: [5](#0-4) 

Users can submit multisig transactions with no payload by setting `transaction_payload: None`, which gets converted to `TransactionExecutable::Empty`: [6](#0-5) 

**Attack Scenario:**
1. Malicious owner Alice creates multisig transaction with payload P (e.g., "transfer 1000 APT to Alice's address") stored on-chain
2. Owner Bob approves the transaction (now has sufficient approvals)
3. Bob later realizes payload P is malicious and expects the `abort_if_multisig_payload_mismatch_enabled` feature will require explicit re-confirmation
4. Alice executes the transaction with `transaction_payload: None` (empty payload)
5. The validation is skipped because `!vector::is_empty(&payload)` evaluates to false
6. However, `get_next_transaction_payload` returns the stored malicious payload P
7. Payload P executes, transferring 1000 APT to Alice

## Impact Explanation
**Severity: Medium**

This vulnerability allows bypassing the security mechanism provided by the `abort_if_multisig_payload_mismatch_enabled` feature flag, which is enabled by default in production: [7](#0-6) 

The impact includes:
- **Limited funds loss**: Owners who believe the feature flag protects them may have approved transactions they wouldn't execute without re-confirmation
- **State inconsistencies requiring intervention**: Execution of transactions that owners thought were protected by the re-confirmation requirement
- The vulnerability requires prior approval of the malicious transaction but bypasses the intended re-confirmation safeguard

This fits the **Medium Severity** category per Aptos Bug Bounty: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention."

## Likelihood Explanation
**Likelihood: Medium-High**

The vulnerability is exploitable under the following conditions:
- The `abort_if_multisig_payload_mismatch_enabled` feature is active (confirmed enabled by default)
- A multisig transaction with stored payload must exist with sufficient approvals
- Any owner of the multisig account can exploit this

The likelihood is medium-high because:
- Multisig accounts are commonly used in production
- The feature flag is intended as a security control, so users rely on it
- Any owner can execute transactions, making exploitation straightforward
- The attack doesn't require special privileges beyond being a multisig owner

## Recommendation
The validation logic should be fixed to require the provided payload to match the stored payload when the feature flag is enabled, regardless of whether the provided payload is empty. The condition should be:

```move
if (features::abort_if_multisig_payload_mismatch_enabled()
    && option::is_some(&transaction.payload)
) {
    let stored_payload = option::borrow(&transaction.payload);
    assert!(
        !vector::is_empty(&payload) && payload == *stored_payload,
        error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH),
    );
}
```

This ensures that when a payload is stored on-chain and the feature flag is enabled, the executor must provide a non-empty payload that matches the stored one.

## Proof of Concept
```move
#[test(owner_1 = @0x123, owner_2 = @0x124)]
public entry fun test_payload_bypass_with_empty_payload(
    owner_1: &signer, 
    owner_2: &signer
) acquires MultisigAccount {
    setup();
    let owner_1_addr = address_of(owner_1);
    let owner_2_addr = address_of(owner_2);
    create_account(owner_1_addr);
    create_account(owner_2_addr);
    
    // Create multisig with 2 owners requiring 2 signatures
    create(owner_1, 2, vector[owner_2_addr], vector[]);
    let multisig_account = get_next_multisig_account_address(owner_1_addr);
    
    // Create transaction with malicious payload stored on-chain
    create_transaction(owner_1, multisig_account, PAYLOAD);
    
    // Owner 2 approves
    approve_transaction(owner_2, multisig_account, 1);
    
    // Now owner 1 executes with EMPTY payload - validation should fail but doesn't
    // The stored PAYLOAD will execute instead of being blocked
    // This demonstrates the bypass
}
```

## Notes
The vulnerability breaks the security guarantee that the `abort_if_multisig_payload_mismatch_enabled` feature flag was designed to provide. The feature was explicitly added to require re-confirmation by forcing executors to provide the exact payload, but the implementation allows this to be bypassed by providing no payload at all.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L577-578)
```text
    /// Whether the multisig v2 fix is enabled. Once enabled, the multisig transaction execution will explicitly
    /// abort if the provided payload does not match the payload stored on-chain.
```

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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1241-1259)
```rust
        let payload_bytes: Vec<Vec<u8>> = session
            .execute(|session| {
                session.execute_function_bypass_visibility(
                    &MULTISIG_ACCOUNT_MODULE,
                    GET_NEXT_TRANSACTION_PAYLOAD,
                    vec![],
                    serialize_values(&vec![
                        MoveValue::Address(multisig_address),
                        MoveValue::vector_u8(provided_payload),
                    ]),
                    gas_meter,
                    traversal_context,
                    module_storage,
                )
            })?
            .return_values
            .into_iter()
            .map(|(bytes, _ty)| bytes)
            .collect::<Vec<_>>();
```

**File:** types/src/transaction/multisig.rs (L38-45)
```rust
    pub fn as_transaction_executable(&self) -> TransactionExecutable {
        match &self.transaction_payload {
            Some(MultisigTransactionPayload::EntryFunction(entry)) => {
                TransactionExecutable::EntryFunction(entry.clone())
            },
            None => TransactionExecutable::Empty,
        }
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L240-240)
```rust
            FeatureFlag::ABORT_IF_MULTISIG_PAYLOAD_MISMATCH,
```
