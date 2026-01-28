# Audit Report

## Title
Multisig Payload Validation Bypass via Empty Payload Execution

## Summary
The `abort_if_multisig_payload_mismatch_enabled` feature flag contains a validation logic flaw that allows multisig owners to bypass payload re-confirmation requirements by submitting transactions with empty payloads, while the stored malicious payload still executes successfully.

## Finding Description

The vulnerability exists in the multisig transaction validation logic within the Aptos Framework. The feature flag was designed to ensure "the multisig transaction execution will explicitly abort if the provided payload does not match the payload stored on-chain" [1](#0-0) , serving as a re-confirmation mechanism for multisig transaction execution.

However, the validation implementation contains a critical logic flaw. The check includes three conditions that must ALL be true for validation to occur: [2](#0-1) 

The third condition `!vector::is_empty(&payload)` causes validation to be **skipped** when an empty payload vector is provided, even though the feature flag is enabled and a payload is stored on-chain.

The attack vector works as follows:

1. Users can submit multisig transactions with `transaction_payload: None`, which gets converted to `TransactionExecutable::Empty`: [3](#0-2) 

2. The VM-level code handles empty payloads by setting `provided_payload` to an empty vector when the feature flag is enabled: [4](#0-3)  and [5](#0-4) 

3. This empty `provided_payload` is passed to `get_next_transaction_payload`, which returns the stored payload when one exists on-chain, regardless of the provided payload value: [6](#0-5) 

4. The returned stored payload is then deserialized and executed: [7](#0-6) 

**Attack Scenario:**
- Malicious owner Alice creates a multisig transaction with payload P (e.g., "transfer 1000 APT to Alice's address") stored on-chain
- Owner Bob approves the transaction, giving it sufficient approvals
- Bob later realizes payload P is malicious and expects the feature flag will require explicit re-confirmation during execution
- Alice executes the transaction with `transaction_payload: None` (empty payload)
- The validation is skipped because `!vector::is_empty(&vec![])` evaluates to false
- However, `get_next_transaction_payload` returns the stored malicious payload P
- Payload P executes, transferring 1000 APT to Alice

This bypasses the security guarantee that owners must explicitly provide and re-confirm the payload during execution.

## Impact Explanation

**Severity: Medium**

The feature flag `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH` is enabled by default in production: [8](#0-7) 

This vulnerability allows complete bypass of the security mechanism, resulting in:

- **Limited funds loss**: Multisig owners who approved transactions believing the feature flag would require re-confirmation may suffer unauthorized fund transfers
- **State inconsistencies requiring intervention**: Transactions execute that owners believed were protected by the re-confirmation requirement
- **Violation of security guarantees**: The documented purpose of the feature is circumvented

This aligns with the **Medium Severity** category per Aptos Bug Bounty: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention." The vulnerability requires prior approval of the malicious transaction but completely bypasses the intended re-confirmation safeguard.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is highly exploitable because:

1. **Feature is enabled by default**: The feature flag check confirms it's enabled: [9](#0-8) 

2. **Low privilege requirement**: Any owner of a multisig account can exploit this - no special privileges needed

3. **Simple execution**: Attack requires only submitting a transaction with `transaction_payload: None`

4. **Common usage pattern**: Multisig accounts are widely used in production for treasury management and governance

5. **Users rely on this security control**: The feature flag is specifically designed as a security mechanism, so users trust it to protect them

The likelihood is medium-high rather than high only because it requires an existing multisig transaction with sufficient approvals already in place.

## Recommendation

The validation logic should be corrected to validate whenever a payload is stored on-chain and the feature flag is enabled, regardless of whether the provided payload is empty. The fix should change the condition from:

```move
if (features::abort_if_multisig_payload_mismatch_enabled()
    && option::is_some(&transaction.payload)
    && !vector::is_empty(&payload))
```

To:

```move
if (features::abort_if_multisig_payload_mismatch_enabled()
    && option::is_some(&transaction.payload))
```

This ensures that when a payload is stored and the feature is enabled, either:
- A matching non-empty payload must be provided, OR
- The transaction aborts if an empty payload is provided

This correctly enforces the re-confirmation requirement that the feature flag was designed to provide.

## Proof of Concept

```move
#[test(framework = @aptos_framework, multisig = @0x789, owner1 = @0xabc, owner2 = @0xdef)]
public fun test_empty_payload_bypass(
    framework: &signer,
    multisig: &signer,
    owner1: &signer,
    owner2: &signer,
) {
    // 1. Setup: Enable feature flag and create multisig account
    features::change_feature_flags_for_testing(
        framework,
        vector[features::get_abort_if_multisig_payload_mismatch_feature()],
        vector[]
    );
    
    // Create multisig with 2 owners, threshold of 2
    multisig_account::create_multisig_account(multisig, 2, vector[], vector[]);
    multisig_account::add_owner(owner1, signer::address_of(multisig), signer::address_of(owner1));
    multisig_account::add_owner(owner1, signer::address_of(multisig), signer::address_of(owner2));
    
    // 2. Create malicious transaction with stored payload (transfer to attacker)
    let payload = /* malicious transfer payload */;
    multisig_account::create_transaction_with_stored_payload(
        owner1,
        signer::address_of(multisig),
        payload
    );
    
    // 3. Get approvals from both owners
    multisig_account::approve_transaction(owner1, signer::address_of(multisig), 1);
    multisig_account::approve_transaction(owner2, signer::address_of(multisig), 1);
    
    // 4. Execute with EMPTY payload (transaction_payload: None)
    // This should abort due to feature flag, but actually succeeds
    multisig_account::execute_transaction(
        owner1,
        signer::address_of(multisig),
        vector[] // Empty payload bypasses validation
    );
    
    // Transaction executes successfully with stored malicious payload
    // demonstrating the bypass
}
```

### Citations

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L577-578)
```text
    /// Whether the multisig v2 fix is enabled. Once enabled, the multisig transaction execution will explicitly
    /// abort if the provided payload does not match the payload stored on-chain.
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L399-403)
```text
        if (option::is_some(&transaction.payload)) {
            *option::borrow(&transaction.payload)
        } else {
            provided_payload
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

**File:** types/src/transaction/multisig.rs (L38-44)
```rust
    pub fn as_transaction_executable(&self) -> TransactionExecutable {
        match &self.transaction_payload {
            Some(MultisigTransactionPayload::EntryFunction(entry)) => {
                TransactionExecutable::EntryFunction(entry.clone())
            },
            None => TransactionExecutable::Empty,
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1221-1230)
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1241-1280)
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
        let payload_bytes = payload_bytes
            .first()
            // We expect the payload to either exists on chain or be passed along with the
            // transaction.
            .ok_or_else(|| {
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Multisig payload bytes return error".to_string())
                    .finish(Location::Undefined)
            })?;
        // We have to deserialize twice as the first time returns the actual return type of the
        // function, which is vec<u8>. The second time deserializes it into the correct
        // EntryFunction payload type.
        // If either deserialization fails for some reason, that means the user provided incorrect
        // payload data either during transaction creation or execution.
        let deserialization_error = || {
            PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT)
                .finish(Location::Undefined)
        };
        let payload_bytes =
            bcs::from_bytes::<Vec<u8>>(payload_bytes).map_err(|_| deserialization_error())?;
        let payload = bcs::from_bytes::<MultisigTransactionPayload>(&payload_bytes)
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

**File:** types/src/on_chain_config/aptos_features.rs (L240-240)
```rust
            FeatureFlag::ABORT_IF_MULTISIG_PAYLOAD_MISMATCH,
```

**File:** types/src/on_chain_config/aptos_features.rs (L425-427)
```rust
    pub fn is_abort_if_multisig_payload_mismatch_enabled(&self) -> bool {
        self.is_enabled(FeatureFlag::ABORT_IF_MULTISIG_PAYLOAD_MISMATCH)
    }
```
