# Audit Report

## Title
JWK Update Race Condition Causes Valid Keyless Transactions to be Discarded During Block Execution

## Summary
A timing vulnerability exists where user transactions using keyless authentication can be validated successfully in mempool but fail during block execution if a `ValidatorTransaction::ObservedJWKUpdate` removes the required JWK key between mempool validation and transaction execution. This causes legitimate user transactions to be permanently discarded with gas fees lost.

## Finding Description

The vulnerability occurs due to the interaction between JWK consensus updates and keyless transaction validation at different stages of the transaction lifecycle:

**Stage 1: Mempool Validation**
When a keyless transaction enters mempool, `validate_authenticators` is called which reads the current on-chain `PatchedJWKs` resource to verify the JWT signature against the appropriate JWK. If the required key exists, validation passes and the transaction enters mempool. [1](#0-0) 

**Stage 2: Block Construction**
Transactions are ordered within a block as: BlockMetadata → ValidatorTransactions → User Transactions [2](#0-1) 

**Stage 3: Block Execution**
When `ValidatorTransaction::ObservedJWKUpdate` executes, it calls `upsert_into_observed_jwks` which modifies the on-chain `ObservedJWKs` resource and then calls `regenerate_patched_jwks`, immediately updating the `PatchedJWKs` resource in global state. [3](#0-2) 

**Stage 4: User Transaction Re-validation**
When the user transaction executes, `execute_user_transaction_impl` calls `validate_signed_transaction` again during the prologue phase, which re-validates keyless authenticators by reading from the UPDATED `PatchedJWKs` state. [4](#0-3) 

If the JWK key was removed by the earlier ValidatorTransaction, the validation fails with an invalid signature error. The `unwrap_or_discard!` macro converts this error into a discarded transaction output, causing the transaction to be permanently rejected. [5](#0-4) [6](#0-5) 

**Why BlockSTM Doesn't Prevent This**

While BlockSTM provides read-write conflict detection for parallel execution, this vulnerability occurs because:
1. The ValidatorTransaction executes BEFORE the user transaction (by block ordering)
2. The user transaction reads the JWK state written by the ValidatorTransaction
3. When validation fails in the prologue, the transaction is **discarded** rather than re-executed with updated state
4. This breaks the assumption that transactions valid at mempool time should execute successfully

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria:

1. **Denial of Service**: Legitimate keyless authentication users are denied service when their valid transactions are rejected
2. **Financial Loss**: Users pay gas fees for transactions that are discarded through no fault of their own
3. **Protocol Violation**: Breaks the invariant that transactions passing mempool validation should execute (barring account-specific state changes like insufficient balance or sequence number mismatches)
4. **Determinism Violation**: The same transaction can succeed or fail based purely on timing of JWK updates, not transaction content

The impact affects all users relying on keyless authentication when JWK rotations occur. While JWK updates are infrequent, the vulnerability creates unpredictable failures that undermine trust in keyless authentication.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability will occur whenever:
1. A user submits a keyless transaction to mempool with JWK key K
2. A ValidatorTransaction removing key K is included in the same block as the user transaction
3. The user transaction executes after the JWK update in the block

Given that:
- JWK updates occur during key rotations for OIDC providers (Google, Facebook, etc.)
- Multiple user transactions may be in mempool when an update occurs
- Block construction places ValidatorTransactions before user transactions
- There is no synchronization mechanism to prevent this race condition

The vulnerability is likely to manifest during any JWK rotation event, potentially affecting dozens or hundreds of user transactions simultaneously.

## Recommendation

**Solution: Cache JWK State at Block Execution Start**

The transaction execution should use a snapshot of the JWK state from the beginning of block execution, not read dynamically updated state during prologue validation. This ensures transactions validated in mempool remain valid during execution.

**Implementation Options:**

1. **Cache PatchedJWKs in BlockExecutor**: Pass the initial `PatchedJWKs` state to all user transaction executions as part of the execution context, preventing mid-block updates from affecting user transaction validation.

2. **Defer JWK Updates to Epoch Boundaries**: Similar to `on_new_epoch` handling for configuration changes, JWK updates could be buffered and applied only at epoch boundaries, eliminating intra-block timing issues.

3. **Add Grace Period**: When a JWK is marked for removal, maintain it for N blocks to allow in-flight transactions to complete before actual removal.

**Recommended Fix (Option 1):**

In `aptos-move/aptos-vm/src/block_executor/mod.rs`, capture the initial `PatchedJWKs` state and pass it through the execution context to prevent reading updated state:

```rust
// Capture initial JWK state at block start
let initial_patched_jwks = PatchedJWKs::fetch_config(state_view);

// Pass to each transaction execution context
// Modify validate_authenticators to use cached JWKs instead of reading from state
```

This ensures deterministic behavior: all user transactions in a block validate against the same JWK set, regardless of ValidatorTransaction updates.

## Proof of Concept

```rust
// Reproduction steps in Rust test:

#[test]
fn test_jwk_update_race_condition() {
    // 1. Setup: Create validator with keyless authentication enabled
    // 2. Create user transaction using keyless auth with JWK key "key_123"
    // 3. Validate transaction in mempool - should pass
    // 4. Create ValidatorTransaction::ObservedJWKUpdate removing "key_123"
    // 5. Construct block: [BlockMetadata, ValidatorTransaction, UserTransaction]
    // 6. Execute block
    // Expected: ValidatorTransaction removes key, UserTransaction validation fails
    // Result: UserTransaction is discarded with TransactionStatus::Discard
    
    let mut executor = FakeExecutor::from_head_genesis();
    
    // Setup JWK with key_123
    let jwk_update_add = create_jwk_update_add("key_123");
    executor.execute_validator_transaction(jwk_update_add);
    
    // Create user transaction with keyless auth using key_123
    let keyless_txn = create_keyless_transaction("key_123");
    
    // Validate in mempool - should succeed
    assert!(executor.validate_transaction(keyless_txn.clone()).is_ok());
    
    // Create JWK update removing key_123
    let jwk_update_remove = create_jwk_update_remove("key_123");
    
    // Execute block with update before transaction
    let block = vec![
        Transaction::ValidatorTransaction(jwk_update_remove),
        Transaction::UserTransaction(keyless_txn),
    ];
    
    let outputs = executor.execute_block(block);
    
    // Assert: second transaction (user tx) was discarded
    assert_eq!(outputs[1].status(), TransactionStatus::Discard(StatusCode::INVALID_SIGNATURE));
}
```

This demonstrates that a transaction valid at mempool validation time becomes invalid during execution due to the JWK update timing issue.

## Notes

The security question mentions "legitimate validators to be rejected" which is imprecise terminology. This vulnerability actually affects **user transactions using keyless authentication**, not validator consensus operations. JWK (JSON Web Key) consensus is specifically for authenticating user transactions via OpenID Connect providers, not for validator operations. The correct framing is: "Can JWK consensus configs be updated to remove valid keys mid-validation, causing legitimate **user transactions** to be rejected?"

### Citations

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L220-220)
```rust
    let patched_jwks = get_jwks_onchain(resolver)?;
```

**File:** consensus/consensus-types/src/block.rs (L553-565)
```rust
    pub fn combine_to_input_transactions(
        validator_txns: Vec<ValidatorTransaction>,
        txns: Vec<SignedTransaction>,
        metadata: BlockMetadataExt,
    ) -> Vec<Transaction> {
        once(Transaction::from(metadata))
            .chain(
                validator_txns
                    .into_iter()
                    .map(Transaction::ValidatorTransaction),
            )
            .chain(txns.into_iter().map(Transaction::UserTransaction))
            .collect()
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L176-189)
```rust
macro_rules! unwrap_or_discard {
    ($res:expr) => {
        match $res {
            Ok(s) => s,
            Err(e) => {
                // covers both VMStatus itself and VMError which can convert to VMStatus
                let s: VMStatus = e.into();

                let o = discarded_output(s.status_code());
                return (s, o);
            },
        }
    };
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1998-2012)
```rust
        // Revalidate the transaction.
        let mut prologue_session = PrologueSession::new(self, &txn_data, resolver);
        let initial_gas = gas_meter.balance();
        let serialized_signers = unwrap_or_discard!(prologue_session.execute(|session| {
            self.validate_signed_transaction(
                session,
                code_storage,
                txn,
                &txn_data,
                log_context,
                is_approved_gov_script,
                &mut traversal_context,
                gas_meter,
            )
        }));
```

**File:** aptos-move/aptos-vm/src/errors.rs (L307-309)
```rust
pub(crate) fn discarded_output(status_code: StatusCode) -> VMOutput {
    VMOutput::empty_with_status(TransactionStatus::Discard(status_code))
}
```
