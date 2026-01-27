# Audit Report

## Title
Transaction Filter Bypass via Multisig Transactions with Empty Payloads

## Summary
The `matches_entry_function()` function in the transaction filter returns `false` for multisig transactions with `None` payloads due to `unwrap_or(false)`, causing entry function-based Deny rules to not match. This allows attackers to bypass mempool and consensus filters by submitting multisig transactions with empty payloads while the actual (blocked) entry function payload is stored on-chain.

## Finding Description

The vulnerability exists in the transaction filtering logic for multisig transactions. When a transaction filter is configured to deny specific entry functions, the filter checks the transaction's payload to determine if it should be blocked. However, for multisig transactions, the implementation has a critical flaw: [1](#0-0) 

When a multisig transaction has `transaction_payload: None`, the `unwrap_or(false)` returns `false`, meaning the entry function matcher does not match this transaction. Since the filter rule requires ALL matchers to match for the rule to apply, the Deny rule fails to trigger, and the transaction is allowed through by default. [2](#0-1) 

The filter is applied in both mempool and consensus contexts: [3](#0-2) 

**Attack Flow:**

1. **On-chain Transaction Creation**: Attacker creates a multisig transaction on-chain with the full payload that calls a blocked entry function using the standard multisig account functionality: [4](#0-3) 

2. **Filter Bypass**: Attacker submits a `SignedTransaction` with `TransactionPayload::Multisig` where `transaction_payload = None`. The filter checks this transaction, and because the payload is `None`, returns `false` from the matcher.

3. **Prologue Validation**: During validation, the empty payload bypasses the payload mismatch check because the validation only occurs when the provided payload is non-empty: [5](#0-4) 

The `provided_payload` is set to an empty vector for Empty executables: [6](#0-5) 

Since `!vector::is_empty(&payload)` is `false` when the payload is empty, the validation check is skipped.

4. **Execution with On-chain Payload**: During execution, the VM retrieves the actual payload from on-chain storage: [7](#0-6) 

The stored payload (containing the blocked entry function) is returned and executed, bypassing the filter.

This breaks the **Transaction Validation** invariant: filters are security controls that must be enforced consistently to protect against execution of malicious or vulnerable contracts.

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria as it constitutes a significant protocol violation. Specifically:

- **Security Control Bypass**: Transaction filters are critical security mechanisms used by node operators to prevent execution of known vulnerable or malicious smart contracts. This bypass completely undermines their effectiveness.

- **Operator Intent Violation**: When operators configure filters to block specific entry functions (e.g., to mitigate a zero-day vulnerability in a deployed contract), they expect these filters to be comprehensive. This bypass allows attackers to execute the exact code that operators intended to block.

- **Network-Wide Impact**: Both mempool filters (preventing transaction propagation) and consensus filters (preventing block voting) can be bypassed, affecting the entire network's ability to enforce security policies.

- **Real-World Scenario**: If a critical vulnerability is discovered in a popular protocol (e.g., a DEX or lending protocol), operators may deploy filters as an emergency measure while a fix is being developed. This bypass would allow continued exploitation during that window.

The impact does not reach Critical severity as it does not directly cause loss of funds, consensus violations, or network partition. However, it enables attackers to bypass intended security controls, which could facilitate other attacks.

## Likelihood Explanation

**High Likelihood:**

- **Low Complexity**: The attack requires only standard multisig account functionality - no special privileges or complex setup.

- **No Special Requirements**: Any user who is an owner of a multisig account can execute this attack. Multisig accounts are a standard feature widely used in the Aptos ecosystem.

- **Deterministic**: The vulnerability is in the code logic, not a race condition or timing-dependent issue. It will work reliably every time.

- **Clear Motivation**: When filters are deployed (usually in response to security incidents), attackers have strong incentive to find bypasses.

- **Easy Discovery**: The vulnerability is evident from reading the filter matching logic - the `unwrap_or(false)` pattern is a clear indicator.

## Recommendation

The fix requires changing the filter matching logic to properly handle multisig transactions with empty payloads. There are two approaches:

**Option 1: Fetch and validate stored payload (Recommended)**

Modify `matches_entry_function()` to fetch the stored payload from on-chain when encountering a multisig transaction with `None` payload, then match against that stored payload. This ensures filters see the actual payload that will be executed.

**Option 2: Conservative approach - Deny by default**

Change the `unwrap_or(false)` to `unwrap_or(true)` or remove the default entirely, forcing explicit handling. When the payload is unknown at filter time, fail-safe by matching the rule (if it's a Deny rule, deny the transaction; if it's an Allow rule, allow it). This is more conservative but may have compatibility implications.

**Option 3: Feature flag fix**

Fix the validation logic in `validate_multisig_transaction` to enforce payload matching even when the provided payload is empty:

```move
// Instead of:
if (features::abort_if_multisig_payload_mismatch_enabled()
    && option::is_some(&transaction.payload)
    && !vector::is_empty(&payload)) {
    
// Change to:
if (features::abort_if_multisig_payload_mismatch_enabled()
    && option::is_some(&transaction.payload)) {
    // Require provided payload to match stored payload
    // Empty provided payload should not be allowed when stored payload exists
    assert!(
        !vector::is_empty(&payload),
        error::invalid_argument(EPAYLOAD_MUST_BE_PROVIDED),
    );
```

This approach prevents the bypass at validation time rather than filter time, ensuring that multisig transactions must provide their payload even if it's stored on-chain when filters are active.

## Proof of Concept

```move
#[test_only]
module test_filter_bypass::poc {
    use aptos_framework::multisig_account;
    use aptos_framework::account;
    use std::signer;
    use std::vector;
    
    #[test(owner = @0x123, multisig_addr = @0xabc)]
    public fun test_multisig_filter_bypass(owner: &signer, multisig_addr: &signer) {
        // Setup: Create multisig account
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(owner_addr);
        
        multisig_account::create_with_owners(
            owner,
            vector[owner_addr],
            1,  // 1-of-1 multisig
            vector[],
            vector[]
        );
        
        let multisig_address = signer::address_of(multisig_addr);
        
        // Step 1: Create transaction on-chain with blocked entry function
        // For example: 0x1::vulnerable_contract::exploit_function
        let payload = /* BCS-encoded EntryFunction calling blocked function */;
        
        multisig_account::create_transaction(
            owner,
            multisig_address,
            payload
        );
        
        // Step 2: Approve transaction
        multisig_account::approve_transaction(owner, multisig_address, 1);
        
        // Step 3: Submit SignedTransaction with Empty payload
        // This would be done off-chain by constructing:
        // SignedTransaction {
        //     payload: TransactionPayload::Multisig(Multisig {
        //         multisig_address,
        //         transaction_payload: None  // <-- Empty payload bypasses filter
        //     }),
        //     ...
        // }
        
        // Step 4: Filter check would return false (doesn't match blocked entry function)
        // Step 5: During execution, stored payload is retrieved and executed
        
        // Result: Blocked entry function executes despite filter
    }
}
```

The above demonstrates the attack flow. In practice, this would involve:
1. Using the Move framework to create the multisig transaction on-chain
2. Constructing a Rust `SignedTransaction` with `transaction_payload: None`
3. Submitting it to a node with active transaction filters
4. Observing that the filter does not block the transaction
5. The transaction executes with the stored payload, calling the blocked entry function

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L30-46)
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
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L342-350)
```rust
        TransactionPayload::Multisig(multisig) => multisig
            .transaction_payload
            .as_ref()
            .map(|payload| match payload {
                MultisigTransactionPayload::EntryFunction(entry_function) => {
                    compare_entry_function(entry_function, address, module_name, function)
                },
            })
            .unwrap_or(false),
```

**File:** mempool/src/shared_mempool/tasks.rs (L435-439)
```rust
            if transaction_filter_config
                .transaction_filter()
                .allows_transaction(&transaction)
            {
                Some((transaction, account_sequence_number, priority))
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L147-158)
```text
    /// A transaction to be executed in a multisig account.
    /// This must contain either the full transaction payload or its hash (stored as bytes).
    struct MultisigTransaction has copy, drop, store {
        payload: Option<vector<u8>>,
        payload_hash: Option<vector<u8>>,
        // Mapping from owner adress to vote (yes for approve, no for reject). Uses a simple map to deduplicate.
        votes: SimpleMap<address, bool>,
        // The owner who created this transaction.
        creator: address,
        // The timestamp in seconds when the transaction was created.
        creation_time_secs: u64,
    }
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
