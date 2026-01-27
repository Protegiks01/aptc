# Audit Report

## Title
Multi-Sender Transaction Filter Bypass via Sender Matcher

## Summary
The `TransactionMatcher::Sender` only validates the primary sender address in multi-sender transactions (MultiAgent and FeePayer), allowing blocked addresses to participate as secondary signers or fee payers, completely bypassing sender-based transaction filters across mempool, consensus, execution, and API layers.

## Finding Description

The transaction filtering system uses matchers to allow or deny transactions. The `Sender` matcher is designed to filter transactions based on account addresses, but contains a critical flaw in its implementation. [1](#0-0) 

The `Sender` matcher delegates to `matches_sender_address`, which only checks the primary sender: [2](#0-1) 

The `sender()` method returns only the RawTransaction's sender field: [3](#0-2) 

However, Aptos supports multi-sender transactions where additional addresses participate:

**MultiAgent transactions** include secondary signer addresses: [4](#0-3) 

**FeePayer transactions** include secondary signers AND a fee payer address: [5](#0-4) 

In contrast, the `AccountAddress` matcher correctly checks ALL addresses including secondary signers and fee payers: [6](#0-5) [7](#0-6) 

**Attack Scenario:**
1. Operator configures mempool filter to block malicious address `0xBAD` using: `Deny(Sender(0xBAD))`
2. Attacker creates a FeePayer transaction with:
   - Primary sender: `0xGOOD` (clean address)
   - Fee payer: `0xBAD` (blocked address)
3. Filter only checks `0xGOOD` and allows the transaction
4. Address `0xBAD` successfully participates by paying transaction fees

The filters are applied at critical points: [8](#0-7) [9](#0-8) 

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria as it represents a **significant protocol violation** - specifically, a complete bypass of transaction filtering mechanisms.

Transaction filters are security-critical controls used for:
- Blocking compromised or malicious addresses during security incidents
- Enforcing compliance and regulatory requirements at the node level
- Implementing emergency access controls
- Protecting against known attack patterns

The bypass allows attackers to:
- Circumvent mempool admission controls (transaction submission)
- Evade consensus proposal filters (block construction)
- Bypass execution filters (transaction processing)
- Defeat API-level filters (simulation and query endpoints)

While this doesn't directly cause fund loss or consensus safety violations, it completely undermines a documented security feature that operators rely on for protecting their nodes and the network. An attacker can trivially bypass any sender-based filter by using MultiAgent or FeePayer transactions.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is:
- **Trivial to exploit**: Requires only creating a MultiAgent or FeePayer transaction (standard Aptos transaction types)
- **No special privileges required**: Any user can submit these transaction types
- **No complexity**: Single transaction submission bypasses the filter
- **Immediately effective**: Works on any node using Sender-based filters
- **Undetectable**: The bypass leaves no trace distinguishable from legitimate multi-sender transactions

The only limitation is that operators must have configured Sender-based filters. However, this is a documented and expected use case for the filtering system, as evidenced by test coverage: [10](#0-9) 

## Recommendation

Replace the `Sender` matcher logic to check ALL participating addresses in multi-sender transactions, similar to the `AccountAddress` matcher implementation.

**Option 1: Modify `matches_sender_address` to check all signers**
```rust
fn matches_sender_address(signed_transaction: &SignedTransaction, sender: &AccountAddress) -> bool {
    // Check primary sender
    if signed_transaction.sender() == *sender {
        return true;
    }
    
    // For multi-sender transactions, also check secondary signers and fee payer
    match signed_transaction.authenticator_ref() {
        TransactionAuthenticator::MultiAgent {
            secondary_signer_addresses,
            ..
        } => secondary_signer_addresses.contains(sender),
        TransactionAuthenticator::FeePayer {
            secondary_signer_addresses,
            fee_payer_address,
            ..
        } => secondary_signer_addresses.contains(sender) || fee_payer_address == sender,
        _ => false,
    }
}
```

**Option 2: Deprecate `Sender` matcher and document `AccountAddress` for filtering signers**

Since `AccountAddress` already provides comprehensive checking, consider deprecating `Sender` and updating documentation to guide users toward `AccountAddress` for filtering based on participating addresses.

## Proof of Concept

```rust
#[test]
fn test_sender_filter_bypass_with_fee_payer() {
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, SigningKey, Uniform};
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{
            authenticator::AccountAuthenticator,
            EntryFunction, RawTransaction, Script, SignedTransaction, TransactionPayload,
        },
    };
    use move_core_types::identifier::Identifier;
    use rand::thread_rng;

    // Create a filter that DENIES transactions from blocked_address
    let blocked_address = AccountAddress::random();
    let clean_address = AccountAddress::random();
    
    let filter = TransactionFilter::empty()
        .add_sender_filter(false, blocked_address); // Deny blocked_address

    // Create a FeePayer transaction where:
    // - Primary sender is clean_address (NOT blocked)
    // - Fee payer is blocked_address (SHOULD be blocked but isn't)
    let raw_txn = RawTransaction::new(
        clean_address, // Primary sender is clean
        0,
        TransactionPayload::EntryFunction(EntryFunction::new(
            move_core_types::language_storage::ModuleId::new(
                AccountAddress::ONE,
                Identifier::new("test").unwrap(),
            ),
            Identifier::new("function").unwrap(),
            vec![],
            vec![],
        )),
        100000,
        1,
        10000,
        ChainId::new(1),
    );

    let private_key = Ed25519PrivateKey::generate(&mut thread_rng());
    let public_key = private_key.public_key();
    
    let bypass_txn = SignedTransaction::new_fee_payer(
        raw_txn,
        AccountAuthenticator::Ed25519 {
            public_key: public_key.clone(),
            signature: private_key.sign(&RawTransaction::new(
                clean_address, 0,
                TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
                0, 0, 0, ChainId::new(1),
            )).unwrap(),
        },
        vec![],
        vec![],
        blocked_address, // Fee payer is the BLOCKED address
        AccountAuthenticator::Ed25519 {
            public_key: public_key.clone(),
            signature: private_key.sign(&RawTransaction::new(
                clean_address, 0,
                TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
                0, 0, 0, ChainId::new(1),
            )).unwrap(),
        },
    );

    // VULNERABILITY: Transaction should be DENIED because blocked_address participates as fee payer
    // But the filter ALLOWS it because it only checks the primary sender
    assert!(filter.allows_transaction(&bypass_txn)); // This passes - VULNERABILITY!

    // For comparison, AccountAddress matcher correctly blocks this
    let correct_filter = TransactionFilter::empty()
        .add_account_address_filter(false, blocked_address);
    
    assert!(!correct_filter.allows_transaction(&bypass_txn)); // Correctly denied
}
```

## Notes

This vulnerability affects all five transaction filter contexts in Aptos:
1. **Mempool filter** - Allows blocked addresses to submit transactions via mempool
2. **Consensus filter** - Allows blocked addresses in consensus proposals  
3. **Execution filter** - Allows blocked addresses during block execution
4. **API filter** - Allows blocked addresses in API operations
5. **Quorum store filter** - Allows blocked addresses in batch operations

The root cause is the semantic mismatch between the `Sender` matcher name (suggesting it matches "the sender") and its implementation (only checking the primary sender, not all participating senders). Operators would reasonably expect `Sender` to block all transactions where a given address participates as any kind of sender, but this is not the case.

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L188-190)
```rust
            TransactionMatcher::Sender(sender) => {
                matches_sender_address(signed_transaction, sender)
            },
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L197-203)
```rust
            TransactionMatcher::AccountAddress(address) => {
                matches_sender_address(signed_transaction, address)
                    || matches_entry_function_module_address(signed_transaction, address)
                    || matches_multisig_address(signed_transaction, address)
                    || matches_script_argument_address(signed_transaction, address)
                    || matches_transaction_authenticator_address(signed_transaction, address)
            },
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L487-490)
```rust
/// Returns true iff the transaction's sender matches the given account address
fn matches_sender_address(signed_transaction: &SignedTransaction, sender: &AccountAddress) -> bool {
    signed_transaction.sender() == *sender
}
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L501-526)
```rust
        TransactionAuthenticator::MultiAgent {
            sender,
            secondary_signer_addresses,
            secondary_signers,
        } => {
            matches_account_authenticator_address(sender, address)
                || secondary_signer_addresses.contains(address)
                || secondary_signers
                    .iter()
                    .any(|signer| matches_account_authenticator_address(signer, address))
        },
        TransactionAuthenticator::FeePayer {
            sender,
            secondary_signer_addresses,
            secondary_signers,
            fee_payer_address,
            fee_payer_signer,
        } => {
            matches_account_authenticator_address(sender, address)
                || secondary_signer_addresses.contains(address)
                || secondary_signers
                    .iter()
                    .any(|signer| matches_account_authenticator_address(signer, address))
                || fee_payer_address == address
                || matches_account_authenticator_address(fee_payer_signer, address)
        },
```

**File:** types/src/transaction/mod.rs (L1135-1151)
```rust
    pub fn new_fee_payer(
        raw_txn: RawTransaction,
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    ) -> Self {
        let authenticator = TransactionAuthenticator::fee_payer(
            sender,
            secondary_signer_addresses,
            secondary_signers,
            fee_payer_address,
            fee_payer_signer,
        );
        Self::new_signed_transaction(raw_txn, authenticator)
    }
```

**File:** types/src/transaction/mod.rs (L1162-1174)
```rust
    pub fn new_multi_agent(
        raw_txn: RawTransaction,
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    ) -> Self {
        let authenticator = TransactionAuthenticator::multi_agent(
            sender,
            secondary_signer_addresses,
            secondary_signers,
        );
        Self::new_signed_transaction(raw_txn, authenticator)
    }
```

**File:** types/src/transaction/mod.rs (L1242-1244)
```rust
    pub fn sender(&self) -> AccountAddress {
        self.raw_txn.sender
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L318-321)
```rust
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);
```

**File:** mempool/src/shared_mempool/tasks.rs (L432-448)
```rust
    let transactions = transactions
        .into_iter()
        .filter_map(|(transaction, account_sequence_number, priority)| {
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

**File:** crates/aptos-transaction-filters/src/tests/transaction_filter.rs (L323-346)
```rust
fn test_sender_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from a specific sender (txn 0 and txn 1)
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_sender_filter(true, transactions[0].sender())
            .add_sender_filter(true, transactions[1].sender())
            .add_all_filter(false);

        // Verify that the filter returns only transactions from the specified senders
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..2].to_vec());

        // Create a filter that denies transactions from a specific sender (txn 0 and txn 1)
        let filter = TransactionFilter::empty()
            .add_sender_filter(false, transactions[0].sender())
            .add_sender_filter(false, transactions[1].sender())
            .add_all_filter(true);

        // Verify that the filter returns all transactions except those from the specified senders
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[2..].to_vec());
    }
}
```
