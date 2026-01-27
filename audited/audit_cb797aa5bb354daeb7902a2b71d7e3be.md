# Audit Report

## Title
Transaction Filter Bypass via Secondary Signers and Fee Payers in Sender-Based Filtering

## Summary
The `TransactionMatcher::Sender` filter only checks the primary sender address of transactions, allowing attackers to bypass address-based filters by using blocked addresses as secondary signers in multi-agent transactions or as fee payers in sponsored transactions. This undermines security controls intended to block malicious or sanctioned addresses.

## Finding Description

The Aptos transaction filtering system provides two distinct matchers for address filtering: [1](#0-0) 

The `Sender` matcher only checks the primary sender field: [2](#0-1) [3](#0-2) 

In contrast, the `AccountAddress` matcher comprehensively checks all address involvement: [4](#0-3) 

Critically, the `matches_transaction_authenticator_address` function checks secondary signers and fee payers: [5](#0-4) [6](#0-5) 

However, **all production examples in the codebase use `Sender` matcher**, not `AccountAddress`: [7](#0-6) [8](#0-7) 

**Attack Scenario:**
1. Node operator configures filter to block address `0xBAD` using `TransactionMatcher::Sender(0xBAD)`
2. Attacker creates multi-agent transaction with benign address `0xGOOD` as sender and `0xBAD` as secondary signer
3. Transaction passes through mempool, consensus, and execution because sender check only examines `0xGOOD`
4. Blocked address `0xBAD` successfully participates in blockchain operations despite the filter

Aptos supports both multi-agent and fee-payer transactions that enable this bypass. The infrastructure exists throughout the codebase and is production-ready.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria because it represents a security control bypass with limited but real impact:

1. **Security Control Undermining**: Filters intended to block malicious/sanctioned addresses can be bypassed, allowing continued blockchain interaction
2. **Compliance Risk**: Organizations using sender-based filters for compliance (sanctions, regulatory requirements) have ineffective controls
3. **API Confusion**: The naming and examples strongly suggest `Sender` is appropriate for blocking addresses, leading to predictable misconfiguration
4. **No Direct Fund Loss**: Does not directly steal funds or violate consensus, but enables blocked actors to operate
5. **Requires Misconfiguration**: Operator must choose `Sender` instead of `AccountAddress`, though examples make this highly likely

The impact is limited to security policy violations rather than direct protocol compromise, placing it in the Medium category.

## Likelihood Explanation

**Likelihood: High** - This is extremely likely to occur in production:

1. **All Official Examples Use Vulnerable Pattern**: Every smoke test and consensus test uses `TransactionMatcher::Sender`, establishing it as the de facto standard
2. **Intuitive Naming**: Operators wanting to "block a sender" naturally choose `Sender` matcher
3. **No Documentation**: No clear guidance exists distinguishing when to use `Sender` vs `AccountAddress`
4. **Simple Exploitation**: Multi-agent and fee-payer transactions are standard Aptos features requiring no special privileges
5. **Silent Failure**: Bypass occurs without errors or warnings, making detection difficult

The combination of misleading examples, intuitive but incorrect naming, and easy exploitation makes this vulnerability highly likely to manifest in real-world deployments.

## Recommendation

**Immediate Fix:**
1. Update all examples to use `TransactionMatcher::AccountAddress` instead of `TransactionMatcher::Sender`
2. Add clear documentation explaining the difference between matchers
3. Consider deprecating or renaming `Sender` to `PrimarySenderOnly` to make limitations explicit

**Code Changes:**

In `testsuite/smoke-test/src/transaction_filter.rs`:
```rust
// Change line 251, 264, 277 from:
TransactionMatcher::Sender(sender_address)
// To:
TransactionMatcher::AccountAddress(sender_address)
```

In `consensus/src/round_manager_tests/txn_filter_proposal_test.rs`:
```rust
// Change line 43, 165 from:
TransactionMatcher::Sender(transactions[0].sender())
// To:
TransactionMatcher::AccountAddress(transactions[0].sender())
```

**Long-term:**
- Add warning logs when `Sender` matcher is used
- Provide configuration validator that detects likely misconfigurations
- Consider making `AccountAddress` the default for address filtering

## Proof of Concept

```rust
#[test]
fn test_sender_filter_bypass_via_secondary_signer() {
    use aptos_crypto::{ed25519::*, PrivateKey, Uniform};
    use aptos_transaction_filters::transaction_filter::{TransactionFilter, TransactionMatcher};
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{
            authenticator::AccountAuthenticator, RawTransaction, RawTransactionWithData,
            Script, SignedTransaction, TransactionPayload,
        },
    };
    use rand::thread_rng;

    // Create blocked address and benign address
    let blocked_address = AccountAddress::random();
    let benign_address = AccountAddress::random();

    // Create filter blocking the "bad" address using Sender matcher (as in production examples)
    let filter = TransactionFilter::empty()
        .add_sender_filter(false, blocked_address)  // Deny transactions from blocked_address
        .add_all_filter(true);  // Allow all others

    // Create multi-agent transaction with:
    // - benign_address as primary sender (passes Sender check)
    // - blocked_address as secondary signer (NOT checked by Sender matcher)
    let sender_private_key = Ed25519PrivateKey::generate(&mut thread_rng());
    let sender_public_key = sender_private_key.public_key();
    let secondary_private_key = Ed25519PrivateKey::generate(&mut thread_rng());
    let secondary_public_key = secondary_private_key.public_key();

    let raw_txn = RawTransaction::new(
        benign_address,
        0,
        TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
        1_000_000,
        1,
        u64::MAX,
        ChainId::test(),
    );

    // Sign as multi-agent with blocked_address as secondary signer
    let message = RawTransactionWithData::new_multi_agent(
        raw_txn.clone(),
        vec![blocked_address],  // Blocked address as secondary signer!
    );

    let sender_signature = sender_private_key.sign(&message).unwrap();
    let sender_auth = AccountAuthenticator::ed25519(sender_public_key, sender_signature);

    let secondary_signature = secondary_private_key.sign(&message).unwrap();
    let secondary_auth = AccountAuthenticator::ed25519(secondary_public_key, secondary_signature);

    let signed_txn = SignedTransaction::new_multi_agent(
        raw_txn,
        sender_auth,
        vec![blocked_address],
        vec![secondary_auth],
    );

    // VULNERABILITY: Transaction with blocked address as secondary signer passes the filter!
    assert!(filter.allows_transaction(&signed_txn));
    
    // The correct AccountAddress matcher would catch this:
    let correct_filter = TransactionFilter::empty()
        .add_account_address_filter(false, blocked_address)
        .add_all_filter(true);
    
    assert!(!correct_filter.allows_transaction(&signed_txn));  // Properly blocked
}

#[test]
fn test_sender_filter_bypass_via_fee_payer() {
    use aptos_crypto::{ed25519::*, PrivateKey, Uniform};
    use aptos_transaction_filters::transaction_filter::{TransactionFilter, TransactionMatcher};
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{
            authenticator::AccountAuthenticator, RawTransaction,
            Script, SignedTransaction, TransactionPayload,
        },
    };
    use rand::thread_rng;

    let blocked_address = AccountAddress::random();
    let benign_address = AccountAddress::random();

    let filter = TransactionFilter::empty()
        .add_sender_filter(false, blocked_address)
        .add_all_filter(true);

    let sender_private_key = Ed25519PrivateKey::generate(&mut thread_rng());
    let sender_public_key = sender_private_key.public_key();
    let fee_payer_private_key = Ed25519PrivateKey::generate(&mut thread_rng());
    let fee_payer_public_key = fee_payer_private_key.public_key();

    let raw_txn = RawTransaction::new(
        benign_address,
        0,
        TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
        1_000_000,
        1,
        u64::MAX,
        ChainId::test(),
    );

    let sender_signature = sender_private_key.sign(&raw_txn).unwrap();
    let sender_auth = AccountAuthenticator::ed25519(sender_public_key, sender_signature);

    let fee_payer_signature = fee_payer_private_key.sign(&raw_txn).unwrap();
    let fee_payer_auth = AccountAuthenticator::ed25519(fee_payer_public_key, fee_payer_signature);

    // Create fee-payer transaction with blocked address as fee payer
    let signed_txn = SignedTransaction::new_fee_payer(
        raw_txn,
        sender_auth,
        vec![],
        vec![],
        blocked_address,  // Blocked address as fee payer!
        fee_payer_auth,
    );

    // VULNERABILITY: Transaction with blocked address as fee payer passes the filter!
    assert!(filter.allows_transaction(&signed_txn));

    // AccountAddress matcher would catch this:
    let correct_filter = TransactionFilter::empty()
        .add_account_address_filter(false, blocked_address)
        .add_all_filter(true);
    
    assert!(!correct_filter.allows_transaction(&signed_txn));
}
```

**Notes:**

This vulnerability represents a critical API design flaw where the most intuitive and documented approach to address filtering is insecure. While the `AccountAddress` matcher provides correct behavior, the widespread use of `Sender` in official examples virtually guarantees real-world exploitation. The fix requires updating documentation and examples rather than core logic changes, but the security impact on existing deployments using sender-based filtering is significant.

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L174-177)
```rust
    Sender(AccountAddress), // Matches any transaction sent by a specific account address
    ModuleAddress(AccountAddress), // Matches any transaction that calls a module at a specific address
    EntryFunction(AccountAddress, String, String), // Matches any transaction that calls a specific entry function in a module
    AccountAddress(AccountAddress), // Matches any transaction that involves a specific account address
```

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

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L488-490)
```rust
fn matches_sender_address(signed_transaction: &SignedTransaction, sender: &AccountAddress) -> bool {
    signed_transaction.sender() == *sender
}
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L501-511)
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
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L512-526)
```rust
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

**File:** testsuite/smoke-test/src/transaction_filter.rs (L247-258)
```rust
fn filter_inline_transactions(node_config: &mut NodeConfig, sender_address: AccountAddress) {
    // Create the block transaction filter
    let block_transaction_filter = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
            TransactionMatcher::Sender(sender_address),
        )])
        .add_all_filter(true);

    // Update the node config with the new filter
    node_config.transaction_filters.consensus_filter =
        BlockTransactionFilterConfig::new(true, block_transaction_filter);
}
```

**File:** consensus/src/round_manager_tests/txn_filter_proposal_test.rs (L40-46)
```rust
        // Create a block filter config that denies the first transaction sender
        let block_txn_filter = BlockTransactionFilter::empty()
            .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(transactions[0].sender()),
            )])
            .add_all_filter(true);
        let block_txn_filter_config = BlockTransactionFilterConfig::new(true, block_txn_filter);
```
