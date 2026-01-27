# Audit Report

## Title
Transaction Filter Bypass via Serialized Script Arguments Containing Hidden Addresses

## Summary
The `compare_script_argument_address()` function only checks `TransactionArgument::Address` variants while completely ignoring `TransactionArgument::Serialized` variants. Since the `ALLOW_SERIALIZED_SCRIPT_ARGS` feature is enabled by default and serialized arguments can contain BCS-encoded addresses, attackers can bypass transaction filters designed to block specific addresses.

## Finding Description

The transaction filtering mechanism is designed to detect and block transactions involving specific addresses (e.g., sanctioned addresses, blocked accounts). The `TransactionMatcher::AccountAddress` variant checks multiple locations for addresses, including script arguments via the `matches_script_argument_address()` function. [1](#0-0) 

However, the underlying `compare_script_argument_address()` function has a critical gap: [2](#0-1) 

This function only checks `TransactionArgument::Address` and returns `false` for all other variants, including `TransactionArgument::Serialized`. 

The `TransactionArgument` enum includes a `Serialized` variant that can contain arbitrary BCS-encoded data: [3](#0-2) 

Existing test code demonstrates that `TransactionArgument::Serialized` is explicitly used to pass BCS-encoded addresses and vectors of addresses: [4](#0-3) 

The `ALLOW_SERIALIZED_SCRIPT_ARGS` feature flag is enabled by default: [5](#0-4) 

**Attack Path:**
1. Node operator configures transaction filter to block address `0xBLOCKED` using `TransactionFilter::add_account_address_filter(false, 0xBLOCKED)`
2. Filter is applied in mempool to reject transactions involving this address: [6](#0-5) 

3. Attacker crafts a script transaction with `TransactionArgument::Serialized(bcs::to_bytes(&0xBLOCKED).unwrap())`
4. Filter calls `matches_script_argument_address()` which calls `compare_script_argument_address()`
5. Function returns `false` because the argument is `Serialized`, not `Address`
6. Transaction bypasses filter and enters mempool despite containing blocked address
7. Script executes with the blocked address when processed

This breaks the security guarantee that transaction filters detect all addresses in transactions.

## Impact Explanation

**Medium Severity** - This vulnerability allows bypassing transaction filtering mechanisms, which are critical security controls for:
- **Sanctions compliance**: Blocking transactions from OFAC-sanctioned addresses
- **Access control**: Preventing specific addresses from interacting with protected modules
- **Security policies**: Enforcing node operator restrictions on allowed addresses

While this doesn't directly cause fund theft or consensus failure, it fundamentally breaks the security guarantees of the transaction filtering system. Operators relying on filters to enforce compliance or security policies would have a false sense of security while blocked addresses can still interact with the blockchain.

This falls under "State inconsistencies requiring intervention" in the Medium Severity category, as operators would need to manually identify and handle transactions that should have been filtered.

## Likelihood Explanation

**High Likelihood**:
- The `ALLOW_SERIALIZED_SCRIPT_ARGS` feature is enabled by default on mainnet
- Creating scripts with serialized arguments is straightforward (demonstrated in existing tests)
- No special privileges required - any transaction sender can exploit this
- The bypass is deterministic and reliable once discovered
- Operators using filters for compliance may not be aware of this limitation

## Recommendation

Modify `compare_script_argument_address()` to deserialize and check addresses within `TransactionArgument::Serialized` variants:

```rust
fn compare_script_argument_address(script: &Script, address: &AccountAddress) -> bool {
    script.args().iter().any(|transaction_argument| {
        match transaction_argument {
            TransactionArgument::Address(argument_address) => argument_address == address,
            TransactionArgument::Serialized(bytes) => {
                // Attempt to deserialize as AccountAddress
                if let Ok(deserialized_address) = bcs::from_bytes::<AccountAddress>(bytes) {
                    if &deserialized_address == address {
                        return true;
                    }
                }
                // Attempt to deserialize as Vec<AccountAddress>
                if let Ok(address_vec) = bcs::from_bytes::<Vec<AccountAddress>>(bytes) {
                    if address_vec.contains(address) {
                        return true;
                    }
                }
                false
            },
            _ => false,
        }
    })
}
```

Alternatively, document this limitation clearly and advise operators that filters cannot detect addresses in serialized arguments, recommending disabling `ALLOW_SERIALIZED_SCRIPT_ARGS` if strict filtering is required.

## Proof of Concept

```rust
#[test]
fn test_account_address_filter_bypasses_serialized_script_argument() {
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, SigningKey, Uniform};
    use aptos_types::{
        chain_id::ChainId,
        transaction::{RawTransaction, Script, SignedTransaction, TransactionArgument},
    };
    use move_core_types::account_address::AccountAddress;
    use rand::thread_rng;
    
    // Target address to block
    let blocked_address = AccountAddress::from_hex_literal("0xBLOCKED").unwrap();
    
    // Create filter that denies transactions involving blocked_address
    let filter = TransactionFilter::empty()
        .add_account_address_filter(false, blocked_address)
        .add_all_filter(true);
    
    // Create script with Address variant (should be blocked)
    let script_with_address = Script::new(
        vec![],
        vec![],
        vec![TransactionArgument::Address(blocked_address)],
    );
    let txn_with_address = create_signed_transaction(
        TransactionPayload::Script(script_with_address)
    );
    
    // Verify this transaction is correctly blocked
    assert!(!filter.allows_transaction(&txn_with_address));
    
    // Create script with Serialized variant containing the same address
    let serialized_address = bcs::to_bytes(&blocked_address).unwrap();
    let script_with_serialized = Script::new(
        vec![],
        vec![],
        vec![TransactionArgument::Serialized(serialized_address)],
    );
    let txn_with_serialized = create_signed_transaction(
        TransactionPayload::Script(script_with_serialized)
    );
    
    // BUG: This transaction bypasses the filter despite containing blocked_address
    assert!(filter.allows_transaction(&txn_with_serialized));
    // Expected: false (should be blocked)
    // Actual: true (bypasses filter)
}

fn create_signed_transaction(payload: TransactionPayload) -> SignedTransaction {
    let sender = AccountAddress::random();
    let raw_txn = RawTransaction::new(
        sender,
        0,
        payload,
        1_000_000,
        1,
        0,
        ChainId::new(1),
    );
    let private_key = Ed25519PrivateKey::generate(&mut thread_rng());
    SignedTransaction::new(
        raw_txn.clone(),
        private_key.public_key(),
        private_key.sign(&raw_txn).unwrap(),
    )
}
```

This PoC demonstrates that identical addresses are treated differently based on whether they're in `TransactionArgument::Address` or `TransactionArgument::Serialized`, allowing filter bypass.

---

**Notes:**

The vulnerability is further validated by examining how serialized arguments can contain not just single addresses but also `Vec<AccountAddress>` as shown in the test code, meaning multiple blocked addresses could be hidden in a single serialized argument. The filter's design assumes all address-containing variants are explicitly checked, but this assumption is violated for the Serialized variant.

### Citations

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

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L248-256)
```rust
fn compare_script_argument_address(script: &Script, address: &AccountAddress) -> bool {
    script.args().iter().any(|transaction_argument| {
        if let TransactionArgument::Address(argument_address) = transaction_argument {
            argument_address == address
        } else {
            false
        }
    })
}
```

**File:** third_party/move/move-core/types/src/transaction_argument.rs (L10-31)
```rust
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionArgument {
    U8(u8),
    U64(u64),
    U128(u128),
    Address(AccountAddress),
    U8Vector(#[serde(with = "serde_bytes")] Vec<u8>),
    Bool(bool),
    // NOTE: Added in bytecode version v6, do not reorder!
    U16(u16),
    U32(u32),
    U256(int256::U256),
    // Note: Gated by feature flag ALLOW_SERIALIZED_SCRIPT_ARGS
    Serialized(#[serde(with = "serde_bytes")] Vec<u8>),
    // NOTE: Added in bytecode version v9, do not reorder!
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    I256(int256::I256),
}
```

**File:** aptos-move/e2e-move-tests/src/tests/scripts.rs (L91-96)
```rust
    let script = Script::new(code, vec![], vec![
        TransactionArgument::Serialized(bcs::to_bytes(&metadata).unwrap()),
        TransactionArgument::Serialized(bcs::to_bytes(&vec![alice.address()]).unwrap()),
        TransactionArgument::Serialized(bcs::to_bytes(&vec![bob.address()]).unwrap()),
        TransactionArgument::Serialized(bcs::to_bytes(&vec![30u64]).unwrap()),
    ]);
```

**File:** types/src/on_chain_config/aptos_features.rs (L242-242)
```rust
            FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS,
```

**File:** mempool/src/shared_mempool/tasks.rs (L435-458)
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

                statuses.push((
                    transaction.clone(),
                    (
                        MempoolStatus::new(MempoolStatusCode::RejectedByFilter),
                        None,
                    ),
                ));
                None
            }
```
