# Audit Report

## Title
Transaction Filter Bypass: EntryFunction and Multisig Payloads Evade Address-Based Filtering

## Summary
The `matches_script_argument_address()` function explicitly returns `false` for EntryFunction and Multisig transaction payloads, allowing addresses embedded in BCS-serialized arguments to bypass address-based transaction filters. This enables filter evasion when using modern transaction types instead of deprecated Script transactions.

## Finding Description

The transaction filter system in Aptos allows operators to configure rules for blocking or allowing transactions based on various criteria, including account addresses involved in transactions. The `TransactionMatcher::AccountAddress` matcher is designed to catch transactions involving a specific address by checking multiple locations: sender address, module address, multisig address, script arguments, and transaction authenticator. [1](#0-0) 

However, the `matches_script_argument_address()` function that checks script arguments explicitly returns `false` for EntryFunction and Multisig payloads: [2](#0-1) 

The fundamental issue is the structural difference between transaction payload types:
- **Script transactions** (deprecated): Use `Vec<TransactionArgument>` where addresses are accessible as `TransactionArgument::Address` [3](#0-2) 

- **EntryFunction transactions** (modern): Use `Vec<Vec<u8>>` where addresses are BCS-serialized bytes [4](#0-3) 

While Script transactions have their address arguments explicitly checked, EntryFunction and Multisig transactions with address arguments embedded in BCS-serialized data are not inspected at all.

**Attack Scenario:**
1. An operator configures a filter using `TransactionMatcher::AccountAddress(blocked_address)` to comply with sanctions or security policies
2. A Script transaction with `blocked_address` as `TransactionArgument::Address` would be caught and rejected
3. An attacker submits an EntryFunction transaction calling the same logic but with `blocked_address` BCS-serialized in the args vector
4. The filter's `matches_script_argument_address()` check returns `false` for EntryFunction payloads
5. The transaction bypasses the filter and is processed

Transaction filters are deployed across multiple critical components: [5](#0-4) 

The mempool uses these filters to reject non-compliant transactions: [6](#0-5) 

## Impact Explanation

This issue falls under **Low Severity** per the Aptos bug bounty program criteria as a non-critical implementation bug. While it represents an incomplete feature that allows filter bypass, it does not result in:
- Loss or theft of funds
- Consensus safety violations
- Network partition or liveness failures
- State corruption or manipulation
- Critical protocol violations

Transaction filters are optional, operator-configured features intended for policy enforcement (e.g., compliance, rate limiting) rather than critical security controls. The bypass requires no special privileges and is trivially exploitable, but the real-world impact is limited to policy violations rather than technical security breaches.

## Likelihood Explanation

The likelihood of exploitation is **High** given that:
- EntryFunctions are the standard modern transaction type (Scripts are deprecated)
- No special privileges or complex setup required
- Attack is deterministic and requires no timing or race conditions
- Operators may reasonably expect `AccountAddress` matching to work across all transaction types
- BCS-serialized address arguments in EntryFunctions are common (e.g., transfer recipients, module addresses)

However, the prerequisite of an operator having configured address-based filters reduces overall likelihood of real-world impact.

## Recommendation

To properly support address filtering for EntryFunction and Multisig payloads, the implementation should attempt to BCS-deserialize each argument and check if it represents an AccountAddress. However, this approach has significant challenges:

1. **Type ambiguity**: Without the function's ABI, you cannot determine which arguments are addresses
2. **False positives**: Arbitrary bytes may accidentally deserialize as valid addresses
3. **Performance cost**: BCS deserialization on every filter check adds overhead

**Recommended approach:**

For comprehensive address filtering, enhance the filter system to accept ABI information and perform typed argument inspection:

```rust
// Add ABI-aware matching
fn matches_entry_function_argument_address(
    signed_transaction: &SignedTransaction,
    address: &AccountAddress,
    function_abi: Option<&EntryFunctionABI>,
) -> bool {
    // If ABI available, deserialize typed arguments
    // Otherwise, attempt best-effort deserialization of all args
}
```

**Alternative simpler fix:**

Document the current behavior clearly and recommend operators use more specific matchers (`EntryFunction`, `ModuleAddress`, `Sender`) rather than relying on `AccountAddress` for comprehensive coverage. Update the `AccountAddress` matcher documentation to explicitly state it does not inspect BCS-serialized arguments.

## Proof of Concept

```rust
#[cfg(test)]
mod test_filter_bypass {
    use super::*;
    use aptos_types::{
        transaction::{EntryFunction, Script, TransactionPayload},
        account_address::AccountAddress,
    };
    use move_core_types::{
        identifier::Identifier,
        language_storage::ModuleId,
        transaction_argument::TransactionArgument,
    };

    #[test]
    fn test_entry_function_bypasses_address_filter() {
        // Target address we want to block
        let blocked_address = AccountAddress::from_hex_literal("0xBAD").unwrap();
        
        // Create filter that blocks the target address
        let filter = TransactionFilter::empty()
            .add_account_address_filter(false, blocked_address)
            .add_all_filter(true);
        
        // Test 1: Script with blocked address as argument - GETS BLOCKED
        let script_args = vec![
            TransactionArgument::Address(blocked_address),
        ];
        let script_payload = TransactionPayload::Script(
            Script::new(vec![0x1], vec![], script_args)
        );
        let script_txn = create_signed_transaction(script_payload, false);
        assert!(!filter.allows_transaction(&script_txn), 
            "Script with blocked address should be rejected");
        
        // Test 2: EntryFunction with blocked address as BCS arg - BYPASSES FILTER
        let entry_function_args = vec![
            bcs::to_bytes(&blocked_address).unwrap(), // BCS-serialized address
        ];
        let entry_function = EntryFunction::new(
            ModuleId::new(AccountAddress::random(), Identifier::new("module").unwrap()),
            Identifier::new("function").unwrap(),
            vec![],
            entry_function_args,
        );
        let entry_function_payload = TransactionPayload::EntryFunction(entry_function);
        let entry_function_txn = create_signed_transaction(entry_function_payload, false);
        assert!(filter.allows_transaction(&entry_function_txn),
            "EntryFunction with blocked address bypasses filter");
    }
}
```

## Notes

This is a **design limitation** rather than a critical vulnerability. The transaction filter system was designed when Scripts were the primary transaction type with strongly-typed arguments. EntryFunctions use BCS serialization for flexibility, but this makes content inspection significantly more complex. The severity remains Low because transaction filters are not intended as security-critical access controls but rather as operational policy enforcement tools.

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

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L451-485)
```rust
fn matches_script_argument_address(
    signed_transaction: &SignedTransaction,
    address: &AccountAddress,
) -> bool {
    // Match all variants explicitly to ensure future enum changes are caught during compilation
    match signed_transaction.payload() {
        TransactionPayload::EntryFunction(_)
        | TransactionPayload::Multisig(_)
        | TransactionPayload::ModuleBundle(_) => false,
        TransactionPayload::Script(script) => compare_script_argument_address(script, address),
        TransactionPayload::Payload(TransactionPayloadInner::V1 { executable, .. }) => {
            match executable.as_ref() {
                TransactionExecutableRef::EntryFunction(_) | TransactionExecutableRef::Empty => {
                    false
                },
                TransactionExecutableRef::Script(script) => {
                    compare_script_argument_address(script, address)
                },
            }
        },
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
    }
}
```

**File:** types/src/transaction/script.rs (L64-69)
```rust
pub struct Script {
    #[serde(with = "serde_bytes")]
    code: Vec<u8>,
    ty_args: Vec<TypeTag>,
    args: Vec<TransactionArgument>,
}
```

**File:** types/src/transaction/script.rs (L108-115)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryFunction {
    module: ModuleId,
    function: Identifier,
    ty_args: Vec<TypeTag>,
    #[serde(with = "vec_bytes")]
    args: Vec<Vec<u8>>,
}
```

**File:** config/src/config/transaction_filters_config.rs (L10-18)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFiltersConfig {
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
}
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
