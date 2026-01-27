# Audit Report

## Title
Script Transaction Bypass of EntryFunction and ModuleAddress Filters Enables Security Control Evasion

## Summary
Script transactions can bypass `EntryFunction` and `ModuleAddress` transaction filters in mempool, consensus, and execution layers, allowing attackers to call blocked module functions and evade administrative security controls intended to prevent exploitation during incident response or network emergencies.

## Finding Description

The Aptos transaction filtering system allows operators to configure filters at multiple layers (mempool, consensus, execution, API, quorum store) to deny or allow specific transactions based on various criteria. Two critical filter types—`EntryFunction` and `ModuleAddress`—are designed to filter transactions based on which Move modules and functions they invoke. [1](#0-0) 

However, the filtering logic explicitly excludes Script transactions from matching these filters: [2](#0-1) [3](#0-2) 

Despite this exclusion, Script transactions **can and do call external module functions**. The Move VM allows scripts to import and invoke public/entry functions from any module through function handles: [4](#0-3) 

This creates a security bypass: when an operator configures filters to deny transactions calling specific modules or functions (e.g., to respond to a discovered vulnerability), attackers can circumvent these filters by wrapping the same function calls in a Script transaction instead of an EntryFunction transaction.

**Attack Scenario:**
1. A critical vulnerability is discovered in `0x1::token::unsafe_mint()`
2. Network operators configure: `Deny: EntryFunction(0x1, "token", "unsafe_mint")` or `Deny: ModuleAddress(0x1)`
3. Attacker crafts a Script transaction containing bytecode that calls `0x1::token::unsafe_mint()`
4. The script passes through mempool and consensus filters (returns false for both matchers)
5. The vulnerable function executes despite the configured security policy
6. The exploit succeeds, undermining the incident response

The filters are applied at critical security checkpoints: [5](#0-4) [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "Significant protocol violations."

Transaction filters serve as critical administrative security controls that enable operators to:
- Respond rapidly to zero-day vulnerabilities by blocking exploits
- Enforce rate limiting during network upgrades
- Prevent specific operations during emergency situations
- Implement temporary security policies without requiring consensus changes

The bypass undermines these capabilities, creating a significant gap in the network's defense-in-depth strategy. While the direct impact depends on the specific functions being filtered, the systemic failure to enforce configured security policies represents a fundamental protocol violation.

The vulnerability affects:
- All validator nodes running with transaction filters enabled
- Network operators' ability to respond to security incidents
- The reliability of emergency response procedures
- Trust in administrative controls across the Aptos ecosystem

## Likelihood Explanation

**Likelihood: Medium-High**

**Prerequisites:**
- Operators must configure EntryFunction or ModuleAddress filters (not default, but common during incidents)
- Target function must have public or entry visibility (callable from scripts)
- Attacker must be aware of configured filters or discover them through trial

**Feasibility:**
- **High Technical Feasibility**: Scripts are fully supported, and creating script bytecode with function calls is straightforward using Move compiler or manual bytecode construction
- **High Operational Feasibility**: No special permissions required; any user can submit script transactions
- **Detection Difficulty**: Operators may not realize filters are being bypassed until post-incident analysis

**Real-World Scenarios:**
- Emergency response to discovered vulnerabilities in framework modules
- Temporary blocking of specific functions during coordinated upgrades
- Rate limiting of resource-intensive operations
- Prevention of known exploit patterns

The likelihood increases significantly during actual security incidents when filters would be actively deployed, making this a critical window of vulnerability.

## Recommendation

Modify the `matches_entry_function_module_address` and `matches_entry_function` functions to include Script transactions that call functions from the specified modules:

```rust
// In matches_entry_function_module_address
fn matches_entry_function_module_address(
    signed_transaction: &SignedTransaction,
    module_address: &AccountAddress,
) -> bool {
    match signed_transaction.payload() {
        TransactionPayload::Script(script) => {
            // Check if script calls any functions from the specified module address
            matches_script_calls_module_address(script, module_address)
        },
        // ... existing logic for other variants
    }
}

// Helper function to check if script references a module
fn matches_script_calls_module_address(
    script: &Script,
    target_address: &AccountAddress,
) -> bool {
    // Parse script bytecode to extract module handles and check if any match target_address
    // This requires analyzing the compiled script's module_handles table
    // Implementation would use Move binary parser to inspect script dependencies
    false // Placeholder - requires full implementation
}
```

**Alternative Recommendation:**

If implementing bytecode analysis is too complex, add explicit configuration warnings:

1. Document that EntryFunction and ModuleAddress filters do NOT apply to Script transactions
2. Add validation that warns operators when these filters are configured
3. Provide alternative filtering mechanisms (e.g., extend AccountAddress matcher to analyze script dependencies)
4. Consider deprecating Script transactions in favor of entry functions only

**Immediate Mitigation:**

Operators needing to block specific module functions should use multiple filter strategies:
- Combine ModuleAddress filters with Sender/AccountAddress filters
- Consider temporarily disabling script transaction acceptance entirely during incidents
- Monitor for script transactions that call critical modules

## Proof of Concept

This PoC demonstrates creating a script that calls an external module function while bypassing ModuleAddress filters:

```rust
use aptos_types::transaction::{Script, TransactionPayload, SignedTransaction};
use move_binary_format::file_format::{
    empty_script, AddressIdentifierIndex, Bytecode, FunctionHandle, 
    FunctionHandleIndex, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
    SignatureIndex,
};
use move_core_types::{identifier::Identifier, account_address::AccountAddress};
use aptos_transaction_filters::transaction_filter::TransactionFilter;

#[test]
fn test_script_bypasses_module_address_filter() {
    // Create a script that calls 0x1::coin::transfer
    let target_module_addr = AccountAddress::ONE;
    let mut script = empty_script();
    
    // Add module handle for 0x1::coin
    script.address_identifiers.push(target_module_addr);
    script.identifiers.push(Identifier::new("coin").unwrap());
    let module_handle = ModuleHandle {
        address: AddressIdentifierIndex((script.address_identifiers.len() - 1) as u16),
        name: IdentifierIndex((script.identifiers.len() - 1) as u16),
    };
    script.module_handles.push(module_handle);
    
    // Add function handle for transfer
    script.identifiers.push(Identifier::new("transfer").unwrap());
    let fun_handle = FunctionHandle {
        module: ModuleHandleIndex((script.module_handles.len() - 1) as u16),
        name: IdentifierIndex((script.identifiers.len() - 1) as u16),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
        access_specifiers: None,
        attributes: vec![],
    };
    script.function_handles.push(fun_handle);
    
    // Add bytecode to call the function
    script.code.code = vec![
        Bytecode::Call(FunctionHandleIndex((script.function_handles.len() - 1) as u16)),
        Bytecode::Ret,
    ];
    
    let mut blob = vec![];
    script.serialize(&mut blob).expect("script must serialize");
    
    // Create signed transaction with script
    let script_txn = create_signed_script_transaction(Script::new(blob, vec![], vec![]));
    
    // Create filter that denies ModuleAddress(0x1)
    let filter = TransactionFilter::empty()
        .add_module_address_filter(false, target_module_addr)
        .add_all_filter(true);
    
    // Verify the filter INCORRECTLY allows the script transaction
    assert!(filter.allows_transaction(&script_txn), 
        "VULNERABILITY: Script calling 0x1::coin bypasses ModuleAddress(0x1) filter");
    
    // Expected behavior: filter should DENY this script
    // Actual behavior: filter ALLOWS this script
}
```

**Notes**

This vulnerability represents a fundamental design flaw in the transaction filtering system. The semantic meaning of "deny transactions calling module X" should encompass all transaction types that invoke functions from that module, including scripts. The current implementation creates a security control bypass that undermines incident response capabilities and emergency procedures critical to network security.

The issue is particularly concerning because:
1. It affects multiple security-critical layers (mempool, consensus, execution)
2. No alternative mechanism exists to filter scripts by their called modules
3. The bypass is not documented or warned about
4. Operators have no visibility into which transactions are bypassing their filters

Immediate action should be taken to either fix the filtering logic to include scripts or clearly document this limitation and provide alternative security controls.

### Citations

**File:** config/src/config/transaction_filters_config.rs (L20-25)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFilterConfig {
    filter_enabled: bool,                  // Whether the filter is enabled
    transaction_filter: TransactionFilter, // The transaction filter to apply
}
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L332-375)
```rust
/// Returns true iff the transaction's entry function matches the given account address, module name, and function name
fn matches_entry_function(
    signed_transaction: &SignedTransaction,
    address: &AccountAddress,
    module_name: &String,
    function: &String,
) -> bool {
    // Match all variants explicitly to ensure future enum changes are caught during compilation
    match signed_transaction.payload() {
        TransactionPayload::Script(_) | TransactionPayload::ModuleBundle(_) => false,
        TransactionPayload::Multisig(multisig) => multisig
            .transaction_payload
            .as_ref()
            .map(|payload| match payload {
                MultisigTransactionPayload::EntryFunction(entry_function) => {
                    compare_entry_function(entry_function, address, module_name, function)
                },
            })
            .unwrap_or(false),
        TransactionPayload::EntryFunction(entry_function) => {
            compare_entry_function(entry_function, address, module_name, function)
        },
        TransactionPayload::Payload(TransactionPayloadInner::V1 { executable, .. }) => {
            match executable.as_ref() {
                TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                TransactionExecutableRef::EntryFunction(entry_function) => {
                    compare_entry_function(entry_function, address, module_name, function)
                },
            }
        },
        TransactionPayload::EncryptedPayload(payload) => {
            if let Ok(executable) = payload.executable_ref() {
                match executable {
                    TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                    TransactionExecutableRef::EntryFunction(entry_function) => {
                        compare_entry_function(entry_function, address, module_name, function)
                    },
                }
            } else {
                false
            }
        },
    }
}
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L377-418)
```rust
/// Returns true iff the transaction's module address matches the given account address
fn matches_entry_function_module_address(
    signed_transaction: &SignedTransaction,
    module_address: &AccountAddress,
) -> bool {
    // Match all variants explicitly to ensure future enum changes are caught during compilation
    match signed_transaction.payload() {
        TransactionPayload::Script(_) | TransactionPayload::ModuleBundle(_) => false,
        TransactionPayload::Multisig(multisig) => multisig
            .transaction_payload
            .as_ref()
            .map(|payload| match payload {
                MultisigTransactionPayload::EntryFunction(entry_function) => {
                    compare_entry_function_module_address(entry_function, module_address)
                },
            })
            .unwrap_or(false),
        TransactionPayload::EntryFunction(entry_function) => {
            compare_entry_function_module_address(entry_function, module_address)
        },
        TransactionPayload::Payload(TransactionPayloadInner::V1 { executable, .. }) => {
            match executable.as_ref() {
                TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                TransactionExecutableRef::EntryFunction(entry_function) => {
                    compare_entry_function_module_address(entry_function, module_address)
                },
            }
        },
        TransactionPayload::EncryptedPayload(payload) => {
            if let Ok(executable) = payload.executable_ref() {
                match executable {
                    TransactionExecutableRef::Script(_) | TransactionExecutableRef::Empty => false,
                    TransactionExecutableRef::EntryFunction(entry_function) => {
                        compare_entry_function_module_address(entry_function, module_address)
                    },
                }
            } else {
                false
            }
        },
    }
}
```

**File:** aptos-move/e2e-testsuite/src/tests/scripts.rs (L84-112)
```rust
    // make a non existent external module
    script
        .address_identifiers
        .push(AccountAddress::new([2u8; AccountAddress::LENGTH]));
    script.identifiers.push(Identifier::new("module").unwrap());
    let module_handle = ModuleHandle {
        address: AddressIdentifierIndex((script.address_identifiers.len() - 1) as u16),
        name: IdentifierIndex((script.identifiers.len() - 1) as u16),
    };
    script.module_handles.push(module_handle);
    // make a non existent function on the non existent external module
    script.identifiers.push(Identifier::new("foo").unwrap());
    let fun_handle = FunctionHandle {
        module: ModuleHandleIndex((script.module_handles.len() - 1) as u16),
        name: IdentifierIndex((script.identifiers.len() - 1) as u16),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
        access_specifiers: None,
        attributes: vec![],
    };
    script.function_handles.push(fun_handle);

    script.code.code = vec![
        Bytecode::Call(FunctionHandleIndex(
            (script.function_handles.len() - 1) as u16,
        )),
        Bytecode::Ret,
    ];
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

**File:** api/src/transactions.rs (L619-631)
```rust
            // Confirm the API simulation filter allows the transaction
            let api_filter = &context.node_config.transaction_filters.api_filter;
            if api_filter.is_enabled()
                && !api_filter
                    .transaction_filter()
                    .allows_transaction(&signed_transaction)
            {
                return Err(SubmitTransactionError::forbidden_with_code(
                    "Transaction not allowed by simulation filter",
                    AptosErrorCode::InvalidInput,
                    &ledger_info,
                ));
            }
```

**File:** consensus/src/block_preparer.rs (L122-146)
```rust
/// Filters transactions in a block based on the filter configuration
fn filter_block_transactions(
    txn_filter_config: Arc<BlockTransactionFilterConfig>,
    block_id: HashValue,
    block_author: Option<AccountAddress>,
    block_epoch: u64,
    block_timestamp_usecs: u64,
    txns: Vec<SignedTransaction>,
) -> Vec<SignedTransaction> {
    // If the transaction filter is disabled, return early
    if !txn_filter_config.is_enabled() {
        return txns;
    }

    // Otherwise, filter the transactions
    txn_filter_config
        .block_transaction_filter()
        .filter_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp_usecs,
            txns,
        )
}
```
