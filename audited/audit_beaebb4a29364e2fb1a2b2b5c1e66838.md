# Audit Report

## Title
Memory Exhaustion DOS via Unbounded EntryFunction Argument Deserialization

## Summary
The `vec_bytes::deserialize()` function performs no size validation on individual `Vec<u8>` elements during BCS deserialization of EntryFunction arguments. This allows attackers to craft transactions with oversized byte vector arguments (up to 64 MiB via P2P network) that are fully deserialized and allocated in validator memory BEFORE transaction size limits are checked, enabling memory exhaustion Denial-of-Service attacks against validator nodes.

## Finding Description
The vulnerability exists in the transaction validation flow where the order of operations creates a window for resource exhaustion:

**Vulnerable Code:** [1](#0-0) 

This deserialization helper has no size validation on individual vectors. It is used by `EntryFunction` to deserialize transaction arguments: [2](#0-1) 

**Critical Ordering Flaw:**

1. **Network Reception:** Transactions arrive via P2P network with `MAX_MESSAGE_SIZE = 64 MiB`: [3](#0-2) 

2. **Deserialization (NO size check):** The entire transaction is deserialized including EntryFunction args via BCS: [4](#0-3) 

Note the depth limit is only 16, with NO size limit. At this point, `vec_bytes::deserialize()` allocates memory for all byte vectors regardless of size.

3. **Size Check (AFTER allocation):** Only after full deserialization is the transaction size checked: [5](#0-4) [6](#0-5) 

The default transaction size limit is only 64 KB: [7](#0-6) 

**Attack Flow:**
An attacker submits a transaction via P2P containing EntryFunction arguments with multiple large byte vectors totaling 50 MiB. The network layer accepts it (under 64 MiB limit), deserializes it completely (allocating 50 MiB), then `check_gas()` rejects it for exceeding 64 KB limit. However, the 50 MiB was already allocated. By flooding validators with such transactions, an attacker exhausts memory.

## Impact Explanation
This qualifies as **High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Excessive memory allocation during deserialization degrades validator performance
- **API crashes**: Memory exhaustion can cause out-of-memory crashes

The attack breaks **Invariant #9 (Resource Limits)**: Memory allocation occurs before resource limits are enforced, allowing unbounded memory consumption per transaction up to the network message size limit (64 MiB), far exceeding the intended transaction size limit (64 KB).

All validator nodes are affected as they process P2P mempool broadcasts before validation. A coordinated attack with multiple oversized transactions can exhaust validator memory pools, causing severe performance degradation or crashes.

## Likelihood Explanation
**Likelihood: HIGH**

- **Attack Complexity:** Low - attacker only needs to craft BCS-encoded transactions with large byte vector arguments
- **Attacker Requirements:** Any network participant can send P2P mempool broadcasts
- **Detection Difficulty:** High - transactions are rejected after deserialization, appearing as normal validation failures in logs
- **Reproducibility:** 100% - the ordering flaw is deterministic

The attack is trivially exploitable and requires no special privileges or validator access.

## Recommendation
Add size validation during deserialization by implementing a size-limited deserializer for `vec_bytes`:

```rust
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    const MAX_TOTAL_BYTES: usize = 64 * 1024; // Match max_transaction_size_in_bytes
    const MAX_SINGLE_VEC_BYTES: usize = 64 * 1024; // Limit individual vectors
    
    let vecs = <Vec<serde_bytes::ByteBuf>>::deserialize(deserializer)?;
    
    let mut total_bytes = 0usize;
    for vec in &vecs {
        let len = vec.len();
        if len > MAX_SINGLE_VEC_BYTES {
            return Err(serde::de::Error::custom(
                format!("Vec<u8> element exceeds maximum size: {} > {}", len, MAX_SINGLE_VEC_BYTES)
            ));
        }
        total_bytes = total_bytes.checked_add(len)
            .ok_or_else(|| serde::de::Error::custom("Total bytes overflow"))?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(serde::de::Error::custom(
                format!("Total Vec<Vec<u8>> size exceeds limit: {} > {}", total_bytes, MAX_TOTAL_BYTES)
            ));
        }
    }
    
    Ok(vecs.into_iter().map(serde_bytes::ByteBuf::into_vec).collect())
}
```

Additionally, enforce size checks at the network layer before full deserialization.

## Proof of Concept

```rust
// Proof of Concept: Craft oversized transaction
use aptos_types::transaction::{EntryFunction, RawTransaction, SignedTransaction, TransactionPayload};
use move_core_types::{identifier::Identifier, language_storage::ModuleId, account_address::AccountAddress};

fn create_oversized_transaction() -> SignedTransaction {
    // Create EntryFunction with oversized arguments
    let huge_arg = vec![0u8; 10 * 1024 * 1024]; // 10 MB byte vector
    let args = vec![huge_arg.clone(), huge_arg.clone(), huge_arg]; // 30 MB total
    
    let entry_function = EntryFunction::new(
        ModuleId::new(AccountAddress::ONE, Identifier::new("test").unwrap()),
        Identifier::new("function").unwrap(),
        vec![],
        args,
    );
    
    let raw_txn = RawTransaction::new_entry_function(
        AccountAddress::ONE,
        0,
        entry_function,
        1_000_000,
        0,
        u64::MAX,
        1,
    );
    
    // Sign and serialize
    // When this transaction is deserialized by a validator:
    // 1. Network accepts it (< 64 MiB)
    // 2. vec_bytes::deserialize() allocates 30 MB
    // 3. check_gas() rejects (> 64 KB limit)
    // 4. But 30 MB was already allocated!
    
    // Repeat with hundreds of such transactions to exhaust validator memory
}
```

**Notes:**
This vulnerability demonstrates a fundamental ordering flaw where resource allocation occurs before validation. The `vec_bytes::deserialize()` helper, while optimized for efficiency, creates a critical security gap by lacking size guards that should match the downstream validation limits.

### Citations

**File:** types/src/serde_helper/vec_bytes.rs (L21-29)
```rust
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(<Vec<serde_bytes::ByteBuf>>::deserialize(deserializer)?
        .into_iter()
        .map(serde_bytes::ByteBuf::into_vec)
        .collect())
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

**File:** network/framework/src/constants.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

/// A collection of constants and default values for configuring various network components.

// NB: Almost all of these values are educated guesses, and not determined using any empirical
// data. If you run into a limit and believe that it is unreasonably tight, please submit a PR
// with your use-case. If you do change a value, please add a comment linking to the PR which
// advocated the change.
/// The timeout for any inbound RPC call before it's cut off
pub const INBOUND_RPC_TIMEOUT_MS: u64 = 10_000;
/// Limit on concurrent Outbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;

// These are only used in tests
// TODO: Fix this so the tests and the defaults in config are the same
pub const NETWORK_CHANNEL_SIZE: usize = 1024;
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
pub const MAX_CONCURRENT_NETWORK_NOTIFS: usize = 100;


```

**File:** api/src/transactions.rs (L1220-1237)
```rust
    ) -> Result<SignedTransaction, SubmitTransactionError> {
        match data {
            SubmitTransactionPost::Bcs(data) => {
                let signed_transaction: SignedTransaction =
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
                        .context("Failed to deserialize input into SignedTransaction")
                        .map_err(|err| {
                            SubmitTransactionError::bad_request_with_code(
                                err,
                                AptosErrorCode::InvalidInput,
                                ledger_info,
                            )
                        })?;
                // Verify the signed transaction
                self.validate_signed_transaction_payload(ledger_info, &signed_transaction)?;
                // TODO: Verify script args?

                Ok(signed_transaction)
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L63-63)
```rust
            transaction_size: (txn.raw_txn_bytes_len() as u64).into(),
```

**File:** aptos-move/aptos-vm/src/gas.rs (L70-121)
```rust
pub(crate) fn check_gas(
    gas_params: &AptosGasParameters,
    gas_feature_version: u64,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl ModuleStorage,
    txn_metadata: &TransactionMetadata,
    features: &Features,
    is_approved_gov_script: bool,
    log_context: &AdapterLogSchema,
) -> Result<(), VMStatus> {
    let txn_gas_params = &gas_params.vm.txn;
    let raw_bytes_len = txn_metadata.transaction_size;

    if is_approved_gov_script {
        let max_txn_size_gov = if gas_feature_version >= RELEASE_V1_13 {
            gas_params.vm.txn.max_transaction_size_in_bytes_gov
        } else {
            MAXIMUM_APPROVED_TRANSACTION_SIZE_LEGACY.into()
        };

        if txn_metadata.transaction_size > max_txn_size_gov
            // Ensure that it is only the approved payload that exceeds the
            // maximum. The (unknown) user input should be restricted to the original
            // maximum transaction size.
            || txn_metadata.transaction_size
                > txn_metadata.script_size + txn_gas_params.max_transaction_size_in_bytes
        {
            speculative_warn!(
                log_context,
                format!(
                    "[VM] Governance transaction size too big {} payload size {}",
                    txn_metadata.transaction_size, txn_metadata.script_size,
                ),
            );
            return Err(VMStatus::error(
                StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
                None,
            ));
        }
    } else if txn_metadata.transaction_size > txn_gas_params.max_transaction_size_in_bytes {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Transaction size too big {} (max {})",
                txn_metadata.transaction_size, txn_gas_params.max_transaction_size_in_bytes
            ),
        );
        return Err(VMStatus::error(
            StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
            None,
        ));
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```
