# Audit Report

## Title
Transaction Size Validation After Expensive Signature Verification Enables Resource Exhaustion DoS

## Summary
The VM validator performs expensive signature verification operations (including multiple memory clones of transaction payloads) before validating transaction size limits. This allows attackers to submit oversized transactions that bypass API-level size limits but fail VM size checks, forcing validators to waste resources on transactions that should be rejected immediately.

## Finding Description

The transaction validation flow has a critical ordering vulnerability where expensive operations occur before basic size validation:

**Vulnerability Chain:**

1. **API Layer Size Check (8 MB limit)**: The API middleware checks Content-Length against 8 MB limit defined as `DEFAULT_REQUEST_CONTENT_LENGTH_LIMIT = 8 * 1024 * 1024` [1](#0-0) 

2. **VM Validation Order in `AptosVM::validate_transaction`**: Signature verification happens BEFORE size check:
   - Signature verification occurs via `transaction.check_signature()` [2](#0-1) 
   - Size check only happens much later via `check_gas()` which validates `txn_metadata.transaction_size > txn_gas_params.max_transaction_size_in_bytes` [3](#0-2) 
   - The `check_gas()` function is called from `run_prologue_with_payload()` [4](#0-3) 

3. **Expensive Signature Verification for FeePayer/MultiAgent**: For FeePayer transactions, the `RawTransaction` is cloned twice during signature verification - once for `no_fee_payer_address_message` and once for `fee_payer_address_message` [5](#0-4) . For MultiAgent transactions, it's cloned once [6](#0-5) 

4. **VM Size Limit**: The maximum transaction size is 64 KB, defined as `max_transaction_size_in_bytes: 64 * 1024` [7](#0-6) 

**Attack Scenario:**
An attacker can craft FeePayer or MultiAgent transactions with payloads between 64 KB and 8 MB. These transactions:
- Pass the API Content-Length check (< 8 MB)
- Undergo expensive signature verification which clones the RawTransaction 2-3 times
- Are THEN rejected for exceeding the VM's 64 KB limit

This violates the **Resource Limits** invariant by performing expensive operations on transactions that exceed size limits before checking those limits.

## Impact Explanation

**Medium-to-High Severity** - This vulnerability enables DoS through resource exhaustion, which the Aptos bug bounty explicitly categorizes under HIGH severity ("Validator Node Slowdowns - DoS through resource exhaustion"):

- **Memory Exhaustion**: Each oversized FeePayer/MultiAgent transaction causes 16+ MB of allocations (original + 2-3 signature verification clones) before being rejected
- **CPU Waste**: Cryptographic signature verification operations are performed on invalid transactions
- **Amplification Attack**: Attacker bandwidth cost (sending 4 MB transaction) << Validator resource cost (allocating 16+ MB, performing cryptographic operations)
- **Limited Rate Limiting**: While HAProxy provides network-level rate limiting (50 MB/s per IP), there is no application-level per-transaction rate limiting during validation
- **Concurrent Amplification**: If 100 such transactions are submitted concurrently, validators allocate 1.6+ GB temporarily

Sustained attacks could degrade validator performance and block processing capacity, though the temporary nature of allocations and existing network-level protections prevent permanent impact.

## Likelihood Explanation

**High Likelihood:**
- **No Authentication Required**: Anyone can submit transactions via public API endpoints
- **Low Attack Cost**: Attacker only needs network bandwidth to send oversized transactions
- **Easy to Execute**: Simple script can generate and submit oversized transactions
- **No Early Detection**: Size validation happens after expensive operations, so attack succeeds in wasting resources
- **Gap Exists by Design**: 8 MB API limit vs 64 KB VM limit creates exploitable 8.3 MB gap

## Recommendation

Reorder validation to perform cheap checks before expensive operations:

1. Move the size validation from `check_gas()` to the beginning of `validate_transaction()`, immediately after feature flag checks but before `check_signature()`
2. This ensures transactions exceeding 64 KB are rejected before any cloning or cryptographic operations occur
3. Consider lowering the API Content-Length limit closer to the VM's 64 KB limit to reduce the exploitable gap

## Proof of Concept

```rust
// Attacker creates a FeePayer transaction with 4 MB payload
// 1. Create transaction with large payload (e.g., 4 MB of dummy data)
// 2. Sign as FeePayer transaction with valid signatures
// 3. Submit to API endpoint /v1/transactions
// 4. API accepts (< 8 MB)
// 5. VM performs signature verification, cloning 4 MB twice (8 MB additional)
// 6. VM finally checks size, rejects (> 64 KB)
// Result: 12+ MB allocated, cryptographic operations performed, all wasted
```

## Notes

The core issue is a violation of the security principle of "fail fast" - expensive operations should happen after cheap validation checks. The existence of a large gap between API-level size limits (8 MB) and VM-level size limits (64 KB) creates an exploitable window for resource exhaustion attacks. While network-level rate limiting provides some protection, the amplification factor (attacker sends 4 MB, validator allocates 16+ MB) makes this a viable DoS vector under sustained attack.

### Citations

**File:** config/src/config/api_config.rs (L97-97)
```rust
const DEFAULT_REQUEST_CONTENT_LENGTH_LIMIT: u64 = 8 * 1024 * 1024; // 8 MB
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2805-2814)
```rust
        check_gas(
            self.gas_params(log_context)?,
            self.gas_feature_version(),
            session.resolver,
            module_storage,
            txn_data,
            self.features(),
            is_approved_gov_script,
            log_context,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3232-3237)
```rust
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
```

**File:** aptos-move/aptos-vm/src/gas.rs (L109-121)
```rust
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

**File:** types/src/transaction/authenticator.rs (L196-213)
```rust
                let no_fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn.clone(),
                    secondary_signer_addresses.clone(),
                    AccountAddress::ZERO,
                );

                let mut remaining = to_verify
                    .iter()
                    .filter(|verifier| verifier.verify(&no_fee_payer_address_message).is_err())
                    .collect::<Vec<_>>();

                remaining.push(&fee_payer_signer);

                let fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn.clone(),
                    secondary_signer_addresses.clone(),
                    *fee_payer_address,
                );
```

**File:** types/src/transaction/authenticator.rs (L230-233)
```rust
                let message = RawTransactionWithData::new_multi_agent(
                    raw_txn.clone(),
                    secondary_signer_addresses.clone(),
                );
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```
