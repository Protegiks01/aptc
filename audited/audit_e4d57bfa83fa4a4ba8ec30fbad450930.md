# Audit Report

## Title
WebAuthn Signature Validation DoS via Unbounded JSON Parsing Before Transaction Size Check

## Summary
The `client_data_json` field in `PartialAuthenticatorAssertionResponse` is an unbounded `Vec<u8>` that undergoes JSON parsing during signature verification, which occurs **before** transaction size validation. An attacker can submit transactions with multi-megabyte JSON payloads (up to ~8 MB) that will be parsed by `serde_json`, causing CPU exhaustion and memory allocation before the transaction is rejected by the 64 KB size limit. [1](#0-0) 

## Finding Description

The vulnerability exists in the transaction validation flow where signature verification happens before gas and size checks:

**Step 1: Unbounded field definition**
The `client_data_json` field is defined as an unbounded `Vec<u8>` with no size constraints: [2](#0-1) 

**Step 2: JSON parsing during signature verification**
During verification, this field is parsed using `serde_json::from_slice()` without any size limits: [3](#0-2) 

**Step 3: Signature verification happens BEFORE size validation**
In the transaction validation flow, `check_signature()` is called first: [4](#0-3) 

**Step 4: Transaction size check happens LATER in check_gas()**
The transaction size limit (64 KB) is only enforced later during gas checking: [5](#0-4) [6](#0-5) 

**Step 5: Size check called after signature verification**
The `check_gas()` function is only invoked within `run_prologue_with_payload()`, which is called **after** authentication: [7](#0-6) 

**Attack Path:**
1. Attacker crafts a WebAuthn transaction with a 7 MB `client_data_json` field containing deeply nested or malformed JSON
2. Transaction passes the 8 MB HTTP content length limit: [8](#0-7) 

3. Transaction is BCS deserialized (only depth limit of 16, no byte size limit): [9](#0-8) [10](#0-9) 

4. `check_signature()` calls WebAuthn verification which parses the 7 MB JSON
5. JSON parsing consumes significant CPU/memory before transaction is rejected
6. Only after signature verification completes does `check_gas()` reject the transaction for exceeding 64 KB

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Each malicious transaction forces expensive JSON parsing (potentially parsing megabytes of deeply nested or malformed JSON) in the critical signature verification path
- **API crashes**: If multiple such transactions are submitted concurrently, memory exhaustion could crash API nodes
- **DoS amplification**: Minimal attacker cost (transaction submission) causes disproportionate validator resource consumption

The vulnerability affects the transaction validation critical path that all validators must execute. The constant `MAX_WEBAUTHN_SIGNATURE_BYTES = 1024` exists but is only used in API validation, not enforced in core types: [11](#0-10) 

## Likelihood Explanation

**High likelihood:**
- **No authentication required**: Any user can submit transactions via public API
- **Easy to exploit**: Simply construct a WebAuthn signature with large JSON payload
- **No special knowledge needed**: Standard HTTP/JSON knowledge sufficient
- **Low cost to attacker**: Transaction submission is cheap
- **High impact per attempt**: Each malicious transaction causes expensive parsing

## Recommendation

Enforce size limits on `client_data_json` **before** JSON parsing during signature verification:

```rust
// In types/src/transaction/webauthn.rs, modify the verify method:

pub fn verify<T: Serialize + CryptoHash>(
    &self,
    message: &T,
    public_key: &AnyPublicKey,
) -> Result<()> {
    // SECURITY: Enforce size limit before JSON parsing
    if self.client_data_json.len() > MAX_WEBAUTHN_SIGNATURE_BYTES {
        return Err(anyhow!(
            "client_data_json exceeds maximum size of {} bytes",
            MAX_WEBAUTHN_SIGNATURE_BYTES
        ));
    }
    
    let collected_client_data: CollectedClientData =
        serde_json::from_slice(self.client_data_json.as_slice())?;
    // ... rest of verification
}
```

Additionally, enforce this limit during BCS deserialization by implementing custom `Deserialize` logic:

```rust
impl<'de> serde::Deserialize<'de> for PartialAuthenticatorAssertionResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize with size validation
        let response = PartialAuthenticatorAssertionResponseHelper::deserialize(deserializer)?;
        
        // Validate sizes before returning
        if response.client_data_json.len() > MAX_WEBAUTHN_SIGNATURE_BYTES {
            return Err(serde::de::Error::custom("client_data_json too large"));
        }
        
        Ok(response)
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod dos_tests {
    use super::*;
    use crate::transaction::authenticator::AnyPublicKey;
    use aptos_crypto::secp256r1_ecdsa;

    #[test]
    fn test_webauthn_large_json_dos() {
        // Create a large client_data_json (7 MB)
        let large_json = vec![b'{'; 7 * 1024 * 1024];
        
        // Create a dummy signature and authenticator_data
        let signature = AssertionSignature::Secp256r1Ecdsa {
            signature: secp256r1_ecdsa::Signature::from_bytes_unchecked(&[0u8; 64]).unwrap(),
        };
        let authenticator_data = vec![0u8; 37];
        
        // Create WebAuthn response with large JSON
        let paar = PartialAuthenticatorAssertionResponse::new(
            signature,
            authenticator_data,
            large_json,
        );
        
        // Serialize to BCS (this succeeds, creating a multi-MB transaction)
        let serialized = paar.to_bytes();
        assert!(serialized.len() > 64 * 1024); // Exceeds 64 KB limit
        
        // Create a dummy transaction and public key
        let raw_txn = get_test_raw_transaction(
            AccountAddress::random(),
            0,
            None,
            None,
            None,
            None,
        );
        let public_key = AnyPublicKey::Secp256r1Ecdsa {
            public_key: secp256r1_ecdsa::PrivateKey::generate_for_testing().public_key(),
        };
        
        // This will attempt to parse the 7 MB JSON during verification
        // BEFORE transaction size checks, causing DoS
        let start = std::time::Instant::now();
        let result = paar.verify(&raw_txn, &public_key);
        let duration = start.elapsed();
        
        // Verification will fail, but only AFTER expensive JSON parsing
        assert!(result.is_err());
        println!("JSON parsing took: {:?}", duration);
        
        // This demonstrates that a multi-MB JSON is parsed before
        // the transaction size limit rejects it
    }
}
```

**Notes:**
- This PoC demonstrates that the BCS serialization accepts the large payload
- The `verify()` method will attempt to parse the JSON before any size validation
- In a real attack, the JSON could be crafted to maximize parsing time (deeply nested structures)
- The transaction would only be rejected by `check_gas()` after signature verification completes

### Citations

**File:** types/src/transaction/webauthn.rs (L12-12)
```rust
pub const MAX_WEBAUTHN_SIGNATURE_BYTES: usize = 1024;
```

**File:** types/src/transaction/webauthn.rs (L91-95)
```rust
    /// This attribute contains the JSON byte serialization of [`CollectedClientData`](CollectedClientData) passed to the
    /// authenticator by the client in order to generate this credential. The exact JSON serialization
    /// MUST be preserved, as the hash of the serialized client data has been computed over it.
    #[serde(with = "serde_bytes")]
    client_data_json: Vec<u8>,
```

**File:** types/src/transaction/webauthn.rs (L134-145)
```rust
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        message: &T,
        public_key: &AnyPublicKey,
    ) -> Result<()> {
        let collected_client_data: CollectedClientData =
            serde_json::from_slice(self.client_data_json.as_slice())?;
        let challenge_bytes = Bytes::try_from(collected_client_data.challenge.as_str())
            .map_err(|e| anyhow!("Failed to decode challenge bytes {:?}", e))?;

        // Check if expected challenge and actual challenge match. If there's no match, throw error
        verify_expected_challenge_from_message_matches_actual(message, challenge_bytes.as_slice())?;
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
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

**File:** config/src/config/api_config.rs (L97-97)
```rust
const DEFAULT_REQUEST_CONTENT_LENGTH_LIMIT: u64 = 8 * 1024 * 1024; // 8 MB
```

**File:** api/src/transactions.rs (L851-851)
```rust
    const MAX_SIGNED_TRANSACTION_DEPTH: usize = 16;
```

**File:** api/src/transactions.rs (L1223-1232)
```rust
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
```
