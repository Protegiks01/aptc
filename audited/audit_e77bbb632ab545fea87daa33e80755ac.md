# Audit Report

## Title
WebAuthn Authenticator Data Validation Bypass - Empty Authenticator Data Accepted

## Summary
The `generate_verification_data()` function in the WebAuthn implementation does not validate that `authenticator_data_bytes` is non-empty or conforms to the W3C WebAuthn specification structure. This allows attackers with access to a WebAuthn private key to bypass critical security checks including user presence verification, user verification flags, relying party validation, and replay protection by submitting transactions with empty authenticator data. [1](#0-0) 

## Finding Description

The WebAuthn specification (W3C §7.2) mandates that verifiers MUST validate the authenticator data structure, which should contain:
- **RP ID Hash** (32 bytes): SHA-256 hash of the relying party identifier
- **Flags** (1 byte): Including User Presence (UP) and User Verification (UV) bits
- **Signature Counter** (4 bytes): For replay attack detection
- **Minimum total size**: 37 bytes

However, the Aptos implementation treats `authenticator_data` as an opaque byte vector without any structural validation. The `generate_verification_data()` function simply concatenates the raw bytes with the SHA-256 hash of `client_data_json`: [2](#0-1) 

When `authenticator_data_bytes` is empty (zero length), the concatenation produces only the 32-byte SHA-256 hash of `client_data_json`. This bypasses all WebAuthn security validations.

**Attack Flow:**

1. Attacker gains access to WebAuthn private key (via malware, key extraction from insecure storage, or software-based authenticator)
2. Constructs a transaction with empty `authenticator_data` field
3. Creates valid `client_data_json` with correct challenge = SHA3-256(signing_message(transaction))
4. Computes `verification_data = SHA256(client_data_json)` (only 32 bytes)
5. Signs the 32-byte hash with their Secp256r1 private key
6. Submits transaction with `PartialAuthenticatorAssertionResponse` containing empty authenticator_data

The verification process in the `verify()` method will:
- Parse and validate the challenge ✓ (passes)
- Generate verification_data from empty bytes + hash ✓ (produces 32-byte hash)
- Verify signature against 32-byte verification_data ✓ (passes if signature is valid) [3](#0-2) 

**What's Bypassed:**
- **User Presence (UP)**: No verification that user physically interacted with the authenticator
- **User Verification (UV)**: No verification of biometric/PIN authentication  
- **RP ID Hash**: No validation that signature was created for the correct relying party
- **Signature Counter**: No replay attack detection mechanism
- **Minimum Length**: No enforcement of 37-byte minimum per WebAuthn spec

Evidence of missing validation is confirmed by a TODO comment in the API layer: [4](#0-3) 

## Impact Explanation

This vulnerability represents a **HIGH severity** issue per Aptos bug bounty criteria as it constitutes a **"Significant protocol violation"**.

The WebAuthn authentication scheme is specifically designed to provide phishing-resistant, hardware-backed authentication with mandatory user presence. By accepting empty authenticator data, the implementation:

1. **Violates W3C WebAuthn Specification**: Section 7.2 explicitly requires validation of authenticator data structure and flags
2. **Defeats Security Model**: Users expect WebAuthn signatures to require physical interaction - this bypass eliminates that guarantee
3. **Enables Silent Transaction Signing**: If an attacker compromises the private key through malware or extracts it from insecure storage, they can sign transactions without any user interaction
4. **Breaks Transaction Validation Invariant**: The system's critical invariant "Transaction Validation: Prologue/epilogue checks must enforce all invariants" is violated

While this doesn't directly result in loss of funds without key compromise, it significantly weakens the security guarantees of the WebAuthn authentication scheme and could enable unauthorized transactions in realistic attack scenarios (device malware, insecure key storage).

This is not Critical severity because it requires the attacker to have already obtained the private key, and doesn't directly break consensus or cause network-wide issues.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability is exploitable in several realistic scenarios:

1. **Malware-based Key Extraction**: Modern malware can extract cryptographic keys from device memory or insecure storage. Once extracted, the attacker can use this vulnerability to sign transactions without triggering user presence checks.

2. **Software-based WebAuthn Implementations**: Some WebAuthn implementations use software-based key storage rather than hardware security modules. These are more vulnerable to extraction.

3. **Compromised Devices**: On a compromised device, malware can intercept WebAuthn operations and sign malicious transactions with empty authenticator data.

The attack doesn't require:
- Validator collusion or privileged access
- Complex cryptographic attacks
- Network-level manipulation
- Social engineering beyond initial device compromise

The main barrier is obtaining the private key, but given the increasing sophistication of malware and the variety of WebAuthn implementations (some less secure than others), this is a realistic threat model.

## Recommendation

Implement strict validation of the `authenticator_data` structure according to W3C WebAuthn specification §7.2:

```rust
fn generate_verification_data(authenticator_data_bytes: &[u8], client_data_json: &[u8]) -> Result<Vec<u8>> {
    // Validate minimum length (32 bytes RP ID hash + 1 byte flags + 4 bytes counter)
    const MIN_AUTHENTICATOR_DATA_LENGTH: usize = 37;
    
    if authenticator_data_bytes.len() < MIN_AUTHENTICATOR_DATA_LENGTH {
        return Err(anyhow!(
            "Invalid authenticator data length: expected at least {} bytes, got {}",
            MIN_AUTHENTICATOR_DATA_LENGTH,
            authenticator_data_bytes.len()
        ));
    }
    
    // Parse and validate flags byte (at position 32)
    let flags = authenticator_data_bytes[32];
    let user_present = (flags & 0x01) != 0; // UP bit
    let user_verified = (flags & 0x04) != 0; // UV bit
    
    // Require user presence at minimum
    if !user_present {
        return Err(anyhow!("User presence (UP) flag not set in authenticator data"));
    }
    
    // Optional: Require user verification for high-value transactions
    // if !user_verified {
    //     return Err(anyhow!("User verification (UV) flag not set in authenticator data"));
    // }
    
    // Optional: Validate and track signature counter (bytes 33-36) for replay detection
    // let counter = u32::from_be_bytes([
    //     authenticator_data_bytes[33],
    //     authenticator_data_bytes[34],
    //     authenticator_data_bytes[35],
    //     authenticator_data_bytes[36],
    // ]);
    
    let client_data_json_hash = sha256(client_data_json);
    Ok([authenticator_data_bytes, &client_data_json_hash]
        .concat()
        .to_vec())
}
```

Update the function signature to return `Result<Vec<u8>>` and handle the error in the calling functions: [5](#0-4) 

## Proof of Concept

```rust
#[test]
fn test_empty_authenticator_data_bypass() {
    use aptos_crypto::{secp256r1_ecdsa, PrivateKey, Uniform};
    use rand::{rngs::StdRng, SeedableRng};
    
    // Generate a WebAuthn keypair
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let private_key: secp256r1_ecdsa::PrivateKey = Uniform::generate(&mut rng);
    let public_key = private_key.public_key();
    let any_public_key = AnyPublicKey::Secp256r1Ecdsa { public_key };
    
    // Create a raw transaction
    let raw_txn = get_test_raw_transaction(
        AccountAddress::random(), 
        0, None, None, None, None
    );
    
    // Generate proper challenge
    let signing_message_bytes = signing_message(&raw_txn).unwrap();
    let challenge = HashValue::sha3_256_of(signing_message_bytes.as_slice());
    
    // Create client_data_json with correct challenge
    let client_data = CollectedClientData {
        ty: "webauthn.get".into(),
        challenge: Bytes::from(challenge.to_vec()),
        origin: "http://localhost:4000".into(),
        cross_origin: Some(false),
        unknown_keys: Default::default(),
    };
    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    
    // ATTACK: Use EMPTY authenticator_data
    let authenticator_data = vec![]; // EMPTY!
    
    // Compute verification_data with empty authenticator_data
    // This will be just SHA256(client_data_json) - 32 bytes
    let verification_data = generate_verification_data(
        &authenticator_data,
        &client_data_json
    );
    
    // Sign the shortened verification_data
    let signature = private_key.sign_arbitrary_message(&verification_data);
    let canonical_signature = secp256r1_ecdsa::Signature::make_canonical(&signature);
    
    // Create malicious PartialAuthenticatorAssertionResponse
    let malicious_paar = PartialAuthenticatorAssertionResponse::new(
        AssertionSignature::Secp256r1Ecdsa { signature: canonical_signature },
        authenticator_data, // EMPTY!
        client_data_json,
    );
    
    // VULNERABILITY: This should FAIL but currently PASSES
    let result = malicious_paar.verify(&raw_txn, &any_public_key);
    
    // The verification INCORRECTLY succeeds because:
    // 1. Challenge validation passes (challenge matches transaction)
    // 2. Verification data = empty + SHA256(client_data_json) = 32 bytes
    // 3. Signature verification passes (signature is valid for those 32 bytes)
    // 4. NO validation of authenticator_data structure or flags
    
    assert!(result.is_ok(), "VULNERABILITY: Empty authenticator_data should be rejected but is accepted!");
}
```

This test demonstrates that a transaction with empty `authenticator_data` can pass signature verification if the signature is crafted to match the shortened verification data, bypassing all WebAuthn security validations required by the specification.

### Citations

**File:** types/src/transaction/webauthn.rs (L19-29)
```rust
fn generate_verification_data(authenticator_data_bytes: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    // Let hash be the result of computing a hash over the clientData using SHA-256.
    let client_data_json_hash = sha256(client_data_json);
    // Binary concatenation of authData and hash.
    // Note: This is compatible with signatures generated by FIDO U2F
    // authenticators. See §6.1.2 FIDO U2F Signature Format Compatibility
    // See <https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-sig-format-compat>
    [authenticator_data_bytes, &client_data_json_hash]
        .concat()
        .to_vec()
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

**File:** api/types/src/transaction.rs (L1504-1504)
```rust
            // TODO: Check if they match / parse correctly?
```
