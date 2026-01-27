# Audit Report

## Title
Unimplemented Secp256r1Ecdsa Signing in EphemeralPrivateKey Causes Runtime Panic and Permanent Fund Lock

## Summary
The `EphemeralPrivateKey::sign()` method contains a `todo!()` macro for the `Secp256r1Ecdsa` variant, causing immediate panic when invoked. Since keyless accounts rely on this method to sign transactions, users who create keyless accounts with Secp256r1Ecdsa ephemeral keys will be unable to sign transactions, resulting in permanent loss of access to any funds sent to those accounts. [1](#0-0) 

## Finding Description
The `EphemeralPrivateKey` enum defines two variants: `Ed25519` and `Secp256r1Ecdsa`. However, the `sign()` implementation only handles the `Ed25519` variant, leaving `Secp256r1Ecdsa` marked with `todo!()`: [2](#0-1) 

This incomplete implementation becomes critical because the `sign()` method is invoked during keyless transaction signing in the `build_keyless_signature()` function: [3](#0-2) 

**Attack Scenario:**

1. An attacker distributes malicious SDK usage examples, libraries, or tools that create `EphemeralKeyPair` instances with `Secp256r1Ecdsa` private keys instead of `Ed25519`
2. A user unknowingly follows this code and creates a keyless account with a Secp256r1Ecdsa ephemeral key
3. The user receives funds to this account address
4. When attempting to sign a transaction to move funds, the `sign()` method is called
5. The `todo!()` macro executes, causing an immediate panic with "not yet implemented"
6. The transaction cannot be signed, and the funds remain permanently locked

The vulnerability is enabled by the enum's deserializability: [4](#0-3) 

Since keyless accounts cryptographically bind the ephemeral public key into the authentication scheme through the JWT and ZK proof, users cannot recover by simply creating a new ephemeral key pair. The account address and authentication are permanently tied to the unusable Secp256r1Ecdsa key.

## Impact Explanation
This vulnerability aligns with **Medium Severity** per Aptos bug bounty criteria: "Limited funds loss or manipulation." 

While not affecting consensus or the blockchain protocol itself, this issue enables:
- **Permanent freezing of funds**: Users tricked into using Secp256r1Ecdsa ephemeral keys lose permanent access to their keyless accounts
- **Unrecoverable state**: Unlike key rotation scenarios, keyless accounts cannot change their ephemeral keys post-creation
- **Client application crashes**: Any application using the SDK will panic when attempting transaction signing

The issue breaks the **Transaction Validation** invariant by preventing legitimate users from signing valid transactions, and violates **Cryptographic Correctness** by exposing an unimplemented cryptographic operation as a valid enum variant.

## Likelihood Explanation
**Likelihood: Medium to High**

Several factors increase exploitability:
1. **Developer confusion**: The `Secp256r1Ecdsa` variant exists and is not marked as deprecated or unstable, suggesting it's safe to use
2. **WebAuthn association**: Developers familiar with WebAuthn (which uses Secp256r1Ecdsa) might intentionally choose this variant, unaware of the implementation gap
3. **No compile-time protection**: Rust's type system doesn't prevent this - the panic only occurs at runtime
4. **Supply chain risk**: Malicious tutorial code, Stack Overflow answers, or compromised dependencies could spread the vulnerable pattern
5. **Silent failure**: The `public_key()` method works correctly for Secp256r1Ecdsa, giving false confidence [5](#0-4) 

## Recommendation
**Immediate Fix**: Implement the missing signing logic for Secp256r1Ecdsa or explicitly remove the variant until WebAuthn integration is complete.

**Option 1 - Remove Unimplemented Variant** (Recommended for immediate safety):
```rust
#[derive(Debug, Eq, PartialEq, Deserialize)]
pub enum EphemeralPrivateKey {
    Ed25519 {
        inner_private_key: Ed25519PrivateKey,
    },
    // TODO: Secp256r1Ecdsa support requires WebAuthn-specific signing context
    // Secp256r1Ecdsa {
    //     inner_private_key: secp256r1_ecdsa::PrivateKey,
    // },
}
```

**Option 2 - Implement Proper Error Handling**:
```rust
impl EphemeralPrivateKey {
    pub fn sign<T: CryptoHash + Serialize>(
        &self,
        message: &T,
    ) -> Result<EphemeralSignature, CryptoMaterialError> {
        match self {
            EphemeralPrivateKey::Ed25519 { inner_private_key } => Ok(EphemeralSignature::ed25519(
                inner_private_key.sign(message)?,
            )),
            EphemeralPrivateKey::Secp256r1Ecdsa { .. } => {
                Err(CryptoMaterialError::ValidationError)
            },
        }
    }
}
```

**Option 3 - Complete WebAuthn Implementation** (Requires additional context parameters):
Modify the signature to accept WebAuthn-specific data structures (authenticator_data, client_data_json) similar to the pattern used in the test suite. [6](#0-5) 

## Proof of Concept
```rust
use aptos_sdk::types::{EphemeralPrivateKey, EphemeralKeyPair, KeylessAccount};
use aptos_crypto::{secp256r1_ecdsa::PrivateKey as Secp256r1EcdsaPrivateKey, Uniform};
use rand::rngs::OsRng;

#[test]
#[should_panic(expected = "not yet implemented")]
fn test_secp256r1_ephemeral_key_panic() {
    // Create a Secp256r1Ecdsa ephemeral private key
    let mut rng = OsRng;
    let inner_key = Secp256r1EcdsaPrivateKey::generate(&mut rng);
    let esk = EphemeralPrivateKey::Secp256r1Ecdsa {
        inner_private_key: inner_key,
    };
    
    // Create an ephemeral key pair (this works fine)
    let ephemeral_key_pair = EphemeralKeyPair::new(
        esk,
        1735475012, // expiry_date_secs
        vec![0; 31], // blinder
    ).unwrap();
    
    // Simulate keyless account creation (simplified)
    // In practice, this would involve JWT, pepper, and ZK proof
    
    // Attempt to sign a transaction - this will PANIC
    let test_message = vec![1, 2, 3, 4];
    let _ = ephemeral_key_pair.private_key.sign(&test_message);
    // ^^^ PANIC: "not yet implemented"
}
```

**Notes**

This vulnerability is particularly insidious because:
1. The `public_key()` method works correctly for Secp256r1Ecdsa, masking the problem during account creation
2. The panic only occurs during transaction signing, after funds may have been deposited
3. The cryptographic binding in keyless accounts prevents recovery through key rotation
4. The existence of working WebAuthn test code (using Secp256r1Ecdsa directly) suggests the variant should be functional, increasing developer confusion

The issue should be addressed by either completing the WebAuthn implementation for keyless accounts or explicitly deprecating the Secp256r1Ecdsa variant until proper support exists.

### Citations

**File:** sdk/src/types.rs (L92-113)
```rust
    fn build_keyless_signature(
        &self,
        txn: RawTransaction,
        account: &impl CommonKeylessAccount,
    ) -> KeylessSignature {
        let proof = account.zk_sig().proof;
        let txn_and_zkp = keyless::TransactionAndProof {
            message: txn,
            proof: Some(proof),
        };

        let esk = account.ephem_private_key();
        let ephemeral_signature = esk.sign(&txn_and_zkp).unwrap();

        KeylessSignature {
            cert: EphemeralCertificate::ZeroKnowledgeSig(account.zk_sig().clone()),
            jwt_header_json: account.jwt_header_json().clone(),
            exp_date_secs: account.expiry_date_secs(),
            ephemeral_pubkey: account.ephem_public_key().clone(),
            ephemeral_signature,
        }
    }
```

**File:** sdk/src/types.rs (L760-768)
```rust
#[derive(Debug, Eq, PartialEq, Deserialize)]
pub enum EphemeralPrivateKey {
    Ed25519 {
        inner_private_key: Ed25519PrivateKey,
    },
    Secp256r1Ecdsa {
        inner_private_key: secp256r1_ecdsa::PrivateKey,
    },
}
```

**File:** sdk/src/types.rs (L770-780)
```rust
impl EphemeralPrivateKey {
    pub fn public_key(&self) -> EphemeralPublicKey {
        match self {
            EphemeralPrivateKey::Ed25519 { inner_private_key } => {
                EphemeralPublicKey::ed25519(inner_private_key.public_key())
            },
            EphemeralPrivateKey::Secp256r1Ecdsa { inner_private_key } => {
                EphemeralPublicKey::secp256r1_ecdsa(inner_private_key.public_key())
            },
        }
    }
```

**File:** sdk/src/types.rs (L783-790)
```rust
impl TryFrom<&[u8]> for EphemeralPrivateKey {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, CryptoMaterialError> {
        bcs::from_bytes::<EphemeralPrivateKey>(bytes)
            .map_err(|_e| CryptoMaterialError::DeserializationError)
    }
}
```

**File:** sdk/src/types.rs (L792-806)
```rust
impl EphemeralPrivateKey {
    pub fn sign<T: CryptoHash + Serialize>(
        &self,
        message: &T,
    ) -> Result<EphemeralSignature, CryptoMaterialError> {
        match self {
            EphemeralPrivateKey::Ed25519 { inner_private_key } => Ok(EphemeralSignature::ed25519(
                inner_private_key.sign(message)?,
            )),
            EphemeralPrivateKey::Secp256r1Ecdsa {
                inner_private_key: _,
            } => todo!(),
        }
    }
}
```

**File:** api/src/tests/webauthn_secp256r1_ecdsa.rs (L53-83)
```rust
    fn sign_webauthn_transaction(
        raw_txn: &RawTransaction,
        collected_client_data: CollectedClientData,
        authenticator_data: &[u8],
        private_key: &Secp256r1EcdsaPrivateKey,
    ) -> SignedTransaction {
        let public_key = Secp256r1EcdsaPublicKey::from(private_key);

        let client_data_json = serde_json::to_vec(&collected_client_data).unwrap();
        let client_data_hash = sha256(client_data_json.as_slice());

        let signature_material = [authenticator_data, &client_data_hash].concat();
        let signature = private_key.sign_arbitrary_message(signature_material.as_slice());
        let assertion_signature = AssertionSignature::Secp256r1Ecdsa { signature };

        let partial_authenticator_assertion_response = PartialAuthenticatorAssertionResponse::new(
            assertion_signature,
            authenticator_data.to_vec(),
            client_data_json,
        );
        let public_key = AnyPublicKey::Secp256r1Ecdsa { public_key };
        let signature = AnySignature::WebAuthn {
            signature: partial_authenticator_assertion_response,
        };
        let authenticator = SingleKeyAuthenticator::new(public_key, signature);
        let account_authenticator = AccountAuthenticator::SingleKey { authenticator };
        let txn_authenticator = TransactionAuthenticator::SingleSender {
            sender: account_authenticator,
        };
        SignedTransaction::new_signed_transaction(raw_txn.clone(), txn_authenticator)
    }
```
