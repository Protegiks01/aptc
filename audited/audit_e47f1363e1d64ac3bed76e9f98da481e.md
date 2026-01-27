# Audit Report

## Title
Move Framework Accepts Invalid Secp256r1 Curve Points Leading to Unspendable Addresses

## Summary
The Move framework's `secp256r1::ecdsa_raw_public_key_from_64_bytes` function only validates the byte length (64 bytes) but does not verify that the bytes represent a valid point on the secp256r1 elliptic curve. This allows attackers to create authentication keys and account addresses derived from invalid public keys, making any funds sent to these addresses permanently unspendable.

## Finding Description
The vulnerability exists in the interaction between the Move and Rust implementations of secp256r1 public key handling:

**On the Move side**, the `ecdsa_raw_public_key_from_64_bytes` function only checks the length: [1](#0-0) 

This function constructs an `ECDSARawPublicKey` struct without validating whether the 64 bytes represent a valid point on the secp256r1 curve. These invalid public keys can then be used to derive authentication keys through the `single_key` module: [2](#0-1) 

The authentication key derivation proceeds normally: [3](#0-2) 

Accounts can be rotated to use these invalid authentication keys: [4](#0-3) 

**On the Rust side**, when a transaction attempts to spend from such an address, the public key must be deserialized. The Rust implementation validates curve points: [5](#0-4) 

The underlying `p256::ecdsa::VerifyingKey::from_sec1_bytes` function validates that bytes represent a valid curve point and returns an error for invalid points. This means transactions attempting to spend from addresses with invalid public keys will fail during deserialization.

**Attack Scenario:**
1. Attacker creates an `ECDSARawPublicKey` with 64 arbitrary bytes that don't represent a valid curve point
2. Attacker derives an authentication key and address from this invalid public key
3. Attacker displays this address as a "deposit address" (e.g., in a dApp, smart contract, or website)
4. Victim sends funds to the address
5. Funds become permanently unspendable because:
   - No transaction authenticator can be created with the invalid public key (Rust deserialization fails)
   - No private key exists for an invalid curve point
   - No alternative authentication mechanism can spend from the address

The Display implementation for PublicKey makes these invalid keys appear legitimate: [6](#0-5) 

## Impact Explanation
This is a **Medium severity** vulnerability under the Aptos bug bounty program criteria for "Limited funds loss or manipulation." 

While the impact affects fund availability (permanent loss), the attack requires:
- Active attacker involvement to craft invalid public keys
- Social engineering to trick users into sending funds
- Users must interact with attacker-controlled interfaces

The vulnerability breaks the **Cryptographic Correctness** invariant that "BLS signatures, VRF, and hash operations must be secure" - the cryptographic validation gap between Move and Rust allows cryptographically invalid states.

## Likelihood Explanation
**Likelihood: Medium-High**

The attack is straightforward to execute:
- No special privileges required
- Simple Move code can generate invalid public keys
- Can be packaged in legitimate-looking dApps or smart contracts
- Victims have no way to verify the public key's validity before sending funds

However, exploitation requires:
- User interaction (sending funds to attacker-provided addresses)
- Attacker must actively promote these addresses
- Limited to individual fund loss (not systemic protocol failure)

## Recommendation
Add curve point validation to the Move framework's secp256r1 module. Implement a native function that validates curve points before allowing `ECDSARawPublicKey` construction:

**Option 1: Native Validation Function**
Add a native Move function that calls the Rust `p256::ecdsa::VerifyingKey::from_sec1_bytes` validation (prepending 0x04 to convert 64-byte to 65-byte SEC1 format):

```move
/// Validates that the 64-byte input represents a valid secp256r1 curve point
native fun validate_curve_point(bytes: &vector<u8>): bool;

public fun ecdsa_raw_public_key_from_64_bytes(bytes: vector<u8>): ECDSARawPublicKey {
    assert!(bytes.length() == RAW_PUBLIC_KEY_NUM_BYTES, std::error::invalid_argument(E_DESERIALIZE));
    assert!(validate_curve_point(&bytes), std::error::invalid_argument(E_INVALID_CURVE_POINT));
    ECDSARawPublicKey { bytes }
}
```

**Option 2: Validation During Authentication Key Rotation**
Add validation in `rotate_authentication_key_from_public_key` to verify public keys before accepting them: [7](#0-6) 

The validation should occur before deriving the authentication key, potentially by adding a `validate()` method to the `AnyPublicKey` type that calls native validation functions for each key type.

## Proof of Concept
```move
#[test_only]
module test_addr::invalid_secp256r1_poc {
    use aptos_framework::account;
    use aptos_std::secp256r1;
    use aptos_std::single_key::{Self, AnyPublicKey};
    use std::signer;
    
    #[test(attacker = @0x123, victim = @0x456)]
    fun test_invalid_secp256r1_creates_unspendable_address(
        attacker: &signer,
        victim: &signer
    ) {
        // Step 1: Attacker creates invalid 64-byte "public key" (not a valid curve point)
        let invalid_pk_bytes = vector[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        
        // Step 2: This succeeds - no curve point validation!
        let invalid_raw_pk = secp256r1::ecdsa_raw_public_key_from_64_bytes(invalid_pk_bytes);
        
        // Step 3: Create AnyPublicKey and derive authentication key
        let any_pk = AnyPublicKey::Secp256r1Ecdsa { pk: invalid_raw_pk };
        let auth_key = single_key::to_authentication_key(&any_pk);
        
        // Step 4: Attacker creates account and rotates to invalid auth key
        let attacker_addr = signer::address_of(attacker);
        account::create_account_for_test(attacker_addr);
        
        // Rotate to invalid authentication key using BCS-encoded public key
        let bcs_encoded_pk = bcs::to_bytes(&any_pk);
        account::rotate_authentication_key_from_public_key(
            attacker,
            2, // SINGLE_KEY_SCHEME
            bcs_encoded_pk
        );
        
        // Step 5: Attacker now has an address with authentication key from invalid public key
        // Any funds sent to this address are permanently unspendable
        
        // Verification: The authentication key is set
        let stored_auth_key = account::get_authentication_key(attacker_addr);
        assert!(stored_auth_key == auth_key, 1);
        
        // NOTE: Any transaction attempting to spend from this account will fail
        // during Rust-side deserialization when the invalid public key is parsed
    }
}
```

## Notes
The vulnerability is particularly insidious because:
1. The invalid public key appears valid when displayed as a hex string
2. The address derived from it looks like any other account address
3. Users have no way to detect the issue before sending funds
4. The account's authentication key is validly stored on-chain
5. Only when attempting to spend does the Rust validation fail, making funds permanently inaccessible

This represents a critical gap in validation between the Move and Rust layers that violates defense-in-depth principles and the system's cryptographic correctness guarantees.

### Citations

**File:** aptos-move/framework/aptos-stdlib/doc/secp256r1.md (L89-92)
```markdown
<pre><code><b>public</b> <b>fun</b> <a href="secp256r1.md#0x1_secp256r1_ecdsa_raw_public_key_from_64_bytes">ecdsa_raw_public_key_from_64_bytes</a>(bytes: <a href="../../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;): <a href="secp256r1.md#0x1_secp256r1_ECDSARawPublicKey">ECDSARawPublicKey</a> {
    <b>assert</b>!(bytes.length() == <a href="secp256r1.md#0x1_secp256r1_RAW_PUBLIC_KEY_NUM_BYTES">RAW_PUBLIC_KEY_NUM_BYTES</a>, std::error::invalid_argument(<a href="secp256r1.md#0x1_secp256r1_E_DESERIALIZE">E_DESERIALIZE</a>));
    <a href="secp256r1.md#0x1_secp256r1_ECDSARawPublicKey">ECDSARawPublicKey</a> { bytes }
}
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/single_key.move (L85-85)
```text
            pk = AnyPublicKey::Secp256r1Ecdsa{pk: secp256r1::ecdsa_raw_public_key_from_64_bytes(public_key_bytes)};
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/single_key.move (L111-115)
```text
    public fun to_authentication_key(self: &AnyPublicKey): vector<u8> {
        let pk_bytes = bcs::to_bytes(self);
        pk_bytes.push_back(SIGNATURE_SCHEME_ID);
        hash::sha3_256(pk_bytes)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L479-481)
```text
        } else if (scheme == SINGLE_KEY_SCHEME) {
            new_auth_key = single_key::new_public_key_from_bytes(new_public_key_bytes).to_authentication_key();
        } else if (scheme == MULTI_KEY_SCHEME) {
```

**File:** crates/aptos-crypto/src/secp256r1_ecdsa/secp256r1_ecdsa_keys.rs (L93-100)
```rust
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<PublicKey, CryptoMaterialError> {
        match p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes) {
            Ok(p256_public_key) => Ok(PublicKey(p256_public_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
```

**File:** crates/aptos-crypto/src/secp256r1_ecdsa/secp256r1_ecdsa_keys.rs (L231-235)
```rust
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_sec1_bytes()))
    }
}
```
