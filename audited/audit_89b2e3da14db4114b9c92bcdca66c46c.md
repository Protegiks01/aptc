# Audit Report

## Title
Faucet Accepts Small-Order Ed25519 Public Keys Leading to Permanent Fund Locking

## Summary
The faucet's `FundRequest::receiver()` function accepts Ed25519 public keys without validating they are not in a small subgroup. When an attacker provides a small-order public key (one of 8 torsion points on Curve25519), the faucet creates and funds an account at the derived address, but these funds become permanently locked because all subsequent transaction signatures will fail strict validation checks enforced throughout the Aptos framework.

## Finding Description

The vulnerability exists in the faucet's public key handling: [1](#0-0) 

When a user provides a `pub_key` field, the faucet parses it using `Ed25519PublicKey::from_encoded_string()`, which internally calls `try_from()`: [2](#0-1) 

This function decodes the hex string and calls `Ed25519PublicKey::try_from()`: [3](#0-2) 

The implementation explicitly does NOT check for small subgroup membership: [4](#0-3) 

The authentication key is then derived deterministically: [5](#0-4) [6](#0-5) 

However, when attempting to use this account, ALL signature verifications in Aptos enforce strict validation that explicitly checks for small subgroups: [7](#0-6) 

The native Move implementation confirms this protection: [8](#0-7) 

**Attack Path:**
1. Attacker generates a hex-encoded small-order point (from the 8-torsion subgroup of Curve25519)
2. Attacker calls the faucet API with `pub_key` set to this malicious value
3. Faucet accepts the key, derives authentication key via SHA3-256(pk_bytes || 0x00)
4. Faucet creates and funds an account at the derived address
5. No valid transaction can ever be submitted from this account because:
   - Small-order points cannot generate valid EdDSA signatures
   - Even if crafted, `verify_strict()` explicitly rejects keys in small subgroups (line 80: `!point.is_small_order()`)
6. Funds are permanently locked, requiring a hardfork to recover

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria, specifically "Permanent freezing of funds (requires hardfork)" which is listed under Critical, but the limited scope (faucet funds only, not user funds) reduces it to Medium severity for "Limited funds loss or manipulation."

Each successful attack permanently locks the amount the faucet transfers (typically small amounts for testnet/devnet, but could be significant on mainnet faucets). The attacker can repeat this attack up to 8 times (one for each torsion point), though the faucet checks prevent funding existing accounts: [9](#0-8) 

## Likelihood Explanation

**Likelihood: Low to Medium**

The attack requires:
- Knowledge of Ed25519 small subgroup attacks and the 8-torsion points
- Ability to compute the compressed representation of small-order points
- Access to the faucet API (publicly available on testnets/devnets)

The attack is straightforward once the attacker has this knowledge. The 8 small-order points are well-documented in cryptographic literature and test code: [10](#0-9) 

## Recommendation

Add small subgroup validation to `Ed25519PublicKey::from_encoded_string()` before accepting public keys in the faucet. The validation should be performed in `Ed25519PublicKey::try_from()`:

```rust
// In crates/aptos-crypto/src/ed25519/ed25519_keys.rs
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        // Decompress and validate the point
        let compressed = CompressedEdwardsY::from_slice(bytes);
        let point = compressed
            .decompress()
            .ok_or(CryptoMaterialError::DeserializationError)?;
        
        // Reject small-order points
        if point.is_small_order() {
            return Err(CryptoMaterialError::SmallSubgroupError);
        }
        
        // Continue with normal deserialization
        Ed25519PublicKey::from_bytes_unchecked(bytes)
    }
}
```

Alternatively, add explicit validation in the faucet endpoint before deriving the authentication key.

## Proof of Concept

```rust
use aptos_crypto::{ed25519::Ed25519PublicKey, ValidCryptoMaterialStringExt};
use aptos_types::transaction::authenticator::AuthenticationKey;
use curve25519_dalek::constants::EIGHT_TORSION;

#[test]
fn test_faucet_small_order_attack() {
    // Get a small-order point from the 8-torsion subgroup
    let small_order_point = EIGHT_TORSION[1]; // Any index 0..8 works
    let malicious_pubkey_bytes = small_order_point.compress().to_bytes();
    
    // Convert to hex string (what attacker would send to faucet)
    let malicious_pubkey_hex = hex::encode(&malicious_pubkey_bytes);
    
    // Faucet parses this without validation
    let parsed_key = Ed25519PublicKey::from_encoded_string(&malicious_pubkey_hex);
    assert!(parsed_key.is_ok(), "Small-order key should be rejected but is accepted!");
    
    // Derive authentication key (what faucet does)
    let auth_key = AuthenticationKey::ed25519(&parsed_key.unwrap());
    let account_address = auth_key.account_address();
    
    println!("Attack successful! Faucet would fund account at: {}", account_address);
    println!("This account is permanently locked - no signature can verify!");
    
    // Any attempt to use this account will fail at signature verification
    // because verify_strict() checks point.is_small_order() and rejects it
}
```

**Notes:**
- The vulnerability specifically affects the faucet's ability to validate public keys before creating accounts
- The strict verification enforced throughout transaction validation prevents the attacker from using these accounts, but doesn't prevent their creation
- This breaks the invariant that faucet-created accounts should be usable by their intended recipients
- The Ed25519 implementation in `aptos-crypto` explicitly documents it does not check small subgroups, while the Move framework's native functions do enforce these checks, creating a validation gap at account creation time

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L68-73)
```rust
        if let Some(pub_key) = self.pub_key.as_ref() {
            return match Ed25519PublicKey::from_encoded_string(pub_key) {
                Ok(pub_key) => Some(AuthenticationKey::ed25519(&pub_key).account_address()),
                Err(_) => None,
            };
        }
```

**File:** third_party/move/move-examples/diem-framework/crates/crypto/src/traits.rs (L77-84)
```rust
    fn from_encoded_string(encoded_str: &str) -> std::result::Result<Self, CryptoMaterialError> {
        let bytes_out = ::hex::decode(encoded_str);
        // We defer to `try_from` to make sure we only produce valid crypto materials.
        bytes_out
            // We reinterpret a failure to serialize: key is mangled someway.
            .or(Err(CryptoMaterialError::DeserializationError))
            .and_then(|ref bytes| Self::try_from(bytes))
    }
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L100-111)
```rust
    /// Deserialize an Ed25519PublicKey without any validation checks apart from expected key size
    /// and valid curve point, although not necessarily in the prime-order subgroup.
    ///
    /// This function does NOT check the public key for membership in a small subgroup.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        match ed25519_dalek::PublicKey::from_bytes(bytes) {
            Ok(dalek_public_key) => Ok(Ed25519PublicKey(dalek_public_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L295-305)
```rust
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Ed25519PublicKey. This method will NOT check for key validity, which means
    /// the returned public key could be in a small subgroup. Nonetheless, our signature
    /// verification implicitly checks if the public key lies in a small subgroup, so canonical
    /// uses of this library will not be susceptible to small subgroup attacks.
    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        Ed25519PublicKey::from_bytes_unchecked(bytes)
    }
}
```

**File:** types/src/transaction/authenticator.rs (L884-887)
```rust
    pub fn from_preimage(mut public_key_bytes: Vec<u8>, scheme: Scheme) -> AuthenticationKey {
        public_key_bytes.push(scheme as u8);
        AuthenticationKey::new(*HashValue::sha3_256_of(&public_key_bytes).as_ref())
    }
```

**File:** types/src/transaction/authenticator.rs (L913-916)
```rust
    /// Create an authentication key from an Ed25519 public key
    pub fn ed25519(public_key: &Ed25519PublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes().to_vec(), Scheme::Ed25519)
    }
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_sigs.rs (L112-139)
```rust
    /// This function will ensure both the signature and the `public_key` are not in a small subgroup.
    fn verify<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        public_key: &Ed25519PublicKey,
    ) -> Result<()> {
        Self::verify_arbitrary_msg(self, &signing_message(message)?, public_key)
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using `public_key`.
    /// Outside of this crate, this particular function should only be used for native signature
    /// verification in Move.
    ///
    /// This function will check both the signature and `public_key` for small subgroup attacks.
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Result<()> {
        // NOTE: ed25519::PublicKey::verify_strict already checks that the s-component of the signature
        // is not mauled, but does so via an optimistic path which fails into a slower path. By doing
        // our own (much faster) checking here, we can ensure dalek's optimistic path always succeeds
        // and the slow path is never triggered.
        Ed25519Signature::check_s_malleability(&self.to_bytes())?;

        // NOTE: ed25519::PublicKey::verify_strict checks that the signature's R-component and
        // the public key are *not* in a small subgroup.
        public_key
            .0
            .verify_strict(message, &self.0)
            .map_err(|e| anyhow!("{}", e))
            .and(Ok(()))
```

**File:** aptos-move/framework/src/natives/cryptography/ed25519.rs (L67-82)
```rust
    // This deserialization only performs point-on-curve checks, so we check for small subgroup below
    // NOTE(Gas): O(1) cost: some arithmetic for converting to (X, Y, Z, T) coordinates
    let point = match CompressedEdwardsY(key_bytes_slice).decompress() {
        Some(point) => point,
        None => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };

    // Check if the point lies on a small subgroup. This is required when using curves with a
    // small cofactor (e.g., in Ed25519, cofactor = 8).
    // NOTE(Gas): O(1) cost: multiplies the point by the cofactor
    context.charge(ED25519_PER_PUBKEY_SMALL_ORDER_CHECK * NumArgs::one())?;
    let valid = !point.is_small_order();

    Ok(smallvec![Value::bool(valid)])
```

**File:** crates/aptos-faucet/core/src/funder/transfer.rs (L295-306)
```rust
        // When updating the sequence numbers, we expect that the receiver sequence
        // number should be None, because the account should not exist yet.
        if receiver_seq_num.is_some() {
            return Err(AptosTapError::new(
                "Account ineligible".to_string(),
                AptosTapErrorCode::Rejected,
            )
            .rejection_reasons(vec![RejectionReason::new(
                format!("Account {} already exists", receiver_address),
                RejectionReasonCode::AccountAlreadyExists,
            )]));
        }
```

**File:** crates/aptos-crypto/src/unit_tests/ed25519_test.rs (L203-217)
```rust
        // Dalek only performs an order check, so this is allowed
        let bad_scalar = Scalar::zero();

        let bad_component_1 = curve25519_dalek::constants::EIGHT_TORSION[idx];
        let bad_component_2 = bad_component_1.neg();

        // compute bad_pub_key, bad_signature
        let bad_pub_key_point = bad_component_1; // we need this to cancel the hashed component of the verification equation

        // we pick an evil R component
        let bad_sig_point = bad_component_2;

        let bad_key = ed25519_dalek::PublicKey::from_bytes(&bad_pub_key_point.compress().to_bytes()).unwrap();
        // This assertion passes because Ed25519PublicKey::TryFrom<&[u8]> no longer checks for small subgroup membership
        prop_assert!(Ed25519PublicKey::try_from(&bad_pub_key_point.compress().to_bytes()[..]).is_ok());
```
