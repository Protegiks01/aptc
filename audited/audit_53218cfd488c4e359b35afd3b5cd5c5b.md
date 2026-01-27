# Audit Report

## Title
Type Confusion Vulnerability in ValidCryptoMaterial Enum Derive Macro Due to Missing Discriminant in Serialization

## Summary
The `ValidCryptoMaterial` derive macro for enums generates serialization code that omits enum variant discriminants, while deserialization attempts variants sequentially. This creates a type confusion vulnerability when multiple enum variants can successfully deserialize the same byte sequence, violating the round-trip property and potentially causing consensus failures or cryptographic verification bypasses.

## Finding Description

The `impl_enum_valid_crypto_material` function generates code with a critical design flaw: [1](#0-0) 

The `to_bytes()` implementation directly forwards to the inner variant's `to_bytes()` without adding any discriminant: [2](#0-1) 

Meanwhile, the `try_from()` implementation tries each variant in sequence until one succeeds: [3](#0-2) 

**The vulnerability:** When an enum contains variants with overlapping valid byte representations, deserialization becomes non-deterministic. For example, if an enum contains both Ed25519 and Secp256k1 private keys (both 32 bytes):

- Ed25519 accepts any 32-byte sequence [4](#0-3) 
- Secp256k1 only accepts 32-byte sequences less than the curve order [5](#0-4) 

If Ed25519 is listed first in the enum, serializing a valid Secp256k1 key and deserializing it will incorrectly return an Ed25519 key, violating the invariant `x == try_from(x.to_bytes())`.

**Impact on Consensus:** Different nodes could deserialize the same cryptographic material as different key types, leading to:
- Different signature verification results
- Different state roots for identical blocks
- Consensus safety violations under AptosBFT

## Impact Explanation

This vulnerability would meet **Critical Severity** criteria if exploited in production:

**Consensus Safety Violation:** The Aptos specification requires deterministic execution where all validators produce identical state roots for identical blocks. Type confusion in cryptographic material deserialization would cause different nodes to interpret the same transaction differently, breaking consensus safety.

**Cryptographic Verification Bypass:** A signature created with one key type could potentially be verified against a different key type if both can parse the same bytes, allowing signature forgery.

However, examination of the codebase reveals **no production usage** of this derive macro on enums. The only usage found is in test code: [6](#0-5) 

Production code uses BCS serialization with proper discriminants instead (e.g., `AnyPublicKey`, `EphemeralPrivateKey`).

## Likelihood Explanation

**Current likelihood: NONE** - The vulnerable macro exists but is not used in production code.

**Future likelihood: MEDIUM** - If developers use this macro to create enums combining cryptographic primitives with same-length serializations (e.g., Ed25519 + Secp256k1 + Secp256r1, all 32-byte private keys), the vulnerability would become active and exploitable.

## Recommendation

The derive macro should be either:

1. **Removed** if not needed in production, or
2. **Fixed** to include discriminants in serialization:

```rust
fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = vec![self.discriminant()]; // Add variant tag
    match self {
        #to_bytes_arms
    }
    bytes
}
```

And update `try_from()` to read the discriminant first before attempting deserialization.

Alternatively, add compile-time validation that enum variants cannot have overlapping valid byte sequences.

## Proof of Concept

```rust
// This would demonstrate the vulnerability if compiled
#[derive(ValidCryptoMaterial)]
enum VulnerableKey {
    Ed25519(Ed25519PrivateKey),     // Accepts any 32 bytes
    Secp256k1(secp256k1_ecdsa::PrivateKey), // Validates < curve order
}

#[test]
fn test_type_confusion() {
    // Create valid Secp256k1 key
    let secp_key = secp256k1_ecdsa::PrivateKey::generate(&mut rng);
    let original = VulnerableKey::Secp256k1(secp_key);
    
    // Serialize and deserialize
    let bytes = original.to_bytes();
    let deserialized = VulnerableKey::try_from(&bytes[..]).unwrap();
    
    // BUG: deserialized is Ed25519, not Secp256k1!
    assert!(matches!(deserialized, VulnerableKey::Ed25519(_))); // Would pass
    assert_ne!(original, deserialized); // Round-trip fails
}
```

## Notes

While this is a design flaw in the macro that violates the round-trip guarantee required by `ValidCryptoMaterial`, it does **not constitute an active vulnerability** in the deployed Aptos codebase because no production code uses this derive macro on enums. All production cryptographic enums use BCS serialization with proper discriminants. This represents a **latent vulnerability** that would only become exploitable if future code incorrectly uses this macro.

### Citations

**File:** crates/aptos-crypto-derive/src/unions.rs (L31-69)
```rust
pub fn impl_enum_tryfrom(name: &Ident, variants: &DataEnum) -> proc_macro2::TokenStream {
    // the TryFrom dispatch
    let mut try_iter = variants.variants.iter();
    let first_variant = try_iter
        .next()
        .expect("#[derive(ValidCryptoMaterial] requires a non-empty enum.");
    let first_variant_ident = &first_variant.ident;
    let first_variant_arg = &first_variant
        .fields
        .iter()
        .next()
        .expect("Unrecognized enum for key types")
        .ty;

    let mut try_chain = quote! {
        #first_variant_arg::try_from(bytes).and_then(|key| Ok(#name::#first_variant_ident(key)))
    };
    for variant in try_iter {
        let variant_ident = &variant.ident;
        let variant_arg = &variant
            .fields
            .iter()
            .next()
            .expect("Unrecognized enum for key types")
            .ty;
        try_chain.extend(quote!{
            .or_else(|_err| #variant_arg::try_from(bytes).and_then(|key| Ok(#name::#variant_ident(key))))
        })
    }

    quote! {
        impl core::convert::TryFrom<&[u8]> for #name {
            type Error = aptos_crypto::CryptoMaterialError;
            fn try_from(bytes: &[u8]) -> std::result::Result<#name, Self::Error> {
                #try_chain
            }
        }
    }
}
```

**File:** crates/aptos-crypto-derive/src/unions.rs (L71-82)
```rust
fn match_enum_to_bytes(name: &Ident, variants: &DataEnum) -> proc_macro2::TokenStream {
    // the ValidCryptoMaterial dispatch proper
    let mut match_arms = quote! {};
    for variant in variants.variants.iter() {
        let variant_ident = &variant.ident;

        match_arms.extend(quote! {
            #name::#variant_ident(key) => key.to_bytes().to_vec(),
        });
    }
    match_arms
}
```

**File:** crates/aptos-crypto-derive/src/unions.rs (L84-102)
```rust
pub fn impl_enum_valid_crypto_material(name: &Ident, variants: &DataEnum) -> TokenStream {
    let mut try_from = impl_enum_tryfrom(name, variants);

    let to_bytes_arms = match_enum_to_bytes(name, variants);

    try_from.extend(quote! {

        impl aptos_crypto::ValidCryptoMaterial for #name {
            const AIP_80_PREFIX: &'static str = "";

            fn to_bytes(&self) -> Vec<u8> {
                match self {
                    #to_bytes_arms
                }
            }
        }
    });
    try_from.into()
}
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L204-217)
```rust
impl TryFrom<&[u8]> for Ed25519PrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Ed25519PrivateKey. This method will check for private key validity: i.e.,
    /// correct key length.
    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PrivateKey, CryptoMaterialError> {
        // Note that the only requirement is that the size of the key is 32 bytes, something that
        // is already checked during deserialization of ed25519_dalek::SecretKey
        //
        // Also, the underlying ed25519_dalek implementation ensures that the derived public key
        // is safe and it will not lie in a small-order group, thus no extra check for PublicKey
        // validation is required.
        Ed25519PrivateKey::from_bytes_unchecked(bytes)
    }
```

**File:** crates/aptos-crypto/src/secp256k1_ecdsa.rs (L63-71)
```rust
impl TryFrom<&[u8]> for PrivateKey {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<PrivateKey, CryptoMaterialError> {
        match libsecp256k1::SecretKey::parse_slice(bytes) {
            Ok(private_key) => Ok(PrivateKey(private_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
```

**File:** crates/aptos-crypto/src/unit_tests/cross_test.rs (L28-62)
```rust
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    ValidCryptoMaterial,
    PublicKey,
    VerifyingKey,
)]
#[PrivateKeyType = "PrivateK"]
#[SignatureType = "Sig"]
enum PublicK {
    Ed(Ed25519PublicKey),
    MultiEd(MultiEd25519PublicKey),
}

#[derive(Serialize, Deserialize, SilentDebug, ValidCryptoMaterial, PrivateKey, SigningKey)]
#[PublicKeyType = "PublicK"]
#[SignatureType = "Sig"]
enum PrivateK {
    Ed(Ed25519PrivateKey),
    MultiEd(MultiEd25519PrivateKey),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Signature)]
#[PublicKeyType = "PublicK"]
#[PrivateKeyType = "PrivateK"]
enum Sig {
    Ed(Ed25519Signature),
    MultiEd(MultiEd25519Signature),
}
```
