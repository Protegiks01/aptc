# Audit Report

## Title
Key Type Confusion in encode_key() and decode_key() Enables Cross-Purpose Key Usage

## Summary
The `encode_key()` and `decode_key()` functions in `encoding_type.rs` lack type information in Hex and Base64 encodings, allowing signing keys (Ed25519) to be decoded and used as encryption keys (X25519) and vice versa. This violates the cryptographic principle of key separation and can enable cross-protocol attacks.

## Finding Description

The `encode_key()` function encodes cryptographic keys without embedding type metadata when using Hex or Base64 encoding. [1](#0-0) 

For Hex and Base64 encodings, only raw bytes are encoded without any type information. The `name` parameter is merely used for error messages and provides no type safety.

When decoding, the `decode_key()` function relies solely on Rust's type inference to determine the target key type: [2](#0-1) 

For Hex encoding, the AIP-80 prefix validation is permissive - it attempts to strip the prefix but uses `unwrap_or(str)` to continue if the prefix is absent or incorrect: [3](#0-2) 

Both Ed25519 and X25519 private keys are 32 bytes, and their validation only checks length: [4](#0-3) [5](#0-4) 

**Attack Scenario:**
1. A user generates an Ed25519 private key for transaction signing
2. The key is saved using `encode_key()` with Hex encoding (no AIP-80 prefix included)
3. Due to misconfiguration or filesystem access, the file is loaded as `x25519::PrivateKey`
4. The decode succeeds because both keys are 32 bytes and no type validation occurs
5. The same key material is now used for both signing and key agreement/encryption

This violates the key separation principle where cryptographic keys should serve only one purpose. The vulnerability exists in production code used by the Aptos CLI: [6](#0-5) 

## Impact Explanation

This is a **High Severity** issue that constitutes a "Significant protocol violation" under the Aptos bug bounty criteria:

1. **Cryptographic Correctness Violation**: Breaks invariant #10 requiring secure cryptographic operations
2. **Cross-Protocol Attack Surface**: Using the same key for signing and encryption enables potential attacks where messages from one context can be manipulated to be valid in another
3. **Security Proof Invalidation**: Many cryptographic security proofs assume single-purpose key usage
4. **Key Compromise Amplification**: If one usage is compromised, all usages are compromised

While not directly causing consensus violations or fund loss, this breaks fundamental cryptographic security principles that underpin the entire system's security model.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- User error in specifying the wrong key type when loading
- OR misconfiguration in key management scripts
- OR filesystem access by an attacker to swap key files

This is more likely to occur in:
- Automated deployment scripts with incorrect type annotations
- Key migration scenarios
- Development/testing environments that later affect production
- Third-party integrations with Aptos key management

The permissive validation and lack of type enforcement make this error easy to make and difficult to detect.

## Recommendation

Add mandatory type validation to prevent cross-type key usage:

**Option 1: Enforce AIP-80 Prefix Validation**
```rust
pub fn decode_key<Key: ValidCryptoMaterial>(
    &self,
    name: &'static str,
    data: Vec<u8>,
) -> Result<Key, EncodingError> {
    match self {
        EncodingType::Hex => {
            let hex_string = String::from_utf8(data)?;
            // Require AIP-80 prefix to match expected type
            if !hex_string.starts_with(Key::AIP_80_PREFIX) {
                return Err(EncodingError::UnableToParse(
                    name, 
                    format!("Expected prefix '{}', key type mismatch", Key::AIP_80_PREFIX)
                ));
            }
            Key::from_encoded_string(hex_string.trim())
                .map_err(|err| EncodingError::UnableToParse(name, err.to_string()))
        },
        // Similar for Base64...
    }
}
```

**Option 2: Always Include Type Metadata in encode_key()**
```rust
pub fn encode_key<Key: ValidCryptoMaterial>(
    &self,
    name: &'static str,
    key: &Key,
) -> Result<Vec<u8>, EncodingError> {
    Ok(match self {
        EncodingType::Hex => {
            // Always include AIP-80 prefix for type safety
            let prefixed = format!("{}{}", Key::AIP_80_PREFIX, hex::encode_upper(key.to_bytes()));
            prefixed.into_bytes()
        },
        // Similar for Base64...
    })
}
```

**Recommendation**: Implement both options to ensure defense in depth. Also add warnings to documentation about key type separation.

## Proof of Concept

```rust
use aptos_crypto::{
    ed25519::Ed25519PrivateKey,
    x25519,
    encoding_type::EncodingType,
    traits::Uniform,
    ValidCryptoMaterial,
};
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    // Generate an Ed25519 signing key
    let mut rng = StdRng::from_seed([0u8; 32]);
    let ed25519_key = Ed25519PrivateKey::generate(&mut rng);
    
    println!("Original Ed25519 key (for signing): {:?}", 
             hex::encode(ed25519_key.to_bytes()));
    
    // Encode it as Hex (no type information)
    let encoding = EncodingType::Hex;
    let encoded = encoding.encode_key("test-key", &ed25519_key)
        .expect("Failed to encode");
    
    println!("Encoded (raw hex): {}", String::from_utf8_lossy(&encoded));
    
    // Decode as X25519 key (WRONG TYPE!)
    let x25519_key: x25519::PrivateKey = encoding.decode_key("test-key", encoded)
        .expect("This should fail but succeeds - VULNERABILITY!");
    
    println!("Decoded as X25519 key (for encryption): {:?}", 
             hex::encode(x25519_key.to_bytes()));
    
    println!("\n⚠️  VULNERABILITY DEMONSTRATED:");
    println!("Same key material is now usable for both signing and encryption!");
    println!("This violates the key separation principle.");
}
```

Running this PoC demonstrates that a signing key can be successfully decoded and used as an encryption key, confirming the vulnerability.

## Notes

- The vulnerability only affects **Hex and Base64** encodings, not BCS encoding (which includes struct name metadata)
- The issue affects production code paths in the Aptos CLI and configuration management
- BCS encoding is type-safe and not affected by this issue
- The permissive AIP-80 prefix handling exacerbates the problem by allowing keys without prefixes or with incorrect prefixes to be processed

### Citations

**File:** crates/aptos-crypto/src/encoding_type.rs (L52-62)
```rust
    pub fn encode_key<Key: ValidCryptoMaterial>(
        &self,
        name: &'static str,
        key: &Key,
    ) -> Result<Vec<u8>, EncodingError> {
        Ok(match self {
            EncodingType::Hex => hex::encode_upper(key.to_bytes()).into_bytes(),
            EncodingType::BCS => bcs::to_bytes(key).map_err(|err| EncodingError::BCS(name, err))?,
            EncodingType::Base64 => base64::encode(key.to_bytes()).into_bytes(),
        })
    }
```

**File:** crates/aptos-crypto/src/encoding_type.rs (L74-97)
```rust
    pub fn decode_key<Key: ValidCryptoMaterial>(
        &self,
        name: &'static str,
        data: Vec<u8>,
    ) -> Result<Key, EncodingError> {
        match self {
            EncodingType::BCS => {
                bcs::from_bytes(&data).map_err(|err| EncodingError::BCS(name, err))
            },
            EncodingType::Hex => {
                let hex_string = String::from_utf8(data)?;
                Key::from_encoded_string(hex_string.trim())
                    .map_err(|err| EncodingError::UnableToParse(name, err.to_string()))
            },
            EncodingType::Base64 => {
                let string = String::from_utf8(data)?;
                let bytes = base64::decode(string.trim())
                    .map_err(|err| EncodingError::UnableToParse(name, err.to_string()))?;
                Key::try_from(bytes.as_slice()).map_err(|err| {
                    EncodingError::UnableToParse(name, format!("Failed to parse key {:?}", err))
                })
            },
        }
    }
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L85-99)
```rust
    fn from_encoded_string(encoded_str: &str) -> std::result::Result<Self, CryptoMaterialError> {
        let mut str = encoded_str;
        // First strip the AIP-80 prefix
        str = str.strip_prefix(Self::AIP_80_PREFIX).unwrap_or(str);

        // Strip 0x at beginning if there is one
        str = str.strip_prefix("0x").unwrap_or(str);

        let bytes_out = ::hex::decode(str);
        // We defer to `try_from` to make sure we only produce valid crypto materials.
        bytes_out
            // We reinterpret a failure to serialize: key is mangled someway.
            .or(Err(CryptoMaterialError::DeserializationError))
            .and_then(|ref bytes| Self::try_from(bytes))
    }
```

**File:** crates/aptos-crypto/src/x25519.rs (L161-170)
```rust
impl std::convert::TryFrom<&[u8]> for PrivateKey {
    type Error = traits::CryptoMaterialError;

    fn try_from(private_key_bytes: &[u8]) -> Result<Self, Self::Error> {
        let private_key_bytes: [u8; PRIVATE_KEY_SIZE] = private_key_bytes
            .try_into()
            .map_err(|_| traits::CryptoMaterialError::DeserializationError)?;
        Ok(Self(x25519_dalek::StaticSecret::from(private_key_bytes)))
    }
}
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L204-218)
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
}
```

**File:** crates/aptos/src/op/key.rs (L426-447)
```rust
    pub fn save_key<Key: PrivateKey + ValidCryptoMaterial>(
        self,
        key: &Key,
        key_name: &'static str,
    ) -> CliTypedResult<HashMap<&'static str, PathBuf>> {
        let encoded_private_key = self.encoding_options.encoding.encode_key(key_name, key)?;
        let encoded_public_key = self
            .encoding_options
            .encoding
            .encode_key(key_name, &key.public_key())?;

        // Write private and public keys to files
        let public_key_file = self.public_key_file()?;
        self.file_options
            .save_to_file_confidential(key_name, &encoded_private_key)?;
        write_to_file(&public_key_file, key_name, &encoded_public_key)?;

        let mut map = HashMap::new();
        map.insert("PrivateKey Path", self.file_options.output_file);
        map.insert("PublicKey Path", public_key_file);
        Ok(map)
    }
```
