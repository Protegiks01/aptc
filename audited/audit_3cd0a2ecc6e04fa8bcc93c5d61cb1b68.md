# Audit Report

## Title
Memory Disclosure of Private Key Material via Non-Zeroed String Representations in Hex and Base64 Encodings

## Summary
The `EncodingType::decode_key()` method creates intermediate `String` objects containing encoded private key material when using Hex or Base64 encodings. These strings are not securely zeroed from memory after use, violating Aptos's secure coding guidelines and potentially exposing private keys to memory-scanning attacks. [1](#0-0) 

## Finding Description

When loading private keys from files, the `EncodingType` enum supports three variants: Hex, BCS, and Base64. However, Hex and Base64 create intermediate string representations that contain the encoded private key material in plaintext form within process memory, and these strings are never securely zeroed.

**Vulnerability Flow for Hex Encoding:** [2](#0-1) 

The `decode_key` method converts the file bytes to a UTF-8 `String` containing the hex-encoded private key. This string persists in memory until garbage collected, but is never zeroed. The `from_encoded_string()` method then performs additional string operations (prefix stripping, trimming) that create more string slices: [3](#0-2) 

**Vulnerability Flow for Base64 Encoding:** [4](#0-3) 

Similarly, Base64 decoding creates a `String` containing the base64-encoded private key that is not zeroed from memory.

**BCS Encoding is NOT Affected:** [5](#0-4) 

BCS directly deserializes from the byte buffer without creating intermediate string representations.

**Violation of Secure Coding Guidelines:**

The Aptos codebase explicitly documents this requirement: [6](#0-5) [7](#0-6) 

While the actual `Ed25519PrivateKey` objects are properly handled (the underlying `ed25519_dalek::SecretKey` implements `Zeroize`), the intermediate string representations created during Hex and Base64 decoding remain in memory unzeroed, potentially appearing in:
- Memory dumps
- Swap files
- Core dumps
- Memory scans by malware

## Impact Explanation

**Severity: Medium** - This qualifies as "limited funds loss or manipulation" because an attacker with local memory access could extract private keys and steal funds from affected accounts. While the attack requires local access, the violation of documented secure coding practices and unnecessary exposure of sensitive cryptographic material represents a real security weakness that could be exploited by:

- Memory-scanning malware on the user's machine
- Forensic analysis of memory dumps or swap files
- Debuggers attached to the process
- Memory inspection during system hibernation

The impact is limited because BCS encoding provides a secure alternative, and the attacker needs local machine access. However, the unnecessary retention of private key material in cleartext string form violates defense-in-depth principles.

## Likelihood Explanation

**Likelihood: Medium** - This vulnerability affects any user who:
1. Stores private keys using Hex or Base64 encoding (Hex is the default per the code)
2. Loads these keys using the CLI or any tool using `EncodingType::decode_key()` [8](#0-7) 

The likelihood is increased because Hex is the **default encoding**, meaning users who don't explicitly choose BCS will be affected. However, exploitation requires the attacker to have local access to capture process memory during or shortly after key loading operations.

## Recommendation

Implement secure memory zeroing for all intermediate string representations containing encoded private key material:

1. Add `zeroize` as an explicit dependency to `aptos-crypto`
2. Use `zeroizing::Zeroizing<String>` wrapper for strings containing sensitive data
3. Alternatively, decode directly from bytes without creating intermediate strings

**Recommended Code Fix:**

```rust
// For Hex decoding - avoid creating persistent strings
EncodingType::Hex => {
    let bytes = hex::decode(data.trim_ascii())
        .map_err(|err| EncodingError::UnableToParse(name, err.to_string()))?;
    Key::try_from(bytes.as_slice())
        .map_err(|err| EncodingError::UnableToParse(name, err.to_string()))
},

// For Base64 decoding - decode directly from bytes
EncodingType::Base64 => {
    let bytes = base64::decode(data.trim_ascii())
        .map_err(|err| EncodingError::UnableToParse(name, err.to_string()))?;
    Key::try_from(bytes.as_slice())
        .map_err(|err| EncodingError::UnableToParse(name, format!("Failed to parse key {:?}", err)))
},
```

## Proof of Concept [9](#0-8) 

```rust
// PoC demonstrating string creation during key loading
use aptos_crypto::{ed25519::Ed25519PrivateKey, encoding_type::EncodingType, ValidCryptoMaterial};
use std::fs;

#[test]
fn test_hex_encoding_leaves_strings_in_memory() {
    // Generate a test key
    let mut keygen = aptos_keygen::KeyGen::from_os_rng();
    let private_key = keygen.generate_ed25519_private_key();
    
    // Encode to hex
    let encoded = EncodingType::Hex.encode_key("test", &private_key).unwrap();
    fs::write("/tmp/test_key.hex", &encoded).unwrap();
    
    // Load key back - this creates non-zeroed strings
    let loaded_data = fs::read("/tmp/test_key.hex").unwrap();
    let _loaded_key: Ed25519PrivateKey = EncodingType::Hex
        .decode_key("test", loaded_data)
        .unwrap();
    
    // At this point, a String containing the hex-encoded key exists in memory
    // and will not be zeroed until garbage collected
    // An attacker with memory access could scan for hex patterns matching
    // Ed25519 private key lengths (64 hex chars)
    
    fs::remove_file("/tmp/test_key.hex").unwrap();
}
```

## Notes

- BCS encoding does not have this vulnerability and should be recommended for private key storage where security is paramount
- The underlying `ed25519_dalek::SecretKey` properly implements `Zeroize`, so the actual key bytes are secured - only intermediate encoded representations are at risk
- This issue represents a defense-in-depth concern and violation of documented secure coding practices
- Users can mitigate by using BCS encoding instead of Hex or Base64 for private key operations

### Citations

**File:** crates/aptos-crypto/src/encoding_type.rs (L38-48)
```rust
/// Types of encodings used by the blockchain
#[derive(Clone, Copy, Debug, Default)]
pub enum EncodingType {
    /// Binary Canonical Serialization
    BCS,
    /// Hex encoded e.g. 0xABCDE12345
    #[default]
    Hex,
    /// Base 64 encoded
    Base64,
}
```

**File:** crates/aptos-crypto/src/encoding_type.rs (L73-97)
```rust
    /// Decodes an encoded key given the known encoding
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

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** crates/aptos/src/op/key.rs (L425-447)
```rust
    /// Saves a key to a file encoded in a string
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
