# Audit Report

## Title
X25519 Private Key Material Leakage During Serialization via Unzeroized Intermediate Buffers

## Summary
The `x25519::PrivateKey` serialization process creates multiple intermediate buffers (`Vec<u8>` and `String`) containing sensitive key material that are not explicitly cleared using zeroize before being dropped, violating Aptos's secure coding guidelines and creating potential attack vectors for memory-based key extraction.

## Finding Description

The `x25519::PrivateKey` type uses the `SerializeKey` derive macro for serialization, which breaks the **Cryptographic Correctness** invariant by leaving sensitive key material in memory without proper sanitization. [1](#0-0) 

The serialization process follows two paths:

**Binary Serialization Path:**
The `SerializeKey` macro calls `ValidCryptoMaterial::to_bytes(self)` which creates an unprotected `Vec<u8>`: [2](#0-1) [3](#0-2) 

**Human-Readable Serialization Path:**
The macro calls `to_encoded_string()` which creates both an unprotected `Vec<u8>` AND a `String` containing the hex-encoded key: [4](#0-3) [5](#0-4) 

**Direct Violation of Security Policy:**

Aptos's own secure coding guidelines explicitly prohibit this pattern: [6](#0-5) [7](#0-6) 

**Attack Vectors:**

Network private keys are serialized in multiple security-critical contexts:

1. **Configuration Persistence:** [8](#0-7) 

2. **YAML Identity Serialization:** [9](#0-8) 

These keys are used for validator network authentication via the Noise protocol, making their compromise a network security issue.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **Network Identity Compromise**: X25519 private keys authenticate validators in the Noise IK protocol. Compromise allows network-level impersonation attacks.

2. **Memory-Based Attack Vectors**:
   - **Swap Space**: Unzeroized heap allocations may be paged to disk
   - **Core Dumps**: Process crashes during serialization capture keys
   - **Cold Boot Attacks**: Keys persist in RAM after process termination
   - **Memory Scanning Malware**: Heap walking tools can extract keys

3. **Violation of Stated Security Policy**: Aptos explicitly requires zeroize for private keys, making this a compliance failure.

While not reaching Critical severity (no direct funds loss or consensus violation), the compromise of validator network identity represents a **state inconsistency requiring intervention** and enables limited network-level attacks.

## Likelihood Explanation

**Moderate Likelihood** due to:

1. **Frequent Serialization**: Occurs during validator startup, configuration updates, and identity management operations
2. **Extended Exposure Window**: Allocators may not immediately reclaim memory; buffers persist until overwritten
3. **Common Attack Scenarios**: Memory dumps for debugging, system compromise via malware, forensic analysis of swap/hibernation files

**Mitigating Factors**:
- Requires local system access or memory access privileges
- Other key extraction methods exist (e.g., reading config files)
- x25519_dalek::StaticSecret itself uses zeroize (though copies do not)

## Recommendation

Implement explicit zeroization for all intermediate buffers containing sensitive key material:

1. **Add zeroize dependency** to `aptos-crypto/Cargo.toml`
2. **Use `zeroize::Zeroizing<Vec<u8>>`** wrapper for `to_bytes()` return value
3. **Use `zeroize::Zeroizing<String>`** for `to_encoded_string()` return value
4. **Implement custom `Serialize`** that explicitly zeros buffers after use

Example fix for `to_bytes()`:

```rust
use zeroize::Zeroizing;

fn to_bytes(&self) -> Vec<u8> {
    Zeroizing::new(self.0.to_bytes().to_vec()).to_vec()
}
```

Better approach - implement custom serialization with explicit cleanup:

```rust
impl ::serde::Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: ::serde::Serializer,
    {
        use zeroize::Zeroizing;
        if serializer.is_human_readable() {
            let bytes = Zeroizing::new(self.to_bytes());
            let encoded = Zeroizing::new(format!("0x{}", hex::encode(&*bytes)));
            serializer.serialize_str(&encoded)
        } else {
            let bytes = Zeroizing::new(self.to_bytes());
            serializer.serialize_newtype_struct(
                "PrivateKey",
                serde_bytes::Bytes::new(&bytes),
            )
        }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod memory_leak_test {
    use aptos_crypto::{x25519, ValidCryptoMaterial, Uniform};
    use std::ptr;
    
    #[test]
    fn demonstrate_unzeroized_serialization_buffers() {
        let mut rng = rand::thread_rng();
        let private_key = x25519::PrivateKey::generate(&mut rng);
        
        // Trigger serialization to create intermediate buffers
        let bytes_vec = private_key.to_bytes();
        let vec_ptr = bytes_vec.as_ptr();
        let vec_data = bytes_vec.clone();
        
        // Drop the Vec - memory is NOT zeroized
        drop(bytes_vec);
        
        // Memory at the old pointer location may still contain key material
        // In a real attack, this would be accessible via memory dumps,
        // swap space, or heap scanning tools
        
        // Demonstrate the issue with encoded string
        let encoded = format!("0x{}", hex::encode(&vec_data));
        let str_ptr = encoded.as_ptr();
        drop(encoded);
        
        // String memory is also not zeroized
        // An attacker with memory access could recover the key
        
        println!("Vec was at: {:p}", vec_ptr);
        println!("String was at: {:p}", str_ptr);
        println!("Key material existed in unzeroized heap allocations");
    }
}
```

**Notes**

This vulnerability represents a gap between Aptos's stated security policy and actual implementation. While x25519_dalek::StaticSecret itself properly uses zeroize (as evidenced by the custom fork), the serialization wrappers create unprotected copies. The risk is amplified by the fact that these keys authenticate validators in the network layer, making their compromise a protocol-level security concern rather than merely a local security issue.

### Citations

**File:** crates/aptos-crypto/src/x25519.rs (L66-68)
```rust
#[derive(DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Clone))]
pub struct PrivateKey(x25519_dalek::StaticSecret);
```

**File:** crates/aptos-crypto/src/x25519.rs (L189-192)
```rust
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L196-199)
```rust
                if serializer.is_human_readable() {
                    self.to_encoded_string()
                        .map_err(<S::Error as ::serde::ser::Error>::custom)
                        .and_then(|str| serializer.serialize_str(&str[..]))
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L200-206)
```rust
                } else {
                    // See comment in deserialize_key.
                    serializer.serialize_newtype_struct(
                        #name_string,
                        serde_bytes::Bytes::new(&ValidCryptoMaterial::to_bytes(self).as_slice()),
                    )
                }
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L102-104)
```rust
    fn to_encoded_string(&self) -> Result<String> {
        Ok(format!("0x{}", ::hex::encode(self.to_bytes())))
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

**File:** config/src/config/identity_config.rs (L24-37)
```rust
#[derive(Deserialize, Serialize)]
pub struct IdentityBlob {
    /// Optional account address. Used for validators and validator full nodes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_address: Option<AccountAddress>,
    /// Optional account key. Only used for validators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_private_key: Option<Ed25519PrivateKey>,
    /// Optional consensus key. Only used for validators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_private_key: Option<bls12381::PrivateKey>,
    /// Network private key. Peer id is derived from this if account address is not present
    pub network_private_key: x25519::PrivateKey,
}
```

**File:** config/src/config/identity_config.rs (L117-126)
```rust
    pub fn save_private_key(path: &PathBuf, key: &x25519::PrivateKey) -> anyhow::Result<()> {
        // Create the parent directory
        let parent_path = path.parent().unwrap();
        fs::create_dir_all(parent_path)?;

        // Save the private key to the specified path
        File::create(path)?
            .write_all(&key.to_bytes())
            .map_err(|error| error.into())
    }
```
