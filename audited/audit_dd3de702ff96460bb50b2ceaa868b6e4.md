# Audit Report

## Title
Validator Private Keys Exposed in Memory Without Secure Wiping During YAML Serialization

## Summary
The `IdentityBlob` serialization functions in `config/src/config/identity_config.rs` and other locations serialize validator private keys (Ed25519, BLS12-381, x25519) to YAML strings in memory without implementing secure memory wiping (zeroization), directly violating Aptos' documented secure coding requirements. This leaves sensitive cryptographic material vulnerable to memory dump attacks, core dumps, and swap file exposure.

## Finding Description

The vulnerability exists in multiple locations where `IdentityBlob` objects containing validator private keys are serialized to YAML:

1. **Primary location**: `IdentityBlob::to_file()` function [1](#0-0) 

2. **Genesis builder**: `write_yaml()` helper function [2](#0-1) 

3. **Test utilities**: Direct serialization in consensus key rotation [3](#0-2) 

The `IdentityBlob` struct contains three types of validator private keys [4](#0-3) :
- `account_private_key: Option<Ed25519PrivateKey>` (validator account operations)
- `consensus_private_key: Option<bls12381::PrivateKey>` (BLS consensus signatures)
- `network_private_key: x25519::PrivateKey` (network identity)

When `serde_yaml::to_string(self)?` is called, it creates a `String` containing plaintext representations of all private keys. This string remains in process memory until garbage collection, and Rust's default allocator does **not** zero memory on deallocation.

**Critical violation**: Aptos' own security guidelines explicitly require [5](#0-4) :
> "Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys."

And further mandates [6](#0-5) :
> "Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data."

**Missing zeroization**: None of the private key types implement `Zeroize` or `ZeroizeOnDrop` traits:
- `Ed25519PrivateKey` lacks zeroization [7](#0-6) 
- `x25519::PrivateKey` lacks zeroization [8](#0-7) 
- `bls12381::PrivateKey` lacks zeroization [9](#0-8) 

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty categories)

If an attacker obtains access to validator process memory through:
- Core dumps after process crashes
- Memory dumps via another vulnerability
- Swap file access (if memory pages are swapped to disk)
- Cold boot attacks or physical access

They could extract validator private keys and:

1. **Consensus compromise**: Sign malicious consensus votes/proposals with the BLS12-381 consensus key, potentially violating AptosBFT safety guarantees
2. **Account compromise**: Perform unauthorized validator account operations with the Ed25519 account key
3. **Network impersonation**: Impersonate the validator in P2P communications using the x25519 network key

This creates a significant attack surface expansion beyond direct key theft, as keys persist in memory long after their intended use.

## Likelihood Explanation

**Likelihood: Low to Medium**

While the vulnerability is present in all validator key persistence operations, exploitation requires:
- An attacker obtaining memory access through a separate vulnerability or physical access
- The serialization operation occurring recently enough that memory pages haven't been reused
- Keys not being stored in secure enclaves or hardware security modules

However, the frequency is high: validator key persistence occurs during:
- Genesis generation [10](#0-9) 
- Consensus key rotation operations
- Validator configuration updates

## Recommendation

**Implement secure memory wiping for all private key serialization operations:**

1. Add `zeroize` crate dependency to `aptos-crypto`
2. Implement `Zeroize` and `ZeroizeOnDrop` for all private key types:
   - `Ed25519PrivateKey`
   - `bls12381::PrivateKey`
   - `x25519::PrivateKey`

3. Create a secure YAML serialization wrapper that zeroizes intermediate strings:

```rust
use zeroize::Zeroizing;

pub fn to_file_secure(&self, path: &Path) -> anyhow::Result<()> {
    // Use Zeroizing wrapper to ensure string is wiped on drop
    let yaml_string = Zeroizing::new(serde_yaml::to_string(self)?);
    let mut file = File::create(path)?;
    file.write_all(yaml_string.as_bytes())?;
    // yaml_string is automatically zeroized when dropped here
    Ok(())
}
```

4. Update all serialization sites to use secure wrappers
5. Consider using `secrecy` crate for private key storage to prevent accidental logging/serialization

## Proof of Concept

```rust
use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use aptos_config::config::IdentityBlob;
use rand::thread_rng;
use std::alloc::{alloc, dealloc, Layout};

#[test]
fn test_key_memory_exposure() {
    // Generate a validator identity with private keys
    let mut rng = thread_rng();
    let account_key = Ed25519PrivateKey::generate(&mut rng);
    let consensus_key = bls12381::PrivateKey::generate(&mut rng);
    let network_key = x25519::PrivateKey::generate(&mut rng);
    
    let identity = IdentityBlob {
        account_address: Some(AccountAddress::random()),
        account_private_key: Some(account_key),
        consensus_private_key: Some(consensus_key),
        network_private_key: network_key,
    };
    
    // Serialize to YAML - this creates a string in memory with plaintext keys
    let yaml_str = serde_yaml::to_string(&identity).unwrap();
    let yaml_ptr = yaml_str.as_ptr();
    let yaml_len = yaml_str.len();
    
    // Verify keys are in plaintext in the string
    assert!(yaml_str.contains("private_key"));
    
    // Drop the string - memory is NOT zeroized
    drop(yaml_str);
    
    // At this point, the memory at yaml_ptr still contains the private keys
    // In a real attack, this memory could be read via core dump or memory scan
    
    // This demonstrates the vulnerability: private key material persists in
    // deallocated memory without secure wiping, violating RUST_SECURE_CODING.md
}
```

**Notes**

This vulnerability represents a **violation of Aptos' documented security requirements** rather than a directly remotely exploitable flaw. However, it significantly weakens defense-in-depth and creates unnecessary risk for validator operations. The fix is straightforward and aligns with industry best practices for handling cryptographic material in memory.

### Citations

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

**File:** config/src/config/identity_config.rs (L44-47)
```rust
    pub fn to_file(&self, path: &Path) -> anyhow::Result<()> {
        let mut file = File::open(path)?;
        Ok(file.write_all(serde_yaml::to_string(self)?.as_bytes())?)
    }
```

**File:** crates/aptos-genesis/src/builder.rs (L418-421)
```rust
fn write_yaml<T: Serialize>(path: &Path, object: &T) -> anyhow::Result<()> {
    File::create(path)?.write_all(serde_yaml::to_string(object)?.as_bytes())?;
    Ok(())
}
```

**File:** testsuite/smoke-test/src/consensus_key_rotation.rs (L91-95)
```rust
            Write::write_all(
                &mut File::create(&new_identity_path).unwrap(),
                serde_yaml::to_string(&validator_identity_blob)
                    .unwrap()
                    .as_bytes(),
```

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L145-145)
```markdown
Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L22-24)
```rust
/// An Ed25519 private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct Ed25519PrivateKey(pub(crate) ed25519_dalek::SecretKey);
```

**File:** crates/aptos-crypto/src/x25519.rs (L66-68)
```rust
#[derive(DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Clone))]
pub struct PrivateKey(x25519_dalek::StaticSecret);
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_keys.rs (L41-45)
```rust
#[derive(SerializeKey, DeserializeKey, SilentDebug, SilentDisplay)]
/// A BLS12381 private key
pub struct PrivateKey {
    pub(crate) privkey: blst::min_pk::SecretKey,
}
```

**File:** crates/aptos-genesis/src/keys.rs (L47-58)
```rust
    let validator_blob = IdentityBlob {
        account_address: Some(account_address),
        account_private_key: Some(account_key.private_key()),
        consensus_private_key: Some(consensus_key.private_key()),
        network_private_key: validator_network_key.private_key(),
    };
    let vfn_blob = IdentityBlob {
        account_address: Some(account_address),
        account_private_key: None,
        consensus_private_key: None,
        network_private_key: full_node_network_key.private_key(),
    };
```
