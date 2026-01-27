# Audit Report

## Title
Ed25519PrivateKey Lacks Memory Zeroization on Drop - Private Keys Remain in Memory After Use

## Summary
The `Ed25519PrivateKey` struct does not implement the `Drop` trait to securely zero its 32-byte secret key material from memory when instances are destroyed. Additionally, the `ed25519-dalek` dependency is not configured with the `zeroize` feature, and no explicit zeroization occurs anywhere in the codebase. This violates the project's own secure coding guidelines and leaves validator account private keys vulnerable to recovery from memory dumps, core dumps, swap files, or cold boot attacks. [1](#0-0) [2](#0-1) 

## Finding Description

The `Ed25519PrivateKey` struct wraps `ed25519_dalek::SecretKey` and is used throughout the Aptos Core codebase for validator account authentication and transaction signing. The struct does NOT implement the `Drop` trait to securely erase its cryptographic material from memory. [3](#0-2) 

The project's secure coding guidelines explicitly state: **"Do not rely on `Drop` trait in security material treatment after the use, use zeroize to explicit destroy security material, e.g. private keys."** and **"Use zeroize for zeroing memory containing sensitive data."**

However, investigation reveals:

1. **No Drop Implementation**: No `Drop` trait implementation exists for `Ed25519PrivateKey`
2. **No Zeroize Dependency**: The `zeroize` crate is not used anywhere in the codebase (grep search returned 0 matches)
3. **Missing Feature Flag**: The `ed25519-dalek` dependency is configured WITHOUT the `zeroize` feature [4](#0-3) 

When `Ed25519PrivateKey` instances are dropped after use (e.g., after signing operations in the secure storage system, after export operations, or during key rotation), the 32 bytes of secret key material remain in memory uncleared. [5](#0-4) [6](#0-5) 

The `OnDiskStorage` implementation even acknowledges this issue in its documentation, stating it "violates the code base" by making copies of key material. [7](#0-6) 

## Impact Explanation

**Severity: Medium**

This vulnerability enables the following attack vectors:

1. **Memory Dumps**: When validator nodes crash and generate core dumps, private keys remain in the dump files
2. **Swap Files**: If memory is paged to disk, unzeroed keys can persist in swap partitions
3. **Cold Boot Attacks**: Physical attackers with access to recently powered-off machines can recover keys from RAM
4. **Debugging Access**: Attackers who gain debugging privileges can scan process memory for key material
5. **VM Snapshots**: Cloud-based validators that take memory snapshots may inadvertently preserve keys

While this requires some form of memory access (post-compromise or physical access), it represents a critical gap in defense-in-depth. Validator account keys (`account_private_key` in `IdentityBlob`) are used to authenticate validators and sign transactions. Compromise of these keys could allow:

- Unauthorized transaction signing
- Validator impersonation for account operations
- Potential theft of staked assets if combined with other vulnerabilities

This qualifies as **Medium severity** per the bug bounty criteria: "Limited funds loss or manipulation" and represents a significant protocol hardening gap that violates documented security requirements.

## Likelihood Explanation

**Likelihood: Medium-High**

The likelihood is elevated due to several factors:

1. **Common Occurrence**: Memory dumps occur regularly in production environments due to crashes, OOM conditions, or system failures
2. **Persistent Storage**: Swap files and core dumps often persist on disk long after the original process terminates
3. **Cloud Environments**: VM snapshots and memory introspection tools are standard in cloud deployments
4. **Multiple Attack Windows**: Keys are instantiated, exported, and used in multiple code paths (key generation, rotation, signing operations)
5. **Guideline Violation**: The codebase explicitly documents that this protection SHOULD exist but is missing

The attack requires post-compromise or physical access, but once obtained, key recovery from unzeroed memory is straightforward with tools like `strings`, `grep`, or specialized forensics software.

## Recommendation

Implement proper memory zeroization for `Ed25519PrivateKey` following the project's documented security guidelines:

1. **Add Zeroize Dependency**: Add the `zeroize` crate to the workspace dependencies
2. **Enable Feature Flag**: Enable the `zeroize` feature for `ed25519-dalek`
3. **Implement Drop**: Implement `Drop` for `Ed25519PrivateKey` to explicitly zero the underlying key bytes
4. **Apply to All Key Types**: Extend this protection to other private key types (BLS12381, X25519) used in the codebase

**Implementation approach** (conceptual, exact implementation depends on internal structure):

- Import the `zeroize` crate
- Implement `Drop` for `Ed25519PrivateKey` that calls `zeroize()` on the inner `SecretKey`'s byte representation
- Ensure the implementation cannot panic (per secure coding guidelines)
- Consider using `ZeroizeOnDrop` derive macro if the structure permits

The same protection should be applied to all cryptographic key material throughout the codebase, including BLS12381 consensus keys and X25519 network keys.

## Proof of Concept

```rust
// Conceptual demonstration (not a complete runnable PoC due to memory inspection requirements)
// This shows the issue conceptually

use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use rand::rngs::OsRng;
use std::ptr;

fn main() {
    // Generate a private key
    let private_key = Ed25519PrivateKey::generate(&mut OsRng);
    let key_bytes = private_key.to_bytes();
    
    // Get the memory address where the key is stored
    let key_ptr = &key_bytes as *const [u8; 32] as *const u8;
    
    println!("Key stored at: {:p}", key_ptr);
    println!("Key bytes: {:?}", key_bytes);
    
    // Drop the private key
    drop(private_key);
    drop(key_bytes);
    
    // VULNERABILITY: After drop, the memory is not zeroed
    // An attacker with memory access could still read the key material
    // In a real scenario, this would be recovered from:
    // - Core dumps: gdb, lldb inspection of crash dumps
    // - Memory dumps: /proc/PID/mem, process memory scanners
    // - Swap files: grep on /swap or pagefile
    // - Cold boot: RAM forensics tools on powered-off machines
    
    unsafe {
        // In a real attack, this data would be read from dumps, not directly
        let leaked_bytes = std::slice::from_raw_parts(key_ptr, 32);
        println!("Memory after drop (LEAKED): {:?}", leaked_bytes);
        // The key material is likely still present and readable
    }
}
```

**Note**: A complete proof-of-concept would require:
1. Forcing a core dump after key use
2. Using forensic tools to search the dump for the known key material
3. Demonstrating successful key recovery

This is difficult to demonstrate in a simple test but is well-established in security research on memory forensics.

---

**Notes:**

This vulnerability represents a clear violation of the codebase's own security requirements. While exploitation requires some form of memory access, such access is not uncommon in real-world scenarios (crashes, physical access, cloud introspection). The fix is straightforward and aligns with industry best practices for handling cryptographic material. The severity is elevated because it affects validator identity keys used for transaction signing and authentication.

### Citations

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L22-24)
```rust
/// An Ed25519 private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct Ed25519PrivateKey(pub(crate) ed25519_dalek::SecretKey);
```

**File:** RUST_SECURE_CODING.md (L89-96)
```markdown
### Drop Trait

Implement the `Drop` trait selectively, only when necessary for specific destructor logic. It's mainly used for managing external resources or memory in structures like Box or Rc, often involving unsafe code and security-critical operations.

In a Rust secure development, the implementation of the `std::ops::Drop` trait
must not panic.

Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
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

**File:** Cargo.toml (L606-606)
```text
ed25519-dalek = { version = "1.0.1", features = ["rand_core", "std", "serde"] }
```

**File:** secure/storage/src/crypto_kv_storage.rs (L26-28)
```rust
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
        self.get(name).map(|v| v.value)
    }
```

**File:** secure/storage/src/crypto_kv_storage.rs (L80-86)
```rust
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        let private_key: Ed25519PrivateKey = self.get(name)?.value;
        let (new_private_key, new_public_key) = new_ed25519_key_pair();
        self.set(&get_previous_version_name(name), private_key)?;
        self.set(name, new_private_key)?;
        Ok(new_public_key)
    }
```

**File:** secure/storage/src/on_disk.rs (L19-22)
```rust
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
```
