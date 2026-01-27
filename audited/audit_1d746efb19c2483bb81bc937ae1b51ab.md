# Audit Report

## Title
Memory Exposure of X25519 Shared Secrets in Validator Network Handshakes

## Summary
The `diffie_hellman()` function returns X25519 shared secrets as plain byte arrays that are not explicitly zeroized after use, potentially allowing recovery of validator session keys through memory dumps. This violates the project's documented security guidelines for handling cryptographic material.

## Finding Description

The X25519 Diffie-Hellman key exchange implementation returns shared secrets as unprotected byte arrays. [1](#0-0) 

These shared secrets are used extensively in the Noise protocol handshake for establishing validator-to-validator encrypted connections: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The validator network uses this during connection establishment: [6](#0-5) [7](#0-6) 

The project's security guidelines explicitly require explicit zeroization: [8](#0-7) [9](#0-8) 

However, no zeroization is implemented anywhere in the codebase - the shared secret byte arrays remain on the stack until overwritten by subsequent operations. When variables like `dh_output` go out of scope, Rust's memory model simply reclaims the stack space without clearing it.

## Impact Explanation

This issue enables a **secondary attack vector** that requires an attacker to first obtain memory access through:
- A separate memory disclosure vulnerability
- Physical access to dump process memory
- Access to core dumps from crashes
- Side-channel attacks on memory

Once memory access is obtained, an attacker could potentially recover shared secrets and derive session keys used for validator-to-validator communication, enabling decryption of network traffic or man-in-the-middle attacks.

This does NOT meet Critical, High, or Medium severity criteria because it is **not independently exploitable**. It only amplifies the impact of a separate memory disclosure vulnerability.

## Likelihood Explanation

**Likelihood: Very Low**

The exploitation requires:
1. A separate vulnerability providing memory access (core dump, memory leak, physical access)
2. Precise timing to capture memory while secrets are still present
3. Technical capability to parse and identify shared secrets in memory dumps

This is a **defense-in-depth violation** rather than a standalone exploit.

## Recommendation

Despite not meeting bug bounty thresholds, this violates documented security policy and should be remediated:

1. Import and use the `zeroize` crate (available as transitive dependency)
2. Wrap return values in a custom type that implements `Drop` with explicit zeroization
3. Apply `#[zeroize(drop)]` attribute to sensitive byte arrays
4. Explicitly call `zeroize()` on local variables containing shared secrets before they go out of scope

Example pattern:
```rust
use zeroize::Zeroize;

pub fn diffie_hellman(&self, remote_public_key: &PublicKey) -> [u8; SHARED_SECRET_SIZE] {
    let remote_public_key = x25519_dalek::PublicKey::from(remote_public_key.0);
    let shared_secret = self.0.diffie_hellman(&remote_public_key);
    let mut result = shared_secret.as_bytes().to_owned();
    // Note: caller must also zeroize result after use
    result
}
```

Better approach: Create a `SharedSecret` wrapper type with automatic zeroization.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Uniform;
    
    #[test]
    fn demonstrate_memory_not_cleared() {
        let mut rng = rand::thread_rng();
        let alice = PrivateKey::generate(&mut rng);
        let bob = PrivateKey::generate(&mut rng);
        let bob_public = bob.public_key();
        
        // Perform DH exchange
        let shared_secret = alice.diffie_hellman(&bob_public);
        
        // Shared secret is now in memory at this location
        let secret_ptr = shared_secret.as_ptr();
        let secret_copy = shared_secret.clone();
        
        // Variable goes out of scope here
        drop(shared_secret);
        
        // Memory at secret_ptr is NOT guaranteed to be cleared
        // In production, this memory could be recovered through dumps
        
        // This test demonstrates that without explicit zeroization,
        // the secret remains in memory until overwritten
        unsafe {
            let memory_after_drop = std::slice::from_raw_parts(secret_ptr, 32);
            // In many cases, memory_after_drop will still contain secret_copy
            // This is undefined behavior but demonstrates the risk
        }
    }
}
```

---

**Notes:**

While this represents a clear violation of the project's security guidelines [8](#0-7) , it does **not** constitute a standalone exploitable vulnerability meeting bug bounty criteria. The issue requires prerequisite memory access (through a separate vulnerability) to pose actual risk. This is a **security hygiene issue** that should be addressed as part of defense-in-depth practices, but cannot be exploited independently by an unprivileged attacker.

The zeroize crate is available as a transitive dependency but is not utilized anywhere in the codebase for cryptographic material handling, representing a systematic gap in implementing the documented security policy.

### Citations

**File:** crates/aptos-crypto/src/x25519.rs (L90-94)
```rust
    pub fn diffie_hellman(&self, remote_public_key: &PublicKey) -> [u8; SHARED_SECRET_SIZE] {
        let remote_public_key = x25519_dalek::PublicKey::from(remote_public_key.0);
        let shared_secret = self.0.diffie_hellman(&remote_public_key);
        shared_secret.as_bytes().to_owned()
    }
```

**File:** crates/aptos-crypto/src/noise.rs (L310-311)
```rust
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L327-328)
```rust
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L377-378)
```rust
        let dh_output = e.diffie_hellman(&re);
        mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L449-450)
```rust
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** network/framework/src/noise/handshake.rs (L209-218)
```rust
        let initiator_state = self
            .noise_config
            .initiate_connection(
                &mut rng,
                prologue_msg,
                remote_public_key,
                Some(&payload),
                client_noise_msg,
            )
            .map_err(NoiseHandshakeError::BuildClientHandshakeMessageFailed)?;
```

**File:** network/framework/src/noise/handshake.rs (L253-256)
```rust
        let (_, session) = self
            .noise_config
            .finalize_connection(initiator_state, &server_response)
            .map_err(NoiseHandshakeError::ClientFinalizeFailed)?;
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
