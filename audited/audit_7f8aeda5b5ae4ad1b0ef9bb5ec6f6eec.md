# Audit Report

## Title
InputSecret Struct Lacks Memory Zeroization on Drop, Violating Security Guidelines and Enabling Potential Memory Scraping Attacks

## Summary
The `InputSecret` struct used in the Distributed Key Generation (DKG) process does not implement memory zeroization when dropped, leaving sensitive cryptographic material in heap memory after deallocation. This violates Aptos's documented secure coding guidelines and could enable memory scraping attacks to recover DKG secrets from validator nodes.

## Finding Description

The `InputSecret` struct contains sensitive cryptographic material used in the PVSS (Publicly Verifiable Secret Sharing) dealing protocol during DKG. There are multiple implementations of this struct:

1. **Generic implementation** [1](#0-0) 

2. **BLS scalar implementation** [2](#0-1) 

Neither implementation provides a `Drop` trait that zeros the memory containing the secret field `a`. When an `InputSecret` is dropped after use, the secret value remains in unallocated heap memory until that memory is reused for other purposes.

The Aptos secure coding guidelines explicitly mandate memory zeroization for sensitive cryptographic material: [3](#0-2) [4](#0-3) 

During the DKG process, validators generate `InputSecret` values: [5](#0-4) 

After the transcript is generated, the `InputSecret` goes out of scope and is dropped without explicit memory cleanup, leaving the secret scalar value in memory.

**Attack Scenario:**
1. Validator generates `InputSecret` during DKG setup
2. `InputSecret` is used to create a PVSS transcript
3. `InputSecret` goes out of scope and is dropped
4. Secret value persists in unallocated heap memory
5. Attacker gains memory access through:
   - Memory dump after validator crash
   - Cold boot attack (physical access)
   - Memory disclosure vulnerability in other code
   - Hypervisor-level access in cloud environments
   - Speculative execution side-channel attacks
6. Attacker scans memory for scalar field patterns
7. Attacker recovers `InputSecret` values, potentially compromising DKG security

## Impact Explanation

**Severity Assessment: Low to Medium**

This vulnerability represents a **defense-in-depth failure** rather than a direct exploit. While it violates documented security guidelines and best practices, exploitation requires the attacker to first gain memory access through other means (physical access, hypervisor compromise, or another vulnerability).

According to Aptos bug bounty categories, this falls under **Low Severity** as "Minor information leaks" because:
- It requires a compound attack (memory access + scraping)
- `InputSecret` is ephemeral and not persisted by validators
- Impact is limited to DKG session secrets

However, it could escalate to **Medium Severity** if:
- Combined with a memory disclosure bug
- Used in crash dump analysis
- Exploited in multi-tenant environments where memory isolation is critical

The primary impact is the violation of the **Cryptographic Correctness** invariant and documented secure coding practices.

## Likelihood Explanation

**Likelihood: Low to Medium**

The likelihood depends on the attack context:

**Low Likelihood** for remote network attacks because:
- Requires memory access to validator nodes
- No direct network-accessible exploit path
- `InputSecret` has short lifetime (only during dealing)

**Medium Likelihood** in specific scenarios:
- Cloud-hosted validators (hypervisor access)
- Validators with crash dump collection enabled
- Multi-tenant hardware (cross-VM attacks)
- Physical access scenarios (data center compromise)
- When combined with other memory disclosure bugs

The fact that other private key types also lack zeroization [6](#0-5)  suggests this is a systemic issue across the cryptographic codebase.

## Recommendation

Implement the `Drop` trait for `InputSecret` with explicit memory zeroization using the `zeroize` crate:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(SilentDebug, SilentDisplay, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct InputSecret {
    a: Scalar,
}
```

For the generic version in chunky PVSS, implement `Drop` manually if the field type doesn't implement `Zeroize`:

```rust
impl<F: ark_ff::Field> Drop for InputSecret<F> {
    fn drop(&mut self) {
        // Zero out the memory - implementation depends on F's internals
        // May require unsafe code or conversion to bytes
    }
}
```

Additionally:
1. Add `zeroize` as a dependency in relevant `Cargo.toml` files
2. Apply the same fix to other private key types (`Ed25519PrivateKey`, etc.)
3. Add compile-time tests ensuring `ZeroizeOnDrop` is implemented
4. Update documentation emphasizing the memory safety guarantees

## Proof of Concept

```rust
#[cfg(test)]
mod memory_scraping_test {
    use super::*;
    use aptos_crypto::Uniform;
    use rand::thread_rng;
    
    #[test]
    fn test_input_secret_memory_not_zeroed() {
        let mut rng = thread_rng();
        
        // Create InputSecret and capture its address
        let secret = InputSecret::generate(&mut rng);
        let secret_bytes = secret.get_secret_a().to_bytes();
        let secret_ptr = secret_bytes.as_ptr() as usize;
        
        // Drop the secret
        drop(secret);
        
        // The memory is not zeroed - the bytes still exist in heap
        // In a real attack, an attacker with memory access could scan
        // for these patterns and recover the secret
        
        // This demonstrates that without zeroize, the secret persists
        // Note: Actually reading this memory would require unsafe code
        // and is UB in this context, but demonstrates the concept
        
        println!("Secret was at address: 0x{:x}", secret_ptr);
        println!("Memory not explicitly zeroed on drop");
    }
}
```

**Notes:**

This vulnerability is a **security best practice violation** rather than a directly exploitable critical flaw. It represents a defense-in-depth failure where sensitive cryptographic material is not properly sanitized from memory, creating potential attack surface when combined with other vulnerabilities or privileged access scenarios. The fix is straightforward and aligns with industry-standard secure coding practices for handling cryptographic secrets.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/input_secret.rs (L12-16)
```rust
#[derive(SilentDebug, SilentDisplay, PartialEq, Add)]
pub struct InputSecret<F: ark_ff::Field> {
    /// The actual secret being dealt; a scalar $a \in F$.
    a: F,
}
```

**File:** crates/aptos-crypto/src/input_secret.rs (L20-24)
```rust
#[derive(SilentDebug, SilentDisplay, PartialEq)]
pub struct InputSecret {
    /// The actual secret being dealt; a scalar $a \in F$.
    a: Scalar,
}
```

**File:** RUST_SECURE_CODING.md (L89-96)
```markdown
### Drop Trait

Implement the `Drop` trait selectively, only when necessary for specific destructor logic. It's mainly used for managing external resources or memory in structures like Box or Rc, often involving unsafe code and security-critical operations.

In a Rust secure development, the implementation of the `std::ops::Drop` trait
must not panic.

Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** dkg/src/dkg_manager/mod.rs (L330-339)
```rust
        let input_secret = DKG::InputSecret::generate(&mut rng);

        let trx = DKG::generate_transcript(
            &mut rng,
            &public_params,
            &input_secret,
            self.my_index as u64,
            &self.dealer_sk,
            &self.dealer_pk,
        );
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L23-24)
```rust
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct Ed25519PrivateKey(pub(crate) ed25519_dalek::SecretKey);
```
