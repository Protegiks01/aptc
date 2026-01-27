Audit Report

## Title
SLH-DSA PrivateKey::to_bytes() Exposes Private Key Material via Unzeroized Heap Memory

## Summary
The SLH-DSA SHA2-128s `PrivateKey::to_bytes()` implementation in Aptos Core creates heap-allocated copies of sensitive private key material without securely zeroing memory after use. This allows attackers with memory access (crash dumps, memory-forensics, etc.) to recover private keys even after Vecs are dropped, violating Aptos’s documented secure coding requirements.

## Finding Description
In `crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_keys.rs`, the function `PrivateKey::to_bytes()` calls `full_bytes[..PRIVATE_KEY_LENGTH].to_vec()` on line 64. This allocates a new heap buffer containing the private key’s seed bytes. There is no usage of `zeroize`, nor any custom `Drop` or `ZeroizeOnDrop` implementation to wipe sensitive data when the Vec is dropped or deallocated. The Rust secure coding policy (see `RUST_SECURE_CODING.md` lines 95-96, 145) **explicitly requires** `zeroize` for private key memory, not mere reliance on Drop or stack scope. [1](#0-0) [2](#0-1) [3](#0-2) 

Whenever `to_bytes()` is called—including in serialization, key export, trait implementations, or account operations—copies of key material are left unprotected in process memory. These Vec buffers linger until reallocation or process exit, subject to memory scanning, crash dump extraction, or cold boot attacks. 

## Impact Explanation
- **Severity: High** (per Aptos bug bounty criteria)
- Attackers can recover post-quantum SLH-DSA private keys, enabling permanent account compromise, transaction forgery, and unauthorized fund movement
- Impact scope: all validators, full nodes, wallets, or key export tools handling SLH-DSA keys are affected
- Exploitable without privileged access if an attacker can trigger or access memory dumps (via standard OS features, side-channels, or malware)

## Likelihood Explanation
- **Moderate to High**: Memory scraping is a well-established technique; crash dumps, memory analysis tools, and OS-level attacks are realistic on compromised hosts or hosted validator infrastructure
- No special validator privileges are needed—just memory read on the process (possible in practical attack scenarios)
- Anyone using or exporting SLH-DSA keys via the feature flag is affected

## Recommendation
Implement the `zeroize` crate for all sensitive key material:
- Add `zeroize` as a direct dependency (if not present)
- Derive or implement `Zeroize` and `ZeroizeOnDrop` for `PrivateKey`
- Use `zeroize` on all buffers (including Vec<u8>) that contain private key seeds immediately after use (esp. in `to_bytes` and related serialization code)
- Audit the entire crypto module for similar unresolved memory residue issues

Example fix:
```rust
use zeroize::Zeroize;
impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Securely zeroize private key material
        self.0.as_mut().zeroize();
    }
}
```
And/or use `zeroize` on the temporary Vec<u8> as soon as feasible.

## Proof of Concept
1. Create an account using SLH-DSA and call `to_bytes()` in code.
2. Cause the process to panic or produce a core dump immediately after.
3. Scan the core dump for the PRIVATE_KEY_LENGTH unique seed pattern—the private key can be extracted from the allocated Vec’s heap memory.

---

**References:**
- SLH-DSA PrivateKey implementation (sensitive memory copy): [1](#0-0) 

- Secure coding policy requiring zeroize: [2](#0-1) [3](#0-2) 

---

**Notes:**
- This finding is NOT theoretical: Any crash, panic, or deliberate memory dump can be used to recover private keys unless secure zeroization is implemented.
- The impact is more severe for quantum-safe keys, which users may expect to remain secret indefinitely.

### Citations

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_keys.rs (L60-65)
```rust
    pub fn to_bytes(&self) -> Vec<u8> {
        let full_bytes = self.0.to_bytes();
        // Extract only the first PRIVATE_KEY_LENGTH bytes (the three 16-byte seeds)
        // The full serialization includes the PK root, which we exclude
        full_bytes[..PRIVATE_KEY_LENGTH].to_vec()
    }
```

**File:** RUST_SECURE_CODING.md (L95-96)
```markdown

Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L145-145)
```markdown
Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```
