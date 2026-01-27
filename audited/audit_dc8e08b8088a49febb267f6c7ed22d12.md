# Audit Report

## Title
Cryptographic Secret Keys Not Zeroized - Memory Exposure Risk in DKG Randomness Implementation

## Summary
Cryptographic secret keys used in Aptos's Distributed Key Generation (DKG) and Weighted Verifiable Unpredictable Function (WVUF) implementations are stored as `blstrs::Scalar` types without explicit memory zeroization. This violates Aptos's documented secure coding guidelines and creates potential exposure vectors through memory dumps, swap files, or memory disclosure vulnerabilities.

## Finding Description

The Aptos codebase explicitly defines secure coding requirements for cryptographic material handling: [1](#0-0) [2](#0-1) 

However, the DKG implementation violates these guidelines in multiple locations:

**Location 1: BlsWUF Implementation** [3](#0-2) 

**Location 2: PinkasWUF Implementation (Production Code)** [4](#0-3) 

The production implementation uses PinkasWUF: [5](#0-4) 

These secret keys are wrapped in `RandKeys` and stored in long-lived validator processes: [6](#0-5) 

The keys are then wrapped in `Arc` for shared access throughout consensus: [7](#0-6) [8](#0-7) 

These keys persist for entire epochs (hours to days) and are used to create randomness shares: [9](#0-8) 

No zeroize implementation exists for these Scalar types in the codebase:
- No `impl Zeroize for Scalar` wrappers
- No explicit zeroization before dropping
- Reliance on default `Drop` behavior which the guidelines explicitly warn against

**Attack Scenarios:**
1. **Core Dump Exposure**: Validator crashes → core dump written to disk → attacker with filesystem access extracts unzeroed secret keys
2. **Swap File Leakage**: Memory pages swapped to disk → attacker with disk access reads swap → finds secret key material
3. **Memory Disclosure Chain**: Another vulnerability allows arbitrary memory reads → attacker targets validator process → extracts secret keys from heap
4. **Cold Boot Attack**: Physical access to validator hardware → memory extraction before volatile RAM fully degrades → recovery of cryptographic material

## Impact Explanation

This issue is categorized as **Medium Severity** with significant caveats:

**Why NOT Critical/High:**
- Does NOT directly cause fund loss, consensus breaks, or network partitions
- Requires privileged system access (root, physical access) or exploitation of another vulnerability
- Compromising a single validator's key share does not break the threshold-based randomness scheme
- Cannot be exploited by unprivileged network peers, transaction senders, or remote attackers

**Why Medium:**
- Violates documented Aptos security guidelines
- Creates defense-in-depth weakness that could enable escalation
- Long-lived secret material (epoch-duration) increases exposure window
- Could contribute to coordinated attacks if combined with other compromises
- Memory-based forensics could recover keys from crashed/compromised validators

**Critical Limitation**: This vulnerability **fails the "unprivileged attacker" validation criterion**. An attacker who already has root access to a validator or can trigger memory disclosure has already achieved significant system compromise. This is more accurately a **security hardening issue** than a standalone exploitable vulnerability.

## Likelihood Explanation

**Likelihood: Low to Medium**

Exploitation requires one of these preconditions:
- **Root/Administrator Access**: Attacker compromises validator OS-level security
- **Physical Access**: Cold boot attacks, hardware extraction (data center scenarios)
- **Memory Disclosure Bug**: Another vulnerability enables arbitrary process memory reads
- **Crash Forensics**: Validator crashes and attacker accesses resulting artifacts

Each precondition represents significant attacker capability beyond typical threat models. However, defense-in-depth principles suggest eliminating unnecessary attack surfaces even when exploitation requires elevated privileges.

## Recommendation

Implement explicit memory zeroization for all cryptographic secret keys using the `zeroize` crate:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

// Wrapper for Scalar to ensure zeroization
#[derive(ZeroizeOnDrop)]
struct ZeroizableScalar(Scalar);

impl Drop for ZeroizableScalar {
    fn drop(&mut self) {
        // Explicitly zero the scalar's internal representation
        // Note: This requires accessing Scalar's internal bytes
        let bytes = self.0.to_bytes_le();
        bytes.zeroize();
    }
}

// Update type definitions to use zeroizable wrappers
type SecretKeyShare = Vec<ZeroizableScalar>;
type AugmentedSecretKeyShare = (ZeroizableScalar, Self::SecretKeyShare);
```

Alternatively, if wrapping is impractical, implement explicit zeroization at key lifecycle boundaries:
- Before dropping `RandKeys` structures
- During epoch transitions
- When error paths cause early returns
- In destructors of long-lived structures containing secret material

**Note**: The `blstrs` crate's `Scalar` type does not implement `Zeroize` by default. Aptos may need to contribute upstream or implement manual byte-level zeroization.

## Proof of Concept

**Note**: This PoC demonstrates the guideline violation but cannot show actual exploitation without privileged system access.

```rust
// Hypothetical memory forensics test (requires root/debug privileges)
#[test]
#[ignore] // Requires privileged execution
fn test_secret_key_memory_persistence() {
    use blstrs::Scalar;
    use aptos_crypto::blstrs::random_scalar;
    use rand::thread_rng;
    
    // Simulate secret key creation
    let secret_key = random_scalar(&mut thread_rng());
    let memory_address = &secret_key as *const Scalar as usize;
    
    // Use the key
    let _computation = secret_key * Scalar::from(42u64);
    
    // Drop the key
    drop(secret_key);
    
    // In a real attack: attacker with memory access reads from memory_address
    // Expected: memory should be zeroed
    // Actual: memory likely still contains the scalar value
    
    // This test cannot actually read the memory without unsafe code
    // and would require privileged debugging capabilities
}
```

**Real-World Demonstration**: An auditor with access to a test validator could:
1. Run validator with DKG enabled
2. Trigger controlled crash or use debugger to dump process memory
3. Search memory dump for known patterns of `Scalar` representations
4. Verify that dropped secret keys remain in memory unzeroed

---

**IMPORTANT CAVEAT**: This report documents a **security hardening opportunity** rather than a directly exploitable vulnerability by unprivileged attackers. The issue fails critical validation criteria (requires privileged access, no standalone exploitation path, limited practical impact). It represents a violation of Aptos's own secure coding standards that should be remediated as part of defense-in-depth practices, but does not meet the threshold for a standalone bug bounty submission under the "unprivileged attacker" requirement.

### Citations

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** crates/aptos-dkg/src/weighted_vuf/bls/mod.rs (L48-48)
```rust
    type SecretKeyShare = Vec<Scalar>;
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L66-66)
```rust
    type AugmentedSecretKeyShare = (Scalar, Self::SecretKeyShare);
```

**File:** types/src/randomness.rs (L11-11)
```rust
pub type WVUF = weighted_vuf::pinkas::PinkasWUF;
```

**File:** types/src/randomness.rs (L104-114)
```rust
pub struct RandKeys {
    // augmented secret / public key share of this validator, obtained from the DKG transcript of last epoch
    pub ask: ASK,
    pub apk: APK,
    // certified augmented public key share of all validators,
    // obtained from all validators in the new epoch,
    // which necessary for verifying randomness shares
    pub certified_apks: Vec<OnceCell<APK>>,
    // public key share of all validators, obtained from the DKG transcript of last epoch
    pub pk_shares: Vec<PKShare>,
}
```

**File:** consensus/src/rand/rand_gen/types.rs (L88-92)
```rust
        let share = Share {
            share: WVUF::create_share(
                &rand_config.keys.ask,
                bcs::to_bytes(&rand_metadata).unwrap().as_slice(),
            ),
```

**File:** consensus/src/rand/rand_gen/types.rs (L588-588)
```rust
    keys: Arc<RandKeys>,
```

**File:** consensus/src/rand/rand_gen/types.rs (L617-617)
```rust
            keys: Arc::new(keys),
```
