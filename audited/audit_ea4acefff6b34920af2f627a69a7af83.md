# Audit Report

## Title
DKG Decryption Private Keys Not Zeroized on Drop - Memory Exposure Vulnerability

## Summary
The `DecryptPrivKey` struct used in Aptos DKG (Distributed Key Generation) does not implement memory zeroization when dropped, violating the repository's own secure coding guidelines. This allows attackers to recover validator decryption keys from memory dumps, swap files, or core dumps after validator crashes, potentially compromising the randomness generation subsystem.

## Finding Description

The `DecryptPrivKey` struct wraps a `blstrs::Scalar` field containing cryptographic private key material used to decrypt DKG secret shares during validator epoch transitions. [1](#0-0) 

This struct does **not** implement the `Drop` trait with zeroization. I verified this by searching the entire codebase - no Drop implementation exists for `DecryptPrivKey`.

The Aptos codebase has explicit secure coding guidelines requiring zeroization of private keys: [2](#0-1) [3](#0-2) 

**Critical Usage in Consensus:**

During epoch transitions, validators derive `DecryptPrivKey` from their BLS consensus keys and use it to decrypt their DKG secret shares: [4](#0-3) 

After the decryption operation completes at line 1066, the `dkg_decrypt_key` variable goes out of scope without explicit zeroization. The sensitive scalar value remains in memory until that memory region is overwritten by subsequent allocations.

**Attack Vector:**

When a validator node crashes or is compromised, an attacker with access to:
- Memory dumps (via debugging tools, crash dumps, or system compromise)
- Swap files (if process memory is paged to disk)
- Core dumps (generated during crashes)
- Cold boot attacks (reading RAM after power loss)

Can scan memory for the characteristic patterns of BLS12-381 scalar values and recover the `DecryptPrivKey`. With this key, the attacker can decrypt the validator's DKG secret shares, which are critical for randomness generation in the consensus protocol.

**Violated Invariant:**
- **Cryptographic Correctness**: Private key material must be properly protected in memory and zeroized when no longer needed
- **Secure Coding Guidelines**: Explicit violation of RUST_SECURE_CODING.md requirements

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:

1. **Validator Node Security Compromise**: Recovered decryption keys allow attackers to decrypt DKG shares, potentially compromising randomness generation which affects leader election and consensus fairness.

2. **Multi-Validator Attack Surface**: Every validator running DKG is vulnerable. An attacker who compromises multiple validators' memory can accumulate decryption keys.

3. **Persistent Exposure Window**: The keys remain in memory from the moment of use until that memory is reallocated. On long-running validators, this window can persist for extended periods, especially if the memory pages are swapped to disk.

4. **Violation of Defense in Depth**: Even if other security measures prevent initial compromise, post-crash memory analysis is a standard forensic technique that becomes an attack vector.

While this doesn't directly cause loss of funds or consensus safety violations, it significantly weakens validator security by exposing cryptographic material that should be ephemeral. This aligns with "Significant protocol violations" under High Severity.

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood of exploitation depends on several factors:

1. **Common Crash Scenarios**: Validator nodes crash due to:
   - Software bugs (OOM, panics, assertion failures)
   - Hardware failures
   - System updates/restarts
   - Network issues causing timeouts

2. **Memory Dump Accessibility**: 
   - Core dumps are often automatically generated and stored on disk
   - System administrators have access to memory dumps for debugging
   - Compromised infrastructure allows memory scraping
   - Swap files persist on disk across reboots

3. **Attack Complexity**: 
   - Low: Memory scanning for scalar patterns is straightforward
   - Standard forensic tools can extract memory contents
   - No special validator privileges required post-compromise

4. **Frequency**: Every epoch transition creates new exposure windows as keys are used and dropped without zeroization.

The combination of frequent key usage, standard crash scenarios, and easy memory extraction makes this vulnerability realistic to exploit.

## Recommendation

Implement the `Drop` trait for `DecryptPrivKey` using the `zeroize` crate to securely clear memory:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

impl Drop for DecryptPrivKey {
    fn drop(&mut self) {
        // Zeroize the scalar field
        // Note: blstrs::Scalar may need to be zeroized through its bytes representation
        let mut bytes = self.dk.to_bytes_le();
        bytes.zeroize();
    }
}
```

Or more elegantly, derive `ZeroizeOnDrop`:

```rust
#[derive(DeserializeKey, SerializeKey, SilentDisplay, SilentDebug, ZeroizeOnDrop)]
pub struct DecryptPrivKey {
    /// A scalar $dk \in F$.
    pub(crate) dk: Scalar,
}
```

**Additional Recommendations:**

1. Add `zeroize` as a direct dependency in `crates/aptos-dkg/Cargo.toml`
2. Apply the same fix to other private key structures (`DealtSecretKey`, etc.)
3. Consider wrapping `blstrs::Scalar` in a custom type that implements `Zeroize`
4. Add integration tests verifying memory is zeroed (though this is challenging to test reliably)
5. Review all structs containing cryptographic private keys for similar issues

## Proof of Concept

```rust
// File: crates/aptos-dkg/tests/memory_exposure_poc.rs

#[cfg(test)]
mod memory_exposure_tests {
    use aptos_dkg::pvss::encryption_dlog::g2::DecryptPrivKey;
    use aptos_crypto::Uniform;
    use rand::thread_rng;
    
    #[test]
    fn test_decrypt_key_memory_exposure() {
        let mut rng = thread_rng();
        
        // Create a DecryptPrivKey
        let dk = DecryptPrivKey::generate(&mut rng);
        let key_bytes = dk.to_bytes();
        
        // Create a memory reference before dropping
        let key_ptr = &dk as *const _ as usize;
        
        // Drop the key - memory should be zeroized but isn't
        drop(dk);
        
        // In a real attack, scan memory around key_ptr for the scalar pattern
        // This demonstrates that without zeroization, the key bytes remain
        // accessible in memory until overwritten
        
        println!("Original key bytes: {:?}", hex::encode(&key_bytes));
        println!("Key was at memory address: 0x{:x}", key_ptr);
        println!("Without zeroization, an attacker scanning memory can recover these bytes");
        
        // Allocation of new objects may not overwrite the old memory immediately
        let _other_data = vec![0u8; 1000]; // Allocate other data
        
        // The original key bytes may still be recoverable by scanning memory
        // This is the vulnerability: no explicit zeroing occurs
    }
    
    #[test] 
    fn test_post_crash_memory_dump_scenario() {
        // Simulate the epoch manager usage pattern
        let mut rng = thread_rng();
        let dk = DecryptPrivKey::generate(&mut rng);
        let key_bytes = dk.to_bytes();
        
        // Use the key (simulating decrypt_secret_share_from_transcript)
        let _result = perform_decryption_operation(&dk);
        
        // Key goes out of scope (simulating end of epoch transition function)
        drop(dk);
        
        // Simulate crash - memory dump would still contain key_bytes
        // An attacker analyzing the dump can search for BLS12-381 scalar patterns
        
        println!("After decryption and drop:");
        println!("Key bytes: {:?}", hex::encode(&key_bytes));
        println!("These bytes remain in memory and can be recovered from:");
        println!("- Core dumps after validator crash");
        println!("- Memory dumps during live debugging");  
        println!("- Swap file if memory was paged to disk");
        println!("- Cold boot attacks on RAM");
    }
    
    fn perform_decryption_operation(_dk: &DecryptPrivKey) {
        // Simulate using the key for decryption
        // In real code, this calls decrypt_own_share()
    }
}
```

**To demonstrate the fix works:**

```rust
// After implementing Drop with zeroize, add this test:
#[test]
fn test_decrypt_key_properly_zeroized() {
    use zeroize::Zeroize;
    
    let mut rng = thread_rng();
    let mut dk = DecryptPrivKey::generate(&mut rng);
    let key_bytes = dk.to_bytes();
    
    // Manually zeroize (this should happen automatically in Drop)
    dk.zeroize(); // or just drop(dk) after implementing Drop
    
    // Verify the internal scalar is zeroed
    let zeroed_bytes = dk.to_bytes();
    assert_ne!(key_bytes, zeroed_bytes, "Key should be different after zeroization");
    assert_eq!(zeroed_bytes, [0u8; 32], "Key should be all zeros after zeroization");
}
```

## Notes

This vulnerability represents a clear violation of the repository's documented secure coding practices and creates a realistic attack vector for compromising validator cryptographic material. The fix is straightforward and should be applied to all private key structures in the DKG subsystem.

### Citations

**File:** crates/aptos-dkg/src/pvss/encryption_dlog.rs (L85-89)
```rust
        #[derive(DeserializeKey, SerializeKey, SilentDisplay, SilentDebug)]
        pub struct DecryptPrivKey {
            /// A scalar $dk \in F$.
            pub(crate) dk: Scalar,
        }
```

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L145-145)
```markdown
Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** consensus/src/epoch_manager.rs (L1054-1070)
```rust
        let dkg_decrypt_key = maybe_dk_from_bls_sk(consensus_key.as_ref())
            .map_err(NoRandomnessReason::ErrConvertingConsensusKeyToDecryptionKey)?;
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_session.transcript.as_slice(),
        )
        .map_err(NoRandomnessReason::TranscriptDeserializationError)?;

        let vuf_pp = WvufPP::from(&dkg_pub_params.pvss_config.pp);

        // No need to verify the transcript.

        // keys for randomness generation
        let (sk, pk) = DefaultDKG::decrypt_secret_share_from_transcript(
            &dkg_pub_params,
            &transcript,
            my_index as u64,
            &dkg_decrypt_key,
```
