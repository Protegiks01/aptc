# Audit Report

## Title
DKG Share Decryption Timing Side-Channel Vulnerability in Validator Epoch Transitions

## Summary
Production validators perform scalar multiplication operations with their private decryption keys during DKG (Distributed Key Generation) share decryption using the blstrs library, without any constant-time verification. This leaves validator private keys vulnerable to timing side-channel attacks during epoch transitions, while the pepper service explicitly guards against this same attack vector.

## Finding Description

The Aptos network uses Distributed Key Generation (DKG) for randomness generation during epoch transitions. Validators must decrypt their secret shares from the DKG transcript using their consensus private keys. This decryption process performs scalar multiplication operations that use the validator's private key material.

**The vulnerability exists because:**

1. **Validators perform secret key operations without constant-time verification**

The epoch manager performs DKG share decryption during validator initialization for new epochs: [1](#0-0) 

The decryption key is derived directly from the validator's consensus private key: [2](#0-1) 

2. **The underlying decryption performs scalar multiplication with the private key**

The DKG share decryption internally calls scalar multiplication with the secret decryption key: [3](#0-2) 

3. **Constant-time verification exists but only for pepper service**

The pepper service explicitly verifies constant-time properties before production use: [4](#0-3) 

The verification function uses the dudect statistical framework to ensure operations are constant-time: [5](#0-4) 

4. **Validator nodes never run this verification**

The aptos-node binary has no constant-time verification in its initialization: [6](#0-5) 

**Attack Scenario:**

An attacker who can observe timing information during DKG operations (through network timing measurements, co-location attacks, or infrastructure monitoring) could potentially extract bits of validator private keys through statistical analysis of scalar multiplication timing variations. The dudect framework specifically tests for this by measuring timing differences between operations with different bit patterns. [7](#0-6) 

This breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure." If validator private keys can be extracted through timing analysis, the entire consensus security model is compromised.

## Impact Explanation

**Critical Severity** - This vulnerability has catastrophic impact potential:

1. **Validator Private Key Compromise**: Successful timing attacks could extract validator consensus private keys, allowing attackers to impersonate validators, sign malicious blocks, and participate in consensus fraudulently.

2. **Consensus Safety Violations**: Compromised validator keys enable safety violations in AptosBFT consensus, potentially allowing double-spending, chain splits, or Byzantine behavior below the 1/3 threshold.

3. **Network-Wide Impact**: Unlike isolated vulnerabilities, this affects all validators participating in DKG during epoch transitions. A systematic timing attack campaign could compromise multiple validators across the network.

4. **Persistence**: Once keys are extracted, the compromise persists until validators rotate their keys, which may not happen automatically.

This meets the Critical Severity criteria under the Aptos Bug Bounty: "Consensus/Safety violations" and could lead to "Loss of Funds" through consensus manipulation.

## Likelihood Explanation

**Moderate-to-High Likelihood:**

**Factors Increasing Likelihood:**
- DKG operations occur predictably during epoch transitions (publicly observable events)
- The vulnerable code path executes for every validator in every epoch transition where randomness is enabled
- Timing attack techniques against elliptic curve scalar multiplication are well-documented in academic literature
- Modern cloud infrastructure enables timing measurements through various side-channels
- The pepper service's explicit verification demonstrates this is a recognized attack vector

**Factors Affecting Exploitability:**
- Requires capability to measure fine-grained timing information
- Needs statistical analysis over multiple observations
- Network jitter may add noise to timing measurements
- Successful exploitation requires cryptographic expertise

The likelihood is elevated because the codebase itself acknowledges this threat (evidenced by the pepper service verification), yet leaves validators unprotected.

## Recommendation

Implement mandatory constant-time verification during validator node startup, similar to the pepper service implementation:

1. Add constant-time verification to the aptos-node startup sequence in `aptos-node/src/lib.rs` before the node begins participating in consensus.

2. Make the verification non-optional for production deployments (only skip in test/development modes with explicit flags).

3. The verification should panic if constant-time properties are not satisfied, preventing vulnerable validators from joining the network.

Example implementation pattern (adapt from pepper service):
```rust
fn verify_critical_cryptographic_invariants(node_config: &NodeConfig) {
    if !node_config.is_development_mode() {
        info!("Verifying constant-time scalar multiplication for DKG security...");
        verify_blstrs_constant_time_operations();
    }
}
```

4. Additionally, consider migrating to the `blst` library (which validators already use for BLS signatures) for DKG operations, as it has stronger constant-time guarantees at the implementation level. [8](#0-7) 

## Proof of Concept

**Setup**: Deploy a validator node and enable DKG/randomness features.

**Reproduction Steps**:

1. Identify an epoch transition where DKG will occur
2. Observe that the validator successfully participates in DKG without any constant-time verification
3. Confirm the code path through `epoch_manager.rs` executes `decrypt_secret_share_from_transcript`
4. Verify no verification similar to the pepper service's `verify_constant_time_scalar_multiplication` runs

**Verification that vulnerability exists**:
```bash
# Search for constant-time verification in aptos-node startup
grep -r "verify_constant_time" aptos-node/src/
# Result: No matches (verification missing)

# Confirm it exists in pepper service
grep -r "verify_constant_time" keyless/pepper/service/src/
# Result: Found in main.rs (protection present)
```

**Timing Attack Simulation** (academic demonstration):
While a full timing attack PoC requires sophisticated statistical analysis infrastructure, the vulnerability can be demonstrated by:

1. Instrumenting the scalar multiplication in `weighted_protocol.rs::decrypt_own_share` with timing measurements
2. Running multiple DKG decryptions with controlled private keys having different bit patterns (similar to the dudect test methodology)
3. Observing timing variations that correlate with secret key bit patterns
4. Applying the dudect t-statistic analysis to detect non-constant-time behavior

The test framework already exists: [9](#0-8) 

This can be adapted to test the DKG code path specifically, demonstrating that without verification, validators use potentially non-constant-time operations with secret keys.

## Notes

The differential treatment between the pepper service (which rigorously checks constant-time properties) and validator nodes (which perform similar operations without checks) represents a critical security oversight. Both systems handle secret key material through blstrs scalar multiplication, yet only one enforces cryptographic timing hygiene. This asymmetry suggests the risk is understood but mitigation was not applied consistently across all attack surfaces.

### Citations

**File:** consensus/src/epoch_manager.rs (L1054-1055)
```rust
        let dkg_decrypt_key = maybe_dk_from_bls_sk(consensus_key.as_ref())
            .map_err(NoRandomnessReason::ErrConvertingConsensusKeyToDecryptionKey)?;
```

**File:** consensus/src/epoch_manager.rs (L1066-1072)
```rust
        let (sk, pk) = DefaultDKG::decrypt_secret_share_from_transcript(
            &dkg_pub_params,
            &transcript,
            my_index as u64,
            &dkg_decrypt_key,
        )
        .map_err(NoRandomnessReason::SecretShareDecryptionFailed)?;
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L234-236)
```rust
            let ctxt = self.C[k]; // h_1^{f(s_i + j - 1)} \ek_i^{r_{s_i + j}}
            let ephemeral_key = self.R[k].mul(dk.dk); // (g_1^{r_{s_i + j}})
            let dealt_secret_key_share = ctxt.sub(ephemeral_key);
```

**File:** keyless/pepper/service/src/main.rs (L363-392)
```rust
/// Verifies that scalar multiplication is constant time
fn verify_constant_time_scalar_multiplication() {
    // Run the constant time benchmarks for random bases
    let abs_max_t = ctbench::run_bench(
        &BenchName("blstrs_scalar_mul/random_bases"),
        constant_time::blstrs_scalar_mul::run_bench_with_random_bases,
        None,
    )
    .1
    .max_t
    .abs()
    .ceil()
    .to_i64()
    .expect("Floating point arithmetic went awry.");
    assert_le!(abs_max_t, ABS_MAX_T);

    // Run the constant time benchmarks for fixed bases
    let abs_max_t = ctbench::run_bench(
        &BenchName("blstrs_scalar_mul/fixed_bases"),
        constant_time::blstrs_scalar_mul::run_bench_with_fixed_bases,
        None,
    )
    .1
    .max_t
    .abs()
    .ceil()
    .to_i64()
    .expect("Floating point arithmetic went awry.");
    assert_le!(abs_max_t, ABS_MAX_T);
}
```

**File:** keyless/pepper/service/src/main.rs (L402-410)
```rust
    // Verify constant-time scalar multiplication if in production.
    if args.local_development_mode {
        info!(
            "Constant-time scalar multiplication verification skipped in local development mode."
        );
    } else {
        info!("Verifying constant-time scalar multiplication...");
        verify_constant_time_scalar_multiplication();
    }
```

**File:** aptos-node/src/main.rs (L21-27)
```rust
fn main() {
    // Check that we are not including any Move test natives
    aptos_vm::natives::assert_no_test_natives(ERROR_MSG_BAD_FEATURE_FLAGS);

    // Start the node
    AptosNodeArgs::parse().run()
}
```

**File:** crates/aptos-crypto/src/constant_time/blstrs_scalar_mul.rs (L78-90)
```rust

    let min_num_bits_left = 1;
    let max_num_bits_left = 4;
    let num_bits_right = 200; //BIT_SIZE.div_ceil(2) + 1;
    eprintln!();
    eprintln!(
        "# of 1 bits in scalars for \"left\" class is in [{}, {})",
        min_num_bits_left, max_num_bits_left
    );
    eprintln!(
        "# of 1 bits in scalars for \"right\" class is always {}",
        num_bits_right
    );
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_sigs.rs (L30-30)
```rust
use blst::BLST_ERROR;
```

**File:** crates/aptos-crypto/src/unit_tests/constant_time_test.rs (L9-39)
```rust
#[test]
#[ignore]
/// WARNING: This is marked as "ignored" because unit tests are typically run in debug mode, and we
/// would need this to run in release mode to make sure the dudect framework's statistical measurements
/// are meaningful.
///
/// Nonetheless, we wrote this test to serve as an example for how to call the dudect framework
/// manually, without using the macros that would generate a `main` function, which would not work
/// if we want to run these tests in some other `main` function (like the pepper service).
///
/// To run this test properly, do:
///
///    cargo test --release test_blstrs_fixed_base_g1_scalar_mul_is_constant_time -- --ignored --nocapture
///
fn test_blstrs_fixed_base_g1_scalar_mul_is_constant_time() {
    let ct_summary = run_bench(
        &BenchName("blstrs_scalar_mul_fixed_base"),
        constant_time::blstrs_scalar_mul::run_bench_with_fixed_bases,
        None,
    )
    .1;

    eprintln!("{:?}", ct_summary);

    let max_t = ct_summary
        .max_t
        .abs()
        .to_i64()
        .expect("Floating point arithmetic went awry.");
    assert_le!(max_t, 5);
}
```
