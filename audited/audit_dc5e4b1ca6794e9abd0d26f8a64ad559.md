# Audit Report

## Title
Partial Aggregation State Corruption in DKG Transcript Aggregation Without Rollback

## Summary
The `aggregate_with()` implementations across all PVSS schemes in the Aptos DKG module modify the accumulator transcript in-place without transactional semantics. If aggregation fails partway through (due to dimension mismatches or panics), the accumulator is left in a partially modified, invalid state with no rollback mechanism, potentially breaking subsequent DKG operations.

## Finding Description

All implementations of `Aggregatable::aggregate_with()` in the Aptos DKG codebase follow a dangerous pattern: they modify the accumulator state (`&mut self`) progressively without validation, then can fail partway through, leaving corrupted state. [1](#0-0) 

The chunky PVSS implementation demonstrates the vulnerability:

1. **Line 395**: `self.V0` is modified first (irreversible)
2. **Lines 397-406**: Nested loops modify `Vs` and `Cs` progressively
3. **Lines 408-413**: `Rs` is modified using `zip()` which silently truncates on length mismatch

**Critical Issues:**

1. **Only Debug Assertions**: Validation uses `debug_assert` (lines 388-392), which is compiled out in release builds [2](#0-1) 

2. **No Pre-Validation**: The function modifies state BEFORE checking compatibility
3. **Panic Points**: Accessing `other.Vs[i][j]` or `other.Cs[i][j][k]` will panic if `other` has smaller inner dimensions
4. **Silent Data Loss**: The `zip()` operation silently truncates if lengths differ, leading to incomplete aggregation without error

The same pattern exists in all other PVSS implementations: [3](#0-2) [4](#0-3) 

**Verification Gaps:**

While transcripts are verified before aggregation: [5](#0-4) 

The verification only checks that each **individual transcript** is structurally valid, not that two transcripts are **compatible for aggregation**. The `check_sizes()` function validates outer dimensions but not inner structure: [6](#0-5) 

**Corruption Scenario:**

When aggregation is called with `.expect()`: [7](#0-6) 

If `aggregate_with()` panics after partial modification:
- The accumulator transcript has `V0`, some `Vs[i][j]`, and some `Cs[i][j][k]` modified
- Other fields remain unmodified
- The transcript is now in an **invalid hybrid state** that will fail all subsequent operations (decryption, reconstruction, verification)

## Impact Explanation

**Severity: High**

While this requires validator participation (not exploitable by unprivileged attackers), it represents a significant protocol violation with the following impacts:

1. **DKG Protocol Failure**: Corrupted transcripts cannot complete secret reconstruction, blocking randomness generation
2. **State Inconsistency**: Different validators may end up with different aggregated states if panics occur non-deterministically
3. **Network Liveness Impact**: DKG failure prevents epoch transitions and validator set updates
4. **No Recovery Mechanism**: Once corrupted, the transcript cannot be recovered without restarting the entire DKG round

This qualifies as **High Severity** per Aptos Bug Bounty criteria: "Significant protocol violations" and potential "Validator node slowdowns" due to DKG failures.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires specific conditions:

1. **Trigger Conditions**:
   - Transcripts from different validator software versions with subtle serialization differences
   - Configuration edge cases during epoch transitions
   - Memory corruption or hardware errors affecting in-memory transcript structure
   - Race conditions in concurrent transcript processing

2. **Mitigating Factors**:
   - Honest validators use consistent configurations
   - Verification catches most structural issues
   - Same secret sharing config should produce compatible structures

However, the lack of defensive programming (runtime validation, rollback) means any unexpected edge case will cause irrecoverable corruption.

## Recommendation

Implement atomic aggregation with validation and rollback:

```rust
fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
    // 1. VALIDATE COMPATIBILITY FIRST (before any modification)
    if self.Cs.len() != sc.get_total_num_players() {
        bail!("Incompatible accumulator: expected {} players, got {}", 
              sc.get_total_num_players(), self.Cs.len());
    }
    if other.Cs.len() != sc.get_total_num_players() {
        bail!("Incompatible element: expected {} players, got {}", 
              sc.get_total_num_players(), other.Cs.len());
    }
    
    // 2. Validate inner dimensions
    for i in 0..sc.get_total_num_players() {
        if self.Vs[i].len() != other.Vs[i].len() {
            bail!("Incompatible Vs[{}]: lengths {} vs {}", 
                  i, self.Vs[i].len(), other.Vs[i].len());
        }
        if self.Rs[i].len() != other.Rs[i].len() {
            bail!("Incompatible Rs[{}]: lengths {} vs {}", 
                  i, self.Rs[i].len(), other.Rs[i].len());
        }
        for j in 0..self.Vs[i].len() {
            if self.Cs[i][j].len() != other.Cs[i][j].len() {
                bail!("Incompatible Cs[{}][{}]: lengths {} vs {}", 
                      i, j, self.Cs[i][j].len(), other.Cs[i][j].len());
            }
        }
    }
    
    // 3. NOW perform aggregation (validation passed, safe to modify)
    self.V0 += other.V0;
    for i in 0..sc.get_total_num_players() {
        for j in 0..self.Vs[i].len() {
            self.Vs[i][j] += other.Vs[i][j];
            for k in 0..self.Cs[i][j].len() {
                self.Cs[i][j][k] += other.Cs[i][j][k];
            }
        }
    }
    for j in 0..self.Rs.len() {
        for k in 0..self.Rs[j].len() {
            self.Rs[j][k] += other.Rs[j][k];  // Use indexed access instead of zip
        }
    }
    
    Ok(())
}
```

Apply similar fixes to all PVSS implementations (DAS, insecure_field, etc.).

## Proof of Concept

```rust
// Simulated attack demonstrating partial aggregation corruption
#[test]
fn test_partial_aggregation_corruption() {
    use aptos_dkg::pvss::chunky::weighted_transcript::Subtranscript;
    use aptos_crypto::weighted_config::WeightedConfigArkworks;
    use ark_bls12_381::Bls12_381;
    
    // Setup: Create valid config
    let sc = WeightedConfigArkworks::<ark_bls12_381::Fr>::new(
        /* threshold */ 2,
        /* weights */ vec![1, 1, 1],
    );
    
    // Create accumulator transcript with 3 players
    let mut accumulator = create_valid_transcript(&sc);
    
    // Create malicious transcript with incompatible inner dimensions
    // (passes outer dimension checks but has mismatched Vs[i].len())
    let mut malicious = accumulator.clone();
    malicious.Vs[1].pop(); // Remove one element from Vs[1]
    
    // Aggregate - this will panic after modifying V0 and Vs[0]
    // leaving accumulator in corrupted state
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        accumulator.aggregate_with(&sc, &malicious)
    }));
    
    assert!(result.is_err(), "Should panic on dimension mismatch");
    
    // VULNERABILITY: accumulator is now corrupted
    // - V0 has been modified (summed with malicious.V0)
    // - Vs[0] has been modified
    // - Vs[1] is partially modified or unmodified
    // - Transcript is now in INVALID STATE
    
    // Subsequent operations will fail with cryptographic errors
    let decrypt_result = accumulator.decrypt_own_share(/* ... */);
    assert!(decrypt_result.is_err(), "Corrupted transcript fails decryption");
}
```

## Notes

The vulnerability exists in production code but exploitation requires validator-level access. The lack of atomicity and proper error handling represents a significant defensive programming failure that could manifest in edge cases during epoch transitions, configuration changes, or validator software version mismatches. While not directly exploitable by external attackers, it poses a real risk to network liveness and should be addressed with proper validation and rollback mechanisms.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L387-416)
```rust
    fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
        debug_assert_eq!(self.Cs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Vs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Cs.len(), other.Cs.len());
        debug_assert_eq!(self.Rs.len(), other.Rs.len());
        debug_assert_eq!(self.Vs.len(), other.Vs.len());

        // Aggregate the V0s
        self.V0 += other.V0;

        for i in 0..sc.get_total_num_players() {
            for j in 0..self.Vs[i].len() {
                // Aggregate the V_{i,j}s
                self.Vs[i][j] += other.Vs[i][j];
                for k in 0..self.Cs[i][j].len() {
                    // Aggregate the C_{i,j,k}s
                    self.Cs[i][j][k] += other.Cs[i][j][k];
                }
            }
        }

        for j in 0..self.Rs.len() {
            for (R_jk, other_R_jk) in self.Rs[j].iter_mut().zip(&other.Rs[j]) {
                // Aggregate the R_{j,k}s
                *R_jk += other_R_jk;
            }
        }

        Ok(())
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L384-410)
```rust
    fn aggregate_with(
        &mut self,
        sc: &WeightedConfig<ThresholdConfigBlstrs>,
        other: &Transcript,
    ) -> anyhow::Result<()> {
        let W = sc.get_total_weight();

        debug_assert!(self.check_sizes(sc).is_ok());
        debug_assert!(other.check_sizes(sc).is_ok());

        for i in 0..self.V.len() {
            self.V[i] += other.V[i];
            self.V_hat[i] += other.V_hat[i];
        }

        for i in 0..W {
            self.R[i] += other.R[i];
            self.R_hat[i] += other.R_hat[i];
            self.C[i] += other.C[i];
        }

        for sok in &other.soks {
            self.soks.push(sok.clone());
        }

        Ok(())
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-455)
```rust
    fn check_sizes(&self, sc: &WeightedConfigBlstrs) -> anyhow::Result<()> {
        let W = sc.get_total_weight();

        if self.V.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V.len()
            );
        }

        if self.V_hat.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V_hat.len()
            );
        }

        if self.R.len() != W {
            bail!(
                "Expected {} G_1 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R.len()
            );
        }

        if self.R_hat.len() != W {
            bail!(
                "Expected {} G_2 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R_hat.len()
            );
        }

        if self.C.len() != W {
            bail!("Expected C of length {}, but got {}", W, self.C.len());
        }

        Ok(())
    }
```

**File:** crates/aptos-dkg/src/pvss/insecure_field/transcript.rs (L204-223)
```rust
    fn aggregate_with(
        &mut self,
        sc: &ThresholdConfigBlstrs,
        other: &Transcript,
    ) -> anyhow::Result<()> {
        debug_assert_eq!(self.C.len(), sc.n);
        debug_assert_eq!(self.V.len(), sc.n + 1);

        for i in 0..sc.n {
            self.C[i] += other.C[i];
            self.V[i] += other.V[i];
        }
        self.V[sc.n] += other.V[sc.n];
        self.dealers.extend_from_slice(other.dealers.as_slice());

        debug_assert_eq!(self.C.len(), other.C.len());
        debug_assert_eq!(self.V.len(), other.V.len());

        Ok(())
    }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L96-101)
```rust
        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L408-411)
```rust
        accumulator
            .main
            .aggregate_with(&params.pvss_config.wconfig, &element.main)
            .expect("Transcript aggregation failed");
```
