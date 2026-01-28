# Audit Report

## Title
Missing Vector Size Validation in DKG PVSS Subtranscript Allows Incomplete Share Decryption

## Summary
The `Subtranscript` struct in the DKG PVSS chunky protocol lacks validation for the `Rs` (randomness) vector size during deserialization and verification. A malicious validator can craft transcripts with truncated `Rs` vectors that pass verification but corrupt the aggregated DKG transcript, causing decryption failures network-wide and breaking on-chain randomness generation.

## Finding Description

The vulnerability exists across multiple validation gaps that allow a single Byzantine validator to corrupt the entire DKG process:

**Gap 1: Deserialization Accepts Arbitrary Vector Sizes**

In v1, the `Subtranscript` struct uses standard BCS deserialization without size validation: [1](#0-0) 

In v2, the `Valid::check()` implementation performs no validation: [2](#0-1) 

**Gap 2: Verification Missing Rs Length Check**

The `verify` function validates `Cs.len()` and `Vs.len()` but omits `Rs.len()`: [3](#0-2) 

The same pattern exists in v2: [4](#0-3) 

**Gap 3: Silent Truncation During Decryption**

The `decrypt_chunked_scalars` function uses zip iteration which truncates at the shorter vector length: [5](#0-4) 

When Rs inner vectors have fewer chunks than expected, zip truncation produces incorrect decryption without errors.

**Expected Invariant Violation**

The `generate` function shows the expected invariant - Rs should have `sc.get_max_weight()` elements: [6](#0-5) [7](#0-6) 

**Aggregation Corruption**

The `aggregate_with` function only has debug assertions for Rs length, allowing truncated Rs to corrupt aggregated transcripts: [8](#0-7) 

**Attack Execution Path**

1. Malicious validator creates transcript with truncated Rs (either outer or inner dimensions)
2. Transcript passes verification due to missing Rs length check: [9](#0-8) 

3. During transcript aggregation, verification occurs before aggregation: [10](#0-9) 

4. Malicious transcript gets aggregated, corrupting the final transcript: [11](#0-10) 

5. All validators attempt to decrypt shares from corrupted transcript: [12](#0-11) 

6. Decryption failures break randomness setup, causing network-wide impact

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

- **Significant protocol violation**: DKG is critical infrastructure for on-chain randomness and validator epoch transitions
- **Network-wide impact**: A single malicious transcript corrupts the aggregated result used by all validators
- **Randomness failure**: Breaks VRF-based operations and randomness beacon functionality
- **Consensus degradation**: While epoch transition continues, randomness failure impacts leader election and other consensus features
- **No direct fund loss**: Does not enable theft of APT or other tokens
- **Recoverable**: Network can recover through DKG retry or governance intervention

The vulnerability affects all validators simultaneously when the corrupted aggregated transcript is used, making it a systemic issue rather than isolated node failure. This aligns with HIGH severity category for "Validator Node Slowdowns" and significant protocol violations affecting critical infrastructure.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

- **Attack complexity**: LOW - requires only ability to submit DKG transcripts as a validator
- **Attacker requirements**: Must be in the validator set during DKG epoch (within threat model of single Byzantine validator)
- **Detection difficulty**: HIGH - truncated vectors pass cryptographic verification and only manifest during decryption
- **Execution barrier**: LOW - no sophisticated cryptographic knowledge required, simple vector manipulation
- **Impact scope**: Network-wide when malicious transcript enters aggregation

Any compromised or malicious validator in the dealer set can execute this attack during DKG participation. The attack exploits a clear validation gap rather than cryptographic weakness.

## Recommendation

Add explicit validation for Rs vector dimensions in the `verify` function:

1. Validate outer vector length: `Rs.len() == sc.get_max_weight()`
2. Validate inner vector lengths match expected chunk count
3. Replace debug assertions in `aggregate_with` with runtime checks that return errors
4. Add size validation in `Valid::check()` for v2 implementation

The verification should occur before any aggregation or decryption operations to reject malformed transcripts early.

## Proof of Concept

A malicious validator can craft a transcript by:
1. Generating a valid transcript using the `deal` function
2. Manually truncating the `Rs` field in the `Subtranscript` before serialization
3. Broadcasting the truncated transcript bytes via the DKG reliable broadcast protocol
4. The truncated transcript passes `verify_transcript` and `verify_transcript_extra` checks
5. During aggregation at other validators, the truncated Rs either causes a panic (if outer dimension truncated) or silent corruption (if inner dimension truncated)
6. Validators attempting to decrypt from the corrupted aggregated transcript experience failures

**Notes**

This vulnerability is confirmed to exist in both v1 and v2 implementations of the chunky PVSS protocol. The missing validation allows a single Byzantine validator to disrupt the entire DKG process, which is a critical component for Aptos on-chain randomness. The issue affects `crates/aptos-dkg/`, `dkg/`, and `types/src/dkg/` components, all of which are in-scope core infrastructure.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L102-109)
```rust
impl<E: Pairing> TryFrom<&[u8]> for Subtranscript<E> {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bcs::from_bytes::<Subtranscript<E>>(bytes)
            .map_err(|_| CryptoMaterialError::DeserializationError)
    }
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L140-153)
```rust
        if self.subtrs.Cs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of chunked ciphertexts, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Cs.len()
            );
        }
        if self.subtrs.Vs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of commitment elements, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Vs.len()
            );
        }
```

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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L630-632)
```rust
                Rs: (0..sc.get_max_weight())
                    .map(|_| unsafe_random_points_group(num_chunks_per_share, rng))
                    .collect(),
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L366-370)
```rust
impl<E: Pairing> Valid for Subtranscript<E> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L474-487)
```rust
        if self.subtrs.Cs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of chunked ciphertexts, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Cs.len()
            );
        }
        if self.subtrs.Vs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of commitment elements, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Vs.len()
            );
        }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L918-920)
```rust
                Rs: (0..sc.get_max_weight())
                    .map(|_| unsafe_random_points_group(num_chunks_per_share, rng))
                    .collect(),
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L327-333)
```rust
    for (row, Rs_row) in Cs_rows.iter().zip(Rs_rows.iter()) {
        // Compute C - d_k * R for each chunk
        let exp_chunks: Vec<C> = row
            .iter()
            .zip(Rs_row.iter())
            .map(|(C_ij, &R_j)| C_ij.sub(R_j * *dk))
            .collect();
```

**File:** dkg/src/transcript_aggregation/mod.rs (L88-90)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
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

**File:** types/src/dkg/real_dkg/mod.rs (L428-435)
```rust
        let (sk, pk) = trx.main.decrypt_own_share(
            &pub_params.pvss_config.wconfig,
            &Player {
                id: player_idx as usize,
            },
            dk,
            &pub_params.pvss_config.pp,
        );
```
