# Audit Report

## Title
Computational DoS via Unbounded Point Decompression in DKG Transcript Deserialization

## Summary
Malicious validators can send DKG transcripts containing arbitrarily large vectors of elliptic curve points (up to ~1 million points), forcing receiving validators to perform expensive point decompression and subgroup validation operations before size checks reject the malformed transcript. This causes significant CPU exhaustion and can DoS validators during the critical DKG (Distributed Key Generation) phase.

## Finding Description
During the DKG protocol, validators exchange transcripts containing encrypted shares. The `TranscriptAggregationState::add()` function in `dkg/src/transcript_aggregation/mod.rs` receives these transcripts from network peers and deserializes them using BCS. [1](#0-0) 

The deserialization occurs **before** any validation of the transcript's structural sizes. The `Transcript` struct contains multiple vectors of BLS12-381 curve points (G1Projective and G2Projective): [2](#0-1) 

During BCS deserialization, each point undergoes expensive operations:
1. Point decompression (solving elliptic curve equations)
2. Subgroup membership validation [3](#0-2) 

The size validation via `check_sizes()` only occurs **after** full deserialization: [4](#0-3) 

**Attack Vector:**
1. Malicious validator crafts a `DKGTranscript` with `transcript_bytes` encoding a `Transcript` where `W` (total weight) is set to ~200,000 instead of the legitimate ~414 (for mainnet with 129 validators)
2. This creates vectors containing ~1 million curve points total
3. Network message size limit is 64 MiB, allowing this payload [5](#0-4) 

4. Each receiving validator deserializes all ~1 million points (expensive CPU operations) before `check_sizes()` rejects the transcript as malformed
5. Attack amplification: **~483x more points** than legitimate transcripts (200,000 vs 414) [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty program: "Validator node slowdowns". 

The DKG protocol is critical for on-chain randomness generation. During DKG:
- Validators must exchange and aggregate transcripts to establish shared randomness secrets
- A single malicious validator can send crafted transcripts to all other validators
- Each victim validator wastes significant CPU cycles (potentially seconds per transcript) on point decompression
- With 129 validators, the attacker could send malicious transcripts to 128 victims
- This could delay or prevent DKG completion, affecting randomness availability for the next epoch
- Repeated attacks could sustain validator DoS during the DKG window

## Likelihood Explanation
**Likelihood: Medium to High**

**Requirements:**
- Attacker must be a validator in the current epoch (can participate in DKG)
- No special cryptographic capabilities needed beyond crafting malformed BCS-encoded data
- Attack is deterministic and reliable

The sender validation check occurs before deserialization: [7](#0-6) 

However, any compromised or malicious validator can execute this attack. Given that validators have economic incentives to disrupt competitors, the attack is feasible.

## Recommendation
Implement **early size validation** on the encoded transcript before expensive deserialization:

```rust
// In dkg/src/transcript_aggregation/mod.rs, before line 88:

// Estimate maximum reasonable transcript size based on expected W
let max_expected_weight = sc.get_total_weight() * 2; // Allow 2x headroom
let max_transcript_size = max_expected_weight * 336; // bytes per weight unit
ensure!(
    transcript_bytes.len() <= max_transcript_size,
    "[DKG] transcript_bytes size {} exceeds maximum expected {}",
    transcript_bytes.len(),
    max_transcript_size
);

let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
    anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
})?;
```

Alternatively, implement **bounded deserialization** that checks vector lengths during BCS parsing before allocating/decompressing points.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Place in dkg/src/transcript_aggregation/tests.rs

#[test]
fn test_dos_via_oversized_transcript() {
    use crate::transcript_aggregation::TranscriptAggregationState;
    use aptos_dkg::pvss::das::weighted_protocol::Transcript;
    use blstrs::{G1Projective, G2Projective};
    use group::Group;
    
    // Create a malicious transcript with W = 100,000 (vs legitimate ~414)
    let malicious_w = 100_000;
    let mut malicious_transcript = Transcript {
        soks: vec![],
        R: vec![G1Projective::generator(); malicious_w],
        R_hat: vec![G2Projective::generator(); malicious_w],
        V: vec![G1Projective::generator(); malicious_w + 1],
        V_hat: vec![G2Projective::generator(); malicious_w + 1],
        C: vec![G1Projective::generator(); malicious_w],
    };
    
    let transcript_bytes = bcs::to_bytes(&malicious_transcript).unwrap();
    println!("Malicious transcript size: {} bytes", transcript_bytes.len());
    
    // Time the deserialization
    let start = std::time::Instant::now();
    let result = bcs::from_bytes::<Transcript>(&transcript_bytes);
    let elapsed = start.elapsed();
    
    println!("Deserialization took: {:?}", elapsed);
    println!("Deserialization result: {:?}", result.is_ok());
    
    // This will show significant CPU time spent before any size validation
    // On a typical validator node, this could take multiple seconds
    assert!(elapsed.as_secs() > 0, "Attack causes measurable CPU exhaustion");
}
```

**Notes**
The vulnerability breaks Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits." The deserialization performs unbounded computation before validation, violating the principle that untrusted input should be validated before expensive processing.

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L79-87)
```rust
        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );
```

**File:** dkg/src/transcript_aggregation/mod.rs (L88-90)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L48-72)
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, BCSCryptoHash, CryptoHasher)]
#[allow(non_snake_case)]
pub struct Transcript {
    /// Proofs-of-knowledge (PoKs) for the dealt secret committed in $c = g_2^{p(0)}$.
    /// Since the transcript could have been aggregated from other transcripts with their own
    /// committed secrets in $c_i = g_2^{p_i(0)}$, this is a vector of PoKs for all these $c_i$'s
    /// such that $\prod_i c_i = c$.
    ///
    /// Also contains BLS signatures from each player $i$ on that player's contribution $c_i$, the
    /// player ID $i$ and auxiliary information `aux[i]` provided during dealing.
    soks: Vec<SoK<G1Projective>>,
    /// Commitment to encryption randomness $g_1^{r_j} \in G_1, \forall j \in [W]$
    R: Vec<G1Projective>,
    /// Same as $R$ except uses $g_2$.
    R_hat: Vec<G2Projective>,
    /// First $W$ elements are commitments to the evaluations of $p(X)$: $g_1^{p(\omega^i)}$,
    /// where $i \in [W]$. Last element is $g_1^{p(0)}$ (i.e., the dealt public key).
    V: Vec<G1Projective>,
    /// Same as $V$ except uses $g_2$.
    V_hat: Vec<G2Projective>,
    /// ElGamal encryption of the $j$th share of player $i$:
    /// i.e., $C[s_i+j-1] = h_1^{p(\omega^{s_i + j - 1})} ek_i^{r_j}, \forall i \in [n], j \in [w_i]$.
    /// We sometimes denote $C[s_i+j-1]$ by C_{i, j}.
    C: Vec<G1Projective>,
}
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L85-89)
```rust
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-454)
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
```

**File:** network/framework/src/constants.rs (L20-21)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** types/src/dkg/real_dkg/rounding/tests.rs (L24-26)
```rust
    println!("mainnet rounding profile: {:?}", dkg_rounding.profile);
    // Result:
    // mainnet rounding profile: total_weight: 414, secrecy_threshold_in_stake_ratio: 0.5, reconstruct_threshold_in_stake_ratio: 0.60478401144595166257, reconstruct_threshold_in_weights: 228, fast_reconstruct_threshold_in_stake_ratio: Some(0.7714506781126183292), fast_reconstruct_threshold_in_weights: Some(335), validator_weights: [7, 5, 6, 6, 5, 1, 6, 6, 1, 5, 6, 5, 1, 7, 1, 6, 6, 1, 2, 1, 6, 3, 2, 1, 1, 4, 3, 2, 5, 5, 5, 1, 1, 4, 1, 1, 1, 7, 5, 1, 1, 2, 6, 1, 6, 1, 3, 5, 5, 1, 5, 5, 3, 2, 5, 1, 6, 3, 6, 1, 1, 3, 1, 5, 1, 9, 1, 1, 1, 6, 1, 5, 7, 4, 6, 1, 5, 6, 5, 5, 3, 1, 6, 7, 6, 1, 3, 1, 1, 1, 1, 1, 1, 7, 2, 1, 6, 7, 1, 1, 1, 1, 5, 3, 1, 2, 3, 1, 1, 1, 1, 4, 1, 1, 1, 2, 1, 6, 7, 5, 1, 5, 1, 6, 1, 2, 3, 2, 2]
```
