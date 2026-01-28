# Audit Report

## Title
DKG Transcript Decompression Bomb Vulnerability During Deserialization

## Summary
A resource exhaustion vulnerability exists in the DKG transcript validation flow where BCS deserialization of elliptic curve points occurs before size validation, allowing Byzantine validators to cause significant CPU consumption on all validators during critical DKG epochs.

## Finding Description

The vulnerability exists in the DKG (Distributed Key Generation) transcript validation flow where expensive cryptographic operations are performed before logical size checks.

**Attack Flow:**

1. A Byzantine validator submits a `ValidatorTransaction::DKGResult` containing a maliciously crafted DKG transcript with excessive elliptic curve points (staying within the 2MB transaction size limit).

2. During consensus proposal processing, `vtxn.verify()` is called [1](#0-0)  which triggers `DKGTranscript::verify()` [2](#0-1) 

3. The verification deserializes the transcript bytes without prior size validation [3](#0-2) 

4. During VM processing, a second deserialization occurs [4](#0-3) 

5. The `Transcript` structure contains vectors of G1 and G2 elliptic curve points [5](#0-4) 

6. The BCS deserialization implementation explicitly performs expensive point validation during deserialization, as documented in the code [6](#0-5) 

7. Only AFTER all elliptic curve points are decompressed and validated does the `verify()` method call `check_sizes()` to validate vector lengths [7](#0-6) 

8. The size validation logic that would reject oversized transcripts [8](#0-7) 

**Exploitation Details:**

With the default 2MB per-block validator transaction limit [9](#0-8) , an attacker can fit approximately 21,845 G2 points (96 bytes each compressed) or 43,690 G1 points (48 bytes each compressed).

Each G2 point decompression involves:
- Extracting the x-coordinate from 96 bytes
- Computing y² = x³ + 4 in Fp2 (extension field arithmetic)
- Modular square root in Fp2 (expensive operation)
- Subgroup membership check

If the expected weight W is small (e.g., 100-500 for typical validator sets), but the attacker provides 20,000+ points, all validators must decompress these points before the mismatch is detected and the transcript rejected.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria (Category 8: "Validator Node Slowdowns").

**Concrete Impact:**
- A single Byzantine validator (< 1/3 threshold) can repeatedly submit malicious DKG transcripts
- Each malicious transcript causes all validators to perform seconds of CPU-intensive elliptic curve operations before rejection
- Multiple such transactions during DKG epochs can significantly degrade validator performance
- DKG occurs during epoch transitions, a critical protocol phase where consensus liveness is essential
- No rate limiting or cost accounting exists for failed transcript processing before the expensive cryptographic operations complete

This breaks the protocol's resource limits invariant, which requires all operations to complete within bounded computational resources. The attack exploits the ordering of validation checks: expensive cryptographic validation occurs before cheap logical size validation.

## Likelihood Explanation

**Likelihood: Medium to High**

**Factors increasing likelihood:**
- Byzantine validators (< 1/3 malicious) are explicitly within the threat model
- Attack requires only validator access, which malicious actors may obtain through stake
- Execution is trivial: craft oversized transcript vectors within the 2MB limit, submit via ValidatorTransaction
- No early-exit size validation prevents the expensive deserialization
- DKG happens at predictable times (epoch boundaries)
- The attack affects all validators simultaneously, amplifying the impact

**Factors decreasing likelihood:**
- Requires attacker to be an active validator with stake
- Validator reputation may suffer, though damage occurs before detection

## Recommendation

**Primary Fix:** Add size validation before deserialization in `DKGTranscript::verify()`:

```rust
// In types/src/dkg/mod.rs, modify verify() method:
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    // Add early size check before deserialization
    let max_reasonable_size = calculate_max_transcript_size(verifier);
    ensure!(
        self.transcript_bytes.len() <= max_reasonable_size,
        "Transcript bytes exceed maximum expected size"
    );
    
    let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
        .context("Transcripts deserialization failed")?;
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

**Secondary Fix:** Add rate limiting for failed DKG transcript verifications to prevent repeated attacks within an epoch.

## Proof of Concept

While a complete executable PoC is not provided, the vulnerability can be demonstrated by:

1. Creating a DKG transcript with vector sizes (V, V_hat, R, R_hat, C) set to approximately 21,000 elements (approaching 2MB limit)
2. Submitting this as a ValidatorTransaction::DKGResult during a DKG epoch
3. Observing that all validators perform expensive BCS deserialization and point validation before `check_sizes()` rejects the oversized vectors
4. Measuring CPU time consumed during the deserialization phase versus the rejection phase

The attack is deterministic and reproducible given validator access.

## Notes

This vulnerability is particularly concerning because:
- It affects a critical system component (DKG for randomness generation)
- The timing is predictable (epoch boundaries)
- Byzantine validators can coordinate to maximize disruption
- The resource exhaustion occurs in consensus-critical code paths

The fix should prioritize early validation of logical constraints (expected sizes) before performing expensive cryptographic operations (point validation).

### Citations

**File:** consensus/src/round_manager.rs (L1134-1136)
```rust
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
```

**File:** types/src/validator_txn.rs (L47-49)
```rust
            ValidatorTransaction::DKGResult(dkg_result) => dkg_result
                .verify(verifier)
                .context("DKGResult verification failed"),
```

**File:** types/src/dkg/mod.rs (L83-87)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L106-109)
```rust
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L85-88)
```rust
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L280-288)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &<Self as traits::Transcript>::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        auxs: &[A],
    ) -> anyhow::Result<()> {
        self.check_sizes(sc)?;
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

**File:** types/src/on_chain_config/consensus_config.rs (L126-126)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB
```
