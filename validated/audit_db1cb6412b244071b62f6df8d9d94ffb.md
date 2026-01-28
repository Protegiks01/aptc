# Audit Report

## Title
DKG Transcript Decompression Bomb Vulnerability During Deserialization

## Summary
A Byzantine validator can cause validator node slowdowns by submitting maliciously crafted DKG transcripts that trigger expensive elliptic curve point decompression operations during BCS deserialization before any size validation occurs, enabling resource exhaustion attacks at zero cost.

## Finding Description

The vulnerability exists in the DKG transcript processing pipeline where expensive cryptographic operations occur during deserialization before transcript size validation.

**Attack Vector**: When a block proposal containing `ValidatorTransaction::DKGResult` is received, the consensus layer validates each validator transaction by calling `vtxn.verify()`. [1](#0-0) 

This triggers `DKGTranscript::verify()` which immediately deserializes the `transcript_bytes` field using `bcs::from_bytes()` without any prior size checking. [2](#0-1) 

The deserialization target is the `Transcript` struct containing multiple vectors of elliptic curve points (G1Projective and G2Projective). [3](#0-2) 

**Critical Issue**: The code explicitly documents that point validation occurs during deserialization: "The `serde` implementation in `blstrs` already performs the necessary point validation by ultimately calling `GroupEncoding::from_bytes`." [4](#0-3) 

Each elliptic curve point decompression involves expensive operations including modular square root computations in finite fields and subgroup membership checks.

**Size Validation Occurs Too Late**: The `check_sizes()` method only executes AFTER deserialization completes, inside the `verify()` method. [5](#0-4) [6](#0-5) 

The system allows validator transactions up to 2MB in total bytes. [7](#0-6) 

The size limit check in `process_proposal` occurs AFTER all validator transaction verification completes. [8](#0-7) 

**Attack Scenario**: A Byzantine validator crafts a DKG transcript with ~21,845 G2 points (96 bytes compressed each) or ~43,690 G1 points (48 bytes compressed each), staying within the 2MB limit. During consensus validation, all points undergo expensive decompression before the transcript is rejected, consuming significant CPU resources. The attacker incurs no cost as failed validation is free.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria as it directly causes "Validator node slowdowns" through protocol-level resource exhaustion.

A Byzantine validator (< 1/3 of stake, within the threat model) can repeatedly submit malicious transcripts that:
- Stay within the 2MB validator transaction size limit
- Contain excessive elliptic curve points requiring seconds of CPU time to decompress
- Are ultimately rejected after expensive processing
- Incur zero cost to the attacker

Multiple such transactions can significantly degrade validator performance during critical DKG epochs, affecting consensus liveness and epoch transitions. Unlike regular transactions with gas limits, validator transaction processing uses `UnmeteredGasMeter` with no cost accounting for failed validations. [9](#0-8) 

## Likelihood Explanation

**High likelihood**:
- **Attacker Profile**: Requires only a Byzantine validator (< 1/3 stake), explicitly within Aptos threat model
- **Execution Complexity**: Simple - craft serialized transcript with excessive points and submit through validator transaction pool
- **Preconditions**: Normal network operation during DKG epoch (predictable, occurs at every epoch transition)
- **Cost**: Zero for failed validation - expensive work is done before rejection
- **Rate Limiting**: No rate limiting on failed validator transaction processing found in codebase
- **Repeatability**: Single Byzantine validator can repeatedly submit malicious transcripts throughout DKG phase

## Recommendation

Implement early size validation before deserialization:

1. **Add pre-deserialization length check** in `DKGTranscript::verify()`:
```rust
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    // Check transcript_bytes size before deserialization
    const MAX_TRANSCRIPT_BYTES: usize = 1_000_000; // 1MB reasonable limit
    ensure!(
        self.transcript_bytes.len() <= MAX_TRANSCRIPT_BYTES,
        "Transcript bytes exceed maximum size: {} > {}",
        self.transcript_bytes.len(),
        MAX_TRANSCRIPT_BYTES
    );
    
    let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
        .context("Transcripts deserialization failed")?;
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

2. **Add constructor validation** in `DKGTranscript::new()` to reject oversized transcripts at creation time.

3. **Implement rate limiting** on failed validator transaction verifications per validator to prevent repeated attacks.

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the attack principle
use aptos_types::{dkg::DKGTranscript, validator_txn::ValidatorTransaction};
use aptos_dkg::pvss::das::WeightedTranscript;

// Attacker creates malicious transcript with excessive G2 points
fn create_malicious_transcript() -> ValidatorTransaction {
    // Craft transcript with ~21,845 G2 points (within 2MB limit)
    // Each G2 point: 96 bytes compressed
    // Total: ~2,097,120 bytes
    let mut malicious_transcript = WeightedTranscript {
        V_hat: vec![/* 21,845 G2 points */],
        // ... other fields with excessive points
    };
    
    let transcript_bytes = bcs::to_bytes(&malicious_transcript).unwrap();
    let dkg_transcript = DKGTranscript::new(epoch, author, transcript_bytes);
    ValidatorTransaction::DKGResult(dkg_transcript)
}

// When validators receive this in a block proposal:
// 1. vtxn.verify() called -> DKGTranscript::verify()
// 2. bcs::from_bytes() deserializes ALL points (expensive!)
// 3. Each G2 point decompression: ~ms of CPU time
// 4. Total: seconds of CPU work
// 5. check_sizes() then rejects it (too late!)
// 6. Attacker cost: ZERO (failed validation is free)
```

**Notes**

This vulnerability breaks the security guarantee that validator transaction processing should not be exploitable for resource exhaustion by Byzantine validators within the < 1/3 threshold. The core issue is that cryptographically expensive operations (elliptic curve point decompression and validation) occur during BCS deserialization before any structural validation checks, allowing zero-cost CPU exhaustion attacks during critical DKG epochs.

### Citations

**File:** consensus/src/round_manager.rs (L1126-1136)
```rust
        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
```

**File:** consensus/src/round_manager.rs (L1173-1177)
```rust
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
```

**File:** types/src/dkg/mod.rs (L83-87)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L50-72)
```rust
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L86-87)
```rust
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L288-288)
```rust
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

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L115-115)
```rust
        let mut gas_meter = UnmeteredGasMeter;
```
