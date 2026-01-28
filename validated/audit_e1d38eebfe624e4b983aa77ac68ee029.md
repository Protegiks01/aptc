# Audit Report

## Title
DKG Transcript Deserialization CPU Exhaustion DoS

## Summary
The DKG transcript deserialization process lacks size validation before performing expensive BLS12-381 elliptic curve point validation, allowing a malicious validator to cause CPU exhaustion on all other validators during proposal validation.

## Finding Description

During consensus proposal validation, validator transactions containing `DKGTranscript` objects are verified without size pre-validation, causing expensive cryptographic operations before rejection.

**Critical Code Path:**

When a validator proposes a block containing a `DKGTranscript`, all validators must verify it. The verification flow: [1](#0-0) 

This calls the validator transaction verify method: [2](#0-1) 

Which triggers immediate deserialization in DKGTranscript::verify(): [3](#0-2) 

The underlying `Transcript` structure contains multiple vectors of BLS12-381 elliptic curve points: [4](#0-3) 

The `TryFrom` implementation performs deserialization with automatic point validation: [5](#0-4) 

The comment explicitly states that BLS12-381 point validation occurs during deserialization via `GroupEncoding::from_bytes`.

**Attack Mechanism:**

The 2MB validator transaction size limit is enforced: [6](#0-5) 

However, size validation occurs AFTER verification: [7](#0-6) 

Each G1 point requires ~50-100 microseconds and each G2 point requires ~150-200 microseconds for decompression and curve membership validation. The 2MB limit allows approximately 21,845 G2Projective points (96 bytes compressed) or 42,666 G1Projective points (48 bytes compressed).

A malicious validator can create a `DKGTranscript` with maximally-sized vectors within the 2MB limit. When proposed, all validators deserialize and validate all elliptic curve points before the proposal is rejected, wasting 2-4 seconds of CPU time per validator.

## Impact Explanation

**Severity: Medium** per Aptos Bug Bounty categories.

This vulnerability causes "Validator node slowdowns":
- Processing ~20,000 G2 points: 3-4 seconds of CPU time per validator
- Synchronous operation blocks the validator thread during proposal validation
- All validators in the network are affected simultaneously  
- Could cause validators to miss consensus deadlines
- Repeatable during consecutive rounds when the malicious validator is the proposer

This does NOT qualify as High/Critical because:
- Does not cause crashes or permanent unavailability
- Does not break consensus safety (Byzantine fault tolerance remains intact)
- System recovers after rejecting the malicious proposal
- Limited to the malicious validator's proposer rounds
- Attacker can be identified through signed proposals

## Likelihood Explanation

**Likelihood: Medium**

Prerequisites:
- Attacker must be a validator (requires stake and network participation)
- Attack only possible when the malicious validator is selected as block proposer
- Attack is repeatable during each of their proposer rounds

Mitigating factors:
- The malicious validator can be identified (proposal is signed)
- Potential for slashing or removal through governance
- The 2MB size limit caps maximum damage per attack
- Attack causes temporary slowdown, not permanent damage

## Recommendation

Implement size validation before deserialization in `DKGTranscript::verify()`:

```rust
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    // Add size check before expensive deserialization
    ensure!(
        self.transcript_bytes.len() <= MAX_EXPECTED_TRANSCRIPT_SIZE,
        "Transcript bytes exceed maximum expected size"
    );
    
    let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
        .context("Transcripts deserialization failed")?;
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

Where `MAX_EXPECTED_TRANSCRIPT_SIZE` is calculated based on the maximum expected validator weight and point sizes (e.g., ~50KB for typical validator sets).

Alternatively, call `verify_transcript()` which includes `check_sizes()` validation after deserialization but before expensive cryptographic operations.

## Proof of Concept

A malicious validator can execute this attack by:

1. Creating a `Transcripts` struct with maximally-sized vectors (within 2MB)
2. Serializing to `transcript_bytes` using BCS
3. Wrapping in `DKGTranscript` with valid metadata
4. Proposing a block containing `ValidatorTransaction::DKGResult`
5. All other validators waste CPU time during `vtxn.verify()` call
6. Proposal is eventually rejected, but damage is done

The attack succeeds because deserialization and point validation occur before any size or structural validation in the consensus proposal validation path.

### Citations

**File:** consensus/src/round_manager.rs (L1126-1137)
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
        }
```

**File:** consensus/src/round_manager.rs (L1166-1177)
```rust
        ensure!(
            num_validator_txns <= vtxn_count_limit,
            "process_proposal failed with per-block vtxn count limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_txn_count(),
            num_validator_txns
        );
        ensure!(
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
```

**File:** types/src/validator_txn.rs (L45-52)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            ValidatorTransaction::DKGResult(dkg_result) => dkg_result
                .verify(verifier)
                .context("DKGResult verification failed"),
            ValidatorTransaction::ObservedJWKUpdate(_) => Ok(()),
        }
    }
```

**File:** types/src/dkg/mod.rs (L83-87)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L82-90)
```rust
impl TryFrom<&[u8]> for Transcript {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
    }
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L125-127)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 2;
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB

```
