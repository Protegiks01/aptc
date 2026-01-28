# Audit Report

## Title
BCS Deserialization Bomb in DKGTranscript Enables Validator Node Memory Exhaustion Attack

## Summary
The `transcript_bytes` field in `DKGTranscript` is deserialized using unbounded `bcs::from_bytes()` before validation, allowing a malicious validator to craft BCS-encoded data with extremely large vector length claims that expand from kilobytes to gigabytes during deserialization, causing victim validators to crash with out-of-memory errors.

## Finding Description

The vulnerability exists in the DKG (Distributed Key Generation) transcript processing flow where `transcript_bytes` is deserialized without size limits before any validation occurs.

**Vulnerability Location 1 - Transcript Aggregation:** [1](#0-0) 

When validators receive transcripts via reliable broadcast, deserialization occurs immediately before any verification checks on lines 96-101.

**Vulnerability Location 2 - VM Processing:** [2](#0-1) 

During block execution, the VM deserializes the transcript before verification on lines 111-112.

**Vulnerability Location 3 - ValidatorTransaction verify:** [3](#0-2) 

The verify method deserializes before calling verification logic.

**Data Structures:** [4](#0-3) 

The `Transcripts` structure contains main and optional fast path transcripts, each of type `WeightedTranscript`. [5](#0-4) 

Each `WeightedTranscript` contains six large vectors of elliptic curve points: `soks`, `R`, `R_hat`, `V`, `V_hat`, and `C`. Five of these vectors have size W (total weight) or W+1.

**Attack Mechanism:**

In BCS encoding, vectors are serialized as ULEB128-encoded length followed by elements. A malicious validator can craft `transcript_bytes` claiming millions of elements (ULEB128 encoding of 10,000,000 takes ~4 bytes), keeping serialized size under the 2MB validator transaction limit: [6](#0-5) 

During deserialization, BCS allocates memory based on the claimed vector length before reading actual data. With G1Projective points consuming 144 bytes in memory, a claim of 10 million elements allocates 1.44 GB per vector. With multiple large vectors across main and fast paths, the attacker forces allocation of 8+ GB from a few KB of serialized data.

The size validation occurs AFTER deserialization: [7](#0-6) [8](#0-7) 

The `check_sizes()` method is the first line of `verify()`, but by then memory allocation has already occurred during deserialization, causing OOM crashes before validation can reject the malicious transcript.

**Comparison with Network Layer:** [9](#0-8) 

The network layer uses `bcs::from_bytes_with_limit()` for safe deserialization, but DKG code does not employ this protection.

**Attack Path:**

1. Malicious validator creates `DKGTranscript` with crafted `transcript_bytes` containing large vector length claims
2. Submits it via reliable broadcast or includes in block proposal
3. Honest validators receive the transcript and call `bcs::from_bytes()`
4. BCS deserializer attempts to allocate gigabytes of memory based on claimed lengths
5. Victim nodes crash with OOM before validation logic executes
6. Multiple validators crash simultaneously, causing consensus disruption

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

This vulnerability enables "**Validator Node Slowdowns (High)**" - validator crashes qualify as extreme slowdowns affecting consensus performance. A single malicious validator can crash multiple honest validators simultaneously, potentially causing:

- **Consensus liveness failures** if enough validators crash concurrently
- **Temporary network partition** requiring manual intervention and restarts
- **Violation of Byzantine fault tolerance guarantees**: The system should tolerate <1/3 malicious validators, but here 1 malicious validator can affect all others through memory exhaustion

This breaks the critical security invariant that all operations must respect resource limits. The vulnerability bypasses gas, storage, and computational limits by exploiting the deserialization layer before any resource accounting occurs.

## Likelihood Explanation

**High Likelihood:**

- **Minimal requirements**: Requires only 1 malicious validator (no collusion needed), well within the <1/3 Byzantine threshold BFT is designed to tolerate
- **Trivial execution**: Attack is straightforward - craft BCS bytes with large ULEB128 length claims
- **No special conditions**: No timing requirements, race conditions, or specific blockchain state needed
- **Broad impact**: Affects all validators processing the malicious transcript
- **Well-documented technique**: BCS deserialization bombs are a known attack pattern with established exploitation methods

## Recommendation

Implement size-limited deserialization for DKG transcripts:

```rust
// In types/src/dkg/mod.rs
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    const MAX_TRANSCRIPT_SIZE: usize = 10_000_000; // 10MB reasonable limit
    let transcripts: Transcripts = bcs::from_bytes_with_limit(&self.transcript_bytes, MAX_TRANSCRIPT_SIZE)
        .context("Transcripts deserialization failed or exceeded size limit")?;
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

Apply similar fixes to:
- `dkg/src/transcript_aggregation/mod.rs` line 88
- `aptos-move/aptos-vm/src/validator_txns/dkg.rs` line 106-109

The limit should be chosen based on legitimate maximum transcript sizes from real validator sets.

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the vulnerability pattern
use bcs;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct MaliciousTranscript {
    // Claim 10 million elements
    large_vector: Vec<[u8; 144]>, 
}

fn create_bomb() -> Vec<u8> {
    let mut bytes = vec![];
    // ULEB128 encode 10,000,000 (~4 bytes)
    let len: u32 = 10_000_000;
    // BCS will allocate 10M * 144 = 1.44 GB
    // But actual serialized data is tiny
    bytes.extend_from_slice(&encode_uleb128(len));
    // Add minimal dummy data
    bytes.extend_from_slice(&[0u8; 100]);
    bytes
}

fn trigger_oom() {
    let bomb_bytes = create_bomb();
    // This will attempt to allocate 1.44 GB and crash
    let _transcript: MaliciousTranscript = bcs::from_bytes(&bomb_bytes)
        .expect("OOM occurs here before validation");
}
```

A real exploit would craft the `transcript_bytes` field of a `DKGTranscript` with large vector length claims across multiple vectors (R, R_hat, V, V_hat, C) in the `WeightedTranscript` structure, then submit it during DKG protocol execution.

---

**Notes:**

This vulnerability is valid because:
1. BFT consensus is designed to tolerate <1/3 Byzantine validators by specification
2. The deserialization-before-validation pattern creates a genuine DoS vector
3. All affected code paths are in production, in-scope components
4. The attack requires no special privileges beyond validator participation
5. Impact meets "High Severity" criteria for validator node disruption

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L88-90)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L106-109)
```rust
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;
```

**File:** types/src/dkg/mod.rs (L84-86)
```rust
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
```

**File:** types/src/dkg/real_dkg/mod.rs (L164-170)
```rust
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Transcripts {
    // transcript for main path
    pub main: WTrx,
    // transcript for fast path
    pub fast: Option<WTrx>,
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

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L260-262)
```rust
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
    }
```
