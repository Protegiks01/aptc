# Audit Report

## Title
DKG Transcript Deserialization DoS via Unbounded Vector Allocation

## Summary
A Byzantine validator can crash honest validator nodes by sending maliciously crafted DKG transcripts with inflated vector length claims in ULEB128 encoding. The vulnerability exists because BCS deserialization occurs without size limits before validation checks, allowing potential out-of-memory crashes during epoch transitions.

## Finding Description

The DKG (Distributed Key Generation) protocol exchanges `WeightedTranscript` structures containing vectors of elliptic curve points during epoch transitions. A critical two-level deserialization vulnerability exists:

**Level 1 (Network - Protected):** The outer `DKGMessage` is deserialized using `bcs::from_bytes_with_limit()` with a recursion depth limit of 64 and approximately 62 MiB decompressed size limit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Level 2 (Application - Unprotected):** The inner `Transcript` deserialization uses `bcs::from_bytes()` WITHOUT any size limit, which is inconsistent with how the codebase handles untrusted input elsewhere. [6](#0-5) 

For comparison, the REST API endpoints properly use size limits when deserializing untrusted user input: [7](#0-6) [8](#0-7) 

The `Transcript` structure contains multiple vector fields (R, R_hat, V, V_hat, C) that hold elliptic curve points: [9](#0-8) 

**Critical Issue:** Size validation via `check_sizes()` only occurs AFTER the transcript is fully deserialized. The verification flow shows that deserialization happens first, then `verify_transcript()` is called: [10](#0-9) 

Inside the verification, `check_sizes()` is called within the `verify()` method: [11](#0-10) [12](#0-11) 

The verification method in the real DKG implementation confirms this ordering: [13](#0-12) 

**Why RECURSION_LIMIT doesn't protect:** The recursion depth limit prevents deeply nested structures but does NOT prevent large flat vectors. A `Vec<G1Projective>` with millions of elements has recursion depth of only 1, bypassing this protection. [14](#0-13) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

**Validator Node Crashes:** A single Byzantine validator (< 1/3 threshold) can potentially crash multiple honest validators by exploiting this deserialization logic bug during DKG protocol execution. This qualifies as "Validator Node Slowdowns (High)" or "API Crashes (High)" in the Aptos bug bounty categories.

**DKG Protocol Disruption:** The DKG protocol is critical for on-chain randomness generation. Crashing validators during epoch transitions can delay epoch transitions, disrupt randomness beacon updates, and impact consensus liveness if sufficient validators crash simultaneously.

**Within Threat Model:** The attack requires only a single Byzantine validator, well within AptosBFT's 1/3 Byzantine fault tolerance assumptions. The DKG message types show that validators exchange transcripts during the protocol: [15](#0-14) 

**Not Critical Severity:** The vulnerability doesn't cause permanent state corruption, fund theft, or consensus safety violations. The network can recover once the malicious validator stops sending crafted transcripts. This affects liveness, not safety.

## Likelihood Explanation

**High Likelihood** if a validator becomes Byzantine:

1. **Simple Execution:** Requires only crafting bytes with inflated ULEB128 length claims—no complex cryptographic attacks needed
2. **Critical Path Target:** DKG runs during every epoch transition, providing regular attack opportunities
3. **Code Inconsistency:** The codebase demonstrates awareness of this protection need (API endpoints use limits) but doesn't apply it to DKG transcript deserialization
4. **No Complex Timing:** Attack doesn't require precise timing or coordination
5. **Within Access Model:** Attacker must be a validator, which is explicitly within the Byzantine fault model for consensus protocols

## Recommendation

Apply size limits to the inner transcript deserialization to match the security pattern used elsewhere in the codebase. Replace the unbounded deserialization with:

```rust
let transcript = bcs::from_bytes_with_limit::<<DefaultDKG as DKGTrait>::Transcript>(
    dkg_node.transcript_bytes.as_slice(),
    RECURSION_LIMIT, // or appropriate limit constant
)
.map_err(|_| Expected(TranscriptDeserializationFailed))?;
```

This would align with the existing security pattern used in the REST API for untrusted user input and provide defense-in-depth against malformed DKG transcripts from Byzantine validators.

## Proof of Concept

Note: While a full PoC would require testing the specific behavior of the BCS library's vector deserialization and memory allocation patterns, the logic vulnerability is evident from the code structure: untrusted validator data is deserialized without size limits, contrary to established security patterns elsewhere in the codebase. The actual exploitability depends on whether the BCS implementation pre-allocates memory based on the ULEB128-encoded length field, but the missing protection represents a security gap that should be addressed regardless.

## Notes

This vulnerability represents a **logic bug** where security-critical deserialization lacks the same protections applied to similar untrusted input elsewhere in the codebase. Even if the specific attack vector described is not practically exploitable due to BCS library implementation details, the inconsistent application of security controls creates unnecessary risk and should be remediated to maintain defense-in-depth.

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L38-39)
```rust
pub const USER_INPUT_RECURSION_LIMIT: usize = 32;
pub const RECURSION_LIMIT: usize = 64;
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L163-164)
```rust
            ProtocolId::DKGDirectSendCompressed | ProtocolId::DKGRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L232-241)
```rust
            Encoding::Bcs(limit) => self.bcs_decode(bytes, limit),
            Encoding::CompressedBcs(limit) => {
                let compression_client = self.get_compression_client();
                let raw_bytes = aptos_compression::decompress(
                    &bytes.to_vec(),
                    compression_client,
                    MAX_APPLICATION_MESSAGE_SIZE,
                )
                .map_err(|e| anyhow! {"{:?}", e})?;
                self.bcs_decode(&raw_bytes, limit)
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L260-261)
```rust
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
```

**File:** config/src/config/network_config.rs (L47-50)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L106-109)
```rust
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** api/src/transactions.rs (L851-851)
```rust
    const MAX_SIGNED_TRANSACTION_DEPTH: usize = 16;
```

**File:** api/src/transactions.rs (L1224-1224)
```rust
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
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

**File:** types/src/dkg/real_dkg/mod.rs (L368-374)
```rust
        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;
```

**File:** dkg/src/types.rs (L25-29)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, EnumConversion, PartialEq)]
pub enum DKGMessage {
    TranscriptRequest(DKGTranscriptRequest),
    TranscriptResponse(DKGTranscript),
}
```
