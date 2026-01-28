# Audit Report

## Title
DKG Transcript Deserialization DoS via Malicious BCS Length Prefixes

## Summary
A malicious validator can cause denial-of-service on peer validator nodes during DKG transcript aggregation by sending specially crafted BCS-encoded transcripts with inflated vector length prefixes, triggering excessive memory allocation attempts that hang or crash the victim node.

## Finding Description

The DKG transcript aggregation system deserializes untrusted peer data without size limits, enabling a memory exhaustion attack.

In the transcript aggregation flow, when a validator receives a DKG transcript from a peer, the system directly deserializes the raw bytes without any size validation: [1](#0-0) 

The deserialized type `Transcripts` contains a `WeightedTranscript` structure with multiple vector fields containing cryptographic group elements: [2](#0-1) [3](#0-2) 

The deserialization implementation uses standard `bcs::from_bytes` without limits: [4](#0-3) 

**Attack Mechanism:**

When BCS deserializes a `Vec<T>`, it reads the ULEB128-encoded length prefix and pre-allocates memory accordingly. A malicious validator can craft BCS data where the length prefix claims billions of elements (e.g., 100,000,000) while the actual serialized data stays within the 64 MiB network message limit: [5](#0-4) 

The ULEB128 encoding of such large lengths requires only ~5 bytes. When the victim validator calls `bcs::from_bytes()`, the deserializer attempts to allocate massive memory (e.g., 100M × 48 bytes = 4.8 GB for G1Projective, or 100M × 96 bytes = 9.6 GB for G2Projective) before deserializing any actual elements.

This allocation happens **before** any size validation. The `check_sizes()` method is only called during verification after deserialization completes: [6](#0-5) 

The verification that invokes `check_sizes()` occurs after the vulnerable deserialization: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Severity: High** - This qualifies under "Validator Node Slowdowns (High): Significant performance degradation affecting consensus, DoS through resource exhaustion."

Impact:
- **Immediate**: Victim validator nodes experience OOM kills, severe memory pressure, or hang during DKG transcript processing
- **Consensus Impact**: If multiple validators are targeted simultaneously during the DKG phase, it can delay epoch transitions and affect network liveness
- **Attack Window**: DKG runs during epoch transitions, a critical time for validator set updates
- **Scope**: Any validator can be targeted by any other validator in the current epoch

This is a protocol-level DoS vulnerability (not a network-level attack), where malformed application data causes resource exhaustion through a deserialization flaw.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Must be a validator in the current epoch (requires stake but not collusion). This fits the BFT threat model where up to 1/3 of validators may be Byzantine.
- **Technical Complexity**: Low - crafting malicious BCS data with inflated length prefixes is straightforward
- **Detection**: Difficult to distinguish from legitimate large transcripts before deserialization occurs
- **Exploit Reliability**: High - the memory allocation attempt is deterministic based on the length prefix

The attack is practical because:
1. Validators are assumed to be potentially Byzantine (up to 1/3) in BFT systems
2. DKG messages are peer-to-peer without centralized filtering
3. No size validation occurs before deserialization
4. The 64 MiB network limit only validates serialized size, not claimed vector lengths

## Recommendation

Implement size-limited deserialization before processing DKG transcripts:

1. **Add pre-deserialization size check**: Validate `transcript_bytes.len()` against a reasonable maximum before calling `bcs::from_bytes()`

2. **Use bounded deserialization**: Replace `bcs::from_bytes()` with a bounded variant that limits maximum container sizes during deserialization

3. **Early validation**: Move `check_sizes()` validation logic to occur before or during deserialization rather than after

Example fix for `dkg/src/transcript_aggregation/mod.rs`:

```rust
// Add before line 88
const MAX_TRANSCRIPT_BYTES: usize = 10 * 1024 * 1024; // 10 MiB reasonable limit
ensure!(
    transcript_bytes.len() <= MAX_TRANSCRIPT_BYTES,
    "[DKG] transcript exceeds size limit"
);
```

Additionally, consider implementing bounded BCS deserialization with depth/size limits similar to how transaction argument validation uses `MAX_NUM_BYTES`: [9](#0-8) 

## Proof of Concept

A complete PoC would require:
1. Creating a BCS-encoded transcript with inflated length prefixes
2. Sending it through the DKG network protocol
3. Observing memory allocation attempts on the victim validator

The vulnerability can be triggered by any validator crafting a `DKGTranscript` with malicious `transcript_bytes` where the BCS encoding contains ULEB128 length prefixes claiming billions of elements while keeping the total serialized size under 64 MiB.

## Notes

This is a protocol-level vulnerability in deserialization logic, not a network-level DoS attack. The codebase demonstrates awareness of this class of issues in other areas (transaction validation, network protocol handling) where size-limited deserialization is used, but DKG transcript processing lacks these protections.

### Citations

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

**File:** types/src/dkg/real_dkg/mod.rs (L165-170)
```rust
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

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L16-16)
```rust
    file_format::FunctionDefinitionIndex,
```
