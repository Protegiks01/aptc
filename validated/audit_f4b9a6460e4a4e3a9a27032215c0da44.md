After thorough technical validation against the Aptos Core codebase, I have verified all claims in this security report. Here is my assessment:

# Audit Report

## Title
DKG Transcript Deserialization CPU Exhaustion DoS

## Summary
The DKG transcript verification during proposal validation deserializes transcript bytes without size pre-validation, causing expensive BLS12-381 elliptic curve point validation to occur before structural checks. A malicious validator can exploit this to cause CPU exhaustion on all validators.

## Finding Description

The vulnerability exists in the DKG transcript verification flow where expensive cryptographic operations occur before size validation. When a validator proposes a block containing a `DKGTranscript`, all other validators must verify it during proposal processing.

**Critical Code Path:**

During proposal validation, validator transactions are verified by calling `vtxn.verify()` on each transaction: [1](#0-0) 

For `DKGResult` variants, this delegates to `DKGTranscript::verify()`: [2](#0-1) 

The `DKGTranscript::verify()` method immediately deserializes the `transcript_bytes` field using `bcs::from_bytes()` before calling any validation: [3](#0-2) 

The underlying `Transcript` structure contains multiple vectors of BLS12-381 elliptic curve points (G1Projective and G2Projective): [4](#0-3) 

During deserialization, the BLS12-381 library performs expensive point validation. The code explicitly documents this: [5](#0-4) 

The `verify_transcript_extra()` method that is called after deserialization performs dealer validation and voting power checks but does NOT call `check_sizes()` to validate vector lengths: [6](#0-5) 

The `check_sizes()` method that validates transcript structure exists but is only called in the `verify()` method of `AggregatableTranscript`: [7](#0-6) 

Size limit checks occur AFTER all verification is complete: [8](#0-7) 

**Attack Mechanism:**

The 2MB validator transaction size limit is enforced: [9](#0-8) 

BLS12-381 points in compressed form are 48 bytes (G1) and 96 bytes (G2), allowing approximately 21,845 G2 points or 43,690 G1 points within the 2MB limit. Each point requires expensive decompression and curve membership validation, resulting in significant CPU time for maximum-sized transcripts.

**Exploitation Sequence:**

1. Malicious validator creates a `DKGTranscript` with `transcript_bytes` containing serialized `Transcripts` with maximum-sized vectors of valid BLS12-381 points
2. Wraps it in `ValidatorTransaction::DKGResult` and proposes a block
3. All validators receive the proposal and call `verify()` during `process_proposal()`
4. BCS deserialization processes all elliptic curve points with expensive cryptographic validation
5. Only after deserialization completes does `verify_transcript_extra()` run (which doesn't validate sizes)
6. The proposal is eventually rejected, but CPU time has been consumed on all validators

## Impact Explanation

**Severity: Medium to High** per Aptos Bug Bounty categories.

This vulnerability causes temporary validator node slowdowns through protocol-level resource exhaustion, which aligns with the Aptos Bug Bounty category "Validator Node Slowdowns (High): Significant performance degradation affecting consensus, DoS through resource exhaustion."

Impact characteristics:
- Processing large transcript vectors requires significant CPU time per validator
- Synchronous operation blocks the validator thread during proposal validation
- All validators in the network are affected simultaneously when the attack occurs
- Could cause validators to miss consensus deadlines during the attack
- Attack is repeatable during consecutive rounds when the malicious validator is selected as proposer

The severity is Medium-to-High (not Critical) because:
- Impact is temporary - system recovers immediately after rejecting the malicious proposal
- Does not cause crashes or permanent unavailability
- Does not break consensus safety - Byzantine fault tolerance remains intact with <1/3 malicious validators
- Limited scope - only occurs during the malicious validator's proposer rounds
- Attacker is identifiable through proposal signatures, enabling governance response

This is a protocol-level resource exhaustion vulnerability, distinct from network-layer DoS attacks (which are out of scope).

## Likelihood Explanation

**Likelihood: Medium**

Prerequisites for exploitation:
- Attacker must be a validator (requires significant stake and network participation rights)
- Attack only possible when the malicious validator is selected as block proposer
- Attack is repeatable during each of their proposer rounds within an epoch

Mitigating factors:
- The malicious validator can be identified from proposal signatures
- Governance can slash or remove the malicious validator
- The 2MB size limit caps maximum damage per individual attack
- Requires sustained Byzantine behavior that risks validator stake

The attack is technically feasible and can be triggered by a single Byzantine validator (<1/3), which is within the Aptos threat model.

## Recommendation

Implement size validation before deserialization in the `DKGTranscript::verify()` method:

```rust
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    // Add size check before deserialization
    ensure!(
        self.transcript_bytes.len() <= REASONABLE_TRANSCRIPT_SIZE_LIMIT,
        "Transcript bytes exceed size limit"
    );
    
    let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
        .context("Transcripts deserialization failed")?;
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

Alternatively, move structural validation (including `check_sizes()`) to occur before or during deserialization, or implement streaming deserialization with early size checks.

## Proof of Concept

A malicious validator can create a `DKGTranscript` as follows:

```rust
// Create transcript with maximum G2 points within 2MB limit
let num_g2_points = 21_000; // ~2MB of G2 points
let mut transcript_bytes = Vec::new();

// Serialize Transcripts with large vectors of valid BLS12-381 points
// Each G2Projective point is 96 bytes compressed
// This will trigger expensive point validation during bcs::from_bytes()

let dkg_transcript = DKGTranscript {
    metadata: DKGTranscriptMetadata {
        epoch: current_epoch,
        author: malicious_validator_address,
    },
    transcript_bytes,
};

// Wrap in ValidatorTransaction and propose
let vtxn = ValidatorTransaction::DKGResult(dkg_transcript);
// Propose block containing this vtxn
```

When other validators process this proposal, they will spend significant CPU time deserializing and validating all the elliptic curve points before rejecting the proposal.

## Notes

This vulnerability exploits the ordering of validation operations - expensive cryptographic validation occurs during deserialization before lightweight structural checks. The attack leverages the protocol's expectation that validators submit valid transcripts, but a Byzantine validator can abuse this to cause resource exhaustion on honest validators. This is a protocol-level design issue, not a network-layer DoS attack.

### Citations

**File:** consensus/src/round_manager.rs (L1134-1136)
```rust
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L86-88)
```rust
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

**File:** types/src/dkg/real_dkg/mod.rs (L295-329)
```rust
    fn verify_transcript_extra(
        trx: &Self::Transcript,
        verifier: &ValidatorVerifier,
        checks_voting_power: bool,
        ensures_single_dealer: Option<AccountAddress>,
    ) -> anyhow::Result<()> {
        let all_validator_addrs = verifier.get_ordered_account_addresses();
        let main_trx_dealers = trx.main.get_dealers();
        let mut dealer_set = HashSet::with_capacity(main_trx_dealers.len());
        for dealer in main_trx_dealers.iter() {
            if let Some(dealer_addr) = all_validator_addrs.get(dealer.id) {
                dealer_set.insert(*dealer_addr);
            } else {
                bail!("invalid dealer idx");
            }
        }
        ensure!(main_trx_dealers.len() == dealer_set.len());
        if ensures_single_dealer.is_some() {
            let expected_dealer_set: HashSet<AccountAddress> =
                ensures_single_dealer.into_iter().collect();
            ensure!(expected_dealer_set == dealer_set);
        }

        if checks_voting_power {
            verifier
                .check_voting_power(dealer_set.iter(), true)
                .context("not enough power")?;
        }

        if let Some(fast_trx) = &trx.fast {
            ensure!(fast_trx.get_dealers() == main_trx_dealers);
            ensure!(trx.main.get_dealt_public_key() == fast_trx.get_dealt_public_key());
        }
        Ok(())
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L126-126)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB
```
