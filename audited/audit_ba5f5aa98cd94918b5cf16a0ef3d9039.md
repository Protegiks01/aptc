# Audit Report

## Title
DKG Liveness Attack via Selective Transcript Withholding

## Summary
The Aptos DKG (Distributed Key Generation) protocol lacks a commit-then-reveal mechanism, allowing validators to withhold their transcripts until observing others' contributions. While this does not enable prediction of the final DKG output due to PVSS cryptographic properties, it enables liveness attacks where validators with significant voting power can strategically delay or prevent DKG completion.

## Finding Description

The DKG protocol uses a request-response model for transcript collection without enforcing simultaneous submission: [1](#0-0) 

The code explicitly states that transcript equivocation is permitted, meaning validators can generate multiple different transcripts or delay their submission.

**Protocol Flow:**
1. Validators generate PVSS transcripts locally containing cryptographic commitments [2](#0-1) 

2. Transcripts are collected via reliable broadcast using TranscriptRequest/TranscriptResponse messages [3](#0-2) 

3. Validators respond to requests on-demand with their already-generated transcript

4. Transcripts are aggregated until quorum threshold (2/3+ voting power) is reached [4](#0-3) 

**The Vulnerability:**
A rational validator can:
- Generate their transcript but delay responding to `TranscriptRequest` messages
- Observe which other validators are participating by collecting their transcripts
- Strategically decide whether to respond based on the observed participation
- If they control >1/3 voting power, prevent quorum by withholding indefinitely

**Why Output Prediction is NOT Possible:**
The PVSS protocol ensures that observing partial transcripts does not reveal the final key: [5](#0-4) 

The dealt public key commitments (V_hat) are visible but the final aggregated key depends on ALL contributions. Without knowing all secrets, prediction is cryptographically infeasible.

## Impact Explanation

**Severity: LOW (does not meet Medium threshold)**

This vulnerability does NOT meet the claimed "Medium" severity for the following reasons:

1. **Cannot predict final DKG output**: The PVSS cryptographic scheme prevents prediction from partial observations, contradicting the question's premise

2. **Liveness attack only**: The only exploitable issue is delaying DKG completion, which:
   - Does not cause loss of funds
   - Does not break consensus safety  
   - Does not cause permanent network partition
   - Only causes temporary delay (validators can retry)

3. **Requires validator access**: The attacker must be a validator with significant voting power (>1/3), which violates the "exploitable by unprivileged attacker" requirement

4. **No state inconsistency**: Different validators don't end up with different aggregated results because: [6](#0-5) 

The validation ensures sufficient voting power, and consensus determines which aggregated transcript is accepted.

## Likelihood Explanation

**Likelihood: LOW**

The attack has significant barriers:
- Requires controlling a validator with >1/3 voting power
- Other validators can complete DKG without the malicious validator
- The network can tolerate up to 1/3 Byzantine validators by design
- Economic disincentives exist for validators causing delays

## Recommendation

While the core claim about "predicting final DKG output" is cryptographically invalid, the protocol could add a commit-then-reveal mechanism to eliminate strategic withholding:

1. **Phase 1 - Commitment**: Validators submit cryptographic commitments (hashes) of their transcripts with timestamps
2. **Phase 2 - Reveal**: Validators reveal actual transcripts, which are verified against commitments
3. **Enforcement**: Transcripts revealed without prior commitment or after deadline are rejected

However, this adds complexity for marginal security benefit given the Byzantine tolerance already handles non-participation.

## Proof of Concept

**This vulnerability does NOT meet the validation criteria** for a valid bug bounty submission:

- ❌ Does not allow predicting final DKG output (cryptographically impossible)
- ❌ Requires privileged validator access (>1/3 voting power)  
- ❌ Does not meet Medium severity impact (only temporary liveness delay)
- ❌ Does not break any critical invariant (Byzantine tolerance handles this)

The PVSS cryptographic properties ensure that the specific attack described in the question ("predicting the final DKG output") is **not possible**. The liveness attack exists but is a known limitation of any Byzantine fault-tolerant quorum-based protocol and does not constitute a vulnerability worthy of remediation beyond the existing 2/3+ quorum requirement.

---

**Final Assessment**: While selective disclosure enables minor liveness delays, it does NOT enable the claimed advantage of "predicting the final DKG output." The cryptographic foundations of PVSS prevent this attack vector entirely.

### Citations

**File:** dkg/src/dkg_manager/mod.rs (L288-293)
```rust
    /// Calculate DKG config. Deal a transcript. Start broadcasting the transcript.
    /// Called when a DKG start event is received, or when the node is restarting.
    ///
    /// NOTE: the dealt DKG transcript does not have to be persisted:
    /// it is ok for a validator to equivocate on its DKG transcript, as long as the transcript is valid.
    async fn setup_deal_broadcast(
```

**File:** dkg/src/dkg_manager/mod.rs (L464-478)
```rust
        let response = match (&self.state, &msg) {
            (InnerState::Finished { my_transcript, .. }, DKGMessage::TranscriptRequest(_))
            | (InnerState::InProgress { my_transcript, .. }, DKGMessage::TranscriptRequest(_)) => {
                Ok(DKGMessage::TranscriptResponse(my_transcript.clone()))
            },
            _ => Err(anyhow!(
                "[DKG] msg {:?} unexpected in state {:?}",
                msg.name(),
                self.state.variant_name()
            )),
        };

        response_sender.send(response);
        Ok(())
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L241-286)
```rust
    fn generate_transcript<R: CryptoRng + RngCore>(
        rng: &mut R,
        pub_params: &Self::PublicParams,
        input_secret: &Self::InputSecret,
        my_index: u64,
        sk: &Self::DealerPrivateKey,
        pk: &Self::DealerPublicKey,
    ) -> Self::Transcript {
        let my_index = my_index as usize;
        let my_addr = pub_params.session_metadata.dealer_validator_set[my_index].addr;
        let aux = (pub_params.session_metadata.dealer_epoch, my_addr);

        let wtrx = WTrx::deal(
            &pub_params.pvss_config.wconfig,
            &pub_params.pvss_config.pp,
            sk,
            pk,
            &pub_params.pvss_config.eks,
            input_secret,
            &aux,
            &Player { id: my_index },
            rng,
        );
        // transcript for fast path
        let fast_wtrx = pub_params
            .pvss_config
            .fast_wconfig
            .as_ref()
            .map(|fast_wconfig| {
                WTrx::deal(
                    fast_wconfig,
                    &pub_params.pvss_config.pp,
                    sk,
                    pk,
                    &pub_params.pvss_config.eks,
                    input_secret,
                    &aux,
                    &Player { id: my_index },
                    rng,
                )
            });
        Transcripts {
            main: wtrx,
            fast: fast_wtrx,
        }
    }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L122-152)
```rust
        let threshold = self.epoch_state.verifier.quorum_voting_power();
        let power_check_result = self
            .epoch_state
            .verifier
            .check_voting_power(trx_aggregator.contributors.iter(), true);
        let new_total_power = match &power_check_result {
            Ok(x) => Some(*x),
            Err(VerifyError::TooLittleVotingPower { voting_power, .. }) => Some(*voting_power),
            _ => None,
        };
        let maybe_aggregated = power_check_result
            .ok()
            .map(|_| trx_aggregator.trx.clone().unwrap());
        info!(
            epoch = self.epoch_state.epoch,
            peer = sender,
            is_self = is_self,
            peer_power = peer_power,
            new_total_power = new_total_power,
            threshold = threshold,
            threshold_exceeded = maybe_aggregated.is_some(),
            "[DKG] added transcript from validator {}, {} out of {} aggregated.",
            self.epoch_state
                .verifier
                .address_to_validator_index()
                .get(&sender)
                .unwrap(),
            new_total_power.unwrap_or(0),
            threshold
        );
        Ok(maybe_aggregated)
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

**File:** types/src/dkg/mod.rs (L83-88)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
}
```
