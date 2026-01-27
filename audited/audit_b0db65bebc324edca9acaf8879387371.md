# Audit Report

## Title
DKG Transcript Author Field Validation Bypass Allows Attribution Fraud

## Summary
The `DKGTranscript.metadata.author` field is never validated against the active validator set during consensus block proposal validation, allowing malicious validators to forge authorship attribution for DKG updates. While P2P transcript aggregation correctly validates the author field, the consensus validation path bypasses this check, enabling false attribution that persists on-chain and is exposed via public APIs.

## Finding Description

The DKG (Distributed Key Generation) system uses a `DKGTranscript` structure containing a `metadata.author` field that identifies which validator created the transcript. This field is validated during P2P aggregation but completely bypassed during consensus block validation.

**Validation Gap in Consensus Path:**

When a validator includes a `ValidatorTransaction::DKGResult` in their block proposal, the validation chain is: [1](#0-0) 

This calls the verification function: [2](#0-1) 

Which delegates to: [3](#0-2) 

The critical issue is that `verify_transcript_extra` is called with `ensures_single_dealer: None`: [4](#0-3) 

This validation only checks that dealers **inside the transcript bytes** are valid validators with quorum voting power (lines 301-322), but **never validates the `metadata.author` field**. When `ensures_single_dealer` is `None`, lines 312-316 are skipped.

**Contrast with P2P Aggregation (Secure):**

The P2P aggregation path correctly validates the author: [5](#0-4) 

**VM Execution Ignores Author:**

During execution, only the epoch is validated, and the author field is not passed to the Move function: [6](#0-5) 

The Move function only stores the transcript bytes: [7](#0-6) 

**API Exposure:**

The false author is exposed through the public API: [8](#0-7) 

**Attack Scenario:**
1. Validator A waits for a valid DKG transcript to be aggregated P2P with quorum
2. Validator A (when selected as block proposer) takes the valid transcript bytes
3. Validator A creates a new `DKGTranscript` with `metadata.author` set to Validator B's address (or even a non-validator address like `0x0`)
4. Validator A includes this in their block proposal
5. The validation passes because the transcript bytes are valid (quorum dealers inside)
6. The block is committed with false authorship attribution
7. APIs and indexers show Validator B (or `0x0`) as the DKG author

## Impact Explanation

This vulnerability represents a **Medium Severity** issue under the Aptos bug bounty program:

- **Protocol Violation**: Breaks the accountability invariant in the DKG subsystem, a critical component for on-chain randomness
- **State Inconsistency**: Creates permanently incorrect attribution data in the blockchain state and API responses
- **Monitoring Corruption**: Dashboards and analytics tools will display false validator participation metrics
- **Future Risk**: If future upgrades add reward/penalty systems based on DKG participation, this could enable fund misallocation
- **No Consensus Impact**: Does not cause state divergence, consensus safety violations, or fund loss (current implementation)

While not immediately critical, this corrupts a fundamental security property (accountability) of a core protocol component.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Attacker Requirements**: Must be an active validator selected as block proposer (happens regularly in round-robin)
- **Complexity**: Low - simple field manipulation, no cryptographic attacks required
- **Detection Difficulty**: High - observers cannot distinguish legitimate from forged author fields without comparing to P2P aggregation logs
- **Current Exploitation**: Likely not occurring (no economic incentive yet), but trivial to execute

Any validator can exploit this during their proposer slot, making it highly accessible to malicious validators.

## Recommendation

Add author validation in the consensus validation path by passing the author field through the verification chain:

**Fix 1: Modify DKGTranscript::verify to validate author**

```rust
// In types/src/dkg/mod.rs
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
        .context("Transcripts deserialization failed")?;
    
    // Validate author is in active validator set
    ensure!(
        verifier.get_voting_power(&self.metadata.author).is_some(),
        "DKG transcript author is not an active validator"
    );
    
    // Validate author is one of the dealers in the transcript
    let dealers = RealDKG::get_dealers(&transcripts);
    let all_validator_addrs = verifier.get_ordered_account_addresses();
    let author_index = all_validator_addrs
        .iter()
        .position(|addr| *addr == self.metadata.author)
        .context("Author address not in validator set")?;
    ensure!(
        dealers.contains(&(author_index as u64)),
        "DKG transcript author is not among the dealers"
    );
    
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

**Fix 2: Alternatively, enforce single-dealer validation during block proposal**

Ensure that when a DKG transcript is included in a block, the dealers set contains exactly the author, preventing multi-dealer aggregated transcripts in blocks (they should only appear via P2P aggregation).

## Proof of Concept

```rust
#[test]
fn test_dkg_author_spoofing() {
    // Setup: Create a validator set with validators A and B
    let validators = create_test_validator_set(vec![
        ("validator_a", 100),
        ("validator_b", 100),
    ]);
    
    let verifier = ValidatorVerifier::new(validators.clone());
    
    // Validator A creates a valid DKG transcript
    let valid_transcript_bytes = create_valid_dkg_transcript(
        &validators[0],
        /* dealer is validator A */
    );
    
    // Malicious validator creates DKGTranscript with WRONG author
    let spoofed_transcript = DKGTranscript {
        metadata: DKGTranscriptMetadata {
            epoch: 1,
            author: validators[1].address, // Claims validator B authored it!
        },
        transcript_bytes: valid_transcript_bytes, // But uses A's transcript
    };
    
    // This should fail but currently PASSES
    let result = spoofed_transcript.verify(&verifier);
    assert!(result.is_ok()); // BUG: Validation passes despite wrong author
    
    // The spoofed transcript would be accepted in a block proposal
    // and committed with false attribution to validator B
}
```

**Notes:**

The indexer-grpc conversion function mentioned in the security question is not responsible for validation—it merely converts already-committed transactions to protobuf format: [9](#0-8) 

The vulnerability exists in the consensus and execution validation layers, not the indexer.

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

**File:** types/src/dkg/mod.rs (L83-88)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
}
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

**File:** dkg/src/transcript_aggregation/mod.rs (L79-97)
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
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L100-120)
```rust
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }

        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;

        // All check passed, invoke VM to publish DKG result on chain.
        let mut gas_meter = UnmeteredGasMeter;
        let mut session = self.new_session(resolver, session_id, None);
        let args = vec![
            MoveValue::Signer(AccountAddress::ONE),
            dkg_node.transcript_bytes.as_move_value(),
        ];
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L90-97)
```text
    public(friend) fun finish(transcript: vector<u8>) acquires DKGState {
        let dkg_state = borrow_global_mut<DKGState>(@aptos_framework);
        assert!(option::is_some(&dkg_state.in_progress), error::invalid_state(EDKG_NOT_IN_PROGRESS));
        let session = option::extract(&mut dkg_state.in_progress);
        session.transcript = transcript;
        dkg_state.last_completed = option::some(session);
        dkg_state.in_progress = option::none();
    }
```

**File:** api/types/src/transaction.rs (L842-860)
```rust
pub struct ExportedDKGTranscript {
    pub epoch: U64,
    pub author: Address,
    pub payload: HexEncodedBytes,
}

impl From<DKGTranscript> for ExportedDKGTranscript {
    fn from(value: DKGTranscript) -> Self {
        let DKGTranscript {
            metadata,
            transcript_bytes,
        } = value;
        let DKGTranscriptMetadata { epoch, author } = metadata;
        Self {
            epoch: epoch.into(),
            author: author.into(),
            payload: HexEncodedBytes::from(transcript_bytes),
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L950-967)
```rust
fn convert_validator_transaction(
    api_validator_txn: &aptos_api_types::transaction::ValidatorTransaction,
) -> transaction::transaction::TxnData {
    transaction::transaction::TxnData::Validator(transaction::ValidatorTransaction {
        validator_transaction_type: match api_validator_txn {
            ApiValidatorTransactionEnum::DkgResult(dgk_result) => {
                Some(
                    validator_transaction::ValidatorTransactionType::DkgUpdate(
                        validator_transaction::DkgUpdate {
                            dkg_transcript: Some(validator_transaction::dkg_update::DkgTranscript {
                                author: dgk_result.dkg_transcript.author.to_string(),
                                epoch: dgk_result.dkg_transcript.epoch.0,
                                payload: dgk_result.dkg_transcript.payload.0.clone(),
                            }),
                        },
                    )
                )
            },
```
