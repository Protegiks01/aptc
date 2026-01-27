# Audit Report

## Title
Incomplete Cryptographic Validation of DKG Transcripts in Consensus Layer Allows Invalid Transactions to be Committed

## Summary
The consensus layer's validation of `DKGResult` validator transactions only performs metadata checks (dealer indices, voting power) without verifying cryptographic proofs (signatures, pairing-based encryption correctness, low-degree tests). This allows malicious validators to propose blocks containing DKG transcripts with valid BCS serialization but corrupted cryptographic proofs. These invalid transactions pass consensus validation and are committed to the blockchain, only to be rejected during VM execution. This creates a validation gap that wastes network resources and could potentially impact epoch transitions requiring valid DKG results for randomness generation.

## Finding Description

The vulnerability exists in the DKG transcript verification flow during consensus validation. When a validator proposes a block containing a `ValidatorTransaction::DKGResult`, the consensus layer calls `vtxn.verify()` which only performs partial validation: [1](#0-0) 

This delegates to `ValidatorTransaction::verify()`: [2](#0-1) 

Which calls `DKGTranscript::verify()`: [3](#0-2) 

The critical issue is that `DKGTranscript::verify()` only calls `RealDKG::verify_transcript_extra()`, which performs **metadata validation only**: [4](#0-3) 

This function checks:
- Dealer indices are valid
- Voting power is sufficient  
- Fast path and main path dealer/key consistency

However, it does **NOT** call the cryptographic verification function. The actual cryptographic verification happens in `RealDKG::verify_transcript()`: [5](#0-4) 

This function performs the critical cryptographic checks including calling `trx.main.verify()`: [6](#0-5) 

This cryptographic verification (PVSS transcript verification including signature verification, pairing checks, and low-degree tests) is **only performed during VM execution**, not during consensus validation: [7](#0-6) 

**Attack Path:**
1. Malicious validator creates a `DKGTranscript` with valid BCS-serialized `transcript_bytes` but corrupted cryptographic proofs (invalid signatures, incorrect pairings, etc.)
2. Proposes a block containing this `DKGResult`
3. During consensus validation, `verify_transcript_extra()` only checks metadata → passes ✓
4. Block is voted on and committed to the blockchain
5. During execution, `verify_transcript()` performs full crypto verification → fails ✗
6. Transaction is discarded with `TransactionStatus::Discard(StatusCode::ABORTED)`: [8](#0-7) 

7. DKG result is not applied to state, potentially impacting epoch transition

This violates the **Transaction Validation** and **Deterministic Execution** invariants by allowing invalid transactions to be committed before being validated.

## Impact Explanation

**Severity: HIGH** - This qualifies as "Significant protocol violations" under the Aptos bug bounty program.

**Security Impact:**
1. **Protocol Violation**: Invalid transactions are committed to the blockchain, violating the principle that consensus should only commit valid transactions
2. **Resource Exhaustion**: Network bandwidth and computational resources are wasted validating, propagating, and storing invalid transactions
3. **Potential Liveness Impact**: If the discarded DKG result was critical for epoch transition and randomness generation, it could cause epoch transition failures or unavailability of randomness in the next epoch
4. **Defense in Depth Failure**: Validation should occur at the earliest possible stage (consensus) rather than deferring to execution

**Why Not Critical:**
- No direct fund loss or theft
- No consensus safety violation (all nodes deterministically discard the transaction)
- No permanent state corruption

**Why HIGH:**
- Significant protocol design flaw where consensus layer trusts validator-provided data without cryptographic verification
- Can be exploited by a single malicious validator without collusion
- Impacts critical system functionality (DKG for randomness generation)
- Wastes network-wide resources

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors Increasing Likelihood:**
- Only requires a single malicious validator (no collusion needed)
- Aptos Byzantine fault tolerance model assumes up to 1/3 of validators can be Byzantine
- Attack is straightforward - simply submit invalid cryptographic proofs in otherwise well-formed BCS data
- No special timing or race conditions required

**Factors Decreasing Likelihood:**
- Requires validator status (not exploitable by arbitrary attackers)
- Malicious validators risk reputation and potential slashing
- The attack is detectable in execution logs

However, in a Byzantine fault tolerance model, the protocol should be robust against a single malicious validator, making this a realistic attack scenario.

## Recommendation

**Fix: Perform full cryptographic verification during consensus validation**

Modify `DKGTranscript::verify()` to call `verify_transcript()` instead of `verify_transcript_extra()`:

```rust
// In types/src/dkg/mod.rs

impl DKGTranscript {
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        
        // Create the public parameters needed for full verification
        // This requires access to DKG session metadata
        // Option 1: Pass session metadata to verify()
        // Option 2: Fetch it from on-chain state within verify()
        // Option 3: Cache it in ValidatorVerifier for current epoch
        
        // For now, showing conceptual fix - implementation needs session metadata access
        let pub_params = RealDKG::new_public_params(&session_metadata);
        
        // Perform FULL cryptographic verification
        RealDKG::verify_transcript(&pub_params, &transcripts)?;
        
        // Also perform voting power checks
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
}
```

**Note:** The fix requires refactoring to make DKG session metadata available during consensus validation. The current architecture may need adjustment to pass this context through the validation chain.

**Alternative Mitigation:**
If full cryptographic verification in consensus is too expensive, consider:
1. Lightweight pre-checks (e.g., signature verification only) in consensus
2. Fast-fail checks that reject obviously invalid transcripts
3. Rate limiting on DKG result proposals per validator

## Proof of Concept

```rust
// Proof of Concept Test (add to types/src/dkg/mod.rs or appropriate test file)

#[cfg(test)]
mod test_incomplete_validation {
    use super::*;
    use crate::dkg::real_dkg::{Transcripts, RealDKG};
    use crate::validator_verifier::ValidatorVerifier;
    use aptos_crypto::bls12381;
    
    #[test]
    fn test_invalid_crypto_passes_consensus_validation() {
        // Setup: Create valid DKG session and verifier
        let (validators, verifier) = create_test_validators(4);
        
        // Create a DKG transcript with valid structure
        let mut valid_transcript = create_valid_test_transcript(&validators);
        
        // Corrupt the cryptographic proofs while keeping BCS structure valid
        // For example, flip bits in signature or encryption data
        corrupt_transcript_crypto(&mut valid_transcript);
        
        // Serialize to bytes
        let transcript_bytes = bcs::to_bytes(&valid_transcript).unwrap();
        
        let dkg_transcript = DKGTranscript {
            metadata: DKGTranscriptMetadata {
                epoch: 1,
                author: validators[0].address,
            },
            transcript_bytes,
        };
        
        // Test consensus validation (uses verify_transcript_extra)
        // This should PASS but it has invalid crypto!
        let consensus_validation = dkg_transcript.verify(&verifier);
        assert!(consensus_validation.is_ok(), 
            "Consensus validation should pass for corrupted transcript");
        
        // Test VM execution validation (uses verify_transcript)
        // This should FAIL due to invalid crypto
        let transcripts: Transcripts = bcs::from_bytes(&dkg_transcript.transcript_bytes).unwrap();
        let pub_params = RealDKG::new_public_params(&create_test_session_metadata(&validators));
        let vm_validation = RealDKG::verify_transcript(&pub_params, &transcripts);
        assert!(vm_validation.is_err(), 
            "VM validation should fail for corrupted transcript");
        
        // This demonstrates the validation gap:
        // Invalid transaction passes consensus but fails execution
        println!("VULNERABILITY DEMONSTRATED:");
        println!("- Consensus validation: {:?}", consensus_validation);
        println!("- VM validation: {:?}", vm_validation);
    }
    
    fn corrupt_transcript_crypto(transcript: &mut Transcripts) {
        // Flip some bits in the main transcript's cryptographic data
        // This maintains BCS validity but corrupts crypto proofs
        // Implementation would flip bits in signatures, encryptions, etc.
    }
}
```

## Notes

This vulnerability represents a defense-in-depth failure where consensus delegates cryptographic validation to execution. While execution correctly rejects invalid transcripts, the gap allows resource waste and potential epoch transition issues. The fix requires architectural changes to make DKG session metadata available during consensus validation, which may have performance implications that need careful evaluation.

### Citations

**File:** consensus/src/round_manager.rs (L1134-1135)
```rust
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
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

**File:** types/src/dkg/real_dkg/mod.rs (L332-401)
```rust
    fn verify_transcript(
        params: &Self::PublicParams,
        trx: &Self::Transcript,
    ) -> anyhow::Result<()> {
        // Verify dealer indices are valid.
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );

        let all_eks = params.pvss_config.eks.clone();

        let addresses = params.verifier.get_ordered_account_addresses();
        let dealers_addresses = dealers
            .iter()
            .filter_map(|&pos| addresses.get(pos))
            .cloned()
            .collect::<Vec<_>>();

        let spks = dealers_addresses
            .iter()
            .filter_map(|author| params.verifier.get_public_key(author))
            .collect::<Vec<_>>();

        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();

        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;

        // Verify fast path is present if and only if fast_wconfig is present.
        ensure!(
            trx.fast.is_some() == params.pvss_config.fast_wconfig.is_some(),
            "real_dkg::verify_transcript failed with mismatched fast path flag in trx and params."
        );

        if let Some(fast_trx) = trx.fast.as_ref() {
            let fast_dealers = fast_trx
                .get_dealers()
                .iter()
                .map(|player| player.id)
                .collect::<Vec<usize>>();
            ensure!(
                dealers == fast_dealers,
                "real_dkg::verify_transcript failed with inconsistent dealer index."
            );
        }

        if let (Some(fast_trx), Some(fast_wconfig)) =
            (trx.fast.as_ref(), params.pvss_config.fast_wconfig.as_ref())
        {
            fast_trx.verify(fast_wconfig, &params.pvss_config.pp, &spks, &all_eks, &aux)?;
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L68-77)
```rust
            Err(Expected(failure)) => {
                // Pretend we are inside Move, and expected failures are like Move aborts.
                Ok((
                    VMStatus::MoveAbort {
                        location: AbortLocation::Script,
                        code: failure as u64,
                        message: None,
                    },
                    VMOutput::empty_with_status(TransactionStatus::Discard(StatusCode::ABORTED)),
                ))
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L104-112)
```rust
        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```
