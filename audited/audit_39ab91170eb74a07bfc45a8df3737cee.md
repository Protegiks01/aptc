# Audit Report

## Title
DKG ValidatorTransaction Author Field Forgery Vulnerability

## Summary
A malicious validator can forge the `metadata.author` field in a `ValidatorTransaction::DKGResult`, falsely attributing a DKG transcript submission to any other validator. While `DKGMessage::TranscriptResponse` messages are correctly validated during peer-to-peer reliable broadcast, the `ValidatorTransaction::DKGResult` path lacks author authentication when included in block proposals.

## Finding Description

The DKG (Distributed Key Generation) system has two paths for handling `DKGTranscript` objects:

**Path 1 (SECURE): TranscriptResponse in Reliable Broadcast**
When validators exchange individual transcripts via `DKGMessage::TranscriptResponse` during the aggregation phase, the `author` field is properly validated: [1](#0-0) 

This check ensures that `metadata.author` matches the authenticated network `sender` (validated via Noise handshake at the transport layer).

**Path 2 (VULNERABLE): ValidatorTransaction in Block Proposals**
When a validator creates a `ValidatorTransaction::DKGResult` containing an aggregated transcript and submits it via block proposal, the author field is NOT validated. The creation flow sets the author: [2](#0-1) 

However, nothing prevents a malicious validator from modifying their code to set `author: victim_addr` instead of `author: self.my_addr`.

When this transaction is validated during proposal processing, the verification chain is:

1. `process_proposal()` calls `vtxn.verify()`: [3](#0-2) 

2. This calls `dkg_result.verify(verifier)`: [4](#0-3) 

3. Which calls `verify_transcript_extra()` with `ensures_single_dealer: None`: [5](#0-4) 

4. The `None` parameter means the dealer validation is skipped: [6](#0-5) 

At the VM execution layer, the author field is similarly unchecked: [7](#0-6) 

The epoch is validated, but not the author field.

**Attack Scenario:**
1. Malicious Validator M modifies their node software
2. M creates a `DKGTranscript` with `metadata.author = V` (victim validator's address)
3. M wraps it in `ValidatorTransaction::DKGResult` and adds to their vtxn_pool
4. When M proposes a block, they include this forged transaction
5. All validators accept it because:
   - The cryptographic transcript verification passes (the transcript itself is valid)
   - The author field is never checked against M's identity
6. API responses, logs, and metrics now falsely attribute the DKG submission to validator V

## Impact Explanation

**Severity: Low-to-Medium**

This vulnerability breaks the **data integrity invariant** for DKG author attribution but does not compromise:
- DKG protocol correctness (cryptographic transcript validation still works)
- Consensus safety (no double-spend or fork risk)
- State consistency (on-chain state remains correct)

However, it enables:
1. **False Attribution**: API responses expose incorrect author information [8](#0-7) 

2. **Metrics Manipulation**: Monitoring systems tracking DKG submissions per validator will receive false data, potentially affecting:
   - Validator reputation scoring
   - Performance analytics
   - Attribution of DKG completion responsibility

3. **Framing Attacks**: A malicious validator could frame another validator as submitting the DKG result, potentially affecting reputation-based systems.

This falls under **Low Severity** per Aptos bug bounty criteria: "Non-critical implementation bugs" or potentially **Medium Severity** if considered a "protocol violation" of the authenticity guarantee.

## Likelihood Explanation

**Likelihood: Low**

This requires:
- Malicious validator with custom node software (code modification required)
- Validator to be selected as proposer for the relevant block
- No external detection mechanisms monitoring author authenticity

The attack is **easily detectable** post-facto by comparing:
- Which validator proposed the block containing the ValidatorTransaction
- Which validator is claimed as author in the metadata

However, exploitation is **straightforward** once a validator decides to act maliciously.

## Recommendation

Add author validation in the `ValidatorTransaction::DKGResult` verification path. Modify the validation to ensure the DKG transcript author matches the block proposer or is validated against the transaction submitter.

**Option 1: Validate author in `verify()` method**
```rust
// In types/src/validator_txn.rs
pub fn verify(&self, verifier: &ValidatorVerifier, expected_author: Option<AccountAddress>) -> anyhow::Result<()> {
    match self {
        ValidatorTransaction::DKGResult(dkg_result) => {
            if let Some(author) = expected_author {
                ensure!(
                    dkg_result.metadata.author == author,
                    "DKGResult author mismatch: expected {:?}, got {:?}",
                    author,
                    dkg_result.metadata.author
                );
            }
            dkg_result
                .verify(verifier)
                .context("DKGResult verification failed")
        },
        ValidatorTransaction::ObservedJWKUpdate(_) => Ok(()),
    }
}
```

**Option 2: Validate at consensus layer**
```rust
// In consensus/src/round_manager.rs, process_proposal()
if let Some(vtxns) = proposal.validator_txns() {
    for vtxn in vtxns {
        // Validate author matches proposer for DKGResult
        if let ValidatorTransaction::DKGResult(dkg_transcript) = vtxn {
            ensure!(
                dkg_transcript.metadata.author == author,
                "DKGResult author {} does not match block proposer {}",
                dkg_transcript.metadata.author,
                author
            );
        }
        vtxn.verify(self.epoch_state.verifier.as_ref())
            .context(format!("{} verify failed", vtxn.type_name()))?;
    }
}
```

## Proof of Concept

**Conceptual PoC (Rust modification required):**

1. Modify `dkg/src/dkg_manager/mod.rs` line 400:
```rust
// Original:
author: self.my_addr,

// Modified to forge:
author: victim_validator_address,
```

2. Run the DKG protocol as a validator node
3. When your node becomes proposer, the forged ValidatorTransaction will be included
4. Check the API response for the committed DKG transaction - it will show the victim as author
5. Verify via logs that the actual proposer was your validator, not the victim

**Detection Script:**
```python
# Query the block and check if DKGResult author matches block proposer
block = api.get_block(version)
if block.has_dkg_result():
    dkg_author = block.validator_txns[0].dkg_result.author
    block_proposer = block.proposer
    if dkg_author != block_proposer:
        print(f"FRAUD DETECTED: DKG author {dkg_author} != proposer {block_proposer}")
```

## Notes

The vulnerability specifically affects the `ValidatorTransaction::DKGResult` path, not the `DKGMessage::TranscriptResponse` path which IS correctly validated. This distinction is important: peer-to-peer transcript exchange during DKG aggregation is secure, but the final submission to the blockchain lacks author authentication.

The author field is not used in on-chain Move contract logic ( [9](#0-8) ), limiting the on-chain impact to off-chain attribution and metrics systems.

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L84-87)
```rust
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );
```

**File:** dkg/src/dkg_manager/mod.rs (L397-404)
```rust
                let txn = ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: self.epoch_state.epoch,
                        author: self.my_addr,
                    },
                    transcript_bytes: bcs::to_bytes(&agg_trx)
                        .map_err(|e| anyhow!("transcript serialization error: {e}"))?,
                });
```

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

**File:** types/src/dkg/mod.rs (L83-88)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
}
```

**File:** types/src/dkg/real_dkg/mod.rs (L312-316)
```rust
        if ensures_single_dealer.is_some() {
            let expected_dealer_set: HashSet<AccountAddress> =
                ensures_single_dealer.into_iter().collect();
            ensure!(expected_dealer_set == dealer_set);
        }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L99-102)
```rust
        // Check epoch number.
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }
```

**File:** api/types/src/transaction.rs (L844-844)
```rust
    pub author: Address,
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
