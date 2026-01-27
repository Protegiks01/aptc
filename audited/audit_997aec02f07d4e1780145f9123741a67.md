# Audit Report

## Title
Type Confusion in Batch Signature Aggregation Allows Quorum Store Denial of Service

## Summary
A type mismatch vulnerability exists in the quorum store batch verification logic where `SignedBatchInfoMsgV2` messages containing `BatchInfoExt::V1` variants are incorrectly processed with `BatchInfo` type aggregators, allowing malicious validators to inject invalid signatures that pass initial verification but fail during aggregation, potentially preventing batch inclusion.

## Finding Description

The vulnerability stems from a type confusion between `BatchInfo` and `BatchInfoExt::V1` in the batch signature aggregation flow.

**Type Structure:** [1](#0-0) [2](#0-1) 

`BatchInfo` is a struct, while `BatchInfoExt` is an enum that can wrap `BatchInfo` as its `V1` variant. These types have **different cryptographic hashes** because:
1. BCS serialization includes enum discriminant tags for `BatchInfoExt::V1`
2. Different `CryptoHasher` seeds are used for different types
3. `hash(BatchInfo)` ≠ `hash(BatchInfoExt::V1 { info: BatchInfo })`

**Attack Flow:**

1. **Message Reception:** A malicious validator sends `ConsensusMsg::SignedBatchInfoMsgV2` with `BatchInfoExt::V1`: [3](#0-2) 

2. **Initial Verification Passes:** The signature is verified against the correct type (`BatchInfoExt`): [4](#0-3) 

3. **Wrong Aggregator Type Created:** ProofCoordinator checks `is_v2()` which returns `false` for `V1` variant, then extracts inner `BatchInfo`: [5](#0-4) 

4. **Hash Mismatch During Aggregation:** The aggregator attempts to verify with `BatchInfo` type: [6](#0-5) 

5. **Signature Verification Uses Wrong Hash:** The signature was computed over `BatchInfoExt::V1` but is verified against `BatchInfo`: [7](#0-6) [8](#0-7) 

6. **Aggregation Fails:** Multi-signature verification fails due to hash mismatch: [9](#0-8) 

7. **Fallback Filtering:** Invalid signatures are filtered, but if malicious voting power is strategically sized, total voting power drops below quorum threshold after filtering: [10](#0-9) 

**Exploitation Scenario:**
- Honest validators control 68% voting power and send valid V1 signatures
- Malicious validator with 10% voting power sends `SignedBatchInfoMsgV2(BatchInfoExt::V1)` 
- Initial total = 78% (above 2/3 quorum)
- After filtering malicious signature = 68% (below 2/3 quorum)
- Proof aggregation fails permanently
- Batch never included in proposals

## Impact Explanation

**High Severity** - This qualifies as a significant protocol violation under the Aptos bug bounty program:

1. **Quorum Store Liveness Failure:** Malicious validators can prevent specific batches from completing proof-of-store aggregation, blocking transaction inclusion in the blockchain.

2. **Validator Node Performance Degradation:** Failed aggregation attempts trigger expensive signature filtering operations, causing computational overhead and delays.

3. **Consensus Protocol Disruption:** While not breaking consensus safety, this attacks the quorum store subsystem which is critical for transaction throughput and network performance.

The attack requires only a single malicious validator with modest voting power (~10-15%) to strategically deny service on specific batches, making it a realistic threat to network availability.

## Likelihood Explanation

**High Likelihood:**

1. **Low Barrier to Entry:** Any validator can send `ConsensusMsg::SignedBatchInfoMsgV2` messages with `BatchInfoExt::V1` variants - no special privileges required beyond validator status.

2. **No Input Validation:** The code doesn't validate that V2 messages contain only V2-type batch info: [4](#0-3) 

3. **Silent Failure:** The initial verification passes, making detection difficult until aggregation fails.

4. **Strategic Timing:** Attackers can target specific batches by waiting for honest signatures to accumulate, then injecting malicious signatures to prevent quorum.

5. **Persistent Effect:** Once injected, malicious signatures remain in the system until aggregation is attempted, causing repeated failures.

## Recommendation

**Fix 1: Enforce Type Consistency**
Add validation in `UnverifiedEvent::verify` to reject `SignedBatchInfoMsgV2` messages containing `BatchInfoExt::V1` variants:

```rust
UnverifiedEvent::SignedBatchInfoMsgV2(sd) => {
    if !self_message {
        // Validate that V2 messages contain V2 batch info
        for signed_info in sd.signed_infos.iter() {
            if !signed_info.batch_info().is_v2() {
                return Err(VerifyError::InvalidBatchVersion);
            }
        }
        sd.verify(...)?;
        ...
    }
    VerifiedEvent::SignedBatchInfo(sd)
}
```

**Fix 2: Correct Aggregator Type Selection**
Modify `ProofCoordinator::init_proof` to use `BatchInfoExt` aggregator for all messages received via V2 path, regardless of variant:

```rust
// Track whether batch was received via V2 message
if received_via_v2_message {
    self.batch_info_to_proof.insert(
        signed_batch_info.batch_info().clone(),
        IncrementalProofState::new_batch_info_ext(signed_batch_info.batch_info().clone()),
    );
} else {
    // Only use BatchInfo aggregator for V1 messages
    ...
}
```

**Fix 3: Add Metadata Tracking**
Extend `SignedBatchInfo` to track the original message type to ensure consistent type usage throughout aggregation.

## Proof of Concept

```rust
// Malicious validator sends V2 message with V1 batch info
let batch_info = BatchInfo::new(
    malicious_validator_id,
    batch_id,
    epoch,
    expiration,
    digest,
    num_txns,
    num_bytes,
    gas_bucket_start,
);

// Wrap as BatchInfoExt::V1
let batch_info_ext = BatchInfoExt::V1 { info: batch_info };

// Sign with CORRECT type (BatchInfoExt::V1)
let signed_batch_info = SignedBatchInfo::new(batch_info_ext, &validator_signer)?;

// Send as V2 message (incorrect usage)
let msg = ConsensusMsg::SignedBatchInfoMsgV2(Box::new(
    SignedBatchInfoMsg::new(vec![signed_batch_info])
));

// Message passes initial verification but causes aggregation failure
// because ProofCoordinator creates BatchInfo aggregator for V1 variant
// while signature was computed over BatchInfoExt::V1
```

**Steps to Reproduce:**
1. Set up a test network with validators having voting power distribution: [68%, 10%, 22%]
2. Validator 1 (68%) sends honest `SignedBatchInfo(BatchInfo)` for a batch
3. Validator 2 (10%) sends malicious `SignedBatchInfoMsgV2(BatchInfoExt::V1)` for same batch
4. Observe initial aggregation reaches 78% voting power (above quorum)
5. Observe aggregation verification fails due to hash mismatch
6. Observe signature filtering removes malicious signature
7. Observe remaining voting power (68%) is below 2/3 quorum threshold
8. Observe proof never completes and batch is never included in blocks

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L46-58)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub struct BatchInfo {
    author: PeerId,
    batch_id: BatchId,
    epoch: u64,
    expiration: u64,
    digest: HashValue,
    num_txns: u64,
    num_bytes: u64,
    gas_bucket_start: u64,
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L192-203)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub enum BatchInfoExt {
    V1 {
        info: BatchInfo,
    },
    V2 {
        info: BatchInfo,
        extra: ExtraBatchInfo,
    },
}
```

**File:** consensus/src/network_interface.rs (L98-102)
```rust
    /// Quorum Store: Send a signed batch digest with BatchInfoExt. This is a vote for the batch and a promise that
    /// the batch of transactions was received and will be persisted until batch expiration.
    SignedBatchInfoMsgV2(Box<SignedBatchInfoMsg<BatchInfoExt>>),
    /// Quorum Store: Broadcast a certified proof of store (a digest that received 2f+1 votes) with BatchInfoExt.
    ProofOfStoreMsgV2(Box<ProofOfStoreMsg<BatchInfoExt>>),
```

**File:** consensus/src/round_manager.rs (L198-211)
```rust
            UnverifiedEvent::SignedBatchInfoMsgV2(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(sd)
            },
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L80-91)
```rust
    pub fn aggregate_and_verify(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<(BatchInfoExt, AggregateSignature), VerifyError> {
        match self {
            Self::BatchInfo(aggregator) => {
                let (batch_info, aggregate_sig) = aggregator.aggregate_and_verify(verifier)?;
                Ok((batch_info.into(), aggregate_sig))
            },
            Self::BatchInfoExt(aggregator) => aggregator.aggregate_and_verify(verifier),
        }
    }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L289-300)
```rust
        if signed_batch_info.batch_info().is_v2() {
            self.batch_info_to_proof.insert(
                signed_batch_info.batch_info().clone(),
                IncrementalProofState::new_batch_info_ext(signed_batch_info.batch_info().clone()),
            );
        } else {
            self.batch_info_to_proof.insert(
                signed_batch_info.batch_info().clone(),
                IncrementalProofState::new_batch_info(
                    signed_batch_info.batch_info().info().clone(),
                ),
            );
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_sigs.rs (L140-143)
```rust
    /// Serializes the message of type `T` to bytes and calls `Signature::verify_arbitrary_msg`.
    fn verify<T: CryptoHash + Serialize>(&self, message: &T, public_key: &PublicKey) -> Result<()> {
        self.verify_arbitrary_msg(&signing_message(message)?, public_key)
    }
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L168-177)
```rust
/// Returns the signing message for the given message.
/// It is used by `SigningKey#sign` function.
pub fn signing_message<T: CryptoHash + Serialize>(
    message: &T,
) -> Result<Vec<u8>, CryptoMaterialError> {
    let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
    bcs::serialize_into(&mut bytes, &message)
        .map_err(|_| CryptoMaterialError::SerializationError)?;
    Ok(bytes)
}
```

**File:** types/src/ledger_info.rs (L510-513)
```rust
    fn filter_invalid_signatures(&mut self, verifier: &ValidatorVerifier) {
        let signatures = mem::take(&mut self.signatures);
        self.signatures = verifier.filter_invalid_signatures(&self.data, signatures);
    }
```

**File:** types/src/ledger_info.rs (L517-536)
```rust
    pub fn aggregate_and_verify(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<(T, AggregateSignature), VerifyError> {
        let aggregated_sig = self.try_aggregate(verifier)?;

        match verifier.verify_multi_signatures(&self.data, &aggregated_sig) {
            Ok(_) => {
                // We are not marking all the signatures as "verified" here, as two malicious
                // voters can collude and create a valid aggregated signature.
                Ok((self.data.clone(), aggregated_sig))
            },
            Err(_) => {
                self.filter_invalid_signatures(verifier);

                let aggregated_sig = self.try_aggregate(verifier)?;
                Ok((self.data.clone(), aggregated_sig))
            },
        }
    }
```
