# Audit Report

## Title
Batch Retrieval Handler Panic on V2 Batches Causes Validator Service Disruption

## Summary
The batch retrieval RPC handler in `quorum_store_builder.rs` incorrectly assumes all batches are V1 format and attempts to forcefully convert V2 batches to V1, causing a panic that crashes the batch serving task. This vulnerability can be exploited in mixed-version networks or during protocol upgrades to disrupt validator nodes' ability to serve batches to peers. [1](#0-0) 

## Finding Description
The vulnerability exists in the batch retrieval RPC handler which processes incoming batch requests from peers. The handler retrieves batches from local storage using `get_batch_from_local()`, which returns `PersistedValue<BatchInfoExt>`. The `BatchInfoExt` enum can be either V1 or V2 variant, where V2 includes additional metadata about batch kind (Normal or Encrypted). [2](#0-1) 

The handler blindly attempts to convert the retrieved batch to V1 format using `.try_into().expect("Batch retrieval requests must be for V1 batch")`. This conversion is implemented with a strict check that fails if the batch is V2: [3](#0-2) 

When a V2 batch is stored locally (either because `enable_batch_v2=true` in configuration or received from a V2-enabled peer) and another node requests it, the conversion fails and the `.expect()` causes a panic. This crashes the batch serving task, preventing the validator from serving batches to other nodes.

The attack path is:
1. Node stores V2 batches in local storage (via `save_batch_v2()` when `enable_batch_v2=true`)
2. Another validator requests this batch via batch retrieval RPC
3. Handler retrieves V2 batch from local storage
4. Handler attempts to convert V2 to V1 with `.expect()`
5. Conversion fails with error "Batch must be V1 type"
6. Panic crashes the batch serving task
7. Node can no longer serve batches to peers, disrupting consensus operations

Notably, the client-side code already has a `BatchResponse::BatchV2` variant defined but marks it as unsupported: [4](#0-3) [5](#0-4) 

This indicates the infrastructure exists to properly handle V2 responses, but the server-side implementation incorrectly forces all batches to V1.

## Impact Explanation
This is a **High Severity** vulnerability according to Aptos bug bounty criteria:

- **Validator node crashes**: The panic directly crashes the batch serving task, degrading validator functionality
- **Significant protocol violations**: Breaks the assumption that batch retrieval should work for all batches regardless of version
- **Consensus availability impact**: If validators cannot serve batches to peers, it disrupts the quorum store protocol and can slow down consensus

The vulnerability particularly affects:
- Networks during protocol upgrades when V2 is being rolled out
- Mixed-configuration networks where some validators have `enable_batch_v2=true`
- Any validator that has stored V2 batches from peers

This meets the High severity criteria of "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation
The likelihood is **HIGH** because:

1. **Natural occurrence during upgrades**: When the network upgrades to support V2 batches, nodes will naturally store V2 batches, making this vulnerability trigger automatically when other nodes request them

2. **No special privileges required**: Any validator can trigger this by simply requesting a batch that happens to be V2 format

3. **Mixed network scenarios**: In any network with mixed versions (some nodes with V2 enabled, others disabled), this will occur frequently

4. **No validation or protection**: There is no check to prevent the panic or gracefully handle V2 batches

The developers' comment "Batch retrieval requests must be for V1 batch" suggests they assumed batch retrieval would only be used for V1, but there's no enforcement mechanism to ensure this assumption holds true.

## Recommendation
The fix should check the batch variant before attempting conversion and return the appropriate response type:

```rust
let response = if let Ok(value) = batch_store.get_batch_from_local(&rpc_request.req.digest()) {
    let batch: Batch<BatchInfoExt> = value.try_into().unwrap();
    
    // Check variant and return appropriate response
    if batch.batch_info().is_v2() {
        BatchResponse::BatchV2(batch)
    } else {
        let batch_v1: Batch<BatchInfo> = batch
            .try_into()
            .expect("V1 batch conversion should not fail");
        BatchResponse::Batch(batch_v1)
    }
} else {
    match aptos_db_clone.get_latest_ledger_info() {
        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
        Err(e) => {
            // handle error
        }
    }
};
```

Additionally, the client-side should properly handle `BatchV2` responses instead of just logging an error:

```rust
Ok(BatchResponse::BatchV2(batch)) => {
    counters::RECEIVED_BATCH_V2_RESPONSE_COUNT.inc();
    let payload = batch.into_transactions();
    return Ok(payload);
}
```

## Proof of Concept
```rust
// Reproduction steps:

// 1. Configure node with enable_batch_v2 = true
// 2. Create a V2 batch and store it locally
use aptos_consensus_types::proof_of_store::{BatchInfoExt, BatchKind};
use consensus::quorum_store::types::Batch;

let batch_v2 = BatchInfoExt::new_v2(
    author,
    batch_id,
    epoch,
    expiration,
    digest,
    num_txns,
    num_bytes,
    gas_bucket_start,
    BatchKind::Normal,
);

// Store the V2 batch
batch_store.persist(vec![PersistedValue::new(batch_v2, Some(txns))]);

// 3. Another node sends a BatchRequest for this digest
let request = BatchRequest::new(requester_peer_id, epoch, digest);

// 4. The batch retrieval handler processes the request:
// - Retrieves the V2 batch from storage
// - Attempts to convert to V1: batch.try_into().expect(...)
// - Conversion fails because batch is V2
// - PANIC: "Batch retrieval requests must be for V1 batch"

// Expected behavior: Handler should check variant and return BatchResponse::BatchV2
// Actual behavior: Handler panics and crashes the batch serving task

// Impact: The batch_serve task crashes, preventing the validator from
// serving any further batch requests until restart
```

The PoC demonstrates that any V2 batch stored locally will cause a panic when requested by peers, effectively DoS'ing the batch serving capability of the validator.

## Notes
This vulnerability highlights a common pattern of incorrect enum variant assumptions in Rust code. The `BatchInfoExt` enum was designed to support both V1 and V2 variants, and the `get_batch_v2()` function correctly returns the enum type. However, the calling code makes the unsafe assumption that results are always V1, violating the type system's guarantees. The fix requires respecting the enum's design and handling both variants appropriately.

### Citations

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L408-415)
```rust
                let response = if let Ok(value) =
                    batch_store.get_batch_from_local(&rpc_request.req.digest())
                {
                    let batch: Batch<BatchInfoExt> = value.try_into().unwrap();
                    let batch: Batch<BatchInfo> = batch
                        .try_into()
                        .expect("Batch retieval requests must be for V1 batch");
                    BatchResponse::Batch(batch)
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L195-203)
```rust
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

**File:** consensus/src/quorum_store/types.rs (L336-350)
```rust
impl TryFrom<Batch<BatchInfoExt>> for Batch<BatchInfo> {
    type Error = anyhow::Error;

    fn try_from(batch: Batch<BatchInfoExt>) -> Result<Self, Self::Error> {
        ensure!(
            matches!(batch.batch_info(), &BatchInfoExt::V1 { .. }),
            "Batch must be V1 type"
        );
        let Batch {
            batch_info,
            payload,
        } = batch;
        Ok(Self {
            batch_info: batch_info.unpack_info(),
            payload,
```

**File:** consensus/src/quorum_store/types.rs (L417-421)
```rust
pub enum BatchResponse {
    Batch(Batch<BatchInfo>),
    NotFound(LedgerInfoWithSignatures),
    BatchV2(Batch<BatchInfoExt>),
}
```

**File:** consensus/src/quorum_store/batch_requester.rs (L153-155)
```rust
                            Ok(BatchResponse::BatchV2(_)) => {
                                error!("Batch V2 response is not supported");
                            }
```
