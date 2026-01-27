# Audit Report

## Title
Batch Server Panic on V2 Batch Retrieval Causes Denial of Service

## Summary
The batch request handler in the quorum store crashes when attempting to serve V2 batches due to forced type conversion to V1, causing denial of service for batch retrieval functionality across the network.

## Finding Description

The Aptos consensus quorum store implements versioned batch types (V1 and V2) but contains a critical version mismatch vulnerability in the batch request serving logic. The system allows V2 batches to be created, broadcast, received, and stored, but the batch request handler assumes all batches must be V1 and panics when encountering V2 batches. [1](#0-0) 

The batch server retrieves batches from local storage and forcibly converts them from `Batch<BatchInfoExt>` to `Batch<BatchInfo>` using `.expect()`. This conversion fails for V2 batches because the `TryFrom` implementation explicitly checks for V1-only batches: [2](#0-1) 

**Attack Propagation Path:**

1. **V2 Batch Creation**: Validators with `enable_batch_v2=true` configuration create V2 batches [3](#0-2) 

2. **V2 Batch Broadcasting**: V2 batches are broadcast via `ConsensusMsg::BatchMsgV2` [4](#0-3) 

3. **V2 Batch Storage**: All validators receive, verify, and store V2 batches as `PersistedValue<BatchInfoExt>` regardless of their local configuration [5](#0-4) 

4. **Batch Request Trigger**: When any validator requests a V2 batch (e.g., after missing the original broadcast), the serving validator's batch handler attempts to convert it to V1

5. **Panic and DoS**: The forced conversion fails with panic, terminating the batch serving task

The batch requester explicitly does not support V2 responses, only expecting V1: [6](#0-5) 

## Impact Explanation

**Severity: Medium**

This vulnerability causes denial of service for the batch request functionality, which is critical for validators that miss batch broadcasts and need to fetch batches to execute blocks. The impact includes:

1. **Batch Serving Failure**: The spawned batch serving task panics and terminates, preventing the affected validator from serving any subsequent batch requests

2. **Consensus Liveness Risk**: If multiple validators are affected and cannot serve batch requests, validators that miss broadcasts cannot catch up, potentially causing consensus liveness issues

3. **Network-Wide Propagation**: Once V2 batches exist in the network (from any validator with `enable_batch_v2=true`), ALL validators that store these batches become vulnerable to crash when serving requests for them

This meets the **Medium Severity** criteria: "State inconsistencies requiring intervention" and potentially **High Severity**: "Significant protocol violations" depending on network impact.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur in realistic scenarios:

1. **Configuration Mismatch During Rollouts**: During feature rollouts or upgrades, some validators may enable `enable_batch_v2` while others have not yet upgraded, creating a mixed-version network

2. **Default Configuration Risk**: The default configuration has `enable_batch_v2=false`, but this can be changed per validator [7](#0-6) 

3. **No Version Negotiation**: The protocol lacks version negotiation between batch creator and requester - requests only specify digest, not version [8](#0-7) 

4. **Automatic Trigger**: Once V2 batches exist in the network, any request for them automatically triggers the panic - no additional attacker action required

## Recommendation

Implement proper version handling in the batch request serving logic:

**Option 1: Support V2 Batch Responses**
```rust
let response = if let Ok(value) = batch_store.get_batch_from_local(&rpc_request.req.digest()) {
    let batch: Batch<BatchInfoExt> = value.try_into().unwrap();
    
    // Check batch version and construct appropriate response
    if batch.batch_info().is_v2() {
        BatchResponse::BatchV2(batch)
    } else {
        let batch_v1: Batch<BatchInfo> = batch
            .try_into()
            .expect("V1 batch conversion should succeed");
        BatchResponse::Batch(batch_v1)
    }
} else {
    // ... NotFound handling
};
```

**Option 2: Filter V2 Batches from Retrieval**
Only allow batch requests for V1 batches and return NotFound for V2 batches until full V2 support is implemented.

**Option 3: Network-Wide Version Enforcement**
Use feature flags or epoch-based version enforcement to ensure all validators agree on supported batch versions before enabling V2.

Additionally, update the batch requester to handle V2 responses: [9](#0-8) 

## Proof of Concept

**Rust Reproduction Steps:**

1. Configure two validator nodes: Node A with `enable_batch_v2=true`, Node B with `enable_batch_v2=false`
2. Node A creates and broadcasts a V2 batch via the quorum store
3. Node B receives and stores the V2 batch in its batch store
4. Simulate Node C sending a `BatchRequest` to Node B for the V2 batch digest
5. Observe Node B's batch serving task panic with error: "Batch retrieval requests must be for V1 batch"

**Test Code Outline:**
```rust
#[tokio::test]
async fn test_v2_batch_request_causes_panic() {
    // Setup batch store
    let batch_store = create_batch_store();
    
    // Create and store V2 batch
    let v2_batch = Batch::new_v2(
        batch_id, txns, epoch, expiration,
        author, gas_bucket_start, BatchKind::Normal
    );
    let persisted_v2: PersistedValue<BatchInfoExt> = v2_batch.into();
    batch_store.save(&persisted_v2).unwrap();
    
    // Simulate batch request handling (will panic)
    let digest = persisted_v2.digest();
    let value = batch_store.get_batch_from_local(&digest).unwrap();
    let batch: Batch<BatchInfoExt> = value.try_into().unwrap();
    
    // This expect will panic for V2 batches
    let batch_v1: Batch<BatchInfo> = batch
        .try_into()
        .expect("Batch retrieval requests must be for V1 batch");
}
```

The test will panic on the final conversion, demonstrating the vulnerability.

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

**File:** consensus/src/quorum_store/types.rs (L336-353)
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
        })
    }
}
```

**File:** consensus/src/quorum_store/batch_generator.rs (L190-201)
```rust
        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
```

**File:** consensus/src/network.rs (L617-621)
```rust
    async fn broadcast_batch_msg_v2(&mut self, batches: Vec<Batch<BatchInfoExt>>) {
        fail_point!("consensus::send::broadcast_batch", |_| ());
        let msg = ConsensusMsg::BatchMsgV2(Box::new(BatchMsg::new(batches)));
        self.broadcast(msg).await
    }
```

**File:** consensus/src/round_manager.rs (L175-183)
```rust
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
            },
```

**File:** consensus/src/quorum_store/batch_requester.rs (L120-120)
```rust
            let request = BatchRequest::new(my_peer_id, epoch, digest);
```

**File:** consensus/src/quorum_store/batch_requester.rs (L136-155)
```rust
                            Ok(BatchResponse::Batch(batch)) => {
                                counters::RECEIVED_BATCH_RESPONSE_COUNT.inc();
                                let payload = batch.into_transactions();
                                return Ok(payload);
                            }
                            // Short-circuit if the chain has moved beyond expiration
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
                                }
                            }
                            Ok(BatchResponse::BatchV2(_)) => {
                                error!("Batch V2 response is not supported");
                            }
```

**File:** config/src/config/quorum_store_config.rs (L144-144)
```rust
            enable_batch_v2: false,
```
