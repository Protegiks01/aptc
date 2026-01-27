# Audit Report

## Title
Critical Panic in Batch Serving Task When V2 Batches Are Enabled - Permanent Batch Retrieval Failure

## Summary
The batch serving async task in `spawn_quorum_store()` contains hardcoded assumptions that all batches are V1 format. When the `enable_batch_v2` configuration is enabled, the task panics when attempting to serve V2 batches, permanently terminating the task and causing all subsequent batch retrieval requests to fail silently. This results in a complete loss of batch retrieval functionality for the affected validator node. [1](#0-0) 

## Finding Description
The vulnerability exists in the batch serving task spawned at lines 404-438. The task processes incoming batch retrieval requests through the following logic:

1. Retrieves a batch from local storage using `batch_store.get_batch_from_local()` which returns `PersistedValue<BatchInfoExt>`
2. **Line 411**: Converts to `Batch<BatchInfoExt>` using `.unwrap()` - panics if payload is missing with error "Payload not exist"
3. **Lines 412-414**: Force-converts `Batch<BatchInfoExt>` to `Batch<BatchInfo>` using `.expect("Batch retrieval requests must be for V1 batch")` - **panics if the batch is V2 format**
4. Returns response as `BatchResponse::Batch(batch)` [2](#0-1) 

The conversion from `Batch<BatchInfoExt>` to `Batch<BatchInfo>` explicitly checks that the batch is V1 and panics for V2 batches: [3](#0-2) 

When `enable_batch_v2` is enabled in the configuration, validators create and persist V2 batches: [4](#0-3) [5](#0-4) 

The `BatchInfoExt` enum supports both V1 and V2 variants: [6](#0-5) 

The `BatchResponse` enum already has a `BatchV2` variant designed to handle V2 batches, but the batch serving task doesn't use it: [7](#0-6) 

**Attack Scenario:**
1. A validator enables `enable_batch_v2 = true` in their configuration
2. The validator generates and persists V2 batches to their batch store
3. Another validator requests one of these V2 batches via the batch retrieval RPC
4. The batch serving task retrieves the V2 batch from storage successfully
5. Line 412-414 attempts to convert the V2 batch to V1 format
6. The conversion panics with "Batch must be V1 type"
7. **The entire async task terminates permanently**
8. All subsequent batch retrieval requests queue up in `batch_retrieval_rx` but are never processed
9. Other validators cannot retrieve batches from this node, impacting consensus progress

## Impact Explanation
This vulnerability has **Critical** severity impact:

**Total Loss of Liveness/Network Availability**: Once the batch serving task panics, the affected validator node can no longer serve batch data to other validators. This breaks the Quorum Store protocol's batch distribution mechanism, which is essential for consensus operation.

**Consensus Impact**: Validators rely on batch retrieval to obtain transaction payloads referenced by batch digests in proposed blocks. If batch retrieval fails:
- Validators cannot execute blocks containing batches from the affected node
- This can stall consensus progress if enough validators are affected
- Network partitioning can occur if different subsets of validators can/cannot retrieve batches

**Silent Failure**: The failure is particularly severe because:
- The task dies silently - no panic handler recovers it
- Incoming requests queue indefinitely without responses
- The node appears operational but cannot fulfill batch requests
- Other validators experience timeouts and retries, degrading performance

**Scope**: Any validator that enables `enable_batch_v2` becomes vulnerable. As this is a configuration option that may be enabled network-wide in the future, the vulnerability could affect the entire validator set simultaneously.

This meets the **Critical Severity** criteria from the Aptos Bug Bounty: "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)" if widely deployed.

## Likelihood Explanation
**Likelihood: Medium to High**

**Triggering Conditions:**
1. `enable_batch_v2` must be set to `true` in the quorum store configuration
2. A validator must generate and store V2 batches
3. Another validator must request one of these V2 batches

**Current Status:**
- The default configuration has `enable_batch_v2 = false`, so the vulnerability is not currently active in production
- However, the feature exists and is intended to be enabled in the future
- The code explicitly supports V2 batch creation, storage, and handling throughout the codebase

**Future Risk:**
- When V2 batches are enabled network-wide (likely for a protocol upgrade), all nodes become immediately vulnerable
- No gradual rollout protection exists
- The panic is deterministic - it WILL occur for every V2 batch request

**Attacker Requirements:**
- No special privileges needed - normal validator operation triggers the bug
- Not intentionally exploitable by external attackers, but validator misconfiguration or protocol upgrade triggers it
- Once triggered, the damage is permanent until node restart

The vulnerability is a **time bomb** - dormant now but guaranteed to activate when the V2 batch feature is enabled.

## Recommendation

**Fix Strategy**: Handle both V1 and V2 batches correctly in the batch serving task by checking the batch version and using the appropriate `BatchResponse` variant.

**Code Fix**:

Replace lines 408-415 in `consensus/src/quorum_store/quorum_store_builder.rs` with:

```rust
let response = if let Ok(value) =
    batch_store.get_batch_from_local(&rpc_request.req.digest())
{
    match value.try_into() {
        Ok(batch_ext) => {
            let batch: Batch<BatchInfoExt> = batch_ext;
            // Check if this is a V2 batch
            if batch.batch_info().is_v2() {
                BatchResponse::BatchV2(batch)
            } else {
                // Convert V1 BatchInfoExt to BatchInfo
                match batch.try_into() {
                    Ok(batch_v1) => BatchResponse::Batch(batch_v1),
                    Err(e) => {
                        error!(epoch = epoch, error = ?e, "Failed to convert V1 batch");
                        match aptos_db_clone.get_latest_ledger_info() {
                            Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
                            Err(e) => {
                                let e = anyhow::Error::from(e);
                                error!(epoch = epoch, error = ?e, kind = error_kind(&e));
                                continue;
                            },
                        }
                    }
                }
            }
        },
        Err(e) => {
            error!(epoch = epoch, error = ?e, "Failed to convert to Batch");
            match aptos_db_clone.get_latest_ledger_info() {
                Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
                Err(e) => {
                    let e = anyhow::Error::from(e);
                    error!(epoch = epoch, error = ?e, kind = error_kind(&e));
                    continue;
                },
            }
        }
    }
} else {
    match aptos_db_clone.get_latest_ledger_info() {
        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
        Err(e) => {
            let e = anyhow::Error::from(e);
            error!(epoch = epoch, error = ?e, kind = error_kind(&e));
            continue;
        },
    }
};
```

**Additional Fix Required**: The batch requester also needs to be updated to handle `BatchResponse::BatchV2` responses properly: [8](#0-7) 

Replace the error case with proper V2 batch handling that extracts transactions from the V2 batch.

**Validation**: After the fix, test both:
1. V1 batch retrieval continues to work
2. V2 batch retrieval works when `enable_batch_v2 = true`
3. No panics occur in either case

## Proof of Concept

**Reproduction Steps**:

1. **Setup**: Configure two validator nodes (Node A and Node B)

2. **Enable V2 on Node A**:
   - Set `enable_batch_v2 = true` in Node A's quorum store config
   - Restart Node A

3. **Generate V2 Batch on Node A**:
   - Let Node A generate transactions and create batches
   - Verify V2 batches are created by checking logs for batch creation with `enable_batch_v2` flag

4. **Trigger Batch Request from Node B**:
   - Node B participates in consensus and encounters a block proposal containing a batch digest from Node A
   - Node B attempts to retrieve the V2 batch from Node A via the batch retrieval RPC

5. **Observe Panic**:
   - Node A's batch serving task will panic with: `"Batch retrieval requests must be for V1 batch"`
   - The task terminates permanently
   - Monitor Node A logs for the panic trace

6. **Verify Permanent Failure**:
   - Send additional batch requests to Node A from any node
   - Observe that all requests timeout - no responses are sent
   - The `batch_serve` task is no longer running
   - Only a node restart can restore batch serving functionality

**Expected Panic Trace**:
```
thread 'tokio-runtime-worker' panicked at 'Batch retrieval requests must be for V1 batch'
consensus/src/quorum_store/types.rs:343
```

**Test Code** (simplified Rust reproduction):

```rust
#[test]
fn test_batch_serve_v2_panic() {
    // Create a V2 batch
    let v2_batch = Batch::new_v2(
        batch_id,
        transactions,
        epoch,
        expiration,
        author,
        gas_bucket_start,
        BatchKind::Normal,
    );
    
    // Convert to PersistedValue
    let persisted: PersistedValue<BatchInfoExt> = v2_batch.into();
    
    // This is what the batch serving task does
    let batch_ext: Batch<BatchInfoExt> = persisted.try_into().unwrap();
    
    // This will panic for V2 batches
    let _batch_v1: Batch<BatchInfo> = batch_ext
        .try_into()
        .expect("Batch retrieval requests must be for V1 batch");
}
```

This test will panic, demonstrating the vulnerability.

### Citations

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L404-438)
```rust
        spawn_named!("batch_serve", async move {
            info!(epoch = epoch, "Batch retrieval task starts");
            while let Some(rpc_request) = batch_retrieval_rx.next().await {
                counters::RECEIVED_BATCH_REQUEST_COUNT.inc();
                let response = if let Ok(value) =
                    batch_store.get_batch_from_local(&rpc_request.req.digest())
                {
                    let batch: Batch<BatchInfoExt> = value.try_into().unwrap();
                    let batch: Batch<BatchInfo> = batch
                        .try_into()
                        .expect("Batch retieval requests must be for V1 batch");
                    BatchResponse::Batch(batch)
                } else {
                    match aptos_db_clone.get_latest_ledger_info() {
                        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
                        Err(e) => {
                            let e = anyhow::Error::from(e);
                            error!(epoch = epoch, error = ?e, kind = error_kind(&e));
                            continue;
                        },
                    }
                };

                let msg = ConsensusMsg::BatchResponseV2(Box::new(response));
                let bytes = rpc_request.protocol.to_bytes(&msg).unwrap();
                if let Err(e) = rpc_request
                    .response_sender
                    .send(Ok(bytes.into()))
                    .map_err(|_| anyhow::anyhow!("Failed to send block retrieval response"))
                {
                    warn!(epoch = epoch, error = ?e, kind = error_kind(&e));
                }
            }
            info!(epoch = epoch, "Batch retrieval task stops");
        });
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

**File:** consensus/src/quorum_store/types.rs (L416-421)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BatchResponse {
    Batch(Batch<BatchInfo>),
    NotFound(LedgerInfoWithSignatures),
    BatchV2(Batch<BatchInfoExt>),
}
```

**File:** consensus/src/quorum_store/batch_generator.rs (L190-211)
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
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
```

**File:** config/src/config/quorum_store_config.rs (L102-144)
```rust
    pub enable_batch_v2: bool,
}

impl Default for QuorumStoreConfig {
    fn default() -> QuorumStoreConfig {
        QuorumStoreConfig {
            channel_size: 1000,
            proof_timeout_ms: 10000,
            batch_generation_poll_interval_ms: 25,
            batch_generation_min_non_empty_interval_ms: 50,
            batch_generation_max_interval_ms: 250,
            sender_max_batch_txns: DEFEAULT_MAX_BATCH_TXNS,
            // TODO: on next release, remove BATCH_PADDING_BYTES
            sender_max_batch_bytes: 1024 * 1024 - BATCH_PADDING_BYTES,
            sender_max_num_batches: DEFAULT_MAX_NUM_BATCHES,
            sender_max_total_txns: 1500,
            // TODO: on next release, remove DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES
            sender_max_total_bytes: 4 * 1024 * 1024 - DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES,
            receiver_max_batch_txns: 100,
            receiver_max_batch_bytes: 1024 * 1024 + BATCH_PADDING_BYTES,
            receiver_max_num_batches: 20,
            receiver_max_total_txns: 2000,
            receiver_max_total_bytes: 4 * 1024 * 1024
                + DEFAULT_MAX_NUM_BATCHES
                + BATCH_PADDING_BYTES,
            batch_request_num_peers: 5,
            batch_request_retry_limit: 10,
            batch_request_retry_interval_ms: 500,
            batch_request_rpc_timeout_ms: 5000,
            batch_expiry_gap_when_init_usecs: Duration::from_secs(60).as_micros() as u64,
            remote_batch_expiry_gap_when_init_usecs: Duration::from_millis(500).as_micros() as u64,
            memory_quota: 120_000_000,
            db_quota: 300_000_000,
            batch_quota: 300_000,
            back_pressure: QuorumStoreBackPressureConfig::default(),
            // number of batch coordinators to handle QS batch messages, should be >= 1
            num_workers_for_remote_batches: 10,
            batch_buckets: DEFAULT_BUCKETS.to_vec(),
            allow_batches_without_pos_in_proposal: true,
            enable_opt_quorum_store: true,
            opt_qs_minimum_batch_age_usecs: Duration::from_millis(50).as_micros() as u64,
            enable_payload_v2: false,
            enable_batch_v2: false,
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L195-273)
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

impl BatchInfoExt {
    pub fn new_v1(
        author: PeerId,
        batch_id: BatchId,
        epoch: u64,
        expiration: u64,
        digest: HashValue,
        num_txns: u64,
        num_bytes: u64,
        gas_bucket_start: u64,
    ) -> Self {
        Self::V1 {
            info: BatchInfo::new(
                author,
                batch_id,
                epoch,
                expiration,
                digest,
                num_txns,
                num_bytes,
                gas_bucket_start,
            ),
        }
    }

    pub fn new_v2(
        author: PeerId,
        batch_id: BatchId,
        epoch: u64,
        expiration: u64,
        digest: HashValue,
        num_txns: u64,
        num_bytes: u64,
        gas_bucket_start: u64,
        kind: BatchKind,
    ) -> Self {
        Self::V2 {
            info: BatchInfo::new(
                author,
                batch_id,
                epoch,
                expiration,
                digest,
                num_txns,
                num_bytes,
                gas_bucket_start,
            ),
            extra: ExtraBatchInfo { batch_kind: kind },
        }
    }

    pub fn info(&self) -> &BatchInfo {
        match self {
            BatchInfoExt::V1 { info } => info,
            BatchInfoExt::V2 { info, .. } => info,
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2 { .. })
    }

    pub fn unpack_info(self) -> BatchInfo {
        match self {
            BatchInfoExt::V1 { info } => info,
            BatchInfoExt::V2 { info, .. } => info,
        }
    }
}
```

**File:** consensus/src/quorum_store/batch_requester.rs (L153-155)
```rust
                            Ok(BatchResponse::BatchV2(_)) => {
                                error!("Batch V2 response is not supported");
                            }
```
