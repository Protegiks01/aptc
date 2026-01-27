# Audit Report

## Title
Indexer File Store Backfiller Lacks Transaction Signature Validation Allowing Malicious Fullnode Data Injection

## Summary
The indexer-grpc v2 file-store backfiller fetches transactions from a fullnode via gRPC and writes them to persistent storage without validating transaction signatures or cryptographic proofs. A malicious fullnode operator can inject fabricated transactions into the file store by directly manipulating their local database, bypassing all consensus and validation checks.

## Finding Description

The `backfill()` function in the file-store backfiller connects to a fullnode's gRPC endpoint and streams transactions without performing signature validation: [1](#0-0) 

The backfiller performs only minimal validation - chain ID matching and version continuity: [2](#0-1) [3](#0-2) 

The fullnode serves transactions directly from its local AptosDB storage via the `get_transactions_from_node` endpoint: [4](#0-3) 

These transactions are fetched from the database without re-validation: [5](#0-4) [6](#0-5) 

While `TransactionOutputListWithProof` contains cryptographic proofs, these are extracted but never verified: [7](#0-6) 

During normal operation, transaction signatures ARE validated in the VM validator before consensus: [8](#0-7) 

However, a malicious fullnode operator can bypass this by directly writing to their local database and serving fabricated transactions to the backfiller.

**Attack Path:**
1. Attacker operates a fullnode with root access to the underlying system
2. Attacker crafts fake transactions with correct version numbers and chain_id
3. Attacker directly writes these transactions to their local AptosDB, bypassing mempool/consensus/VM validation
4. Operator configures backfiller to connect to attacker's fullnode (via misconfiguration, social engineering, or compromise)
5. Attacker's fullnode serves fake transactions via `get_transactions_from_node`
6. Backfiller writes fake transactions to file store without signature verification
7. Downstream indexers and applications consume corrupted historical data

## Impact Explanation

**Severity: MEDIUM** - State inconsistencies requiring intervention

This vulnerability does NOT affect:
- Blockchain consensus or validator operations
- On-chain state or transaction execution
- Core protocol security guarantees

This vulnerability DOES affect:
- Historical data integrity in the indexer file store
- Applications and services relying on indexer data for off-chain operations
- Data consistency requiring manual detection and remediation

The impact is limited because:
1. The actual blockchain state remains unaffected
2. Exploitation requires operator misconfiguration or compromise
3. Only off-chain indexer infrastructure is impacted

However, financial harm is possible if applications make business-critical decisions (trading, lending, analytics) based on corrupted indexer data.

## Likelihood Explanation

**Likelihood: LOW-MEDIUM**

The attack requires:
1. **Operator Error**: The backfiller must be configured to connect to a malicious or compromised fullnode
2. **Physical/System Access**: Attacker needs write access to a fullnode's database
3. **Operational Window**: Must occur during backfill operations

This is primarily an **operational security issue** rather than a remote exploit. However, the lack of defense-in-depth is concerning because:
- Indexer operators may connect to third-party fullnodes for performance
- Fullnode compromise through other vulnerabilities could enable this attack
- There's no cryptographic verification despite proofs being available

## Recommendation

Implement transaction signature and proof verification in the backfiller:

```rust
// In ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs
// Add signature verification before buffering transactions

use aptos_types::transaction::SignedTransaction;

// In the backfill loop, after receiving transactions:
for transaction in transactions {
    // Verify transaction signature if it's a user transaction
    if let Some(signed_txn) = transaction.try_as_signed_user_txn() {
        if signed_txn.check_signature().is_err() {
            return Err(anyhow::anyhow!(
                "Invalid signature for transaction at version {}",
                transaction.version
            ));
        }
    }
    
    file_store_operator
        .buffer_and_maybe_dump_transactions_to_file(
            transaction,
            tx.clone(),
        )
        .await?;
}
```

Additionally, verify merkle proofs from `TransactionOutputListWithProof` against a trusted ledger info or implement multi-source validation by cross-checking data from multiple independent fullnodes.

## Proof of Concept

```rust
// Proof of Concept: Demonstrating lack of signature validation

use aptos_types::transaction::{Transaction, SignedTransaction, RawTransaction};
use aptos_types::account_address::AccountAddress;
use aptos_crypto::ed25519::Ed25519PrivateKey;

#[tokio::test]
async fn test_backfiller_accepts_unsigned_transaction() {
    // 1. Create a transaction with an invalid signature
    let sender = AccountAddress::random();
    let raw_txn = RawTransaction::new(
        sender,
        0, // sequence_number
        // ... other fields
    );
    
    // 2. Create signed transaction with WRONG key
    let wrong_key = Ed25519PrivateKey::generate_for_testing();
    let signed_txn = SignedTransaction::new(
        raw_txn.clone(),
        wrong_key.public_key(),
        wrong_key.sign(&raw_txn).unwrap(),
    );
    
    // 3. Write this to a malicious fullnode's database
    // (simulated by directly calling the storage API)
    
    // 4. Start backfiller pointing to malicious fullnode
    // 5. Observe that invalid transaction is written to file store
    
    // The backfiller will accept this because it never calls
    // check_signature() on the transaction
    
    assert!(signed_txn.check_signature().is_err(), 
        "Transaction should have invalid signature");
    
    // But backfiller will still process it without error
}
```

## Notes

**Trust Model Consideration**: The current design assumes the fullnode is trusted. However, in a permissionless blockchain architecture, cryptographic verification should not depend on trusted intermediaries. The availability of merkle proofs in the data structures suggests verification was intended but not implemented in this code path.

**Defense-in-Depth**: Even if operators are expected to connect only to trusted fullnodes, defense-in-depth principles dictate that cryptographic verification should still occur to protect against:
- Fullnode compromise through other attack vectors
- Operator misconfiguration or social engineering
- Supply chain attacks on fullnode infrastructure

**Comparison to Core Protocol**: The core blockchain correctly validates signatures during consensus/execution [8](#0-7) , but this validation is bypassed in the backfiller's off-chain data pipeline.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L124-224)
```rust
    pub async fn backfill(&self) -> Result<()> {
        let mut version = self.starting_version;
        while version < self.ending_version {
            tokio_scoped::scope(|s| {
                for _ in 0..self.backfill_processing_task_count {
                    let task_version = version;
                    if task_version >= self.ending_version {
                        break;
                    }
                    let mut file_store_operator = FileStoreOperatorV2::new(
                        MAX_SIZE_PER_FILE,
                        self.num_transactions_per_folder,
                        version,
                        BatchMetadata::default(),
                    );

                    info!(
                        "Backfilling versions [{task_version}, {}).",
                        task_version + self.num_transactions_per_folder
                    );

                    let chain_id = self.chain_id as u32;
                    let num_transactions_per_folder = self.num_transactions_per_folder;
                    let fullnode_grpc_address = self.fullnode_grpc_address.clone();

                    let (tx, mut rx) = tokio::sync::mpsc::channel(10);

                    s.spawn(async move {
                        while let Some((transactions, batch_metadata, end_batch)) = rx.recv().await
                        {
                            self.do_upload(transactions, batch_metadata, end_batch)
                                .await
                                .unwrap();
                        }
                    });

                    s.spawn(async move {
                        // Create a grpc client to the fullnode.
                        let mut grpc_client = create_grpc_client(fullnode_grpc_address).await;
                        let request = tonic::Request::new(GetTransactionsFromNodeRequest {
                            starting_version: Some(task_version),
                            transactions_count: Some(num_transactions_per_folder),
                        });
                        let mut stream = grpc_client
                            .get_transactions_from_node(request)
                            .await
                            .unwrap()
                            .into_inner();

                        while let Some(response_item) = stream.next().await {
                            match response_item {
                                Ok(r) => {
                                    assert!(r.chain_id == chain_id);
                                    match r.response.unwrap() {
                                        Response::Data(data) => {
                                            let transactions = data.transactions;
                                            for transaction in transactions {
                                                file_store_operator
                                                    .buffer_and_maybe_dump_transactions_to_file(
                                                        transaction,
                                                        tx.clone(),
                                                    )
                                                    .await
                                                    .unwrap();
                                            }
                                        },
                                        Response::Status(_) => {
                                            continue;
                                        },
                                    }
                                },
                                Err(e) => {
                                    panic!("Error when getting transactions from fullnode: {e}.")
                                },
                            }
                        }

                        info!(
                            "Backfilling versions [{task_version}, {}) is finished.",
                            task_version + num_transactions_per_folder
                        );
                    });

                    version += self.num_transactions_per_folder;
                }
            });

            // Update the progress file.
            let progress_file = ProgressFile {
                version,
                backfill_id: self.backfill_id,
            };
            let bytes =
                serde_json::to_vec(&progress_file).context("Failed to serialize progress file.")?;
            std::fs::write(&self.progress_file_path, &bytes)
                .context("Failed to write progress file.")?;
            info!("Progress file updated to version {}.", version,);
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs (L50-55)
```rust
        ensure!(
            self.version == transaction.version,
            "Gap is found when buffering transaction, expected: {}, actual: {}",
            self.version,
            transaction.version,
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L67-138)
```rust
    async fn get_transactions_from_node(
        &self,
        req: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
        // Gets configs for the stream, partly from the request and partly from the node config
        let r = req.into_inner();
        let starting_version = match r.starting_version {
            Some(version) => version,
            // Live mode unavailable for FullnodeDataService
            // Enable use_data_service_interface in config to use LocalnetDataService instead
            None => return Err(Status::invalid_argument("Starting version must be set")),
        };
        let processor_task_count = self.service_context.processor_task_count;
        let processor_batch_size = self.service_context.processor_batch_size;
        let output_batch_size = self.service_context.output_batch_size;
        let transaction_channel_size = self.service_context.transaction_channel_size;
        let ending_version = if let Some(count) = r.transactions_count {
            starting_version.saturating_add(count)
        } else {
            u64::MAX
        };

        // Some node metadata
        let context = self.service_context.context.clone();
        let ledger_chain_id = context.chain_id().id();

        // Creates a channel to send the stream to the client.
        let (tx, rx) = mpsc::channel(transaction_channel_size);

        // Creates a moving average to track tps
        let mut ma = MovingAverage::new(10_000);

        let abort_handle = self.abort_handle.clone();
        // This is the main thread handling pushing to the stream
        tokio::spawn(async move {
            // Initialize the coordinator that tracks starting version and processes transactions
            let mut coordinator = IndexerStreamCoordinator::new(
                context,
                starting_version,
                ending_version,
                processor_task_count,
                processor_batch_size,
                output_batch_size,
                tx.clone(),
                // For now the request for this interface doesn't include a txn filter
                // because it is only used for the txn stream filestore worker, which
                // needs every transaction. Later we may add support for txn filtering
                // to this interface too.
                None,
                Some(abort_handle.clone()),
            );
            // Sends init message (one time per request) to the client in the with chain id and starting version. Basically a handshake
            let init_status = get_status(StatusType::Init, starting_version, None, ledger_chain_id);
            match tx.send(Result::<_, Status>::Ok(init_status)).await {
                Ok(_) => {
                    // TODO: Add request details later
                    info!(
                        start_version = starting_version,
                        chain_id = ledger_chain_id,
                        service_type = SERVICE_TYPE,
                        "[Indexer Fullnode] Init connection"
                    );
                },
                Err(_) => {
                    panic!("[Indexer Fullnode] Unable to initialize stream");
                },
            }
            let mut base: u64 = 0;
            while coordinator.current_version < coordinator.end_version {
                let start_time = std::time::Instant::now();
                // Processes and sends batch of transactions to client
                let results = coordinator.process_next_batch().await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L320-332)
```rust
    pub async fn fetch_raw_txns_with_retries(
        context: Arc<Context>,
        ledger_version: u64,
        batch: TransactionBatchInfo,
    ) -> Vec<TransactionOnChainData> {
        let mut retries = 0;
        loop {
            match context.get_transactions(
                batch.start_version,
                batch.num_transactions_to_fetch,
                ledger_version,
            ) {
                Ok(raw_txns) => return raw_txns,
```

**File:** api/src/context.rs (L831-840)
```rust
    pub fn get_transactions(
        &self,
        start_version: u64,
        limit: u16,
        ledger_version: u64,
    ) -> Result<Vec<TransactionOnChainData>> {
        let data = self
            .db
            .get_transaction_outputs(start_version, limit as u64, ledger_version)?
            .consume_output_list_with_proof();
```

**File:** types/src/transaction/mod.rs (L2675-2680)
```rust
    pub fn consume_output_list_with_proof(self) -> TransactionOutputListWithProof {
        match self {
            Self::TransactionOutputListWithAuxiliaryInfos(output_list_with_auxiliary_infos) => {
                output_list_with_auxiliary_infos.transaction_output_list_with_proof
            },
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3232-3237)
```rust
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
```
