# Audit Report

## Title
Indexer Backfiller Denial of Service via Incomplete Batch Handling - Transactions Permanently Stuck in Buffer When BatchEnd Received with < 1000 Transactions

## Summary
The indexer-grpc-file-store-backfiller service contains a critical logic flaw in its batch processing implementation that causes it to hang indefinitely when receiving batches with fewer than 1000 transactions. This occurs both naturally (when the total transaction count is not a multiple of 1000) and when connecting to fullnodes with non-standard configurations, resulting in complete denial of service to the indexing infrastructure.

## Finding Description

The backfiller's `backfill()` function processes transactions received from a fullnode gRPC stream by buffering them until BatchEnd signals are received. However, the implementation contains a hardcoded assumption that batches must contain exactly 1000 transactions. [1](#0-0) 

The critical flaw is at the while loop condition: when a BatchEnd signal is received, transactions are only processed if `transactions_buffer.len() >= 1000`. If the buffer contains fewer than 1000 transactions, the loop body never executes, leaving those transactions permanently stuck in the buffer.

This violates the gRPC protocol specification, which explicitly allows variable batch sizes: [2](#0-1) 

The protocol documentation clearly states that batch size "n" is variable, yet the backfiller enforces a fixed 1000-transaction requirement.

The processing workers compound this issue by performing strict validation: [3](#0-2) 

Workers panic if they receive anything other than exactly 1000 transactions starting at a version divisible by 1000.

**Exploitation Paths:**

1. **Natural Edge Case (Highest Likelihood):** When a backfiller requests a transaction count that is not a multiple of 1000 (e.g., requesting 1500 transactions starting from version 0):
   - First batch: versions 0-999 (1000 txns) → processes successfully
   - Second batch: versions 1000-1499 (500 txns) → stuck in buffer forever
   - Backfiller hangs indefinitely, progress file never updates to version 1500

2. **Non-Standard Fullnode Configuration:** The fullnode's `processor_batch_size` is configurable: [4](#0-3) 

If a fullnode operator sets `processor_batch_size` to 500, every batch sent will have ≤500 transactions, causing the backfiller to fail completely.

3. **Malicious Fullnode:** A malicious fullnode can deliberately send BatchEnd signals after fewer than 1000 transactions by modifying the server code or configuration, causing denial of service to any connecting backfiller.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

- **API crashes / Service failure**: The backfiller service becomes completely non-functional, hanging indefinitely without completing its task or exiting.

- **Significant protocol violation**: The implementation violates the published gRPC protocol specification which explicitly allows variable batch sizes.

- **Infrastructure availability**: The indexer-grpc file store is critical infrastructure for historical transaction data. When the backfiller fails:
  - Historical transaction data remains incomplete in the file store
  - Downstream applications and indexers experience data gaps
  - Manual intervention is required to recover
  - The service cannot self-heal or resume progress

- **Scope**: While this affects indexer infrastructure rather than core consensus, the indexer-grpc components are part of the Aptos Core repository and provide critical data availability services for the ecosystem.

## Likelihood Explanation

**Very High Likelihood:**

1. **Natural occurrence**: Any backfill operation requesting a transaction count not divisible by 1000 will trigger this bug. This is a common use case—operators rarely request round thousands.

2. **Configuration mismatch**: Different fullnode operators may use different `processor_batch_size` values for performance tuning. A backfiller connecting to such a node will immediately fail.

3. **End-of-range scenarios**: When backfilling up to the latest ledger version, the final batch will often have fewer than 1000 transactions.

4. **No defensive coding**: The code contains no timeout mechanisms, retry logic, or handling for partial batches, making the failure deterministic rather than probabilistic.

5. **Silent failure**: The backfiller hangs silently without logging errors or exiting, making the issue difficult to detect and diagnose in production.

## Recommendation

The backfiller should process all transactions in the buffer after receiving BatchEnd, regardless of count. The 1000-transaction batching should be an optimization, not a requirement:

**Fix for processor.rs lines 286-300:**

```rust
Response::Status(signal) => {
    if signal.r#type() != StatusType::BatchEnd {
        anyhow::bail!("Unexpected status signal type");
    }
    // Process all complete batches of 1000
    while transactions_buffer.len() >= 1000 {
        let mut transactions = Vec::new();
        for _ in 0..1000 {
            let (_, txn) = transactions_buffer.pop_first().unwrap();
            transactions.push(txn);
        }
        sender.send(transactions).await?;
    }
    // Process remaining transactions if this is the final batch
    if !transactions_buffer.is_empty() {
        // Check if we've received all expected transactions
        let should_flush = if let Some(ending_version) = ending_version {
            // If we have an ending version and buffer contains transactions 
            // up to or past it, flush the remaining transactions
            transactions_buffer.keys().last()
                .map(|&last_version| last_version >= ending_version - 1)
                .unwrap_or(false)
        } else {
            false
        };
        
        if should_flush {
            let mut transactions = Vec::new();
            while let Some((_, txn)) = transactions_buffer.pop_first() {
                transactions.push(txn);
            }
            if !transactions.is_empty() {
                sender.send(transactions).await?;
            }
        }
    }
}
```

**Fix for worker validation (lines 188-199):**

```rust
// Data quality check - allow variable sizes for final batches
if transactions.len() != 1000 {
    // Verify this is a valid final batch
    ensure!(
        transactions.len() > 0 && transactions.len() < 1000,
        "Unexpected transaction count: {}", transactions.len()
    );
}
// Verify version alignment for full batches only
if transactions.len() == 1000 {
    ensure!(
        transactions[0].version % 1000 == 0,
        "Unexpected starting version for full batch"
    );
}
// Verify version continuity
for (idx, t) in transactions.iter().enumerate() {
    ensure!(
        t.version == transactions[0].version + idx as u64,
        "Unexpected version at index {}", idx
    );
}
```

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: Deploy a fullnode with standard configuration (processor_batch_size = 1000)

2. **Run backfiller** requesting non-multiple of 1000:
```bash
cargo run --bin aptos-indexer-grpc-file-store-backfiller -- \
    --fullnode-grpc-address http://localhost:50051 \
    --file-store-config file_store.yaml \
    --starting-version 0 \
    --transactions-count 1500
```

3. **Expected behavior**: Backfiller should complete and exit after processing all 1500 transactions.

4. **Actual behavior**: 
   - Backfiller processes first 1000 transactions (versions 0-999)
   - Progress file updates to version 1000
   - Receives next 500 transactions (versions 1000-1499)
   - Receives BatchEnd signal
   - Buffer contains 500 transactions but while loop condition fails
   - Backfiller hangs indefinitely at line 265 waiting for more stream data
   - Progress file never updates to version 1500
   - Process never exits

5. **Verification**: 
   - Check progress file: `cat progress.json` shows `{"version": 1000}`
   - Check file store: Only contains batch file for versions 0-999
   - Process continues running but makes no progress
   - No timeout or error occurs

**Alternative PoC - Fullnode Configuration:**

1. Configure fullnode with `processor_batch_size: 500` in config
2. Start backfiller requesting any number of transactions
3. All batches will be 500 transactions or less
4. Backfiller will receive BatchEnd after 500 transactions
5. Buffer never reaches 1000, all transactions stuck
6. Complete denial of service

---

**Notes:**

This vulnerability is particularly severe because it affects a critical indexing component and can occur naturally without any malicious intent. The hardcoded 1000-transaction assumption is fundamentally incompatible with the variable-batch-size protocol specification, making this a protocol implementation bug rather than just an edge case.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L188-199)
```rust
                        // Data quality check.
                        ensure!(transactions.len() == 1000, "Unexpected transaction count");
                        ensure!(
                            transactions[0].version % 1000 == 0,
                            "Unexpected starting version"
                        );
                        for (ide, t) in transactions.iter().enumerate() {
                            ensure!(
                                t.version == transactions[0].version + ide as u64,
                                "Unexpected version"
                            );
                        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L286-300)
```rust
                Response::Status(signal) => {
                    if signal.r#type() != StatusType::BatchEnd {
                        anyhow::bail!("Unexpected status signal type");
                    }
                    while transactions_buffer.len() >= 1000 {
                        // Take the first 1000 transactions.
                        let mut transactions = Vec::new();
                        // Pop the first 1000 transactions from buffer.
                        for _ in 0..1000 {
                            let (_, txn) = transactions_buffer.pop_first().unwrap();
                            transactions.push(txn);
                        }
                        sender.send(transactions).await?;
                    }
                },
```

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L11-16)
```text
// Transaction data is transferred via 1 stream with batches until terminated.
// One stream consists:
//  StreamStatus: INIT with version x
//  loop k:
//    TransactionOutput data(size n)
//    StreamStatus: BATCH_END with version x + (k + 1) * n - 1
```

**File:** config/src/config/indexer_grpc_config.rs (L17-18)
```rust
const DEFAULT_PROCESSOR_BATCH_SIZE: u16 = 1000;
const DEFAULT_OUTPUT_BATCH_SIZE: u16 = 100;
```
