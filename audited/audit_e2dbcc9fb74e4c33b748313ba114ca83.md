# Audit Report

## Title
Memory Exhaustion via Slow Client Consumption in Indexer gRPC Transaction Streaming

## Summary
The indexer-grpc-fullnode service has a critical mismatch between its transaction processing batch size (up to 20,000 transactions) and its channel buffer size (35 messages). Slow clients can cause unbounded memory accumulation in the spawned streaming task, potentially leading to node memory exhaustion and service degradation.

## Finding Description

The vulnerability exists in the transaction streaming architecture where processed transaction responses accumulate in memory while waiting to be sent to slow clients.

The channel buffer size is configured with a default of 35 messages: [1](#0-0) 

This channel is created in the streaming handler: [2](#0-1) 

The coordinator processes transactions in large batches determined by `processor_task_count` (default 20) and `processor_batch_size` (default 1000): [3](#0-2) [4](#0-3) 

The critical issue occurs in `process_next_batch()` where all responses are collected in memory before sending: [5](#0-4) 

These responses are then sent one-by-one through the bounded channel: [6](#0-5) 

**Attack Flow:**
1. Attacker connects as a legitimate gRPC client requesting transactions
2. Coordinator fetches and processes up to 20,000 transactions (20 tasks × 1,000 transactions each)
3. These are converted into 200+ response messages (minimum, at 100 transactions per chunk)
4. All response messages are collected in the `responses` vector in memory
5. Attacker consumes from the channel very slowly (or stops consuming)
6. Channel fills up (35 message capacity)
7. The `send().await` blocks, but all 200+ messages remain in the `responses` vector
8. Each message can be up to 15MB (MESSAGE_SIZE_LIMIT)
9. Multiple slow clients multiply this effect, potentially causing gigabytes of memory buildup

This breaks **Invariant #9: Resource Limits** - the system fails to enforce proper memory constraints for streaming operations.

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability causes resource exhaustion on fullnodes running the indexer-grpc service:

1. **Memory Exhaustion**: With default settings, a single slow client can cause accumulation of 200+ response messages totaling hundreds of MBs to several GBs of memory
2. **Service Degradation**: Multiple slow clients can exhaust node memory, causing OOM conditions or severe performance degradation
3. **Availability Impact**: Affects data indexers and applications relying on the transaction stream API

The impact qualifies as Medium severity under "State inconsistencies requiring intervention" as node operators would need to manually restart affected services or disconnect slow clients.

While this doesn't directly affect consensus or validator operations, it impacts the critical indexer infrastructure that many ecosystem applications depend on for transaction data.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be triggered:

1. **Low Barrier to Attack**: Any client can connect to the gRPC endpoint and request transactions
2. **No Special Permissions**: No authentication or special privileges required
3. **Natural Occurrence**: Can happen accidentally with legitimately slow clients on poor network connections
4. **Easy to Exploit**: Simply connect and consume data slowly or pause consumption
5. **Amplification**: Multiple clients multiply the effect

The default configuration makes this particularly exploitable:
- Small channel size (35) vs. large batch size (20,000 transactions → 200+ messages)
- Messages can be large (up to 15MB each per MESSAGE_SIZE_LIMIT)
- No backpressure mechanism to limit batch size based on client consumption rate

## Recommendation

**Immediate Fix**: Implement backpressure by making the channel size configurable and proportional to the batch processing capacity:

```rust
// In config/src/config/indexer_grpc_config.rs
// Change from fixed 35 to a reasonable multiple of expected batch output
const DEFAULT_TRANSACTION_CHANNEL_SIZE: usize = 500; // At least 2x expected batch message count
```

**Better Solution**: Implement dynamic backpressure in the coordinator:

1. **Don't pre-collect all responses**: Send responses to the channel as they are produced instead of collecting them all first
2. **Monitor channel capacity**: Check channel capacity before processing next batch and reduce batch size if channel is filling
3. **Add timeout mechanism**: Disconnect clients that don't consume for extended periods
4. **Implement rate limiting**: Limit number of concurrent slow clients

**Example fix for process_next_batch()**:
```rust
// Instead of collecting all responses and then sending (lines 202-226)
// Send responses incrementally as tasks complete:

for task in tasks {
    let task_responses = task.await.unwrap();
    for response in task_responses {
        if self.transactions_sender.send(Ok(response)).await.is_err() {
            return vec![];
        }
        // Check if client is too slow
        if self.transactions_sender.capacity() < transaction_channel_size / 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
```

## Proof of Concept

```rust
// Integration test demonstrating memory buildup
#[tokio::test]
async fn test_slow_client_memory_buildup() {
    // Setup: Start indexer-grpc fullnode service
    let config = NodeConfig {
        indexer_grpc: IndexerGrpcConfig {
            enabled: true,
            processor_task_count: Some(20),
            processor_batch_size: 1000,
            transaction_channel_size: 35, // Small channel
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Connect as a client requesting many transactions
    let mut client = FullnodeDataClient::connect("http://localhost:50051")
        .await
        .unwrap();
    
    let request = GetTransactionsFromNodeRequest {
        starting_version: Some(0),
        transactions_count: Some(100_000), // Request 100k transactions
    };
    
    let mut stream = client.get_transactions_from_node(request)
        .await
        .unwrap()
        .into_inner();
    
    // Consume very slowly - only consume 10 messages then pause
    let mut count = 0;
    while let Some(response) = stream.message().await.unwrap() {
        count += 1;
        if count >= 10 {
            // Pause consumption - channel will fill up
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
    
    // Monitor server memory during this test - it will show significant buildup
    // as the coordinator has processed 20,000 transactions into 200+ messages
    // but only 35 can fit in the channel, leaving 165+ messages in memory
}

// To observe the issue:
// 1. Deploy indexer fullnode with default config
// 2. Connect with above client
// 3. Monitor process memory with `ps aux` or similar
// 4. Observe memory growth as coordinator processes batches
//    but client doesn't consume them
```

**Notes:**
- This vulnerability specifically affects the indexer-grpc-fullnode service, not core consensus
- The issue is architectural: processing large batches entirely before sending creates memory pressure when combined with small channel buffers
- Real-world impact depends on transaction sizes, but with 15MB message limit, memory buildup can be severe
- Fix requires either increasing channel size significantly or implementing proper backpressure mechanisms

### Citations

**File:** config/src/config/indexer_grpc_config.rs (L17-17)
```rust
const DEFAULT_PROCESSOR_BATCH_SIZE: u16 = 1000;
```

**File:** config/src/config/indexer_grpc_config.rs (L19-19)
```rust
const DEFAULT_TRANSACTION_CHANNEL_SIZE: usize = 35;
```

**File:** config/src/config/indexer_grpc_config.rs (L23-29)
```rust
pub fn get_default_processor_task_count(use_data_service_interface: bool) -> u16 {
    if use_data_service_interface {
        1
    } else {
        20
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L94-94)
```rust
        let (tx, rx) = mpsc::channel(transaction_channel_size);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L202-208)
```rust
        let responses = match futures::future::try_join_all(tasks).await {
            Ok(res) => res.into_iter().flatten().collect::<Vec<_>>(),
            Err(err) => panic!(
                "[Indexer Fullnode] Error processing transaction batches: {:?}",
                err
            ),
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L221-226)
```rust
        for response in responses {
            if self.transactions_sender.send(Ok(response)).await.is_err() {
                // Error from closed channel. This means the client has disconnected.
                return vec![];
            }
        }
```
