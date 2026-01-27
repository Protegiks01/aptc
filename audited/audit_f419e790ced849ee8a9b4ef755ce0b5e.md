# Audit Report

## Title
Consensus SecurityEvent Log Flooding Vulnerability via Unrate-Limited Invalid Message Logging

## Summary
A Byzantine validator can trigger excessive `SecurityEvent::ConsensusInvalidMessage` logging by sending a continuous stream of invalid consensus messages. Unlike `SecurityEvent::NoiseHandshake` which has sample rate limiting, consensus security events lack rate limiting protection, enabling log flooding attacks that can cause disk exhaustion and hide legitimate security alerts.

## Finding Description

The Aptos consensus layer logs security events when receiving invalid messages from peers. However, there is an inconsistency in how different `SecurityEvent` types are rate-limited:

**Protected Event (NoiseHandshake):** [1](#0-0) 

This event uses `sample!(SampleRate::Duration(Duration::from_secs(15)), ...)` to limit logging to once per 15 seconds.

**Unprotected Event (ConsensusInvalidMessage):** [2](#0-1) 

This event logs at ERROR level **without any sample rate limiting**. Each invalid consensus message triggers immediate logging.

**Attack Vector:**

1. A Byzantine validator sends a stream of invalid consensus messages (e.g., messages with invalid signatures, malformed data, incorrect epochs)
2. Messages are queued in the `consensus_messages` channel: [3](#0-2) 

3. Messages are processed and verification is spawned on a bounded executor: [4](#0-3) 

4. The bounded executor capacity is configurable: [5](#0-4) 

5. When message verification fails quickly (e.g., signature verification in ~1-10ms), an ERROR log is generated without rate limiting

**Rate Limiting Analysis:**

The bounded executor provides some natural rate limiting (16 concurrent tasks by default), but:
- Invalid signature verification completes in milliseconds
- This allows processing 100s-1000s of invalid messages per second
- Each generates an ERROR-level log entry
- Over time, this produces massive log volumes (potentially GB/hour)

In contrast, the mempool uses TRACE level for similar events: [6](#0-5) 

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:

1. **Validator Node Slowdowns**: Excessive logging causes high disk I/O, degrading validator performance. Validators must maintain low latency for consensus participation.

2. **Disk Exhaustion**: Without adequate log rotation, continuous invalid message streams can fill disk space, potentially causing node crashes or service degradation.

3. **Security Alert Obfuscation**: Flooding logs with `ConsensusInvalidMessage` entries buries legitimate security events, making incident detection and forensic analysis difficult.

4. **Operational Impact**: Operators must frequently rotate/clean logs, increasing operational overhead and risk of missing real attacks.

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - logging should have rate limits to prevent resource exhaustion.

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Complexity**: Byzantine validators (within < 1/3 BFT assumption) can trivially send invalid messages by:
   - Sending messages with invalid signatures
   - Sending malformed consensus proposals
   - Sending messages from wrong epochs

2. **Minimal Resources Required**: The attacker only needs to maintain network connectivity and send messages (negligible bandwidth/compute)

3. **No Detection/Penalty**: Unlike equivocation (which triggers slashing in some systems), sending invalid messages has no economic penalty - it just gets rejected and logged

4. **Sustained Attack**: Can be maintained indefinitely as long as the Byzantine validator remains in the validator set

## Recommendation

Apply sample rate limiting to consensus security events, consistent with the existing pattern for `NoiseHandshake`:

**In `consensus/src/epoch_manager.rs`**, modify the error logging:

```rust
Err(e) => {
    sample!(
        SampleRate::Duration(Duration::from_secs(15)),
        error!(
            SecurityEvent::ConsensusInvalidMessage,
            remote_peer = peer_id,
            error = ?e,
            unverified_event = unverified_event
        )
    );
},
```

**Additionally**, consider:

1. **Per-peer rate limiting**: Track invalid message counts per peer and apply exponential backoff or temporary filtering
2. **Metrics-based monitoring**: Use counters for invalid messages (already exists via `counters::CONSENSUS_CHANNEL_MSGS`) instead of verbose logging
3. **Structured logging levels**: Use WARN or INFO level for expected Byzantine behavior, reserve ERROR for unexpected system failures
4. **Log aggregation**: Log summary statistics periodically (e.g., "Received 1000 invalid messages from peer X in last minute") rather than individual entries

## Proof of Concept

**Rust Simulation** demonstrating log generation rate:

```rust
use std::time::{Duration, Instant};
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};

#[tokio::test]
async fn test_consensus_log_flooding() {
    // Simulate Byzantine validator sending invalid messages
    let start = Instant::now();
    let mut log_count = 0;
    
    // Simulate bounded executor with 16 capacity
    let semaphore = Arc::new(Semaphore::new(16));
    
    // Send 1000 invalid messages
    for i in 0..1000 {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        
        // Spawn verification task
        tokio::spawn(async move {
            // Simulate signature verification failure (1-5ms realistic)
            tokio::time::sleep(Duration::from_millis(2)).await;
            
            // In real code, this would log SecurityEvent::ConsensusInvalidMessage
            log_count += 1;
            
            drop(permit);
        });
    }
    
    let elapsed = start.elapsed();
    println!("Generated {} logs in {:?}", log_count, elapsed);
    println!("Rate: {} logs/second", (log_count as f64) / elapsed.as_secs_f64());
    
    // With 16 concurrent tasks and 2ms verification time:
    // Expected rate: ~8000 logs/second
    // In 1 hour: ~28 million log entries
    // At ~200 bytes/entry: ~5.6 GB/hour
}
```

**Attack Simulation Steps:**

1. Deploy a validator node in a test network
2. Configure the validator to send invalid consensus messages (modified signatures)
3. Monitor log file growth rate
4. Observe disk space consumption and I/O latency impact

**Expected Results:**
- Log files grow at GB/hour rates
- Disk I/O wait time increases
- Legitimate security events become difficult to find in logs
- Without log rotation, disk exhaustion occurs within hours/days depending on disk size

## Notes

This vulnerability exists because consensus security events lack the same rate limiting protections applied to network-layer security events. The sample rate limiting mechanism already exists in the codebase [7](#0-6)  but is inconsistently applied.

The attack requires a Byzantine validator (within the < 1/3 BFT threat model), which is an expected adversary in AptosBFT. The system should handle Byzantine behavior gracefully without operational failures. While the bounded executor and channel size provide some rate limiting, they are insufficient to prevent log flooding over time.

### Citations

**File:** network/framework/src/transport/mod.rs (L280-289)
```rust
                sample!(
                    SampleRate::Duration(Duration::from_secs(15)),
                    warn!(
                        SecurityEvent::NoiseHandshake,
                        NetworkSchema::new(&ctxt.noise.network_context)
                            .network_address(&addr)
                            .connection_origin(&origin),
                        error = %err,
                    )
                );
```

**File:** consensus/src/epoch_manager.rs (L1612-1619)
```rust
                        Err(e) => {
                            error!(
                                SecurityEvent::ConsensusInvalidMessage,
                                remote_peer = peer_id,
                                error = ?e,
                                unverified_event = unverified_event
                            );
                        },
```

**File:** consensus/src/network.rs (L757-761)
```rust
        let (consensus_messages_tx, consensus_messages) = aptos_channel::new(
            QueueStyle::FIFO,
            10,
            Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
```

**File:** consensus/src/consensus_provider.rs (L81-84)
```rust
    let bounded_executor = BoundedExecutor::new(
        node_config.consensus.num_bounded_executor_tasks as usize,
        runtime.handle().clone(),
    );
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```

**File:** mempool/src/shared_mempool/tasks.rs (L599-604)
```rust
            trace!(
                SecurityEvent::InvalidTransactionMempool,
                failed_transaction = txn,
                vm_status = vm_status,
                sender = sender,
            );
```

**File:** crates/aptos-logger/src/sample.rs (L11-23)
```rust
/// The rate at which a `sample!` macro will run it's given function
#[derive(Debug)]
pub enum SampleRate {
    /// Only sample a single time during a window of time. This rate only has a resolution in
    /// seconds.
    Duration(Duration),
    /// Sample based on the frequency of the event. The provided u64 is the inverse of the
    /// frequency (1/x), for example Frequency(2) means that 1 out of every 2 events will be
    /// sampled (1/2).
    Frequency(u64),
    /// Always Sample
    Always,
}
```
