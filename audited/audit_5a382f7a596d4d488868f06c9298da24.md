# Audit Report

## Title
Resource Exhaustion via Unauthenticated EpochRetrievalRequest Flooding

## Summary
A malicious peer can exhaust validator resources by repeatedly requesting retrieval of extremely old epochs without authentication or rate limiting, causing disk I/O contention, CPU load, and network bandwidth consumption that degrades validator performance.

## Finding Description
The `EpochRetrievalRequest` message handling in the consensus layer lacks proper input validation, authentication, and rate limiting. When a validator receives an `EpochRetrievalRequest`, it processes the request without verifying the sender's identity or imposing per-peer limits. [1](#0-0) 

The handler only validates that the requested `end_epoch` does not exceed the local epoch, but performs no checks on:
1. The `start_epoch` value (can be epoch 0, requesting ancient history)
2. The epoch range size
3. The requesting peer's identity or authorization
4. Rate limits on requests from the same peer [2](#0-1) 

When `process_epoch_retrieval` is invoked, it directly queries AptosDB to retrieve epoch ending ledger infos. While the database implementation limits responses to 100 epochs per request, an attacker can repeatedly request the oldest 100 epochs, forcing expensive disk I/O operations. [3](#0-2) 

Each `LedgerInfoWithSignatures` contains BLS signatures from 2/3+ of the validator set, making these objects large and expensive to deserialize and transmit. By flooding `EpochRetrievalRequest` messages for old epochs (which are unlikely to be cached), an attacker forces:
- **Disk I/O**: Repeated reads from RocksDB for ancient epoch data
- **CPU Usage**: Deserialization of cryptographic signatures
- **Network Bandwidth**: Transmission of large `EpochChangeProof` responses
- **Memory Pressure**: Loading old data into memory

The `EpochRetrievalRequest` messages are routed through the `consensus_messages` channel with a queue size of only 10 messages. While this provides some backpressure, an attacker can continuously flood requests to keep the channel saturated, delaying processing of legitimate consensus messages. [4](#0-3) [5](#0-4) 

## Impact Explanation
This vulnerability enables **validator node slowdowns**, which qualifies as **High Severity** under the Aptos bug bounty program (up to $50,000). An attacker can degrade validator performance by:

1. **Disk I/O Contention**: Forcing repeated reads of old epochs from disk competes with legitimate consensus operations that also require disk access for block storage and state management
2. **CPU Exhaustion**: Deserializing 100 epochs worth of multi-signature data repeatedly consumes CPU cycles needed for block verification and execution
3. **Network Saturation**: Large `EpochChangeProof` responses consume bandwidth that could be used for consensus messages
4. **Channel Blocking**: Flooding the consensus messages channel can delay legitimate proposal, vote, and sync messages

While individual validators can tolerate some slowdown, if multiple validators are targeted simultaneously (which requires minimal resources for the attacker), this could impact overall network consensus performance, increasing block times or causing timeout rounds.

## Likelihood Explanation
This attack has **high likelihood** of occurrence because:

1. **No Authentication Required**: Any network peer can send `EpochRetrievalRequest` messages without being part of the validator set or proving authorization
2. **Low Attack Cost**: The attacker only needs to send small request messages repeatedly, while forcing the victim validator to perform expensive operations
3. **Simple Exploitation**: The attack requires no sophisticated techniques—just repeatedly sending `EpochRetrievalRequest(start_epoch=0, end_epoch=99)` messages
4. **No Per-Peer Limits**: The code implements no rate limiting per peer, allowing a single malicious actor to sustain the attack

The only mitigating factors are the database response limit (100 epochs) and channel backpressure (10 messages), which reduce but do not eliminate the attack's effectiveness.

## Recommendation
Implement multiple layers of defense:

1. **Authentication**: Verify that epoch retrieval requests come from known validators in the current or recent epoch's validator set
2. **Rate Limiting**: Add per-peer rate limiting for `EpochRetrievalRequest` messages (e.g., max 1 request per 10 seconds per peer)
3. **Range Validation**: Reject requests for epoch ranges older than a reasonable threshold (e.g., only allow retrieval of the last 10 epochs worth of history)
4. **Request Throttling**: Implement exponential backoff for peers sending excessive requests

Example fix for `check_epoch` method:

```rust
ConsensusMsg::EpochRetrievalRequest(request) => {
    ensure!(
        request.end_epoch <= self.epoch(),
        "[EpochManager] Received EpochRetrievalRequest beyond what we have locally"
    );
    
    // NEW: Validate start_epoch is not too old
    let min_epoch = self.epoch().saturating_sub(MAX_HISTORICAL_EPOCHS);
    ensure!(
        request.start_epoch >= min_epoch,
        "[EpochManager] Received EpochRetrievalRequest for overly old epochs"
    );
    
    // NEW: Check rate limit for this peer
    if !self.epoch_retrieval_rate_limiter.check_and_update(peer_id) {
        bail!("[EpochManager] Rate limit exceeded for EpochRetrievalRequest");
    }
    
    monitor!(
        "process_epoch_retrieval",
        self.process_epoch_retrieval(*request, peer_id)
    )?;
},
```

Additionally, consider requiring authentication by verifying the requesting peer is in the current validator set before processing the request.

## Proof of Concept

**Attack Steps:**

1. Set up a malicious node that can connect to validator network peers
2. Continuously send `EpochRetrievalRequest` messages to target validators:
   ```rust
   // Pseudocode for attack
   loop {
       let request = EpochRetrievalRequest {
           start_epoch: 0,
           end_epoch: 99,
       };
       let msg = ConsensusMsg::EpochRetrievalRequest(Box::new(request));
       network_client.send_to(target_validator, msg)?;
       // Send multiple requests rapidly to saturate the channel
   }
   ```

3. Monitor target validator's performance metrics:
   - Disk I/O latency increases
   - CPU usage spikes from deserialization
   - Network bandwidth consumption from large responses
   - Consensus message processing delays

4. Observe degraded validator performance:
   - Increased block proposal timeouts
   - Delayed vote processing
   - Higher round timeout rates

**Expected Impact:**
The target validator will experience measurable performance degradation, with increased resource utilization (disk I/O, CPU, network) and slower consensus message processing, potentially affecting block production times if the validator is a proposer or causing vote delays.

## Notes
This vulnerability is particularly concerning because:
- It requires no special privileges or validator status to exploit
- The attack can be sustained with minimal resources from the attacker
- Multiple validators can be targeted simultaneously to amplify the impact
- The lack of authentication makes it difficult to identify and block malicious peers

The database-level limit of 100 epochs provides some protection against unbounded response sizes, but does not prevent the resource exhaustion attack from being effective, especially when sustained over time or targeting multiple validators concurrently.

### Citations

**File:** consensus/src/epoch_manager.rs (L451-476)
```rust
    fn process_epoch_retrieval(
        &mut self,
        request: EpochRetrievalRequest,
        peer_id: AccountAddress,
    ) -> anyhow::Result<()> {
        debug!(
            LogSchema::new(LogEvent::ReceiveEpochRetrieval)
                .remote_peer(peer_id)
                .epoch(self.epoch()),
            "[EpochManager] receive {}", request,
        );
        let proof = self
            .storage
            .aptos_db()
            .get_epoch_ending_ledger_infos(request.start_epoch, request.end_epoch)
            .map_err(DbError::from)
            .context("[EpochManager] Failed to get epoch proof")?;
        let msg = ConsensusMsg::EpochChangeProof(Box::new(proof));
        if let Err(err) = self.network_sender.send_to(peer_id, msg) {
            warn!(
                "[EpochManager] Failed to send epoch proof to {}, with error: {:?}",
                peer_id, err,
            );
        }
        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L1677-1686)
```rust
            ConsensusMsg::EpochRetrievalRequest(request) => {
                ensure!(
                    request.end_epoch <= self.epoch(),
                    "[EpochManager] Received EpochRetrievalRequest beyond what we have locally"
                );
                monitor!(
                    "process_epoch_retrieval",
                    self.process_epoch_retrieval(*request, peer_id)
                )?;
            },
```

**File:** storage/aptosdb/src/common.rs (L7-9)
```rust
// TODO: Either implement an iteration API to allow a very old client to loop through a long history
// or guarantee that there is always a recent enough waypoint and client knows to boot from there.
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
```

**File:** consensus/src/network.rs (L757-761)
```rust
        let (consensus_messages_tx, consensus_messages) = aptos_channel::new(
            QueueStyle::FIFO,
            10,
            Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
```

**File:** consensus/src/network.rs (L869-870)
```rust
                        | ConsensusMsg::EpochRetrievalRequest(_)
                        | ConsensusMsg::EpochChangeProof(_)) => {
```
