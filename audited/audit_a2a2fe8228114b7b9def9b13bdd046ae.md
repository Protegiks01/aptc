# Audit Report

## Title
Memory Exhaustion via Unbounded execution_wait_phase_tx Channel in VFN/PFN Nodes

## Summary
The `execution_wait_phase_tx` channel in the consensus execution pipeline is implemented as an unbounded channel. For Validator Full Nodes (VFNs) and Public Full Nodes (PFNs) where buffer manager backpressure is automatically disabled, a malicious network peer can cause up to 150 ordered blocks to rapidly queue in this channel. Since ExecutionSchedulePhase produces ExecutionWaitRequests faster than ExecutionWaitPhase can consume them (due to awaiting slow compute results), this can lead to memory exhaustion and node degradation.

## Finding Description

The execution pipeline uses an unbounded MPSC channel to pass `ExecutionWaitRequest` objects from ExecutionSchedulePhase to ExecutionWaitPhase. [1](#0-0) [2](#0-1) 

**Asymmetric Processing Speeds:**
- ExecutionSchedulePhase quickly creates boxed futures without awaiting them [3](#0-2) 
- ExecutionWaitPhase processes sequentially, awaiting each compute result [4](#0-3) 

**Backpressure Disabled for Non-Validators:**
The buffer manager backpressure mechanism is automatically disabled for VFNs and PFNs via the config optimizer. [5](#0-4) 

When `enable_pre_commit` is false (automatic for non-validators), the `need_back_pressure()` check always returns false, allowing unlimited block acceptance. [6](#0-5) 

**Attack Vector:**
1. A VFN/PFN receives ordered blocks via consensus observer from a malicious or compromised validator peer
2. Consensus observer accepts up to 150 pending blocks (max_num_pending_blocks limit) [7](#0-6) 
3. After state sync, all pending ordered blocks are finalized in rapid succession [8](#0-7) 
4. BufferManager forwards each ExecutionSchedulePhase response directly to the unbounded `execution_wait_phase_tx` without size checks [9](#0-8) 
5. Each ExecutionWaitRequest contains futures capturing full block batches with all transactions
6. If blocks are large and execution is slow, all 150 requests accumulate in memory simultaneously

**Memory Amplification:**
Each `ExecutionWaitRequest` contains a boxed future that captures `ordered_blocks: Vec<Arc<PipelinedBlock>>`, where blocks can approach the maximum block size limit (multiple MB per block). With 150 blocks queued, this represents significant memory consumption beyond normal operation.

## Impact Explanation

This qualifies as **HIGH severity** under the Aptos bug bounty program criteria for "Validator node slowdowns" and "API crashes":

- **Node Performance Degradation**: Memory pressure from 150 large blocks queued in the channel causes increased GC pressure, slower response times, and potential OOM conditions
- **Service Disruption**: VFN/PFN nodes becoming unresponsive affects applications relying on them for RPC access
- **Network Health**: If multiple VFNs/PFNs are targeted simultaneously, it degrades the network's ability to serve read requests
- **No Funds at Risk**: This is a DoS vulnerability, not affecting consensus safety or fund security

While the consensus observer limit bounds the maximum queue size (preventing "unbounded" growth to infinity), 150 large blocks is sufficient to cause memory exhaustion on nodes with limited resources.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Attack Requirements:**
- Target must be a VFN or PFN (backpressure disabled by default)
- Attacker must be able to send ordered block messages (requires being a network peer)
- Blocks must be large enough and execution slow enough for memory impact
- Most effective during state sync catch-up scenarios

**Mitigating Factors:**
- Consensus observer limit of 150 blocks prevents unlimited growth
- Normal execution is relatively fast, limiting accumulation
- Validators have backpressure enabled (MAX_BACKLOG = 20), making them less vulnerable
- Attack requires sustained sending of large blocks

**Ease of Exploitation:**
Moderate - requires network access to VFN/PFN and ability to send consensus observer messages, but no cryptographic attacks or validator collusion needed.

## Recommendation

Implement bounded channels with backpressure for the execution wait phase, even when `enable_pre_commit` is disabled:

```rust
// In decoupled_execution_utils.rs, replace unbounded channel with bounded:
pub const EXECUTION_WAIT_PHASE_CHANNEL_SIZE: usize = 50;

let (execution_wait_phase_request_tx, execution_wait_phase_request_rx) =
    futures::channel::mpsc::channel::<CountedRequest<ExecutionWaitRequest>>(
        EXECUTION_WAIT_PHASE_CHANNEL_SIZE
    );
```

Modify BufferManager to handle backpressure when forwarding to execution wait phase:

```rust
// In buffer_manager.rs process_execution_schedule_response:
async fn process_execution_schedule_response(&mut self, response: ExecutionWaitRequest) {
    let request = self.create_new_request(response);
    
    // Add timeout to prevent indefinite blocking
    match timeout(Duration::from_secs(30), self.execution_wait_phase_tx.send(request)).await {
        Ok(Ok(_)) => {},
        Ok(Err(e)) => error!("Failed to send to execution wait phase: {:?}", e),
        Err(_) => {
            error!("Timeout sending to execution wait phase - channel likely full");
            // Trigger warning/metric for monitoring
        }
    }
}
```

Additionally, enforce per-peer rate limiting in consensus observer to prevent rapid block flooding from single malicious peers.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_execution_wait_channel_flooding() {
    use consensus::pipeline::buffer_manager::create_channel;
    use consensus::pipeline::execution_wait_phase::{ExecutionWaitRequest, ExecutionWaitPhase};
    use futures::StreamExt;
    
    // Create unbounded channel as in production
    let (tx, mut rx) = create_channel::<ExecutionWaitRequest>();
    
    // Simulate rapid sending of 150 large blocks (as consensus observer would)
    for i in 0..150 {
        let block_id = HashValue::random();
        let fut = Box::pin(async move {
            // Simulate slow execution (100ms per block)
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(vec![]) // Simplified
        });
        
        let req = ExecutionWaitRequest { block_id, fut };
        tx.unbounded_send(req).expect("Channel should accept all");
    }
    
    // Measure channel depth - in production this would be 150 pending items
    let mut received_count = 0;
    while let Ok(Some(_)) = tokio::time::timeout(
        Duration::from_millis(10), 
        rx.next()
    ).await {
        received_count += 1;
    }
    
    // Verify all 150 are queued (demonstrating memory accumulation)
    assert_eq!(received_count, 150, "Channel accumulated all blocks without limit");
    
    // In real scenario, each block contains full transaction payload
    // With max block size ~5MB, 150 blocks = ~750MB in channel alone
}
```

**Notes:**
- This PoC requires access to the consensus module internals
- A full exploitation would require setting up a VFN with consensus observer and sending crafted ordered block messages from a malicious peer
- The memory impact scales with actual block sizes in production (bounded by `max_sending_block_bytes` configuration)

### Citations

**File:** consensus/src/pipeline/buffer_manager.rs (L98-100)
```rust
pub fn create_channel<T>() -> (Sender<T>, Receiver<T>) {
    unbounded::<T>()
}
```

**File:** consensus/src/pipeline/buffer_manager.rs (L598-605)
```rust
    async fn process_execution_schedule_response(&mut self, response: ExecutionWaitRequest) {
        // pass through to the execution wait phase
        let request = self.create_new_request(response);
        self.execution_wait_phase_tx
            .send(request)
            .await
            .expect("Failed to send execution wait request.");
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L906-910)
```rust
    fn need_back_pressure(&self) -> bool {
        const MAX_BACKLOG: Round = 20;

        self.back_pressure_enabled && self.highest_committed_round + MAX_BACKLOG < self.latest_round
    }
```

**File:** consensus/src/pipeline/decoupled_execution_utils.rs (L67-68)
```rust
    let (execution_wait_phase_request_tx, execution_wait_phase_request_rx) =
        create_channel::<CountedRequest<ExecutionWaitRequest>>();
```

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L70-79)
```rust
        let fut = async move {
            for b in ordered_blocks.iter_mut() {
                let (compute_result, execution_time) = b.wait_for_compute_result().await?;
                b.set_compute_result(compute_result, execution_time);
            }
            Ok(ordered_blocks)
        }
        .boxed();

        ExecutionWaitRequest { block_id, fut }
```

**File:** consensus/src/pipeline/execution_wait_phase.rs (L49-56)
```rust
    async fn process(&self, req: ExecutionWaitRequest) -> ExecutionResponse {
        let ExecutionWaitRequest { block_id, fut } = req;

        ExecutionResponse {
            block_id,
            inner: fut.await,
        }
    }
```

**File:** config/src/config/consensus_config.rs (L547-552)
```rust
        // Disable pre-commit for VFNs and PFNs (if they are not manually set)
        let mut modified_config = false;
        if local_consensus_config_yaml["enable_pre_commit"].is_null() && !node_type.is_validator() {
            consensus_config.enable_pre_commit = false;
            modified_config = true;
        }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L78-88)
```rust
        let max_num_ordered_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
        if self.ordered_blocks.len() >= max_num_ordered_blocks {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Exceeded the maximum number of ordered blocks: {:?}. Dropping block: {:?}.",
                    max_num_ordered_blocks,
                    observed_ordered_block.ordered_block().proof_block_info()
                ))
            );
            return; // Drop the block if we've exceeded the maximum
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1051-1055)
```rust
        let all_ordered_blocks = self.observer_block_data.lock().get_all_ordered_blocks();
        for (_, (observed_ordered_block, commit_decision)) in all_ordered_blocks {
            // Finalize the ordered block
            let ordered_block = observed_ordered_block.consume_ordered_block();
            self.finalize_ordered_block(ordered_block).await;
```
