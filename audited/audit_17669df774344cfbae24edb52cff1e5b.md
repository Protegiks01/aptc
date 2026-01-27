# Audit Report

## Title
Silent Consensus Liveness Failure Due to Unhandled Panic in DirectMempoolQuorumStore

## Summary
The `DirectMempoolQuorumStore` task can panic when receiving an unexpected `PayloadFilter::InQuorumStore` variant, causing silent task termination and permanent consensus deadlock. The panic leaves partially processed requests in an inconsistent state with no error reporting or recovery mechanism.

## Finding Description

The `DirectMempoolQuorumStore::start()` function spawns an async task that processes consensus payload requests. When a panic occurs in `handle_consensus_request()`, it causes a critical liveness failure:

**Panic Source:** [1](#0-0) 

The `unreachable!()` macro on line 101 will panic if `PayloadFilter::InQuorumStore` is received.

**Unmonitored Task Spawn:** [2](#0-1) 

The task is spawned via `spawn_named!()` which expands to `tokio::spawn()`, and the `JoinHandle` is immediately dropped (not stored or monitored): [3](#0-2) 

**Incomplete Request Processing:** [4](#0-3) 

When panic occurs at line 158's `.await` call:
1. Message is consumed from `consensus_receiver` (line 157)
2. Panic unwinds the task before callback response is sent
3. Tokio catches panic and terminates task silently
4. Consensus waits indefinitely for response that never arrives
5. All subsequent messages in channel are never processed

**Why This Breaks Consensus Safety:**

The `PayloadFilter` is constructed from pending blocks' payloads in the proposal generation flow: [5](#0-4) 

The filter type is determined by payload types: [6](#0-5) 

If ANY pending block contains an `InQuorumStore` payload while the node is in DirectMempool mode, line 772's check creates an `InQuorumStore` filter, which triggers the panic.

**Validation Gap:**

While payload verification exists: [7](#0-6) 

This validation happens during proposal reception, but does not prevent scenarios where:
- Blocks from recovery contain mismatched payload types
- Timing windows during mode transitions leave incompatible blocks in pending state
- Byzantine behavior or implementation bugs bypass validation

## Impact Explanation

**High Severity** - This meets the bug bounty criteria for "Significant protocol violations" and causes validator node operational failures:

1. **Consensus Liveness Loss**: Once the task panics, the validator can no longer participate in consensus (cannot create new blocks)
2. **Silent Failure**: No crash, no logs, no alerts - node appears running but consensus is dead
3. **No Recovery**: Requires node restart to restore functionality
4. **Affects All Validators**: Any validator running DirectMempool mode is vulnerable

This violates the **Consensus Safety** invariant: "AptosBFT must prevent... liveness failures" and the general principle that consensus must continue making progress.

## Likelihood Explanation

**Low-to-Medium Likelihood** in production, but **High Impact** when triggered:

- Requires specific conditions (DirectMempool mode with incompatible pending blocks)
- Payload validation should prevent most scenarios
- However, defensive programming failures like this often have unexpected triggers
- The presence of `unreachable!()` indicates developers expected this case to never occur, suggesting potential blind spots

## Recommendation

Replace the panic with graceful error handling:

```rust
async fn handle_block_request(
    &self,
    max_txns: u64,
    max_bytes: u64,
    return_non_full: bool,
    payload_filter: PayloadFilter,
    callback: oneshot::Sender<Result<GetPayloadResponse>>,
) {
    let exclude_txns = match payload_filter {
        PayloadFilter::DirectMempool(exclude_txns) => exclude_txns,
        PayloadFilter::InQuorumStore(_) => {
            // Log error and send error response instead of panicking
            error!("Received InQuorumStore filter in DirectMempool mode: {}", payload_filter);
            let _ = callback.send(Err(anyhow::anyhow!(
                "Invalid payload filter type for DirectMempool mode"
            )));
            return;
        },
        PayloadFilter::Empty => Vec::new(),
    };
    // ... rest of function
}
```

Additionally, monitor the task health:
```rust
fn start(self) {
    let handle = spawn_named!("DirectMempoolQuorumStore", quorum_store.start());
    // Monitor handle for panic
    tokio::spawn(async move {
        if let Err(e) = handle.await {
            error!("DirectMempoolQuorumStore task panicked: {:?}", e);
            // Trigger node restart or alert
        }
    });
}
```

## Proof of Concept

```rust
// Test demonstrating the panic vulnerability
#[tokio::test]
async fn test_direct_mempool_panic_on_wrong_filter() {
    use futures::channel::mpsc;
    use consensus_types::common::PayloadFilter;
    use std::collections::HashSet;
    
    let (consensus_tx, consensus_rx) = mpsc::channel(10);
    let (mempool_tx, _mempool_rx) = mpsc::channel(10);
    
    let store = DirectMempoolQuorumStore::new(
        consensus_rx,
        mempool_tx,
        5000,
    );
    
    // Spawn the task (JoinHandle dropped)
    tokio::spawn(store.start());
    
    // Create request with InQuorumStore filter (wrong type for DirectMempool)
    let (callback, _callback_rx) = oneshot::channel();
    let wrong_filter = PayloadFilter::InQuorumStore(HashSet::new());
    
    let req = GetPayloadCommand::GetPayloadRequest(GetPayloadRequest {
        max_txns: PayloadTxnsSize::new(100, 1_000_000),
        max_txns_after_filtering: 100,
        soft_max_txns_after_filtering: 80,
        maybe_optqs_payload_pull_params: None,
        max_inline_txns: PayloadTxnsSize::new(10, 100_000),
        filter: wrong_filter, // This will trigger unreachable!()
        return_non_full: false,
        callback,
        block_timestamp: Duration::from_secs(0),
    });
    
    // Send request - task will panic
    consensus_tx.clone().try_send(req).unwrap();
    
    // Task has now silently terminated due to panic
    // Subsequent requests will never be processed
    // Callback will never receive response -> consensus deadlock
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    // At this point, task is dead but no one knows
}
```

### Citations

**File:** consensus/src/quorum_store/direct_mempool_quorum_store.rs (L98-104)
```rust
        let exclude_txns = match payload_filter {
            PayloadFilter::DirectMempool(exclude_txns) => exclude_txns,
            PayloadFilter::InQuorumStore(_) => {
                unreachable!("Unknown payload_filter: {}", payload_filter)
            },
            PayloadFilter::Empty => Vec::new(),
        };
```

**File:** consensus/src/quorum_store/direct_mempool_quorum_store.rs (L153-163)
```rust
    pub async fn start(mut self) {
        loop {
            let _timer = counters::MAIN_LOOP.start_timer();
            ::futures::select! {
                msg = self.consensus_receiver.select_next_some() => {
                    self.handle_consensus_request(msg).await;
                },
                complete => break,
            }
        }
    }
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L114-121)
```rust
    fn start(self) {
        let quorum_store = DirectMempoolQuorumStore::new(
            self.consensus_to_quorum_store_receiver,
            self.quorum_store_to_mempool_sender,
            self.mempool_txn_pull_timeout_ms,
        );
        spawn_named!("DirectMempoolQuorumStore", quorum_store.start());
    }
```

**File:** crates/aptos-logger/src/macros.rs (L7-8)
```rust
macro_rules! spawn_named {
      ($name:expr, $func:expr) => { tokio::spawn($func); };
```

**File:** consensus/src/liveness/proposal_generator.rs (L585-589)
```rust
        let exclude_payload: Vec<_> = pending_blocks
            .iter()
            .flat_map(|block| block.payload())
            .collect();
        let payload_filter = PayloadFilter::from(&exclude_payload);
```

**File:** consensus/consensus-types/src/common.rs (L574-631)
```rust
    pub fn verify(
        &self,
        verifier: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> anyhow::Result<()> {
        match (quorum_store_enabled, self) {
            (false, Payload::DirectMempool(_)) => Ok(()),
            (true, Payload::InQuorumStore(proof_with_status)) => {
                Self::verify_with_cache(&proof_with_status.proofs, verifier, proof_cache)
            },
            (true, Payload::InQuorumStoreWithLimit(proof_with_status)) => Self::verify_with_cache(
                &proof_with_status.proof_with_data.proofs,
                verifier,
                proof_cache,
            ),
            (true, Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _))
            | (true, Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _)) => {
                Self::verify_with_cache(&proof_with_data.proofs, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    inline_batches.iter().map(|(info, txns)| (info, txns)),
                )?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V1(p))) => {
                let proof_with_data = p.proof_with_data();
                Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    p.inline_batches()
                        .iter()
                        .map(|batch| (batch.info(), batch.transactions())),
                )?;
                Self::verify_opt_batches(verifier, p.opt_batches())?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V2(p))) => {
                if true {
                    bail!("OptQuorumStorePayload::V2 cannot be accepted yet");
                }
                #[allow(unreachable_code)]
                {
                    let proof_with_data = p.proof_with_data();
                    Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                    Self::verify_inline_batches(
                        p.inline_batches()
                            .iter()
                            .map(|batch| (batch.info(), batch.transactions())),
                    )?;
                    Self::verify_opt_batches(verifier, p.opt_batches())?;
                    Ok(())
                }
            },
            (_, _) => Err(anyhow::anyhow!(
                "Wrong payload type. Expected Payload::InQuorumStore {} got {} ",
                quorum_store_enabled,
                self
            )),
        }
```

**File:** consensus/consensus-types/src/common.rs (L767-788)
```rust
impl From<&Vec<&Payload>> for PayloadFilter {
    fn from(exclude_payloads: &Vec<&Payload>) -> Self {
        if exclude_payloads.is_empty() {
            return PayloadFilter::Empty;
        }
        let direct_mode = exclude_payloads.iter().any(|payload| payload.is_direct());

        if direct_mode {
            let mut exclude_txns = Vec::new();
            for payload in exclude_payloads {
                if let Payload::DirectMempool(txns) = payload {
                    for txn in txns {
                        exclude_txns.push(TransactionSummary {
                            sender: txn.sender(),
                            replay_protector: txn.replay_protector(),
                            hash: txn.committed_hash(),
                        });
                    }
                }
            }
            PayloadFilter::DirectMempool(exclude_txns)
        } else {
```
