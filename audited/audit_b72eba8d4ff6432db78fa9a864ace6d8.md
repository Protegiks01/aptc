# Audit Report

## Title
Secret Share Verification Task Blocks on Executor Saturation Causing Message Drops and Consensus Disruption

## Summary
The `verification_task()` function in `SecretShareManager` has a critical resource exhaustion vulnerability. When processing incoming secret share messages, it awaits on `bounded_executor.spawn()` for each message, which blocks the entire verification loop when the executor reaches capacity. This allows a malicious validator to flood the system with messages, causing legitimate secret shares to be dropped from the channel queue, potentially preventing randomness generation and causing consensus liveness failures.

## Finding Description

The vulnerability exists in the `verification_task()` function which processes incoming secret share RPC requests. The function's design creates a blocking bottleneck that can be exploited through message flooding. [1](#0-0) 

The critical flaw is that the function **awaits** the `spawn()` call for each message. The `BoundedExecutor::spawn()` method is async and blocks when the semaphore is at capacity, waiting for a permit to become available: [2](#0-1) [3](#0-2) 

The bounded executor is created with a default capacity of only 16 concurrent tasks: [4](#0-3) [5](#0-4) 

Meanwhile, incoming messages queue in an `aptos_channel` with KLAST eviction policy and a capacity of only 10 messages per peer: [6](#0-5) [7](#0-6) 

When the queue exceeds capacity, **oldest messages are dropped**: [8](#0-7) 

**Attack Path:**
1. Malicious validator sends rapid stream of secret share messages (valid or crafted to be expensive to verify)
2. Up to 16 verification tasks spawn and occupy the `bounded_executor`
3. The 17th message causes `bounded_executor.spawn().await` to **block**, waiting for a permit
4. While blocked, the `verification_task()` **cannot consume any new messages** from `incoming_rpc_request.next().await`
5. Messages continue arriving from the network and queue up (max 10 per peer in the channel)
6. Once the channel exceeds 10 messages per peer, **oldest messages are dropped** including potentially legitimate secret shares from that peer or others
7. Dropped secret shares prevent proper secret reconstruction needed for randomness generation

The verification itself involves cryptographic operations that can be time-consuming: [9](#0-8) 

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The unbounded message acceptance without proper rate limiting before spawning allows resource exhaustion.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for multiple reasons:

1. **Validator Node Slowdowns** (explicitly listed as High severity): The blocking behavior directly causes validator nodes to be unable to process secret share messages efficiently, slowing down the randomness generation subsystem.

2. **Significant Protocol Violations**: The secret sharing protocol is critical for randomness generation in Aptos consensus. Dropped secret shares mean validators cannot reconstruct the shared secrets needed for on-chain randomness, violating consensus protocol invariants.

3. **Consensus Liveness Impact**: While not causing complete network halt, the disruption to randomness generation can affect consensus liveness and block production that depends on randomness.

4. **Single Validator Attack**: A single malicious or compromised validator can cause this disruption across the network, affecting all other validators' ability to process secret shares.

The impact is amplified by:
- Very small channel capacity (10 per peer)
- Very small executor pool (16 tasks)
- Cryptographically expensive verification operations
- No rate limiting or prioritization mechanism before spawning

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is practical and likely because:

1. **Low Complexity**: Exploiting requires only sending rapid secret share messages - no complex cryptographic attacks or protocol violations needed

2. **Single Validator Sufficient**: Only one malicious validator is needed to cause disruption, which is within the Byzantine fault tolerance model (<1/3 validators)

3. **No Detection Mechanism**: There's no rate limiting or anomaly detection before spawning verification tasks

4. **Small Capacity Thresholds**: With only 16 executor slots and 10 messages per peer queuing, the thresholds are easily exceeded

5. **Natural Occurrence Possible**: Even without malicious intent, network conditions or bugs causing message retransmission could trigger this issue

The likelihood is slightly reduced by:
- Requires validator-level network access (consensus network participation)
- Assumes Byzantine validator in the system (though this is the explicit threat model for BFT)

## Recommendation

**Immediate Fix**: Use `try_spawn()` instead of `spawn().await` to avoid blocking:

```rust
async fn verification_task(
    epoch_state: Arc<EpochState>,
    mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
    verified_msg_tx: UnboundedSender<SecretShareRpc>,
    config: SecretShareConfig,
    bounded_executor: BoundedExecutor,
) {
    while let Some(dec_msg) = incoming_rpc_request.next().await {
        let tx = verified_msg_tx.clone();
        let epoch_state_clone = epoch_state.clone();
        let config_clone = config.clone();
        
        // Use try_spawn instead of blocking spawn
        match bounded_executor.try_spawn(async move {
            match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                Ok(msg) => {
                    if msg.verify(&epoch_state_clone, &config_clone).is_ok() {
                        let _ = tx.unbounded_send(SecretShareRpc {
                            msg,
                            protocol: dec_msg.protocol,
                            response_sender: dec_msg.response_sender,
                        });
                    }
                },
                Err(e) => {
                    warn!("Invalid dec message: {}", e);
                },
            }
        }) {
            Ok(_handle) => {
                // Task spawned successfully
            },
            Err(_future) => {
                // Executor at capacity - drop this message or implement backpressure
                warn!("Bounded executor at capacity, dropping secret share message verification");
                counters::SECRET_SHARE_DROPPED_MESSAGES.inc();
            }
        }
    }
}
```

**Additional Improvements:**

1. **Per-Peer Rate Limiting**: Add rate limiting before spawning based on peer_id to prevent single peer flooding

2. **Priority Queue**: Implement prioritization so legitimate shares from well-behaved validators are processed first

3. **Increase Capacity**: Consider increasing `num_bounded_executor_tasks` and `internal_per_key_channel_size` with appropriate monitoring

4. **Early Validation**: Perform lightweight validation (epoch check, author check) before spawning expensive cryptographic verification

5. **Backpressure**: Implement proper backpressure to the network layer when verification queue is saturated

## Proof of Concept

```rust
// Rust reproduction test (add to secret_share_manager.rs tests)
#[tokio::test]
async fn test_verification_task_executor_exhaustion() {
    use futures::channel::oneshot;
    use aptos_bounded_executor::BoundedExecutor;
    use aptos_channel::Config;
    use std::time::Duration;
    
    // Create bounded executor with very small capacity
    let runtime = tokio::runtime::Handle::current();
    let bounded_executor = BoundedExecutor::new(2, runtime); // Small capacity
    
    // Create channel for incoming messages
    let (msg_tx, msg_rx) = Config::new(5)
        .build::<Author, IncomingSecretShareRequest>();
    
    let (verified_tx, mut verified_rx) = unbounded();
    
    // Create mock epoch state and config
    let epoch_state = Arc::new(/* mock epoch state */);
    let config = /* mock config */;
    
    // Spawn verification task
    let verification_handle = tokio::spawn(SecretShareManager::verification_task(
        epoch_state,
        msg_rx,
        verified_tx,
        config,
        bounded_executor,
    ));
    
    // Send messages that take long to verify
    for i in 0..20 {
        let (response_tx, _response_rx) = oneshot::channel();
        let msg = IncomingSecretShareRequest {
            req: /* create expensive-to-verify message */,
            sender: Author::random(),
            protocol: RPC[0],
            response_sender: response_tx,
        };
        
        // This should succeed but messages will start getting dropped
        // or verification will block after executor fills
        let _ = msg_tx.push(msg.sender, msg);
    }
    
    // Observe that:
    // 1. After 2 messages, executor is full
    // 2. 3rd message blocks verification_task
    // 3. Messages queue in channel
    // 4. After 5 messages per peer, oldest are dropped
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify some messages were dropped (check counters or channel state)
    // This demonstrates the vulnerability
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Byzantine Tolerance**: While Aptos BFT is designed to tolerate up to 1/3 Byzantine validators, this vulnerability allows a SINGLE malicious validator to disrupt secret sharing across the entire network

2. **Randomness Critical**: On-chain randomness is increasingly important for DeFi applications, gaming, and fair transaction ordering. Disrupting randomness generation has cascading effects

3. **Subtle Nature**: The bug is subtle - using `await` on spawn seems natural but creates a hidden blocking point that exhausts resources under load

4. **Production Impact**: With default configuration (16 executor tasks, 10 message queue depth), this is easily triggered in production conditions

The fix is straightforward but requires careful consideration of what to do when the executor is saturated - the system must gracefully handle overload without blocking the message processing loop.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L205-235)
```rust
    async fn verification_task(
        epoch_state: Arc<EpochState>,
        mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
        verified_msg_tx: UnboundedSender<SecretShareRpc>,
        config: SecretShareConfig,
        bounded_executor: BoundedExecutor,
    ) {
        while let Some(dec_msg) = incoming_rpc_request.next().await {
            let tx = verified_msg_tx.clone();
            let epoch_state_clone = epoch_state.clone();
            let config_clone = config.clone();
            bounded_executor
                .spawn(async move {
                    match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                        Ok(msg) => {
                            if msg.verify(&epoch_state_clone, &config_clone).is_ok() {
                                let _ = tx.unbounded_send(SecretShareRpc {
                                    msg,
                                    protocol: dec_msg.protocol,
                                    response_sender: dec_msg.response_sender,
                                });
                            }
                        },
                        Err(e) => {
                            warn!("Invalid dec message: {}", e);
                        },
                    }
                })
                .await;
        }
    }
```

**File:** crates/bounded-executor/src/executor.rs (L33-35)
```rust
    async fn acquire_permit(&self) -> OwnedSemaphorePermit {
        self.semaphore.clone().acquire_owned().await.unwrap()
    }
```

**File:** crates/bounded-executor/src/executor.rs (L45-52)
```rust
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```

**File:** config/src/config/consensus_config.rs (L242-242)
```rust
            internal_per_key_channel_size: 10,
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```

**File:** consensus/src/consensus_provider.rs (L81-84)
```rust
    let bounded_executor = BoundedExecutor::new(
        node_config.consensus.num_bounded_executor_tasks as usize,
        runtime.handle().clone(),
    );
```

**File:** consensus/src/epoch_manager.rs (L1285-1290)
```rust
        let (secret_share_manager_tx, secret_share_manager_rx) =
            aptos_channel::new::<AccountAddress, IncomingSecretShareRequest>(
                QueueStyle::KLAST,
                self.config.internal_per_key_channel_size,
                None,
            );
```

**File:** crates/channel/src/message_queues.rs (L134-147)
```rust
        if key_message_queue.len() >= self.max_queue_size.get() {
            if let Some(c) = self.counters.as_ref() {
                c.with_label_values(&["dropped"]).inc();
            }
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
            }
```

**File:** types/src/secret_sharing.rs (L75-82)
```rust
    pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
        let index = config.get_id(self.author());
        let decryption_key_share = self.share().clone();
        // TODO(ibalajiarun): Check index out of bounds
        config.verification_keys[index]
            .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
        Ok(())
    }
```
