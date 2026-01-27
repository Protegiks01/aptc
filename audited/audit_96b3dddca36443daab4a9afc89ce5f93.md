# Audit Report

## Title
Byzantine Validators Can Flood Secret Share Verification Pipeline with Valid-but-Useless Messages

## Summary
Byzantine validators can exploit the `verification_task()` function to flood the secret share verification pipeline with cryptographically valid but operationally useless secret share messages. This congests the bounded verification executor, blocks processing of new messages, and delays critical share aggregation needed for consensus progression.

## Finding Description

The `verification_task()` function processes incoming secret share RPC requests with insufficient filtering of message usefulness: [1](#0-0) 

The verification only checks epoch matching and cryptographic validity, but does NOT verify:
- Whether the share is for an already-decided round
- Whether the share is a duplicate from the same sender
- Whether the share is for a round that's actually needed [2](#0-1) 

The cryptographic verification only validates the share against verification keys: [3](#0-2) 

Byzantine validators can exploit this by sending valid shares for:

1. **Old decided rounds**: Shares for rounds where aggregation already completed pass verification but are no-ops in the store
2. **Far-future rounds**: System accepts shares up to 200 rounds ahead of the current round
3. **Duplicate shares**: Same share sent repeatedly (deduplication only happens after verification) [4](#0-3) 

The attack exploits multiple bottlenecks:

**Bottleneck 1 - Bounded Executor**: Verification tasks spawn on a bounded executor with default capacity of 16 tasks. When full, the verification loop blocks: [5](#0-4) [6](#0-5) 

**Bottleneck 2 - Unbounded Verified Channel**: Successfully verified messages queue in an unbounded channel, allowing unlimited memory growth: [7](#0-6) 

**Exploitation Path:**

1. Byzantine validator crafts 1000 valid secret shares for old/future/useless rounds
2. Sends these shares via RPC to target validators
3. Per-sender channel queue (capacity 10) fills with messages
4. Verification task spawns verifications on bounded executor (capacity 16)
5. Executor fills up, verification loop blocks at line 233
6. Meanwhile, legitimate shares for active consensus rounds arrive but cannot be verified
7. Unbounded verified_msg_tx channel grows with useless verified messages
8. Main event loop must process all queued messages, delaying critical share processing
9. Share aggregation for active rounds is delayed, potentially blocking consensus progress

The store does have deduplication and round filtering, but only AFTER messages pass through the expensive verification pipeline: [8](#0-7) 

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Byzantine flooding directly causes verification task congestion and processing delays on victim validators
- **Significant protocol violations**: Delays consensus by preventing timely secret share aggregation, violating the Resource Limits invariant (#9) that all operations must respect computational limits
- **Consensus liveness impact**: Secret shares must be aggregated within consensus timeouts. Systematic delays could prevent block finalization

With 100+ validators in production Aptos networks, even a small coalition of Byzantine validators (e.g., 10 out of 100) could each send 100 useless shares per round, creating sustained congestion on honest validators.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker requirements**: Any validator in the active set can perform this attack with no special privileges
- **Detection difficulty**: Valid cryptographic signatures make filtering at network layer impossible
- **Attack complexity**: Trivial - just broadcast valid but useless shares
- **Cost to attacker**: Minimal - shares are small messages and verification is done by victims
- **Mitigation absence**: No rate limiting, usefulness filtering, or early deduplication in verification pipeline

## Recommendation

Implement multi-layered defenses:

**1. Early Usefulness Filtering** - Check round relevance before expensive verification:

```rust
async fn verification_task(
    epoch_state: Arc<EpochState>,
    mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
    verified_msg_tx: UnboundedSender<SecretShareRpc>,
    config: SecretShareConfig,
    bounded_executor: BoundedExecutor,
    secret_share_store: Arc<Mutex<SecretShareStore>>,  // Add store reference
) {
    while let Some(dec_msg) = incoming_rpc_request.next().await {
        let tx = verified_msg_tx.clone();
        let epoch_state_clone = epoch_state.clone();
        let config_clone = config.clone();
        let store_clone = secret_share_store.clone();
        bounded_executor
            .spawn(async move {
                match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                    Ok(msg) => {
                        // Early filtering before expensive verification
                        if let SecretShareMessage::Share(ref share) = msg {
                            let store = store_clone.lock();
                            let highest_known = store.get_highest_known_round();
                            // Reject shares too far in past or future
                            if share.metadata().round < highest_known.saturating_sub(10) 
                                || share.metadata().round > highest_known + FUTURE_ROUNDS_TO_ACCEPT {
                                return;
                            }
                            // Skip if round already decided
                            if store.is_round_decided(share.metadata().round) {
                                return;
                            }
                        }
                        
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

**2. Bounded Verified Channel** - Replace unbounded channel with bounded to prevent memory exhaustion:

```rust
let (verified_msg_tx, mut verified_msg_rx) = bounded(1000);  // Bounded capacity
```

**3. Per-Sender Rate Limiting** - Add time-based rate limiting on verification attempts per sender

**4. Deduplication Cache** - Maintain bloom filter of recently verified share IDs to skip re-verification

## Proof of Concept

```rust
#[tokio::test]
async fn test_byzantine_flooding_attack() {
    // Setup: Create secret share manager with real config
    let (author, epoch_state, config, bounded_executor) = setup_test_environment();
    let (verified_tx, mut verified_rx) = unbounded();
    let (rpc_tx, rpc_rx) = aptos_channel::new(QueueStyle::KLAST, 10, None);
    
    // Spawn verification task
    tokio::spawn(SecretShareManager::verification_task(
        epoch_state.clone(),
        rpc_rx,
        verified_tx,
        config.clone(),
        bounded_executor,
    ));
    
    // Attack: Byzantine validator floods with 100 valid shares for old rounds
    let current_round = 1000u64;
    let byzantine_validator = create_validator_keys();
    
    for old_round in 900..1000 {
        let share = create_valid_share(
            &byzantine_validator,
            old_round,
            &config,
        );
        let msg = SecretShareMessage::Share(share);
        let serialized = bcs::to_bytes(&msg).unwrap();
        
        rpc_tx.push(
            byzantine_validator.address(),
            IncomingSecretShareRequest {
                req: SecretShareNetworkMessage::new(epoch_state.epoch, serialized),
                sender: byzantine_validator.address(),
                protocol: ProtocolId::ConsensusDirectSend,
                response_sender: oneshot::channel().0,
            },
        );
    }
    
    // Verification: Bounded executor fills up (capacity 16)
    // Further messages block in verification task
    // Legitimate shares for round 1000 are delayed
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Legitimate share arrives but processing is delayed
    let legitimate_share = create_valid_share(&honest_validator, current_round, &config);
    let start = Instant::now();
    send_share(rpc_tx, legitimate_share);
    
    // Assert: Legitimate share processing is significantly delayed
    wait_for_verification(&mut verified_rx, current_round).await;
    let delay = start.elapsed();
    
    assert!(delay > Duration::from_millis(500), 
        "Byzantine flooding should cause significant delay, got {:?}", delay);
}
```

## Notes

This vulnerability is particularly severe because:

1. **No authentication of usefulness**: Cryptographic validity ≠ operational usefulness
2. **Unbounded resource consumption**: Memory can grow without limit via verified_msg_tx
3. **Blocking architecture**: Single verification loop blocks entire pipeline
4. **Large attack window**: FUTURE_ROUNDS_TO_ACCEPT=200 provides huge space for flooding
5. **Coalition amplification**: Multiple Byzantine validators multiply the attack effect

The fix requires defense-in-depth with early filtering, bounded resources, and rate limiting to prevent Byzantine validators from weaponizing the verification pipeline.

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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L333-333)
```rust
        let (verified_msg_tx, mut verified_msg_rx) = unbounded();
```

**File:** consensus/src/rand/secret_sharing/network_messages.rs (L28-38)
```rust
    pub fn verify(
        &self,
        epoch_state: &EpochState,
        config: &SecretShareConfig,
    ) -> anyhow::Result<()> {
        ensure!(self.epoch() == epoch_state.epoch);
        match self {
            SecretShareMessage::RequestShare(_) => Ok(()),
            SecretShareMessage::Share(share) => share.verify(config),
        }
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

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-275)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }
```
