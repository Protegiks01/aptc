# Audit Report

## Title
Indefinite Chain Halt Due to DKG Failure Without Automatic Fallback Mechanism

## Summary
When DKG (Distributed Key Generation) cannot complete due to network channel saturation or message dropping, the Aptos blockchain halts indefinitely with no automatic fallback mechanism. Recovery requires manual intervention by all validators to restart with `randomness_override_seq_num` configuration, creating a critical availability vulnerability.

## Finding Description

The DKG system uses a network channel with `max_network_channel_size` (default 256 messages) for message passing between validators. [1](#0-0) 

When DKG starts, validators exchange transcript requests and responses via `ReliableBroadcast`. [2](#0-1) 

The critical issue is that `ReliableBroadcast` has **no global timeout** - it retries indefinitely until quorum is reached. [3](#0-2) 

The retry loop at line 167-206 continues forever with the comment "unreachable!("Should aggregate with all responses")" at line 203, indicating the system expects to always eventually succeed. Failed RPCs trigger exponential backoff and retry at lines 191-200, but there is no condition to abort if quorum cannot be reached.

When the network channel (FIFO queue with size 256) becomes saturated due to high message volume or slow processing, new messages are dropped. [4](#0-3) 

If DKG cannot complete and randomness is enabled, the chain enters reconfiguration state and **halts indefinitely**. [5](#0-4) 

The documentation explicitly states: "When randomness generation is stuck due to a bug, the chain is also stuck."

The only recovery mechanism is **manual intervention**: validators must restart with `randomness_override_seq_num` set to bypass the stalled DKG session. [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program:
- **Total loss of liveness/network availability**: The entire blockchain halts indefinitely when DKG cannot complete
- **Non-recoverable without manual intervention**: Unlike normal consensus delays, this requires coordinated action by all validators to modify configurations and restart nodes
- **No automatic failsafe**: The system has no timeout, circuit breaker, or automatic fallback to disable randomness

The impact affects all network participants - validators cannot produce blocks, users cannot submit transactions, and the network is completely frozen until manual recovery.

## Likelihood Explanation

**Moderate to High Likelihood**:
- Channel size of 256 messages is relatively small for network operations during epoch boundaries
- All validators simultaneously participate in DKG, creating message bursts
- Network congestion, slow processing, or resource constraints can cause channel saturation
- Once saturation occurs, the retry loop exacerbates the problem rather than resolving it
- No automatic detection or mitigation exists

The scenario does not require malicious action - it can occur naturally under:
- High network load during epoch transitions
- Validator node performance issues
- Network connectivity problems
- Resource exhaustion on validator nodes

## Recommendation

Implement multiple defense layers:

1. **Add Global Timeout to ReliableBroadcast**:
```rust
// In ReliableBroadcast::multicast()
let timeout_duration = Duration::from_secs(300); // 5 minute timeout
let start_time = time_service.now();

loop {
    if time_service.now().duration_since(start_time) > timeout_duration {
        return Err(anyhow!("ReliableBroadcast timed out after {:?}", timeout_duration));
    }
    // ... existing loop logic
}
```

2. **Implement Automatic DKG Fallback**:
```rust
// In DKGManager, handle broadcast timeout
match rb.broadcast(req, agg_state).await {
    Ok(agg_trx) => { /* normal path */ },
    Err(e) => {
        warn!("DKG broadcast failed: {}, entering fallback mode", e);
        // Automatically disable randomness for this epoch
        // Continue chain operation without randomness
        return Ok(());
    }
}
```

3. **Increase Default Channel Size**:
```rust
// In dkg_config.rs
impl Default for DKGConfig {
    fn default() -> Self {
        Self {
            max_network_channel_size: 2048, // Increase from 256
        }
    }
}
```

4. **Add Circuit Breaker Pattern**:
Implement detection when DKG is taking too long and automatically trigger fallback before complete halt.

## Proof of Concept

The existing test demonstrates chain halt, but via manual sync_only mode. A complete PoC would require:

```rust
// Conceptual PoC - simulate channel saturation during DKG
#[tokio::test]
async fn test_dkg_channel_saturation_causes_halt() {
    // 1. Start swarm with randomness enabled
    // 2. Reduce max_network_channel_size to very small value (e.g., 10)
    // 3. Trigger epoch transition to start DKG
    // 4. Flood DKG network channel with messages
    // 5. Observe that DKG cannot complete due to dropped messages
    // 6. Verify chain halts and liveness check fails
    // 7. Verify ReliableBroadcast is stuck in infinite retry loop
}
```

The critical code path is: DKG start → ReliableBroadcast → channel saturation → message drops → infinite retry → chain halt → manual recovery required.

## Notes

This issue represents a fundamental design limitation where the randomness feature lacks resilience against network-level failures. While the Aptos team has documented a manual recovery procedure, the absence of automatic fallback mechanisms makes this a critical availability vulnerability that violates blockchain liveness guarantees.

### Citations

**File:** config/src/config/dkg_config.rs (L9-15)
```rust
    pub max_network_channel_size: usize,
}

impl Default for DKGConfig {
    fn default() -> Self {
        Self {
            max_network_channel_size: 256,
```

**File:** dkg/src/agg_trx_producer.rs (L63-74)
```rust
        let task = async move {
            let agg_trx = rb
                .broadcast(req, agg_state)
                .await
                .expect("broadcast cannot fail");
            info!(
                epoch = epoch,
                my_addr = my_addr,
                "[DKG] aggregated transcript locally"
            );
            if let Err(e) = agg_trx_tx
                .expect("[DKG] agg_trx_tx should be available")
```

**File:** crates/reliable-broadcast/src/lib.rs (L167-206)
```rust
            loop {
                tokio::select! {
                    Some((receiver, result)) = rpc_futures.next() => {
                        let aggregating = aggregating.clone();
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
                        aggregate_futures.push(future);
                    },
                    Some(result) = aggregate_futures.next() => {
                        let (receiver, result) = result.expect("spawned task must succeed");
                        match result {
                            Ok(may_be_aggragated) => {
                                if let Some(aggregated) = may_be_aggragated {
                                    return Ok(aggregated);
                                }
                            },
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
                        }
                    },
                    else => unreachable!("Should aggregate with all responses")
                }
            }
        }
```

**File:** aptos-node/src/network.rs (L82-88)
```rust
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(node_config.dkg.max_network_channel_size)
            .queue_style(QueueStyle::FIFO),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config_seqnum.move (L1-9)
```text
/// Randomness stall recovery utils.
///
/// When randomness generation is stuck due to a bug, the chain is also stuck. Below is the recovery procedure.
/// 1. Ensure more than 2/3 stakes are stuck at the same version.
/// 1. Every validator restarts with `randomness_override_seq_num` set to `X+1` in the node config file,
///    where `X` is the current `RandomnessConfigSeqNum` on chain.
/// 1. The chain should then be unblocked.
/// 1. Once the bug is fixed and the binary + framework have been patched,
///    a governance proposal is needed to set `RandomnessConfigSeqNum` to be `X+2`.
```

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L64-84)
```rust
    info!("Hot-fixing all validators.");
    for (idx, validator) in swarm.validators_mut().enumerate() {
        info!("Stopping validator {}.", idx);
        validator.stop();
        let config_path = validator.config_path();
        let mut validator_override_config =
            OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        validator_override_config
            .override_config_mut()
            .randomness_override_seq_num = 1;
        validator_override_config
            .override_config_mut()
            .consensus
            .sync_only = false;
        info!("Updating validator {} config.", idx);
        validator_override_config.save_config(config_path).unwrap();
        info!("Restarting validator {}.", idx);
        validator.start().unwrap();
        info!("Let validator {} bake for 5 secs.", idx);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
```
