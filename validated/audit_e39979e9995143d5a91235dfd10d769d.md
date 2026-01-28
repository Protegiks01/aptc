# Audit Report

## Title
Unbounded Exponential Backoff in JWK Consensus Causes Resource Exhaustion and Prolonged InProgress States

## Summary
The JWK consensus mechanism lacks a maximum delay cap on its exponential backoff retry policy, causing retry intervals to grow unboundedly (potentially reaching hours or days). This creates a resource exhaustion vulnerability where consensus states remain stuck in `InProgress` for extended periods when view divergence occurs during OIDC provider key rotations.

## Finding Description

The JWK consensus initialization creates a `ReliableBroadcast` instance with an uncapped exponential backoff policy starting at 5ms with no maximum delay configured: [1](#0-0) 

This differs significantly from other consensus components that properly configure bounded backoff. The DAG consensus component configures a maximum delay of 3000ms (3 seconds): [2](#0-1) 

Similarly, the DKG component properly bounds its exponential backoff with configurable max_delay: [3](#0-2) 

The default configuration for ReliableBroadcast in other components sets max_delay to 3000ms: [4](#0-3) 

When `update_certifier.start_produce()` initiates consensus, it spawns an async task that calls `rb.broadcast()`: [5](#0-4) 

The reliable broadcast retry mechanism handles aggregation failures by exponentially backing off without any upper bound. When a peer response causes an aggregation error, the system retrieves the next backoff duration and schedules a retry: [6](#0-5) 

The observation aggregation strictly enforces view consistency, rejecting any responses where the peer's view doesn't match the local view: [7](#0-6) 

When consensus is initiated, the state transitions to `InProgress` holding the proposal and abort handle: [8](#0-7) [9](#0-8) 

**Attack Scenario:**

During an OIDC provider key rotation:
1. Validator V1 observes JWK set A (pre-rotation) and starts consensus
2. Validators V2, V3 observe JWK set B (post-rotation) and start their own consensus  
3. When V2, V3 respond to V1's request, they send observations for set B
4. V1's aggregation rejects these responses due to view mismatch (set B ≠ set A)
5. The reliable broadcast retries with exponential backoff: 5ms, 10ms, 20ms, 40ms...
6. After 30 iterations, the delay reaches ~5.37 million seconds (approximately 62 days)
7. The consensus remains in `InProgress` state with the task sleeping for extreme durations

The mathematical progression: 5ms × 2^30 = 5,368,709,120ms ≈ 62 days

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria for **Validator Node Slowdowns**:

- **Resource exhaustion**: The BoundedExecutor is initialized with only 8 slots [10](#0-9) . Multiple stuck consensus tasks can occupy these slots, preventing new JWK consensus from starting efficiently.

- **Memory consumption**: Each stuck consensus task maintains the `InProgress` state holding the proposal, signature, and abort handle in memory indefinitely.

- **Protocol degradation**: The JWK consensus mechanism fails to make timely progress, preventing validators from updating on-chain JWK sets used for OIDC authentication. This affects the validator transaction pool functionality.

While AptosBFT consensus continues normally, the JWK consensus subsystem experiences significant operational degradation affecting validator node health and OIDC authentication updates.

## Likelihood Explanation

**High likelihood** of occurrence:

1. **Natural occurrence**: OIDC providers routinely rotate JWKs for security reasons, creating time windows where different validators observe different key sets
2. **No Byzantine behavior required**: The issue manifests during normal operations when validators query JWK endpoints at slightly different times
3. **No defensive mechanisms**: Unlike DAG and DKG consensus components, JWK consensus lacks bounded backoff, retry limits, or timeout mechanisms
4. **Clear deviation from pattern**: All other consensus components (DAG, DKG, commit voting) properly configure `max_delay()`, indicating this is an oversight

## Recommendation

Add `max_delay()` configuration to the JWK consensus ReliableBroadcast initialization to match the pattern used in other consensus components:

```rust
let rb = ReliableBroadcast::new(
    self.my_addr,
    epoch_state.verifier.get_ordered_account_addresses(),
    Arc::new(network_sender),
    ExponentialBackoff::from_millis(5)
        .max_delay(Duration::from_millis(3000)),  // Add max delay cap
    aptos_time_service::TimeService::real(),
    Duration::from_millis(1000),
    BoundedExecutor::new(8, tokio::runtime::Handle::current()),
);
```

Alternatively, use the `ReliableBroadcastConfig` pattern from DAG and DKG components to make the backoff policy configurable.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up multiple validator nodes monitoring the same OIDC provider
2. Triggering a JWK rotation at the provider
3. Observing that validators who query at different times enter view divergence
4. Monitoring the exponential backoff delays growing unboundedly in logs
5. Confirming consensus tasks remain in `InProgress` state for extended periods

The code evidence clearly shows the missing `max_delay()` configuration compared to other consensus components, making this a deterministic issue rather than requiring a complex PoC.

## Notes

This vulnerability represents a clear deviation from the established pattern in the Aptos codebase where all other consensus components (DAG, DKG) properly bound their exponential backoff policies. While Byzantine validators cannot prevent quorum formation when 2f+1 honest validators agree, the unbounded retry mechanism creates operational issues that naturally manifest during OIDC provider key rotations without requiring any malicious behavior.

### Citations

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L204-212)
```rust
            let rb = ReliableBroadcast::new(
                self.my_addr,
                epoch_state.verifier.get_ordered_account_addresses(),
                Arc::new(network_sender),
                ExponentialBackoff::from_millis(5),
                aptos_time_service::TimeService::real(),
                Duration::from_millis(1000),
                BoundedExecutor::new(8, tokio::runtime::Handle::current()),
            );
```

**File:** consensus/src/dag/bootstrap.rs (L570-572)
```rust
        let rb_backoff_policy = ExponentialBackoff::from_millis(rb_config.backoff_policy_base_ms)
            .factor(rb_config.backoff_policy_factor)
            .max_delay(Duration::from_millis(rb_config.backoff_policy_max_delay_ms));
```

**File:** dkg/src/epoch_manager.rs (L212-216)
```rust
                ExponentialBackoff::from_millis(self.rb_config.backoff_policy_base_ms)
                    .factor(self.rb_config.backoff_policy_factor)
                    .max_delay(Duration::from_millis(
                        self.rb_config.backoff_policy_max_delay_ms,
                    )),
```

**File:** config/src/config/dag_consensus_config.rs (L112-123)
```rust
impl Default for ReliableBroadcastConfig {
    fn default() -> Self {
        Self {
            // A backoff policy that starts at 100ms and doubles each iteration up to 3secs.
            backoff_policy_base_ms: 2,
            backoff_policy_factor: 50,
            backoff_policy_max_delay_ms: 3000,

            rpc_timeout_ms: 1000,
        }
    }
}
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-69)
```rust
        let task = async move {
            let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
            ConsensusMode::log_certify_done(epoch, &qc_update);
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-84)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L106-109)
```rust
    InProgress {
        my_proposal: T,
        abort_handle_wrapper: QuorumCertProcessGuard,
    },
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L216-223)
```rust
            state.consensus_state = ConsensusState::InProgress {
                my_proposal: ObservedUpdate {
                    author: self.my_addr,
                    observed: observed.clone(),
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard::new(abort_handle),
            };
```
