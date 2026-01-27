# Audit Report

## Title
Unbounded Exponential Backoff in JWK Consensus ReliableBroadcast Enables Resource Exhaustion via Byzantine Validator Manipulation

## Summary
The JWK consensus `UpdateCertifier` configures `ReliableBroadcast` with `ExponentialBackoff::from_millis(5)` without specifying `factor` or `max_delay` parameters. This allows Byzantine validators to force unbounded retry delays by sending invalid responses, causing resource exhaustion and significantly delaying JWK consensus completion compared to properly configured consensus components.

## Finding Description

The JWK consensus system uses `ReliableBroadcast` to distribute JWK observations across validators and aggregate responses into quorum-certified updates. The exponential backoff configuration in `epoch_manager.rs` is critically misconfigured: [1](#0-0) 

This contrasts sharply with other consensus components that properly configure bounded backoff:

DAG Consensus configuration: [2](#0-1) 

With default configuration values: [3](#0-2) 

DKG configuration: [4](#0-3) 

The retry mechanism in `ReliableBroadcast` triggers when aggregation fails: [5](#0-4) 

Byzantine validators can force aggregation failures by sending responses that fail validation in `ObservationAggregationState::add()`: [6](#0-5) 

**Attack Flow:**
1. Honest validator broadcasts JWK observation request to all n validators
2. Byzantine validators (up to f < n/3) immediately respond with:
   - Mismatched `ProviderJWKs` (different from requester's view)
   - Invalid BLS signatures
   - Mismatched author fields
3. Each invalid response fails the checks in `ObservationAggregationState::add()`, returning an error
4. `ReliableBroadcast` triggers retries with exponentially growing delays: 5ms → 10ms (default factor=2) → 20ms → 40ms → 80ms → 160ms → 320ms → 640ms → 1.28s → 2.56s → 5.12s → 10.24s → 20.48s → 40.96s → 81.92s → 163.84s (~2.7 min) → 327.68s (~5.5 min) → ...
5. Without `max_delay`, delays can grow to hours or days
6. Each retry sends the full `JWKConsensusMsg` (including `ProviderJWKs`, signatures, epoch metadata)
7. Retries consume network bandwidth, CPU for serialization, executor threads, and network buffers
8. If multiple concurrent JWK updates occur, resource consumption multiplies

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program:

1. **Validator Node Slowdowns** (High severity criteria): While the exponential backoff prevents continuous flooding, the misconfiguration allows Byzantine validators to trigger significantly more retries than necessary. With proper `max_delay` configuration (3000ms for DAG, 5000ms for buffer_manager), retries would be capped, but JWK consensus allows unbounded growth.

2. **Resource Exhaustion**: Each retry consumes:
   - Network bandwidth for message serialization and transmission
   - CPU cycles for BLS signature operations during serialization
   - Bounded executor thread slots
   - Network buffer space

3. **Delayed Critical Updates**: JWK (JSON Web Key) updates are critical for OIDC authentication. Significant delays in JWK consensus can impact zkLogin functionality and require manual intervention.

4. **Amplification Factor**: With 33 Byzantine validators in a 100-validator network, if honest validators take 5 minutes to respond (due to network congestion or load), approximately 17 retries occur per Byzantine validator, sending 561 additional messages. At 10KB per message, this is ~5.6MB of unnecessary traffic per broadcast instance.

The impact is less severe than bandwidth exhaustion (which exponential backoff prevents) but constitutes a resource consumption vulnerability exploitable by Byzantine validators.

## Likelihood Explanation

**Likelihood: High**

1. **No Special Requirements**: Byzantine validators only need to send invalid responses—a trivial operation requiring no sophisticated attack infrastructure.

2. **Expected Threat Model**: BFT consensus assumes up to f < n/3 Byzantine validators. This attack works within that assumption.

3. **Persistent Opportunity**: Every JWK consensus round is vulnerable. With periodic JWK observations, the attack can be repeated indefinitely.

4. **No Detection Mechanism**: The system treats retry exhaustion as normal operation. Byzantine behavior is indistinguishable from network issues.

5. **Real-World Conditions**: Network delays causing slow honest validator responses are common, amplifying the vulnerability's impact.

## Recommendation

Apply the same backoff configuration pattern used by DAG consensus and other components:

```rust
// In crates/aptos-jwk-consensus/src/epoch_manager.rs, line 208
let rb = ReliableBroadcast::new(
    self.my_addr,
    epoch_state.verifier.get_ordered_account_addresses(),
    Arc::new(network_sender),
    ExponentialBackoff::from_millis(5)
        .factor(50)  // Add exponential factor
        .max_delay(Duration::from_millis(3000)),  // Cap maximum delay at 3 seconds
    aptos_time_service::TimeService::real(),
    Duration::from_millis(1000),
    BoundedExecutor::new(8, tokio::runtime::Handle::current()),
);
```

This configuration:
- Starts with 5ms base delay (250ms after first retry with factor=50)
- Grows exponentially with factor=50
- Caps maximum delay at 3000ms, preventing unbounded growth
- Matches the battle-tested configuration from DAG consensus

Alternative: Create a shared `ReliableBroadcastConfig` structure to ensure consistent configuration across all consensus components.

## Proof of Concept

```rust
#[cfg(test)]
mod jwk_retry_exhaustion_test {
    use super::*;
    use aptos_types::validator_verifier::ValidatorVerifier;
    use tokio_retry::strategy::ExponentialBackoff;
    
    #[tokio::test]
    async fn test_unbounded_retry_delays() {
        // Simulate JWK consensus backoff configuration
        let mut jwk_backoff = ExponentialBackoff::from_millis(5);
        
        // Simulate retries to Byzantine validator
        let mut delays = Vec::new();
        for _ in 0..20 {
            if let Some(delay) = jwk_backoff.next() {
                delays.push(delay);
            }
        }
        
        // Verify delays grow unboundedly
        assert!(delays[10] > Duration::from_secs(5), 
                "After 10 retries: {:?}", delays[10]);
        assert!(delays[15] > Duration::from_secs(160), 
                "After 15 retries: {:?}", delays[15]);
        assert!(delays[19] > Duration::from_secs(2600), 
                "After 19 retries: {:?}", delays[19]);
        
        // Compare with properly configured DAG consensus backoff
        let mut dag_backoff = ExponentialBackoff::from_millis(2)
            .factor(50)
            .max_delay(Duration::from_millis(3000));
        
        let mut dag_delays = Vec::new();
        for _ in 0..20 {
            if let Some(delay) = dag_backoff.next() {
                dag_delays.push(delay);
            }
        }
        
        // DAG backoff is bounded at 3 seconds
        assert!(dag_delays[10] <= Duration::from_secs(3), 
                "DAG delay capped: {:?}", dag_delays[10]);
        assert_eq!(dag_delays[19], Duration::from_millis(3000), 
                   "DAG delay remains capped");
        
        // Demonstrate resource amplification
        let byzantine_validators = 33;
        let jwk_total_delay: Duration = delays.iter().sum();
        let dag_total_delay: Duration = dag_delays.iter().sum();
        
        println!("JWK total retry time (33 Byzantine validators): {:?}", 
                 jwk_total_delay * byzantine_validators as u32);
        println!("DAG total retry time (33 Byzantine validators): {:?}", 
                 dag_total_delay * byzantine_validators as u32);
        
        assert!(jwk_total_delay > dag_total_delay * 100, 
                "JWK allows >100x more retry time than DAG");
    }
}
```

**Notes**

The vulnerability is a **configuration flaw** rather than a logic error. The `ReliableBroadcast` implementation itself is correct, but JWK consensus fails to properly configure its retry parameters. This is evidenced by comparing against DAG consensus [2](#0-1) , buffer manager [7](#0-6) , and DKG [4](#0-3) , all of which properly specify `factor()` and `max_delay()`.

The attack does not cause true "bandwidth exhaustion" (as exponential backoff reduces request rate over time), but it does enable **unbounded retry delays** and **unnecessary resource consumption** that other consensus components explicitly prevent through proper configuration.

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

**File:** dkg/src/epoch_manager.rs (L212-216)
```rust
                ExponentialBackoff::from_millis(self.rb_config.backoff_policy_base_ms)
                    .factor(self.rb_config.backoff_policy_factor)
                    .max_delay(Duration::from_millis(
                        self.rb_config.backoff_policy_max_delay_ms,
                    )),
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

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-89)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );

        // Verify peer signature.
        self.epoch_state
            .verifier
            .verify(sender, &peer_view, &signature)?;
```

**File:** consensus/src/pipeline/buffer_manager.rs (L208-210)
```rust
        let rb_backoff_policy = ExponentialBackoff::from_millis(2)
            .factor(50)
            .max_delay(Duration::from_secs(5));
```
