# Audit Report

## Title
JWK Consensus Denial of Service Through Provider Equivocation

## Summary
An attacker controlling or compromising a registered OIDC provider can cause validators to observe different JWK values, preventing 2f+1 consensus and blocking JWK updates for an entire epoch. The observation aggregation logic strictly rejects mismatched observations, causing infinite retry loops with no timeout or recovery mechanism.

## Finding Description

The JWK consensus protocol allows validators to agree on JSON Web Keys from OIDC providers for keyless authentication. When validators observe JWKs from a provider, they must reach 2f+1 consensus before updating the on-chain state.

The vulnerability exists in the observation aggregation logic: [1](#0-0) 

This strict equality check means validators will **only accept observations matching their own local view**. When an OIDC provider serves different JWK responses to different validators (provider equivocation), validators reject each other's observations.

The attack path:

1. **Provider Equivocation**: An attacker-controlled OIDC provider responds with different JWK sets to different validators, ensuring no group has 2f+1 with the same observation.

2. **Observation Rejection**: Each validator starts consensus with their local observation. When exchanging observations via ReliableBroadcast, the `add()` method rejects any observation that doesn't match `local_view`.

3. **Infinite Retry Loop**: The ReliableBroadcast mechanism retries failed RPCs indefinitely with exponential backoff: [2](#0-1) 

4. **Consensus Stall**: The broadcast operation never completes, causing the update certifier task to hang indefinitely: [3](#0-2) 

5. **Epoch-Long Block**: The consensus remains stuck until the epoch ends and the JWK manager is restarted: [4](#0-3) 

**Evidence from Tests**: The behavior is demonstrated in existing tests where `EquivocatingServer` with strategic split prevents consensus: [5](#0-4) [6](#0-5) 

The test confirms that when validators are split 2-2 (neither group reaching 2f+1=3), no update occurs for the equivocating provider.

## Impact Explanation

**High Severity** - This qualifies as a "Significant protocol violation" under the Aptos bug bounty criteria:

1. **Protocol Violation**: The JWK consensus protocol's purpose is to synchronize JWK updates across validators. An attacker can completely prevent this for specific issuers.

2. **Service Disruption**: Keyless accounts depending on the affected OIDC provider cannot update their keys, potentially breaking authentication if keys have rotated.

3. **Resource Exhaustion**: Infinite retry attempts waste network bandwidth and CPU cycles across all validators for the entire epoch duration.

4. **No Recovery**: Even if the provider later serves consistent values, validators remain stuck with their initial observations until epoch change.

5. **Cascading Impact**: If multiple registered providers are compromised, JWK consensus can be disrupted across multiple issuers simultaneously.

This does NOT affect core AptosBFT consensus or other blockchain operations, preventing it from reaching Critical severity.

## Likelihood Explanation

**Medium-High Likelihood**:

**Attack Requirements**:
- Attacker must control or compromise a registered OIDC provider
- Provider must be able to identify requesting validators (via request headers/IPs)
- Attacker must distribute responses strategically to prevent 2f+1 consensus

**Realistic Scenarios**:
1. **Provider Compromise**: If a legitimate OIDC provider (Google, Facebook, etc.) is compromised, the attacker can execute this attack
2. **Malicious Provider**: If governance is tricked into adding a malicious provider
3. **BGP Hijacking**: Network-level attacks could route different validators to different servers

**Probability Factors**:
- OIDC providers are high-value targets already
- The attack requires no special validator privileges
- The test infrastructure already demonstrates the mechanism
- Epochs can be long (30+ seconds in tests, potentially longer in production)

## Recommendation

Implement multiple defensive mechanisms:

**1. Equivocation Detection**: Track and log when validators receive different observations for the same issuer. Emit warnings and potentially disable the provider automatically.

**2. Timeout Mechanism**: Add a configurable timeout for the entire consensus process:

```rust
// In update_certifier.rs
pub fn start_produce(
    &self,
    epoch_state: Arc<EpochState>,
    payload: ProviderJWKs,
    qc_update_tx: aptos_channel::Sender<...>,
) -> anyhow::Result<AbortHandle> {
    // ... existing code ...
    let task = async move {
        let timeout = Duration::from_secs(120); // Configurable
        match tokio::time::timeout(timeout, rb.broadcast(req, agg_state)).await {
            Ok(Ok(qc_update)) => {
                // Success path
                let _ = qc_update_tx.push(key, qc_update);
            },
            Ok(Err(e)) => {
                error!("Broadcast failed: {}", e);
            },
            Err(_) => {
                warn!("JWK consensus timed out - possible provider equivocation");
                // Emit metric, log, or take other action
            }
        }
    };
    // ... rest of code ...
}
```

**3. Observation Flexibility**: Consider accepting observations with a threshold less than strict equality, or implement a "best-effort" mode when equivocation is detected.

**4. Provider Health Scoring**: Maintain reputation scores for providers based on equivocation history, automatically deprioritizing or removing consistently problematic providers.

**5. Maximum Retry Limit**: Cap the number of retry attempts in ReliableBroadcast to prevent indefinite resource waste.

## Proof of Concept

The vulnerability is already demonstrated in the existing test suite:

```rust
// From testsuite/smoke-test/src/jwks/jwk_consensus_per_issuer.rs
// This PoC shows how to cause consensus failure:

// 1. Set up an equivocating server that splits validators
alice_jwks_server.update_request_handler(Some(Arc::new(EquivocatingServer::new(
    r#"{"keys": ["ALICE_JWK_V1A"]}"#.as_bytes().to_vec(),  // 2 validators see this
    r#"{"keys": ["ALICE_JWK_V1B"]}"#.as_bytes().to_vec(),  // 2 validators see this
    2,  // Split point: first 2 get V1A, rest get V1B
))));

// 2. With 4 validators (f=1, 2f+1=3), neither group reaches quorum
// 3. Wait for consensus attempt
sleep(Duration::from_secs(60)).await;

// 4. Verify no update occurred for the equivocating provider
// (Test confirms Alice's JWKs are NOT updated)
```

**Attack Reproduction Steps**:
1. Deploy a malicious OIDC provider or compromise an existing one
2. Configure the provider to serve different JWK responses based on requester identity
3. Ensure the distribution prevents any group from reaching 2f+1 consensus
4. Observe that JWK updates fail for the entire epoch
5. Monitor increased network traffic from continuous retry attempts
6. Confirm keyless authentication issues for affected users

**Notes**

The vulnerability represents a fundamental tension between **safety** (not accepting incorrect data) and **liveness** (making progress despite failures). The current implementation prioritizes safety absolutely, with no fallback mechanism when consensus cannot be reached.

While per-key consensus mode (enabled via `FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE`) provides some resilience by allowing individual keys to reach consensus independently, it still suffers from the same fundamental issue for each key individually. [7](#0-6) 

The attack does not compromise safety (no incorrect JWKs are ever accepted) but significantly impacts availability and wastes resources, making it a valid High severity denial-of-service vulnerability in the JWK consensus subsystem.

### Citations

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L82-84)
```rust
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** crates/reliable-broadcast/src/lib.rs (L167-205)
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
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-69)
```rust
        let task = async move {
            let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
            ConsensusMode::log_certify_done(epoch, &qc_update);
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L228-246)
```rust
                if features.is_enabled(FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE) {
                    Box::new(KeyLevelConsensusManager::new(
                        Arc::new(my_sk),
                        self.my_addr,
                        epoch_state.clone(),
                        rb,
                        self.vtxn_pool.clone(),
                    ))
                } else {
                    //TODO: move this into IssuerLevelConsensusManager construction?
                    let update_certifier = UpdateCertifier::new(rb);
                    Box::new(IssuerLevelConsensusManager::new(
                        Arc::new(my_sk),
                        self.my_addr,
                        epoch_state.clone(),
                        Arc::new(update_certifier),
                        self.vtxn_pool.clone(),
                    ))
                };
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L259-264)
```rust
    async fn on_new_epoch(&mut self, reconfig_notification: ReconfigNotification<P>) -> Result<()> {
        self.shutdown_current_processor().await;
        self.start_new_epoch(reconfig_notification.on_chain_configs)
            .await?;
        Ok(())
    }
```

**File:** testsuite/smoke-test/src/jwks/jwk_consensus_per_issuer.rs (L86-90)
```rust
    alice_jwks_server.update_request_handler(Some(Arc::new(EquivocatingServer::new(
        r#"{"keys": ["ALICE_JWK_V1A"]}"#.as_bytes().to_vec(),
        r#"{"keys": ["ALICE_JWK_V1B"]}"#.as_bytes().to_vec(),
        2,
    ))));
```

**File:** testsuite/smoke-test/src/jwks/jwk_consensus_per_issuer.rs (L110-113)
```rust
    info!("Wait for 60 secs and there should only update for Bob, not Alice.");
    sleep(Duration::from_secs(60)).await;
    let patched_jwks = get_patched_jwks(&client).await;
    debug!("patched_jwks={:?}", patched_jwks);
```
