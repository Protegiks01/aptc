# Audit Report

## Title
Stale Validator Set Causes Network Partition When REST Discovery Fails

## Summary
Nodes configured with REST-based discovery (`RestStream`) continue operating with increasingly stale validator sets when REST requests consistently fail. When an epoch change occurs and the validator set rotates, affected nodes cannot discover new validators' network addresses, leading to consensus participation failure and potential network partition.

## Finding Description

The Aptos network discovery system supports multiple discovery methods, including REST-based discovery that polls an external REST endpoint to retrieve the current validator set. The vulnerability exists in how REST discovery handles persistent failures. [1](#0-0) 

When REST requests fail, the `poll_next()` function returns an error wrapped in `DiscoveryError::Rest`. This error is caught by the `DiscoveryChangeListener::run()` loop: [2](#0-1) 

The critical flaw is that **when an error occurs, only a warning is logged, but no update is sent to the connectivity manager**. The node continues operating with whatever validator set information was last successfully retrieved. The loop continues indefinitely, retrying at the configured interval, but never updating the node's view of the validator set. [3](#0-2) 

The connectivity manager's `close_stale_connections()` function relies on the trusted peers set being current. When REST discovery fails to provide updates, the trusted peers become stale, and the node continues attempting to connect to outdated validators while being unable to discover new validators.

**Attack Scenario:**

1. A node is configured with REST discovery method in its network configuration [4](#0-3) 

2. REST endpoint becomes unavailable (network partition, DoS attack, infrastructure failure)
3. REST requests consistently timeout or fail
4. Node logs errors but continues with last known validator set
5. On-chain epoch change occurs - validator set rotates (validators join/leave)
6. Nodes using on-chain discovery (`ValidatorSetStream`) receive automatic updates via reconfig notifications [5](#0-4) 

7. Nodes using REST discovery with failing REST do NOT receive updates
8. Affected nodes:
   - Attempt to connect to old validators who may have left the set
   - Cannot discover network addresses for new validators
   - Cannot participate in consensus
   - Form isolated partition if multiple nodes are affected

This breaks the critical invariant that **all active nodes must be able to discover and connect to the current validator set for consensus participation**.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Affected nodes cannot participate in consensus, effectively slowing or halting their validator operations
- **Significant protocol violations**: Nodes operating with stale validator sets violate the protocol requirement that all validators must be aware of the current validator set

The impact is particularly severe when:
- Multiple nodes are configured with the same REST endpoint (single point of failure)
- The REST endpoint experiences extended downtime during an epoch transition
- A significant portion of validators rotate out during the epoch change

While this may not cause total network unavailability (nodes using on-chain discovery continue functioning), it can cause:
- **Consensus liveness degradation**: Fewer nodes able to participate
- **Partial network partition**: REST-configured nodes separated from the active consensus set
- **Validator rewards loss**: Affected validators miss consensus participation
- **Network security reduction**: Effective reduction in active validator count

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurring:

1. **REST endpoint failures are common**: Network partitions, infrastructure outages, DNS issues, DDoS attacks, and maintenance windows all cause REST endpoint unavailability

2. **No timeout or circuit breaker**: The code has no mechanism to detect that the validator set has become dangerously stale. There is no timeout after which the node would refuse to operate with old data

3. **Silent degradation**: The error is only logged at `info!` level, making it easy for operators to miss that their node is operating with stale information

4. **Configuration incentives**: The RestStream is described as "Useful for when genesis is significantly far behind in time", suggesting it's used in scenarios where quick bootstrap is needed, potentially in production

5. **No fallback mechanism**: Unlike proper defense-in-depth design, there's no fallback from REST to on-chain discovery when REST fails persistently

## Recommendation

Implement multiple layers of protection:

**1. Add Staleness Detection:**
```rust
// In RestStream or DiscoveredPeerSet
const MAX_VALIDATOR_SET_AGE: Duration = Duration::from_secs(3600); // 1 hour

struct RestStream {
    // ... existing fields ...
    last_successful_update: Arc<Mutex<Option<Instant>>>,
}

// In poll_next()
match response {
    Ok(inner) => {
        *self.last_successful_update.lock() = Some(Instant::now());
        // ... existing success handling ...
    },
    Err(err) => {
        // Check if validator set is too stale
        if let Some(last_update) = *self.last_successful_update.lock() {
            if last_update.elapsed() > MAX_VALIDATOR_SET_AGE {
                error!("Validator set is dangerously stale! Last update: {:?} ago", 
                       last_update.elapsed());
                // Could panic or trigger node shutdown for safety
            }
        }
        // ... existing error handling ...
    }
}
```

**2. Implement Circuit Breaker Pattern:**
```rust
// Track consecutive failures and stop operating if threshold exceeded
struct RestStream {
    // ... existing fields ...
    consecutive_failures: Arc<Mutex<u32>>,
}

const MAX_CONSECUTIVE_FAILURES: u32 = 10;

// In poll_next() error handling
*self.consecutive_failures.lock() += 1;
if *self.consecutive_failures.lock() > MAX_CONSECUTIVE_FAILURES {
    panic!("REST discovery has failed {} consecutive times. Node safety compromised.", 
           MAX_CONSECUTIVE_FAILURES);
}
```

**3. Add Fallback to On-Chain Discovery:**
```rust
// In DiscoveryChangeListener, support multiple discovery sources with priority
// If REST fails for extended period, automatically fall back to on-chain discovery
```

**4. Emit Metrics and Alerts:**
```rust
// Add counters for REST failures and staleness
counters::REST_DISCOVERY_FAILURES.inc();
counters::VALIDATOR_SET_AGE_SECONDS.set(age_seconds);
```

**5. Configuration Validation:**
Discourage or prevent REST-only discovery for validator nodes. Recommend REST as supplement to on-chain discovery, not replacement.

## Proof of Concept

```rust
// Reproduction steps:

// 1. Configure a validator node with REST discovery
// In node config:
// network:
//   discovery_method:
//     rest:
//       url: "http://rest-endpoint.example.com"
//       interval_secs: 60

// 2. Start the node and let it successfully fetch validator set once

// 3. Block access to REST endpoint (firewall, DNS poisoning, or server shutdown):
// iptables -A OUTPUT -d rest-endpoint.example.com -j DROP

// 4. Monitor logs - will see repeating errors:
// "Failed to retrieve validator set by REST discovery"

// 5. Trigger an epoch change on-chain (via governance or natural epoch boundary)
// This causes validator set rotation

// 6. Observe that the affected node:
//    - Continues attempting to dial old validators
//    - Cannot discover new validators
//    - Fails to participate in consensus
//    - Logs "Failed to dial peer" for new validators
//    - Never receives consensus messages from new validator set

// 7. Verify using metrics:
// curl http://localhost:9101/metrics | grep discovery
// Should show stale validator set and failed dial attempts

// Expected result: Node is partitioned from consensus and cannot recover
// without manual intervention (restart or REST endpoint restoration)
```

**Minimal test case:**
```rust
#[tokio::test]
async fn test_rest_discovery_staleness() {
    // Setup mock REST server that returns validator set once then fails
    let mut rest_server = MockRestServer::new();
    rest_server.respond_once_then_fail();
    
    // Create RestStream with the mock server
    let rest_stream = RestStream::new(
        network_context,
        rest_server.url(),
        Duration::from_secs(1),
        time_service,
    );
    
    // First poll succeeds
    let result1 = rest_stream.next().await;
    assert!(result1.is_some());
    assert!(result1.unwrap().is_ok());
    
    // Subsequent polls fail, but stream continues
    for _ in 0..100 {
        let result = rest_stream.next().await;
        assert!(result.is_some());
        assert!(result.unwrap().is_err()); // Returns error but keeps going
    }
    
    // Node is now operating with validator set from first poll
    // If epoch changed during those 100 failed attempts, 
    // node has dangerously stale validator set
}
```

## Notes

This vulnerability affects nodes specifically configured with `DiscoveryMethod::Rest`. Nodes using `DiscoveryMethod::Onchain` (which uses `ValidatorSetStream`) are not affected as they receive automatic updates via reconfig notifications from the blockchain state.

The severity is mitigated somewhat by the fact that:
- Not all nodes may be configured with REST discovery
- Nodes can potentially recover by restarting or when REST endpoint becomes available again
- The validator set typically doesn't change drastically in a single epoch

However, the lack of any safety mechanism (timeout, staleness detection, circuit breaker) makes this a clear protocol violation that can lead to consensus participation failures and partial network partitions.

### Citations

**File:** network/discovery/src/rest.rs (L42-68)
```rust
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Wait for delay, or add the delay for next call
        futures::ready!(self.interval.as_mut().poll_next(cx));

        // Retrieve the onchain resource at the interval
        // TODO there should be a better way than converting this to a blocking call
        let response = block_on(self.rest_client.get_account_resource_bcs::<ValidatorSet>(
            AccountAddress::ONE,
            "0x1::stake::ValidatorSet",
        ));
        Poll::Ready(match response {
            Ok(inner) => {
                let validator_set = inner.into_inner();
                Some(Ok(extract_validator_set_updates(
                    self.network_context,
                    validator_set,
                )))
            },
            Err(err) => {
                info!(
                    "Failed to retrieve validator set by REST discovery {:?}",
                    err
                );
                Some(Err(DiscoveryError::Rest(err)))
            },
        })
    }
```

**File:** network/discovery/src/lib.rs (L141-165)
```rust
        while let Some(update) = source_stream.next().await {
            if let Ok(update) = update {
                trace!(
                    NetworkSchema::new(&network_context),
                    "{} Sending update: {:?}",
                    network_context,
                    update
                );
                let request = ConnectivityRequest::UpdateDiscoveredPeers(discovery_source, update);
                if let Err(error) = update_channel.try_send(request) {
                    inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "send_failure", 1);
                    warn!(
                        NetworkSchema::new(&network_context),
                        "{} Failed to send update {:?}", network_context, error
                    );
                }
            } else {
                warn!(
                    NetworkSchema::new(&network_context),
                    "{} {} Discovery update failed {:?}",
                    &network_context,
                    discovery_source,
                    update
                );
            }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L484-531)
```rust
    async fn close_stale_connections(&mut self) {
        if let Some(trusted_peers) = self.get_trusted_peers() {
            // Identify stale peer connections
            let stale_peers = self
                .connected
                .iter()
                .filter(|(peer_id, _)| !trusted_peers.contains_key(peer_id))
                .filter_map(|(peer_id, metadata)| {
                    // If we're using server only auth, we need to not evict unknown peers
                    // TODO: We should prevent `Unknown` from discovery sources
                    if !self.mutual_authentication
                        && metadata.origin == ConnectionOrigin::Inbound
                        && (metadata.role == PeerRole::ValidatorFullNode
                            || metadata.role == PeerRole::Unknown)
                    {
                        None
                    } else {
                        Some(*peer_id) // The peer is stale
                    }
                });

            // Close existing connections to stale peers
            for stale_peer in stale_peers {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&stale_peer),
                    "{} Closing stale connection to peer {}",
                    self.network_context,
                    stale_peer.short_str()
                );

                if let Err(disconnect_error) = self
                    .connection_reqs_tx
                    .disconnect_peer(stale_peer, DisconnectReason::StaleConnection)
                    .await
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .remote_peer(&stale_peer),
                        error = %disconnect_error,
                        "{} Failed to close stale connection to peer {}, error: {}",
                        self.network_context,
                        stale_peer.short_str(),
                        disconnect_error
                    );
                }
            }
        }
    }
```

**File:** config/src/config/network_config.rs (L345-364)
```rust
pub enum DiscoveryMethod {
    Onchain,
    File(FileDiscovery),
    Rest(RestDiscovery),
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FileDiscovery {
    pub path: PathBuf,
    pub interval_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RestDiscovery {
    pub url: url::Url,
    pub interval_secs: u64,
}
```

**File:** network/discovery/src/validator_set.rs (L94-105)
```rust
impl<P: OnChainConfigProvider> Stream for ValidatorSetStream<P> {
    type Item = Result<PeerSet, DiscoveryError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.reconfig_events)
            .poll_next(cx)
            .map(|maybe_notification| {
                maybe_notification
                    .map(|notification| Ok(self.extract_updates(notification.on_chain_configs)))
            })
    }
}
```
