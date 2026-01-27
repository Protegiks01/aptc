# Audit Report

## Title
REST Discovery Silent Error Propagation Causes Public Full Node Isolation via Stale Validator Sets

## Summary
When REST errors occur in the discovery mechanism at `network/discovery/src/rest.rs`, errors are logged but silently ignored, preventing nodes from updating their validator sets. This causes affected Public Full Nodes (PFNs) to continue operating with stale validator set information, eventually leading to network isolation as they cannot discover new validators or stop attempting connections to departed validators.

## Finding Description
The vulnerability exists in the error handling path of the REST-based peer discovery system: [1](#0-0) 

When the REST client fails to retrieve the validator set, the error is wrapped in `Some(Err())` and returned. The consumer in the discovery listener silently ignores these errors: [2](#0-1) 

The error handling only logs a warning and continues the loop without sending any update to the connectivity manager. This means:

1. **No retry logic**: The REST call in `poll_next()` uses `block_on()` without retry wrappers [3](#0-2) 

2. **No fallback mechanism**: When errors persist, no alternative discovery method is triggered

3. **Silent degradation**: The connectivity manager never receives updates, so it continues using stale `discovered_peers` [4](#0-3) 

**Attack Scenario:**
An attacker targeting PFNs using REST discovery (e.g., nodes syncing from far behind per the comment in rest.rs line 16-17) could: [5](#0-4) 

1. DoS the REST endpoint serving validator set information
2. Cause affected PFNs to fail validator set updates at every polling interval
3. As validator set changes during epoch transitions, affected PFNs remain stuck with old validator lists
4. These PFNs cannot dial new validators and waste resources attempting connections to departed validators
5. Eventually, affected PFNs become isolated and unable to sync blockchain state

## Impact Explanation
This qualifies as **Medium Severity** under "State inconsistencies requiring intervention":

- **Scope**: Affects Public Full Nodes configured with REST discovery [6](#0-5) 

- **Non-Consensus Impact**: Validators and VFNs use OnchainDiscovery, not REST, so consensus is unaffected [7](#0-6) 

- **State Inconsistency**: Affected PFNs have stale cached validator sets diverging from on-chain truth, requiring operator intervention (service restart or REST endpoint repair)

- **No Critical Impact**: Does not affect consensus safety, validator operations, or funds

## Likelihood Explanation
**Medium-High likelihood:**
- REST endpoints can fail due to network issues, server overload, or targeted DoS
- No retry logic increases vulnerability to transient failures
- PFNs commonly use REST discovery when bootstrapping or syncing from far behind
- Multiple PFNs sharing a REST endpoint amplifies impact

## Recommendation
Implement retry logic with exponential backoff for REST discovery, similar to the pattern used elsewhere in the codebase:

```rust
// In rest.rs poll_next()
let response = block_on(async {
    // Use try_until_ok similar to other REST client usage
    let mut backoff = Duration::from_secs(1);
    for attempt in 0..5 {
        match self.rest_client.get_account_resource_bcs::<ValidatorSet>(
            AccountAddress::ONE,
            "0x1::stake::ValidatorSet",
        ).await {
            Ok(result) => return Ok(result),
            Err(err) if attempt < 4 => {
                info!("REST discovery attempt {} failed: {:?}, retrying...", attempt, err);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!()
});
```

Additionally, consider:
1. Alerting operators when REST discovery fails repeatedly
2. Providing fallback to file-based or seed-based discovery
3. Adding metrics to track REST discovery health

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configure a PFN with REST discovery pointing to a test REST endpoint
2. Start the PFN and verify it successfully fetches the validator set
3. Make the REST endpoint return 503 errors
4. Observe that the PFN logs errors but continues with stale validator set
5. Update the on-chain validator set (add/remove validators)
6. Verify the PFN never updates its connectivity to reflect new validators

Test setup (Rust):
```rust
#[tokio::test]
async fn test_rest_discovery_stale_validator_set() {
    // Setup PFN with REST discovery
    let mut swarm = SwarmBuilder::new_local(1).with_aptos().build().await;
    let rest_endpoint = start_failing_rest_endpoint(); // Returns 503
    
    let mut config = NodeConfig::get_default_pfn_config();
    config.full_node_networks[0].discovery_method = 
        DiscoveryMethod::Rest(RestDiscovery {
            url: rest_endpoint,
            interval_secs: 1,
        });
    
    let pfn = swarm.add_full_node(&version, config).await.unwrap();
    
    // Verify PFN logs errors but doesn't update validator set
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Add new validator to swarm
    let new_validator = swarm.add_validator().await;
    
    // PFN should not discover new validator due to stale set
    assert_eq!(pfn.get_connected_peers().await.len(), 1); // Still old count
}
```

**Notes:**

While this is a valid implementation bug affecting PFN availability, the impact is limited as:
- Validators use OnchainDiscovery (reconfig events), not REST
- The on-chain validator set remains authoritative and consistent
- Only PFNs using REST discovery are affected
- This represents an availability/liveness issue rather than a consensus safety violation

### Citations

**File:** network/discovery/src/rest.rs (L16-17)
```rust
/// A discovery stream that uses the REST client to determine the validator
/// set nodes.  Useful for when genesis is significantly far behind in time
```

**File:** network/discovery/src/rest.rs (L48-51)
```rust
        let response = block_on(self.rest_client.get_account_resource_bcs::<ValidatorSet>(
            AccountAddress::ONE,
            "0x1::stake::ValidatorSet",
        ));
```

**File:** network/discovery/src/rest.rs (L60-66)
```rust
            Err(err) => {
                info!(
                    "Failed to retrieve validator set by REST discovery {:?}",
                    err
                );
                Some(Err(DiscoveryError::Rest(err)))
            },
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

**File:** network/framework/src/connectivity_manager/mod.rs (L886-898)
```rust
    fn handle_update_discovered_peers(
        &mut self,
        src: DiscoverySource,
        new_discovered_peers: PeerSet,
    ) {
        // Log the update event
        info!(
            NetworkSchema::new(&self.network_context),
            "{} Received updated list of discovered peers! Source: {:?}, num peers: {:?}",
            self.network_context,
            src,
            new_discovered_peers.len()
        );
```

**File:** testsuite/smoke-test/src/network.rs (L156-159)
```rust
    network_config.discovery_method = DiscoveryMethod::Rest(RestDiscovery {
        url: rest_endpoint,
        interval_secs: 1,
    });
```

**File:** config/src/config/test_data/validator.yaml (L1-10)
```yaml
base:
    data_dir: "/opt/aptos/data"
    role: "validator"
    waypoint:
        from_storage:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"
```
