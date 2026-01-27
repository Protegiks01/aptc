# Audit Report

## Title
DNS Poisoning Attack via Unauthenticated REST Discovery Enables Network Partition

## Summary
The REST-based validator discovery mechanism in `network/discovery/src/rest.rs` fetches validator set information from an HTTP endpoint without cryptographic validation of state proofs or signatures. This allows DNS poisoning attacks to redirect nodes to malicious servers that serve fake validator sets, causing affected nodes to connect exclusively to attacker-controlled peers and creating network partition.

## Finding Description

The `RestStream::poll_next()` function retrieves the validator set from a REST API endpoint without any cryptographic verification: [1](#0-0) 

The REST client fetches on-chain resources using only HTTP without state proof validation: [2](#0-1) 

The response validation only checks HTTP status codes and extracts metadata from headers, with no cryptographic verification: [3](#0-2) [4](#0-3) 

The `State` structure contains only chain metadata (chain_id, epoch, version, timestamp) extracted from HTTP headers - there is no `StateProof`, `LedgerInfoWithSignatures`, or any cryptographic validation mechanism.

**Attack Path:**

1. Attacker performs DNS poisoning on the domain configured in `RestDiscovery.url`
2. Node's DNS queries resolve to attacker-controlled IP address
3. Malicious REST server responds with crafted `ValidatorSet` containing attacker-controlled IP addresses and public keys
4. Node accepts the fake validator set without verification: [5](#0-4) 
5. Node attempts to connect to fake validators, becoming isolated from the honest network
6. Network partition occurs as affected nodes cannot communicate with legitimate validators

The REST discovery URL is configured via the `RestDiscovery` struct: [6](#0-5) [7](#0-6) 

**Security Invariants Broken:**

1. **Network Availability**: Affected nodes become partitioned and cannot participate in consensus
2. **Cryptographic Correctness**: The system accepts unauthenticated data from untrusted sources
3. **Validator Set Integrity**: Fake validator sets are accepted without on-chain validation

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos Bug Bounty criteria:
- **Validator node slowdowns**: Nodes using REST discovery experience degraded performance or complete isolation
- **Significant protocol violations**: Network partition violates the liveness guarantees of AptosBFT consensus

While REST discovery is not the default configuration for validators (default is "onchain" discovery as shown in validator configs), it is a supported production feature explicitly designed for nodes when "genesis is significantly far behind in time": [8](#0-7) [9](#0-8) 

Any node configured to use REST discovery becomes vulnerable. The impact includes:
- Complete network partition for affected nodes
- Inability to receive blocks or participate in consensus
- Potential for coordinated attacks if multiple nodes use the same poisoned DNS
- Liveness failure requiring manual intervention to restore connectivity

## Likelihood Explanation

**Prerequisites for exploitation:**
1. Target node must be configured with `DiscoveryMethod::Rest` (not the default, but supported)
2. REST URL must use a domain name vulnerable to DNS poisoning (not a direct IP address)
3. Attacker must control DNS infrastructure or perform successful MITM attacks

**Likelihood Assessment: Medium**

While REST discovery is not the default, it is a documented feature used in specific scenarios (bootstrapping nodes with outdated genesis). The complete absence of cryptographic validation means any node using this feature is trivially exploitable once DNS poisoning prerequisites are met. DNS poisoning attacks are well-understood and have been successfully executed against production systems.

## Recommendation

Implement cryptographic validation of validator sets retrieved via REST API using Aptos state proofs:

1. **Add State Proof Verification**: Extend the REST client to request and validate state proofs for all account resources
2. **Use Trusted State**: Maintain a `TrustedState` and verify responses using `verify_and_ratchet()`: [10](#0-9) 

3. **Validate Signatures**: Verify that `LedgerInfoWithSignatures` contains valid BLS signatures from the known validator set

**Recommended Fix Pattern:**

```rust
// In RestStream, maintain trusted state
pub struct RestStream {
    network_context: NetworkContext,
    rest_client: aptos_rest_client::Client,
    interval: Pin<Box<Interval>>,
    trusted_state: TrustedState, // Add this
}

// In poll_next(), verify state proofs
fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    futures::ready!(self.interval.as_mut().poll_next(cx));
    
    // Fetch with state proof
    let response = block_on(self.rest_client.get_account_resource_with_proof(
        AccountAddress::ONE,
        "0x1::stake::ValidatorSet",
    ));
    
    Poll::Ready(match response {
        Ok((resource, state_proof)) => {
            // Verify state proof cryptographically
            match self.trusted_state.verify_and_ratchet(&state_proof) {
                Ok(_) => {
                    let validator_set = resource.into_inner();
                    Some(Ok(extract_validator_set_updates(
                        self.network_context,
                        validator_set,
                    )))
                },
                Err(err) => {
                    error!("State proof verification failed: {:?}", err);
                    Some(Err(DiscoveryError::Rest(err.into())))
                }
            }
        },
        Err(err) => Some(Err(DiscoveryError::Rest(err))),
    })
}
```

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_dns_poisoning_vulnerability() {
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    
    // Start malicious REST server
    let mock_server = MockServer::start().await;
    
    // Create fake validator set with attacker-controlled addresses
    let fake_validator_set = create_fake_validator_set(
        vec!["192.0.2.1:6180"], // Attacker IP
        vec![generate_random_public_key()],
    );
    
    // Configure mock to return fake validator set
    Mock::given(method("GET"))
        .and(path("/v1/accounts/0x1/resource/0x1::stake::ValidatorSet"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_bytes(bcs::to_bytes(&fake_validator_set).unwrap())
            .insert_header("X-Aptos-Chain-Id", "4")
            .insert_header("X-Aptos-Ledger-Version", "1000")
            .insert_header("X-Aptos-Epoch", "1"))
        .mount(&mock_server)
        .await;
    
    // Configure node with REST discovery pointing to mock server
    let mut config = NodeConfig::get_default_pfn_config();
    let network_config = config.full_node_networks.first_mut().unwrap();
    network_config.discovery_method = DiscoveryMethod::Rest(RestDiscovery {
        url: mock_server.uri().parse().unwrap(),
        interval_secs: 1,
    });
    
    // Create RestStream
    let rest_stream = RestStream::new(
        network_context,
        mock_server.uri().parse().unwrap(),
        Duration::from_secs(1),
        time_service,
    );
    
    // Poll and verify fake validator set is accepted
    let result = rest_stream.poll_next(cx).await;
    
    // VULNERABILITY: The fake validator set is accepted without verification
    assert!(result.is_ok());
    let peer_set = result.unwrap();
    assert!(peer_set.contains_key(&attacker_peer_id));
    
    // Node will now attempt to connect to attacker-controlled validators
    // causing network partition
}
```

**Notes:**
- This vulnerability only affects nodes explicitly configured to use REST discovery, which is not the default for validators
- However, the complete absence of cryptographic validation makes it a critical design flaw in the REST discovery feature
- The proper solution requires integrating state proof verification throughout the REST client stack
- Until fixed, operators should avoid using REST discovery on untrusted networks or ensure REST URLs use direct IP addresses with TLS certificate pinning

### Citations

**File:** network/discovery/src/rest.rs (L16-18)
```rust
/// A discovery stream that uses the REST client to determine the validator
/// set nodes.  Useful for when genesis is significantly far behind in time
pub struct RestStream {
```

**File:** network/discovery/src/rest.rs (L42-58)
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
```

**File:** crates/aptos-rest-client/src/lib.rs (L1209-1221)
```rust
    pub async fn get_account_resource_bcs<T: DeserializeOwned>(
        &self,
        address: AccountAddress,
        resource_type: &str,
    ) -> AptosResult<Response<T>> {
        let url = self.build_path(&format!(
            "accounts/{}/resource/{}",
            address.to_hex(),
            resource_type
        ))?;
        let response = self.get_bcs(url).await?;
        Ok(response.and_then(|inner| bcs::from_bytes(&inner))?)
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1645-1656)
```rust
    async fn check_response(
        &self,
        response: reqwest::Response,
    ) -> AptosResult<(reqwest::Response, State)> {
        if !response.status().is_success() {
            Err(parse_error(response).await)
        } else {
            let state = parse_state(&response)?;

            Ok((response, state))
        }
    }
```

**File:** crates/aptos-rest-client/src/state.rs (L22-102)
```rust
impl State {
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> anyhow::Result<Self> {
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_version = headers
            .get(X_APTOS_LEDGER_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_timestamp = headers
            .get(X_APTOS_LEDGER_TIMESTAMP)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_epoch = headers
            .get(X_APTOS_EPOCH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_ledger_version = headers
            .get(X_APTOS_LEDGER_OLDEST_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_block_height = headers
            .get(X_APTOS_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_block_height = headers
            .get(X_APTOS_OLDEST_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cursor = headers
            .get(X_APTOS_CURSOR)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let state = if let (
            Some(chain_id),
            Some(version),
            Some(timestamp_usecs),
            Some(epoch),
            Some(oldest_ledger_version),
            Some(block_height),
            Some(oldest_block_height),
            cursor,
        ) = (
            maybe_chain_id,
            maybe_version,
            maybe_timestamp,
            maybe_epoch,
            maybe_oldest_ledger_version,
            maybe_block_height,
            maybe_oldest_block_height,
            cursor,
        ) {
            Self {
                chain_id,
                epoch,
                version,
                timestamp_usecs,
                oldest_ledger_version,
                block_height,
                oldest_block_height,
                cursor,
            }
        } else {
            anyhow::bail!(
                "Failed to build State from headers due to missing values in response. \
                Chain ID: {:?}, Version: {:?}, Timestamp: {:?}, Epoch: {:?}, \
                Oldest Ledger Version: {:?}, Block Height: {:?} Oldest Block Height: {:?}",
                maybe_chain_id,
                maybe_version,
                maybe_timestamp,
                maybe_epoch,
                maybe_oldest_ledger_version,
                maybe_block_height,
                maybe_oldest_block_height,
            )
        };

        Ok(state)
    }
```

**File:** network/discovery/src/validator_set.rs (L108-150)
```rust
pub(crate) fn extract_validator_set_updates(
    network_context: NetworkContext,
    node_set: ValidatorSet,
) -> PeerSet {
    let is_validator = network_context.network_id().is_validator_network();

    // Decode addresses while ignoring bad addresses
    node_set
        .into_iter()
        .map(|info| {
            let peer_id = *info.account_address();
            let config = info.into_config();

            let addrs = if is_validator {
                config
                    .validator_network_addresses()
                    .map_err(anyhow::Error::from)
            } else {
                config
                    .fullnode_network_addresses()
                    .map_err(anyhow::Error::from)
            }
            .map_err(|err| {
                inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "read_failure", 1);

                warn!(
                    NetworkSchema::new(&network_context),
                    "OnChainDiscovery: Failed to parse any network address: peer: {}, err: {}",
                    peer_id,
                    err
                )
            })
            .unwrap_or_default();

            let peer_role = if is_validator {
                PeerRole::Validator
            } else {
                PeerRole::ValidatorFullNode
            };
            (peer_id, Peer::from_addrs(peer_role, addrs))
        })
        .collect()
}
```

**File:** config/src/config/network_config.rs (L359-364)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RestDiscovery {
    pub url: url::Url,
    pub interval_secs: u64,
}
```

**File:** network/builder/src/builder.rs (L379-385)
```rust
                DiscoveryMethod::Rest(rest_discovery) => DiscoveryChangeListener::rest(
                    self.network_context,
                    conn_mgr_reqs_tx.clone(),
                    rest_discovery.url.clone(),
                    Duration::from_secs(rest_discovery.interval_secs),
                    self.time_service.clone(),
                ),
```

**File:** config/src/config/test_data/validator.yaml (L40-41)
```yaml
validator_network:
    discovery_method: "onchain"
```

**File:** types/src/trusted_state.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

#![allow(clippy::arc_with_non_send_sync)]

use crate::{
    epoch_change::{EpochChangeProof, Verifier},
    epoch_state::EpochState,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    proof::TransactionAccumulatorSummary,
    state_proof::StateProof,
    transaction::Version,
    waypoint::Waypoint,
};
use anyhow::{bail, ensure, format_err, Result};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

/// `TrustedState` keeps track of light clients' latest, trusted view of the
/// ledger state. Light clients can use proofs from a state proof to "ratchet"
/// their view forward to a newer state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, CryptoHasher, BCSCryptoHash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum TrustedState {
    /// The current trusted state is an epoch waypoint, which is a commitment to
    /// an epoch change ledger info. Most light clients will start here when
    /// syncing for the first time.
    EpochWaypoint(Waypoint),
    /// The current trusted state is inside a verified epoch (which includes the
    /// validator set inside that epoch).
    EpochState {
        /// The current trusted version and a commitment to a ledger info inside
        /// the current trusted epoch.
        waypoint: Waypoint,
        /// The current epoch and validator set inside that epoch.
        epoch_state: EpochState,
    },
}

/// `TrustedStateChange` is the result of attempting to ratchet to a new trusted
/// state. In order to reduce redundant error checking, `TrustedStateChange` also
/// contains references to relevant items used to ratchet us.
#[derive(Clone, Debug)]
pub enum TrustedStateChange<'a> {
    /// We have a newer `TrustedState` but it's still in the same epoch, so only
    /// the latest trusted version changed.
    Version { new_state: TrustedState },
    /// We have a newer `TrustedState` and there was at least one epoch change,
```
