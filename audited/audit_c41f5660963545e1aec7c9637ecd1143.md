# Audit Report

## Title
JWK Consensus HashMap Memory Exhaustion via Unvalidated Issuer Requests

## Summary
Byzantine validators can flood honest validators with `ObservationRequest` messages containing arbitrary issuer names, causing unbounded memory consumption in the `states_by_issuer` HashMap. The `process_peer_request()` function creates HashMap entries for any requested issuer without validating against the list of supported OIDC providers, enabling a memory exhaustion DoS attack.

## Finding Description

The JWK consensus mechanism allows validators to request observations from peers for specific OIDC issuers. When an honest validator receives an `ObservationRequest`, it processes the request without validating whether the issuer is in the supported OIDC providers list. [1](#0-0) 

The critical vulnerability occurs at line 302 where `self.states_by_issuer.entry(request.issuer).or_default()` unconditionally creates a new HashMap entry for any issuer name provided in the request. There is no validation that `request.issuer` matches any issuer in the supported OIDC providers list configured on-chain.

The same vulnerability exists in the key-level consensus mode: [2](#0-1) 

At line 276, `self.states_by_key.entry((issuer.clone(), kid.clone())).or_default()` creates entries for arbitrary (issuer, kid) pairs without validation.

**Attack Path:**

1. Byzantine validator crafts `ObservationRequest` messages with random/fake issuer names (e.g., "fake-issuer-1", "fake-issuer-2", etc.)
2. Sends these requests to honest validators through the network interface
3. Each honest validator's `process_peer_request()` creates a new `PerProviderState` entry in the HashMap
4. HashMap grows unbounded as attacker sends requests with unique issuer names
5. Honest validators experience memory exhaustion, leading to slowdowns or crashes

**Evidence of Missing Validation:**

The `reset_with_on_chain_state()` function demonstrates that only issuers present in the on-chain configuration should be tracked: [3](#0-2) 

Line 253 explicitly retains only issuers that exist in `onchain_issuer_set`, confirming that arbitrary issuers should not persist in the HashMap. However, `process_peer_request()` bypasses this invariant.

**Resource Limits:**

While channel sizes are limited (10 for NetworkTask, 100 for EpochManager): [4](#0-3) [5](#0-4) 

These limits do NOT prevent HashMap exhaustion because:
- Requests can be sent slowly to avoid filling the channel
- Once processed, channel space is freed while HashMap entries persist
- No rate limiting exists on unique issuers per validator

## Impact Explanation

**Severity: MEDIUM to HIGH**

Per Aptos Bug Bounty criteria:
- **High Severity**: "Validator node slowdowns" - This attack directly causes resource exhaustion and performance degradation
- **Medium Severity**: "State inconsistencies requiring intervention" - Requires epoch change or manual restart to clear malicious entries

The vulnerability breaks **Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits."

**Quantified Impact:**
- Memory consumption grows linearly with number of unique fake issuers (each `PerProviderState` struct allocates heap memory)
- In key-level mode, impact is quadratic: unique (issuer, kid) pairs
- Affects all honest validators who process these requests
- Can lead to node crashes if system memory is exhausted
- Reduces network availability and consensus performance

This does NOT violate consensus safety (no chain splits or double-spending), but degrades availability, qualifying as **High Severity** under validator node slowdown category.

## Likelihood Explanation

**Likelihood: HIGH**

Requirements for exploitation:
- Attacker must be a validator (or compromise a validator's network identity)
- Under <1/3 Byzantine assumption, this is the expected threat model
- No cryptographic primitives need to be broken
- Attack is trivial to execute - just send RPC messages

**Feasibility:**
- Very simple attack vector with no special conditions required
- Can be executed continuously throughout an epoch
- Difficult to attribute or block without rate limiting infrastructure
- No existing defenses against this specific attack vector

## Recommendation

Add validation to check if the requested issuer exists in the supported OIDC providers list before creating HashMap entries:

```rust
pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest {
        msg,
        mut response_sender,
        ..
    } = rpc_req;
    match msg {
        JWKConsensusMsg::ObservationRequest(request) => {
            // ADDED: Validate issuer against on-chain supported providers
            let valid_issuer = self.states_by_issuer.contains_key(&request.issuer);
            if !valid_issuer {
                // Reject requests for unknown issuers
                response_sender.send(Err(anyhow!("issuer not in supported OIDC providers")));
                return Ok(());
            }
            
            let state = self.states_by_issuer.entry(request.issuer).or_default();
            let response: Result<JWKConsensusMsg> = match &state.consensus_state {
                ConsensusState::NotStarted => Err(anyhow!("observed update unavailable")),
                ConsensusState::InProgress { my_proposal, .. }
                | ConsensusState::Finished { my_proposal, .. } => Ok(
                    JWKConsensusMsg::ObservationResponse(ObservedUpdateResponse {
                        epoch: self.epoch_state.epoch,
                        update: my_proposal.clone(),
                    }),
                ),
            };
            response_sender.send(response);
            Ok(())
        },
        _ => {
            bail!("unexpected rpc: {}", msg.name());
        },
    }
}
```

Apply similar validation to `KeyLevelConsensusManager::process_peer_request()` checking both issuer and kid against `onchain_jwks`.

**Additional Recommendations:**
1. Implement rate limiting per peer for RPC requests
2. Add monitoring/alerting for HashMap size growth
3. Consider maximum HashMap size limits with eviction policies

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use aptos_types::jwks::Issuer;
    use crate::types::{JWKConsensusMsg, ObservedUpdateRequest};
    
    #[tokio::test]
    async fn test_unbounded_issuer_hashmap_growth() {
        // Setup: Create IssuerLevelConsensusManager instance
        // (Setup code omitted for brevity - would initialize with test epoch state)
        
        let mut manager = /* initialize manager */;
        let initial_map_size = manager.states_by_issuer.len();
        
        // Attack: Send ObservationRequests for 1000 fake issuers
        for i in 0..1000 {
            let fake_issuer: Issuer = format!("fake-issuer-{}", i).into_bytes();
            let request = ObservedUpdateRequest {
                epoch: manager.epoch_state.epoch,
                issuer: fake_issuer.clone(),
            };
            
            let rpc_request = IncomingRpcRequest {
                msg: JWKConsensusMsg::ObservationRequest(request),
                sender: /* test peer address */,
                response_sender: /* test response sender */,
            };
            
            // Process the malicious request
            manager.process_peer_request(rpc_request).unwrap();
        }
        
        let final_map_size = manager.states_by_issuer.len();
        
        // Vulnerability: HashMap grew by 1000 entries for fake issuers
        assert_eq!(final_map_size - initial_map_size, 1000);
        
        // These entries persist until epoch change
        // Memory consumption: ~1000 * sizeof(PerProviderState) bytes leaked
    }
}
```

**Notes:**
- The vulnerability is exploitable by any Byzantine validator within the <1/3 Byzantine fault tolerance assumption
- Complete PoC would require full test harness setup with mock epoch state and network components
- Attack can be amplified in key-level mode by varying both issuer and kid fields

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L231-256)
```rust
    pub fn reset_with_on_chain_state(&mut self, on_chain_state: AllProvidersJWKs) -> Result<()> {
        info!(
            epoch = self.epoch_state.epoch,
            "reset_with_on_chain_state starting."
        );
        let onchain_issuer_set: HashSet<Issuer> = on_chain_state
            .entries
            .iter()
            .map(|entry| entry.issuer.clone())
            .collect();
        let local_issuer_set: HashSet<Issuer> = self.states_by_issuer.keys().cloned().collect();

        for issuer in local_issuer_set.difference(&onchain_issuer_set) {
            info!(
                epoch = self.epoch_state.epoch,
                op = "delete",
                issuer = issuer.clone(),
                "reset_with_on_chain_state"
            );
        }

        self.states_by_issuer
            .retain(|issuer, _| onchain_issuer_set.contains(issuer));
        for on_chain_provider_jwks in on_chain_state.entries {
            let issuer = on_chain_provider_jwks.issuer.clone();
            let locally_cached = self
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L294-320)
```rust
    pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
        let IncomingRpcRequest {
            msg,
            mut response_sender,
            ..
        } = rpc_req;
        match msg {
            JWKConsensusMsg::ObservationRequest(request) => {
                let state = self.states_by_issuer.entry(request.issuer).or_default();
                let response: Result<JWKConsensusMsg> = match &state.consensus_state {
                    ConsensusState::NotStarted => Err(anyhow!("observed update unavailable")),
                    ConsensusState::InProgress { my_proposal, .. }
                    | ConsensusState::Finished { my_proposal, .. } => Ok(
                        JWKConsensusMsg::ObservationResponse(ObservedUpdateResponse {
                            epoch: self.epoch_state.epoch,
                            update: my_proposal.clone(),
                        }),
                    ),
                };
                response_sender.send(response);
                Ok(())
            },
            _ => {
                bail!("unexpected rpc: {}", msg.name());
            },
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L265-309)
```rust
    pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
        let IncomingRpcRequest {
            msg,
            mut response_sender,
            ..
        } = rpc_req;
        match msg {
            JWKConsensusMsg::KeyLevelObservationRequest(request) => {
                let ObservedKeyLevelUpdateRequest { issuer, kid, .. } = request;
                let consensus_state = self
                    .states_by_key
                    .entry((issuer.clone(), kid.clone()))
                    .or_default();
                let response: Result<JWKConsensusMsg> = match &consensus_state {
                    ConsensusState::NotStarted => {
                        debug!(
                            issuer = String::from_utf8(issuer.clone()).ok(),
                            kid = String::from_utf8(kid.clone()).ok(),
                            "key-level jwk consensus not started"
                        );
                        return Ok(());
                    },
                    ConsensusState::InProgress { my_proposal, .. }
                    | ConsensusState::Finished { my_proposal, .. } => Ok(
                        JWKConsensusMsg::ObservationResponse(ObservedUpdateResponse {
                            epoch: self.epoch_state.epoch,
                            update: ObservedUpdate {
                                author: self.my_addr,
                                observed: my_proposal
                                    .observed
                                    .try_as_issuer_level_repr()
                                    .context("process_peer_request failed with repr conversion")?,
                                signature: my_proposal.signature.clone(),
                            },
                        }),
                    ),
                };
                response_sender.send(response);
                Ok(())
            },
            _ => {
                bail!("unexpected rpc: {}", msg.name());
            },
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/network.rs (L163-186)
```rust
impl NetworkTask {
    /// Establishes the initial connections with the peers and returns the receivers.
    pub fn new(
        network_service_events: NetworkServiceEvents<JWKConsensusMsg>,
        self_receiver: aptos_channels::Receiver<Event<JWKConsensusMsg>>,
    ) -> (NetworkTask, NetworkReceivers) {
        let (rpc_tx, rpc_rx) = aptos_channel::new(QueueStyle::FIFO, 10, None);

        let network_and_events = network_service_events.into_network_and_events();
        if (network_and_events.values().len() != 1)
            || !network_and_events.contains_key(&NetworkId::Validator)
        {
            panic!("The network has not been setup correctly for JWK consensus!");
        }

        // Collect all the network events into a single stream
        let network_events: Vec<_> = network_and_events.into_values().collect();
        let network_events = select_all(network_events).fuse();
        let all_events = Box::new(select(network_events, self_receiver));

        (NetworkTask { rpc_tx, all_events }, NetworkReceivers {
            rpc_rx,
        })
    }
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L220-225)
```rust
            let (jwk_event_tx, jwk_event_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
            self.jwk_updated_event_txs = Some(jwk_event_tx);
            let (jwk_rpc_msg_tx, jwk_rpc_msg_rx) = aptos_channel::new(QueueStyle::FIFO, 100, None);

            let (jwk_manager_close_tx, jwk_manager_close_rx) = oneshot::channel();
            self.jwk_rpc_msg_tx = Some(jwk_rpc_msg_tx);
```
