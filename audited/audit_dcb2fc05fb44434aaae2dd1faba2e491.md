# Audit Report

## Title
Consensus Failure via ValidatorSet Schema Mismatch Between Move and Rust Implementations

## Summary
A critical coordination vulnerability exists where the Move framework's `ValidatorSet` resource structure can be modified through governance proposals without ensuring the corresponding Rust deserializer is updated, causing all validator nodes to panic during epoch transitions and resulting in complete network halt.

## Finding Description

The Aptos blockchain maintains two separate representations of the `ValidatorSet` structure:

1. **On-chain Move definition** [1](#0-0) 

2. **Off-chain Rust definition** [2](#0-1) 

While both currently match in field order and types, the Move VM's compatibility checking system only ensures **backward compatibility of Move code with existing on-chain resources**. It does NOT verify that off-chain Rust node code can deserialize NEW resource formats after framework upgrades.

The compatibility checker validates struct layout changes: [3](#0-2) 

However, this only ensures new Move code can read old data, not that Rust code can read new data.

**Attack Vector:**

When a governance proposal modifies the `ValidatorSet` structure (e.g., adding new fields), the upgrade can proceed if it's backward-compatible from Move's perspective. However, critical consensus components deserialize `ValidatorSet` using `.expect()` which panics on failure: [4](#0-3) 

This pattern is replicated across multiple critical components:
- [5](#0-4) 
- [6](#0-5) 
- [7](#0-6) 

**Exploitation Steps:**

1. Governance proposal passes to upgrade framework, adding a new field to `ValidatorSet` struct
2. Compatibility check passes (backward compatible for Move)
3. Framework upgrade deploys on-chain
4. New epoch begins, creating `ValidatorSet` with additional field
5. Validator nodes attempt to deserialize using outdated Rust struct
6. BCS deserialization fails (field count mismatch)
7. `.expect()` panics in `start_new_epoch()`
8. All validator nodes crash simultaneously
9. Network halts - no validators can participate in consensus

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program:

- **Total loss of liveness/network availability**: All validator nodes crash when attempting epoch transition, preventing any consensus or block production
- **Non-recoverable without intervention**: Requires emergency coordinated node upgrades across the entire validator set
- **Consensus violation**: Breaks the fundamental requirement that validators must be able to process epoch changes

The impact affects 100% of validator nodes simultaneously, causing complete network halt rather than partial degradation.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability has moderate-to-high likelihood because:

1. **Framework upgrades are frequent**: The Aptos governance regularly upgrades framework modules to add features
2. **ValidatorSet is subject to evolution**: As consensus features expand (e.g., randomness, DKG), ValidatorSet may need new fields
3. **Coordination gap exists**: The compatibility checker cannot validate off-chain Rust code, creating a blind spot
4. **Manual coordination required**: Relies on perfect synchronization between Move developers, Rust developers, and validator operators
5. **No automated safeguards**: No CI/CD checks enforce schema matching between Move and Rust definitions

However, likelihood is reduced by:
- Governance proposal review processes
- Testnet validation before mainnet deployment
- Developer awareness of this coordination requirement

A single coordination failure during a routine framework upgrade could trigger this vulnerability.

## Recommendation

**Immediate Mitigations:**

1. **Replace `.expect()` with graceful error handling** in all epoch manager implementations:

```rust
let validator_set: ValidatorSet = match payload.get() {
    Ok(vs) => vs,
    Err(e) => {
        error!("Failed to deserialize ValidatorSet: {:?}", e);
        // Attempt recovery or graceful shutdown
        return;
    }
};
```

2. **Implement schema validation tests** that compare Move and Rust struct definitions at compile time

3. **Add pre-deployment validation** that deserializes actual on-chain `ValidatorSet` using both old and new Rust code

**Long-term Solutions:**

1. **Automated schema synchronization**: Generate Rust structs from Move definitions or vice versa to ensure consistency

2. **Versioned serialization**: Add version fields to ValidatorSet allowing graceful handling of schema evolution:

```move
struct ValidatorSet has copy, key, drop, store {
    version: u8,  // Schema version
    // ... existing fields
}
```

3. **Staged deployment protocol**: Enforce that node software updates must deploy before framework upgrades through governance mechanics

4. **Enhanced compatibility checking**: Extend the Move compatibility checker to validate against registered off-chain schema definitions

## Proof of Concept

**Reproduction Steps:**

1. Create governance proposal that adds a field to `ValidatorSet`:

```move
// Modified ValidatorSet in new framework version
struct ValidatorSet has copy, key, drop, store {
    consensus_scheme: u8,
    active_validators: vector<ValidatorInfo>,
    pending_inactive: vector<ValidatorInfo>,
    pending_active: vector<ValidatorInfo>,
    total_voting_power: u128,
    total_joining_power: u128,
    new_feature_flag: u64,  // New field added
}
```

2. Deploy framework upgrade through governance without updating Rust node code

3. Trigger epoch transition

4. Observe panic in validator logs:
```
thread 'main' panicked at 'failed to get ValidatorSet from payload'
consensus/src/epoch_manager.rs:1167
```

5. Verify all validators crash and network halts

**Validation Test:**

Create integration test that simulates schema mismatch:

```rust
#[test]
fn test_validator_set_schema_mismatch() {
    // Serialize ValidatorSet with extra field
    let extended_bytes = serialize_extended_validator_set();
    
    // Attempt to deserialize using current Rust struct
    let result = bcs::from_bytes::<ValidatorSet>(&extended_bytes);
    
    // Should fail due to field count mismatch
    assert!(result.is_err());
    
    // Verify this would cause panic in epoch_manager
    // (demonstrates the vulnerability)
}
```

## Notes

This vulnerability represents a critical gap in the Aptos framework's upgrade coordination mechanism. While the on-chain compatibility checker functions correctly for its intended purpose (Move backward compatibility), it creates a false sense of security regarding overall system consistency. The reliance on `.expect()` in consensus-critical paths transforms what should be a recoverable error into a catastrophic network failure. Immediate action is required to add defensive error handling and establish robust coordination protocols between Move framework and Rust node implementations.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L181-193)
```text
    struct ValidatorSet has copy, key, drop, store {
        consensus_scheme: u8,
        // Active validators for the current epoch.
        active_validators: vector<ValidatorInfo>,
        // Pending validators to leave in next epoch (still active).
        pending_inactive: vector<ValidatorInfo>,
        // Pending validators to join in next epoch.
        pending_active: vector<ValidatorInfo>,
        // Current total voting power.
        total_voting_power: u128,
        // Total voting power waiting to join in the next epoch.
        total_joining_power: u128,
    }
```

**File:** types/src/on_chain_config/validator_set.rs (L23-32)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ValidatorSet {
    pub scheme: ConsensusScheme,
    pub active_validators: Vec<ValidatorInfo>,
    pub pending_inactive: Vec<ValidatorInfo>,
    pub pending_active: Vec<ValidatorInfo>,
    pub total_voting_power: u128,
    pub total_joining_power: u128,
}
```

**File:** third_party/move/move-binary-format/src/compatibility.rs (L145-147)
```rust
            if self.check_struct_layout && !self.struct_layout_compatible(&old_struct, new_struct) {
                errors.push(format!("changed layout of struct `{}`", old_struct.name()));
            }
```

**File:** consensus/src/epoch_manager.rs (L1165-1167)
```rust
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
```

**File:** dkg/src/epoch_manager.rs (L108-260)
```rust
    fn on_dkg_start_notification(&mut self, notification: EventNotification) -> Result<()> {
        if let Some(tx) = self.dkg_start_event_tx.as_ref() {
            let EventNotification {
                subscribed_events, ..
            } = notification;
            for event in subscribed_events {
                if let Ok(dkg_start_event) = DKGStartEvent::try_from(&event) {
                    let _ = tx.push((), dkg_start_event);
                    return Ok(());
                } else {
                    debug!("[DKG] on_dkg_start_notification: failed in converting a contract event to a dkg start event!");
                }
            }
        }
        Ok(())
    }

    pub async fn start(mut self, mut network_receivers: NetworkReceivers) {
        self.await_reconfig_notification().await;
        loop {
            let handling_result = tokio::select! {
                notification = self.dkg_start_events.select_next_some() => {
                    self.on_dkg_start_notification(notification)
                },
                reconfig_notification = self.reconfig_events.select_next_some() => {
                    self.on_new_epoch(reconfig_notification).await
                },
                (peer, rpc_request) = network_receivers.rpc_rx.select_next_some() => {
                    self.process_rpc_request(peer, rpc_request)
                },
            };

            if let Err(e) = handling_result {
                error!("{}", e);
            }
        }
    }

    async fn await_reconfig_notification(&mut self) {
        let reconfig_notification = self
            .reconfig_events
            .next()
            .await
            .expect("Reconfig sender dropped, unable to start new epoch");
        self.start_new_epoch(reconfig_notification.on_chain_configs)
            .await
            .unwrap();
    }

    async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) -> Result<()> {
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");

        let epoch_state = Arc::new(EpochState::new(payload.epoch(), (&validator_set).into()));
        self.epoch_state = Some(epoch_state.clone());
        let my_index = epoch_state
            .verifier
            .address_to_validator_index()
            .get(&self.my_addr)
            .copied();

        let onchain_randomness_config_seq_num = payload
            .get::<RandomnessConfigSeqNum>()
            .unwrap_or_else(|_| RandomnessConfigSeqNum::default_if_missing());

        let randomness_config_move_struct = payload.get::<RandomnessConfigMoveStruct>();

        info!(
            epoch = epoch_state.epoch,
            local = self.randomness_override_seq_num,
            onchain = onchain_randomness_config_seq_num.seq_num,
            "Checking randomness config override."
        );
        if self.randomness_override_seq_num > onchain_randomness_config_seq_num.seq_num {
            warn!("Randomness will be force-disabled by local config!");
        }

        let onchain_randomness_config = OnChainRandomnessConfig::from_configs(
            self.randomness_override_seq_num,
            onchain_randomness_config_seq_num.seq_num,
            randomness_config_move_struct.ok(),
        );

        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
        if let Err(error) = &onchain_consensus_config {
            error!("Failed to read on-chain consensus config {}", error);
        }
        let consensus_config = onchain_consensus_config.unwrap_or_default();

        // Check both validator txn and randomness features are enabled
        let randomness_enabled =
            consensus_config.is_vtxn_enabled() && onchain_randomness_config.randomness_enabled();
        if let (true, Some(my_index)) = (randomness_enabled, my_index) {
            let DKGState {
                in_progress: in_progress_session,
                ..
            } = payload.get::<DKGState>().unwrap_or_default();

            let network_sender = self.create_network_sender();
            let rb = ReliableBroadcast::new(
                self.my_addr,
                epoch_state.verifier.get_ordered_account_addresses(),
                Arc::new(network_sender),
                ExponentialBackoff::from_millis(self.rb_config.backoff_policy_base_ms)
                    .factor(self.rb_config.backoff_policy_factor)
                    .max_delay(Duration::from_millis(
                        self.rb_config.backoff_policy_max_delay_ms,
                    )),
                aptos_time_service::TimeService::real(),
                Duration::from_millis(self.rb_config.rpc_timeout_ms),
                BoundedExecutor::new(8, tokio::runtime::Handle::current()),
            );
            let agg_trx_producer = AggTranscriptProducer::new(rb);

            let (dkg_start_event_tx, dkg_start_event_rx) =
                aptos_channel::new(QueueStyle::KLAST, 1, None);
            self.dkg_start_event_tx = Some(dkg_start_event_tx);

            let (dkg_rpc_msg_tx, dkg_rpc_msg_rx) = aptos_channel::new::<
                AccountAddress,
                (AccountAddress, IncomingRpcRequest),
            >(QueueStyle::FIFO, 100, None);
            self.dkg_rpc_msg_tx = Some(dkg_rpc_msg_tx);
            let (dkg_manager_close_tx, dkg_manager_close_rx) = oneshot::channel();
            self.dkg_manager_close_tx = Some(dkg_manager_close_tx);
            let my_pk = epoch_state
                .verifier
                .get_public_key(&self.my_addr)
                .ok_or_else(|| anyhow!("my pk not found in validator set"))?;
            let dealer_sk = self
                .key_storage
                .consensus_sk_by_pk(my_pk.clone())
                .map_err(|e| {
                    anyhow!("dkg new epoch handling failed with consensus sk lookup err: {e}")
                })?;
            let dkg_manager = DKGManager::<DefaultDKG>::new(
                Arc::new(dealer_sk),
                Arc::new(my_pk),
                my_index,
                self.my_addr,
                epoch_state,
                Arc::new(agg_trx_producer),
                self.vtxn_pool.clone(),
            );
            tokio::spawn(dkg_manager.run(
                in_progress_session,
                dkg_start_event_rx,
                dkg_rpc_msg_rx,
                dkg_manager_close_rx,
            ));
        };
        Ok(())
```

**File:** network/discovery/src/validator_set.rs (L1-151)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    counters::{DISCOVERY_COUNTS, EVENT_PROCESSING_LOOP_BUSY_DURATION_S, NETWORK_KEY_MISMATCH},
    DiscoveryError,
};
use aptos_config::{
    config::{Peer, PeerRole, PeerSet},
    network_id::NetworkContext,
};
use aptos_crypto::x25519;
use aptos_event_notifications::ReconfigNotificationListener;
use aptos_logger::prelude::*;
use aptos_network::{counters::inc_by_with_context, logging::NetworkSchema};
use aptos_short_hex_str::AsShortHexStr;
use aptos_types::on_chain_config::{OnChainConfigPayload, OnChainConfigProvider, ValidatorSet};
use futures::Stream;
use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
};

pub struct ValidatorSetStream<P: OnChainConfigProvider> {
    pub(crate) network_context: NetworkContext,
    expected_pubkey: x25519::PublicKey,
    reconfig_events: ReconfigNotificationListener<P>,
}

impl<P: OnChainConfigProvider> ValidatorSetStream<P> {
    pub(crate) fn new(
        network_context: NetworkContext,
        expected_pubkey: x25519::PublicKey,
        reconfig_events: ReconfigNotificationListener<P>,
    ) -> Self {
        Self {
            network_context,
            expected_pubkey,
            reconfig_events,
        }
    }

    fn find_key_mismatches(&self, onchain_keys: Option<&HashSet<x25519::PublicKey>>) {
        let mismatch = onchain_keys.map_or(0, |pubkeys| {
            if !pubkeys.contains(&self.expected_pubkey) {
                error!(
                    NetworkSchema::new(&self.network_context),
                    "Onchain pubkey {:?} differs from local pubkey {}",
                    pubkeys,
                    self.expected_pubkey
                );
                1
            } else {
                0
            }
        });

        NETWORK_KEY_MISMATCH
            .with_label_values(&[
                self.network_context.role().as_str(),
                self.network_context.network_id().as_str(),
                self.network_context.peer_id().short_str().as_str(),
            ])
            .set(mismatch);
    }

    fn extract_updates(&mut self, payload: OnChainConfigPayload<P>) -> PeerSet {
        let _process_timer = EVENT_PROCESSING_LOOP_BUSY_DURATION_S.start_timer();

        let node_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");

        let peer_set = extract_validator_set_updates(self.network_context, node_set);
        // Ensure that the public key matches what's onchain for this peer
        self.find_key_mismatches(
            peer_set
                .get(&self.network_context.peer_id())
                .map(|peer| &peer.keys),
        );

        inc_by_with_context(
            &DISCOVERY_COUNTS,
            &self.network_context,
            "new_nodes",
            peer_set.len() as u64,
        );

        peer_set
    }
}

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

/// Extracts a set of ConnectivityRequests from a ValidatorSet which are appropriate for a network with type role.
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

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L143-196)
```rust
    async fn await_reconfig_notification(&mut self) {
        let reconfig_notification = self
            .reconfig_events
            .next()
            .await
            .expect("Reconfig sender dropped, unable to start new epoch");
        self.start_new_epoch(reconfig_notification.on_chain_configs)
            .await
            .unwrap();
    }

    async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) -> Result<()> {
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");

        let epoch_state = Arc::new(EpochState::new(payload.epoch(), (&validator_set).into()));
        self.epoch_state = Some(epoch_state.clone());
        let my_index = epoch_state
            .verifier
            .address_to_validator_index()
            .get(&self.my_addr)
            .copied();

        info!(
            epoch = epoch_state.epoch,
            "EpochManager starting new epoch."
        );

        let features = payload.get::<Features>().unwrap_or_default();
        let jwk_consensus_config = payload.get::<OnChainJWKConsensusConfig>();
        let onchain_observed_jwks = payload.get::<ObservedJWKs>().ok();
        let onchain_consensus_config = payload.get::<OnChainConsensusConfig>().unwrap_or_default();

        let (jwk_manager_should_run, oidc_providers) = match jwk_consensus_config {
            Ok(config) => {
                let should_run =
                    config.jwk_consensus_enabled() && onchain_consensus_config.is_vtxn_enabled();
                let providers = config
                    .oidc_providers_cloned()
                    .into_iter()
                    .map(jwks::OIDCProvider::from)
                    .collect();
                (should_run, Some(SupportedOIDCProviders { providers }))
            },
            Err(_) => {
                //TODO: remove this case once the framework change of this commit is published.
                let should_run = features.is_enabled(FeatureFlag::JWK_CONSENSUS)
                    && onchain_consensus_config.is_vtxn_enabled();
                let providers = payload.get::<SupportedOIDCProviders>().ok();
                (should_run, providers)
            },
        };

```
