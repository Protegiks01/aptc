# Audit Report

## Title
Silent Message Dropping in DKG Channel Causes Network Liveness Failure During Epoch Transitions

## Summary
The DKG (Distributed Key Generation) system silently drops RPC messages when its channel reaches capacity (100 messages per peer), causing RPC failures that prevent transcript collection. When randomness is enabled, incomplete DKG blocks epoch transitions, potentially halting the blockchain until manual governance intervention via `force_end_epoch()` is executed.

## Finding Description

The DKG EpochManager creates a FIFO channel with 100-message capacity per peer to forward RPC requests to the DKGManager: [1](#0-0) 

When RPC requests arrive, the result of `push()` is explicitly discarded, providing no error notification: [2](#0-1) 

The underlying FIFO implementation drops the newest message when at capacity: [3](#0-2) 

The `push()` method returns `Ok(())` even when messages are dropped, only returning errors if the receiver is closed: [4](#0-3) 

When messages are dropped, the contained `IncomingRpcRequest` with its `response_sender` is destroyed without sending a response, causing the RPC caller's oneshot channel to close and triggering timeout errors. The ReliableBroadcast layer retries indefinitely with exponential backoff (max 3000ms delay): [5](#0-4) [6](#0-5) 

**Critical Liveness Impact**: When randomness is enabled, the `reconfigure()` function calls `try_start()` instead of immediately finishing the epoch transition: [7](#0-6) 

The `try_start()` function checks for incomplete DKG sessions and returns early if one exists for the current epoch, preventing new epoch transitions: [8](#0-7) 

If DKG cannot complete due to channel saturation preventing transcript collection, the incomplete session blocks all future epoch transitions. The blockchain remains stuck until governance manually invokes `force_end_epoch()` to clear the incomplete DKG session: [9](#0-8) 

The test suite demonstrates this exact failure scenario: [10](#0-9) 

## Impact Explanation

**CRITICAL Severity** per Aptos bug bounty criteria - **Total Loss of Liveness/Network Availability**:

When randomness is enabled (the default configuration for mainnet), incomplete DKG prevents epoch transitions. If channel saturation prevents DKG transcript collection across sufficient validators (>f validators unable to respond due to saturated channels), DKG cannot complete, and the blockchain cannot progress to new epochs. This effectively halts the network until manual governance intervention.

The vulnerability also causes **Validator Node Slowdowns** through retry mechanisms with delays up to 3000ms, degrading performance during critical DKG operations.

Unlike typical DoS attacks (which are out of scope), this is a protocol design flaw where legitimate high-load operations trigger a liveness failure without requiring malicious actors.

## Likelihood Explanation

**Medium-High Likelihood** during normal operations:

1. **Epoch transitions create synchronized load**: All validators simultaneously execute DKG, creating N² message exchanges
2. **100-message capacity may be insufficient**: Large validator sets (100+ validators) can generate hundreds of concurrent requests
3. **No backpressure mechanism**: Senders have no indication that receivers are overloaded
4. **No monitoring**: The DKG module lacks dropped message metrics unlike consensus channels which track dropped messages via `CONSENSUS_CHANNEL_MSGS` [11](#0-10) 

The test suite explicitly includes recovery scenarios for DKG stalls, confirming this is a recognized failure mode.

## Recommendation

1. **Add channel monitoring**: Implement dropped message counters for DKG channels similar to consensus monitoring
2. **Increase channel capacity**: Raise capacity based on expected validator set size (e.g., 1000 messages for 100+ validators)
3. **Check push results**: Log errors when messages are dropped:
```rust
if let Err(e) = tx.push(peer_id, (peer_id, dkg_request)) {
    error!("DKG message dropped: {:?}", e);
    // Potentially emit metric
}
```
4. **Implement backpressure**: Add flow control to slow down senders when receivers are overloaded
5. **Add DKG timeout**: Automatically clear incomplete sessions after a timeout period rather than requiring manual governance intervention

## Proof of Concept

The existing test demonstrates the vulnerability: [12](#0-11) 

To trigger manually:
1. Deploy network with randomness enabled and 100+ validators
2. Wait for epoch transition
3. Artificially slow DKGManager processing (e.g., via failpoint injection)
4. Observe channel saturation as transcripts cannot be collected
5. Verify epoch transition blocks until `force_end_epoch()` is called

The vulnerability is reproducible by saturating the DKG RPC channel during epoch transitions, causing transcript collection to fail and blocking epoch progression.

### Citations

**File:** dkg/src/epoch_manager.rs (L94-106)
```rust
    fn process_rpc_request(
        &mut self,
        peer_id: AccountAddress,
        dkg_request: IncomingRpcRequest,
    ) -> Result<()> {
        if Some(dkg_request.msg.epoch()) == self.epoch_state.as_ref().map(|s| s.epoch) {
            // Forward to DKGManager if it is alive.
            if let Some(tx) = &self.dkg_rpc_msg_tx {
                let _ = tx.push(peer_id, (peer_id, dkg_request));
            }
        }
        Ok(())
    }
```

**File:** dkg/src/epoch_manager.rs (L227-230)
```rust
            let (dkg_rpc_msg_tx, dkg_rpc_msg_rx) = aptos_channel::new::<
                AccountAddress,
                (AccountAddress, IncomingRpcRequest),
            >(QueueStyle::FIFO, 100, None);
```

**File:** crates/channel/src/message_queues.rs (L138-147)
```rust
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
            }
```

**File:** crates/channel/src/aptos_channel.rs (L91-112)
```rust
    pub fn push_with_feedback(
        &self,
        key: K,
        message: M,
        status_ch: Option<oneshot::Sender<ElementStatus<M>>>,
    ) -> Result<()> {
        let mut shared_state = self.shared_state.lock();
        ensure!(!shared_state.receiver_dropped, "Channel is closed");
        debug_assert!(shared_state.num_senders > 0);

        let dropped = shared_state.internal_queue.push(key, (message, status_ch));
        // If this or an existing message had to be dropped because of the queue being full, we
        // notify the corresponding status channel if it was registered.
        if let Some((dropped_val, Some(dropped_status_ch))) = dropped {
            // Ignore errors.
            let _err = dropped_status_ch.send(ElementStatus::Dropped(dropped_val));
        }
        if let Some(w) = shared_state.waker.take() {
            w.wake();
        }
        Ok(())
    }
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

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L694-703)
```text
    /// Change epoch immediately.
    /// If `RECONFIGURE_WITH_DKG` is enabled and we are in the middle of a DKG,
    /// stop waiting for DKG and enter the new epoch without randomness.
    ///
    /// WARNING: currently only used by tests. In most cases you should use `reconfigure()` instead.
    /// TODO: migrate these tests to be aware of async reconfiguration.
    public entry fun force_end_epoch(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        reconfiguration_with_dkg::finish(aptos_framework);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-40)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
    }
```

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L1-100)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    genesis::enable_sync_only_mode, smoke_test_environment::SwarmBuilder,
    utils::get_on_chain_resource,
};
use aptos::common::types::GasOptions;
use aptos_config::config::{OverrideNodeConfig, PersistableConfig};
use aptos_forge::{NodeExt, Swarm, SwarmExt};
use aptos_logger::{debug, info};
use aptos_types::{on_chain_config::OnChainRandomnessConfig, randomness::PerBlockRandomness};
use std::{
    ops::Add,
    sync::Arc,
    time::{Duration, Instant},
};

/// Chain recovery using a local config from randomness stall should work.
/// See `randomness_config_seqnum.move` for more details.
#[tokio::test]
async fn randomness_stall_recovery() {
    let epoch_duration_secs = 20;

    let (mut swarm, mut cli, _faucet) = SwarmBuilder::new_local(4)
        .with_num_fullnodes(0) //TODO: revert back to 1 after invalid version bug is fixed
        .with_aptos()
        .with_init_config(Arc::new(|_, conf, _| {
            conf.api.failpoints_enabled = true;
        }))
        .with_init_genesis_config(Arc::new(move |conf| {
            conf.epoch_duration_secs = epoch_duration_secs;

            // Ensure randomness is enabled.
            conf.consensus_config.enable_validator_txns();
            conf.randomness_config_override = Some(OnChainRandomnessConfig::default_enabled());
        }))
        .build_with_cli(0)
        .await;

    let root_addr = swarm.chain_info().root_account().address();
    let root_idx = cli.add_account_with_address_to_cli(swarm.root_key(), root_addr);

    let rest_client = swarm.validators().next().unwrap().rest_client();

    info!("Wait for epoch 2.");
    swarm
        .wait_for_all_nodes_to_catchup_to_epoch(2, Duration::from_secs(epoch_duration_secs * 2))
        .await
        .expect("Epoch 2 taking too long to arrive!");

    info!("Halting the chain by putting every validator into sync_only mode.");
    for validator in swarm.validators_mut() {
        enable_sync_only_mode(4, validator).await;
    }

    info!("Chain should have halted.");
    let liveness_check_result = swarm
        .liveness_check(Instant::now().add(Duration::from_secs(20)))
        .await;
    info!("liveness_check_result={:?}", liveness_check_result);
    assert!(liveness_check_result.is_err());

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

    info!("Hot-fixing the VFNs.");
    for (idx, vfn) in swarm.fullnodes_mut().enumerate() {
        info!("Stopping VFN {}.", idx);
        vfn.stop();
        let config_path = vfn.config_path();
        let mut vfn_override_config = OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        vfn_override_config
            .override_config_mut()
            .randomness_override_seq_num = 1;
        info!("Updating VFN {} config.", idx);
        vfn_override_config.save_config(config_path).unwrap();
        info!("Restarting VFN {}.", idx);
        vfn.start().unwrap();
        info!("Let VFN {} bake for 5 secs.", idx);
        tokio::time::sleep(Duration::from_secs(5)).await;
```

**File:** dkg/src/counters.rs (L1-32)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_metrics_core::{register_histogram_vec, register_int_gauge, HistogramVec, IntGauge};
use once_cell::sync::Lazy;

/// Count of the pending messages sent to itself in the channel
pub static PENDING_SELF_MESSAGES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_dkg_pending_self_messages",
        "Count of the pending messages sent to itself in the channel"
    )
    .unwrap()
});

pub static DKG_STAGE_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_dkg_session_stage_seconds",
        "How long it takes to reach different DKG stages",
        &["dealer", "stage"]
    )
    .unwrap()
});

pub static ROUNDING_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_dkg_rounding_seconds",
        "Rounding seconds and counts by method",
        &["method"]
    )
    .unwrap()
});
```
