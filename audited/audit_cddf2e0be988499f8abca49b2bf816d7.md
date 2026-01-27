# Audit Report

## Title
JWK Consensus Epoch Transition Deadlock Due to Unbounded Network Request Timeout

## Summary
The JWK consensus epoch manager's shutdown mechanism lacks timeout protection at multiple levels, allowing indefinite blocking during epoch transitions. When a JWKObserver is fetching JWKs from a remote OIDC provider and the network request hangs, the entire epoch transition for the JWK consensus subsystem becomes blocked, requiring manual node restart to recover.

## Finding Description

The vulnerability exists in a multi-level blocking chain during JWK consensus epoch shutdown:

**Level 1: Unbounded Shutdown Wait**
The `shutdown_current_processor()` method waits indefinitely for acknowledgment from the JWK consensus manager without any timeout: [1](#0-0) 

**Level 2: Observer Shutdown Chain**
When the JWK consensus manager receives the shutdown signal, it must wait for all JWKObservers to complete shutdown: [2](#0-1) 

**Level 3: Task Join Without Timeout**
Each JWKObserver's shutdown waits for its background task to complete without timeout: [3](#0-2) 

**Level 4: Blocking Network Request**
The critical issue is in the observer's event loop. When the `interval.tick()` branch is selected, the handler calls `fetch_jwks(...).await` which is NOT inside the tokio::select!: [4](#0-3) 

Once a select! branch handler starts executing, it runs to completion before the next select! iteration. If `fetch_jwks` blocks indefinitely, the `close_rx` signal cannot be processed.

**Level 5: HTTP Request Without Timeout**
The underlying HTTP request has no timeout configured: [5](#0-4) 

The `reqwest::Client::new()` creates a client without explicit timeout configuration, and the network request can hang indefinitely if the remote OIDC provider is unresponsive or the network connection is degraded.

**Attack/Failure Scenario:**
1. Validator node is running with JWK consensus enabled
2. A JWKObserver is periodically fetching JWKs from an OIDC provider
3. An epoch transition begins, triggering shutdown of the old epoch's JWK manager
4. At the moment of shutdown signal, the observer is executing `fetch_jwks(...).await`
5. The remote OIDC provider is unresponsive or network is experiencing connectivity issues
6. The HTTP request hangs indefinitely (no timeout configured)
7. The observer task cannot process the close signal
8. The shutdown method waits indefinitely on `join_handle.await`
9. The tear_down method waits indefinitely on `join_all(futures).await`
10. The epoch manager waits indefinitely on `ack_rx.await`
11. The JWK consensus subsystem cannot transition to the new epoch

**Important Clarification on Impact:**
While this blocks the JWK consensus subsystem's epoch transition, it does NOT block the main consensus. The main consensus EpochManager operates independently with its own reconfig notification listener: [6](#0-5) 

The architecture uses separate subscription services where JWK consensus and main consensus each have independent epoch management: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** based on the Aptos bug bounty criteria:

**Affected Systems:**
- JWK consensus subsystem becomes stuck and cannot process JWK updates in the new epoch
- OIDC authentication infrastructure is impaired as JWK updates cannot be validated
- Validator transaction pool will not receive new JWK update transactions
- Node requires manual restart to recover

**NOT Affected:**
- Main AptosBFT consensus continues operating normally
- Network liveness and safety are preserved
- Other validators can continue producing blocks
- No funds are at risk

This meets the "High Severity" criteria of "Validator node slowdowns" and "Significant protocol violations" as the JWK consensus feature becomes unavailable and requires operational intervention. While not Critical (since main consensus is unaffected), it represents a significant availability issue for an important authentication subsystem.

## Likelihood Explanation

**High Likelihood** - This vulnerability can occur naturally without any malicious intent:

**Triggering Conditions (All Common):**
1. Network connectivity issues to OIDC providers (common in distributed systems)
2. OIDC provider experiencing high load or outages (Google, Facebook services can be slow)
3. Firewall or routing issues causing connection hangs
4. DNS resolution failures causing long timeouts
5. Epoch transitions occur regularly in Aptos (configuration changes, validator set updates)

**No Attacker Required:**
- This is a reliability/availability bug, not requiring malicious action
- Normal network degradation is sufficient to trigger it
- OIDC providers are external third-party services beyond validator control

**Frequency:**
- Epochs transition periodically based on governance actions
- JWK observers fetch every 10 seconds (configurable): [8](#0-7) 
- High probability that shutdown occurs during an active fetch operation

## Recommendation

Implement timeout protection at multiple levels:

**1. Add HTTP Request Timeout:**
```rust
// In crates/jwk-utils/src/lib.rs
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))  // Add timeout
        .build()?;
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

**2. Add Timeout to Observer Shutdown:**
```rust
// In crates/aptos-jwk-consensus/src/jwk_observer.rs
pub async fn shutdown(self) {
    let Self { close_tx, join_handle } = self;
    let _ = close_tx.send(());
    let _ = tokio::time::timeout(
        Duration::from_secs(15),
        join_handle
    ).await;
}
```

**3. Add Timeout to Epoch Manager Shutdown:**
```rust
// In crates/aptos-jwk-consensus/src/epoch_manager.rs
async fn shutdown_current_processor(&mut self) {
    if let Some(tx) = self.jwk_manager_close_tx.take() {
        let (ack_tx, ack_rx) = oneshot::channel();
        let _ = tx.send(ack_tx);
        let _ = tokio::time::timeout(
            Duration::from_secs(30),
            ack_rx
        ).await;
    }
    self.jwk_updated_event_txs = None;
}
```

**4. Make fetch_jwks Cancellable:**
Use `tokio::select!` around the fetch operation in the observer loop so it can be interrupted:
```rust
// In observer start loop
tokio::select! {
    _ = interval.tick().fuse() => {
        let timer = Instant::now();
        tokio::select! {
            result = fetch_jwks(open_id_config_url.as_str(), my_addr) => {
                // Process result
            },
            _ = &mut close_rx => {
                break;
            }
        }
    },
    _ = close_rx.select_next_some() => {
        break;
    }
}
```

## Proof of Concept

```rust
// PoC demonstrating the hang (pseudo-code for clarity)
#[tokio::test]
async fn test_jwk_epoch_transition_hang() {
    // Setup: Start JWK consensus with a mock OIDC provider that hangs
    let mock_server = start_hanging_oidc_server().await;
    let epoch_manager = setup_jwk_epoch_manager(&mock_server.url()).await;
    
    // Trigger: Start JWK observer which will attempt to fetch
    epoch_manager.start_new_epoch(config).await;
    
    // Wait for observer to be mid-fetch
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Attempt epoch transition (shutdown old epoch)
    let shutdown_future = epoch_manager.shutdown_current_processor();
    
    // Verify: Shutdown hangs indefinitely (would timeout in real test)
    tokio::time::timeout(
        Duration::from_secs(5),
        shutdown_future
    ).await.expect_err("Shutdown should timeout but doesn't");
    
    // Expected: Timeout error
    // Actual: Hangs indefinitely without timeout protection
}
```

**Reproduction Steps:**
1. Configure validator with JWK consensus enabled
2. Configure OIDC provider pointing to an unresponsive server
3. Wait for JWK observer to start fetching
4. Trigger epoch transition (via governance or configuration change)
5. Observe that the node logs show JWK consensus stuck in shutdown
6. Main consensus continues but JWK updates stop processing
7. Node requires restart to recover JWK consensus functionality

**Notes:**
- This is a production reliability issue affecting validator operations
- External OIDC providers (Google, Facebook, etc.) can experience outages
- Without timeout protection, validators lose the JWK consensus feature during network issues
- The bug violates the principle of defensive timeout handling in distributed systems

### Citations

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L266-274)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(tx) = self.jwk_manager_close_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            let _ = tx.send(ack_tx);
            let _ = ack_rx.await;
        }

        self.jwk_updated_event_txs = None;
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L117-124)
```rust
                    (Ok(issuer), Ok(config_url)) => Some(JWKObserver::spawn(
                        this.epoch_state.epoch,
                        this.my_addr,
                        issuer,
                        config_url,
                        Duration::from_secs(10),
                        local_observation_tx.clone(),
                    )),
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L170-181)
```rust
    async fn tear_down(&mut self, ack_tx: Option<oneshot::Sender<()>>) -> Result<()> {
        self.stopped = true;
        let futures = std::mem::take(&mut self.jwk_observers)
            .into_iter()
            .map(JWKObserver::shutdown)
            .collect::<Vec<_>>();
        join_all(futures).await;
        if let Some(tx) = ack_tx {
            let _ = tx.send(());
        }
        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L70-89)
```rust
        loop {
            tokio::select! {
                _ = interval.tick().fuse() => {
                    let timer = Instant::now();
                    let result = fetch_jwks(open_id_config_url.as_str(), my_addr).await;
                    debug!(issuer = issuer, "observe_result={:?}", result);
                    let secs = timer.elapsed().as_secs_f64();
                    if let Ok(mut jwks) = result {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "ok"]).observe(secs);
                        jwks.sort();
                        let _ = observation_tx.push((), (issuer.as_bytes().to_vec(), jwks));
                    } else {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "err"]).observe(secs);
                    }
                },
                _ = close_rx.select_next_some() => {
                    break;
                }
            }
        }
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L92-99)
```rust
    pub async fn shutdown(self) {
        let Self {
            close_tx,
            join_handle,
        } = self;
        let _ = close_tx.send(());
        let _ = join_handle.await;
    }
```

**File:** crates/jwk-utils/src/lib.rs (L25-37)
```rust
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

**File:** consensus/src/epoch_manager.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    block_storage::{
        pending_blocks::PendingBlocks,
        tracing::{observe_block, BlockStage},
        BlockStore,
    },
    consensus_observer::publisher::consensus_publisher::ConsensusPublisher,
    counters,
    dag::{DagBootstrapper, DagCommitSigner, StorageAdapter},
    error::{error_kind, DbError},
    liveness::{
        cached_proposer_election::CachedProposerElection,
        leader_reputation::{
            extract_epoch_to_proposers, AptosDBBackend, LeaderReputation,
            ProposerAndVoterHeuristic, ReputationHeuristic,
        },
        proposal_generator::{
            ChainHealthBackoffConfig, PipelineBackpressureConfig, ProposalGenerator,
        },
        proposal_status_tracker::{ExponentialWindowFailureTracker, OptQSPullParamsProvider},
        proposer_election::ProposerElection,
        rotating_proposer_election::{choose_leader, RotatingProposer},
        round_proposer_election::RoundProposer,
        round_state::{ExponentialTimeInterval, RoundState},
    },
    logging::{LogEvent, LogSchema},
    metrics_safety_rules::MetricsSafetyRules,
    monitor,
    network::{
        DeprecatedIncomingBlockRetrievalRequest, IncomingBatchRetrievalRequest,
        IncomingBlockRetrievalRequest, IncomingDAGRequest, IncomingRandGenRequest,
        IncomingRpcRequest, IncomingSecretShareRequest, NetworkReceivers, NetworkSender,
    },
    network_interface::{ConsensusMsg, ConsensusNetworkClient},
    payload_client::{
        mixed::MixedPayloadClient, user::quorum_store_client::QuorumStoreClient, PayloadClient,
    },
    payload_manager::{DirectMempoolPayloadManager, TPayloadManager},
    persistent_liveness_storage::{LedgerRecoveryData, PersistentLivenessStorage, RecoveryData},
    pipeline::execution_client::TExecutionClient,
    quorum_store::{
        quorum_store_builder::{DirectMempoolInnerBuilder, InnerBuilder, QuorumStoreBuilder},
        quorum_store_coordinator::CoordinatorCommand,
        quorum_store_db::QuorumStoreStorage,
    },
    rand::rand_gen::{
        storage::interface::RandStorage,
```

**File:** crates/aptos-jwk-consensus/src/lib.rs (L25-50)
```rust
pub fn start_jwk_consensus_runtime(
    my_addr: AccountAddress,
    safety_rules_config: &SafetyRulesConfig,
    network_client: NetworkClient<JWKConsensusMsg>,
    network_service_events: NetworkServiceEvents<JWKConsensusMsg>,
    reconfig_events: ReconfigNotificationListener<DbBackedOnChainConfig>,
    jwk_updated_events: EventNotificationListener,
    vtxn_pool_writer: VTxnPoolState,
) -> Runtime {
    let runtime = aptos_runtimes::spawn_named_runtime("jwk".into(), Some(4));
    let (self_sender, self_receiver) = aptos_channels::new(1_024, &counters::PENDING_SELF_MESSAGES);
    let jwk_consensus_network_client = JWKConsensusNetworkClient::new(network_client);
    let epoch_manager = EpochManager::new(
        my_addr,
        safety_rules_config,
        reconfig_events,
        jwk_updated_events,
        self_sender,
        jwk_consensus_network_client,
        vtxn_pool_writer,
    );
    let (network_task, network_receiver) = NetworkTask::new(network_service_events, self_receiver);
    runtime.spawn(network_task.start());
    runtime.spawn(epoch_manager.start(network_receiver));
    runtime
}
```
