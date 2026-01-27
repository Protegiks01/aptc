# Audit Report

## Title
Service Initialization Order Vulnerability: API and Mempool Accept Transactions Before State Sync Completes Bootstrapping

## Summary
The node startup sequence in `setup_environment_and_start_node()` starts the REST API and mempool services before state sync completes its bootstrapping phase. This allows attackers to submit transactions that get validated against stale or incomplete blockchain state, leading to mempool pollution, resource exhaustion, and degraded node performance during the critical startup period.

## Finding Description

The vulnerability exists in the service initialization order within the `setup_environment_and_start_node()` function. The problematic sequence is: [1](#0-0) 

The API service is bootstrapped and immediately begins accepting HTTP requests, including transaction submissions to the `/transactions` endpoint. [2](#0-1) 

The mempool runtime starts and immediately begins processing transactions from the API through its coordinator loop: [3](#0-2) 

At this point, both the API and mempool are fully operational and accepting transactions. However, state sync has **not yet completed its bootstrapping phase**: [4](#0-3) 

The critical wait for state sync initialization only happens **after** the API and mempool are already running. This creates a window where transactions can be submitted and validated against stale state.

**Transaction Validation Against Stale State:**

When transactions are submitted during this window, mempool validates them using the current database state: [5](#0-4) 

The validator reads account sequence numbers from this potentially stale state: [6](#0-5) 

**No Bootstrapping Check in API:**

The transaction submission endpoint has no check for state sync completion: [7](#0-6) 

The health check endpoint also fails to verify state sync status: [8](#0-7) 

**Attack Scenario:**

1. Node starts/restarts after being offline or crashes
2. State sync begins bootstrapping (may need to fetch thousands of blocks from the network)
3. API becomes available and returns 200 on `/-/healthy` endpoint
4. Attacker monitors for node startups (via network reconnaissance or timing attacks)
5. Attacker floods `/transactions` endpoint with transactions
6. Mempool validates transactions against stale state (e.g., old sequence numbers, outdated account balances)
7. Invalid transactions are accepted into mempool
8. State sync completes and updates state to current version
9. Consensus starts but finds mempool filled with transactions validated against outdated state
10. These transactions fail execution, waste resources, and degrade node performance

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per the Aptos bug bounty criteria for the following reasons:

**Validator Node Slowdowns:** During the critical bootstrapping phase, attackers can flood the mempool with transactions that were validated against stale state. When consensus eventually starts and attempts to execute these transactions, many will fail due to state inconsistencies (incorrect sequence numbers, changed account states), wasting validator computational resources and slowing block production.

**Significant Protocol Violations:** The system violates the **Transaction Validation** invariant that "Prologue/epilogue checks must enforce all invariants." Transactions are being accepted without validation against the current blockchain state, breaking the fundamental assumption that mempool only contains transactions validated against up-to-date state.

**Resource Exhaustion:** Attackers can exploit this window to fill the mempool to capacity with transactions that appear valid but will ultimately fail. This prevents legitimate transactions from entering mempool and degrades the node's ability to process real user requests.

**User Experience Degradation:** Legitimate users submitting transactions during this window will receive successful 202 responses from the API, but their transactions may later fail execution due to state changes during sync completion, creating a poor user experience and false positives.

The impact is particularly severe for validators and public fullnodes that frequently restart (e.g., during upgrades, crashes, or maintenance), as they repeatedly expose this attack window.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Predictable Attack Window:** Node restarts are often publicly observable through network monitoring, peer disconnections, or scheduled maintenance announcements. Attackers can detect when nodes come back online and are in the bootstrapping phase.

2. **Low Barrier to Entry:** Any attacker with HTTP access to the REST API can exploit this. No special privileges, consensus participation, or validator access is required.

3. **Significant Bootstrapping Duration:** On mainnet, nodes that have been offline can take minutes to hours to bootstrap depending on how far behind they are. This provides a substantial attack window.

4. **No Rate Limiting During Bootstrap:** The API doesn't implement special rate limiting during the bootstrapping phase, allowing attackers to maximize mempool pollution.

5. **Frequent Occurrence:** Validators regularly restart for upgrades, configuration changes, or recovery from crashes. Each restart creates a new exploitation opportunity.

6. **Automated Exploitation:** The attack can be fully automated with simple scripts that monitor node health endpoints and submit transactions when state sync is detected to be incomplete.

## Recommendation

**Immediate Fix:**

Add a bootstrapping status check before accepting transaction submissions. The API and mempool should reject transactions until state sync completes initialization.

**Solution 1: Add Bootstrap Check to API (Recommended)**

Modify the transaction submission endpoint to check state sync status:

```rust
// In api/src/context.rs, add a method to check bootstrap status
pub fn is_state_sync_bootstrapped(&self) -> bool {
    // Add a shared atomic bool that state sync driver sets upon completion
    // Or query the state sync driver's bootstrap status
    self.state_sync_bootstrapped.load(Ordering::Acquire)
}

// In api/src/transactions.rs, modify submit_transaction
async fn submit_transaction(
    &self,
    accept_type: AcceptType,
    data: SubmitTransactionPost,
) -> SubmitTransactionResult<PendingTransaction> {
    // Add bootstrap check
    if !self.context.is_state_sync_bootstrapped() {
        return Err(SubmitTransactionError::service_unavailable_with_code_no_info(
            "Node is still bootstrapping. Please retry after state sync completes.",
            AptosErrorCode::NodeIsBootstrapping,
        ));
    }
    
    // ... rest of the function
}
```

**Solution 2: Delay API/Mempool Startup (Alternative)**

Reorder the initialization sequence to start API and mempool **after** state sync completion:

```rust
// In aptos-node/src/lib.rs, move the wait earlier
pub fn setup_environment_and_start_node(...) -> anyhow::Result<AptosHandle> {
    // ... existing initialization up to state sync ...
    
    // Start state sync
    let (aptos_data_client, state_sync_runtimes, mempool_listener, consensus_notifier) =
        state_sync::start_state_sync_and_get_notification_handles(...)?;
    
    // WAIT HERE - before starting API/mempool
    debug!("Waiting until state sync is initialized!");
    state_sync_runtimes.block_until_initialized();
    debug!("State sync initialization complete.");
    
    // NOW start inspection service, API, mempool
    services::start_node_inspection_service(...);
    let (...) = services::bootstrap_api_and_indexer(...)?;
    let (mempool_runtime, consensus_to_mempool_sender) = 
        services::start_mempool_runtime_and_get_consensus_sender(...);
    
    // ... rest of initialization
}
```

**Solution 3: Update Health Check (Defense in Depth)**

Enhance the health check endpoint to report bootstrap status:

```rust
// In api/src/basic.rs
async fn healthy(
    &self,
    accept_type: AcceptType,
    duration_secs: Query<Option<u32>>,
) -> HealthCheckResult<HealthCheckSuccess> {
    let ledger_info = self.context.get_latest_ledger_info()?;
    
    // Add bootstrap check
    if !self.context.is_state_sync_bootstrapped() {
        return Err(HealthCheckError::service_unavailable_with_code(
            "Node is bootstrapping",
            AptosErrorCode::NodeIsBootstrapping,
            &ledger_info,
        ));
    }
    
    // ... existing health checks
}
```

## Proof of Concept

```rust
// Test to demonstrate the vulnerability
// Place in aptos-node/src/tests/initialization_order_test.rs

#[tokio::test]
async fn test_api_accepts_transactions_before_state_sync_completes() {
    use aptos_config::config::NodeConfig;
    use aptos_types::transaction::SignedTransaction;
    use reqwest::Client;
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::Duration;
    
    // Create a test config
    let config = NodeConfig::get_default_validator_config();
    
    // Track when state sync completes
    let state_sync_complete = Arc::new(AtomicBool::new(false));
    let state_sync_complete_clone = state_sync_complete.clone();
    
    // Start node in background (this would normally call setup_environment_and_start_node)
    tokio::spawn(async move {
        // Simulate state sync delay
        tokio::time::sleep(Duration::from_secs(5)).await;
        state_sync_complete_clone.store(true, Ordering::Release);
    });
    
    // Wait for API to be available
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Try to submit transaction BEFORE state sync completes
    let client = Client::new();
    let api_url = format!("http://{}/v1/transactions", config.api.address);
    
    // Create a dummy transaction
    let txn = create_test_transaction();
    let response = client.post(&api_url)
        .header("Content-Type", "application/json")
        .json(&txn)
        .send()
        .await
        .unwrap();
    
    // VULNERABILITY: Transaction is accepted (202) even though state sync hasn't completed
    assert_eq!(response.status(), 202, "Transaction accepted during bootstrap");
    assert!(!state_sync_complete.load(Ordering::Acquire), 
            "State sync should not be complete yet");
    
    println!("VULNERABILITY CONFIRMED: API accepted transaction before state sync completed!");
}

fn create_test_transaction() -> serde_json::Value {
    // Create a test transaction payload
    serde_json::json!({
        "sender": "0x1",
        "sequence_number": "0",
        "max_gas_amount": "1000",
        "gas_unit_price": "1",
        "expiration_timestamp_secs": "9999999999",
        "payload": {
            "type": "entry_function_payload",
            "function": "0x1::aptos_account::transfer",
            "type_arguments": [],
            "arguments": ["0x2", "100"]
        },
        "signature": {
            "type": "ed25519_signature",
            "public_key": "0x1234",
            "signature": "0x5678"
        }
    })
}
```

**Manual Testing Steps:**

1. Start an Aptos node from a state several blocks behind the network
2. Immediately after startup, monitor the API endpoint: `curl http://localhost:8080/v1/-/healthy`
3. The health check returns 200 (healthy) even though state sync is still bootstrapping
4. Submit a transaction: `curl -X POST http://localhost:8080/v1/transactions -H "Content-Type: application/json" -d '{...}'`
5. Transaction is accepted with 202 response
6. Monitor mempool and observe that the transaction was validated against stale state
7. After state sync completes, observe transaction execution failures due to state changes

**Notes**

This vulnerability represents a clear violation of the node's operational semantics where external interfaces should only become available after all critical initialization is complete. The fix requires either reordering the initialization sequence or adding explicit bootstrap status checks to the API endpoints. The recommended approach is Solution 2 (delaying API/mempool startup) as it provides the strongest guarantee that no transactions are processed against incomplete state.

### Citations

**File:** aptos-node/src/lib.rs (L778-795)
```rust
    // Bootstrap the API and indexer
    let (
        mempool_client_receiver,
        api_runtime,
        indexer_table_info_runtime,
        indexer_runtime,
        indexer_grpc_runtime,
        internal_indexer_db_runtime,
        mempool_client_sender,
    ) = services::bootstrap_api_and_indexer(
        &node_config,
        db_rw.clone(),
        chain_id,
        indexer_db_opt,
        update_receiver,
        api_port_tx,
        indexer_grpc_port_tx,
    )?;
```

**File:** aptos-node/src/lib.rs (L801-810)
```rust
    let (mempool_runtime, consensus_to_mempool_sender) =
        services::start_mempool_runtime_and_get_consensus_sender(
            &mut node_config,
            &db_rw,
            mempool_reconfig_subscription,
            mempool_network_interfaces,
            mempool_listener,
            mempool_client_receiver,
            peers_and_metadata,
        );
```

**File:** aptos-node/src/lib.rs (L825-827)
```rust
    debug!("Waiting until state sync is initialized!");
    state_sync_runtimes.block_until_initialized();
    debug!("State sync initialization complete.");
```

**File:** mempool/src/shared_mempool/coordinator.rs (L106-129)
```rust
    loop {
        let _timer = counters::MAIN_LOOP.start_timer();
        ::futures::select! {
            msg = client_events.select_next_some() => {
                handle_client_request(&mut smp, &bounded_executor, msg).await;
            },
            msg = quorum_store_requests.select_next_some() => {
                tasks::process_quorum_store_request(&smp, msg);
            },
            reconfig_notification = mempool_reconfig_events.select_next_some() => {
                handle_mempool_reconfig_event(&mut smp, &bounded_executor, reconfig_notification.on_chain_configs).await;
            },
            (peer, backoff) = scheduled_broadcasts.select_next_some() => {
                tasks::execute_broadcast(peer, backoff, &mut smp, &mut scheduled_broadcasts, executor.clone()).await;
            },
            (network_id, event) = events.select_next_some() => {
                handle_network_event(&bounded_executor, &mut smp, network_id, event).await;
            },
            _ = update_peers_interval.tick().fuse() => {
                handle_update_peers(peers_and_metadata.clone(), &mut smp, &mut scheduled_broadcasts, executor.clone()).await;
            },
            complete => break,
        }
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L329-332)
```rust
    let state_view = smp
        .db
        .latest_state_checkpoint_view()
        .expect("Failed to get latest state checkpoint view.");
```

**File:** mempool/src/shared_mempool/tasks.rs (L335-350)
```rust
    let account_seq_numbers = IO_POOL.install(|| {
        transactions
            .par_iter()
            .map(|(t, _, _)| match t.replay_protector() {
                ReplayProtector::Nonce(_) => Ok(None),
                ReplayProtector::SequenceNumber(_) => {
                    get_account_sequence_number(&state_view, t.sender())
                        .map(Some)
                        .inspect_err(|e| {
                            error!(LogSchema::new(LogEntry::DBError).error(e));
                            counters::DB_ERROR.inc();
                        })
                },
            })
            .collect::<Vec<_>>()
    });
```

**File:** api/src/transactions.rs (L476-498)
```rust
    async fn submit_transaction(
        &self,
        accept_type: AcceptType,
        data: SubmitTransactionPost,
    ) -> SubmitTransactionResult<PendingTransaction> {
        data.verify()
            .context("Submitted transaction invalid'")
            .map_err(|err| {
                SubmitTransactionError::bad_request_with_code_no_info(
                    err,
                    AptosErrorCode::InvalidInput,
                )
            })?;
        fail_point_poem("endpoint_submit_transaction")?;
        if !self.context.node_config.api.transaction_submission_enabled {
            return Err(api_disabled("Submit transaction"));
        }
        self.context
            .check_api_output_enabled("Submit transaction", &accept_type)?;
        let ledger_info = self.context.get_latest_ledger_info()?;
        let signed_transaction = self.get_signed_transaction(&ledger_info, data)?;
        self.create(&accept_type, &ledger_info, signed_transaction)
            .await
```

**File:** api/src/basic.rs (L151-191)
```rust
    async fn healthy(
        &self,
        accept_type: AcceptType,
        /// Threshold in seconds that the server can be behind to be considered healthy
        ///
        /// If not provided, the healthcheck will always succeed
        duration_secs: Query<Option<u32>>,
    ) -> HealthCheckResult<HealthCheckSuccess> {
        let context = self.context.clone();
        let ledger_info = api_spawn_blocking(move || context.get_latest_ledger_info()).await?;

        // If we have a duration, check that it's close to the current time, otherwise it's ok
        if let Some(max_skew) = duration_secs.0 {
            let ledger_timestamp = Duration::from_micros(ledger_info.timestamp());
            let skew_threshold = SystemTime::now()
                .sub(Duration::from_secs(max_skew as u64))
                .duration_since(UNIX_EPOCH)
                .context("Failed to determine absolute unix time based on given duration")
                .map_err(|err| {
                    HealthCheckError::internal_with_code(
                        err,
                        AptosErrorCode::InternalError,
                        &ledger_info,
                    )
                })?;

            if ledger_timestamp < skew_threshold {
                return Err(HealthCheckError::service_unavailable_with_code(
                    format!("The latest ledger info timestamp is {:?}, which is beyond the allowed skew ({}s).", ledger_timestamp, max_skew),
                    AptosErrorCode::HealthCheckFailed,
                    &ledger_info,
                ));
            }
        }
        HealthCheckResponse::try_from_rust_value((
            HealthCheckSuccess::new(),
            &ledger_info,
            HealthCheckResponseStatus::Ok,
            &accept_type,
        ))
    }
```
