# Audit Report

## Title
Unresponsive OIDC Provider Endpoints Can Block Epoch Transitions in JWK Consensus

## Summary
The `tear_down()` function in the JWK consensus manager waits indefinitely for all JWK observers to shut down before completing epoch transitions. JWK observers perform HTTP requests to OIDC provider endpoints without timeout configuration, allowing unresponsive endpoints to block observer shutdown, which in turn blocks epoch transitions and affects consensus liveness.

## Finding Description

During epoch transitions, the JWK consensus component must gracefully shut down before a new epoch begins. The shutdown flow follows this path:

1. **Epoch transition initiated**: When a new epoch starts, `on_new_epoch()` calls `shutdown_current_processor()` which waits for an acknowledgment from the JWK consensus manager. [1](#0-0) 

2. **Shutdown waits for acknowledgment**: The shutdown process sends a close signal and blocks waiting for the acknowledgment response. [2](#0-1) 

3. **tear_down() waits for all observers**: The acknowledgment is only sent after `tear_down()` completes, which uses `join_all()` to wait for ALL JWK observers to shut down. [3](#0-2) 

4. **Observer shutdown waits for task completion**: Each observer's shutdown method sends a close signal but then waits indefinitely for the spawned task to finish. [4](#0-3) 

5. **Task stuck in HTTP request**: The spawned task uses `tokio::select!` but if it's currently executing a `fetch_jwks()` call when the close signal arrives, it cannot process the close signal until the fetch completes. [5](#0-4) 

6. **No timeout on HTTP requests**: The HTTP requests to OIDC provider endpoints are made using `reqwest::Client::new()` without any timeout configuration, meaning requests can hang indefinitely if endpoints are unresponsive. [6](#0-5) 

**Attack Scenario:**
- An OIDC provider endpoint becomes unresponsive (due to operational issues, malicious behavior by the provider, or network problems)
- A JWK observer is in the middle of fetching from this endpoint when an epoch transition begins
- The HTTP request hangs indefinitely due to lack of timeout
- The observer cannot shut down
- The `tear_down()` function cannot complete
- The epoch transition acknowledgment is never sent
- The epoch transition is blocked

This violates the liveness invariant that epoch transitions should complete in a timely manner.

## Impact Explanation

This is a **Medium severity** vulnerability per the Aptos bug bounty criteria:

1. **Validator node slowdowns**: Blocked epoch transitions cause significant operational delays across all validator nodes, as they cannot proceed to the next epoch until the shutdown completes.

2. **State inconsistencies requiring intervention**: If epoch transitions are blocked for extended periods, it may require manual intervention to recover the network, creating an operational state that deviates from normal protocol operation.

3. **Liveness impact**: While this doesn't break consensus safety (validators won't commit conflicting blocks), it does affect network liveness by preventing progression to new epochs.

The issue does not qualify for Critical or High severity because:
- It doesn't cause permanent loss of funds or consensus safety violations
- It doesn't cause non-recoverable network partition
- It's a temporary liveness issue rather than a permanent failure

However, it's more severe than Low severity because it can cause significant operational impact affecting the entire validator set.

## Likelihood Explanation

This vulnerability has a **moderate to high likelihood** of occurrence:

1. **Natural occurrence**: OIDC provider endpoints can experience operational issues, network problems, or maintenance windows that make them temporarily unresponsive. This is a realistic scenario that doesn't require attacker action.

2. **No attacker privileges required**: If an OIDC provider is already configured on-chain (through governance), the provider operator could intentionally make their endpoint unresponsive to cause this issue.

3. **Network variability**: Network connectivity between validators and OIDC providers can be unreliable, especially for geographically distributed infrastructure.

4. **Timing window**: The vulnerability only triggers if a fetch operation is in progress when an epoch transition begins. Given that observers fetch periodically (every 10 seconds as configured), and epoch transitions happen regularly, there's a reasonable probability of this timing alignment.

The attack complexity is low - it only requires an endpoint to be unresponsive, which can happen naturally or be trivially induced by a malicious provider.

## Recommendation

Add timeout configuration to the HTTP client used for JWK fetching. The codebase already demonstrates the correct pattern in the keyless pepper service.

**Fix for `crates/jwk-utils/src/lib.rs`:**

```rust
use std::time::Duration;

// Define a reasonable timeout for JWK fetching operations
const JWK_FETCH_TIMEOUT_SECS: u64 = 10;

pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(JWK_FETCH_TIMEOUT_SECS))
        .build()?;
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}

pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(JWK_FETCH_TIMEOUT_SECS))
        .build()?;
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

This ensures that HTTP requests will timeout after a reasonable period, allowing the observer to shut down promptly during epoch transitions.

**Additional hardening**: Consider adding a timeout wrapper around the entire `tear_down()` operation to ensure epoch transitions can proceed even if observer shutdown takes too long:

```rust
async fn tear_down(&mut self, ack_tx: Option<oneshot::Sender<()>>) -> Result<()> {
    self.stopped = true;
    let futures = std::mem::take(&mut self.jwk_observers)
        .into_iter()
        .map(JWKObserver::shutdown)
        .collect::<Vec<_>>();
    
    // Add timeout for observer shutdown
    let shutdown_timeout = Duration::from_secs(30);
    if tokio::time::timeout(shutdown_timeout, join_all(futures)).await.is_err() {
        warn!("JWK observer shutdown timed out after {:?}", shutdown_timeout);
    }
    
    if let Some(tx) = ack_tx {
        let _ = tx.send(());
    }
    Ok(())
}
```

## Proof of Concept

```rust
// Test demonstrating the blocking behavior
// Add to crates/aptos-jwk-consensus/src/jwk_observer.rs test module

#[tokio::test]
async fn test_unresponsive_endpoint_blocks_shutdown() {
    use std::time::Duration;
    use tokio::time::{timeout, sleep};
    
    // Start a mock HTTP server that never responds
    let mock_server = tokio::spawn(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    // Accept connection but never send response
                    tokio::spawn(async move {
                        let _ = sleep(Duration::from_secs(3600)).await;
                        drop(socket);
                    });
                }
            }
        });
        addr
    });
    
    let server_addr = mock_server.await.unwrap();
    let (tx, _rx) = aptos_channel::new(QueueStyle::KLAST, 10, None);
    
    // Create observer pointing to unresponsive endpoint
    let observer = JWKObserver::spawn(
        1,
        AccountAddress::ZERO,
        "test_issuer".to_string(),
        format!("http://{}", server_addr),
        Duration::from_millis(100),
        tx,
    );
    
    // Wait for observer to start fetching
    sleep(Duration::from_millis(200)).await;
    
    // Try to shutdown with timeout - this will fail without the fix
    let shutdown_future = observer.shutdown();
    let result = timeout(Duration::from_secs(5), shutdown_future).await;
    
    // Without fix: timeout will occur
    // With fix: shutdown completes within timeout
    assert!(result.is_err(), 
        "Observer shutdown should timeout when endpoint is unresponsive (demonstrating vulnerability)");
}
```

## Notes

The vulnerability affects both `IssuerLevelConsensusManager` and `KeyLevelConsensusManager` as they share the same observer implementation. The fix should be applied to the shared `jwk-utils` crate to benefit both consensus modes.

Other parts of the codebase (keyless pepper service) already implement proper timeout handling for JWK fetching, demonstrating awareness of this requirement. [7](#0-6)

### Citations

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L259-264)
```rust
    async fn on_new_epoch(&mut self, reconfig_notification: ReconfigNotification<P>) -> Result<()> {
        self.shutdown_current_processor().await;
        self.start_new_epoch(reconfig_notification.on_chain_configs)
            .await?;
        Ok(())
    }
```

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

**File:** crates/jwk-utils/src/lib.rs (L25-44)
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

/// Given an Open ID configuration URL, fetch its JWK url.
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

**File:** keyless/pepper/service/src/utils.rs (L17-27)
```rust
pub fn create_request_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(CLIENT_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("Failed to build the request client!")
}

/// Extracts the origin header from the request
pub fn get_request_origin(request: &Request<Body>) -> String {
    request
        .headers()
```
