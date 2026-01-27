# Audit Report

## Title
Indefinite Validator Hang During Epoch Transition Due to Missing HTTP Timeout in JWK Observer Shutdown

## Summary
The JWK consensus observer shutdown process lacks HTTP request timeouts, allowing slow or unresponsive OIDC providers to indefinitely block validator epoch transitions, causing validator downtime and consensus participation failure.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Missing HTTP Timeout**: The `fetch_jwks` functions create reqwest HTTP clients without timeout configuration. [1](#0-0) [2](#0-1) 

2. **Non-Preemptible Observer Loop**: The JWK observer's main loop uses `tokio::select!` but once the `interval.tick()` branch executes, the HTTP request runs to completion before the close signal can be checked. [3](#0-2) 

3. **Blocking Shutdown**: The `tear_down()` function waits for all observers to complete shutdown using `join_all`, which blocks until every observer's join handle completes. [4](#0-3) 

4. **Epoch Transition Dependency**: During epoch transitions, the epoch manager must complete the shutdown before proceeding. [5](#0-4) 

**Exploitation Path:**

1. Validator runs with active JWK observers monitoring governance-approved OIDC providers
2. An OIDC provider becomes unresponsive (network issue, DDoS, outage, firewall)
3. An observer's HTTP request to that provider hangs indefinitely
4. Epoch transition begins, triggering `shutdown_current_processor()`
5. The shutdown waits for `ack_rx.await`, which depends on `tear_down()` completing
6. `tear_down()` waits for all observers via `join_all(futures).await`
7. The hanging observer cannot process the close signal because it's blocked in `fetch_jwks(...).await`
8. The validator becomes stuck and cannot transition to the new epoch
9. Validator cannot participate in consensus for the new epoch, losing rewards and harming network availability

**Broken Invariants:**
- Validators must be able to transition between epochs to maintain consensus participation
- System operations should have bounded execution time to prevent indefinite hangs

## Impact Explanation

This is **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns/unavailability**: Affected validators become completely stuck during epoch transitions, unable to participate in consensus
- **Loss of validator rewards**: Validators miss all block proposals and voting opportunities in the new epoch until manual intervention
- **Network decentralization impact**: If multiple validators are affected simultaneously (e.g., due to a popular OIDC provider outage), network performance degrades

While not reaching Critical severity (no permanent fund loss or consensus safety violation), this qualifies as High because it causes validator downtime requiring intervention. The issue affects validator liveness, which is a "Significant protocol violation" category.

## Likelihood Explanation

**High Likelihood:**

1. **Common Occurrence**: Network timeouts, provider outages, and connectivity issues are routine operational events
2. **External Dependency**: Validators depend on external OIDC providers (Google, Facebook, etc.) whose availability they cannot control
3. **No Special Access Required**: The vulnerability triggers through normal operation, not malicious action
4. **Timing Window**: The issue occurs whenever an HTTP request is in progress during epoch transition (which happens regularly)
5. **Observable Pattern**: Many other reqwest client creations in the codebase properly set timeouts (10-60 seconds), indicating this is a recognized best practice [6](#0-5) 

## Recommendation

Add explicit timeouts to HTTP requests in the JWK utilities library:

```rust
// In crates/jwk-utils/src/lib.rs

use std::time::Duration;

// Add constant for timeout
const JWK_FETCH_TIMEOUT_SECS: u64 = 30;

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

**Additional Safeguard**: Consider adding a shutdown timeout at the `tear_down` level using `tokio::time::timeout`:

```rust
async fn tear_down(&mut self, ack_tx: Option<oneshot::Sender<()>>) -> Result<()> {
    self.stopped = true;
    let futures = std::mem::take(&mut self.jwk_observers)
        .into_iter()
        .map(JWKObserver::shutdown)
        .collect::<Vec<_>>();
    
    // Add timeout to prevent indefinite hang
    match tokio::time::timeout(Duration::from_secs(60), join_all(futures)).await {
        Ok(_) => info!("All observers shut down successfully"),
        Err(_) => warn!("Observer shutdown timed out after 60s"),
    }
    
    if let Some(tx) = ack_tx {
        let _ = tx.send(());
    }
    Ok(())
}
```

## Proof of Concept

Create a Rust test that simulates a hanging OIDC provider:

```rust
#[tokio::test]
async fn test_hanging_oidc_provider_blocks_shutdown() {
    use std::sync::Arc;
    use tokio::time::{sleep, Duration, timeout};
    use axum::{Router, routing::get};
    
    // Start a slow OIDC provider that never responds
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(|| async {
            sleep(Duration::from_secs(3600)).await; // Hang for 1 hour
            "never reaches here"
        }));
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    
    // Create JWK observer pointing to hanging provider
    let (tx, _rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
    let observer = JWKObserver::spawn(
        1,
        AccountAddress::random(),
        "test_issuer".to_string(),
        format!("http://{}", addr),
        Duration::from_millis(100), // Fetch frequently
        tx,
    );
    
    // Wait for observer to start fetching
    sleep(Duration::from_millis(200)).await;
    
    // Try to shutdown - this will hang indefinitely without the fix
    let shutdown_result = timeout(
        Duration::from_secs(5),
        observer.shutdown()
    ).await;
    
    assert!(
        shutdown_result.is_err(),
        "Shutdown should timeout because HTTP request has no timeout"
    );
}
```

This test demonstrates that without proper HTTP timeouts, the observer shutdown hangs indefinitely, which would block epoch transitions in production validators.

## Notes

This vulnerability affects all validators participating in JWK consensus and relies on OIDC providers configured through on-chain governance. [7](#0-6)  While OIDC providers are trusted entities selected by governance, their availability cannot be guaranteed, making this a realistic operational risk rather than a malicious attack scenario.

### Citations

**File:** crates/jwk-utils/src/lib.rs (L29-29)
```rust
    let client = reqwest::Client::new();
```

**File:** crates/jwk-utils/src/lib.rs (L41-41)
```rust
    let client = reqwest::Client::new();
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L71-88)
```rust
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
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L97-101)
```rust
        let futures = std::mem::take(&mut self.jwk_observers)
            .into_iter()
            .map(JWKObserver::shutdown)
            .collect::<Vec<_>>();
        join_all(futures).await;
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L266-271)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(tx) = self.jwk_manager_close_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            let _ = tx.send(ack_tx);
            let _ = ack_rx.await;
        }
```

**File:** keyless/pepper/service/src/utils.rs (L17-21)
```rust
pub fn create_request_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(CLIENT_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("Failed to build the request client!")
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L1-10)
```text
/// JWK functions and structs.
///
/// Note: An important design constraint for this module is that the JWK consensus Rust code is unable to
/// spawn a VM and make a Move function call. Instead, the JWK consensus Rust code will have to directly
/// write some of the resources in this file. As a result, the structs in this file are declared so as to
/// have a simple layout which is easily accessible in Rust.
module aptos_framework::jwks {
    use std::bcs;
    use std::error;
    use std::features;
```
