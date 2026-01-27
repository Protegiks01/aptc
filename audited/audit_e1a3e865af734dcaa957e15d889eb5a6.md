# Audit Report

## Title
Epoch Transition Hang Due to Unresponsive OIDC Provider in JWK Observer Shutdown

## Summary
The JWK consensus manager's shutdown mechanism can hang indefinitely if an OIDC provider becomes unresponsive during HTTP requests, preventing epoch transitions and causing a denial-of-service condition at the consensus level. A malicious or compromised OIDC provider can exploit the lack of HTTP timeouts to block validator nodes from progressing to new epochs.

## Finding Description

The vulnerability exists in the resource cleanup path of the JWK consensus system, specifically in how observer tasks are shut down during epoch transitions.

**Root Cause Chain:**

1. **Missing HTTP Timeouts**: The HTTP client used to fetch JWKs has no timeout configuration. [1](#0-0) [2](#0-1) 

2. **Observer Task Blocking**: When a JWKObserver fetches JWKs, it awaits the HTTP request outside of the `tokio::select!` cancellation scope. [3](#0-2) 

   Once `interval.tick()` completes and execution enters that branch, the task calls `fetch_jwks().await` without the ability to respond to the close signal until the fetch completes. If the HTTP request hangs indefinitely, the observer task hangs.

3. **Blocking Shutdown**: The `tear_down()` function uses `join_all()` to wait for all observer shutdowns to complete. [4](#0-3) 

   Each observer's `shutdown()` method awaits the task's `join_handle`. [5](#0-4) 

   Since `join_all()` waits for ALL futures to complete, a single hanging observer blocks the entire shutdown process.

4. **Epoch Transition Hang**: The epoch manager's shutdown process waits indefinitely for the acknowledgment. [6](#0-5) 

   This is called during epoch transitions, blocking the node from progressing. [7](#0-6) 

**Attack Vector:**
An attacker who controls or can man-in-the-middle an OIDC provider listed in the on-chain `SupportedOIDCProviders` configuration can make HTTP responses hang indefinitely (e.g., accept the connection but never send data). When an epoch transition occurs, the affected validator node will hang during shutdown and fail to transition to the new epoch.

## Impact Explanation

**Severity: High to Critical** (depending on scope)

This vulnerability affects **consensus liveness**, violating the system's availability guarantees:

- **Individual Node Impact (High)**: A single affected validator experiences "Validator node slowdowns" and inability to participate in epoch transitions, meeting the High severity criteria ($50,000 tier).

- **Network-Wide Impact (Critical)**: If multiple validators are affected simultaneously (either through multiple compromised OIDC providers or a single popular provider used by many validators), this could lead to "Total loss of liveness/network availability" as the validator set cannot transition epochs, meeting Critical severity criteria ($1,000,000 tier).

The attack directly prevents the epoch transition mechanism, which is critical for:
- Validator set rotation
- On-chain configuration updates
- Consensus protocol progression

## Likelihood Explanation

**Likelihood: Medium to High**

**Requirements:**
1. Attacker must control or MITM an OIDC provider in the `SupportedOIDCProviders` on-chain configuration
2. Timing must coincide with epoch transitions (which occur periodically)

**Feasibility:**
- OIDC providers are external services (Google, Facebook, etc.) that validators must connect to
- DNS hijacking, BGP hijacking, or compromise of the OIDC provider infrastructure could enable this attack
- No special validator privileges required
- The attack is sustainable (can be maintained across multiple epochs)
- Detection may be delayed as HTTP hangs can appear as network issues

**Mitigation Factors:**
- Requires external infrastructure compromise or network-level attacks
- Diverse OIDC providers may limit single-point-of-failure scenarios
- Observable through monitoring (missing epoch transitions)

## Recommendation

**Immediate Fix: Add HTTP Timeouts**

Add explicit timeouts to the HTTP client configuration:

```rust
// In crates/jwk-utils/src/lib.rs
use std::time::Duration;

const JWK_FETCH_TIMEOUT_SECS: u64 = 30;

pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(JWK_FETCH_TIMEOUT_SECS))
        .build()?;
    // ... rest of implementation
}

pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(JWK_FETCH_TIMEOUT_SECS))
        .build()?;
    // ... rest of implementation
}
```

**Additional Hardening:**

1. **Add Shutdown Timeout**: Add a timeout to the shutdown acknowledgment wait in `shutdown_current_processor()`:
```rust
let _ = tokio::time::timeout(
    Duration::from_secs(60),
    ack_rx
).await;
```

2. **Restructure Observer Loop**: Move the fetch inside a timeout wrapper within the select to maintain cancellation:
```rust
tokio::select! {
    _ = interval.tick().fuse() => {
        if let Ok(result) = tokio::time::timeout(
            Duration::from_secs(30),
            fetch_jwks(...)
        ).await {
            // process result
        }
    },
    _ = close_rx.select_next_some() => {
        break;
    }
}
```

## Proof of Concept

```rust
// Rust test demonstrating the hang scenario
#[tokio::test]
async fn test_observer_shutdown_hang_with_unresponsive_provider() {
    use tokio::time::{timeout, Duration};
    use warp::Filter;
    
    // Create a mock OIDC provider that accepts connections but never responds
    let hanging_route = warp::path!(".well-known" / "openid-configuration")
        .and_then(|| async {
            tokio::time::sleep(Duration::from_secs(3600)).await; // Hang for 1 hour
            Ok::<_, warp::Rejection>(warp::reply())
        });
    
    let server = warp::serve(hanging_route);
    let (addr, server_fut) = server.bind_ephemeral(([127, 0, 0, 1], 0));
    tokio::spawn(server_fut);
    
    // Create observer pointing to hanging server
    let (tx, _rx) = aptos_channel::new(QueueStyle::KLAST, 10, None);
    let observer = JWKObserver::spawn(
        1,
        AccountAddress::random(),
        "test_issuer".to_string(),
        format!("http://127.0.0.1:{}/.well-known/openid-configuration", addr.port()),
        Duration::from_millis(100), // Fetch frequently
        tx,
    );
    
    // Wait for observer to start fetching
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Attempt shutdown with timeout - this should timeout, demonstrating the hang
    let shutdown_result = timeout(
        Duration::from_secs(5),
        observer.shutdown()
    ).await;
    
    // This assertion will fail, proving the vulnerability
    assert!(
        shutdown_result.is_ok(),
        "Observer shutdown should complete within timeout, but it hangs indefinitely"
    );
}
```

## Notes

This vulnerability specifically addresses the security question about whether `join_all()` properly handles failing observers. While `join_all()` correctly handles errors and panics (they don't prevent other observers from cleaning up), it does NOT handle **hanging** futures - a single hanging observer blocks the entire shutdown process because `join_all()` waits for all futures to complete.

The issue is particularly severe because:
1. It affects the critical epoch transition path
2. External OIDC providers are outside the trust boundary
3. Network conditions or provider issues can inadvertently trigger this
4. The attack is sustainable and hard to distinguish from legitimate network problems

### Citations

**File:** crates/jwk-utils/src/lib.rs (L29-29)
```rust
    let client = reqwest::Client::new();
```

**File:** crates/jwk-utils/src/lib.rs (L41-41)
```rust
    let client = reqwest::Client::new();
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L72-84)
```rust
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
