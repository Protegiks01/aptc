# Audit Report

## Title
Missing HTTP Response Timeout in MetricsPusher Causes Indefinite Hang During Service Initialization

## Summary
The `MetricsPusher::push()` method in `aptos-push-metrics/src/lib.rs` only sets an HTTP connection timeout but omits the response/read timeout. When combined with the `join()` method's indefinite wait behavior, this causes the `ProcessExecutorService` initialization to hang indefinitely if the metrics push gateway accepts connections but never responds, preventing critical executor service restarts during emergency procedures.

## Finding Description

The vulnerability involves two related issues in the MetricsPusher component:

**Issue 1: Missing Response Timeout**

The `push()` method makes HTTP requests to a metrics gateway but only configures connection timeout: [1](#0-0) 

This only limits the time to establish a TCP connection. If the server accepts the connection but never sends a response, the request blocks indefinitely. The correct pattern (as demonstrated in the Vault client) requires both timeouts: [2](#0-1) 

**Issue 2: Indefinite Wait in join()**

The `join()` method waits indefinitely for the worker thread to complete: [3](#0-2) 

When quit signal is sent, the worker performs a "final push" before exiting: [4](#0-3) 

If this final push encounters an unresponsive server (accepts connection but never responds), the worker thread hangs, and `join()` waits indefinitely.

**Issue 3: Blocking Service Initialization**

The `ProcessExecutorService` (used for sharded execution in production validators) creates a MetricsPusher during initialization but immediately drops it: [5](#0-4) 

Since `_mp` is a local variable, it's dropped when `new()` returns at line 44. The Drop trait calls `join()`: [6](#0-5) 

**Attack Scenario:**
1. Attacker controls or compromises the metrics push gateway endpoint, or network issues cause gateway unresponsiveness
2. Gateway accepts TCP connections but never sends HTTP responses
3. Operator attempts to restart ProcessExecutorService during emergency (security patch, critical bug fix)
4. During initialization, MetricsPusher is created and starts worker thread
5. At end of `new()`, `_mp` is dropped, triggering `join()`
6. Worker thread attempts final push to unresponsive gateway
7. HTTP request hangs indefinitely (no response timeout)
8. `join()` blocks indefinitely waiting for worker thread
9. `ProcessExecutorService::new()` never returns
10. Service fails to initialize, preventing validator operations

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability affects **validator availability and operational resilience** during critical situations:

1. **Service Initialization Failure**: ProcessExecutorService, used for sharded transaction execution in production validators, cannot initialize if the metrics push gateway is unresponsive.

2. **Emergency Procedure Disruption**: During security incidents requiring rapid service restart (critical patches, vulnerability remediation), operators cannot bring services back online, extending the vulnerability window.

3. **Availability Impact**: While not directly affecting consensus safety or causing fund loss, this prevents validator nodes from processing transactions during critical periods.

This falls under the Medium severity category: "State inconsistencies requiring intervention" and operational disruptions affecting validator functionality.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can manifest under several realistic scenarios:

1. **Network Instability**: Transient network issues causing the push gateway to accept connections but fail to respond (half-open connections).

2. **Gateway Service Degradation**: The metrics push gateway experiencing high load or bugs causing request handling failures without closing connections.

3. **Attacker Control**: If an attacker gains control over the push gateway endpoint (via DNS poisoning, BGP hijacking, or compromise), they can deliberately hang connections.

4. **Configuration Issues**: Misconfigured push gateway URLs pointing to unresponsive endpoints.

The issue requires:
- `PUSH_METRICS_ENDPOINT` environment variable to be set (common in production)
- Gateway to accept connections but not respond (realistic network/service failure mode)
- Service restart during this condition (common during emergency procedures)

No special privileges or insider access required. The ureq library's default behavior without explicit response timeout makes this a realistic failure mode.

## Recommendation

Add explicit response timeout to HTTP requests in the `push()` method:

```rust
fn push(
    push_metrics_endpoint: &str,
    api_token: Option<&str>,
    push_metrics_extra_labels: &[String],
) {
    let mut buffer = Vec::new();

    if let Err(e) = TextEncoder::new().encode(&aptos_metrics_core::gather(), &mut buffer) {
        error!("Failed to encode push metrics: {}.", e.to_string());
    } else {
        let mut request = ureq::post(push_metrics_endpoint);
        if let Some(token) = api_token {
            request.set("apikey", token);
        }
        push_metrics_extra_labels.iter().for_each(|label| {
            request.query("extra_label", label);
        });
        // FIX: Add both connection and response timeouts
        let response = request
            .timeout_connect(10_000)
            .timeout(Duration::from_millis(10_000))  // Add response timeout
            .send_bytes(&buffer);
        if !response.ok() {
            warn!(
                "Failed to push metrics to {},  resp: {}",
                push_metrics_endpoint,
                response.status_text()
            )
        }
    }
}
```

Additionally, consider making the MetricsPusher lifecycle explicit rather than relying on Drop during initialization, or add a timeout to the `join()` call itself using `worker_thread.join_timeout()` (requires additional handling).

## Proof of Concept

```rust
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use std::env;

#[test]
fn test_metrics_pusher_hangs_on_unresponsive_gateway() {
    // Start a TCP server that accepts connections but never responds
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(_stream) = stream {
                // Accept connection but never read/write
                // This simulates an unresponsive server
                thread::sleep(Duration::from_secs(3600));
            }
        }
    });
    
    // Set the push metrics endpoint to our unresponsive server
    env::set_var("PUSH_METRICS_ENDPOINT", format!("http://{}/metrics", addr));
    env::set_var("PUSH_METRICS_FREQUENCY_SECS", "1");
    
    // This should complete quickly but will hang indefinitely
    let start = std::time::Instant::now();
    
    // Create and immediately drop MetricsPusher (simulates ProcessExecutorService::new)
    {
        let _mp = aptos_push_metrics::MetricsPusher::start(vec![]);
        // _mp is dropped here, calling join() which hangs on the final push
    }
    
    let elapsed = start.elapsed();
    
    // This assertion will fail - the test will hang indefinitely
    // In a proper implementation, this should complete in < 15 seconds
    assert!(elapsed < Duration::from_secs(15), 
            "MetricsPusher hung for {:?}, expected < 15s", elapsed);
}
```

**Expected Result**: Test hangs indefinitely when the push gateway doesn't respond.

**Fixed Result**: With proper response timeout, test completes in ~10-20 seconds (connection timeout + response timeout + cleanup).

---

## Notes

While this vulnerability affects the `ProcessExecutorService` (used for sharded execution) rather than the main validator node, it still impacts production validator operations that utilize sharded execution. The issue is particularly critical during emergency procedures when rapid service restart is required.

### Citations

**File:** crates/aptos-push-metrics/src/lib.rs (L54-54)
```rust
            let response = request.timeout_connect(10_000).send_bytes(&buffer);
```

**File:** crates/aptos-push-metrics/src/lib.rs (L84-88)
```rust
        Self::push(
            &push_metrics_endpoint,
            push_metrics_api_token.as_deref(),
            &push_metrics_extra_labels,
        );
```

**File:** crates/aptos-push-metrics/src/lib.rs (L201-213)
```rust
    pub fn join(&mut self) {
        if let Some(worker_thread) = self.worker_thread.take() {
            if let Err(e) = self.quit_sender.send(()) {
                error!(
                    "Failed to send quit signal to metric pushing worker thread: {:?}",
                    e
                );
            }
            if let Err(e) = worker_thread.join() {
                error!("Failed to join metric pushing worker thread: {:?}", e);
            }
        }
    }
```

**File:** crates/aptos-push-metrics/src/lib.rs (L216-221)
```rust
impl Drop for MetricsPusher {
    #[allow(deprecated)]
    fn drop(&mut self) {
        self.join()
    }
}
```

**File:** secure/storage/vault/src/lib.rs (L488-489)
```rust
        request.timeout_connect(self.connection_timeout_ms);
        request.timeout(Duration::from_millis(self.response_timeout_ms));
```

**File:** execution/executor-service/src/process_executor_service.rs (L30-32)
```rust
        let _mp = MetricsPusher::start_for_local_run(
            &("remote-executor-service-".to_owned() + &shard_id.to_string()),
        );
```
