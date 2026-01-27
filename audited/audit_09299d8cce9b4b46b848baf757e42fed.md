# Audit Report

## Title
Telemetry Write Failures Silently Swallow Critical Security Events With Broken Alert Monitoring

## Summary
The `LoggerService::run()` function ignores telemetry write failures with `let _`, allowing critical consensus security events like `ConsensusEquivocatingVote` to fail transmission to remote monitoring systems without any automated alerting. The monitoring infrastructure is additionally broken because alert rules reference non-existent metrics, creating a complete blind spot for Byzantine validator detection.

## Finding Description

The vulnerability exists in the telemetry logging pipeline where security-critical events are sent to remote monitoring backends: [1](#0-0) 

The `writer.write(s)` call returns `std::io::Result<usize>` but the result is deliberately ignored. This method can fail in two scenarios: [2](#0-1) 

When failures occur, metrics are incremented but no other action is taken. The system defines these metrics: [3](#0-2) 

However, the alert monitoring infrastructure references completely different, non-existent metrics: [4](#0-3) 

The alert monitors `aptos_struct_log_send_error`, which does not exist in the codebase. The actual metrics (`aptos_log_ingest_writer_full`, `aptos_log_ingest_writer_disconnected`) are never monitored by alerts.

**Critical Security Events Affected:**

The system logs consensus security events that must be monitored: [5](#0-4) 

When Byzantine validators perform equivocating votes (double-voting), the security event is logged: [6](#0-5) 

**Attack Scenario:**
1. Attacker fills the 10,000-entry telemetry channel through log spam
2. Byzantine validator performs equivocation attack
3. `ConsensusEquivocatingVote` security event is logged locally but fails telemetry transmission (channel full)
4. Error is silently ignored beyond incrementing `aptos_log_ingest_writer_full`
5. No alert fires because alerts monitor non-existent `aptos_struct_log_send_error`
6. Operators relying on centralized monitoring/alerting miss the Byzantine behavior
7. Attack continues undetected by automated systems

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

The telemetry state becomes inconsistent with actual consensus security events occurring on the node. This creates a critical observability gap where:

- Byzantine validators can evade automated detection systems
- Compliance and audit requirements may be violated (security logs not centralized)
- Incident response is delayed because operators miss real-time alerts
- Manual intervention is required to correlate local logs and detect attacks

This does NOT directly break consensus safety (local logs still work), but it undermines the security monitoring infrastructure designed to detect and respond to consensus attacks, enabling Byzantine behavior to persist longer than intended.

## Likelihood Explanation

**High Likelihood** - This will occur in production environments:

1. **Channel saturation is common**: With 10,000 entries and typical logging rates, high-traffic periods or log bursts can fill the channel
2. **Production reliance on centralized monitoring**: Most operators use centralized log aggregation (ELK, Splunk, Loki) for alerting
3. **Broken alerts guarantee missed detection**: The alert monitoring wrong metrics ensures automated detection fails
4. **Byzantine validators exist**: The Aptos threat model explicitly assumes up to 1/3 Byzantine validators

The combination of ignored errors and broken monitoring makes this vulnerability likely to hide real consensus attacks in production.

## Recommendation

**Fix 1: Handle telemetry write errors**

Replace the silent error swallowing with explicit error handling:

```rust
if let Some(writer) = &mut telemetry_writer {
    if self
        .facade
        .filter
        .read()
        .telemetry_filter
        .enabled(&entry.metadata)
    {
        let s = json_format(&entry).expect("Unable to format");
        if let Err(e) = writer.write(s) {
            // Log to stderr for visibility
            sample!(
                SampleRate::Duration(Duration::from_secs(60)),
                eprintln!("[CRITICAL] Telemetry write failed: {} - Security logs may not reach remote monitoring!", e)
            );
            // Consider: Implement a fallback mechanism or circuit breaker
        }
    }
}
```

**Fix 2: Correct the monitoring metrics**

Update the alert configuration to monitor actual metrics:

```yaml
- alert: Logs Being Dropped
  expr: 1 < (rate(aptos_log_ingest_writer_full[1m]) + rate(aptos_log_ingest_writer_disconnected[1m]) + rate(aptos_struct_log_queue_error_count[1m]))
  for: 5m
  labels:
    severity: error  # Upgrade to error for security events
    summary: "Critical: Telemetry logs being dropped - security events may be lost"
  annotations:
    description: "Telemetry channel failures detected. Security audit logs may not reach remote monitoring. Check local logs immediately."
```

**Fix 3: Add security-specific telemetry guarantee**

For critical security events, consider implementing a retry mechanism or synchronous write with timeout to ensure they reach telemetry.

## Proof of Concept

**Rust reproduction steps:**

1. Configure Aptos node with telemetry enabled and small channel size for testing
2. Generate log spam to fill the telemetry channel:
```rust
// Spawn a task that floods the logging system
for i in 0..15000 {
    info!("Spam log {}", i);
}
```

3. Trigger a consensus security event (simulate equivocation detection):
```rust
error!(
    SecurityEvent::ConsensusEquivocatingVote,
    remote_peer = "byzantine_validator",
    vote = "vote_1",
    previous_vote = "vote_2"
);
```

4. Check telemetry backend - the security event will be missing
5. Check local logs - the security event IS present
6. Check Prometheus metrics - `aptos_log_ingest_writer_full` will be incremented
7. Check alerts - NO alert fires because it monitors `aptos_struct_log_send_error` (non-existent)

**Expected behavior:** Security event is lost in telemetry with no automated alerting, creating detection blind spot.

## Notes

This vulnerability has two critical components:
1. **Error swallowing** at line 651 prevents visibility of telemetry failures
2. **Broken monitoring** means alerts never fire even when failures occur

The combination creates a complete observability gap for consensus security events in remote monitoring systems. While local logs remain functional, production deployments typically rely on centralized log aggregation and automated alerting for Byzantine validator detection. The misconfigured alert metrics (`aptos_struct_log_send_error` vs actual `aptos_log_ingest_writer_*`) indicate this issue has likely persisted undetected, as the alerts designed to catch it cannot function correctly.

For operators: Immediately verify your monitoring stack is configured to alert on `aptos_log_ingest_writer_full` and `aptos_log_ingest_writer_disconnected` metrics, and ensure local logs are regularly audited for security events.

### Citations

**File:** crates/aptos-logger/src/aptos_logger.rs (L642-653)
```rust
                    if let Some(writer) = &mut telemetry_writer {
                        if self
                            .facade
                            .filter
                            .read()
                            .telemetry_filter
                            .enabled(&entry.metadata)
                        {
                            let s = json_format(&entry).expect("Unable to format");
                            let _ = writer.write(s);
                        }
                    }
```

**File:** crates/aptos-logger/src/telemetry_log_writer.rs (L29-43)
```rust
    pub fn write(&mut self, log: String) -> std::io::Result<usize> {
        let len = log.len();
        match self.tx.try_send(TelemetryLog::Log(log)) {
            Ok(_) => Ok(len),
            Err(err) => {
                if err.is_full() {
                    APTOS_LOG_INGEST_WRITER_FULL.inc_by(len as u64);
                    Err(Error::new(ErrorKind::WouldBlock, "Channel full"))
                } else {
                    APTOS_LOG_INGEST_WRITER_DISCONNECTED.inc_by(len as u64);
                    Err(Error::new(ErrorKind::ConnectionRefused, "Disconnected"))
                }
            },
        }
    }
```

**File:** crates/aptos-logger/src/counters.rs (L48-63)
```rust
pub static APTOS_LOG_INGEST_WRITER_FULL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_log_ingest_writer_full",
        "Number of log ingest writes that failed due to channel full"
    )
    .unwrap()
});

/// Counter for failed log ingest writes (see also: aptos-telemetry for sender metrics)
pub static APTOS_LOG_INGEST_WRITER_DISCONNECTED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_log_ingest_writer_disconnected",
        "Number of log ingest writes that failed due to channel disconnected"
    )
    .unwrap()
});
```

**File:** terraform/helm/monitoring/files/rules/alerts.yml (L156-166)
```yaml
  - alert: Logs Being Dropped
    expr: 1 < (rate(aptos_struct_log_queue_error[1m]) + rate(aptos_struct_log_send_error[1m]))
    for: 5m
    labels:
      severity: warning
      summary: "Logs being dropped"
    annotations:
      description: "Logging Transmit Error rate is high \
        check the logging dashboard and \
        there may be network issues, downstream throughput issues, or something wrong with Vector \
        TODO: Runbook"
```

**File:** crates/aptos-logger/src/security.rs (L23-82)
```rust
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEvent {
    //
    // Mempool
    //
    /// Mempool received a transaction from another peer with an invalid signature
    InvalidTransactionMempool,

    /// Mempool received an invalid network event
    InvalidNetworkEventMempool,

    // Consensus
    // ---------
    /// Consensus received an invalid message (not well-formed, invalid vote data or incorrect signature)
    ConsensusInvalidMessage,

    /// Consensus received an equivocating vote
    ConsensusEquivocatingVote,

    /// Consensus received an equivocating order vote
    ConsensusEquivocatingOrderVote,

    /// Consensus received an invalid proposal
    InvalidConsensusProposal,

    /// Consensus received an invalid new round message
    InvalidConsensusRound,

    /// Consensus received an invalid sync info message
    InvalidSyncInfoMsg,

    /// A received block is invalid
    InvalidRetrievedBlock,

    /// A block being committed or executed is invalid
    InvalidBlock,

    // State-Sync
    // ----------
    /// Invalid chunk of transactions received
    StateSyncInvalidChunk,

    // Health Checker
    // --------------
    /// HealthChecker received an invalid network event
    InvalidNetworkEventHC,

    /// HealthChecker received an invalid message
    InvalidHealthCheckerMsg,

    // Network
    // -------
    /// Network received an invalid message from a remote peer
    InvalidNetworkEvent,

    /// A failed noise handshake that's either a clear bug or indicates some
    /// security issue.
    NoiseHandshake,
}
```

**File:** consensus/src/pending_votes.rs (L300-308)
```rust
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
```
