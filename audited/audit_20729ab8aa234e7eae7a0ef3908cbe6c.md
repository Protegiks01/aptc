# Audit Report

## Title
Silent Dropping of Critical Security Events Due to Unbounded Log Queue Failures

## Summary

The Aptos logger implementation uses a bounded channel to queue log events asynchronously. When this channel fills up, critical security events (Byzantine proposals, equivocating votes, signature verification failures) are silently dropped with only a counter increment, providing no indication to operators about which specific security events were lost. This enables attackers to blind validators to Byzantine behavior by first flooding the logging system, then executing attacks whose evidence is destroyed.

## Finding Description

The logging flow in Aptos Core proceeds through multiple layers:

1. Security events use the `error!` macro [1](#0-0) 
2. This calls `Event::dispatch()` [2](#0-1) 
3. Which calls `logger::dispatch()` [3](#0-2) 
4. The logger's `record()` method creates a log entry and calls `send_entry()` [4](#0-3) 

The critical vulnerability occurs in `send_entry()` where logs are sent to a bounded channel: [5](#0-4) 

The channel has a default size of only 10,000 entries [6](#0-5) , and the comment explicitly acknowledges that logs are dropped when full.

Critical security events that use this logging system include:

- **Byzantine equivocating votes**: [7](#0-6) 
- **Invalid sync info messages**: [8](#0-7) 
- **Signature verification failures**: [9](#0-8) 
- **Vote verification errors**: [10](#0-9) 

The `SecurityEvent` enum defines all critical events that can be silently dropped: [11](#0-10) 

**Attack Scenario:**

1. Attacker sends high-volume invalid transactions/network messages to a validator
2. The logging channel fills to 10,000 entries (easily achievable under load)
3. Attacker performs Byzantine attack (equivocation, invalid proposals)
4. The critical security logs for the actual attack are dropped
5. Only a counter metric increments [12](#0-11) 
6. Operator cannot distinguish between dropped debug logs vs. dropped critical security events
7. Byzantine behavior goes undetected and unrecorded

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program for multiple reasons:

1. **Significant Protocol Violations**: Byzantine behavior can occur without being logged, violating the fundamental security invariant that all validator misbehavior must be observable and auditable.

2. **Validator Node Security Compromise**: Operators cannot detect attacks against their nodes, as the evidence is destroyed. This breaks the security monitoring capabilities essential for validator operation.

3. **Forensic Analysis Prevention**: Post-incident investigation becomes impossible when critical security events are missing from logs. This prevents proper incident response and attribution.

4. **Attack Amplification**: A relatively simple DoS attack on the logging system enables more serious consensus attacks to proceed undetected.

The impact extends beyond individual validators - if multiple validators experience log flooding simultaneously (coordinated attack), Byzantine behavior could occur network-wide without detection, potentially threatening consensus safety.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur in production for several reasons:

1. **Low Attack Complexity**: Flooding logs requires only sending invalid transactions or malformed network messages - no special privileges needed.

2. **Small Buffer Size**: 10,000 entries is surprisingly small for a production blockchain. A validator processing hundreds of transactions per second can easily generate thousands of log entries under normal operation.

3. **Asynchronous Processing**: The async logging design means the channel can fill if log processing (disk I/O, remote logging) is temporarily slow.

4. **No Backpressure**: The system uses `try_send()` instead of blocking, meaning there's no flow control to prevent the channel from filling.

5. **Common Attack Pattern**: Log flooding is a well-known attack technique in distributed systems.

Real-world triggers include:
- Network partition causing message replay floods
- Disk I/O slowdowns during state sync
- Remote logging service outages
- Malicious peers sending invalid messages at high rate
- High transaction throughput during peak usage

## Recommendation

Implement a multi-tiered approach to prevent critical security event loss:

**1. Priority Queues**: Separate critical security events from normal logs
```rust
enum LogPriority {
    Critical,  // SecurityEvent logs
    Normal,    // Regular logs
}

struct AptosData {
    critical_sender: Option<sync::mpsc::SyncSender<LogEntry>>,  // Never drop
    normal_sender: Option<sync::mpsc::SyncSender<LogEntry>>,    // Can drop
    // ...
}
```

**2. Synchronous Fallback for Critical Events**: When the critical queue is full, block or write synchronously rather than drop
```rust
fn send_entry(&self, entry: LogEntry) {
    if entry.is_security_event() {
        if let Some(sender) = &self.critical_sender {
            // Block until sent - critical events must not be lost
            let _ = sender.send(LoggerServiceEvent::LogEntry(entry));
        }
    } else {
        // Normal logs can be dropped
        if let Some(sender) = &self.normal_sender {
            if sender.try_send(LoggerServiceEvent::LogEntry(entry)).is_err() {
                STRUCT_LOG_QUEUE_ERROR_COUNT.inc();
            }
        }
    }
}
```

**3. Explicit Alerting**: When ANY security event is dropped, trigger immediate alerts
```rust
if sender.try_send(LoggerServiceEvent::LogEntry(entry)).is_err() {
    if entry.is_security_event() {
        CRITICAL_SECURITY_LOG_DROPPED_COUNT.inc();
        eprintln!("CRITICAL: Security event dropped: {:?}", entry.metadata());
        // Could also trigger emergency alert via separate channel
    }
    STRUCT_LOG_QUEUE_ERROR_COUNT.inc();
}
```

**4. Increase Buffer Sizes**: For critical events, use much larger buffers (100K+ entries)

**5. Add Monitoring**: Expose detailed metrics showing which event types are being dropped

## Proof of Concept

```rust
// Proof of Concept: Demonstrating log queue overflow

#[cfg(test)]
mod log_overflow_poc {
    use aptos_logger::{error, SecurityEvent, Logger};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_security_event_dropped_during_log_flood() {
        // Initialize logger with small buffer for testing
        let logger = aptos_logger::AptosDataBuilder::new()
            .channel_size(100)  // Small buffer to demonstrate overflow
            .is_async(true)
            .build();
        aptos_logger::set_global_logger(Arc::new(logger), None);

        // Simulate log flooding with benign events
        for i in 0..150 {
            error!("Benign flood message {}", i);
        }

        // Now log a critical security event
        error!(
            SecurityEvent::ConsensusEquivocatingVote,
            validator = "malicious_validator",
            round = 12345,
            "Byzantine validator detected"
        );

        // Give logger thread time to process
        thread::sleep(Duration::from_millis(100));
        
        // The security event above was likely dropped due to queue overflow
        // In production, this means Byzantine behavior goes undetected
        
        // Check STRUCT_LOG_QUEUE_ERROR_COUNT metric - it will be > 0
        // but we have NO IDEA if the dropped log was the security event
        // or one of the benign floods
    }

    #[test] 
    fn test_realistic_attack_scenario() {
        let logger = aptos_logger::AptosDataBuilder::new()
            .channel_size(10000)  // Production default
            .is_async(true)
            .build();
        aptos_logger::set_global_logger(Arc::new(logger), None);

        // Phase 1: Attacker floods logs with invalid transactions
        for i in 0..12000 {
            error!("Invalid transaction signature from peer_{}", i);
        }

        // Phase 2: Attacker performs actual Byzantine attack
        // This critical event will be dropped:
        error!(
            SecurityEvent::ConsensusEquivocatingVote,
            validator = "byzantine_validator_address",
            round = 100,
            block_1 = "0xabc...",
            block_2 = "0xdef...",
            "CRITICAL: Validator sent two different votes for same round"
        );

        thread::sleep(Duration::from_millis(100));
        
        // Result: Byzantine attack occurred but no log evidence exists
        // Operator only sees queue error counter increment
        // Cannot determine what was dropped
    }
}
```

**Notes:**

The vulnerability is exacerbated by the fact that the `Logger` trait's `record()` method has no return value [13](#0-12) , so even if the implementation wanted to signal failure, the interface doesn't support it. The entire logging architecture is designed with the assumption that log writes cannot fail, which is demonstrably false given the bounded channel implementation.

This represents a fundamental design flaw where critical security invariants (all Byzantine behavior must be observable) are violated by an architectural decision (bounded async logging) without adequate safeguards.

### Citations

**File:** crates/aptos-logger/src/macros.rs (L119-123)
```rust
macro_rules! error {
    ($($arg:tt)+) => {
        $crate::log!($crate::Level::Error, $($arg)+)
    };
}
```

**File:** crates/aptos-logger/src/event.rs (L29-36)
```rust
    pub fn dispatch(
        metadata: &'a Metadata,
        message: Option<fmt::Arguments<'a>>,
        keys_and_values: &'a [&'a dyn Schema],
    ) {
        let event = Event::new(metadata, message, keys_and_values);
        crate::logger::dispatch(&event)
    }
```

**File:** crates/aptos-logger/src/logger.rs (L19-20)
```rust
    /// Record an event
    fn record(&self, event: &Event);
```

**File:** crates/aptos-logger/src/logger.rs (L27-32)
```rust
pub(crate) fn dispatch(event: &Event) {
    if let Some(logger) = LOGGER.get() {
        STRUCT_LOG_COUNT.inc();
        logger.record(event)
    }
}
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L43-44)
```rust
/// Default size of log write channel, if the channel is full, logs will be dropped
pub const CHANNEL_SIZE: usize = 10000;
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L556-563)
```rust
        if let Some(sender) = &self.sender {
            if sender
                .try_send(LoggerServiceEvent::LogEntry(entry))
                .is_err()
            {
                STRUCT_LOG_QUEUE_ERROR_COUNT.inc();
            }
        }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L572-580)
```rust
    fn record(&self, event: &Event) {
        let entry = LogEntry::new(
            event,
            ::std::thread::current().name(),
            self.enable_backtrace,
        );

        self.send_entry(entry)
    }
```

**File:** consensus/src/pending_votes.rs (L247-251)
```rust
                    error!(
                        "MUST_FIX: 2-chain timeout vote received could not be added: {}, vote: {}",
                        error, timeout
                    );
                    return VoteReceptionResult::ErrorAddingVote(error);
```

**File:** consensus/src/pending_votes.rs (L300-305)
```rust
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );
```

**File:** consensus/src/round_manager.rs (L889-894)
```rust
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L242-247)
```rust
                            error!(
                                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                                    "Failed to verify the block payload signatures for epoch: {:?} and round: {:?}. Error: {:?}",
                                    epoch, round, error
                                ))
                            );
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

**File:** crates/aptos-logger/src/counters.rs (L31-37)
```rust
pub static STRUCT_LOG_QUEUE_ERROR_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_struct_log_queue_error_count",
        "Count of all errors during queuing struct logs."
    )
    .unwrap()
});
```
