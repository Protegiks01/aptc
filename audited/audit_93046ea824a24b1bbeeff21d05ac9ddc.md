# Audit Report

## Title
Broken Rate Limiting in Quorum Store Back Pressure Logging Allows Log Spam

## Summary
The `qs_back_pressure()` function in `proof_manager.rs` attempts to rate-limit logging to once per 200 milliseconds using the `sample!` macro, but due to a limitation in the `sample_duration` implementation that only supports second-granularity, the rate limiting is effectively disabled. This causes uncontrolled logging when the system is back-pressured, potentially leading to disk space exhaustion over time.

## Finding Description
The vulnerability exists in how the `sample!` macro handles sub-second durations. In `proof_manager.rs`, the logging is wrapped with: [1](#0-0) 

The `sample!` macro uses `SampleRate::Duration(Duration::from_millis(200))` intending to rate-limit to once every 200 milliseconds. However, the `sample_duration` implementation converts the duration to seconds: [2](#0-1) 

At line 63, `rate.as_secs()` truncates 200 milliseconds to 0 seconds. This causes the rate limiting check at line 72 (`now.saturating_sub(last_sample) >= rate`) to become `now.saturating_sub(last_sample) >= 0`, which is always true when time doesn't move backwards. Consequently, the log fires on every invocation instead of being rate-limited.

The `qs_back_pressure()` function is called in the main event loop after processing every proposal and every proof manager command: [3](#0-2) [4](#0-3) 

When the system is back-pressured (transaction or proof count exceeds limits), each incoming proof, batch, or proposal triggers a log entry. In a high-throughput consensus network processing hundreds or thousands of messages per second, this generates substantial log output that could exhaust disk space over hours or days.

## Impact Explanation
This qualifies as **Low Severity** per the Aptos bug bounty program criteria for "Non-critical implementation bugs." The impact is:

1. **Disk Space Exhaustion**: Uncontrolled logging can fill disk space, potentially causing node failure
2. **Gradual Degradation**: The impact accumulates over time rather than causing immediate failure
3. **Operational Impact**: Affects node availability but not blockchain consensus integrity
4. **Mitigation Available**: Standard log rotation and monitoring practices limit the impact

This does not meet Medium or higher severity because it doesn't directly compromise funds, consensus safety, or cause immediate critical failures. However, it violates the Resource Limits invariant by allowing unbounded log growth.

## Likelihood Explanation
The likelihood is **Medium** because:

1. **Back-pressure conditions** occur naturally under high network load or when validators lag behind
2. **Normal consensus operation** triggers the vulnerable code path without requiring malicious behavior
3. **Detection is easy**: Operators monitoring disk usage would notice the issue
4. **Limited attack surface**: Only validators can send messages that trigger the logging, and causing sustained back-pressure requires either validator cooperation or legitimate high network load

The bug activates automatically under back-pressure conditions without requiring specific attacker action, but the actual harm depends on operational factors like log rotation policies.

## Recommendation
Fix the `sample_duration` implementation to support sub-second granularity, or adjust the rate limit to use whole seconds:

**Option 1 - Fix sample_duration for millisecond precision:**
```rust
fn sample_duration(rate: &Duration, last_sample: &AtomicU64) -> bool {
    let rate_millis = rate.as_millis() as u64;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH!")
        .as_millis() as u64;
    
    last_sample
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last_sample| {
            if now.saturating_sub(last_sample) >= rate_millis {
                Some(now)
            } else {
                None
            }
        })
        .is_ok()
}
```

**Option 2 - Use second-granularity in proof_manager.rs:**
```rust
sample!(
    SampleRate::Duration(Duration::from_secs(1)),  // Changed from from_millis(200)
    info!(
        "Quorum store is back pressured with {} txns, limit: {}, proofs: {}, limit: {}",
        self.remaining_total_txn_num,
        self.back_pressure_total_txn_limit,
        self.remaining_total_proof_num,
        self.back_pressure_total_proof_limit
    );
);
```

## Proof of Concept
```rust
#[cfg(test)]
mod test_rate_limit_bug {
    use aptos_logger::sample::{SampleRate, Sampling};
    use std::time::Duration;
    
    #[test]
    fn test_millisecond_rate_limiting_broken() {
        // This test demonstrates that 200ms rate limiting doesn't work
        let sampling = Sampling::new(SampleRate::Duration(Duration::from_millis(200)));
        
        let mut sample_count = 0;
        // Call sample() 1000 times in rapid succession
        for _ in 0..1000 {
            if sampling.sample() {
                sample_count += 1;
            }
        }
        
        // With proper 200ms rate limiting, we should get ~1 sample
        // But due to the bug, we get samples on every call (after the first)
        // because 200ms truncates to 0 seconds
        assert!(sample_count > 100, 
            "Expected many samples due to bug, got {}", sample_count);
        // This assertion passes, proving the bug exists
    }
    
    #[test]
    fn test_second_rate_limiting_works() {
        // This test shows that second-level granularity works correctly
        let sampling = Sampling::new(SampleRate::Duration(Duration::from_secs(1)));
        
        let mut sample_count = 0;
        for _ in 0..1000 {
            if sampling.sample() {
                sample_count += 1;
            }
        }
        
        // With 1-second rate limiting, we should get only 1 sample
        assert_eq!(sample_count, 1, 
            "Expected 1 sample with proper rate limiting, got {}", sample_count);
    }
}
```

## Notes
- This bug affects all code using `sample!` with `Duration::from_millis()` where the millisecond value is less than 1000
- Other uses in the codebase correctly use `Duration::from_secs()` for second-level granularity
- While this is a valid bug, its security impact is limited by standard operational practices (log rotation, disk monitoring) and the gradual nature of the resource exhaustion
- The issue would be more severe if log files were not rotated or if disk space were constrained, but modern validator infrastructure typically includes monitoring and log management

### Citations

**File:** consensus/src/quorum_store/proof_manager.rs (L249-258)
```rust
            sample!(
                SampleRate::Duration(Duration::from_millis(200)),
                info!(
                    "Quorum store is back pressured with {} txns, limit: {}, proofs: {}, limit: {}",
                    self.remaining_total_txn_num,
                    self.back_pressure_total_txn_limit,
                    self.remaining_total_proof_num,
                    self.back_pressure_total_proof_limit
                );
            );
```

**File:** consensus/src/quorum_store/proof_manager.rs (L281-291)
```rust
            tokio::select! {
                    Some(msg) = proposal_rx.next() => monitor!("proof_manager_handle_proposal", {
                        self.handle_proposal_request(msg);

                        let updated_back_pressure = self.qs_back_pressure();
                        if updated_back_pressure != back_pressure {
                            back_pressure = updated_back_pressure;
                            if back_pressure_tx.send(back_pressure).await.is_err() {
                                debug!("Failed to send back_pressure for proposal");
                            }
                        }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L293-326)
```rust
                    Some(msg) = proof_rx.recv() => {
                        monitor!("proof_manager_handle_command", {
                        match msg {
                            ProofManagerCommand::Shutdown(ack_tx) => {
                                counters::QUORUM_STORE_MSG_COUNT.with_label_values(&["ProofManager::shutdown"]).inc();
                                ack_tx
                                    .send(())
                                    .expect("Failed to send shutdown ack to QuorumStore");
                                break;
                            },
                            ProofManagerCommand::ReceiveProofs(proofs) => {
                                counters::QUORUM_STORE_MSG_COUNT.with_label_values(&["ProofManager::receive_proofs"]).inc();
                                self.receive_proofs(proofs.take());
                            },
                            ProofManagerCommand::ReceiveBatches(batches) => {
                                counters::QUORUM_STORE_MSG_COUNT.with_label_values(&["ProofManager::receive_batches"]).inc();
                                self.receive_batches(batches);
                            }
                            ProofManagerCommand::CommitNotification(block_timestamp, batches) => {
                                counters::QUORUM_STORE_MSG_COUNT.with_label_values(&["ProofManager::commit_notification"]).inc();
                                self.handle_commit_notification(
                                    block_timestamp,
                                    batches,
                                );
                            },
                        }
                        let updated_back_pressure = self.qs_back_pressure();
                        if updated_back_pressure != back_pressure {
                            back_pressure = updated_back_pressure;
                            if back_pressure_tx.send(back_pressure).await.is_err() {
                                debug!("Failed to send back_pressure for commit notification");
                            }
                        }
                    })
```

**File:** crates/aptos-logger/src/sample.rs (L62-79)
```rust
    fn sample_duration(rate: &Duration, last_sample: &AtomicU64) -> bool {
        let rate = rate.as_secs();
        // Seconds since Unix Epoch
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();

        last_sample
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last_sample| {
                if now.saturating_sub(last_sample) >= rate {
                    Some(now)
                } else {
                    None
                }
            })
            .is_ok()
    }
```
