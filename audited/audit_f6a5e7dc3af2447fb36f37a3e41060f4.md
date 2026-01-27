# Audit Report

## Title
DKG Transcript Aggregation Lock Contention Allows Malicious Validator to Prevent Legitimate Transcript Submissions

## Summary
A malicious validator can cause lock contention in the DKG transcript aggregation process by repeatedly sending invalid transcripts that fail cryptographic verification. The `add()` function acquires a global mutex before performing expensive verification operations, allowing an attacker to monopolize the lock and block legitimate validators from submitting transcripts within the DKG timeout window.

## Finding Description
The vulnerability exists in the `add()` function of `TranscriptAggregationState` which implements the `BroadcastStatus` trait for DKG transcript aggregation. [1](#0-0) 

The function acquires a mutex lock on `trx_aggregator` before performing cryptographic verification operations: [2](#0-1) 

These verification operations involve expensive cryptographic computations including pairing checks: [3](#0-2) 

**Attack Flow:**

1. A malicious validator crafts transcripts that pass deserialization but fail cryptographic verification
2. When legitimate validators use reliable broadcast to collect transcripts, the malicious validator responds with the invalid transcript
3. The `add()` function is called with the malicious validator's transcript:
   - Lock is acquired at line 91
   - The contributor check at line 92-94 passes (validator not yet added since verification never succeeded)
   - Expensive verification runs at lines 96-101 while holding the lock
   - Verification fails, function returns error via `?` operator
4. The reliable broadcast retry mechanism detects the error and retries: [4](#0-3) 

5. Steps 2-4 repeat, creating a cycle where the malicious validator monopolizes the lock during expensive verification operations
6. While the lock is held, other legitimate validators' `add()` calls block at line 91, preventing them from submitting their transcripts
7. If this lock contention persists long enough, legitimate validators cannot aggregate sufficient transcripts to reach quorum within the DKG session timeout

The attack exploits the fact that failed verifications don't add the validator to the contributors set (line 116 is never reached), allowing the same validator to cause `add()` to be called repeatedly. [5](#0-4) 

## Impact Explanation
This vulnerability represents a **Medium severity** issue that can cause DKG liveness failures. According to the Aptos bug bounty criteria, this falls under "State inconsistencies requiring intervention" or "Validator node slowdowns."

**Specific Impacts:**
- **DKG Session Failure**: Prevents successful completion of DKG sessions needed for randomness generation
- **Epoch Transition Delays**: DKG failure blocks epoch transitions, affecting validator set updates
- **Network Availability**: Prolonged DKG failures can impact overall network operation
- **Validator Performance**: Legitimate validators experience slowdowns due to lock contention

While this doesn't directly cause consensus safety violations or fund loss, it affects network liveness and requires operator intervention to resolve.

## Likelihood Explanation
The likelihood is **HIGH** for the following reasons:

1. **Single Malicious Validator**: Only requires one Byzantine validator (well within < 1/3 threshold)
2. **No Collusion Required**: The attack is executed independently by a single validator
3. **Simple Execution**: Malicious validator only needs to respond to RPC requests with crafted invalid transcripts
4. **Automatic Retry Mechanism**: The reliable broadcast framework automatically retries on errors, amplifying the attack
5. **No Rate Limiting**: There's no rate limiting or deduplication mechanism to prevent repeated invalid submissions: [6](#0-5) 

The check only prevents successful duplicate submissions, not repeated failures.

## Recommendation

**Solution: Move Expensive Verification Outside the Lock**

The expensive cryptographic verification operations should be performed *before* acquiring the mutex lock. Only the contributor check and aggregation logic need to be protected by the lock.

**Recommended Code Structure:**
```rust
pub fn add(
    &self,
    sender: Author,
    dkg_transcript: DKGTranscript,
) -> anyhow::Result<Option<Self::Aggregated>> {
    // ... initial checks (lines 70-87) ...
    
    let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
        anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
    })?;
    
    // PERFORM VERIFICATION BEFORE ACQUIRING LOCK
    S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
        .context("extra verification failed")?;
    S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
        anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
    })?;
    
    // NOW acquire lock only for state mutations
    let mut trx_aggregator = self.trx_aggregator.lock();
    if trx_aggregator.contributors.contains(&metadata.author) {
        return Ok(None);
    }
    
    // ... rest of aggregation logic (lines 104-152) ...
}
```

**Additional Protections:**
1. Implement per-validator rate limiting to prevent rapid retry storms
2. Add a backoff mechanism that increases delay after repeated failures from the same validator
3. Consider adding a maximum retry count per validator per DKG session

## Proof of Concept

```rust
#[cfg(test)]
mod lock_contention_test {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};
    
    #[test]
    fn test_malicious_validator_lock_contention() {
        // Setup: Create DKG session with multiple validators
        let epoch_state = create_test_epoch_state(4); // 4 validators
        let dkg_pub_params = create_test_dkg_params();
        let aggregator = Arc::new(TranscriptAggregationState::new(
            Duration::from_secs(0),
            validator_addresses[0],
            dkg_pub_params,
            epoch_state,
        ));
        
        // Malicious validator creates invalid transcript
        // (passes deserialization but fails verification)
        let invalid_transcript = create_invalid_transcript(
            validator_addresses[1],
            epoch_state.epoch
        );
        
        // Spawn threads simulating concurrent add() calls
        let mut handles = vec![];
        
        // Malicious validator thread - repeatedly sends invalid transcripts
        let agg_clone = aggregator.clone();
        let malicious_handle = thread::spawn(move || {
            let start = Instant::now();
            let mut call_count = 0;
            // Simulate reliable broadcast retries
            while start.elapsed() < Duration::from_secs(5) {
                let _ = agg_clone.add(
                    validator_addresses[1],
                    invalid_transcript.clone()
                );
                call_count += 1;
                thread::sleep(Duration::from_millis(100)); // Backoff
            }
            call_count
        });
        
        // Legitimate validator threads
        for i in 2..4 {
            let agg_clone = aggregator.clone();
            let valid_transcript = create_valid_transcript(
                validator_addresses[i],
                epoch_state.epoch
            );
            handles.push(thread::spawn(move || {
                let start = Instant::now();
                let result = agg_clone.add(
                    validator_addresses[i],
                    valid_transcript
                );
                (start.elapsed(), result)
            }));
        }
        
        // Collect results
        let malicious_calls = malicious_handle.join().unwrap();
        let legitimate_results: Vec<_> = handles.into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        
        // Verify: Legitimate validators experienced delays
        for (elapsed, result) in legitimate_results {
            // If lock contention occurred, legitimate validators
            // should experience significant delays (> 1 second)
            assert!(elapsed > Duration::from_secs(1),
                "Lock contention should delay legitimate validators");
        }
        
        // Malicious validator made multiple calls
        assert!(malicious_calls > 5,
            "Malicious validator should make multiple calls");
        
        println!("Attack demonstrated: {} malicious calls caused lock contention", 
                 malicious_calls);
    }
}
```

**Notes:**
- The vulnerability requires the attacker to be a validator with voting power, which is reasonable in the DKG threat model
- A single Byzantine validator (well under the 1/3 threshold) can execute this attack
- The attack exploits the reliable broadcast retry mechanism combined with holding a global lock during expensive operations
- The fix is straightforward: move verification before lock acquisition, following the "check-lock-act" pattern instead of "lock-check-act"

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L91-91)
```rust
        let mut trx_aggregator = self.trx_aggregator.lock();
```

**File:** dkg/src/transcript_aggregation/mod.rs (L92-94)
```rust
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L96-101)
```rust
        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** dkg/src/transcript_aggregation/mod.rs (L116-116)
```rust
        trx_aggregator.contributors.insert(metadata.author);
```

**File:** types/src/dkg/real_dkg/mod.rs (L368-374)
```rust
        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;
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
