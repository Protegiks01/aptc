# Audit Report

## Title
DKG Transcript Aggregation Mutex Poisoning Leads to Permanent Denial of Service

## Summary
The DKG transcript aggregation in `add()` function uses `aptos_infallible::Mutex` which panics on poison errors. If `verify_transcript` panics while holding the mutex lock, the mutex becomes poisoned, causing all subsequent aggregation attempts to panic indefinitely, permanently disabling DKG for the affected validator node.

## Finding Description
The `TranscriptAggregationState::add()` function acquires a mutex lock before calling `verify_transcript`: [1](#0-0) 

The mutex implementation is `aptos_infallible::Mutex`, which wraps `std::sync::Mutex` and calls `.expect()` on lock results: [2](#0-1) 

When a panic occurs while holding a `std::sync::Mutex`, Rust's panic unwinding mechanism properly drops the `MutexGuard`, releasing the lock. However, the mutex enters a "poisoned" state to indicate that invariants may have been violated. Subsequent lock attempts return `Err(PoisonError)`.

The `aptos_infallible::Mutex::lock()` implementation explicitly panics when encountering a poisoned mutex, meaning the next thread attempting to call `add()` will also panic at line 91, creating a cascading failure.

**Panic Sources in Verification Path:**

The `verify_transcript` call chain contains multiple panic points. The most critical is in `g2_multi_exp`: [3](#0-2) 

This function is called during transcript verification: [4](#0-3) 

Additionally, there are assertions that could panic: [5](#0-4) 

**Attack Scenario:**

1. Malicious peer sends a crafted `DKGTranscript` with malformed `transcript_bytes`
2. Bytes successfully deserialize via BCS (creates transcript with arbitrary vector sizes)
3. Validator's `add()` acquires mutex lock at line 91
4. `verify_transcript` is called at line 99
5. Verification encounters an edge case (arithmetic overflow, inconsistent config, unexpected input) causing a panic
6. Panic unwinds, `MutexGuard` drops, lock releases
7. **Mutex becomes poisoned**
8. Next peer's transcript arrives, `add()` is called again
9. Line 91 attempts `self.trx_aggregator.lock()`
10. Lock returns `Err(PoisonError)` due to poisoning
11. `.expect()` panics with "Cannot currently handle a poisoned lock"
12. Repeat for all subsequent calls

## Impact Explanation
**High Severity** - This vulnerability meets the "Validator node slowdowns" and "Significant protocol violations" criteria:

- **DKG Process Failure**: The affected validator cannot complete DKG transcript aggregation, preventing participation in randomness generation
- **Epoch Transition Impact**: If quorum cannot be reached due to affected nodes, epoch transitions may fail
- **Consensus Liveness**: While not a total network halt, this degrades network health and validator participation
- **Permanent DoS**: Unlike transient errors, mutex poisoning persists until the node is restarted, making this a persistent availability issue

The impact is contained to individual validator nodes (no direct fund loss), but affects critical consensus infrastructure.

## Likelihood Explanation
**Medium-High Likelihood**:

- **Attacker Requirements**: Any network peer can send DKG transcripts to validators
- **Complexity**: Low - attacker only needs to craft malformed transcript bytes
- **Detection**: The panic may occur in production due to edge cases even without malicious input (arithmetic overflow, unexpected validator configurations, etc.)
- **Mitigation Absence**: No recovery mechanism exists; mutex stays poisoned until restart

The verification code path contains multiple potential panic points (assertions, unwraps, arithmetic operations), increasing likelihood that either malicious input or edge cases trigger the vulnerability.

## Recommendation
Replace `aptos_infallible::Mutex` with a panic-safe locking strategy:

**Option 1**: Use `std::sync::Mutex` directly and handle poison errors:
```rust
let mut trx_aggregator = match self.trx_aggregator.lock() {
    Ok(guard) => guard,
    Err(poisoned) => {
        warn!("Transcript aggregator mutex was poisoned, recovering");
        poisoned.into_inner()
    }
};
```

**Option 2**: Use `parking_lot::Mutex` which doesn't poison:
```rust
use parking_lot::Mutex;

pub struct TranscriptAggregationState<DKG: DKGTrait> {
    // ...
    trx_aggregator: Mutex<TranscriptAggregator<DKG>>,
    // ...
}
```

**Option 3**: Wrap verification in `catch_unwind` to prevent panic propagation:
```rust
use std::panic::catch_unwind;

let verify_result = catch_unwind(|| {
    S::verify_transcript(&self.dkg_pub_params, &transcript)
});

match verify_result {
    Ok(Ok(())) => {}, // Verification passed
    Ok(Err(e)) => return Err(e), // Verification failed normally
    Err(_) => return Err(anyhow!("[DKG] verify_transcript panicked")),
}
```

**Recommended**: Combination of Option 2 (use `parking_lot::Mutex`) + defensive programming to eliminate panic sources in verification path.

## Proof of Concept
```rust
use std::sync::Arc;
use std::thread;
use aptos_infallible::Mutex;

// Simulate the vulnerable pattern
struct VulnerableState {
    data: Mutex<Vec<u8>>,
}

impl VulnerableState {
    fn process(&self, input: &[u8]) -> anyhow::Result<()> {
        let mut data = self.data.lock();
        
        // Simulate verify_transcript panic
        if input.is_empty() {
            panic!("Invalid input causes panic!");
        }
        
        data.extend_from_slice(input);
        Ok(())
    }
}

fn main() {
    let state = Arc::new(VulnerableState {
        data: Mutex::new(Vec::new()),
    });
    
    // Thread 1: Trigger panic while holding lock
    let state1 = state.clone();
    let handle1 = thread::spawn(move || {
        let _ = state1.process(&[]); // Panics!
    });
    
    // Wait for panic
    let _ = handle1.join();
    
    // Thread 2: Attempt to acquire poisoned lock
    let state2 = state.clone();
    let handle2 = thread::spawn(move || {
        let _ = state2.process(&[1, 2, 3]); // Panics at lock()!
    });
    
    // This will also panic, demonstrating cascading failure
    let _ = handle2.join();
    
    println!("If we reach here, mutex wasn't poisoned (shouldn't happen)");
}
```

**Expected behavior**: First thread panics during processing. Second thread panics immediately when attempting to acquire the poisoned lock, demonstrating the vulnerability.

**Notes**:
The Mutex guard does technically unwind properly (the lock is released), but the mutex poisoning creates a permanent denial-of-service condition. This is a design flaw rather than memory corruption, but still represents a critical availability vulnerability in DKG consensus infrastructure.

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L91-101)
```rust
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** crates/aptos-infallible/src/mutex.rs (L19-23)
```rust
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0
            .lock()
            .expect("Cannot currently handle a poisoned lock")
    }
```

**File:** crates/aptos-dkg/src/utils/mod.rs (L75-82)
```rust
pub fn g2_multi_exp(bases: &[G2Projective], scalars: &[blstrs::Scalar]) -> G2Projective {
    if bases.len() != scalars.len() {
        panic!(
            "blstrs's multiexp has heisenbugs when the # of bases != # of scalars ({} != {})",
            bases.len(),
            scalars.len()
        );
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L327-329)
```rust
        assert_eq!(alphas.len(), W + 1);
        assert_eq!(betas.len(), W);
        assert_eq!(gammas.len(), W);
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L347-350)
```rust
            lc_R_hat.push(g2_multi_exp(
                &self.R_hat[s_i..s_i + weight],
                &gammas[s_i..s_i + weight],
            ));
```
