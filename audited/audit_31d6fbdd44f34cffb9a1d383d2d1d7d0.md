# Audit Report

## Title
Time Source Mismatch in Mempool Transaction Expiration Validation Causes Valid Transaction Rejection

## Summary
Mempool uses system time (`duration_since_epoch()`) for garbage collection before consensus pulls transactions, while transaction prologue validation uses blockchain consensus time (`timestamp::now_seconds()`). This time source mismatch allows valid transactions to be incorrectly rejected when validator system clocks drift ahead of blockchain time, or expired transactions to be kept when clocks lag behind, causing availability issues and resource waste.

## Finding Description

The vulnerability stems from using two different time sources at different validation stages:

**Stage 1: Mempool Garbage Collection (Pre-Consensus)**
When consensus requests transactions via `GetBatchRequest`, mempool performs garbage collection using system time: [1](#0-0) 

The comment explicitly documents the assumption that "consensus uses the system time to determine block timestamp," but this assumption is flawed because:

1. **Block proposer does use system time initially:** [2](#0-1) 

2. **However, blockchain time is consensus-driven and must be validated:** [3](#0-2) 

**Stage 2: Prologue Validation (During Execution)**
When transactions execute, the prologue validates expiration against blockchain consensus time: [4](#0-3) 

**The Core Implementation:**
The `duration_since_epoch()` function uses local system time: [5](#0-4) 

**Attack Scenario:**

1. Validator A has system clock 90 seconds ahead of blockchain consensus time
2. User submits transaction with `expiration_timestamp_secs = T` where T is current blockchain time + 60 seconds
3. Mempool GC on Validator A executes: `duration_since_epoch()` returns `T + 90`
4. Comparison: `T + 90 > T` evaluates to true, transaction marked as expired
5. Transaction is garbage collected before reaching consensus
6. **Result:** Valid transaction that should live for 60 more seconds (according to blockchain time) is rejected

**Inverse Scenario:**
If Validator B's clock is 90 seconds behind, transactions already expired by blockchain consensus time will remain in mempool, wasting bandwidth and processing resources when they eventually fail prologue validation.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

1. **Availability Impact**: Valid user transactions can be incorrectly rejected before consensus, degrading user experience and network reliability. This affects transaction availability but does not compromise funds or consensus safety.

2. **Resource Waste**: Expired transactions kept in mempool due to lagging clocks consume network bandwidth and validator resources processing transactions that will inevitably fail validation.

3. **Inconsistent Mempool State**: Different validators with different system clock skew will have inconsistent views of which transactions are "expired," potentially affecting consensus efficiency and block composition fairness.

4. **No Consensus Break**: The prologue validation using blockchain time provides a final safety check, preventing actually-expired transactions from being committed. This limits the severity to availability/efficiency rather than safety.

This qualifies as **Medium severity** under "State inconsistencies requiring intervention" - while not directly causing fund loss, it creates operational issues requiring clock synchronization intervention across validators.

## Likelihood Explanation

**High Likelihood:**

1. **Natural Clock Drift**: System clocks naturally drift without proper NTP synchronization. Validators running without strict time synchronization will experience this issue organically.

2. **Geographic Distribution**: Validators in different geographic regions may have varying clock accuracy and NTP server accessibility, making time drift common in production.

3. **Low Attack Barrier**: No special privileges required - any validator with system clock manipulation can trigger this, whether intentional or accidental.

4. **Observable in Production**: The code comment acknowledging the time source assumption suggests this design choice was deliberate but potentially overlooked the drift implications.

5. **Continuous Effect**: Unlike one-time exploits, clock drift is an ongoing condition that continuously affects transaction processing.

## Recommendation

**Fix: Use Blockchain Consensus Time for Mempool GC**

When performing garbage collection before consensus pulls transactions, use the last known blockchain timestamp instead of system time. This can be tracked by storing the most recent committed block's timestamp.

**Proposed Solution:**

```rust
// In SharedMempool or CoreMempool, maintain:
struct Mempool {
    // ... existing fields ...
    last_committed_block_timestamp: Arc<AtomicU64>,
}

// Update on commit notifications:
pub(crate) fn process_committed_transactions(
    mempool: &Mutex<CoreMempool>,
    use_case_history: &Mutex<UseCaseHistory>,
    transactions: Vec<CommittedTransaction>,
    block_timestamp_usecs: u64,
) {
    let mut pool = mempool.lock();
    let block_timestamp = Duration::from_micros(block_timestamp_usecs);
    
    // Store for future GC operations
    pool.last_committed_block_timestamp.store(
        block_timestamp_usecs,
        Ordering::Relaxed
    );
    
    // ... rest of function ...
}

// In process_quorum_store_request, replace system time with blockchain time:
let curr_time = Duration::from_micros(
    mempool.last_committed_block_timestamp.load(Ordering::Relaxed)
);
mempool.gc_by_expiration_time(curr_time);
```

**Alternative Conservative Approach:**

Add a safety margin to account for potential blockchain time lag:

```rust
// Allow transactions to stay in mempool longer to account for blockchain lag
let curr_time = aptos_infallible::duration_since_epoch()
    .saturating_sub(Duration::from_secs(BLOCKCHAIN_TIME_LAG_TOLERANCE));
mempool.gc_by_expiration_time(curr_time);
```

Where `BLOCKCHAIN_TIME_LAG_TOLERANCE` (e.g., 30-60 seconds) accounts for maximum expected difference between system time and blockchain time.

## Proof of Concept

**Rust Reproduction Steps:**

```rust
#[test]
fn test_time_source_mismatch_vulnerability() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use aptos_types::transaction::SignedTransaction;
    
    // Setup: Create mempool and mock blockchain state
    let mut mempool = create_test_mempool();
    
    // Current blockchain consensus time (from last committed block)
    let blockchain_time_secs = 1000000u64;
    
    // Simulate validator with system clock 90 seconds ahead
    // In production, this would be actual SystemTime::now()
    let system_time_ahead = blockchain_time_secs + 90;
    
    // Create transaction with expiration 60 seconds from blockchain time
    // This transaction SHOULD be valid for another 60 seconds
    let txn_expiration = blockchain_time_secs + 60;
    let valid_txn = create_test_transaction(txn_expiration);
    
    // Add transaction to mempool
    mempool.add_txn(valid_txn.clone(), /*...*/).unwrap();
    
    // Simulate mempool GC before consensus pull (using system time)
    let gc_time = Duration::from_secs(system_time_ahead);
    mempool.gc_by_expiration_time(gc_time);
    
    // Attempt to retrieve transaction for consensus
    let batch = mempool.get_batch(100, 1000000, true, BTreeMap::new());
    
    // VULNERABILITY: Transaction was incorrectly GC'd despite being valid
    // according to blockchain time
    assert!(
        batch.is_empty(),
        "Valid transaction was incorrectly garbage collected due to \
         system time being ahead of blockchain time"
    );
    
    // However, if we used blockchain time for GC:
    let mut mempool2 = create_test_mempool();
    mempool2.add_txn(valid_txn.clone(), /*...*/).unwrap();
    
    let blockchain_gc_time = Duration::from_secs(blockchain_time_secs);
    mempool2.gc_by_expiration_time(blockchain_gc_time);
    
    let batch2 = mempool2.get_batch(100, 1000000, true, BTreeMap::new());
    
    // Transaction correctly retained
    assert_eq!(
        batch2.len(), 1,
        "Transaction correctly retained when using blockchain time for GC"
    );
}
```

**Observable in Production:**

Monitor validators with different system clock configurations and observe inconsistent transaction rejection rates, particularly for transactions near their expiration time. Validators with clocks ahead of blockchain time will reject more transactions prematurely.

## Notes

**Additional Context:**

The current implementation at [6](#0-5)  correctly uses blockchain timestamp when processing committed transactions, showing that the codebase already has the infrastructure to use blockchain time. The vulnerability only exists in the pre-consensus GC path.

The safer approach of using blockchain consensus time for all expiration-related operations would eliminate this entire class of time-drift vulnerabilities and ensure consistent behavior across all validators regardless of their system clock configuration.

### Citations

**File:** mempool/src/shared_mempool/tasks.rs (L662-665)
```rust
                    // gc before pulling block as extra protection against txns that may expire in consensus
                    // Note: this gc operation relies on the fact that consensus uses the system time to determine block timestamp
                    let curr_time = aptos_infallible::duration_since_epoch();
                    mempool.gc_by_expiration_time(curr_time);
```

**File:** mempool/src/shared_mempool/tasks.rs (L740-742)
```rust
    if block_timestamp_usecs > 0 {
        pool.gc_by_expiration_time(block_timestamp);
    }
```

**File:** consensus/src/util/time_service.rs (L127-129)
```rust
    fn get_current_timestamp(&self) -> Duration {
        aptos_infallible::duration_since_epoch()
    }
```

**File:** aptos-move/framework/aptos-framework/sources/timestamp.move (L31-50)
```text
    /// Updates the wall clock time by consensus. Requires VM privilege and will be invoked during block prologue.
    public fun update_global_time(
        account: &signer,
        proposer: address,
        timestamp: u64
    ) acquires CurrentTimeMicroseconds {
        // Can only be invoked by AptosVM signer.
        system_addresses::assert_vm(account);

        let global_timer = borrow_global_mut<CurrentTimeMicroseconds>(@aptos_framework);
        let now = global_timer.microseconds;
        if (proposer == @vm_reserved) {
            // NIL block with null address as proposer. Timestamp must be equal.
            assert!(now == timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
        } else {
            // Normal block. Time must advance
            assert!(now < timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
            global_timer.microseconds = timestamp;
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L139-142)
```text
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
```

**File:** crates/aptos-infallible/src/time.rs (L9-13)
```rust
pub fn duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
}
```
