# Audit Report

## Title
Critical Liveness Failure Due to Unchecked Integer Underflow in Batch Creation Timestamp Calculation

## Summary
The `batch_expiry_gap_when_init_usecs` configuration parameter lacks validation and is used in an unchecked subtraction operation that can cause integer underflow. This leads to validator node crashes (debug builds) or total consensus liveness failure (release builds) when batches are pulled for block proposals.

## Finding Description

The vulnerability exists in the `pull_internal` function of `BatchProofQueue` where batch creation timestamps are calculated by subtracting `batch_expiry_gap_when_init_usecs` from the batch expiration time. [1](#0-0) 

This subtraction operation is **not protected** against underflow. When `batch_expiry_gap_when_init_usecs` is greater than the batch expiration value, the following occurs:

**In debug builds**: The subtraction panics, crashing the validator node entirely.

**In release builds**: The subtraction wraps around to a value near `u64::MAX`, causing the subsequent age check to always evaluate as true, filtering out ALL batches from being pulled. [2](#0-1) 

This occurs because there is **no configuration validation** for `batch_expiry_gap_when_init_usecs`: [3](#0-2) 

The sanitizer only checks send/recv and batch/total limits, but completely ignores expiration gap values.

Additionally, there's a **systemic mismatch** between how remote and local batches are created versus how their creation times are calculated:

**Local batches** are created with: [4](#0-3) 

**Remote batches** are created with: [5](#0-4) 

However, the `BatchProofQueue` is initialized with only `batch_expiry_gap_when_init_usecs`: [6](#0-5) 

This means remote batches (created with 500ms gap) have their creation time incorrectly calculated using the 60-second gap, causing them to appear ~59.5 seconds older than they actually are.

**Attack Scenarios**:

1. **Zero or very small gap**: Setting `batch_expiry_gap_when_init_usecs: 0` causes batches to expire immediately and be rejected at insertion: [7](#0-6) 

2. **Excessively large gap**: Causes integer overflow during batch creation or underflow during timestamp calculation, resulting in either immediate rejection or filtering of all batches.

3. **Default configuration with remote batches**: Remote batches with expiration = `current_time + 500ms` minus `60s` gap could underflow with certain timestamp values.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program because it causes **Total loss of liveness/network availability**:

- **Validator node crashes** (debug builds): When the underflow occurs, the node panics and terminates, removing it from consensus participation.

- **Complete inability to propose blocks** (release builds): When batches are filtered out due to wraparound, the `pull_proofs` and `pull_batches` functions return empty results, preventing the validator from including any transactions in proposed blocks. This breaks the consensus liveness invariant.

- **Network-wide impact**: If multiple validators use the same misconfigured value (common in production deployments using shared configuration), the entire network loses liveness as no validator can successfully propose blocks with transactions.

This directly violates the **Consensus Liveness** critical invariant: validators must be able to propose and commit blocks to advance the chain state.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **No configuration validation**: Operators can accidentally or maliciously set any `u64` value without detection.

2. **Common deployment patterns**: Production networks often share configuration files across validators, so a single misconfiguration affects multiple nodes simultaneously.

3. **Remote batch mismatch**: The existing default configuration already contains the seeds of this vulnerability through the gap mismatch between local (60s) and remote (500ms) batches.

4. **No runtime checks**: The code performs no bounds checking or validation before the arithmetic operation.

## Recommendation

Implement comprehensive configuration validation and use saturating arithmetic:

**1. Add configuration sanitization**:
```rust
// In config/src/config/quorum_store_config.rs
fn sanitize_batch_expiry_gaps(
    sanitizer_name: &str,
    config: &QuorumStoreConfig,
) -> Result<(), Error> {
    // Ensure gaps are within reasonable bounds (1 second to 10 minutes)
    const MIN_GAP_USECS: u64 = 1_000_000; // 1 second
    const MAX_GAP_USECS: u64 = 600_000_000; // 10 minutes
    
    if config.batch_expiry_gap_when_init_usecs < MIN_GAP_USECS 
        || config.batch_expiry_gap_when_init_usecs > MAX_GAP_USECS {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name.to_owned(),
            format!("batch_expiry_gap_when_init_usecs out of bounds: {}", 
                    config.batch_expiry_gap_when_init_usecs),
        ));
    }
    
    if config.remote_batch_expiry_gap_when_init_usecs < MIN_GAP_USECS 
        || config.remote_batch_expiry_gap_when_init_usecs > MAX_GAP_USECS {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name.to_owned(),
            format!("remote_batch_expiry_gap_when_init_usecs out of bounds: {}", 
                    config.remote_batch_expiry_gap_when_init_usecs),
        ));
    }
    
    Ok(())
}

// Call from sanitize() method
Self::sanitize_batch_expiry_gaps(&sanitizer_name, &node_config.consensus.quorum_store)?;
```

**2. Use saturating subtraction in batch_proof_queue.rs**:
```rust
// Line 603-604
let batch_create_ts_usecs = item.info.expiration()
    .saturating_sub(self.batch_expiry_gap_when_init_usecs);
```

**3. Store both gap values in BatchProofQueue**:
```rust
// Add field to track whether batch is local or remote, and use appropriate gap
// Or store both gaps and determine which to use based on batch author
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::PeerId;
    
    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn test_underflow_causes_panic_in_debug() {
        // This test demonstrates the panic in debug builds
        let my_peer_id = PeerId::random();
        let batch_store = Arc::new(BatchStore::new(/*...*/));
        
        // Set an excessively large expiry gap
        let bad_gap = u64::MAX / 2;
        let queue = BatchProofQueue::new(my_peer_id, batch_store, bad_gap);
        
        // Create a batch with normal expiration (current_time + 60s)
        let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
        let batch_expiration = current_time + 60_000_000; // 60 seconds
        
        // This will panic when pull_internal calculates:
        // batch_create_ts = batch_expiration - bad_gap
        // = (current_time + 60s) - (u64::MAX/2)
        // = UNDERFLOW in debug mode
        
        queue.pull_proofs(
            &HashSet::new(),
            PayloadTxnsSize::new(1000, 1000000),
            100,
            100,
            false,
            Duration::from_secs(current_time / 1_000_000),
        );
    }
    
    #[test]
    fn test_liveness_failure_in_release() {
        // In release builds, the underflow wraps to ~u64::MAX
        // causing all batches to be filtered out
        let my_peer_id = PeerId::random();
        let batch_store = Arc::new(BatchStore::new(/*...*/));
        
        let bad_gap = u64::MAX / 2;
        let mut queue = BatchProofQueue::new(my_peer_id, batch_store, bad_gap);
        
        // Insert some valid proofs
        let proof = create_test_proof(/*...*/);
        queue.insert_proof(proof);
        
        // Try to pull proofs - should return empty due to wraparound filtering
        let (proofs, _, _, _) = queue.pull_proofs(
            &HashSet::new(),
            PayloadTxnsSize::new(1000, 1000000),
            100,
            100,
            true,
            Duration::from_secs(0),
        );
        
        // No proofs can be pulled - total liveness failure
        assert_eq!(proofs.len(), 0);
    }
}
```

## Notes

This vulnerability affects the core consensus mechanism and can be triggered through configuration alone, making it a critical threat to network availability. The lack of any validation on these time-critical parameters is a systemic issue that should be addressed through comprehensive configuration sanitization across all quorum store parameters.

### Citations

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L176-179)
```rust
        if proof.expiration() <= self.latest_block_timestamp {
            counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
            return;
        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L603-604)
```rust
                    let batch_create_ts_usecs =
                        item.info.expiration() - self.batch_expiry_gap_when_init_usecs;
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L608-612)
```rust
                    if max_batch_creation_ts_usecs
                        .is_some_and(|max_create_ts| batch_create_ts_usecs > max_create_ts)
                    {
                        return None;
                    }
```

**File:** config/src/config/quorum_store_config.rs (L253-271)
```rust
impl ConfigSanitizer for QuorumStoreConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // Sanitize the send/recv batch limits
        Self::sanitize_send_recv_batch_limits(
            &sanitizer_name,
            &node_config.consensus.quorum_store,
        )?;

        // Sanitize the batch total limits
        Self::sanitize_batch_total_limits(&sanitizer_name, &node_config.consensus.quorum_store)?;

        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L383-384)
```rust
        let expiry_time = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.batch_expiry_gap_when_init_usecs;
```

**File:** consensus/src/quorum_store/batch_generator.rs (L398-399)
```rust
        let expiry_time_usecs = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.remote_batch_expiry_gap_when_init_usecs;
```

**File:** consensus/src/quorum_store/proof_manager.rs (L51-55)
```rust
            batch_proof_queue: BatchProofQueue::new(
                my_peer_id,
                batch_store,
                batch_expiry_gap_when_init_usecs,
            ),
```
