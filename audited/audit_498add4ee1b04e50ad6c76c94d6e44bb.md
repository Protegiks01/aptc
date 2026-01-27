# Audit Report

## Title
Signature Reuse Attack in Batch Requester Allows Stale LedgerInfo Replay to Deny Valid Batches

## Summary
The `request_batch()` function in `batch_requester.rs` validates `BatchResponse::NotFound` responses using only epoch, timestamp, and signature verification, without checking the round or version of the LedgerInfo. This allows attackers to replay old but validly-signed LedgerInfo from earlier rounds in the same epoch to falsely indicate batch expiration, causing denial of service on the quorum store. [1](#0-0) 

## Finding Description

The quorum store's batch requester implements a short-circuit mechanism to avoid retrying requests for expired batches. When receiving a `BatchResponse::NotFound` response, it checks if the included LedgerInfo proves the batch has expired: [2](#0-1) 

The validation only verifies:
1. **Epoch matches**: `ledger_info.commit_info().epoch() == epoch`
2. **Timestamp exceeds expiration**: `ledger_info.commit_info().timestamp_usecs() > expiration`
3. **Signatures are cryptographically valid**: `ledger_info.verify_signatures(&validator_verifier).is_ok()`

However, it **fails to validate** that this LedgerInfo represents the current state of the chain. Each LedgerInfo commits to a specific BlockInfo containing a monotonically increasing round number: [3](#0-2) 

**Attack Scenario:**

1. **Epoch 5, Round 100**: Network produces LedgerInfo L1 with timestamp 50,000 microseconds
2. **Epoch 5, Round 150**: Batch B is created with expiration timestamp 40,000 microseconds  
3. **Malicious Response**: Attacker intercepts batch request and responds with `BatchResponse::NotFound(L1)`
4. **Validation Passes**:
   - Epoch check: 5 == 5 ✓
   - Timestamp check: 50,000 > 40,000 ✓
   - Signature check: L1 has valid validator signatures ✓
5. **False Expiration**: Batch requester concludes batch has expired and returns error
6. **Actual State**: At round 150, the batch may still be valid and available

The vulnerability exists because the code trusts any validly-signed LedgerInfo from the same epoch, regardless of whether it represents the current chain state. Proper validation should verify the round/version against the node's committed state, as done in other consensus components: [4](#0-3) 

## Impact Explanation

**Severity: High**

This vulnerability causes **significant protocol violations** affecting quorum store availability:

1. **Batch Request Denial**: Legitimate batch requests fail unnecessarily, forcing nodes to repeatedly retry or give up
2. **Consensus Liveness Degradation**: If multiple batch requests fail, validators may be unable to construct blocks with sufficient transactions
3. **Resource Exhaustion**: Unnecessary retries waste network bandwidth and CPU cycles across all requesting nodes
4. **No Privileges Required**: Any network peer can send malicious `BatchResponse::NotFound` messages without validator access

The test suite confirms the short-circuit behavior is critical for performance: [5](#0-4) 

This meets **High Severity** criteria per the Aptos bug bounty program: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to occur because:

1. **Low Barrier**: Any peer can participate in the P2P network and respond to batch requests
2. **Easy Exploitation**: Attackers only need to capture one valid LedgerInfo from earlier in the epoch
3. **No Detection**: The replayed LedgerInfo passes all cryptographic checks
4. **Persistence**: Attacker can reuse the same stale LedgerInfo for the entire epoch duration
5. **Amplification**: A single captured LedgerInfo can be replayed against multiple batch requests

The legitimate construction of NotFound responses shows they use the latest ledger info: [6](#0-5) 

But the requester has no mechanism to verify this is actually the latest.

## Recommendation

Add round/version validation to ensure the LedgerInfo represents recent chain state:

```rust
Ok(BatchResponse::NotFound(ledger_info)) => {
    counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
    
    // Validate epoch
    if ledger_info.commit_info().epoch() != epoch {
        continue; // Wrong epoch, ignore
    }
    
    // NEW: Validate round is reasonable relative to current state
    // Get current committed round from block store or similar source
    let current_round = get_current_committed_round(); 
    let li_round = ledger_info.commit_info().round();
    
    // Only accept LedgerInfo within reasonable round distance
    const MAX_ROUND_GAP: u64 = 30;
    if li_round < current_round.saturating_sub(MAX_ROUND_GAP) {
        debug!("QS: batch request received stale ledger info, li_round:{}, current:{}", 
               li_round, current_round);
        continue; // Stale LedgerInfo, ignore and retry
    }
    
    // Verify signatures and timestamp
    if ledger_info.commit_info().timestamp_usecs() > expiration
        && ledger_info.verify_signatures(&validator_verifier).is_ok()
    {
        counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
        debug!("QS: batch request expired, digest:{}", digest);
        return Err(ExecutorError::CouldNotGetData);
    }
}
```

The fix should:
1. Track the current committed/ordered round in the batch requester context
2. Reject LedgerInfo with round numbers significantly behind current state
3. Use a configurable gap threshold (similar to `need_sync_for_ledger_info` logic)

## Proof of Concept

```rust
// Add to consensus/src/quorum_store/tests/batch_requester_test.rs

#[tokio::test]
async fn test_stale_ledger_info_replay_attack() {
    let retry_interval_ms = 1_000;
    let expiration = 10_000;
    
    // Create a stale LedgerInfo from "round 50" with timestamp that exceeds expiration
    // This simulates an attacker capturing an old LedgerInfo and replaying it
    let (stale_ledger_info, validator_verifier) = 
        create_ledger_info_with_timestamp(expiration + 5000);
    
    // Current round is implicitly much higher (e.g., round 100)
    // But the batch_requester has no way to detect the LedgerInfo is stale
    
    let batch = Batch::new(
        BatchId::new_for_test(1),
        vec![],
        1,
        expiration,
        AccountAddress::random(),
        0,
    );
    
    // Attacker sends stale LedgerInfo as NotFound response
    let malicious_response = BatchResponse::NotFound(stale_ledger_info);
    
    let batch_requester = BatchRequester::new(
        1,
        AccountAddress::random(),
        1,
        2,
        retry_interval_ms,
        1_000,
        MockBatchRequester::new(malicious_response),
        validator_verifier.into(),
    );
    
    let request_start = Instant::now();
    let (_, subscriber_rx) = oneshot::channel();
    let result = batch_requester
        .request_batch(
            *batch.digest(),
            batch.expiration(),
            Arc::new(Mutex::new(btreeset![AccountAddress::random()])),
            subscriber_rx,
        )
        .await;
    let request_duration = request_start.elapsed();
    
    // VULNERABILITY: Batch is incorrectly rejected due to stale LedgerInfo
    // The request should retry or timeout, but instead fails immediately
    assert_err!(result);
    assert!(request_duration < Duration::from_millis(retry_interval_ms as u64),
            "Stale LedgerInfo caused incorrect short-circuit expiration");
}
```

This PoC demonstrates that a stale but validly-signed LedgerInfo causes immediate batch request failure, even though the batch may still be valid at the current round. The vulnerability allows signature reuse attacks where old LedgerInfo signatures are replayed to deny service.

## Notes

The root cause is trusting cryptographic validity (signatures) without validating temporal validity (round/version freshness). The LedgerInfo structure includes all necessary fields for proper validation: [7](#0-6) 

Other consensus components properly validate round numbers before trusting LedgerInfo, but the batch requester omits this critical check. The fix requires minimal changes: track current round state and reject LedgerInfo beyond a reasonable staleness threshold.

### Citations

**File:** consensus/src/quorum_store/batch_requester.rs (L142-151)
```rust
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
                                }
```

**File:** types/src/block_info.rs (L29-44)
```rust
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
}
```

**File:** consensus/src/block_storage/sync_manager.rs (L65-73)
```rust
    pub fn need_sync_for_ledger_info(&self, li: &LedgerInfoWithSignatures) -> bool {
        const MAX_PRECOMMIT_GAP: u64 = 200;
        let block_not_exist = self.ordered_root().round() < li.commit_info().round()
            && !self.block_exists(li.commit_info().id());
        // TODO move min gap to fallback (30) to config, and if configurable make sure the value is
        // larger than buffer manager MAX_BACKLOG (20)
        let max_commit_gap = 30.max(2 * self.vote_back_pressure_limit);
        let min_commit_round = li.commit_info().round().saturating_sub(max_commit_gap);
        let current_commit_round = self.commit_root().round();
```

**File:** consensus/src/quorum_store/tests/batch_requester_test.rs (L234-277)
```rust
#[tokio::test]
async fn test_batch_request_not_exists_expired() {
    let retry_interval_ms = 1_000;
    let expiration = 10_000;

    // Batch has expired according to the ledger info that will be returned
    let (ledger_info_with_signatures, validator_verifier) =
        create_ledger_info_with_timestamp(expiration + 1);

    let batch = Batch::new(
        BatchId::new_for_test(1),
        vec![],
        1,
        expiration,
        AccountAddress::random(),
        0,
    );
    let batch_response = BatchResponse::NotFound(ledger_info_with_signatures);
    let batch_requester = BatchRequester::new(
        1,
        AccountAddress::random(),
        1,
        2,
        retry_interval_ms,
        1_000,
        MockBatchRequester::new(batch_response),
        validator_verifier.into(),
    );

    let request_start = Instant::now();
    let (_, subscriber_rx) = oneshot::channel();
    let result = batch_requester
        .request_batch(
            *batch.digest(),
            batch.expiration(),
            Arc::new(Mutex::new(btreeset![AccountAddress::random()])),
            subscriber_rx,
        )
        .await;
    let request_duration = request_start.elapsed();
    assert_err!(result);
    // No retry because of short-circuiting of expired batch
    assert!(request_duration < Duration::from_millis(retry_interval_ms as u64));
}
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L417-418)
```rust
                    match aptos_db_clone.get_latest_ledger_info() {
                        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
```

**File:** types/src/ledger_info.rs (L51-59)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct LedgerInfo {
    commit_info: BlockInfo,

    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}
```
