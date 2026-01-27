# Audit Report

## Title
Network-Wide Liveness Failure via Vote Back Pressure Deadlock Under Sustained Execution Delays

## Summary
The `vote_back_pressure()` mechanism in the BlockStore can cause all validators to enter permanent `sync_only` mode if execution consistently lags behind consensus ordering, potentially halting the entire network without a guaranteed recovery path.

## Finding Description

The `sync_only()` function determines whether a validator should stop voting on new proposals: [1](#0-0) 

This function returns `true` when `vote_back_pressure()` returns `true`, which occurs when: [2](#0-1) 

The critical condition is: `ordered_round > vote_back_pressure_limit + commit_round` (with default limit of 12 rounds). [3](#0-2) 

When `sync_only()` is active, validators refuse to vote: [4](#0-3) 

**The Attack Scenario:**

1. Blocks are ordered rapidly via consensus (updating `ordered_root`) [5](#0-4) 

2. Execution pipeline processes blocks slowly, delaying `commit_root` updates [6](#0-5) 

3. When the gap exceeds 12 rounds across all validators simultaneously, all enter `sync_only` mode
4. All validators stop voting, preventing new QC formation
5. No new blocks are ordered, so `ordered_root` stops advancing
6. If execution remains slow/stuck, `commit_root` doesn't catch up
7. **Permanent network-wide consensus halt**

The state sync recovery mechanism requires some validators to be ahead: [7](#0-6) 

If ALL validators hit backpressure uniformly (deterministic execution on similar hardware executing the same slow blocks), no validator advances beyond others, and state sync cannot recover the network.

## Impact Explanation

**Critical Severity**: This meets the "Total loss of liveness/network availability" criterion per the Aptos bug bounty program. If all validators enter permanent `sync_only` mode:
- No new blocks can be proposed or committed
- All transactions are halted
- Network requires manual intervention or hard fork to recover
- Complete consensus failure across the entire validator set

## Likelihood Explanation

**Low-Medium Likelihood** due to multiple requirements:

1. **Execution must be slow uniformly**: All validators must experience slow execution simultaneously (likely due to inherently expensive blocks within gas limits or execution engine bugs)
2. **Gas limits provide partial protection**: Individual attackers cannot trivially create arbitrarily slow blocks
3. **Requires specific conditions**: Gap must exceed 12 rounds across all validators
4. **Mitigating factors**: 
   - Validator hardware diversity might prevent uniform slowdown
   - Pipeline backpressure mechanisms may limit block complexity
   - Proposal resending provides temporary relief

However, the vulnerability becomes realistic if:
- There exists a gas metering discrepancy (operations cheap in gas but expensive in wall-clock time)
- Network experiences sustained stress with many expensive transactions
- Execution engine has performance bugs

## Recommendation

Implement a guaranteed recovery mechanism for network-wide backpressure:

1. **Add timeout-based recovery**: If `sync_only` mode persists beyond a threshold (e.g., 60 seconds), allow voting to resume with reduced block size/complexity limits
   
2. **Implement progressive degradation**: Instead of binary on/off, gradually reduce voting throughput as backpressure increases

3. **Add emergency escape hatch**: If `vote_back_pressure()` is true for more than N consecutive rounds AND no progress is being made on `commit_root`, allow limited voting to resume

4. **Improve monitoring**: Add alerts when gap approaches the limit to allow operator intervention

Example fix for emergency recovery:

```rust
fn sync_only(&self) -> bool {
    let has_backpressure = self.block_store.vote_back_pressure();
    
    // Emergency recovery: if backpressure persists too long, allow voting
    if has_backpressure && self.backpressure_start_time.is_some() {
        let duration = Instant::now().duration_since(self.backpressure_start_time.unwrap());
        if duration > Duration::from_secs(60) {
            warn!("Backpressure exceeded emergency threshold, resuming limited voting");
            return false;  // Allow voting to resume
        }
    }
    
    let sync_or_not = self.local_config.sync_only || has_backpressure;
    // ... rest of function
}
```

## Proof of Concept

Due to the nature of this vulnerability requiring execution delays rather than malicious transaction content, a full PoC would require either:

1. **Simulated execution delay**: Modify the execution client to artificially delay block execution
2. **Find gas metering bug**: Identify operations that are cheap in gas but expensive in execution time

Simplified Rust test outline demonstrating the condition:

```rust
#[tokio::test]
async fn test_network_wide_backpressure_deadlock() {
    // Setup: Create multiple validators with shared slow execution
    let mut validators = create_test_validators(4);
    
    // Phase 1: Rapidly order blocks (12+ blocks)
    for i in 0..15 {
        let block = create_test_block(i);
        for validator in &validators {
            validator.process_proposal(block.clone()).await;
        }
    }
    
    // Phase 2: Execution is delayed - commit_root doesn't advance
    // This would require modifying the execution mock to delay
    
    // Phase 3: Verify all validators enter sync_only mode
    for validator in &validators {
        assert!(validator.round_manager.sync_only());
    }
    
    // Phase 4: Verify no voting occurs
    let new_block = create_test_block(16);
    for validator in &validators {
        let result = validator.process_proposal(new_block.clone()).await;
        assert!(result.is_err()); // Should refuse to vote
    }
    
    // Phase 5: Verify network cannot recover without external intervention
    // All validators stuck, no progress possible
}
```

**Notes:**
- This vulnerability represents a defensive failure mode rather than a direct attack vector
- Requires further investigation into whether gas-cheap but execution-expensive operations exist
- The backpressure mechanism itself is a security feature; this identifies its failure case
- Real-world exploitation requires conditions beyond normal attacker capabilities without additional bugs

### Citations

**File:** consensus/src/round_manager.rs (L956-966)
```rust
    fn sync_only(&self) -> bool {
        let sync_or_not = self.local_config.sync_only || self.block_store.vote_back_pressure();
        if self.block_store.vote_back_pressure() {
            warn!("Vote back pressure is set");
        }
        counters::OP_COUNTERS
            .gauge("sync_only")
            .set(sync_or_not as i64);

        sync_or_not
    }
```

**File:** consensus/src/round_manager.rs (L1514-1517)
```rust
        ensure!(
            !self.sync_only(),
            "[RoundManager] sync_only flag is set, stop voting"
        );
```

**File:** consensus/src/block_storage/block_store.rs (L338-347)
```rust
        self.inner.write().update_ordered_root(block_to_commit.id());
        self.inner
            .write()
            .insert_ordered_cert(finality_proof_clone.clone());
        update_counters_for_ordered_blocks(&blocks_to_commit);

        self.execution_client
            .finalize_order(blocks_to_commit, finality_proof.clone())
            .await
            .expect("Failed to persist commit");
```

**File:** consensus/src/block_storage/block_store.rs (L691-704)
```rust
    fn vote_back_pressure(&self) -> bool {
        #[cfg(any(test, feature = "fuzzing"))]
        {
            if self.back_pressure_for_test.load(Ordering::Relaxed) {
                return true;
            }
        }
        let commit_round = self.commit_root().round();
        let ordered_round = self.ordered_root().round();
        counters::OP_COUNTERS
            .gauge("back_pressure")
            .set((ordered_round - commit_round) as i64);
        ordered_round > self.vote_back_pressure_limit + commit_round
    }
```

**File:** config/src/config/consensus_config.rs (L253-257)
```rust
            // Voting backpressure is only used as a backup, to make sure pending rounds don't
            // increase uncontrollably, and we know when to go to state sync.
            // Considering block gas limit and pipeline backpressure should keep number of blocks
            // in the pipline very low, we can keep this limit pretty low, too.
            vote_back_pressure_limit: 12,
```

**File:** consensus/src/block_storage/block_tree.rs (L341-346)
```rust
    fn update_highest_commit_cert(&mut self, new_commit_cert: WrappedLedgerInfo) {
        if new_commit_cert.commit_info().round() > self.highest_commit_cert.commit_info().round() {
            self.highest_commit_cert = Arc::new(new_commit_cert);
            self.update_commit_root(self.highest_commit_cert.commit_info().id());
        }
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L65-72)
```rust
    pub fn need_sync_for_ledger_info(&self, li: &LedgerInfoWithSignatures) -> bool {
        const MAX_PRECOMMIT_GAP: u64 = 200;
        let block_not_exist = self.ordered_root().round() < li.commit_info().round()
            && !self.block_exists(li.commit_info().id());
        // TODO move min gap to fallback (30) to config, and if configurable make sure the value is
        // larger than buffer manager MAX_BACKLOG (20)
        let max_commit_gap = 30.max(2 * self.vote_back_pressure_limit);
        let min_commit_round = li.commit_info().round().saturating_sub(max_commit_gap);
```
