# Audit Report

## Title
Memory Exhaustion in BufferManager's Commit Vote Cache Due to Unbounded Configuration Parameter

## Summary
The `max_pending_rounds_in_commit_vote_cache` configuration parameter lacks upper bound validation, allowing misconfiguration that enables malicious validators to exhaust node memory through commit vote spam, potentially causing validator OOM crashes and network disruption.

## Finding Description

The `BufferManager` in the consensus pipeline maintains a cache of pending commit votes for future rounds. The cache size is controlled by the `max_pending_rounds_in_commit_vote_cache` configuration parameter, which defaults to 100 but can be set to any `u64` value without validation. [1](#0-0) [2](#0-1) 

The cache stores commit votes in a `BTreeMap<Round, HashMap<AccountAddress, CommitVote>>` structure: [3](#0-2) 

When a commit vote is received, it's validated and cached if within the acceptable range: [4](#0-3) 

The vulnerability arises because:

1. **No Upper Bound Validation**: The configuration sanitization does not validate `max_pending_rounds_in_commit_vote_cache`: [5](#0-4) 

2. **Delayed Cleanup**: Cached votes are only removed when rounds are committed: [6](#0-5) 

3. **Signature-Only Verification**: Commit votes only require valid validator signatures, not actual block existence: [7](#0-6) 

**Attack Scenario:**

If `max_pending_rounds_in_commit_vote_cache` is misconfigured to 1,000,000, a malicious Byzantine validator (within the <1/3 Byzantine assumption) can:

1. Construct `LedgerInfo` structures for 1,000,000 future rounds with arbitrary block IDs
2. Sign each with their validator key  
3. Send these commit votes to other validators
4. All signatures verify successfully (valid validator signatures)
5. All votes are cached in memory regardless of whether matching blocks exist

**Memory Calculation:**
- Per commit vote: ~500 bytes (AccountAddress + LedgerInfo + BLS Signature)
- Single malicious validator: 1,000,000 rounds × 500 bytes = **500 MB**
- 10 Byzantine validators: 1,000,000 rounds × 10 validators × 500 bytes = **5 GB**
- With max value (10,000,000 rounds): Up to **50-500 GB** depending on validator participation

Votes remain cached until those rounds are reached (potentially days/weeks at 1-2 seconds per round), causing sustained memory exhaustion.

## Impact Explanation

This vulnerability allows validator Out-of-Memory (OOM) crashes, qualifying as **Medium Severity** under the Aptos bug bounty criteria:

- **Validator node slowdowns** (High Severity boundary): Memory pressure degrades node performance
- **State inconsistencies requiring intervention** (Medium Severity): Crashed validators require manual recovery
- **Consensus liveness impact**: Multiple validator crashes reduce network capacity and increase consensus latency

The impact is limited by requiring both misconfiguration and Byzantine validator participation, preventing Critical severity classification.

## Likelihood Explanation

**Likelihood: Low-to-Medium**

**Prerequisites:**
1. Administrator misconfigures `max_pending_rounds_in_commit_vote_cache` to an unsafe value (>10,000)
2. At least one Byzantine validator in the active set (within Aptos's <1/3 Byzantine tolerance)

**Mitigating Factors:**
- Default value (100) is safe
- Requires explicit configuration change
- Byzantine validators needed (though part of threat model)

**Aggravating Factors:**
- No validation prevents misconfiguration
- No warnings in logs or documentation
- Comment in code still mentions "100 rounds" despite configurable parameter
- Once misconfigured, exploitation is straightforward

## Recommendation

**Immediate Fix:** Add validation to bound the parameter to a safe maximum:

```rust
// In config/src/config/consensus_config.rs
const MAX_SAFE_PENDING_COMMIT_VOTE_CACHE: u64 = 1000;

impl ConfigSanitizer for ConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        
        // Validate max_pending_rounds_in_commit_vote_cache
        if node_config.consensus.max_pending_rounds_in_commit_vote_cache > MAX_SAFE_PENDING_COMMIT_VOTE_CACHE {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "max_pending_rounds_in_commit_vote_cache ({}) exceeds safe maximum ({})",
                    node_config.consensus.max_pending_rounds_in_commit_vote_cache,
                    MAX_SAFE_PENDING_COMMIT_VOTE_CACHE
                ),
            ));
        }
        
        // ... existing validation ...
    }
}
```

**Additional Hardening:**
1. Add rate limiting on commit vote processing per validator
2. Add metrics monitoring cache size
3. Update code comment on line 343 to reflect configurable nature
4. Add documentation warning about memory implications

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_commit_vote_cache_memory_exhaustion() {
    // Setup: Configure BufferManager with large cache size
    let large_cache_size = 100_000u64; // Reduced for test, but demonstrates issue
    let mut config = ConsensusConfig::default();
    config.max_pending_rounds_in_commit_vote_cache = large_cache_size;
    
    // Create a validator signer
    let validator_signer = ValidatorSigner::random([0u8; 32]);
    let author = validator_signer.author();
    
    // Track memory before attack
    let initial_memory = get_process_memory_mb();
    
    // Attack: Send commit votes for many future rounds
    let current_round = 1000u64;
    for future_round in (current_round + 1)..(current_round + large_cache_size) {
        // Create a fake LedgerInfo for future round
        let block_info = BlockInfo::new(
            0, // epoch
            future_round,
            HashValue::random(),
            HashValue::random(),
            0, // version
            0, // timestamp
            None, // next_epoch_state
        );
        let ledger_info = LedgerInfo::new(block_info, HashValue::random());
        
        // Sign it with validator key
        let commit_vote = CommitVote::new(author, ledger_info, &validator_signer)
            .expect("Failed to create commit vote");
        
        // Send to buffer manager (would be through network in real scenario)
        send_commit_vote(commit_vote).await;
    }
    
    // Verify memory consumption increased significantly
    let final_memory = get_process_memory_mb();
    let memory_increase_mb = final_memory - initial_memory;
    
    // With 100k rounds × ~500 bytes each = ~50 MB expected increase
    assert!(memory_increase_mb > 40, 
        "Memory did not increase as expected. Increase: {} MB", memory_increase_mb);
    
    println!("Memory exhaustion demonstrated: {} MB consumed", memory_increase_mb);
}
```

**Notes**

This vulnerability represents a **configuration-dependent DoS attack** within the Aptos consensus threat model. While requiring both misconfiguration and Byzantine validator participation, it violates the **Resource Limits** invariant by allowing unbounded memory consumption. The absence of validation on this security-critical parameter represents a defense-in-depth failure that should be addressed through the recommended bounds checking.

### Citations

**File:** config/src/config/consensus_config.rs (L99-99)
```rust
    pub max_pending_rounds_in_commit_vote_cache: u64,
```

**File:** config/src/config/consensus_config.rs (L381-381)
```rust
            max_pending_rounds_in_commit_vote_cache: 100,
```

**File:** config/src/config/consensus_config.rs (L503-532)
```rust
impl ConfigSanitizer for ConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // Verify that the safety rules and quorum store configs are valid
        SafetyRulesConfig::sanitize(node_config, node_type, chain_id)?;
        QuorumStoreConfig::sanitize(node_config, node_type, chain_id)?;

        // Verify that the consensus-only feature is not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && is_consensus_only_perf_test_enabled() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "consensus-only-perf-test should not be enabled in mainnet!".to_string(),
                ));
            }
        }

        // Sender block limits must be <= receiver block limits
        Self::sanitize_send_recv_block_limits(&sanitizer_name, &node_config.consensus)?;

        // Quorum store batches must be <= consensus blocks
        Self::sanitize_batch_block_limits(&sanitizer_name, &node_config.consensus)?;

        Ok(())
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L167-170)
```rust
    max_pending_rounds_in_commit_vote_cache: u64,
    // If the buffer manager receives a commit vote for a block that is not in buffer items, then
    // the vote will be cached. We can cache upto max_pending_rounds_in_commit_vote_cache (100) blocks.
    pending_commit_votes: BTreeMap<Round, HashMap<AccountAddress, CommitVote>>,
```

**File:** consensus/src/pipeline/buffer_manager.rs (L335-361)
```rust
    fn try_add_pending_commit_vote(&mut self, vote: CommitVote) -> bool {
        let block_id = vote.commit_info().id();
        let round = vote.commit_info().round();

        // Don't need to store commit vote if we have already committed up to that round
        if round <= self.highest_committed_round {
            true
        } else
        // Store the commit vote only if it is for one of the next 100 rounds.
        if round > self.highest_committed_round
            && self.highest_committed_round + self.max_pending_rounds_in_commit_vote_cache > round
        {
            self.pending_commit_votes
                .entry(round)
                .or_default()
                .insert(vote.author(), vote);
            true
        } else {
            debug!(
                round = round,
                highest_committed_round = self.highest_committed_round,
                block_id = block_id,
                "Received a commit vote not in the next 100 rounds, ignored."
            );
            false
        }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L919-933)
```rust
        spawn_named!("buffer manager verification", async move {
            while let Some((sender, commit_msg)) = commit_msg_rx.next().await {
                let tx = verified_commit_msg_tx.clone();
                let epoch_state_clone = epoch_state.clone();
                bounded_executor
                    .spawn(async move {
                        match commit_msg.req.verify(sender, &epoch_state_clone.verifier) {
                            Ok(_) => {
                                let _ = tx.unbounded_send(commit_msg);
                            },
                            Err(e) => warn!("Invalid commit message: {}", e),
                        }
                    })
                    .await;
            }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L968-972)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
```
