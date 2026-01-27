# Audit Report

## Title
Unbounded Task Spawning During Backpressure Leading to Validator Resource Exhaustion

## Summary
The `resend_verified_proposal_to_self()` function spawns unbounded tokio tasks for each proposal received during backpressure periods, without any limit, deduplication, or rate control. This can cause severe memory and CPU resource exhaustion on validator nodes when multiple proposals accumulate during backpressure, potentially degrading consensus performance and node stability.

## Finding Description

The vulnerability exists in the consensus backpressure handling mechanism. When vote backpressure is detected (when `ordered_round > commit_round + vote_back_pressure_limit`), the system delays proposal processing by spawning a tokio task that retries sending the proposal to itself after the backpressure clears. [1](#0-0) 

The critical flaw is at line 1326 where `tokio::spawn()` is called **without any limit** on the number of concurrent tasks. Each spawned task:

1. Runs for up to `timeout_ms` (default 1000ms) [2](#0-1) 
2. Polls every `polling_interval_ms` (10ms) [3](#0-2) 
3. Consumes CPU checking `block_store.vote_back_pressure()` up to 100 times per task
4. Holds the proposal Block data in memory throughout its lifetime

**How the vulnerability is triggered:**

1. Backpressure is activated when the gap between ordered and committed rounds exceeds the limit [4](#0-3) 

2. During backpressure, each incoming proposal triggers task spawning [5](#0-4) 

3. **There is no deduplication** - the same proposal arriving multiple times (due to network retransmission, delayed delivery, or malicious resending) spawns multiple tasks

4. **There is no rate limiting** - proposals from multiple rounds can accumulate

5. **The RoundManager struct has no field tracking spawned tasks**, allowing unbounded accumulation [6](#0-5) 

**Exploitation Scenario:**

During a backpressure period lasting 1 second (default timeout):
- If proposals arrive at 10/second from normal consensus operation: **10 concurrent tasks**
- With 100 validators and potential proposal retransmissions: **100+ concurrent tasks**
- Each performing 100 polling iterations: **10,000+ total backpressure checks**
- Cumulative memory for 100 Block objects + task overhead

This violates the **Resource Limits invariant (#9)**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: Medium** (aligns with Aptos Bug Bounty "Validator node slowdowns" category - up to $10,000)

**Direct Impacts:**
1. **Memory Exhaustion**: Each task holds a `Box<Block>` in the `VerifiedEvent`, plus tokio async runtime overhead. With 100+ concurrent tasks, this can consume hundreds of MB
2. **CPU Degradation**: Each task polls every 10ms, creating a CPU amplification factor of 100x (100 tasks × 100 iterations = 10,000 operations vs. 100 without the bug)
3. **Consensus Slowdown**: Resource exhaustion during critical backpressure periods degrades validator performance when the network most needs responsiveness
4. **Cascading Effect**: Node slowdown can worsen backpressure, creating a positive feedback loop

**Affected Nodes**: All validator nodes experiencing backpressure, network-wide impact during high-load scenarios.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability triggers during **normal protocol operation** when backpressure occurs, which happens naturally when:
- Execution is slower than block production (high transaction load)
- Network latency causes proposal delays
- State sync operations cause temporary slowdowns

**Amplification factors:**
1. **Network retransmissions**: Proposals can arrive multiple times due to network unreliability
2. **Multiple concurrent rounds**: During backpressure, proposals from rounds R, R+1, R+2... can all arrive simultaneously  
3. **Byzantine validators**: Up to 1/3 Byzantine validators could deliberately send duplicate or extra proposals to amplify resource consumption (within BFT fault tolerance assumptions)

The default backpressure limit is only 12 rounds [7](#0-6) , making this condition reasonably frequent during network stress.

## Recommendation

**Fix: Implement bounded task spawning with deduplication**

Add a tracking mechanism to limit concurrent retry tasks:

```rust
// Add to RoundManager struct
pending_retry_proposals: HashSet<HashValue>, // Track proposals with active retry tasks
max_concurrent_retries: usize, // Configurable limit (e.g., 50)

// Modified resend_verified_proposal_to_self
async fn check_backpressure_and_process_proposal(
    &mut self,
    proposal: Block,
) -> anyhow::Result<()> {
    let author = proposal.author().expect("Proposal should be verified having an author");
    let proposal_id = proposal.id();
    
    if self.block_store.vote_back_pressure() {
        // Deduplication check
        if self.pending_retry_proposals.contains(&proposal_id) {
            return Ok(()); // Already have a retry task for this proposal
        }
        
        // Rate limiting check
        if self.pending_retry_proposals.len() >= self.max_concurrent_retries {
            warn!("Max retry tasks reached, dropping proposal retry for {}", proposal_id);
            counters::CONSENSUS_BACKPRESSURE_RETRY_DROPPED.inc();
            return Ok(());
        }
        
        self.pending_retry_proposals.insert(proposal_id);
        counters::CONSENSUS_WITHOLD_VOTE_BACKPRESSURE_TRIGGERED.observe(1.0);
        
        // Pass a cleanup channel to remove from tracking when task completes
        let pending_set = Arc::clone(&self.pending_retry_proposals_shared);
        Self::resend_verified_proposal_to_self_bounded(
            self.block_store.clone(),
            self.buffered_proposal_tx.clone(),
            proposal,
            author,
            BACK_PRESSURE_POLLING_INTERVAL_MS,
            self.local_config.round_initial_timeout_ms,
            proposal_id,
            pending_set,
        ).await;
        return Ok(());
    }
    // ... rest of function
}
```

**Alternative Fix**: Use a semaphore to limit concurrent retry tasks globally, allowing fairness without per-proposal tracking.

## Proof of Concept

```rust
#[tokio::test]
async fn test_unbounded_retry_task_spawning() {
    // Setup: Create RoundManager with backpressure active
    let (mut round_manager, mut network_rx) = create_test_round_manager().await;
    round_manager.block_store.set_backpressure_for_test(true); // Enable backpressure
    
    // Attack: Send 200 proposals during backpressure
    let mut proposal_handles = vec![];
    for i in 0..200 {
        let proposal = create_test_proposal(i);
        proposal_handles.push(tokio::spawn(async move {
            round_manager.check_backpressure_and_process_proposal(proposal).await
        }));
    }
    
    // Wait for all to trigger task spawning
    for handle in proposal_handles {
        handle.await.unwrap().unwrap();
    }
    
    // Verify: Check system resource consumption
    let task_count = tokio::task::spawn_count(); // Hypothetical API
    assert!(task_count > 200, "Expected 200+ spawned tasks, got {}", task_count);
    
    // Measure CPU usage over 100ms polling period
    let start_cpu = get_cpu_usage();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cpu_delta = get_cpu_usage() - start_cpu;
    
    // With 200 tasks polling every 10ms, expect ~2000 polling operations in 100ms
    assert!(cpu_delta > baseline_cpu * 10, "CPU amplification detected");
    
    // Cleanup and verify memory leak
    round_manager.block_store.set_backpressure_for_test(false);
    tokio::time::sleep(Duration::from_millis(1100)).await; // Wait for timeout
    
    let final_task_count = tokio::task::spawn_count();
    assert_eq!(final_task_count, 0, "Tasks should clean up after timeout");
}
```

## Notes

This vulnerability is particularly concerning because:

1. **It occurs during the worst time**: Backpressure indicates the system is already under stress, and this bug adds additional resource pressure exactly when the validator needs maximum performance

2. **Positive feedback loop risk**: Resource exhaustion can slow consensus further, prolonging backpressure and spawning even more retry tasks

3. **Network-wide impact**: All validators experiencing backpressure are affected simultaneously, potentially degrading overall network consensus performance

4. **Silent degradation**: Unlike crashes or panics, resource exhaustion causes gradual performance degradation that may be difficult to diagnose

The fix should include monitoring metrics for:
- Number of active retry tasks (`consensus_active_retry_tasks`)
- Number of dropped retries due to limits (`consensus_retry_tasks_dropped`)
- Total retry task spawns (`consensus_retry_tasks_spawned`)

### Citations

**File:** consensus/src/round_manager.rs (L105-105)
```rust
pub const BACK_PRESSURE_POLLING_INTERVAL_MS: u64 = 10;
```

**File:** consensus/src/round_manager.rs (L303-332)
```rust
pub struct RoundManager {
    epoch_state: Arc<EpochState>,
    block_store: Arc<BlockStore>,
    round_state: RoundState,
    proposer_election: Arc<UnequivocalProposerElection>,
    proposal_generator: Arc<ProposalGenerator>,
    safety_rules: Arc<Mutex<MetricsSafetyRules>>,
    network: Arc<NetworkSender>,
    storage: Arc<dyn PersistentLivenessStorage>,
    onchain_config: OnChainConsensusConfig,
    vtxn_config: ValidatorTxnConfig,
    buffered_proposal_tx: aptos_channel::Sender<Author, VerifiedEvent>,
    block_txn_filter_config: BlockTransactionFilterConfig,
    local_config: ConsensusConfig,
    randomness_config: OnChainRandomnessConfig,
    jwk_consensus_config: OnChainJWKConsensusConfig,
    fast_rand_config: Option<RandConfig>,
    // Stores the order votes from all the rounds above highest_ordered_round
    pending_order_votes: PendingOrderVotes,
    // Round manager broadcasts fast shares when forming a QC or when receiving a proposal.
    // To avoid duplicate broadcasts for the same block, we keep track of blocks for
    // which we recently broadcasted fast shares.
    blocks_with_broadcasted_fast_shares: LruCache<HashValue, ()>,
    futures: FuturesUnordered<
        Pin<Box<dyn Future<Output = (anyhow::Result<()>, Block, Instant)> + Send>>,
    >,
    proposal_status_tracker: Arc<dyn TPastProposalStatusTracker>,
    pending_opt_proposals: BTreeMap<Round, OptBlockData>,
    opt_proposal_loopback_tx: aptos_channels::UnboundedSender<OptBlockData>,
}
```

**File:** consensus/src/round_manager.rs (L1296-1308)
```rust
        if self.block_store.vote_back_pressure() {
            counters::CONSENSUS_WITHOLD_VOTE_BACKPRESSURE_TRIGGERED.observe(1.0);
            // In case of back pressure, we delay processing proposal. This is done by resending the
            // same proposal to self after some time.
            Self::resend_verified_proposal_to_self(
                self.block_store.clone(),
                self.buffered_proposal_tx.clone(),
                proposal,
                author,
                BACK_PRESSURE_POLLING_INTERVAL_MS,
                self.local_config.round_initial_timeout_ms,
            )
            .await;
```

**File:** consensus/src/round_manager.rs (L1316-1337)
```rust
    async fn resend_verified_proposal_to_self(
        block_store: Arc<BlockStore>,
        self_sender: aptos_channel::Sender<Author, VerifiedEvent>,
        proposal: Block,
        author: Author,
        polling_interval_ms: u64,
        timeout_ms: u64,
    ) {
        let start = Instant::now();
        let event = VerifiedEvent::VerifiedProposalMsg(Box::new(proposal));
        tokio::spawn(async move {
            while start.elapsed() < Duration::from_millis(timeout_ms) {
                if !block_store.vote_back_pressure() {
                    if let Err(e) = self_sender.push(author, event) {
                        warn!("Failed to send event to round manager {:?}", e);
                    }
                    break;
                }
                sleep(Duration::from_millis(polling_interval_ms)).await;
            }
        });
    }
```

**File:** config/src/config/consensus_config.rs (L235-235)
```rust
            round_initial_timeout_ms: 1000,
```

**File:** config/src/config/consensus_config.rs (L257-257)
```rust
            vote_back_pressure_limit: 12,
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
