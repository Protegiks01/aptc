# Audit Report

## Title
DAG Consensus Pipeline Latency Tracking Memory Leak Causes Total Liveness Failure After 30 Seconds

## Summary
The DAG consensus implementation fails to clean up the `block_ordered_ts` tracking map, causing all validators to permanently stop voting after 30 seconds of operation within an epoch, resulting in complete consensus halt.

## Finding Description
The `OrderedNotifierAdapter` in DAG consensus maintains a `block_ordered_ts` map to track when blocks are ordered for pipeline latency measurement. [1](#0-0)  This map is used by `pipeline_pending_latency()` to calculate the elapsed time since the oldest ordered block. [2](#0-1) 

When nodes are ordered, entries are inserted into this map: [3](#0-2) 

However, the cleanup callback that should remove committed blocks from this map is commented out with a TODO: [4](#0-3) 

The `PipelineLatencyBasedBackpressure` implementation compares this growing latency against `voter_pipeline_latency_limit_ms` (default 30,000ms): [5](#0-4) 

When the limit is exceeded, validators refuse to vote on new blocks: [6](#0-5) 

**Security Guarantee Broken**: This violates the Consensus Liveness invariant. After 30 seconds from the first block ordered in an epoch, ALL validators (honest and Byzantine alike) will hit the latency limit and stop voting, causing complete consensus halt until the next epoch boundary.

## Impact Explanation
**Critical Severity** - This meets the "Total loss of liveness/network availability" category. Within 30 seconds of epoch start, the entire DAG consensus network would stop producing blocks. While epochs reset the state (default 2-hour epochs), this creates a 30-second window of liveness followed by consensus halt for the remaining ~7170 seconds of each epoch. [7](#0-6) 

The graduated pipeline backpressure penalties at lower thresholds would also incorrectly trigger as latency grows: [8](#0-7) 

## Likelihood Explanation
**Certain** - This bug triggers automatically on all DAG consensus validators. No attacker action required. The moment the first block is ordered in an epoch, the 30-second countdown begins. This would manifest immediately in any DAG consensus deployment.

Note: The original security question asked about Byzantine validators manipulating latency to avoid penalties. This is NOT that scenario - this is an implementation bug affecting all validators equally, not a Byzantine manipulation attack.

## Recommendation
Implement the commented-out commit callback to clean up the `block_ordered_ts` map when blocks are committed. The callback should:

1. Retain only entries with rounds greater than the committed round
2. Integrate with the pipeline execution completion flow
3. Ensure thread-safe updates to the shared map

The intended logic is shown in the commented code but needs proper integration with `pipeline_builder`.

## Proof of Concept
```rust
// Reproduction: Deploy DAG consensus network and observe:
// 1. At T=0s: First block ordered, entry added to block_ordered_ts
// 2. At T=30s: pipeline_pending_latency() returns 30s
// 3. At T=30s: stop_voting() returns true for all validators  
// 4. At T=30s+: All validators refuse votes with VoteRefused error
// 5. Result: Consensus halts, no new blocks can be voted on

// To verify, add logging in pipeline_pending_latency():
// consensus/src/dag/adapter.rs line 129
// Check that block_ordered_ts size grows unbounded and
// latency continues increasing past 30 seconds
```

## Notes
This finding differs from the original security question which asked about Byzantine validators manipulating their latency. The actual vulnerability is an implementation bug that affects all validators equally - Byzantine validators cannot exploit this any differently than honest validators. The missing cleanup is a critical liveness bug, not a Byzantine manipulation vector.

### Citations

**File:** consensus/src/dag/adapter.rs (L101-101)
```rust
    block_ordered_ts: Arc<RwLock<BTreeMap<Round, Instant>>>,
```

**File:** consensus/src/dag/adapter.rs (L125-134)
```rust
    pub(super) fn pipeline_pending_latency(&self) -> Duration {
        match self.block_ordered_ts.read().first_key_value() {
            Some((round, timestamp)) => {
                let latency = timestamp.elapsed();
                info!(round = round, latency = latency, "pipeline pending latency");
                latency
            },
            None => Duration::ZERO,
        }
    }
```

**File:** consensus/src/dag/adapter.rs (L203-205)
```rust
        self.block_ordered_ts
            .write()
            .insert(block_info.round(), Instant::now());
```

**File:** consensus/src/dag/adapter.rs (L215-228)
```rust
            // TODO: this needs to be properly integrated with pipeline_builder
            // callback: Box::new(
            //     move |committed_blocks: &[Arc<PipelinedBlock>],
            //           commit_decision: LedgerInfoWithSignatures| {
            //         block_created_ts
            //             .write()
            //             .retain(|&round, _| round > commit_decision.commit_info().round());
            //         dag.commit_callback(commit_decision.commit_info().round());
            //         ledger_info_provider
            //             .write()
            //             .notify_commit_proof(commit_decision);
            //         update_counters_for_committed_blocks(committed_blocks);
            //     },
            // ),
```

**File:** consensus/src/dag/health/pipeline_health.rs (L77-80)
```rust
    fn stop_voting(&self) -> bool {
        let latency = self.adapter.pipeline_pending_latency();
        latency > self.voter_pipeline_latency_limit
    }
```

**File:** consensus/src/dag/rb_handler.rs (L219-222)
```rust
        ensure!(
            !self.health_backoff.stop_voting(),
            NodeBroadcastHandleError::VoteRefused
        );
```

**File:** config/src/config/dag_consensus_config.rs (L147-154)
```rust
impl Default for DagHealthConfig {
    fn default() -> Self {
        Self {
            chain_backoff_config: Vec::new(),
            voter_pipeline_latency_limit_ms: 30_000,
            pipeline_backpressure_config: Vec::new(),
        }
    }
```

**File:** config/src/config/consensus_config.rs (L270-318)
```rust
                    back_pressure_pipeline_latency_limit_ms: 1200,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 50,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1500,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 100,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1900,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 200,
                },
                // with execution backpressure, only later start reducing block size
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 2500,
                    max_sending_block_txns_after_filtering_override: 1000,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 3500,
                    max_sending_block_txns_after_filtering_override: 200,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 4500,
                    max_sending_block_txns_after_filtering_override: 30,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 6000,
                    // in practice, latencies and delay make it such that ~2 blocks/s is max,
                    // meaning that most aggressively we limit to ~10 TPS
                    // For transactions that are more expensive than that, we should
                    // instead rely on max gas per block to limit latency.
                    max_sending_block_txns_after_filtering_override: 5,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
```
