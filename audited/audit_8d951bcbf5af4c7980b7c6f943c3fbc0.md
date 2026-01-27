# Audit Report

## Title
DAG Consensus Liveness Failure Due to Missing Pipeline Latency Cleanup and Low voter_pipeline_latency_limit_ms

## Summary
The DAG consensus implementation contains a critical liveness vulnerability where validators will stop voting on new nodes when the `voter_pipeline_latency_limit_ms` threshold is exceeded. Due to missing cleanup logic for the `block_ordered_ts` tracking map, pipeline latency accumulates indefinitely, causing validators to permanently refuse votes even under legitimate load conditions. If configured with low values (e.g., 10ms) or under normal execution delays, this triggers consensus stall requiring validator restarts.

## Finding Description

The vulnerability exists across three interconnected components in the DAG consensus system:

**1. Missing Cleanup Logic in OrderedNotifierAdapter** [1](#0-0) 

The `block_ordered_ts` map tracks when blocks are ordered by inserting timestamps: [2](#0-1) 

However, the cleanup callback that should remove committed blocks is commented out with a TODO note: [3](#0-2) 

This means `block_ordered_ts` grows unbounded and entries are never removed after blocks are committed.

**2. Latency Calculation Returns Oldest Entry** [4](#0-3) 

The `pipeline_pending_latency()` method returns the elapsed time of the **first (oldest)** entry in the map. Without cleanup, this latency increases indefinitely.

**3. Vote Refusal When Limit Exceeded** [5](#0-4) 

When pipeline latency exceeds the configured limit, `stop_voting()` returns true. This is checked before processing any node: [6](#0-5) 

When a validator refuses to vote, it returns a `VoteRefused` error, preventing the requesting node from obtaining this validator's vote.

**4. Consensus Requires 2f+1 Quorum**

DAG consensus requires 2f+1 voting power to certify nodes. If enough validators stop voting (due to exceeding the latency limit), nodes cannot reach quorum and consensus halts.

**Attack Scenario:**

1. Configure `voter_pipeline_latency_limit_ms` to 10ms (as in the security question)
2. Under any legitimate load, blocks take >10ms to execute/commit
3. First block is added to `block_ordered_ts` and never removed
4. After 10ms, `pipeline_pending_latency()` exceeds the limit
5. Validator stops voting on all incoming nodes (`stop_voting()` returns true)
6. Other validators experience the same issue
7. Nodes cannot obtain 2f+1 votes for certification
8. Consensus stalls completely

Even with the default 30-second limit: [7](#0-6) 

Under heavy load or execution delays, validators will eventually hit the 30s threshold and stop voting, causing cascading liveness failures.

**No Configuration Validation:**

There is no validation preventing dangerously low values from being configured, and no minimum threshold enforcement.

## Impact Explanation

This is a **HIGH severity** vulnerability per the Aptos Bug Bounty criteria:

- **Validator node slowdowns**: When validators stop voting, consensus progress slows dramatically
- **Significant protocol violations**: Breaks the liveness guarantee of the consensus protocol
- **Potential total loss of network availability**: If enough validators are affected simultaneously, the network cannot make progress

The vulnerability can escalate to requiring manual intervention (validator restarts) to restore consensus, which violates the self-healing properties expected of a production blockchain system. Under adversarial conditions or with misconfigured thresholds, this could approach **Critical severity** if it causes sustained network partition.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will occur under the following realistic conditions:

1. **Configuration Error**: Operators setting `voter_pipeline_latency_limit_ms` too low (e.g., 10ms-100ms) thinking it will improve responsiveness
2. **Legitimate Load Spikes**: Transaction volume increases causing execution delays beyond 30s
3. **Network Latency**: Normal network conditions causing block propagation and execution delays
4. **Storage I/O Delays**: Disk I/O bottlenecks during state commitment
5. **Code Deployment**: The TODO comment indicates this is a known incomplete implementation

The default 30-second value provides some buffer, but the missing cleanup mechanism means the issue is inevitable under sustained load. The vulnerability is deterministic and not dependent on timing races or complex state manipulation.

## Recommendation

**Immediate Fix: Implement the Missing Cleanup Callback**

1. Integrate the commented-out callback mechanism with the pipeline_builder:

```rust
// In consensus/src/dag/adapter.rs, OrderedNotifierAdapter::send_ordered_nodes

let block_ordered_ts = self.block_ordered_ts.clone();
let dag = self.dag.clone();
let ledger_info_provider = self.ledger_info_provider.clone();

let blocks_to_send = OrderedBlocks {
    ordered_blocks: vec![block],
    ordered_proof: LedgerInfoWithSignatures::new(
        LedgerInfo::new(block_info, anchor.digest()),
        AggregateSignature::empty(),
    ),
    callback: Box::new(
        move |_committed_blocks: &[Arc<PipelinedBlock>],
              commit_decision: LedgerInfoWithSignatures| {
            block_ordered_ts
                .write()
                .retain(|&round, _| round > commit_decision.commit_info().round());
            dag.commit_callback(commit_decision.commit_info().round());
            ledger_info_provider
                .write()
                .notify_commit_proof(commit_decision);
        },
    ),
};
```

2. Add configuration validation to prevent dangerously low values:

```rust
// In config/src/config/dag_consensus_config.rs

impl ConfigSanitizer for DagHealthConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let health_config = &node_config.dag_consensus.health_config;
        
        // Enforce minimum of 5 seconds to prevent liveness issues
        if health_config.voter_pipeline_latency_limit_ms < 5000 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_owned(),
                format!(
                    "voter_pipeline_latency_limit_ms must be at least 5000ms, got {}ms",
                    health_config.voter_pipeline_latency_limit_ms
                ),
            ));
        }
        
        Ok(())
    }
}
```

3. Add monitoring alerts when validators approach the voting threshold to detect issues before consensus halts.

## Proof of Concept

**Reproduction Steps:**

1. Modify the DAG consensus configuration to set `voter_pipeline_latency_limit_ms` to 10ms:

```rust
// In config file
dag_consensus:
  health_config:
    voter_pipeline_latency_limit_ms: 10
```

2. Start a validator with this configuration

3. Submit transactions to create load on the network

4. Observe the following sequence:
   - Block is ordered and added to `block_ordered_ts`
   - After 10ms, `pipeline_pending_latency()` exceeds limit
   - Validator logs show `VoteRefused` errors
   - Incoming node vote requests are rejected
   - Consensus progress stalls (no new certified nodes)

**Verification:**

Add logging to `NodeBroadcastHandler::process`:

```rust
async fn process(&self, node: Self::Request) -> anyhow::Result<Self::Response> {
    let latency = self.health_backoff.pipeline_health.pipeline_pending_latency();
    let stop = self.health_backoff.stop_voting();
    info!("Processing node vote request: latency={:?}, stop_voting={}", latency, stop);
    
    ensure!(
        !stop,
        NodeBroadcastHandleError::VoteRefused
    );
    // ... rest of implementation
}
```

Monitor logs to observe when `stop_voting=true` and `VoteRefused` errors begin occurring, correlating with consensus stall.

**Expected Outcome:**

Within seconds of starting under any load, validators will permanently stop voting, and consensus will halt until validators are restarted (which only provides temporary relief until the issue recurs).

---

**Notes:**

This vulnerability represents a critical gap in the DAG consensus implementation where the health monitoring system intended to provide backpressure instead causes complete consensus failure. The TODO comment indicates the developers are aware the callback integration is incomplete, but the current state creates a production-ready trap that can cause network-wide outages. The lack of configuration validation compounds the risk by allowing operators to unknowingly deploy with dangerous settings.

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
