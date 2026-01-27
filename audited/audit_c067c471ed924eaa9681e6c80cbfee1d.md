# Audit Report

## Title
NIL Block Timestamp Reuse Causes Stale Ledger Timestamps in Peer Monitoring Service

## Summary
The `get_ledger_timestamp_usecs()` function in the peer monitoring service returns stale timestamps when NIL blocks are committed. NIL blocks reuse their parent block's timestamp instead of using the current time, causing the ledger timestamp to remain unchanged even as new blocks are committed during consensus timeouts. This results in inaccurate network latency reporting.

## Finding Description

The vulnerability occurs in the consensus layer's handling of NIL blocks. When a consensus round times out (e.g., when a proposer fails to send a proposal), validators generate NIL blocks to maintain liveness. [1](#0-0) 

The `BlockData::new_nil()` function creates NIL blocks with their parent's timestamp directly (line 312), despite the comment claiming "parent + 1" (line 310). This timestamp is preserved through the entire commit flow:

1. When a NIL block is created during timeout: [2](#0-1) 

2. The NIL block's timestamp comes from its parent: [3](#0-2) 

3. When the NIL block is executed and committed, its `BlockInfo` is generated with the stale timestamp: [4](#0-3) 

4. This `BlockInfo` becomes part of the `LedgerInfo` that is persisted to storage.

5. The peer monitoring service retrieves this stale timestamp: [5](#0-4) 

6. The stale timestamp is reported in node information responses: [6](#0-5) 

**Attack Scenario:**
No attacker action is required. This occurs naturally during normal network conditions:
- Block A committed at round N with timestamp T (e.g., 12:00:00)
- Round N+1 times out at 12:00:05 (no proposal received)
- NIL block created for round N+1 with timestamp T (12:00:00, same as parent)
- NIL block achieves consensus and is committed
- `get_ledger_timestamp_usecs()` returns T (12:00:00)
- Actual network time is 12:00:05, causing 5 seconds of staleness

Multiple consecutive timeouts compound this issue, with staleness accumulating across multiple NIL blocks.

## Impact Explanation

This issue falls under **Low to Medium** severity based on the Aptos bug bounty criteria:

**Why not Critical/High:**
- Does not cause loss of funds
- Does not break consensus safety
- Does not cause network partitions
- Does not affect on-chain state or smart contract execution

**Why Medium (borderline):**
- Affects operational monitoring accuracy
- Could lead to incorrect peer health assessments
- May impact consensus observer fallback decisions
- Causes information inaccuracy in network health reporting

The on-chain timestamp module has explicit handling for NIL blocks: [7](#0-6) 

This shows that NIL blocks are intentionally designed not to advance on-chain time. However, the peer monitoring service's exposure of stale BlockInfo timestamps was likely unintended.

## Likelihood Explanation

**Likelihood: HIGH**

This occurs automatically during normal consensus operation:
- Any round timeout triggers NIL block creation
- Network latency, slow validators, or temporary connectivity issues cause timeouts
- No malicious actor required
- Happens independently across all validator nodes
- Multiple consecutive timeouts compound the staleness

## Recommendation

Fix the timestamp assignment in `BlockData::new_nil()` to use the current system time or increment the parent's timestamp:

```rust
pub fn new_nil(
    round: Round,
    quorum_cert: QuorumCert,
    failed_authors: Vec<(Round, Author)>,
) -> Self {
    // Use parent timestamp + 1 microsecond to maintain monotonicity
    // while indicating time has passed
    assume!(quorum_cert.certified_block().timestamp_usecs() < u64::MAX);
    let timestamp_usecs = quorum_cert.certified_block().timestamp_usecs() + 1;

    Self {
        epoch: quorum_cert.certified_block().epoch(),
        round,
        timestamp_usecs,
        quorum_cert,
        block_type: BlockType::NilBlock { failed_authors },
    }
}
```

Alternatively, use a more accurate timestamp from the system clock at NIL block creation time, ensuring it's greater than the parent's timestamp to maintain the monotonicity guarantee.

Update the on-chain timestamp validation to accept NIL block timestamps that are greater than or equal to the current time (rather than strictly equal):

```move
if (proposer == @vm_reserved) {
    // NIL block with null address as proposer. Timestamp must not decrease.
    assert!(now <= timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
    global_timer.microseconds = timestamp;
}
```

## Proof of Concept

```rust
#[test]
fn test_nil_block_stale_timestamp() {
    use aptos_types::block_info::BlockInfo;
    use aptos_types::on_chain_config::ValidatorSet;
    
    // Create genesis block with timestamp T
    let genesis_timestamp = 1000000;
    let genesis_block_info = BlockInfo::genesis(
        HashValue::random(),
        ValidatorSet::empty()
    );
    
    // Create QC for genesis
    let genesis_qc = QuorumCert::new(
        VoteData::new(genesis_block_info.clone(), genesis_block_info.clone()),
        LedgerInfoWithSignatures::genesis(HashValue::random(), ValidatorSet::empty())
    );
    
    // Create NIL block - should ideally have timestamp > genesis_timestamp
    let nil_block = Block::new_nil(1, genesis_qc.clone(), vec![]);
    
    // BUG: NIL block has same timestamp as genesis
    assert_eq!(nil_block.timestamp_usecs(), genesis_block_info.timestamp_usecs());
    
    // If this NIL block is committed, ledger timestamp remains stale
    let nil_block_info = nil_block.gen_block_info(
        HashValue::random(),
        1,
        None
    );
    
    // The committed ledger info will have the stale timestamp
    assert_eq!(nil_block_info.timestamp_usecs(), genesis_block_info.timestamp_usecs());
    
    // Expected: timestamp should advance even for NIL blocks
    // assert!(nil_block_info.timestamp_usecs() > genesis_block_info.timestamp_usecs());
}
```

## Notes

This vulnerability is confirmed to exist in the codebase. NIL blocks definitively reuse their parent's timestamp, and this stale timestamp is exposed through the peer monitoring service's `get_ledger_timestamp_usecs()` function. However, the security impact is limited to monitoring accuracy and does not directly threaten consensus safety, fund security, or network liveness. The severity assessment as "Medium" is borderline and could reasonably be classified as "Low" under strict bug bounty criteria.

### Citations

**File:** consensus/consensus-types/src/block_data.rs (L304-321)
```rust
    pub fn new_nil(
        round: Round,
        quorum_cert: QuorumCert,
        failed_authors: Vec<(Round, Author)>,
    ) -> Self {
        // We want all the NIL blocks to agree on the timestamps even though they're generated
        // independently by different validators, hence we're using the timestamp of a parent + 1.
        assume!(quorum_cert.certified_block().timestamp_usecs() < u64::MAX); // unlikely to be false in this universe
        let timestamp_usecs = quorum_cert.certified_block().timestamp_usecs();

        Self {
            epoch: quorum_cert.certified_block().epoch(),
            round,
            timestamp_usecs,
            quorum_cert,
            block_type: BlockType::NilBlock { failed_authors },
        }
    }
```

**File:** consensus/src/round_manager.rs (L1051-1053)
```rust
                    let nil_block = self
                        .proposal_generator
                        .generate_nil_block(round, self.proposer_election.clone())?;
```

**File:** consensus/src/liveness/proposal_generator.rs (L462-476)
```rust
    pub fn generate_nil_block(
        &self,
        round: Round,
        proposer_election: Arc<dyn ProposerElection>,
    ) -> anyhow::Result<Block> {
        let hqc = self.ensure_highest_quorum_cert(round)?;
        let quorum_cert = hqc.as_ref().clone();
        let failed_authors = self.compute_failed_authors(
            round, // to include current round, as that is what failed
            quorum_cert.certified_block().round(),
            true,
            proposer_election,
        );
        Ok(Block::new_nil(round, quorum_cert, failed_authors))
    }
```

**File:** consensus/consensus-types/src/block.rs (L237-252)
```rust
    pub fn gen_block_info(
        &self,
        executed_state_id: HashValue,
        version: Version,
        next_epoch_state: Option<EpochState>,
    ) -> BlockInfo {
        BlockInfo::new(
            self.epoch(),
            self.round(),
            self.id(),
            executed_state_id,
            version,
            self.timestamp_usecs(),
            next_epoch_state,
        )
    }
```

**File:** peer-monitoring-service/server/src/storage.rs (L50-53)
```rust
    fn get_ledger_timestamp_usecs(&self) -> Result<u64, Error> {
        let latest_ledger_info = self.get_latest_ledger_info()?;
        Ok(latest_ledger_info.timestamp_usecs())
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L259-280)
```rust
    fn get_node_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the node information
        let build_information = aptos_build_info::get_build_information();
        let current_time: Instant = self.time_service.now();
        let uptime = current_time.duration_since(self.start_time);
        let (highest_synced_epoch, highest_synced_version) =
            self.storage.get_highest_synced_epoch_and_version()?;
        let ledger_timestamp_usecs = self.storage.get_ledger_timestamp_usecs()?;
        let lowest_available_version = self.storage.get_lowest_available_version()?;

        // Create and return the response
        let node_information_response = NodeInformationResponse {
            build_information,
            highest_synced_epoch,
            highest_synced_version,
            ledger_timestamp_usecs,
            lowest_available_version,
            uptime,
        };
        Ok(PeerMonitoringServiceResponse::NodeInformation(
            node_information_response,
        ))
```

**File:** aptos-move/framework/aptos-framework/sources/timestamp.move (L42-49)
```text
        if (proposer == @vm_reserved) {
            // NIL block with null address as proposer. Timestamp must be equal.
            assert!(now == timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
        } else {
            // Normal block. Time must advance
            assert!(now < timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
            global_timer.microseconds = timestamp;
        };
```
