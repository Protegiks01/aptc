# Audit Report

## Title
Optimistic Block Hash Collision Due to Partial QuorumCert Hashing

## Summary
For optimistic blocks, the hash function only includes the `vote_data` portion of the parent QuorumCert, not the full QuorumCert including signatures. This allows different validators to create blocks with identical hashes but different QuorumCert content, violating the block hash uniqueness invariant.

## Finding Description

The vulnerability exists in how optimistic blocks compute their hash. When an OptBlockData is received and converted to a Block, each validator uses their local highest QuorumCert (HQC) as the parent QC. [1](#0-0) 

The hash function for opt blocks only serializes the `quorum_cert_vote_data` (line 124), omitting the `signed_ledger_info` which contains the actual validator signatures and signature bitvec. [2](#0-1) 

A QuorumCert contains both `vote_data` (the consensus data about the certified block) and `signed_ledger_info` (the LedgerInfo with validator signatures). Two valid QuorumCerts can have identical vote_data but different signature sets (e.g., validators {1,2,3} vs {1,2,4}), as long as both constitute a valid quorum.

**Exploitation Path:**

1. Block X at round r gets certified
2. Due to network timing, different validators receive different QCs for block X:
   - Validator A receives QC_A with signatures from validators {V1, V2, V3}
   - Validator B receives QC_B with signatures from validators {V1, V2, V4}
3. Both QCs have identical vote_data (same BlockInfo) but different signature sets
4. Both validators store their respective QC as the HQC [3](#0-2) 

5. Proposer broadcasts OptBlockData for round r+1
6. Each validator converts it using their local HQC: [4](#0-3) 

7. Validator A creates Block_A with QC_A, hash = H
8. Validator B creates Block_B with QC_B, hash = H (same!)
9. Both blocks are stored in the BlockTree with hash H as the key [5](#0-4) 

When a block with existing hash is inserted, the existing block is returned (line 312-317), causing the new block's QC to be silently discarded.

**Invariant Violation:**

This breaks the fundamental invariant that a block's hash uniquely identifies its complete content. The hash validation in `verify_well_formed()` uses `debug_checked_verify_eq!` which only runs in debug builds, not in production release builds: [6](#0-5) 

## Impact Explanation

**Severity Assessment: Medium**

While this violates the hash uniqueness invariant, it does NOT cause consensus safety violations because:

1. The QuorumCert's LedgerInfo is deterministically tied to vote_data via consensus_data_hash verification, so two QCs with the same vote_data must have identical LedgerInfo content (only signatures differ) [7](#0-6) 

2. Consensus decisions are based on vote_data (BlockInfo), not on which specific validators signed
3. Different valid signature sets for the same block are functionally equivalent for consensus purposes

However, this creates state inconsistencies that could require manual intervention:
- Storage/retrieval confusion when blocks are requested by hash
- Debugging difficulties when validators have "different" blocks with the same hash  
- Potential for future vulnerabilities if code assumes hash uniqueness

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

## Likelihood Explanation

**High Likelihood** - This occurs naturally in a distributed BFT system without requiring any malicious behavior:

- Network delays and partitions are common in distributed systems
- Different validators frequently receive votes at different times
- Multiple valid quorums can form for the same block
- The `or_insert_with` pattern ensures only the first QC received is stored

This is not a theoretical attack requiring specific timing or coordination—it happens organically during normal network operation.

## Recommendation

Include the full QuorumCert (including signatures) in the hash computation for opt blocks:

```rust
fn hash(&self) -> HashValue {
    let mut state = Self::Hasher::default();
    if self.is_opt_block() {
        // Hash the FULL quorum_cert, not just vote_data
        #[derive(Serialize)]
        struct OptBlockDataForHash<'a> {
            epoch: u64,
            round: Round,
            timestamp_usecs: u64,
            quorum_cert: &'a QuorumCert,  // Changed from quorum_cert_vote_data
            block_type: &'a BlockType,
        }

        let opt_block_data_for_hash = OptBlockDataForHash {
            epoch: self.epoch,
            round: self.round,
            timestamp_usecs: self.timestamp_usecs,
            quorum_cert: &self.quorum_cert,  // Include full QC
            block_type: &self.block_type,
        };
        bcs::serialize_into(&mut state, &opt_block_data_for_hash)
            .expect("OptBlockDataForHash must be serializable");
    } else {
        bcs::serialize_into(&mut state, &self).expect("BlockData must be serializable");
    }
    state.finish()
}
```

Alternatively, if the partial hashing was intentional for performance or deduplication reasons, add explicit validation that blocks with the same hash have identical QuorumCerts.

## Proof of Concept

```rust
#[test]
fn test_opt_block_hash_collision() {
    use aptos_crypto::HashValue;
    use aptos_types::{
        account_address::AccountAddress,
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };
    use aptos_bitvec::BitVec;
    
    // Create identical vote_data
    let parent_info = BlockInfo::random(10);
    let vote_data = VoteData::new(parent_info.clone(), BlockInfo::random(9));
    
    // Create two QCs with same vote_data but different signatures
    let mut bitvec1 = BitVec::with_num_bits(4);
    bitvec1.set(0); bitvec1.set(1); bitvec1.set(2); // Validators 0,1,2
    
    let mut bitvec2 = BitVec::with_num_bits(4);
    bitvec2.set(0); bitvec2.set(1); bitvec2.set(3); // Validators 0,1,3
    
    let ledger_info = LedgerInfo::new(parent_info.clone(), vote_data.hash());
    
    let qc1 = QuorumCert::new(
        vote_data.clone(),
        LedgerInfoWithSignatures::new(
            ledger_info.clone(),
            AggregateSignature::new(bitvec1, None),
        ),
    );
    
    let qc2 = QuorumCert::new(
        vote_data.clone(),
        LedgerInfoWithSignatures::new(
            ledger_info,
            AggregateSignature::new(bitvec2, None),
        ),
    );
    
    // Create opt block data
    let opt_data = OptBlockData::new(
        vec![],
        Payload::empty(false, true),
        AccountAddress::random(),
        1,
        11,
        1000,
        parent_info,
        QuorumCert::dummy(),
    );
    
    // Create two blocks with different QCs
    let block1 = BlockData::new_from_opt(opt_data.clone(), qc1);
    let block2 = BlockData::new_from_opt(opt_data, qc2);
    
    // Verify hash collision
    assert_eq!(block1.hash(), block2.hash(), "Hashes should match!");
    assert_ne!(block1, block2, "But blocks should be different!");
}
```

## Notes

This vulnerability specifically affects optimistic proposals, a performance optimization where validators can propose round r+1 before round r's QC is fully aggregated. While the hash collision doesn't break consensus safety (because vote_data is preserved), it violates the assumption that block hashes uniquely identify block content. This could cause subtle bugs in block storage, retrieval, and synchronization logic that assumes hash uniqueness. The issue is exacerbated by the `debug_checked_verify_eq!` validation only running in debug builds, not production.

### Citations

**File:** consensus/consensus-types/src/block_data.rs (L108-134)
```rust
    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        if self.is_opt_block() {
            #[derive(Serialize)]
            struct OptBlockDataForHash<'a> {
                epoch: u64,
                round: Round,
                timestamp_usecs: u64,
                quorum_cert_vote_data: &'a VoteData,
                block_type: &'a BlockType,
            }

            let opt_block_data_for_hash = OptBlockDataForHash {
                epoch: self.epoch,
                round: self.round,
                timestamp_usecs: self.timestamp_usecs,
                quorum_cert_vote_data: self.quorum_cert.vote_data(),
                block_type: &self.block_type,
            };
            bcs::serialize_into(&mut state, &opt_block_data_for_hash)
                .expect("OptBlockDataForHash must be serializable");
        } else {
            bcs::serialize_into(&mut state, &self).expect("BlockData must be serializable");
        }
        state.finish()
    }
}
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L17-23)
```rust
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumCert {
    /// The vote information is certified by the quorum.
    vote_data: VoteData,
    /// The signed LedgerInfo of a committed block that carries the data about the certified block.
    signed_ledger_info: LedgerInfoWithSignatures,
}
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L119-124)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let vote_hash = self.vote_data.hash();
        ensure!(
            self.ledger_info().ledger_info().consensus_data_hash() == vote_hash,
            "Quorum Cert's hash mismatch LedgerInfo"
        );
```

**File:** consensus/src/block_storage/block_tree.rs (L307-338)
```rust
    pub(super) fn insert_block(
        &mut self,
        block: PipelinedBlock,
    ) -> anyhow::Result<Arc<PipelinedBlock>> {
        let block_id = block.id();
        if let Some(existing_block) = self.get_block(&block_id) {
            debug!("Already had block {:?} for id {:?} when trying to add another block {:?} for the same id",
                       existing_block,
                       block_id,
                       block);
            Ok(existing_block)
        } else {
            match self.get_linkable_block_mut(&block.parent_id()) {
                Some(parent_block) => parent_block.add_child(block_id),
                None => bail!("Parent block {} not found", block.parent_id()),
            };
            let linkable_block = LinkableBlock::new(block);
            let arc_block = Arc::clone(linkable_block.executed_block());
            assert!(self.id_to_block.insert(block_id, linkable_block).is_none());
            // Note: the assumption is that we have/enforce unequivocal proposer election.
            if let Some(old_block_id) = self.round_to_ids.get(&arc_block.round()) {
                warn!(
                    "Multiple blocks received for round {}. Previous block id: {}",
                    arc_block.round(),
                    old_block_id
                );
            } else {
                self.round_to_ids.insert(arc_block.round(), block_id);
            }
            counters::NUM_BLOCKS_IN_TREE.inc();
            Ok(arc_block)
        }
```

**File:** consensus/src/block_storage/block_tree.rs (L376-378)
```rust
        self.id_to_quorum_cert
            .entry(block_id)
            .or_insert_with(|| Arc::clone(&qc));
```

**File:** consensus/src/round_manager.rs (L851-864)
```rust
        let hqc = self.block_store.highest_quorum_cert().as_ref().clone();
        ensure!(
            hqc.certified_block().round() + 1 == opt_block_data.round(),
            "Opt proposal round {} is not the next round after the highest qc round {}",
            opt_block_data.round(),
            hqc.certified_block().round()
        );
        ensure!(
            hqc.certified_block().id() == opt_block_data.parent_id(),
            "Opt proposal parent id {} is not the same as the highest qc certified block id {}",
            opt_block_data.parent_id(),
            hqc.certified_block().id()
        );
        let proposal = Block::new_from_opt(opt_block_data, hqc);
```

**File:** consensus/consensus-types/src/block.rs (L545-549)
```rust
        debug_checked_verify_eq!(
            self.id(),
            self.block_data.hash(),
            "Block id mismatch the hash"
        );
```
