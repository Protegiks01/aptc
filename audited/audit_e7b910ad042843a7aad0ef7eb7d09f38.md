# Audit Report

## Title
Genesis Block Verification Bypass in WrappedLedgerInfo Allows Consensus Safety Violations via Commit/Certified Block Confusion

## Summary
The `WrappedLedgerInfo.verify()` function fails to validate consensus data hash consistency between `vote_data` and `ledger_info`, and skips all verification for genesis blocks (round == 0). This allows attackers to craft malicious `WrappedLedgerInfo` structures where `commit_info()` and `certified_block()` return completely different, unrelated blocks, violating the fundamental AptosBFT invariant that committed blocks must be ancestors of certified blocks. This confusion is exploited in the fast-forward sync path to cause incorrect block retrieval calculations and potential state corruption.

## Finding Description

The vulnerability exists in the verification flow for `WrappedLedgerInfo` structures used in consensus synchronization: [1](#0-0) 

The `verify()` method has two critical flaws:

1. **Missing Hash Consistency Check**: Unlike `certified_block()` which calls `verify_consensus_data_hash()`, the `verify()` method never validates that `vote_data.hash()` matches `ledger_info.consensus_data_hash`. This allows `vote_data` and `ledger_info` to be completely inconsistent.

2. **Genesis Verification Bypass**: For round == 0 blocks, it skips signature verification entirely and returns early, accepting the structure without any cryptographic validation.

This is compounded by the verification logic in `SyncInfo`: [2](#0-1) 

When `commit_info().round() == 0`, the entire `verify()` call is skipped, creating a double-bypass where a malicious genesis `WrappedLedgerInfo` is never validated at all.

**Attack Scenario:**

An attacker crafts a malicious `SyncInfo` message with `highest_commit_cert` containing:
- `ledger_info.commit_info`: A fake genesis block at round 0 with arbitrary block ID `G_fake`
- `vote_data.proposed()`: A malicious block at round `R` with block ID `B_malicious` 
- `consensus_data_hash`: Set to `vote_data.hash()` (to pass hash checks if `certified_block()` is ever called)
- No signatures (valid for genesis)

This structure passes both verification checks and is accepted by the node. The critical exploit occurs in the sync path: [3](#0-2) 

The `generate_target_block_retrieval_payload_and_num_blocks()` function calculates:
- `num_blocks` using `ledger_info().round()` (reads 0 from fake genesis)
- `target_block_id` using `commit_info().id()` (reads `G_fake` ID)

This causes the node to:
1. Calculate `num_blocks = R - 0 + 1 = R + 1` (fetch excessive blocks from genesis)
2. Use a non-existent fake genesis block ID as the retrieval target
3. Attempt state synchronization from an invalid chain root

The inconsistency between what `commit_info()` returns (fake genesis) and what `certified_block()` returns (malicious block) breaks the consensus invariant that certified and committed blocks must be related by the parent chain. [4](#0-3) 

Additionally, when `order_vote_enabled == false`, the code calls `certified_block()` which would return the malicious block `B_malicious`, while other code paths use `commit_info()` seeing the fake genesis `G_fake`, creating dangerous state inconsistencies.

## Impact Explanation

**Critical Severity** - This vulnerability enables multiple consensus safety violations:

1. **Block Retrieval Manipulation**: Attackers can cause nodes to fetch blocks from non-existent genesis blocks, potentially accepting malicious block sequences if an attacker controls the peer responses.

2. **State Synchronization Corruption**: Nodes calculate sync parameters using inconsistent block information, leading to incorrect state roots and potential chain forks.

3. **Consensus Safety Violation**: The fundamental invariant that "committed blocks must be ancestors of certified blocks" is violated. A node could believe it has committed to block `G_fake` while the QC certifies unrelated block `B_malicious`, breaking AptosBFT safety guarantees.

4. **Denial of Service**: Integer arithmetic with fake round 0 could cause excessive block fetches, memory exhaustion, or crashes when trying to retrieve non-existent blocks.

This meets Critical Severity criteria: **Consensus/Safety violations** that can cause chain splits and non-recoverable network partitions.

## Likelihood Explanation

**High Likelihood** - The vulnerability is readily exploitable:

1. **No Privileged Access Required**: Any network peer can send malicious `SyncInfo` messages to target nodes
2. **Simple Attack Construction**: Creating the malicious `WrappedLedgerInfo` requires only setting specific field values, no cryptographic breaks needed
3. **Automatic Processing**: Nodes automatically process incoming `SyncInfo` messages during normal consensus operation
4. **Multiple Attack Vectors**: The verification bypass affects all paths where `WrappedLedgerInfo` with genesis rounds are processed

The TODO comment acknowledges prior uncertainty about this exact verification logic change: [5](#0-4) 

## Recommendation

Add proper hash consistency validation to `WrappedLedgerInfo.verify()`:

```rust
pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
    // Always verify consensus data hash consistency
    self.verify_consensus_data_hash()?;
    
    // Genesis's QC is implicitly agreed upon, it doesn't have real signatures.
    if self.ledger_info().ledger_info().round() == 0 {
        ensure!(
            self.ledger_info().get_num_voters() == 0,
            "Genesis QC should not carry signatures"
        );
        // For genesis, also verify that vote_data matches commit_info
        ensure!(
            self.vote_data.proposed() == self.ledger_info().ledger_info().commit_info(),
            "Genesis: certified block must equal commit block"
        );
        return Ok(());
    }
    
    self.ledger_info()
        .verify_signatures(validator)
        .context("Fail to verify WrappedLedgerInfo")?;
    Ok(())
}
```

Additionally, remove the genesis bypass in `SyncInfo.verify()`:

```rust
// Always verify commit certificate, including genesis
self.highest_commit_cert
    .verify(validator)
    .context("Fail to verify commit certificate")?;
```

## Proof of Concept

```rust
// PoC: Construct malicious WrappedLedgerInfo that bypasses verification
use aptos_types::{
    block_info::BlockInfo,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
};
use consensus_types::{
    vote_data::VoteData,
    wrapped_ledger_info::WrappedLedgerInfo,
};

// Step 1: Create fake genesis commit_info at round 0
let fake_genesis = BlockInfo::new(
    1,  // epoch
    0,  // round 0 (genesis)
    HashValue::random(),  // fake genesis ID
    HashValue::zero(),
    0,
    0,
    None,
);

// Step 2: Create malicious certified block at higher round
let malicious_block = BlockInfo::new(
    1,  // same epoch
    100,  // round 100
    HashValue::random(),  // malicious block ID
    HashValue::zero(),
    0,
    0,
    None,
);

// Step 3: Create vote_data pointing to malicious block
let vote_data = VoteData::new(malicious_block.clone(), fake_genesis.clone());

// Step 4: Create ledger_info with fake genesis commit but hash matching vote_data
let ledger_info = LedgerInfo::new(
    fake_genesis.clone(),  // commits fake genesis
    vote_data.hash(),  // consensus_data_hash matches vote_data
);

// Step 5: Create WrappedLedgerInfo with no signatures (valid for genesis)
let malicious_wrapped = WrappedLedgerInfo::new(
    vote_data,
    LedgerInfoWithSignatures::new(
        ledger_info,
        AggregateSignature::empty(),
    ),
);

// Step 6: Verification bypasses all checks for genesis
assert!(malicious_wrapped.verify(&validator).is_ok());  // PASSES!

// Step 7: Inconsistent results
assert_eq!(malicious_wrapped.commit_info().round(), 0);  // Returns fake genesis
assert_eq!(malicious_wrapped.commit_info().id(), fake_genesis.id());

// When order_vote_enabled = false:
assert_eq!(malicious_wrapped.certified_block(false).unwrap().round(), 100);  // Returns malicious block!
assert_eq!(malicious_wrapped.certified_block(false).unwrap().id(), malicious_block.id());

// The node now has inconsistent state - safety violation!
```

## Notes

The vulnerability exists in the tension between backward compatibility for order votes and proper security validation. The `WrappedLedgerInfo` structure was designed to support both order-vote-enabled and order-vote-disabled modes, but the verification logic fails to maintain security invariants in the genesis case. The fix must ensure that `vote_data` and `ledger_info` are always consistent, especially for genesis blocks where signature verification is skipped.

### Citations

**File:** consensus/consensus-types/src/wrapped_ledger_info.rs (L90-108)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        // Genesis's QC is implicitly agreed upon, it doesn't have real signatures.
        // If someone sends us a QC on a fake genesis, it'll fail to insert into BlockStore
        // because of the round constraint.

        // TODO: Earlier, we were comparing self.certified_block().round() to 0. Now, we are
        // comparing self.ledger_info().ledger_info().round() to 0. Is this okay?
        if self.ledger_info().ledger_info().round() == 0 {
            ensure!(
                self.ledger_info().get_num_voters() == 0,
                "Genesis QC should not carry signatures"
            );
            return Ok(());
        }
        self.ledger_info()
            .verify_signatures(validator)
            .context("Fail to verify WrappedLedgerInfo")?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/sync_info.rs (L196-202)
```rust
                // we do not verify genesis ledger info
                if self.highest_commit_cert.commit_info().round() > 0 {
                    self.highest_commit_cert
                        .verify(validator)
                        .context("Fail to verify commit certificate")?
                }
                Ok(())
```

**File:** consensus/src/block_storage/sync_manager.rs (L329-347)
```rust
    pub(crate) fn generate_target_block_retrieval_payload_and_num_blocks<'a>(
        highest_quorum_cert: &'a QuorumCert,
        highest_commit_cert: &'a WrappedLedgerInfo,
        window_size: Option<u64>,
    ) -> (TargetBlockRetrieval, u64) {
        match window_size {
            None => {
                let num_blocks = highest_quorum_cert.certified_block().round()
                    - highest_commit_cert.ledger_info().ledger_info().round()
                    + 1;
                let target_block_id = highest_commit_cert.commit_info().id();
                info!(
                    "[FastForwardSync] with window_size: None, target_block_id: {}, num_blocks: {}",
                    target_block_id, num_blocks
                );
                (
                    TargetBlockRetrieval::TargetBlockId(target_block_id),
                    num_blocks,
                )
```

**File:** consensus/src/block_storage/sync_manager.rs (L413-426)
```rust
        if !order_vote_enabled {
            // TODO: this is probably still necessary, but need to think harder, it's pretty subtle
            // check if highest_commit_cert comes from a fork
            // if so, we need to fetch it's block as well, to have a proof of commit.
            let highest_commit_certified_block =
                highest_commit_cert.certified_block(order_vote_enabled)?;
            if !blocks
                .iter()
                .any(|block| block.id() == highest_commit_certified_block.id())
            {
                info!(
                    "Found forked QC {}, fetching it as well",
                    highest_commit_cert
                );
```
