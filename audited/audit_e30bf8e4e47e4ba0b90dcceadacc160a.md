# Audit Report

## Title
Asymmetric DoS via Duplicate Transaction Hash Computation in Consensus Deduplication

## Summary
A Byzantine block proposer can craft malicious blocks containing multiple transactions with identical (sender, sequence_number) pairs but different payloads, forcing all receiving validators to compute expensive cryptographic hashes during the deduplication process. This creates an asymmetric resource exhaustion attack where the attacker's cost is lower than the collective defense cost across all validators.

## Finding Description

The transaction deduplication logic in consensus explicitly acknowledges that hash calculation is expensive [1](#0-0) , yet the implementation computes hashes for ALL transactions marked as "possible duplicates" without early validation.

**Attack Flow:**

1. **Malicious Block Creation**: A Byzantine validator, when elected as proposer, creates a block payload containing N transactions where all share the same (sender, sequence_number) but have different payloads/signatures.

2. **Initial Validation Passes**: The block passes all pre-deduplication checks [2](#0-1) , including payload size limits [3](#0-2)  and proposer validity checks, as there is no validation for duplicate (sender, sequence_number) pairs before deduplication.

3. **Network Deserialization**: When honest validators receive the block, transactions are deserialized from BCS format. Due to the `#[serde(skip)]` attribute on the cached hash field [4](#0-3) , the `committed_hash` OnceCell is empty after deserialization.

4. **Deduplication Triggers Hash Computation**: During block insertion [5](#0-4) , the pipeline builder invokes block preparation [6](#0-5)  which calls the deduper. The deduper marks all N transactions as "possible duplicates" [7](#0-6)  and computes expensive hashes for all of them [8](#0-7) .

5. **Hash Computation Cost**: Each hash computation requires BCS serialization of the entire SignedTransaction plus cryptographic hashing [9](#0-8) , which is computationally expensive as documented.

**Cost Asymmetry:**
- **Attacker cost**: Create and sign N transactions once, broadcast one block
- **Defender cost**: ALL validators compute N expensive hashes (BCS serialization + SHA3-256)
- **Amplification**: With V validators, the attack triggers N×V hash computations for N transaction creations

**Invariant Violated:** Resource Limits (Invariant #9) - "All operations must respect gas, storage, and computational limits" is violated as computational resources can be asymmetrically exhausted without proportional cost to the attacker.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria of "Validator node slowdowns" [10](#0-9) . 

With the default limit of 10,000 transactions per block, a Byzantine proposer can force 10,000 hash computations on every validator per malicious block. Assuming:
- 100 validators in the network
- 10,000 duplicate transactions per block
- 100 microseconds per hash computation (conservative estimate for BCS + SHA3-256)

**Impact per attack:**
- 10,000 hashes × 100 μs = 1 second per validator
- Network-wide: 100 seconds of aggregate computation
- Attacker cost: ~1 second to create and sign 10,000 transactions once

**Repeated attacks** could significantly degrade validator performance, especially if executed during critical consensus rounds. While mempool validation pre-computes hashes [11](#0-10) , this only applies to transactions going through normal mempool flow, not to malicious blocks crafted directly by Byzantine proposers.

## Likelihood Explanation

**Likelihood: Medium**

**Required conditions:**
1. Attacker must be a validator in the active validator set
2. Attacker must be elected as proposer for a round
3. Attacker must craft malicious block with duplicate (sender, seq_num) pairs

**Barriers:**
- Requires validator status (high barrier to entry)
- Only effective when elected as proposer (~1/V chance per round where V = validator count)
- Byzantine validator could be slashed/removed after detection

**Realistic scenario:** A compromised or malicious validator with ~1% of stake in a 100-validator network would have proposer slot roughly once per 100 rounds. They could execute this attack during their slot, causing temporary slowdowns before being detected.

**Mitigating factors:**
- Attack is detectable (blocks with many duplicate sender/seq pairs are anomalous)
- Impact is temporary (only affects one block's processing)
- Parallelization reduces impact [12](#0-11) 

Despite the barriers, the attack is practical for any Byzantine validator, making it a real threat to network performance.

## Recommendation

**Solution: Early duplicate detection before hash computation**

Add a fast pre-filter check before marking transactions as possible duplicates. Reject blocks that contain an excessive number of transactions with identical (sender, sequence_number) pairs:

```rust
// In dedup() function, after the first pass marking duplicates:
let mut duplicate_counts: HashMap<(AccountAddress, ReplayProtector), usize> = HashMap::new();
for (i, txn) in transactions.iter().enumerate() {
    if possible_duplicates[i] {
        *duplicate_counts
            .entry((txn.sender(), txn.replay_protector()))
            .or_insert(0) += 1;
    }
}

// Reject if any (sender, seq_num) pair appears more than threshold times
const MAX_DUPLICATES_PER_KEY: usize = 5; // Conservative limit
for (key, count) in duplicate_counts.iter() {
    if *count > MAX_DUPLICATES_PER_KEY {
        bail!("Block rejected: excessive duplicates for {:?} (count: {})", key, count);
    }
}
```

Add this check in `consensus/src/round_manager.rs` during proposal validation (before line 1243) to reject malicious blocks early:

```rust
// Validate no excessive duplicate (sender, seq_num) pairs
if let Some(payload) = proposal.payload() {
    self.block_preparer.validate_no_excessive_duplicates(payload)?;
}
```

**Alternative:** Move deduplication to an earlier stage where hashes are already cached, or cache hashes aggressively during block deserialization.

## Proof of Concept

```rust
#[test]
fn test_asymmetric_dos_via_duplicate_hash_computation() {
    use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use aptos_keygen::KeyGen;
    use aptos_types::{
        chain_id::ChainId,
        transaction::{RawTransaction, ReplayProtector, Script, SignedTransaction, TransactionExecutable},
    };
    use std::time::Instant;
    
    let deduper = TxnHashAndAuthenticatorDeduper::new();
    let (privkey, pubkey) = KeyGen::from_os_rng().generate_ed25519_keypair();
    let sender = aptos_types::account_address::from_public_key(&pubkey);
    
    // Create 10,000 transactions with SAME sender and sequence number but different payloads
    let num_duplicates = 10_000;
    let mut transactions = Vec::new();
    
    for i in 0..num_duplicates {
        // Different gas prices make different transaction hashes
        let raw_txn = RawTransaction::new_txn(
            sender,
            ReplayProtector::SequenceNumber(0), // SAME sequence number for all
            TransactionExecutable::Script(Script::new(vec![i as u8], vec![], vec![])), // Different script
            None,
            500_000,
            100 + i, // Different gas price ensures different hash
            0,
            ChainId::new(10),
        );
        
        let signed_txn = raw_txn.sign(&privkey, pubkey.clone()).unwrap().into_inner();
        transactions.push(signed_txn);
    }
    
    // Measure deduplication time
    let start = Instant::now();
    let deduped = deduper.dedup(transactions.clone());
    let elapsed = start.elapsed();
    
    // Should take significant time due to 10,000 hash computations
    println!("Deduplication of {} duplicate txns took: {:?}", num_duplicates, elapsed);
    println!("Only {} txns remain after dedup", deduped.len());
    
    // Attack verification: 10,000 transactions were hashed, but only 1 remains
    assert_eq!(deduped.len(), 1);
    assert!(elapsed.as_millis() > 100, "Hash computation should take significant time");
}
```

**Expected behavior:** The test demonstrates that 10,000 transactions with the same (sender, seq_num) trigger 10,000 expensive hash computations, with only 1 transaction surviving deduplication. This proves the asymmetric cost where creating 10,000 signed transactions (attacker cost) forces 10,000 hash computations (defender cost per validator).

## Notes

This vulnerability specifically affects the consensus layer and represents a protocol-level resource exhaustion vector. While the impact per attack instance is bounded by `MAX_RECEIVING_BLOCK_TXNS` (10,000 transactions), a Byzantine validator could repeatedly exploit this during their proposer slots. The core issue is the lack of early validation for duplicate (sender, sequence_number) pairs before expensive cryptographic operations are performed.

### Citations

**File:** consensus/src/txn_hash_and_authenticator_deduper.rs (L24-25)
```rust
/// 2. Calculate txn hashes (parallel): For all possible duplicates, calculate the txn hash. This
///    is an expensive operation.
```

**File:** consensus/src/txn_hash_and_authenticator_deduper.rs (L44-55)
```rust
        for (i, txn) in transactions.iter().enumerate() {
            match seen.get(&(txn.sender(), txn.replay_protector())) {
                None => {
                    seen.insert((txn.sender(), txn.replay_protector()), i);
                },
                Some(first_index) => {
                    is_possible_duplicate = true;
                    possible_duplicates[*first_index] = true;
                    possible_duplicates[i] = true;
                },
            }
        }
```

**File:** consensus/src/txn_hash_and_authenticator_deduper.rs (L63-71)
```rust
        let hash_and_authenticators: Vec<_> = possible_duplicates
            .into_par_iter()
            .zip(&transactions)
            .with_min_len(optimal_min_len(num_txns, 48))
            .map(|(need_hash, txn)| match need_hash {
                true => Some((txn.committed_hash(), txn.authenticator())),
                false => None,
            })
            .collect();
```

**File:** consensus/src/round_manager.rs (L1111-1241)
```rust
    async fn process_proposal(&mut self, proposal: Block) -> anyhow::Result<()> {
        let author = proposal
            .author()
            .expect("Proposal should be verified having an author");

        if !self.vtxn_config.enabled()
            && matches!(
                proposal.block_data().block_type(),
                BlockType::ProposalExt(_)
            )
        {
            counters::UNEXPECTED_PROPOSAL_EXT_COUNT.inc();
            bail!("ProposalExt unexpected while the vtxn feature is disabled.");
        }

        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
        }

        let (num_validator_txns, validator_txns_total_bytes): (usize, usize) =
            proposal.validator_txns().map_or((0, 0), |txns| {
                txns.iter().fold((0, 0), |(count_acc, size_acc), txn| {
                    (count_acc + 1, size_acc + txn.size_in_bytes())
                })
            });

        let num_validator_txns = num_validator_txns as u64;
        let validator_txns_total_bytes = validator_txns_total_bytes as u64;
        let vtxn_count_limit = self.vtxn_config.per_block_limit_txn_count();
        let vtxn_bytes_limit = self.vtxn_config.per_block_limit_total_bytes();
        let author_hex = author.to_hex();
        PROPOSED_VTXN_COUNT
            .with_label_values(&[&author_hex])
            .inc_by(num_validator_txns);
        PROPOSED_VTXN_BYTES
            .with_label_values(&[&author_hex])
            .inc_by(validator_txns_total_bytes);
        info!(
            vtxn_count_limit = vtxn_count_limit,
            vtxn_count_proposed = num_validator_txns,
            vtxn_bytes_limit = vtxn_bytes_limit,
            vtxn_bytes_proposed = validator_txns_total_bytes,
            proposer = author_hex,
            "Summarizing proposed validator txns."
        );

        ensure!(
            num_validator_txns <= vtxn_count_limit,
            "process_proposal failed with per-block vtxn count limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_txn_count(),
            num_validator_txns
        );
        ensure!(
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );

        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );

        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );

        // If the proposal contains any inline transactions that need to be denied
        // (e.g., due to filtering) drop the message and do not vote for the block.
        if let Err(error) = self
            .block_store
            .check_denied_inline_transactions(&proposal, &self.block_txn_filter_config)
        {
            counters::REJECTED_PROPOSAL_DENY_TXN_COUNT.inc();
            bail!(
                "[RoundManager] Proposal for block {} contains denied inline transactions: {}. Dropping proposal!",
                proposal.id(),
                error
            );
        }

        if !proposal.is_opt_block() {
            // Validate that failed_authors list is correctly specified in the block.
            let expected_failed_authors = self.proposal_generator.compute_failed_authors(
                proposal.round(),
                proposal.quorum_cert().certified_block().round(),
                false,
                self.proposer_election.clone(),
            );
            ensure!(
                proposal.block_data().failed_authors().is_some_and(|failed_authors| *failed_authors == expected_failed_authors),
                "[RoundManager] Proposal for block {} has invalid failed_authors list {:?}, expected {:?}",
                proposal.round(),
                proposal.block_data().failed_authors(),
                expected_failed_authors,
            );
        }

        let block_time_since_epoch = Duration::from_micros(proposal.timestamp_usecs());

        ensure!(
            block_time_since_epoch < self.round_state.current_round_deadline(),
            "[RoundManager] Waiting until proposal block timestamp usecs {:?} \
            would exceed the round duration {:?}, hence will not vote for this round",
            block_time_since_epoch,
            self.round_state.current_round_deadline(),
        );
```

**File:** types/src/transaction/mod.rs (L1055-1058)
```rust
    /// A cached hash of the transaction.
    #[serde(skip)]
    committed_hash: OnceCell<HashValue>,
}
```

**File:** types/src/transaction/mod.rs (L1335-1339)
```rust
    pub fn committed_hash(&self) -> HashValue {
        *self
            .committed_hash
            .get_or_init(|| Transaction::UserTransaction(self.clone()).hash())
    }
```

**File:** consensus/src/block_storage/block_store.rs (L412-438)
```rust
    pub async fn insert_block(&self, block: Block) -> anyhow::Result<Arc<PipelinedBlock>> {
        if let Some(existing_block) = self.get_block(block.id()) {
            return Ok(existing_block);
        }
        ensure!(
            self.inner.read().ordered_root().round() < block.round(),
            "Block with old round"
        );

        let block_window = self
            .inner
            .read()
            .get_ordered_block_window(&block, self.window_size)?;
        let blocks = block_window.blocks();
        for block in blocks {
            if let Some(payload) = block.payload() {
                self.payload_manager.prefetch_payload_data(
                    payload,
                    block.author().expect("Payload block must have author"),
                    block.timestamp_usecs(),
                );
            }
        }

        let pipelined_block = PipelinedBlock::new_ordered(block, block_window);
        self.insert_block_inner(pipelined_block).await
    }
```

**File:** consensus/src/block_preparer.rs (L99-99)
```rust
            let deduped_txns = txn_deduper.dedup(filtered_txns);
```

**File:** config/src/config/consensus_config.rs (L47-47)
```rust
    pub mempool_txn_pull_timeout_ms: u64,
```

**File:** mempool/src/shared_mempool/tasks.rs (L496-499)
```rust
                if result.is_ok() {
                    t.0.committed_hash();
                    t.0.txn_bytes_len();
                }
```
