# Audit Report

## Title
Unverified TransactionFilter Enables Byzantine Validators to Selectively Censor Validator Transactions

## Summary
The `pull()` function in the validator transaction pool accepts a `TransactionFilter` parameter that is constructed locally by the proposer without any verification by receiving validators. Colluding Byzantine validators can manipulate this filter to selectively exclude validator transactions from honest validators while including their own, causing unfair transaction ordering and potential delays in critical protocol operations like DKG and JWK consensus.

## Finding Description

The vulnerability exists in the interaction between the validator transaction pool's `pull()` function and the consensus proposal generation mechanism.

**Attack Flow:**

1. When generating a proposal, the proposer constructs a `TransactionFilter` based on pending blocks [1](#0-0) 

2. This filter is passed to `pull()` to exclude validator transactions that are supposedly in pending blocks [2](#0-1) 

3. The `pull()` implementation filters out transactions whose hashes match the filter [3](#0-2) 

4. The filter checks if transactions should be excluded [4](#0-3) 

**The Critical Issue:**

A Byzantine proposer can modify their local code to inject arbitrary transaction hashes into the `pending_validator_txn_hashes` set, falsely claiming these transactions are in pending blocks. When receiving validators process the proposal, they validate the included validator transactions but **never verify** that the proposer correctly filtered based on actual pending blocks [5](#0-4) 

The validation only checks:
- Valid signatures on included transactions
- Count and size limits
- Proposer validity

But crucially, there is **no verification** that:
- The filter was constructed correctly from pending blocks
- All available validator transactions were considered
- No transactions were arbitrarily excluded

## Impact Explanation

This vulnerability enables **selective censorship attacks** on critical validator transactions:

**Critical Protocol Operations Affected:**
- **DKG Results** (Distributed Key Generation): Required for on-chain randomness. Censoring DKG transactions delays randomness availability, affecting protocols depending on it [6](#0-5) 

- **JWK Updates** (JSON Web Key): Required for keyless account authentication. Censoring JWK updates delays security patches and key rotations

**Consensus Impact:**
While this doesn't break consensus safety (all honest validators will agree on blocks), it violates **consensus fairness** and can cause **liveness degradation** for validator coordination protocols. With f Byzantine validators colluding, they can delay critical validator transactions by up to f consecutive rounds.

**Severity Assessment:** This meets **High Severity** criteria as it constitutes a "significant protocol violation" that can cause validator coordination delays and unfair transaction ordering. It could escalate to **Critical** if time-sensitive validator transactions fail to complete within required timeframes.

## Likelihood Explanation

**Likelihood: High**

The attack requires:
1. Byzantine validator(s) with proposal rights
2. Code modification to inject arbitrary hashes into the filter
3. No additional consensus-level permissions or complex exploits

With f < n/3 Byzantine validators (standard BFT assumption), they will regularly get proposal opportunities and can execute this attack whenever they are selected as proposer. The attack is:
- **Trivial to implement**: Single line of code modification
- **Undetectable**: No validation checks the filter correctness  
- **Repeatable**: Can be executed in every round the Byzantine validator proposes
- **Requires no coordination**: Single Byzantine validator sufficient

## Recommendation

Implement **receiver-side verification** of validator transaction inclusion:

**Solution 1: Consensus-level Verification**
Each validator should independently compute what validator transactions should have been included and verify the proposer's choices:

```rust
// In process_proposal() after line 1137
// Verify validator transaction completeness
let expected_filter = compute_expected_filter(&pending_blocks);
let available_vtxns = local_vtxn_pool.pull(deadline, max_items, max_bytes, expected_filter);

// Check if proposer omitted available transactions
let proposed_vtxn_set: HashSet<_> = proposal.validator_txns()
    .unwrap_or(&[])
    .iter()
    .map(|v| v.hash())
    .collect();

for available_vtxn in available_vtxns {
    if !proposed_vtxn_set.contains(&available_vtxn.hash()) {
        bail!(
            "Proposer omitted available validator transaction: {}",
            available_vtxn.hash()
        );
    }
}
```

**Solution 2: Filter Inclusion in Proposal**
Include the filter hash in the block proposal so validators can verify it matches their expected filter for the given pending blocks.

**Solution 3: Deterministic Pull**
Make validator transaction inclusion deterministic based on globally observable state (pending blocks) rather than a locally-constructed filter.

## Proof of Concept

```rust
// Malicious Proposer Code Modification
// In consensus/src/liveness/proposal_generator.rs

async fn generate_proposal_inner(
    &self,
    round: Round,
    parent_id: HashValue,
    proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    maybe_optqs_payload_pull_params: Option<OptQSPayloadPullParams>,
) -> anyhow::Result<(Vec<ValidatorTransaction>, Payload, u64)> {
    // ... existing code ...
    
    let mut pending_validator_txn_hashes: HashSet<HashValue> = pending_blocks
        .iter()
        .filter_map(|block| block.validator_txns())
        .flatten()
        .map(ValidatorTransaction::hash)
        .collect();
    
    // MALICIOUS MODIFICATION: Inject target victim's validator transaction hash
    // This hash could be obtained by observing the victim's validator transaction
    // from the network or local pool
    let victim_vtxn_hash = get_target_victim_vtxn_hash(); // Attacker's function
    pending_validator_txn_hashes.insert(victim_vtxn_hash); // ← ATTACK: Falsely exclude victim's transaction
    
    let validator_txn_filter =
        vtxn_pool::TransactionFilter::PendingTxnHashSet(pending_validator_txn_hashes);
    
    // The victim's validator transaction is now excluded from the proposal
    // Receiving validators will accept this block without detecting the censorship
    // ... rest of the function
}
```

**Attack Demonstration:**
1. Byzantine validator observes honest validator's DKG transaction with hash `H_honest`
2. When proposing, Byzantine validator adds `H_honest` to the filter
3. Byzantine validator's own DKG transaction with hash `H_byzantine` is not filtered
4. Resulting block includes `H_byzantine` but excludes `H_honest`
5. Other validators accept the block (all validations pass)
6. DKG protocol progresses with only Byzantine validator's contribution, delaying completion

### Citations

**File:** consensus/src/liveness/proposal_generator.rs (L643-650)
```rust
        let pending_validator_txn_hashes: HashSet<HashValue> = pending_blocks
            .iter()
            .filter_map(|block| block.validator_txns())
            .flatten()
            .map(ValidatorTransaction::hash)
            .collect();
        let validator_txn_filter =
            vtxn_pool::TransactionFilter::PendingTxnHashSet(pending_validator_txn_hashes);
```

**File:** consensus/src/payload_client/mixed.rs (L65-79)
```rust
        let mut validator_txns = self
            .validator_txn_pool_client
            .pull(
                params.max_poll_time,
                min(
                    params.max_txns.count(),
                    self.validator_txn_config.per_block_limit_txn_count(),
                ),
                min(
                    params.max_txns.size_in_bytes(),
                    self.validator_txn_config.per_block_limit_total_bytes(),
                ),
                validator_txn_filter,
            )
            .await;
```

**File:** crates/validator-transaction-pool/src/lib.rs (L30-34)
```rust
    pub fn should_exclude(&self, txn: &ValidatorTransaction) -> bool {
        match self {
            TransactionFilter::PendingTxnHashSet(set) => set.contains(&txn.hash()),
        }
    }
```

**File:** crates/validator-transaction-pool/src/lib.rs (L152-199)
```rust
    pub fn pull(
        &mut self,
        deadline: Instant,
        mut max_items: u64,
        mut max_bytes: u64,
        filter: TransactionFilter,
    ) -> Vec<ValidatorTransaction> {
        let mut ret = vec![];
        let mut seq_num_lower_bound = 0;

        // Check deadline at the end of every iteration to ensure validator txns get a chance no matter what current proposal delay is.
        while max_items >= 1 && max_bytes >= 1 {
            // Find the seq_num of the first txn that satisfies the quota.
            if let Some(seq_num) = self
                .txn_queue
                .range(seq_num_lower_bound..)
                .filter(|(_, item)| {
                    item.txn.size_in_bytes() as u64 <= max_bytes
                        && !filter.should_exclude(&item.txn)
                })
                .map(|(seq_num, _)| *seq_num)
                .next()
            {
                // Update the quota usage.
                // Send the pull notification if requested.
                let PoolItem {
                    txn,
                    pull_notification_tx,
                    ..
                } = self.txn_queue.get(&seq_num).unwrap();
                if let Some(tx) = pull_notification_tx {
                    let _ = tx.push((), txn.clone());
                }
                max_items -= 1;
                max_bytes -= txn.size_in_bytes() as u64;
                seq_num_lower_bound = seq_num + 1;
                ret.push(txn.as_ref().clone());

                if Instant::now() >= deadline {
                    break;
                }
            } else {
                break;
            }
        }

        ret
    }
```

**File:** consensus/src/round_manager.rs (L1126-1137)
```rust
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
```

**File:** types/src/validator_txn.rs (L14-18)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub enum ValidatorTransaction {
    DKGResult(DKGTranscript),
    ObservedJWKUpdate(jwks::QuorumCertifiedUpdate),
}
```
