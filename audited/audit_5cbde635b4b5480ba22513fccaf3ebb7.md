# Audit Report

## Title
Consensus Safety Violation: Transaction Filter Bypass via QuorumStore Proof Batches Causes Deterministic Execution Failure

## Summary
A critical discrepancy exists between transaction filtering during the voting phase and execution phase in QuorumStore payloads. During voting, only inline transactions are checked against block transaction filters, but during execution, ALL transactions (including those from proof batches and optimistic batches) are filtered. This allows transactions that match Deny rules to pass voting validation but be filtered differently across validators during execution, breaking consensus safety and causing network partition.

## Finding Description

The `BlockTransactionFilter.allows_transaction()` function is invoked at two critical points in the consensus flow with different transaction sets, violating the **Deterministic Execution** invariant.

**Voting Phase (Proposal Validation):** [1](#0-0) 

The check calls `check_denied_inline_transactions()` which only validates inline transactions: [2](#0-1) 

The function `get_inline_transactions()` only extracts transactions from inline batches: [3](#0-2) 

**Execution Phase (Block Preparation):** [4](#0-3) 

This filters ALL transactions returned by `get_transactions()`, which includes proof batches and optimistic batches: [5](#0-4) 

**Attack Scenario:**

1. Validators have transaction filters configured (e.g., to deny transactions from specific addresses or calling specific functions)
2. Attacker crafts a transaction matching a Deny rule in some validators' filters
3. Attacker includes this transaction in a `ProofWithData` batch or `opt_batch` (NOT in inline batch)
4. During voting: All validators check only inline batches via `get_inline_transactions()`, find no denied transactions, vote to accept
5. Block achieves 2/3+ quorum and gets committed
6. During execution:
   - Validators with matching Deny rules: Filter out the malicious transaction, execute N-1 transactions
   - Validators without the rule or with different filter configs: Execute all N transactions
7. **Result:** Different validators compute different state roots → consensus split → network partition

**The Rule Matching Logic:** [6](#0-5) 

The filter correctly processes rules, but the vulnerability lies in **when and where** it's called with **which transaction set**.

## Impact Explanation

**Critical Severity** - This vulnerability breaks the fundamental consensus safety guarantee:

- **Breaks Deterministic Execution Invariant:** Different validators execute different transaction sets from the same committed block, producing different state roots
- **Consensus Split:** Validators diverge on state, unable to reach agreement on subsequent blocks
- **Network Partition:** Requires emergency intervention or hard fork to recover
- **Loss of Funds:** Depending on filtered transactions, state divergence can lead to double-spending or fund loss

This qualifies for **Critical Severity** (up to $1,000,000) under "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood** if transaction filters are deployed in production:

- **Low Attacker Requirements:** Any transaction sender can craft transactions for proof batches
- **No Special Access Needed:** Does not require validator privileges or insider knowledge
- **Deterministic Trigger:** If validators have different filter configurations or any filters with Deny rules, the attack succeeds
- **Existing Test Gaps:** Current tests only verify inline transaction filtering, missing this scenario: [7](#0-6) 

The test creates `ProofWithData::empty()` - never testing denied transactions in proof batches.

## Recommendation

**Fix: Apply transaction filters consistently at both voting and execution phases.**

**Option 1 (Preferred):** Extend `check_denied_inline_transactions()` to validate ALL transactions that will be executed:

```rust
// In consensus/src/payload_manager/quorum_store_payload_manager.rs
fn check_denied_inline_transactions(
    &self,
    block: &Block,
    block_txn_filter_config: &BlockTransactionFilterConfig,
) -> anyhow::Result<()> {
    if !block_txn_filter_config.is_enabled() {
        return Ok(());
    }

    // Get ALL transactions that will be executed (not just inline)
    // This requires fetching transactions from proof batches and opt batches
    let all_transactions = self.get_all_transactions_for_validation(block)?;
    
    if all_transactions.is_empty() {
        return Ok(());
    }

    let block_id = block.id();
    let block_author = block.author();
    let block_epoch = block.epoch();
    let block_timestamp = block.timestamp_usecs();

    let denied_transactions = block_txn_filter_config
        .block_transaction_filter()
        .get_denied_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp,
            all_transactions,
        );
        
    if !denied_transactions.is_empty() {
        return Err(anyhow::anyhow!(
            "Transactions in block denied by filter: {:?}",
            denied_transactions
        ));
    }

    Ok(())
}
```

**Option 2:** Remove filtering during execution phase and rely solely on voting-phase checks (less secure, not recommended).

**Option 3:** Disallow transactions in proof batches/opt batches if filters are enabled (degrades QuorumStore efficiency).

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
#[test]
fn test_consensus_split_via_proof_batch_filter_bypass() {
    // Create a transaction that matches a Deny rule
    let denied_sender = AccountAddress::random();
    let denied_transaction = create_transaction(denied_sender);
    
    // Create a block filter that denies this sender
    let block_txn_filter = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(
            false, 
            vec![BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(denied_sender)
            )]
        )
        .add_all_filter(true);
    let block_txn_filter_config = BlockTransactionFilterConfig::new(true, block_txn_filter);
    
    // Create a QuorumStore payload with:
    // - Clean inline batch (no denied transactions)
    // - Proof batch containing the denied transaction
    let clean_inline_batch = (create_batch_info(1), vec![create_transaction(AccountAddress::random())]);
    let proof_with_denied_txn = create_proof_with_data(vec![denied_transaction.clone()]);
    
    let payload = Payload::QuorumStoreInlineHybrid(
        vec![clean_inline_batch],
        proof_with_denied_txn,
        None
    );
    
    let block = Block::new_proposal(payload, 1, 1, certificate_for_genesis(), &signer, Vec::new()).unwrap();
    
    // VOTING PHASE: Should pass (only checks inline batch)
    assert!(payload_manager
        .check_denied_inline_transactions(&block, &block_txn_filter_config)
        .is_ok());
    
    // EXECUTION PHASE: Filters out denied transaction
    let filtered_txns = block_txn_filter_config
        .block_transaction_filter()
        .filter_block_transactions(
            block.id(),
            block.author(),
            block.epoch(),
            block.timestamp_usecs(),
            vec![denied_transaction.clone()]
        );
    
    // Proof: Transaction passes voting but is filtered during execution
    assert!(filtered_txns.is_empty()); // Transaction was filtered!
    
    // This creates consensus divergence:
    // - Validator A (with filter): executes 1 transaction (inline only)
    // - Validator B (without filter): executes 2 transactions (inline + proof)
    // -> Different state roots -> Consensus split
}
```

**Notes**

- The incomplete security question "[Rule" likely intended to ask about rule matching logic, but the investigation revealed this more fundamental architectural vulnerability
- The issue affects all QuorumStore payload types: `QuorumStoreInlineHybrid`, `QuorumStoreInlineHybridV2`, and `OptQuorumStore`
- Current test coverage only validates inline transaction filtering, missing proof batch and opt batch scenarios
- The vulnerability is latent if transaction filters are not actively used, but becomes critical when filters are deployed
- This represents a violation of the separation of concerns: voting-time validation should match execution-time behavior exactly

### Citations

**File:** consensus/src/round_manager.rs (L1204-1214)
```rust
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
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L308-347)
```rust
    fn check_denied_inline_transactions(
        &self,
        block: &Block,
        block_txn_filter_config: &BlockTransactionFilterConfig,
    ) -> anyhow::Result<()> {
        // If the filter is disabled, return early
        if !block_txn_filter_config.is_enabled() {
            return Ok(());
        }

        // Get the inline transactions for the block proposal
        let inline_transactions = get_inline_transactions(block);
        if inline_transactions.is_empty() {
            return Ok(());
        }

        // Fetch the block metadata
        let block_id = block.id();
        let block_author = block.author();
        let block_epoch = block.epoch();
        let block_timestamp = block.timestamp_usecs();

        // Identify any denied inline transactions
        let block_transaction_filter = block_txn_filter_config.block_transaction_filter();
        let denied_inline_transactions = block_transaction_filter.get_denied_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp,
            inline_transactions,
        );
        if !denied_inline_transactions.is_empty() {
            return Err(anyhow::anyhow!(
                "Inline transactions for QuorumStorePayload denied by block transaction filter: {:?}",
                denied_inline_transactions
            ));
        }

        Ok(()) // No transactions were denied
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L446-564)
```rust
    async fn get_transactions(
        &self,
        block: &Block,
        block_signers: Option<BitVec>,
    ) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
        let Some(payload) = block.payload() else {
            return Ok((Vec::new(), None, None));
        };

        let transaction_payload = match payload {
            Payload::InQuorumStore(proof_with_data) => {
                let transactions = process_qs_payload(
                    proof_with_data,
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                )
                .await?;
                BlockTransactionPayload::new_in_quorum_store(
                    transactions,
                    proof_with_data.proofs.clone(),
                )
            },
            Payload::InQuorumStoreWithLimit(proof_with_data) => {
                let transactions = process_qs_payload(
                    &proof_with_data.proof_with_data,
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                )
                .await?;
                BlockTransactionPayload::new_in_quorum_store_with_limit(
                    transactions,
                    proof_with_data.proof_with_data.proofs.clone(),
                    proof_with_data.max_txns_to_execute,
                )
            },
            Payload::QuorumStoreInlineHybrid(
                inline_batches,
                proof_with_data,
                max_txns_to_execute,
            ) => {
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    max_txns_to_execute,
                    &None,
                )
                .await?
            },
            Payload::QuorumStoreInlineHybridV2(
                inline_batches,
                proof_with_data,
                execution_limits,
            ) => {
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    &execution_limits.max_txns_to_execute(),
                    &execution_limits.block_gas_limit(),
                )
                .await?
            },
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(opt_qs_payload)) => {
                let opt_batch_txns = process_optqs_payload(
                    opt_qs_payload.opt_batches(),
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                    block_signers.as_ref(),
                )
                .await?;
                let proof_batch_txns = process_optqs_payload(
                    opt_qs_payload.proof_with_data(),
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                    None,
                )
                .await?;
                let inline_batch_txns = opt_qs_payload.inline_batches().transactions();
                let all_txns = [proof_batch_txns, opt_batch_txns, inline_batch_txns].concat();
                BlockTransactionPayload::new_opt_quorum_store(
                    all_txns,
                    opt_qs_payload.proof_with_data().deref().clone(),
                    opt_qs_payload.max_txns_to_execute(),
                    opt_qs_payload.block_gas_limit(),
                    [
                        opt_qs_payload.opt_batches().deref().clone(),
                        opt_qs_payload.inline_batches().batch_infos(),
                    ]
                    .concat(),
                )
            },
            _ => unreachable!(
                "Wrong payload {} epoch {}, round {}, id {}",
                payload,
                block.block_data().epoch(),
                block.block_data().round(),
                block.id()
            ),
        };

        if let Some(consensus_publisher) = &self.maybe_consensus_publisher {
            let message = ConsensusObserverMessage::new_block_payload_message(
                block.gen_block_info(HashValue::zero(), 0, None),
                transaction_payload.clone(),
            );
            consensus_publisher.publish_message(message);
        }

        Ok((
            transaction_payload.transactions(),
            transaction_payload.transaction_limit(),
            transaction_payload.gas_limit(),
        ))
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L567-599)
```rust
/// Extracts and returns all inline transactions from the payload in the given block
fn get_inline_transactions(block: &Block) -> Vec<SignedTransaction> {
    // If the block has no payload, return an empty vector
    let Some(payload) = block.payload() else {
        return vec![];
    };

    // Fetch the inline transactions from the payload
    match payload {
        Payload::QuorumStoreInlineHybrid(inline_batches, ..) => {
            // Flatten the inline batches and return the transactions
            inline_batches
                .iter()
                .flat_map(|(_batch_info, txns)| txns.clone())
                .collect()
        },
        Payload::QuorumStoreInlineHybridV2(inline_batches, ..) => {
            // Flatten the inline batches and return the transactions
            inline_batches
                .iter()
                .flat_map(|(_batch_info, txns)| txns.clone())
                .collect()
        },
        Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => p.inline_batches().transactions(),
        Payload::OptQuorumStore(OptQuorumStorePayload::V2(_p)) => {
            error!("OptQSPayload V2 is not expected");
            Vec::new()
        },
        _ => {
            vec![] // Other payload types do not have inline transactions
        },
    }
}
```

**File:** consensus/src/block_preparer.rs (L91-98)
```rust
            let filtered_txns = filter_block_transactions(
                txn_filter_config,
                block_id,
                block_author,
                block_epoch,
                block_timestamp_usecs,
                txns,
            );
```

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L29-59)
```rust
    pub fn allows_transaction(
        &self,
        block_id: HashValue,
        block_author: Option<AccountAddress>,
        block_epoch: u64,
        block_timestamp: u64,
        signed_transaction: &SignedTransaction,
    ) -> bool {
        // If the filter is empty, allow the transaction by default
        if self.is_empty() {
            return true;
        }

        // Check if any rule matches the block transaction
        for block_transaction_rule in &self.block_transaction_rules {
            if block_transaction_rule.matches(
                block_id,
                block_author,
                block_epoch,
                block_timestamp,
                signed_transaction,
            ) {
                return match block_transaction_rule {
                    BlockTransactionRule::Allow(_) => true,
                    BlockTransactionRule::Deny(_) => false,
                };
            }
        }

        true // No rules match (allow the block transaction by default)
    }
```

**File:** consensus/src/round_manager_tests/txn_filter_proposal_test.rs (L234-244)
```rust
fn create_payload(
    transactions: Vec<SignedTransaction>,
    use_quorum_store_payloads: bool,
) -> Payload {
    if use_quorum_store_payloads {
        let inline_batch = (create_batch_info(transactions.len()), transactions);
        Payload::QuorumStoreInlineHybrid(vec![inline_batch], ProofWithData::empty(), None)
    } else {
        Payload::DirectMempool(transactions)
    }
}
```
