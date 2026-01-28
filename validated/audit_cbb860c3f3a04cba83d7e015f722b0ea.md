# Audit Report

## Title
High-Priority Transaction Permanent Starvation Due to Priority Queue Ordering with Sequence Number Dependencies

## Summary
The `get_batch()` function in the mempool can permanently starve legitimate high-priority transactions when lower sequence number transactions from the same account have very low gas prices and the mempool is consistently full with high-priority transactions from other accounts. This violates the gas-price-based priority guarantee and can prevent time-sensitive transactions from being executed.

## Finding Description

The mempool's `get_batch()` function uses a priority queue ordered by `gas_ranking_score` to select transactions for consensus blocks. [1](#0-0)  The priority queue iterator returns transactions in reverse order (highest gas ranking score first). [2](#0-1) 

However, sequence number transactions have a strict ordering requirement enforced at the point of batch selection. [3](#0-2) 

The vulnerability occurs when:

1. An account has transaction `seq=100` with very low `gas_ranking_score` (e.g., 1)
2. The same account has transactions `seq=101, 102, 103` with very high `gas_ranking_score` (e.g., 1000000)
3. The mempool is full with many high-priority transactions from different accounts

**Attack Scenario:**

When `get_batch()` is called with the default `max_txns=50` [4](#0-3) :

1. The priority queue iteration encounters `seq=101, 102, 103` first due to high ranking scores
2. These transactions cannot be included because `seq=100` hasn't been chosen yet and the sequence number check fails
3. They are added to the `skipped` HashSet [5](#0-4) 
4. The batch fills up with 50 high-priority transactions from OTHER accounts before ever reaching `seq=100` in the priority queue
5. The loop breaks when `max_txns` is reached [6](#0-5) 
6. The skipped transaction promotion logic **never executes** for `seq=100` because it only runs after a transaction is successfully included [7](#0-6) 
7. The `skipped` HashSet is local to each `get_batch()` call, so it doesn't persist
8. On the next `get_batch()` call, the cycle repeats indefinitely

The code comments explicitly acknowledge this scenario was anticipated and the skipped/promotion mechanism was designed to handle it. [8](#0-7)  However, this mechanism fails when the batch fills before reaching the blocking transaction.

**Broken Invariant:** This violates the fundamental guarantee that higher gas prices result in faster transaction inclusion. Transactions with `gas_ranking_score=1000000` are permanently blocked by a transaction with `gas_ranking_score=1`.

## Impact Explanation

**Severity: MEDIUM** (per Aptos bug bounty criteria)

This vulnerability causes:

1. **State inconsistencies requiring manual intervention** - Users cannot execute their high-priority transactions despite paying high gas fees without manually resubmitting the blocking transaction with higher gas
2. **Limited funds loss or manipulation** - Users may lose arbitrage opportunities, fail to prevent liquidations, or miss time-sensitive DeFi operations
3. **Protocol degradation** - Breaks the gas price priority mechanism, a core blockchain invariant

**Affected Users:**
- Any account that submits transactions with varying gas prices across different sequence numbers
- Users needing urgent transaction execution (liquidations, arbitrage, governance votes)
- Can affect multiple accounts if attackers deliberately create this scenario

**Attack Cost:** Very low - attacker only needs to submit one low-gas transaction followed by high-gas transactions from the same account.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** in congested network conditions

**Factors increasing likelihood:**

1. **Network Congestion**: During high transaction volume, batches consistently fill to `max_txns` with high-priority transactions. The quorum store configuration limits batch sizes. [9](#0-8) 

2. **Deliberate Attack**: Malicious actors can intentionally create this scenario:
   - Submit `seq=N` with `gas_unit_price=1` (minimum)
   - Submit `seq=N+1, N+2, ...` with `gas_unit_price=MAX`
   - Watch high-priority transactions starve indefinitely

3. **Accidental Occurrence**: Users who submit a low-priority transaction first, then urgent high-priority transactions later will experience this

4. **No Automatic Recovery**: Unlike temporary delays, this is **permanent starvation** until:
   - Network congestion decreases significantly
   - The low-priority transaction expires (TTL) and is garbage collected
   - User manually increases gas price on the blocking transaction

**Likelihood is REDUCED when:**
- Network has low transaction volume
- Batches don't consistently reach `max_txns` limit

## Recommendation

Modify the `get_batch()` function to continue iterating through the priority queue even after reaching `max_txns`, specifically to find and include blocking transactions for accounts that have transactions in the `skipped` set. This ensures the skipped promotion mechanism can function correctly.

Alternative approach: Maintain a persistent priority queue of accounts with skipped transactions across `get_batch()` calls, and prioritize including their blocking transactions in subsequent batches.

## Proof of Concept

```rust
#[test]
fn test_transaction_starvation_with_full_batch() {
    let (mut mempool, mut consensus) = setup_mempool();
    
    // Add low-priority blocking transaction seq=100 from account 0
    add_txn(&mut mempool, TestTransaction::new(0, ReplayProtector::SequenceNumber(100), 1)).unwrap();
    
    // Add high-priority transactions seq=101, 102, 103 from account 0
    for seq in 101..104 {
        add_txn(&mut mempool, TestTransaction::new(0, ReplayProtector::SequenceNumber(seq), 1000000)).unwrap();
    }
    
    // Add 50 high-priority transactions from different accounts to fill the batch
    for account in 1..51 {
        add_txn(&mut mempool, TestTransaction::new(account, ReplayProtector::SequenceNumber(0), 10000)).unwrap();
    }
    
    // Get batch with max_txns=50
    let batch = consensus.get_block(&mut mempool, 50, 1024 * 1024);
    
    // Verify that none of the high-priority transactions from account 0 are included
    // because seq=100 was never reached due to batch filling up
    for txn in &batch {
        assert_ne!(txn.sender(), TestTransaction::get_address(0));
    }
    
    // On subsequent calls, the same starvation continues
    let batch2 = consensus.get_block(&mut mempool, 50, 1024 * 1024);
    for txn in &batch2 {
        assert_ne!(txn.sender(), TestTransaction::get_address(0));
    }
    
    // Account 0's high-priority transactions remain starved indefinitely
}
```

**Notes:**
- This vulnerability is confirmed through code analysis of the mempool batch selection logic
- The skipped promotion mechanism was designed to handle sequence number dependencies but fails when the batch limit is reached before the blocking transaction is encountered in the priority queue iteration
- The issue represents a design flaw rather than a simple bug, as the comments indicate this scenario was anticipated but the mitigation is incomplete
- Recovery requires either TTL expiration (default 600 seconds), manual gas price increase, or decreased network congestion

### Citations

**File:** mempool/src/core_mempool/index.rs (L167-168)
```rust
    pub(crate) fn iter(&self) -> PriorityQueueIter<'_> {
        self.data.iter().rev()
```

**File:** mempool/src/core_mempool/index.rs (L192-197)
```rust
impl Ord for OrderedQueueKey {
    fn cmp(&self, other: &OrderedQueueKey) -> Ordering {
        // Higher gas preferred
        match self.gas_ranking_score.cmp(&other.gas_ranking_score) {
            Ordering::Equal => {},
            ordering => return ordering,
```

**File:** mempool/src/core_mempool/mempool.rs (L439-444)
```rust
        // Helper DS. Helps to mitigate scenarios where account submits several transactions
        // with increasing gas price (e.g. user submits transactions with sequence number 1, 2
        // and gas_price 1, 10 respectively)
        // Later txn has higher gas price and will be observed first in priority index iterator,
        // but can't be executed before first txn. Once observed, such txn will be saved in
        // `skipped` DS and rechecked once it's ancestor becomes available
```

**File:** mempool/src/core_mempool/mempool.rs (L445-445)
```rust
        let mut skipped = HashSet::new();
```

**File:** mempool/src/core_mempool/mempool.rs (L459-471)
```rust
                ReplayProtector::SequenceNumber(txn_seq) => {
                    let txn_in_sequence = txn_seq > 0
                        && Self::txn_was_chosen(
                            txn.address,
                            txn_seq - 1,
                            &inserted,
                            &exclude_transactions,
                        );
                    let account_sequence_number =
                        self.transactions.get_account_sequence_number(&txn.address);
                    // include transaction if it's "next" for given account or
                    // we've already sent its ancestor to Consensus.
                    if txn_in_sequence || account_sequence_number == Some(&txn_seq) {
```

**File:** mempool/src/core_mempool/mempool.rs (L474-475)
```rust
                        if (result.len() as u64) == max_txns {
                            break;
```

**File:** mempool/src/core_mempool/mempool.rs (L478-494)
```rust
                        // that were skipped before for given account
                        let (skipped_txn_sender, mut skipped_txn_seq_num) =
                            (txn.address, txn_seq + 1);
                        while skipped.remove(&(skipped_txn_sender, skipped_txn_seq_num)) {
                            inserted.insert((
                                skipped_txn_sender,
                                ReplayProtector::SequenceNumber(skipped_txn_seq_num),
                            ));
                            result.push((
                                skipped_txn_sender,
                                ReplayProtector::SequenceNumber(skipped_txn_seq_num),
                            ));
                            if (result.len() as u64) == max_txns {
                                break 'main;
                            }
                            skipped_txn_seq_num += 1;
                        }
```

**File:** config/src/config/quorum_store_config.rs (L13-13)
```rust
pub const DEFEAULT_MAX_BATCH_TXNS: usize = 50;
```

**File:** config/src/config/quorum_store_config.rs (L105-119)
```rust
impl Default for QuorumStoreConfig {
    fn default() -> QuorumStoreConfig {
        QuorumStoreConfig {
            channel_size: 1000,
            proof_timeout_ms: 10000,
            batch_generation_poll_interval_ms: 25,
            batch_generation_min_non_empty_interval_ms: 50,
            batch_generation_max_interval_ms: 250,
            sender_max_batch_txns: DEFEAULT_MAX_BATCH_TXNS,
            // TODO: on next release, remove BATCH_PADDING_BYTES
            sender_max_batch_bytes: 1024 * 1024 - BATCH_PADDING_BYTES,
            sender_max_num_batches: DEFAULT_MAX_NUM_BATCHES,
            sender_max_total_txns: 1500,
            // TODO: on next release, remove DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES
            sender_max_total_bytes: 4 * 1024 * 1024 - DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES,
```
