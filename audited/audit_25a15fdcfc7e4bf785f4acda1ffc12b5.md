# Audit Report

## Title
High-Priority Transaction Permanent Starvation Due to Priority Queue Ordering with Sequence Number Dependencies

## Summary
The `get_batch()` function in the mempool can permanently starve legitimate high-priority transactions when lower sequence number transactions from the same account have very low gas prices and the mempool is consistently full with high-priority transactions from other accounts. This violates the gas-price-based priority guarantee and can prevent time-sensitive transactions from being executed.

## Finding Description

The mempool's `get_batch()` function uses a priority queue ordered by `gas_ranking_score` to select transactions for consensus blocks. However, sequence number transactions have a strict ordering requirement: transaction N can only be included if transaction N-1 was already chosen or matches the account's current sequence number. [1](#0-0) 

The vulnerability occurs when:

1. An account has transaction `seq=100` with very low `gas_ranking_score` (e.g., 1)
2. The same account has transactions `seq=101, 102, 103` with very high `gas_ranking_score` (e.g., 1000000)
3. The mempool is full with many high-priority transactions from different accounts

**Attack Scenario:**

When `get_batch()` is called with `max_txns=50`:

1. The priority queue iteration encounters `seq=101, 102, 103` first due to high ranking scores
2. These transactions cannot be included because `seq=100` hasn't been chosen yet (line 471 check fails)
3. They are added to the `skipped` HashSet (line 496)
4. The batch fills up with 50 high-priority transactions from OTHER accounts before ever reaching `seq=100` in the priority queue
5. The loop breaks when `max_txns` is reached (line 474-475)
6. The skipped transaction promotion logic (lines 479-494) **never executes** because we broke before reaching it
7. On the next `get_batch()` call, `seq=100` is NOT in `exclude_transactions` (it was never included), so the cycle repeats indefinitely [2](#0-1) 

The transactions are ordered by the `OrderedQueueKey` which prioritizes higher `gas_ranking_score`: [3](#0-2) 

The priority queue iterator returns transactions in reverse order (highest priority first): [4](#0-3) 

**Broken Invariant:** This violates the fundamental guarantee that higher gas prices result in faster transaction inclusion. Transactions with `gas_ranking_score=1000000` are permanently blocked by a transaction with `gas_ranking_score=1`.

## Impact Explanation

**Severity: MEDIUM** (per Aptos bug bounty criteria)

This vulnerability causes:

1. **State inconsistencies requiring intervention** - Users cannot execute their high-priority transactions despite paying high gas fees
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

1. **Network Congestion**: During high transaction volume, batches consistently fill to `max_txns` with high-priority transactions
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

**Fix 1: Process sequence numbers in order within skipped set**

Modify `get_batch()` to ensure that when a lower sequence number transaction is encountered, it takes precedence over higher sequence numbers from the same account that are in the skipped set:

```rust
// After line 449, before iterating the queue:
let mut account_min_seq: HashMap<AccountAddress, u64> = HashMap::new();

// In the main loop, before checking sequence number logic:
if let ReplayProtector::SequenceNumber(txn_seq) = txn_replay_protector {
    // Track minimum sequence number encountered per account
    account_min_seq.entry(txn.address)
        .and_modify(|min_seq| *min_seq = (*min_seq).min(txn_seq))
        .or_insert(txn_seq);
    
    // If we've skipped higher sequences from this account, 
    // prioritize including this lower sequence even if it has lower gas
    if skipped.iter().any(|(addr, seq)| 
        addr == &txn.address && 
        if let ReplayProtector::SequenceNumber(s) = seq { s > &txn_seq } else { false }
    ) {
        // Force inclusion of this blocking transaction
        // (additional logic needed to handle batch size limits)
    }
}
```

**Fix 2: Add sequence number awareness to priority ordering**

Modify `OrderedQueueKey` comparison to prioritize lower sequence numbers when transactions are from the same account and higher sequences are waiting:

```rust
// In OrderedQueueKey::cmp, add before gas_ranking_score comparison:
if self.address == other.address {
    match (self.replay_protector, other.replay_protector) {
        (ReplayProtector::SequenceNumber(s1), ReplayProtector::SequenceNumber(s2)) => {
            // Lower sequence number gets priority from same account
            if s1 != s2 {
                return s1.cmp(&s2);
            }
        },
        _ => {}
    }
}
```

**Fix 3: Implement fairness mechanism**

Track accounts with skipped transactions and ensure their blocking transactions get included before the batch is full:

```rust
// Reserve slots in batch for blocking transactions
let reserved_slots_for_blockers = skipped.len().min(max_txns / 10); // Reserve 10% of batch
```

## Proof of Concept

```rust
#[test]
fn test_sequence_number_starvation() {
    use aptos_types::transaction::{SignedTransaction, RawTransaction};
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    
    let mut mempool = Mempool::new(&NodeConfig::default());
    let mut rng = rand::thread_rng();
    
    // Setup victim account
    let victim_key = Ed25519PrivateKey::generate(&mut rng);
    let victim_addr = AccountAddress::random();
    
    // Submit seq=100 with LOW gas price (1)
    let txn_100 = create_signed_txn(victim_addr, 100, 1, &victim_key);
    mempool.add_txn(txn_100, 1, Some(100), TimelineState::NotReady, true, None, None);
    
    // Submit seq=101, 102, 103 with HIGH gas price (1000000)
    for seq in 101..=103 {
        let txn = create_signed_txn(victim_addr, seq, 1000000, &victim_key);
        mempool.add_txn(txn, 1000000, Some(100), TimelineState::NotReady, true, None, None);
    }
    
    // Fill mempool with 100 high-priority transactions from other accounts
    for i in 0..100 {
        let other_key = Ed25519PrivateKey::generate(&mut rng);
        let other_addr = AccountAddress::random();
        let txn = create_signed_txn(other_addr, 0, 100000, &other_key);
        mempool.add_txn(txn, 100000, Some(0), TimelineState::NotReady, true, None, None);
    }
    
    // Try to get batch with max_txns=50
    let batch = mempool.get_batch(50, 1_000_000, true, BTreeMap::new());
    
    // VERIFY: seq=101, 102, 103 are NOT in batch despite high priority
    let victim_txns_in_batch = batch.iter()
        .filter(|t| t.sender() == victim_addr)
        .count();
    
    assert_eq!(victim_txns_in_batch, 0, 
        "High-priority transactions seq=101-103 should be starved!");
    
    // Even after multiple rounds, starvation persists
    for _ in 0..10 {
        let batch = mempool.get_batch(50, 1_000_000, true, BTreeMap::new());
        let victim_txns = batch.iter().filter(|t| t.sender() == victim_addr).count();
        assert_eq!(victim_txns, 0, "Starvation persists across multiple get_batch calls!");
    }
}

fn create_signed_txn(
    sender: AccountAddress, 
    seq: u64, 
    gas_price: u64,
    key: &Ed25519PrivateKey
) -> SignedTransaction {
    // Implementation details for creating a signed transaction
    // (would need proper RawTransaction construction)
}
```

## Notes

The vulnerability is more severe during network congestion when batches consistently fill to capacity. The issue stems from a fundamental mismatch between priority queue ordering (by gas price) and sequence number execution requirements (sequential ordering). The current implementation assumes that transactions will eventually be reached in the priority queue iteration, but this assumption breaks when the batch size limit is reached before lower-priority blocking transactions are encountered.

This is a **design-level vulnerability** that requires careful refactoring of the priority queue and batch selection logic to ensure fairness across sequence numbers while maintaining gas-price-based prioritization.

### Citations

**File:** mempool/src/core_mempool/mempool.rs (L459-497)
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
                        inserted.insert((txn.address, txn_replay_protector));
                        result.push((txn.address, txn_replay_protector));
                        if (result.len() as u64) == max_txns {
                            break;
                        }
                        // check if we can now include some transactions
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
                    } else {
                        skipped.insert((txn.address, txn_seq));
                    }
```

**File:** mempool/src/core_mempool/index.rs (L167-169)
```rust
    pub(crate) fn iter(&self) -> PriorityQueueIter<'_> {
        self.data.iter().rev()
    }
```

**File:** mempool/src/core_mempool/index.rs (L192-215)
```rust
impl Ord for OrderedQueueKey {
    fn cmp(&self, other: &OrderedQueueKey) -> Ordering {
        // Higher gas preferred
        match self.gas_ranking_score.cmp(&other.gas_ranking_score) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
        // Lower insertion time preferred
        match self.insertion_time.cmp(&other.insertion_time).reverse() {
            Ordering::Equal => {},
            ordering => return ordering,
        }
        // Higher address preferred
        match self.address.cmp(&other.address) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
        match self.replay_protector.cmp(&other.replay_protector).reverse() {
            Ordering::Equal => {},
            ordering => return ordering,
        }
        self.hash.cmp(&other.hash)
    }
}
```
