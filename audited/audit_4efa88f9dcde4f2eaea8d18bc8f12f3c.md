# Audit Report

## Title
Mempool Resource Exhaustion via Non-Evictable Nonce Transactions

## Summary
The asymmetric handling of nonce-based versus sequence-number-based transactions in the mempool's commit and eviction logic creates a resource exhaustion vulnerability. Nonce transactions are never stored in the parking lot and thus cannot be evicted when mempool capacity is reached, allowing attackers to fill the mempool with low-gas nonce transactions that persist until TTL expiration.

## Finding Description

The mempool implements different cleanup strategies for sequence-number and nonce-based transactions during commits: [1](#0-0) 

When a sequence number transaction commits, it triggers `clean_committed_transactions_below_account_seq_num()` which removes all transactions with lower sequence numbers and calls `process_ready_seq_num_based_transactions()` to promote pending transactions. However, nonce commits only remove the specific committed transaction with no additional cleanup.

The critical vulnerability arises from the fact that **nonce transactions are always considered "ready" and never stored in the parking lot:** [2](#0-1) [3](#0-2) 

When the mempool reaches capacity, the eviction mechanism only removes transactions from the parking lot: [4](#0-3) 

The parking lot insertion logic explicitly excludes nonce transactions: [5](#0-4) 

**Attack Path:**

1. Attacker creates 2,000 accounts (to reach the 2,000,000 total mempool capacity limit)
2. Each account submits 1,000 nonce-based transactions (the per-user limit) with minimum gas price
3. Total: 2,000,000 nonce transactions fill the mempool to capacity
4. These transactions have low gas prices so consensus will not select them
5. When mempool is full, incoming legitimate transactions are rejected with `MempoolIsFull` status
6. Attempted eviction fails because nonce transactions are not in the parking lot
7. Only cleanup mechanisms are:
   - Individual nonce commits (but low-gas transactions won't be selected by consensus)
   - TTL expiration after 600 seconds (10 minutes)

The configuration shows this is feasible: [6](#0-5) [7](#0-6) 

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The mempool should prioritize high-value transactions, but the non-evictable nature of nonce transactions allows low-value transactions to persist and crowd out legitimate high-value transactions.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria:
- Causes temporary denial of service for transaction submission (limited funds loss or manipulation)
- Creates state inconsistency where mempool prioritization fails (requires intervention via TTL cleanup)
- Does not cause permanent damage or consensus violations
- Does not require validator compromise

The impact includes:
- Legitimate users cannot submit transactions for up to 10 minutes
- Network transaction throughput is degraded
- User experience is severely impacted during attack
- Mempool resources are inefficiently utilized

## Likelihood Explanation

**Medium Likelihood:**

**Required Resources:**
- 2,000 accounts to fill mempool capacity
- Gas payment for 2,000,000 transaction submissions
- No validator access or special privileges needed

**Feasibility:**
- Account creation is permissionless
- Gas costs are the primary barrier but are one-time per transaction
- Attack can be repeated every 10 minutes after TTL expiration
- Detection may be delayed as transactions appear valid

**Mitigating Factors:**
- Per-account limit reduces impact from single attacker
- TTL expiration provides automatic cleanup after 10 minutes
- Gas costs make sustained attacks expensive
- Monitoring could detect mass low-gas nonce submissions

## Recommendation

Implement eviction capability for low-priority nonce transactions when mempool is at capacity:

**Option 1: Priority-based eviction from PriorityIndex**
When mempool is full and all parking lot transactions are evicted, allow eviction of lowest-priority transactions from the PriorityIndex (which contains nonce transactions). This maintains the invariant that higher-gas transactions take precedence.

**Option 2: Separate capacity limits**
Enforce a global limit on nonce transactions separate from sequence number transactions, preventing nonce transactions from crowding out all sequence number transactions.

**Option 3: Dynamic TTL adjustment**
Reduce TTL for nonce transactions when mempool utilization is high, providing faster cleanup during potential attacks.

**Recommended fix (Option 1):**
```rust
fn check_is_full_after_eviction(&mut self, txn: &MempoolTransaction, account_sequence_number: Option<u64>) -> bool {
    if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
        // First try parking lot eviction
        let evicted_from_parking_lot = self.evict_from_parking_lot();
        
        // If still full and incoming txn has higher priority, evict lowest priority ready txns
        if self.is_full() && txn.ranking_score > 0 {
            self.evict_lowest_priority_ready_transactions(txn.ranking_score);
        }
    }
    self.is_full()
}

fn evict_lowest_priority_ready_transactions(&mut self, min_ranking_score: u64) {
    // Evict nonce transactions with ranking score below incoming transaction
    while self.is_full() {
        if let Some(lowest_txn) = self.priority_index.get_lowest() {
            if lowest_txn.ranking_score < min_ranking_score {
                // Remove lowest priority transaction
                // Update: implementation details for removal
            } else {
                break;
            }
        } else {
            break;
        }
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_nonce_transaction_resource_exhaustion() {
    let mut config = NodeConfig::default();
    config.mempool.capacity = 100; // Reduced for test
    config.mempool.orderless_txn_capacity_per_user = 10;
    
    let mut mempool = CoreMempool::new(&config);
    
    // Create 10 accounts, each submitting 10 low-gas nonce transactions
    for account_idx in 0..10 {
        let account = AccountAddress::random();
        
        for nonce in 0..10 {
            let txn = create_nonce_transaction(
                account,
                nonce,
                1, // minimum gas price
                Duration::from_secs(600),
            );
            
            let status = mempool.add_txn(
                txn,
                0,
                nonce,
                TimelineState::NotReady,
                false,
            );
            assert_eq!(status.code, MempoolStatusCode::Accepted);
        }
    }
    
    // Mempool should be full (100 transactions)
    assert_eq!(mempool.transactions.system_ttl_index.size(), 100);
    
    // Try to add a high-gas sequence number transaction from a new account
    let legitimate_account = AccountAddress::random();
    let high_gas_txn = create_sequence_number_transaction(
        legitimate_account,
        0,
        1000, // high gas price
        Duration::from_secs(600),
    );
    
    let status = mempool.add_txn(
        high_gas_txn,
        0,
        0,
        TimelineState::Ready,
        false,
    );
    
    // Expected: transaction rejected due to mempool full
    // Actual: eviction should prioritize but doesn't for nonce transactions
    assert_eq!(status.code, MempoolStatusCode::MempoolIsFull);
    
    // Verify that low-gas nonce transactions cannot be evicted
    // Only TTL expiration or commit will clear them
}
```

**Notes**

The vulnerability requires coordination across multiple accounts to fill mempool capacity, but the per-account limit of 1,000 nonce transactions combined with the 2,000,000 total capacity makes this feasible. The 10-minute TTL provides eventual cleanup but does not prevent temporary denial of service. The asymmetry between sequence number and nonce transaction handling is by design for functional reasons, but creates an exploitable resource exhaustion vector that violates the mempool's prioritization guarantees.

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L76-79)
```rust
    // Keeps track of "non-ready" txns (transactions that can't be included in next block).
    // Orderless transactions (transactions with nonce replay protector) are always "ready", and are not
    // stored in the parking lot.
    parking_lot_index: ParkingLotIndex,
```

**File:** mempool/src/core_mempool/transaction_store.rs (L415-456)
```rust
    fn check_is_full_after_eviction(
        &mut self,
        txn: &MempoolTransaction,
        account_sequence_number: Option<u64>,
    ) -> bool {
        if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
            let now = Instant::now();
            // try to free some space in Mempool from ParkingLot by evicting non-ready txns
            let mut evicted_txns = 0;
            let mut evicted_bytes = 0;
            while let Some(txn_pointer) = self.parking_lot_index.get_poppable() {
                if let Some(txn) = self
                    .transactions
                    .get_mut(&txn_pointer.sender)
                    .and_then(|txns| txns.remove(&txn_pointer.replay_protector))
                {
                    debug!(
                        LogSchema::new(LogEntry::MempoolFullEvictedTxn).txns(TxnsLog::new_txn(
                            txn.get_sender(),
                            txn.get_replay_protector()
                        ))
                    );
                    evicted_bytes += txn.get_estimated_bytes() as u64;
                    evicted_txns += 1;
                    self.index_remove(&txn);
                    if !self.is_full() {
                        break;
                    }
                } else {
                    error!("Transaction not found in mempool while evicting from parking lot");
                    break;
                }
            }
            if evicted_txns > 0 {
                counters::CORE_MEMPOOL_PARKING_LOT_EVICTED_COUNT.observe(evicted_txns as f64);
                counters::CORE_MEMPOOL_PARKING_LOT_EVICTED_BYTES.observe(evicted_bytes as f64);
                counters::CORE_MEMPOOL_PARKING_LOT_EVICTED_LATENCY
                    .observe(now.elapsed().as_secs_f64());
            }
        }
        self.is_full()
    }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L495-498)
```rust
            ReplayProtector::Nonce(_) => {
                // Nonce based transactions are always ready for broadcast
                true
            },
```

**File:** mempool/src/core_mempool/transaction_store.rs (L677-706)
```rust
            ReplayProtector::SequenceNumber(txn_sequence_number) => {
                let current_account_seq_number =
                    self.get_account_sequence_number(account).map_or(0, |v| *v);
                let new_account_seq_number =
                    max(current_account_seq_number, txn_sequence_number + 1);
                self.account_sequence_numbers
                    .insert(*account, new_account_seq_number);
                self.clean_committed_transactions_below_account_seq_num(
                    account,
                    new_account_seq_number,
                );
                self.process_ready_seq_num_based_transactions(account, new_account_seq_number);
            },
            ReplayProtector::Nonce(nonce) => {
                if let Some(txns) = self.transactions.get_mut(account) {
                    if let Some(txn) = txns.remove(&ReplayProtector::Nonce(nonce)) {
                        self.index_remove(&txn);
                        trace!(
                            LogSchema::new(LogEntry::CleanCommittedTxn).txns(TxnsLog::new_txn(
                                txn.get_sender(),
                                txn.get_replay_protector()
                            )),
                            "txns cleaned with committing tx {}:{:?}",
                            txn.get_sender(),
                            txn.get_replay_protector()
                        );
                    }
                }
            },
        }
```

**File:** mempool/src/core_mempool/index.rs (L547-587)
```rust
    pub(crate) fn insert(&mut self, txn: &mut MempoolTransaction) {
        // Orderless transactions are always in the "ready" state and are not stored in the parking lot.
        match txn.get_replay_protector() {
            ReplayProtector::SequenceNumber(sequence_number) => {
                if txn.insertion_info.park_time.is_none() {
                    txn.insertion_info.park_time = Some(SystemTime::now());
                }
                txn.was_parked = true;

                let sender = &txn.txn.sender();
                let hash = txn.get_committed_hash();
                let is_new_entry = match self.account_indices.get(sender) {
                    Some(index) => {
                        if let Some((_account, seq_nums)) = self.data.get_mut(*index) {
                            seq_nums.insert((sequence_number, hash))
                        } else {
                            counters::CORE_MEMPOOL_INVARIANT_VIOLATION_COUNT.inc();
                            error!(
                                LogSchema::new(LogEntry::InvariantViolated),
                                "Parking lot invariant violated: for account {}, account index exists but missing entry in data",
                                sender
                            );
                            return;
                        }
                    },
                    None => {
                        let entry = [(sequence_number, hash)]
                            .iter()
                            .cloned()
                            .collect::<BTreeSet<_>>();
                        self.data.push((*sender, entry));
                        self.account_indices.insert(*sender, self.data.len() - 1);
                        true
                    },
                };
                if is_new_entry {
                    self.size += 1;
                }
            },
            ReplayProtector::Nonce(_) => {},
        }
```

**File:** config/src/config/mempool_config.rs (L121-123)
```rust
            capacity: 2_000_000,
            capacity_bytes: 2 * 1024 * 1024 * 1024,
            capacity_per_user: 100,
```

**File:** config/src/config/mempool_config.rs (L171-171)
```rust
            orderless_txn_capacity_per_user: 1000,
```
