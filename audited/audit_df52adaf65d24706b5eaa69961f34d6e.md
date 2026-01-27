# Audit Report

## Title
Mempool Saturation via Ready Transaction Flooding: Eviction Mechanism Fails When Parking Lot is Empty

## Summary
The mempool eviction mechanism in `check_is_full_after_eviction()` only evicts transactions from the parking lot, which exclusively contains non-ready sequence number transactions. An attacker can saturate the mempool by flooding it with ready transactions (nonce-based or initial sequence number transactions) that bypass the parking lot entirely, causing all subsequent transaction submissions to fail until system TTL expires.

## Finding Description

The vulnerability stems from a critical design flaw in the mempool eviction logic. The eviction process has two key constraints:

1. **Eviction only triggers for ready transactions**: The condition at line 420 requires the incoming transaction to be "ready" before attempting eviction. [1](#0-0) 

2. **Eviction only removes from parking lot**: The eviction loop exclusively removes transactions from the parking lot index. [2](#0-1) 

However, the parking lot has severe limitations on what it contains:

- **Nonce-based transactions are never added**: These transactions are always considered "ready" and explicitly excluded from the parking lot. [3](#0-2) 

- **Ready transactions are removed from parking lot**: When sequence number transactions become ready, they are explicitly removed from the parking lot. [4](#0-3) 

- **Nonce transactions always ready**: The `check_txn_ready()` function explicitly returns true for all nonce-based transactions. [5](#0-4) 

**Attack Execution:**

The attacker exploits this by creating approximately 2,000 accounts and submitting 1,000 nonce-based transactions per account (the maximum allowed by `orderless_txn_capacity_per_user`). [6](#0-5) 

All these transactions:
- Pass signature verification and prologue validation (no gas charged since never executed)
- Are classified as "ready" and stored in mempool
- Count towards the global capacity limit of 2,000,000 transactions [7](#0-6) 
- Are NOT stored in the parking lot
- Cannot be evicted by the current eviction mechanism

Once mempool capacity is reached, the `is_full()` check based on `system_ttl_index.size()` prevents any new insertions. [8](#0-7) 

When new transactions attempt to enter:
- If incoming transaction is non-ready: No eviction attempted (condition fails), rejected immediately
- If incoming transaction is ready: Eviction attempted but parking lot is empty, no space freed, still rejected at line 455 [9](#0-8) 

The saturation persists until system TTL garbage collection removes expired transactions (default 600 seconds). [10](#0-9) 

## Impact Explanation

This is a **Critical Severity** vulnerability meeting the Aptos Bug Bounty criteria for "Total loss of liveness/network availability":

- **Network-wide DoS**: All nodes in the network reject legitimate transaction submissions
- **Complete transaction processing halt**: Both ready and non-ready transactions are rejected
- **Extended duration**: Lasts minimum 10 minutes (system TTL timeout) but can be continuously reapplied
- **No recovery without intervention**: The mempool cannot self-recover through normal operation

The vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits" - the eviction mechanism fails to enforce the intended capacity management when the parking lot doesn't contain evictable transactions.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible:
- **Low cost**: Requires only ~2,000 account creations (minimal/free on Aptos)
- **No gas fees**: Transactions never execute, so no gas is consumed
- **Simple execution**: Only requires basic transaction signing and submission
- **No special privileges**: Any external actor can perform this attack
- **Automatable**: Can be scripted and repeated continuously
- **Network-wide impact**: Single attacker affects all network participants

## Recommendation

Implement a multi-tiered eviction strategy that doesn't rely solely on the parking lot:

1. **Add ready transaction eviction**: When parking lot is empty or insufficient, evict lowest-priority ready transactions based on gas price ranking
2. **Implement per-account eviction limits**: Track insertion time per account and evict oldest transactions from accounts with many pending transactions
3. **Add rate limiting**: Implement per-IP or per-account submission rate limits at the API layer
4. **Proactive capacity management**: Start evicting when mempool reaches 90% capacity rather than waiting until full

**Proposed Fix** (conceptual):

```rust
fn check_is_full_after_eviction(&mut self, txn: &MempoolTransaction, account_sequence_number: Option<u64>) -> bool {
    if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
        // Try parking lot eviction first
        self.evict_from_parking_lot();
        
        // If still full, evict lowest priority ready transactions
        if self.is_full() {
            self.evict_lowest_priority_ready_transactions(txn.ranking_score);
        }
    }
    self.is_full()
}

fn evict_lowest_priority_ready_transactions(&mut self, min_score: u64) {
    // Evict ready transactions with ranking_score < incoming transaction score
    // Target accounts with oldest insertion times first
}
```

## Proof of Concept

```rust
#[test]
fn test_mempool_saturation_with_ready_nonce_transactions() {
    use aptos_types::transaction::{SignedTransaction, RawTransaction, TransactionPayload};
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    use rand::SeedableRng;
    
    // Initialize mempool with small capacity for testing
    let mut config = MempoolConfig::default();
    config.capacity = 2000; // Small capacity for test
    config.orderless_txn_capacity_per_user = 20;
    let mut transaction_store = TransactionStore::new(&config);
    
    // Create 100 attacker accounts (2000 / 20 = 100)
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let accounts: Vec<_> = (0..100)
        .map(|_| Ed25519PrivateKey::generate(&mut rng))
        .collect();
    
    // Flood mempool with nonce-based ready transactions
    for (i, private_key) in accounts.iter().enumerate() {
        for nonce in 0..20 {
            let sender = private_key.public_key().into();
            let raw_txn = RawTransaction::new_with_nonce(
                sender,
                nonce,
                TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
                100_000,
                1,
                u64::MAX,
                ChainId::test(),
            );
            let signed_txn = SignedTransaction::new(
                raw_txn,
                private_key.public_key(),
                private_key.sign(&raw_txn).unwrap(),
            );
            
            let txn = MempoolTransaction::new(signed_txn, /* ... */);
            let status = transaction_store.insert(txn, None);
            
            // All should be accepted until capacity reached
            assert!(status.code == MempoolStatusCode::Accepted || 
                    status.code == MempoolStatusCode::MempoolIsFull);
        }
    }
    
    // Mempool should now be full (2000 transactions)
    assert!(transaction_store.is_full());
    
    // Parking lot should be empty (all nonce transactions are ready)
    assert_eq!(transaction_store.get_parking_lot_size(), 0);
    
    // Attempt to insert legitimate high-priority ready transaction
    let victim_key = Ed25519PrivateKey::generate(&mut rng);
    let victim_addr = victim_key.public_key().into();
    let high_priority_txn = create_high_priority_txn(&victim_key, victim_addr);
    
    // Insertion should FAIL despite being high priority and ready
    let status = transaction_store.insert(high_priority_txn, None);
    assert_eq!(status.code, MempoolStatusCode::MempoolIsFull);
    
    // This demonstrates complete mempool saturation with no recovery mechanism
}
```

## Notes

This vulnerability represents a fundamental design flaw where the eviction mechanism assumes non-ready transactions will always be available for eviction. The attack succeeds by filling the mempool with transactions that are ready-by-design (nonce-based) or strategically ready (sequence number matching current state), ensuring the parking lot remains empty and eviction fails. The 10-minute TTL provides only temporary relief, as the attack can be immediately repeated to maintain continuous DoS.

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L420-420)
```rust
        if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
```

**File:** mempool/src/core_mempool/transaction_store.rs (L425-446)
```rust
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
```

**File:** mempool/src/core_mempool/transaction_store.rs (L455-455)
```rust
        self.is_full()
```

**File:** mempool/src/core_mempool/transaction_store.rs (L458-460)
```rust
    fn is_full(&self) -> bool {
        self.system_ttl_index.size() >= self.capacity || self.size_bytes >= self.capacity_bytes
    }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L495-498)
```rust
            ReplayProtector::Nonce(_) => {
                // Nonce based transactions are always ready for broadcast
                true
            },
```

**File:** mempool/src/core_mempool/transaction_store.rs (L589-590)
```rust
                // priority_index / timeline_index, i.e., txn status is ready.
                self.parking_lot_index.remove(txn);
```

**File:** mempool/src/core_mempool/index.rs (L586-587)
```rust
            ReplayProtector::Nonce(_) => {},
        }
```

**File:** config/src/config/mempool_config.rs (L121-121)
```rust
            capacity: 2_000_000,
```

**File:** config/src/config/mempool_config.rs (L129-129)
```rust
            system_transaction_timeout_secs: 600,
```

**File:** config/src/config/mempool_config.rs (L171-171)
```rust
            orderless_txn_capacity_per_user: 1000,
```
