# Audit Report

## Title
Parking Lot Eviction Bypass Enables Denial-of-Service via Unnecessary Broadcast Backoff

## Summary
An attacker can fill a node's mempool parking lot with future-sequence transactions, causing legitimate broadcast messages containing non-ready transactions to trigger unnecessary 30-second backoff delays without attempting parking lot eviction. This exploits a design flaw in the eviction logic that only evicts when incoming transactions are ready for broadcast.

## Finding Description

This vulnerability exploits a conditional eviction logic in the mempool's `TransactionStore` that breaks the security guarantee of graceful mempool management under state divergence conditions.

**Root Cause:**

The `check_is_full_after_eviction()` method only attempts to evict parking lot transactions when **both** conditions are met: (1) mempool is full, and (2) the incoming transaction is ready for broadcast. [1](#0-0) 

A transaction is considered "ready" only if its sequence number exactly matches the account's current sequence number in the node's state view. [2](#0-1) 

**Critical Design Behavior:**

The Aptos VM explicitly treats `SEQUENCE_NUMBER_TOO_NEW` errors as validation success, allowing future-sequence transactions to pass VM validation and enter the mempool parking lot. [3](#0-2) 

**Attack Execution Path:**

1. **Parking Lot Saturation:** Attacker submits up to 100 future-sequence transactions per account [4](#0-3)  across multiple accounts, filling the mempool to its capacity limits of 2M transactions and 2GB. [5](#0-4) 

2. **State Divergence Exploitation:** Due to natural blockchain state synchronization delays between nodes, Node A (ahead in block height) broadcasts transactions that are ready on its state view but NOT ready on the victim node's state view.

3. **Eviction Bypass:** When the victim receives these non-ready broadcast transactions, `check_txn_ready()` returns false, causing the eviction loop to never execute despite the parking lot being full of evictable attacker transactions. The method returns `MempoolIsFull`.

4. **Backoff Trigger:** The `gen_ack_response()` function detects any transaction with `MempoolStatusCode::MempoolIsFull` and sets `backoff_and_retry = true`. [6](#0-5) 

5. **Broadcast Delay:** The ACK response includes the backoff flag, causing the broadcaster to wait 30 seconds [7](#0-6)  instead of the normal 10 milliseconds [8](#0-7)  between subsequent broadcasts. [9](#0-8) 

The vulnerability exists because the eviction logic fails to distinguish between "mempool full of useful transactions" versus "mempool full of parking lot junk that should be evicted."

## Impact Explanation

**Severity: High** - This qualifies as "Validator node slowdowns" per the Aptos bug bounty program.

**Network-Wide Impact:**
- Transaction propagation delays increase from 10ms to 30 seconds (3000x slowdown) across affected peer connections
- Reduced mempool synchronization efficiency network-wide, as nodes cannot effectively share their transaction pools
- Potential for consensus liveness degradation if sufficient validators are simultaneously targeted
- User-facing delays in transaction confirmation times as transactions take longer to propagate to block proposers

**Attack Persistence:**
Attacker transactions expire after 600 seconds, [10](#0-9)  requiring continuous resubmission to maintain the attack, but this is economically feasible for motivated attackers targeting high-value nodes.

## Likelihood Explanation

**Likelihood: Medium-High**

**Favorable Factors:**
- State divergence between nodes at different block heights is a normal occurrence in distributed blockchain networks
- Nodes continuously broadcast transactions from their mempool, creating constant opportunities to trigger the backoff condition
- Attack can selectively target high-value infrastructure (VFNs, major RPC providers)
- Per-account transaction limits can be circumvented by creating multiple accounts

**Required Resources:**
- With default capacity limits, attacker needs 313-20,000 accounts depending on transaction sizes
- Each account can hold up to 100 pending transactions
- Requires ongoing maintenance as transactions expire every 10 minutes
- Economic cost includes account creation and gas fees, but remains feasible for targeted attacks on critical infrastructure

**Exploitation Complexity:**
- Attack leverages normal protocol operations (transaction submission)
- Does not require special privileges or network positioning
- Exploits inherent state synchronization delays in distributed systems

## Recommendation

Modify the eviction logic to attempt parking lot eviction whenever the mempool is full, regardless of whether the incoming transaction is ready:

```rust
fn check_is_full_after_eviction(
    &mut self,
    txn: &MempoolTransaction,
    account_sequence_number: Option<u64>,
) -> bool {
    if self.is_full() {
        let now = Instant::now();
        // Evict from parking lot regardless of incoming transaction readiness
        let mut evicted_txns = 0;
        let mut evicted_bytes = 0;
        while let Some(txn_pointer) = self.parking_lot_index.get_poppable() {
            // ... existing eviction logic ...
            if !self.is_full() {
                break;
            }
        }
        // ... existing metrics tracking ...
    }
    self.is_full()
}
```

This ensures that when mempool capacity is exhausted, parking lot transactions are always candidates for eviction, preventing attackers from using future-sequence transactions to bypass eviction and trigger unnecessary backoff.

## Proof of Concept

The existing test `test_parking_lot_evict_only_for_ready_txn_insertion` explicitly validates this behavior, confirming that non-ready transactions are rejected when mempool is full without attempting eviction. [11](#0-10) 

To reproduce:
1. Configure a node with reduced mempool capacity (e.g., `capacity: 10`)
2. Fill the parking lot with future-sequence transactions (seq_num >> account_seq_num)
3. Attempt to broadcast a transaction that is not ready on the receiver's state view
4. Observe that `MempoolIsFull` is returned without eviction attempt
5. Verify that the broadcaster receives backoff signal and delays subsequent broadcasts by 30 seconds

**Notes:**
- This is a protocol-level logic vulnerability, not a traditional network DoS attack
- The behavior is by design but creates an exploitable condition when combined with the backoff mechanism
- The vulnerability affects validator node performance (HIGH severity per Aptos bug bounty guidelines)
- Mitigation requires modifying the eviction policy to be state-independent

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L420-420)
```rust
        if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
```

**File:** mempool/src/core_mempool/transaction_store.rs (L477-478)
```rust
                if tx_sequence_number == account_sequence_number {
                    return true;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3292-3299)
```rust
            Err(err) if err.status_code() != StatusCode::SEQUENCE_NUMBER_TOO_NEW => (
                "failure",
                VMValidatorResult::new(Some(err.status_code()), 0),
            ),
            _ => (
                "success",
                VMValidatorResult::new(None, txn.gas_unit_price()),
            ),
```

**File:** config/src/config/mempool_config.rs (L111-111)
```rust
            shared_mempool_tick_interval_ms: 10,
```

**File:** config/src/config/mempool_config.rs (L112-112)
```rust
            shared_mempool_backoff_interval_ms: 30_000,
```

**File:** config/src/config/mempool_config.rs (L121-122)
```rust
            capacity: 2_000_000,
            capacity_bytes: 2 * 1024 * 1024 * 1024,
```

**File:** config/src/config/mempool_config.rs (L123-123)
```rust
            capacity_per_user: 100,
```

**File:** config/src/config/mempool_config.rs (L129-129)
```rust
            system_transaction_timeout_secs: 600,
```

**File:** mempool/src/shared_mempool/tasks.rs (L110-114)
```rust
    let interval_ms = if schedule_backoff {
        smp.config.shared_mempool_backoff_interval_ms
    } else {
        smp.config.shared_mempool_tick_interval_ms
    };
```

**File:** mempool/src/shared_mempool/tasks.rs (L261-263)
```rust
        if mempool_status.code == MempoolStatusCode::MempoolIsFull {
            backoff_and_retry = true;
            break;
```

**File:** mempool/src/tests/core_mempool_test.rs (L1287-1328)
```rust
fn test_parking_lot_evict_only_for_ready_txn_insertion() {
    let mut config = NodeConfig::generate_random_config();
    config.mempool.capacity = 6;
    let mut pool = CoreMempool::new(&config);
    // Add transactions with the following sequence numbers to Mempool.
    for seq in &[0, 1, 2, 9, 10, 11] {
        add_txn(
            &mut pool,
            TestTransaction::new(1, ReplayProtector::SequenceNumber(*seq), 1),
        )
        .unwrap();
    }

    // Try inserting for ready txs.
    let ready_seq_nums = vec![3, 4];
    for seq in ready_seq_nums {
        add_txn(
            &mut pool,
            TestTransaction::new(1, ReplayProtector::SequenceNumber(seq), 1),
        )
        .unwrap();
    }

    // Make sure that we have correct txns in Mempool.
    let mut txns: Vec<_> = pool
        .get_batch(5, 5120, true, btreemap![])
        .iter()
        .map(SignedTransaction::sequence_number)
        .collect();
    txns.sort_unstable();
    assert_eq!(txns, vec![0, 1, 2, 3, 4]);

    // Trying to insert a tx that would not be ready after inserting should fail.
    let not_ready_seq_nums = vec![6, 8, 12, 14];
    for seq in not_ready_seq_nums {
        assert!(add_txn(
            &mut pool,
            TestTransaction::new(1, ReplayProtector::SequenceNumber(seq), 1)
        )
        .is_err());
    }
}
```
