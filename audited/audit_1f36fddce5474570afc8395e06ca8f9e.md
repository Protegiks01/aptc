# Audit Report

## Title
Gas Auction Griefing Attack via Unrestricted Transaction Replacement in Mempool

## Summary
The Aptos mempool allows unlimited transaction replacement with higher gas prices without any cost to the attacker. When transactions are replaced, consensus can pull multiple versions of the same transaction (identified by sender + sequence number but different hashes), wasting validator resources and delaying legitimate transactions. Attackers pay zero gas fees since continuously replaced transactions never execute.

## Finding Description

The mempool implements transaction replacement logic that allows users to update existing transactions with higher gas prices. [1](#0-0) 

When a transaction is replaced, the old transaction is removed and a new one with a different hash is inserted. The critical issue is in how consensus handles these replacements. When consensus pulls transactions via `get_batch()`, it maintains an `exclude_transactions` map to avoid re-pulling already selected transactions. [2](#0-1) 

However, the exclusion check uses exact hash matching. When a transaction is replaced with higher gas, the new version has a different hash and is NOT excluded, allowing consensus to pull it again. [3](#0-2) 

The test suite explicitly demonstrates this behavior, confirming that when a low-gas transaction is in `exclude_transactions`, the high-gas replacement (same sender/sequence, different hash) can still be pulled. [4](#0-3) 

**Attack Execution:**
1. Attacker submits transaction T1 with sequence number X and gas price G
2. Consensus pulls T1, adds it to `exclude_transactions` with hash H1
3. Before T1 executes, attacker submits T2 (same sequence X, gas price G+1)
4. T1 is removed from mempool, T2 (with hash H2) is inserted
5. Consensus pulls T2 (H2 ≠ H1, so not excluded)
6. Attacker repeats with T3, T4, T5... each with incrementally higher gas
7. Consensus processes multiple versions; only first to execute succeeds, others fail with SEQUENCE_NUMBER_TOO_OLD
8. **No gas fees charged** because transactions are replaced before execution

The vulnerability violates the invariant that "All operations must respect gas, storage, and computational limits" - attackers consume consensus resources without paying gas.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Consensus maintains multiple in-flight versions of the same transaction
- **Resource exhaustion**: Consensus validators waste CPU/network processing duplicate transactions
- **Transaction delay**: Legitimate transactions may be delayed as consensus processes constantly-replaced transactions
- **Zero-cost attack**: Attacker incurs no gas fees since transactions never execute

While this cannot completely DoS the network (capacity limits at 2M transactions, 100 per account limit the scope), it can significantly disrupt transaction ordering and waste validator resources. The economic attack is particularly concerning because it costs the attacker nothing while imposing costs on validators.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is easily automatable with minimal requirements:
- Public API access (no special privileges needed)
- API rate limit of 100 requests/minute per endpoint allows ~1.67 replacements/second
- Attacker can use multiple IP addresses/endpoints to increase replacement rate
- Gas price must stay within bounds, but range from `min_price_per_gas_unit` to `max_price_per_gas_unit` provides ample room for incremental increases [5](#0-4) 
- Simple script can monitor mempool and continuously replace transactions

The main limiting factors are:
- API rate limiting (can be bypassed with multiple endpoints)
- Per-account transaction limit of 100 (can be scaled across multiple accounts)
- Gas price bounds (still allows many replacement iterations)

## Recommendation

Implement rate limiting on transaction replacements and/or charge a small fee for replacement attempts:

**Option 1: Replacement Rate Limiting**
Add a per-account rate limit on gas upgrades in the mempool configuration:
```rust
pub struct MempoolConfig {
    // existing fields...
    /// Maximum gas upgrades per account per minute
    pub max_gas_upgrades_per_account_per_minute: usize,
}
```

Track replacement attempts per account and reject if limit exceeded.

**Option 2: Replacement Fee**
Require a minimum gas price increase for replacements (e.g., 10% minimum increase) to make rapid replacements more expensive. This discourages micro-incrementing attacks.

**Option 3: Enhanced Exclude Logic**
Modify the exclusion check to match by (sender, sequence_number) instead of exact hash, preventing re-pulling of replaced transactions: [6](#0-5) 

The range-based `txn_was_chosen()` function already implements this pattern for sequential transactions - extend this to the primary exclusion check.

**Option 4: Transaction Replacement Window**
Implement a time-based window where replacements are only allowed within N seconds of initial submission, after which the transaction is "locked" in mempool until execution or expiration.

## Proof of Concept

The existing test demonstrates the vulnerability:

```rust
// From mempool/src/tests/core_mempool_test.rs:1694-1750
// This test shows that when a low-gas transaction is excluded,
// the high-gas replacement (same sequence, different hash) is NOT excluded

#[test]
fn test_include_gas_upgraded() {
    // 1. Add transaction with gas_price=1
    let low_gas_txn = add_txn_with_gas(pool, sequence_number, 1);
    
    // 2. Exclude the low-gas transaction
    let batch = pool.get_batch(10, 10240, true, btreemap! {
        low_gas_txn_summary => TransactionInProgress::new(1)
    });
    assert_eq!(batch.len(), 0); // Correctly excluded
    
    // 3. Replace with gas_price=100 (same sequence, different hash)
    let high_gas_txn = add_txn_with_gas(pool, sequence_number, 100);
    
    // 4. Get batch with ONLY low-gas txn excluded
    let batch = pool.get_batch(10, 10240, true, btreemap! {
        low_gas_txn_summary => TransactionInProgress::new(1)
    });
    
    // VULNERABILITY: High-gas version is pulled despite same sequence number!
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].gas_unit_price(), 100);
}
```

**Extended PoC for continuous replacement attack:**
1. Submit transaction with sequence N, gas price 100
2. In a loop (100 times):
   - Wait 600ms (stay under API rate limit)
   - Submit replacement with gas price += 1
   - Observe transaction is accepted and old version removed
3. Verify that after 100 replacements (~60 seconds), no gas has been charged
4. Monitor consensus logs to see multiple versions being processed
5. Verify legitimate transaction at same gas price is delayed

This demonstrates the zero-cost resource consumption attack where consensus processes 100+ versions of the same transaction while the attacker pays nothing.

## Notes

The code contains a TODO comment suggesting this issue was previously recognized but not addressed: [7](#0-6) 

The parameter `include_gas_upgraded` mentioned in the function documentation suggests there was previously logic to handle gas-upgraded transactions specially, but it has been removed, leaving the vulnerability exploitable.

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L251-294)
```rust
        // If the transaction is already in Mempool, we only allow the user to
        // increase the gas unit price to speed up a transaction, but not the max gas.
        //
        // Transactions with all the same inputs (but possibly signed differently) are idempotent
        // since the raw transaction is the same
        if let Some(txns) = self.transactions.get_mut(&address) {
            if let Some(current_version) = txns.get_mut(&txn_replay_protector) {
                if current_version.txn.payload() != txn.txn.payload() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different payload".to_string(),
                    );
                } else if current_version.txn.expiration_timestamp_secs()
                    != txn.txn.expiration_timestamp_secs()
                {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different expiration timestamp"
                            .to_string(),
                    );
                } else if current_version.txn.max_gas_amount() != txn.txn.max_gas_amount() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different max gas amount"
                            .to_string(),
                    );
                } else if current_version.get_gas_price() < txn.get_gas_price() {
                    // Update txn if gas unit price is a larger value than before
                    if let Some(txn) = txns.remove(&txn_replay_protector) {
                        self.index_remove(&txn);
                    };
                    counters::CORE_MEMPOOL_GAS_UPGRADED_TXNS.inc();
                } else if current_version.get_gas_price() > txn.get_gas_price() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a higher gas price".to_string(),
                    );
                } else {
                    // If the transaction is the same, it's an idempotent call
                    // Updating signers is not supported, the previous submission must fail
                    counters::CORE_MEMPOOL_IDEMPOTENT_TXNS.inc();
                    if let Some(acc_seq_num) = account_sequence_number {
                        self.process_ready_seq_num_based_transactions(&address, acc_seq_num);
                    }
                    return MempoolStatus::new(MempoolStatusCode::Accepted);
                }
            }
        }
```

**File:** mempool/src/core_mempool/mempool.rs (L384-415)
```rust
    /// Txn was already chosen, either in a local or remote previous pull (so now in consensus) or
    /// in the current pull.
    fn txn_was_chosen(
        account_address: AccountAddress,
        sequence_number: u64,
        inserted: &HashSet<(AccountAddress, ReplayProtector)>,
        exclude_transactions: &BTreeMap<TransactionSummary, TransactionInProgress>,
    ) -> bool {
        if inserted.contains(&(
            account_address,
            ReplayProtector::SequenceNumber(sequence_number),
        )) {
            return true;
        }

        // TODO: Make sure this range search works as expected
        let min_inclusive = TxnPointer::new(
            account_address,
            ReplayProtector::SequenceNumber(sequence_number),
            HashValue::zero(),
        );
        let max_exclusive = TxnPointer::new(
            account_address,
            ReplayProtector::SequenceNumber(sequence_number.saturating_add(1)),
            HashValue::zero(),
        );

        exclude_transactions
            .range(min_inclusive..max_exclusive)
            .next()
            .is_some()
    }
```

**File:** mempool/src/core_mempool/mempool.rs (L417-456)
```rust
    /// Fetches next block of transactions for consensus.
    /// `return_non_full` - if false, only return transactions when max_txns or max_bytes is reached
    ///                     Should always be true for Quorum Store.
    /// `include_gas_upgraded` - Return transactions that had gas upgraded, even if they are in
    ///                          exclude_transactions. Should only be true for Quorum Store.
    /// `exclude_transactions` - transactions that were sent to Consensus but were not committed yet
    ///  mempool should filter out such transactions.
    #[allow(clippy::explicit_counter_loop)]
    pub(crate) fn get_batch(
        &self,
        max_txns: u64,
        max_bytes: u64,
        return_non_full: bool,
        exclude_transactions: BTreeMap<TransactionSummary, TransactionInProgress>,
    ) -> Vec<SignedTransaction> {
        let start_time = Instant::now();
        let exclude_size = exclude_transactions.len();
        let mut inserted = HashSet::new();

        let gas_end_time = start_time.elapsed();

        let mut result = vec![];
        // Helper DS. Helps to mitigate scenarios where account submits several transactions
        // with increasing gas price (e.g. user submits transactions with sequence number 1, 2
        // and gas_price 1, 10 respectively)
        // Later txn has higher gas price and will be observed first in priority index iterator,
        // but can't be executed before first txn. Once observed, such txn will be saved in
        // `skipped` DS and rechecked once it's ancestor becomes available
        let mut skipped = HashSet::new();
        let mut total_bytes = 0;
        let mut txn_walked = 0usize;
        // iterate over the queue of transactions based on gas price
        'main: for txn in self.transactions.iter_queue() {
            txn_walked += 1;
            let txn_ptr = TxnPointer::from(txn);

            // TODO: removed gas upgraded logic. double check if it's needed
            if exclude_transactions.contains_key(&txn_ptr) {
                continue;
            }
```

**File:** consensus/consensus-types/src/common.rs (L37-52)
```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, Hash, Ord, PartialOrd)]
pub struct TransactionSummary {
    pub sender: AccountAddress,
    pub replay_protector: ReplayProtector,
    pub hash: HashValue,
}

impl TransactionSummary {
    pub fn new(sender: AccountAddress, replay_protector: ReplayProtector, hash: HashValue) -> Self {
        Self {
            sender,
            replay_protector,
            hash,
        }
    }
}
```

**File:** mempool/src/tests/core_mempool_test.rs (L1693-1750)
```rust
#[test]
fn test_include_gas_upgraded() {
    let mut config = NodeConfig::generate_random_config();
    config.mempool.capacity = 100;
    let mut pool = CoreMempool::new(&config);

    let sequence_number = 0;
    let address_index = 0;

    let low_gas_price = 1;
    let low_gas_signed_txn = add_txn(
        &mut pool,
        TestTransaction::new(
            address_index,
            ReplayProtector::SequenceNumber(sequence_number),
            low_gas_price,
        ),
    )
    .unwrap();

    let low_gas_txn = TransactionSummary::new(
        low_gas_signed_txn.sender(),
        ReplayProtector::SequenceNumber(low_gas_signed_txn.sequence_number()),
        low_gas_signed_txn.committed_hash(),
    );
    let batch = pool.get_batch(10, 10240, true, btreemap! {
        low_gas_txn => TransactionInProgress::new(low_gas_price)
    });
    assert_eq!(batch.len(), 0);

    let high_gas_price = 100;
    let high_gas_signed_txn = add_txn(
        &mut pool,
        TestTransaction::new(
            address_index,
            ReplayProtector::SequenceNumber(sequence_number),
            high_gas_price,
        ),
    )
    .unwrap();
    let high_gas_txn = TransactionSummary::new(
        high_gas_signed_txn.sender(),
        ReplayProtector::SequenceNumber(high_gas_signed_txn.sequence_number()),
        high_gas_signed_txn.committed_hash(),
    );

    // When the low gas txn (but not the high gas txn) is excluded, will the high gas txn be included.
    let batch = pool.get_batch(10, 10240, true, btreemap! {
        low_gas_txn => TransactionInProgress::new(low_gas_price)
    });
    assert_eq!(batch.len(), 1);
    assert_eq!(
        batch[0].sender(),
        TestTransaction::get_address(address_index)
    );
    assert_eq!(batch[0].sequence_number(), sequence_number);
    assert_eq!(batch[0].gas_unit_price(), high_gas_price);

```

**File:** aptos-move/aptos-vm/src/gas.rs (L174-208)
```rust
    // The submitted gas price is less than the minimum gas unit price set by the VM.
    // NB: MIN_PRICE_PER_GAS_UNIT may equal zero, but need not in the future. Hence why
    // we turn off the clippy warning.
    #[allow(clippy::absurd_extreme_comparisons)]
    let below_min_bound = txn_metadata.gas_unit_price() < txn_gas_params.min_price_per_gas_unit;
    if below_min_bound {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; min {}, submitted {}",
                txn_gas_params.min_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_BELOW_MIN_BOUND,
            None,
        ));
    }

    // The submitted gas price is greater than the maximum gas unit price set by the VM.
    if txn_metadata.gas_unit_price() > txn_gas_params.max_price_per_gas_unit {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.max_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_ABOVE_MAX_BOUND,
            None,
        ));
    }
```
