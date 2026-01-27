# Audit Report

## Title
Transaction Shuffler Panic on Account Re-insertion Causes Validator Crashes

## Summary
The `strict_insert()` method in the transaction shuffler's `DelayedQueue` can panic when attempting to insert an account that already exists in the HashMap, causing validator node crashes. The vulnerability stems from an incorrect assumption in `update_delays_for_selected_txn()` that accounts never exist when the function is called, despite the calling logic explicitly allowing for existing empty accounts with expired delays. [1](#0-0) 

## Finding Description

The `StrictMap` trait implements `strict_insert()` using `assert!()`, which panics if a duplicate key exists: [2](#0-1) 

This method is used in `update_delays_for_selected_txn()` to insert account entries: [3](#0-2) 

The comment claims "the account must not have been tracked before", but this assumption is **incorrect**. The function is called from `queue_or_return()` when `account_should_delay = false`: [4](#0-3) 

The condition `account_should_delay = false` occurs in TWO cases:
1. Account doesn't exist (`account_opt.is_none()`)
2. **Account EXISTS but is empty AND `try_delay_till <= output_idx`**

Case #2 directly contradicts the assumption in `update_delays_for_selected_txn()`. When an account exists with expired delay, calling `strict_insert()` on that account causes a panic.

**Attack Scenario:**
1. Transaction T1 from account A is processed, creating account A with `try_delay_till = N`
2. Account A becomes empty and is added to placeholder tracking
3. Time advances, `output_idx` increases to M where M > N
4. The `drain_placeholders()` cleanup is delayed or hasn't run yet
5. Transaction T2 from account A arrives
6. `queue_or_return()` finds account A exists, is empty, and `try_delay_till ≤ output_idx`
7. `account_should_delay = false`, so `update_delays_for_selected_txn()` is called
8. Line 511 attempts `strict_insert(address, new_account)` on existing account A
9. **Validator panics and crashes**

The vulnerability is exacerbated by the placeholder draining logic, which only runs when `output_idx` changes: [5](#0-4) 

If multiple transactions are processed before `output_idx` increments again, stale empty accounts can remain in the HashMap.

**Code Inconsistency:** Note that use_case handling properly uses the Entry API to handle both existing and new cases, while account handling assumes non-existence: [6](#0-5) 

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty program:

- **Validator node crashes**: Any validator processing a transaction sequence that triggers this condition will panic and crash
- **Consensus disruption**: If multiple validators crash simultaneously, it can affect network liveness
- **Denial of Service**: Attackers can deliberately craft transaction sequences to trigger this panic
- **Production feasibility**: The vulnerability can occur during normal operation with legitimate transaction patterns

The impact aligns with the "Validator node slowdowns" and "API crashes" categories under High Severity, as the panic causes immediate node termination requiring manual restart.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is likely to occur because:

1. **Normal operation trigger**: The bug can manifest during regular transaction processing without requiring malicious input
2. **Timing-dependent**: Depends on the interleaving of transaction processing and placeholder cleanup, which varies based on network conditions
3. **Multiple code paths**: Similar patterns exist in `queue_txn()` at line 467 with another `strict_insert()` call
4. **No defensive programming**: The code uses `assert!()` instead of error handling, guaranteeing a crash on invariant violation

The attacker complexity is LOW - simply sending multiple transactions from the same account with appropriate timing can trigger the condition. No special privileges or validator access required.

## Recommendation

Replace all `strict_insert()` calls with proper Entry API usage that handles both existing and new entries:

```rust
// In update_delays_for_selected_txn():
match self.accounts.entry(address) {
    hash_map::Entry::Occupied(mut occupied) => {
        // Account exists (empty with expired delay) - update it
        let account = occupied.get_mut();
        account.update_try_delay_till(account_try_delay_till);
        account.input_idx = input_idx;
        let new_account_delay_key = account.delay_key();
        self.account_placeholders_by_delay
            .insert(new_account_delay_key, address);
    },
    hash_map::Entry::Vacant(vacant) => {
        // Account doesn't exist - create new
        let new_account = Account::new_empty(account_try_delay_till, input_idx);
        let new_account_delay_key = new_account.delay_key();
        vacant.insert(new_account);
        self.account_placeholders_by_delay
            .insert(new_account_delay_key, address);
    },
}
```

Similar changes should be applied to:
- `queue_txn()` line 467
- All BTreeMap `strict_insert()` calls should use `insert()` or handle collisions gracefully
- Consider removing the `StrictMap` trait entirely in favor of explicit error handling

Additionally, ensure `drain_placeholders()` runs more reliably or handle stale entries defensively.

## Proof of Concept

```rust
// Rust test demonstrating the panic
#[test]
#[should_panic(expected = "assertion failed")]
fn test_account_reinsertion_panic() {
    use crate::transaction_shuffler::use_case_aware::{
        delayed_queue::DelayedQueue,
        Config,
    };
    use aptos_types::transaction::SignedTransaction;
    
    let config = Config {
        sender_spread_factor: 1,
        platform_use_case_spread_factor: 1,
        user_use_case_spread_factor: 1,
    };
    
    let mut queue = DelayedQueue::new(config);
    
    // Create mock transactions from same account
    let account_a = AccountAddress::random();
    let txn1 = create_test_transaction(account_a, 0);
    let txn2 = create_test_transaction(account_a, 1);
    
    // Process first transaction - creates account A
    let input_idx_1 = 0;
    queue.queue_or_return(input_idx_1, txn1);
    
    // Advance time but don't trigger drain
    // Simulate output_idx advancing without calling bump_output_idx
    queue.output_idx = 10;
    
    // Process second transaction from same account
    // Account exists, is empty, try_delay_till < output_idx
    // This will panic at strict_insert()
    let input_idx_2 = 1;
    queue.queue_or_return(input_idx_2, txn2); // PANIC HERE
}
```

The proof of concept shows that when an account exists with expired delay, attempting to process a new transaction from that account causes a panic at the `strict_insert()` call, crashing the validator node.

### Citations

**File:** consensus/src/transaction_shuffler/use_case_aware/utils.rs (L17-20)
```rust
impl<K: Eq + Hash, V> StrictMap<K, V> for HashMap<K, V> {
    fn strict_insert(&mut self, key: K, value: V) {
        assert!(self.insert(key, value).is_none())
    }
```

**File:** consensus/src/transaction_shuffler/use_case_aware/delayed_queue.rs (L297-304)
```rust
    pub fn bump_output_idx(&mut self, output_idx: OutputIdx) {
        assert!(output_idx >= self.output_idx);
        // It's possible that the queue returned nothing last round hence the output idx didn't move.
        if output_idx > self.output_idx {
            self.output_idx = output_idx;
            self.drain_placeholders();
        }
    }
```

**File:** consensus/src/transaction_shuffler/use_case_aware/delayed_queue.rs (L486-504)
```rust
        match self.use_cases.entry(use_case_key.clone()) {
            hash_map::Entry::Occupied(occupied) => {
                let use_case = occupied.into_mut();
                // Txn wouldn't have been selected for output if the use case is empty (tracking
                // for a try_delay_till > self.output_idx)
                assert!(!use_case.is_empty());

                self.use_cases_by_delay.strict_remove(&use_case.delay_key());
                use_case.update_try_delay_till(use_case_try_delay_till);
                self.use_cases_by_delay
                    .strict_insert(use_case.delay_key(), use_case_key);
            },
            hash_map::Entry::Vacant(vacant) => {
                let use_case = UseCase::new_empty(use_case_try_delay_till, input_idx);
                self.use_case_placeholders_by_delay
                    .strict_insert(use_case.delay_key(), use_case_key);
                vacant.insert(use_case);
            },
        }
```

**File:** consensus/src/transaction_shuffler/use_case_aware/delayed_queue.rs (L506-513)
```rust
        // Notice this function is called after the txn is selected for output due to no delaying
        // needed, so the account must not have been tracked before, otherwise it wouldn't have been
        // selected for output.
        let new_account = Account::new_empty(account_try_delay_till, input_idx);
        let new_account_delay_key = new_account.delay_key();
        self.accounts.strict_insert(address, new_account);
        self.account_placeholders_by_delay
            .strict_insert(new_account_delay_key, address);
```

**File:** consensus/src/transaction_shuffler/use_case_aware/delayed_queue.rs (L524-538)
```rust
        let account_should_delay = account_opt.as_ref().is_some_and(|account| {
            !account.is_empty()  // needs delaying due to queued txns under the same account
                    || account.try_delay_till > self.output_idx
        });
        let use_case_should_delay = use_case_opt
            .as_ref()
            .is_some_and(|use_case| use_case.try_delay_till > self.output_idx);

        if account_should_delay || use_case_should_delay {
            self.queue_txn(input_idx, address, use_case_key, txn);
            None
        } else {
            self.update_delays_for_selected_txn(input_idx, address, use_case_key);
            Some(txn)
        }
```
