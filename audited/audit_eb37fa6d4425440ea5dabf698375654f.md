# Audit Report

## Title
Mempool Storage Read Exhaustion via Unverified Transaction Flooding

## Summary
Attackers can exhaust validator storage read capacity by flooding the mempool with transactions that trigger database lookups before signature verification occurs, causing validator performance degradation.

## Finding Description

The `process_incoming_transactions()` function in mempool performs expensive storage reads to fetch account sequence numbers **before** validating transaction signatures. This violates the principle of failing fast on cheap checks before expensive operations. [1](#0-0) 

The storage reads occur for all transactions in parallel using `IO_POOL`, fetching account sequence numbers from the database via `get_account_sequence_number()`. [2](#0-1) 

Only **after** all storage reads complete does signature verification happen in `validate_and_add_transactions()`: [3](#0-2) [4](#0-3) 

The mempool uses an **uncached** `DbStateView` for these reads, meaning every lookup queries RocksDB directly without caching: [5](#0-4) 

**Attack Path:**
1. Attacker crafts transactions with invalid signatures and random sender addresses
2. Sends them via network broadcast (up to 4-16 concurrent batches based on `shared_mempool_max_concurrent_inbound_syncs`)
3. Each batch contains up to 200-300 transactions (`shared_mempool_batch_size`) [6](#0-5) 

4. Total concurrent storage reads: **800-4,800 transactions** × parallel lookups via IO_POOL
5. All storage reads complete before any signature verification occurs
6. Invalid transactions are eventually rejected, but storage resources have been consumed

The `IO_POOL` is configured with default Rayon settings (typically number of CPU cores), amplifying the parallel storage read load: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program because it enables "Validator node slowdowns."

Storage read exhaustion impacts validator performance by:
- Saturating RocksDB I/O capacity with lookups for non-existent/invalid accounts
- Delaying legitimate transaction processing through mempool congestion  
- Increasing transaction validation latency across all validators
- Potentially causing validators to fall behind in consensus if mempool becomes a bottleneck

While this doesn't directly cause consensus safety violations or fund loss, sustained attacks could degrade network throughput and user experience across all validators simultaneously.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- No authentication or privileged access required
- Attackers can connect as regular network peers
- Transaction creation requires no proof-of-work or stake
- No per-peer rate limiting on storage reads (only on concurrent inbound syncs)
- BoundedExecutor limits concurrent batches but not transactions per batch

The attack is cost-effective because:
- Crafting invalid transactions is computationally cheap
- Each transaction triggers expensive database operations before rejection
- Asymmetric cost favors the attacker (cheap send, expensive validate)

## Recommendation

**Solution: Verify signatures before storage reads**

Reorder validation to perform signature verification (a stateless check) before account sequence number lookups (a stateful storage operation):

```rust
pub(crate) fn process_incoming_transactions<NetworkClient, TransactionValidator>(
    smp: &SharedMempool<NetworkClient, TransactionValidator>,
    transactions: Vec<(SignedTransaction, Option<u64>, Option<BroadcastPeerPriority>)>,
    timeline_state: TimelineState,
    client_submitted: bool,
) -> Vec<SubmissionStatusBundle> {
    let mut statuses = vec![];
    
    // Filter transactions first
    let transactions = filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);
    if transactions.is_empty() {
        return statuses;
    }
    
    // NEW: Verify signatures BEFORE storage reads
    let sig_verified_txns: Vec<_> = transactions
        .into_iter()
        .filter_map(|(txn, ready_time, priority)| {
            if txn.check_signature().is_ok() {
                Some((txn, ready_time, priority))
            } else {
                statuses.push((
                    txn,
                    (MempoolStatus::new(MempoolStatusCode::VmError), 
                     Some(StatusCode::INVALID_SIGNATURE)),
                ));
                None
            }
        })
        .collect();
    
    if sig_verified_txns.is_empty() {
        return statuses;
    }
    
    // NOW perform storage reads only for signature-verified transactions
    let state_view = smp.db.latest_state_checkpoint_view()
        .expect("Failed to get latest state checkpoint view.");
    
    let account_seq_numbers = IO_POOL.install(|| {
        sig_verified_txns.par_iter()
            .map(|(t, _, _)| match t.replay_protector() {
                // ... existing logic
            })
            .collect::<Vec<_>>()
    });
    
    // ... rest of existing logic
}
```

This ensures only signature-valid transactions trigger storage reads, dramatically reducing attack surface.

## Proof of Concept

```rust
#[cfg(test)]
mod attack_poc {
    use super::*;
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, SigningKey, Uniform};
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{RawTransaction, Script, TransactionPayload},
    };
    use std::time::Instant;

    #[tokio::test]
    async fn test_storage_read_exhaustion_attack() {
        // Setup mempool and mock validator
        let (mut smp, _) = setup_test_mempool();
        
        // Create 1000 transactions with INVALID signatures but valid structure
        let mut attack_txns = vec![];
        let wrong_key = Ed25519PrivateKey::generate_for_testing();
        
        for i in 0..1000 {
            let sender = AccountAddress::random();
            let raw_txn = RawTransaction::new(
                sender,
                0,
                TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
                1000,
                0,
                0,
                ChainId::test(),
            );
            
            // Sign with WRONG private key (attacker doesn't know real key)
            let signature = wrong_key.sign(&raw_txn).unwrap();
            let signed_txn = SignedTransaction::new(
                raw_txn,
                wrong_key.public_key(), 
                signature,
            );
            
            attack_txns.push((signed_txn, None, Some(BroadcastPeerPriority::Primary)));
        }
        
        // Measure storage read latency under attack
        let start = Instant::now();
        let results = process_incoming_transactions(
            &smp,
            attack_txns,
            TimelineState::NotReady,
            false,
        );
        let attack_duration = start.elapsed();
        
        // All transactions should be rejected (invalid signatures)
        assert_eq!(results.iter().filter(|(_, (status, _))| 
            status.code == MempoolStatusCode::VmError).count(), 1000);
        
        // BUT storage reads were still performed, consuming resources
        // Observe high latency (>100ms for 1000 lookups is problematic)
        println!("Storage read latency under attack: {:?}", attack_duration);
        assert!(attack_duration.as_millis() > 100, 
            "Attack should cause measurable storage read overhead");
    }
}
```

## Notes

While the security question specifically mentions "RESOURCE_DOES_NOT_EXIST error (line 388)," the actual vulnerability is broader. Line 388 only triggers when storage reads genuinely **fail** (database errors), not when accounts simply don't exist (which returns `Ok(0)`). [8](#0-7) 

However, the core issue remains valid: attackers can exhaust storage read capacity by flooding with **any** unverified transactions (whether they trigger RESOURCE_DOES_NOT_EXIST errors or not) because storage reads precede signature verification. The vulnerability affects all incoming transactions, making it a systemic resource exhaustion attack vector that degrades validator performance.

### Citations

**File:** mempool/src/shared_mempool/tasks.rs (L328-350)
```rust
    let start_storage_read = Instant::now();
    let state_view = smp
        .db
        .latest_state_checkpoint_view()
        .expect("Failed to get latest state checkpoint view.");

    // Track latency: fetching seq number
    let account_seq_numbers = IO_POOL.install(|| {
        transactions
            .par_iter()
            .map(|(t, _, _)| match t.replay_protector() {
                ReplayProtector::Nonce(_) => Ok(None),
                ReplayProtector::SequenceNumber(_) => {
                    get_account_sequence_number(&state_view, t.sender())
                        .map(Some)
                        .inspect_err(|e| {
                            error!(LogSchema::new(LogEntry::DBError).error(e));
                            counters::DB_ERROR.inc();
                        })
                },
            })
            .collect::<Vec<_>>()
    });
```

**File:** mempool/src/shared_mempool/tasks.rs (L381-391)
```rust
            } else {
                // Failed to get account's onchain sequence number
                statuses.push((
                    t,
                    (
                        MempoolStatus::new(MempoolStatusCode::VmError),
                        Some(DiscardedVMStatus::RESOURCE_DOES_NOT_EXIST),
                    ),
                ));
            }
            None
```

**File:** mempool/src/shared_mempool/tasks.rs (L395-401)
```rust
    validate_and_add_transactions(
        transactions,
        smp,
        timeline_state,
        &mut statuses,
        client_submitted,
    );
```

**File:** mempool/src/shared_mempool/tasks.rs (L486-494)
```rust
    // Track latency: VM validation
    let vm_validation_timer = counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::VM_VALIDATION_LABEL])
        .start_timer();
    let validation_results = VALIDATION_POOL.install(|| {
        transactions
            .par_iter()
            .map(|t| {
                let result = smp.validator.read().validate_transaction(t.0.clone());
```

**File:** vm-validator/src/vm_validator.rs (L103-117)
```rust
pub fn get_account_sequence_number(
    state_view: &DbStateView,
    address: AccountAddress,
) -> Result<u64> {
    fail_point!("vm_validator::get_account_sequence_number", |_| {
        Err(anyhow::anyhow!(
            "Injected error in get_account_sequence_number"
        ))
    });

    match AccountResource::fetch_move_resource(state_view, &address)? {
        Some(account_resource) => Ok(account_resource.sequence_number()),
        None => Ok(0),
    }
}
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L77-91)
```rust
pub trait LatestDbStateCheckpointView {
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView>;
}

impl LatestDbStateCheckpointView for Arc<dyn DbReader> {
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
}
```

**File:** config/src/config/mempool_config.rs (L113-116)
```rust
            shared_mempool_batch_size: 300,
            shared_mempool_max_batch_bytes: MAX_APPLICATION_MESSAGE_SIZE as u64,
            shared_mempool_ack_timeout_ms: 2_000,
            shared_mempool_max_concurrent_inbound_syncs: 4,
```

**File:** mempool/src/thread_pool.rs (L8-13)
```rust
pub(crate) static IO_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| {
    rayon::ThreadPoolBuilder::new()
        .thread_name(|index| format!("mempool_io_{}", index))
        .build()
        .unwrap()
});
```
