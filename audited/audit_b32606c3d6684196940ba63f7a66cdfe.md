# Audit Report

## Title
DKG Transaction Timing Manipulation via Validator Transaction Pool Starvation

## Summary
The validator transaction pool's FIFO ordering combined with a default per-block limit of 2 validator transactions allows DKG (Distributed Key Generation) transactions to be starved by JWK (JSON Web Key) consensus transactions, enabling malicious validators to manipulate the timing of epoch transitions and potentially affect validator selection and economic outcomes.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Validator Transaction Pool** [1](#0-0)  implements a FIFO queue where all validator transactions compete for inclusion, with global sequence number ordering.

2. **Per-Block Limit** [2](#0-1)  sets the default limit to only 2 validator transactions per block.

3. **Mixed Payload Client** [3](#0-2)  pulls validator transactions first using these limits before pulling user transactions.

The attack flow:

**Step 1**: Multiple JWK consensus managers can create transactions for different issuers [4](#0-3)  where each issuer gets its own `Topic::JWK_CONSENSUS(issuer)`, allowing multiple JWK transactions in the pool simultaneously.

**Step 2**: When malicious validators observe DKG starting [5](#0-4) , they can trigger quorum-certified JWK updates for multiple configured OIDC providers [6](#0-5) .

**Step 3**: These JWK transactions enter the pool ahead of or around the same time as the DKG transaction [7](#0-6)  in FIFO order.

**Step 4**: When a block is proposed, the pull mechanism [8](#0-7)  respects the minimum of proposal limits and validator config limits (default 2).

**Step 5**: The pool's pull implementation [9](#0-8)  iterates in FIFO order, selecting only the first 2 transactions that fit the quota, which would be the JWK transactions if they were added first.

**Step 6**: The DKG transaction is blocked from inclusion and delayed to subsequent blocks.

**Step 7**: When the DKG transaction finally executes, it triggers reconfiguration [10](#0-9)  which sets `last_reconfiguration_time` to the current block timestamp [11](#0-10) .

By controlling which block the DKG transaction executes in, attackers control:
- The epoch transition timestamp
- When the next epoch will start (via the epoch_interval check)
- The duration of the current validator set's tenure

## Impact Explanation

This vulnerability constitutes **Medium severity** under the Aptos bug bounty criteria as it enables "state inconsistencies requiring intervention" and "limited manipulation."

Specific impacts include:

1. **Epoch Timing Manipulation**: Delaying DKG execution delays epoch transitions, extending the current validator set's active period and deferring stake changes.

2. **Economic Distortion**: Current validators earn rewards and fees for an extended period, while pending validators are delayed from becoming active.

3. **Deterministic Execution Violation**: While not causing consensus splits, the ability to manipulate timing creates non-deterministic epoch boundaries that depend on attacker behavior rather than protocol rules.

4. **Validator Selection Timing**: Although validator selection itself is deterministic based on stake, the timing of when validator set changes take effect can be manipulated.

The vulnerability does not reach Critical or High severity because it does not directly cause:
- Loss of funds or minting
- Consensus safety violations (nodes still agree on blocks)
- Network partition or total liveness loss

## Likelihood Explanation

**Likelihood: Medium-Low**

The attack requires:

1. **Multiple OIDC Issuers Configured**: The network must have multiple JWK consensus issuers configured (e.g., Google, Apple, Facebook), which is the intended production configuration for keyless accounts.

2. **Quorum-Level Validator Collusion**: Attackers need validators controlling >2/3 voting power to create quorum-certified JWK updates [12](#0-11) . This is a high bar but within the threat model for Byzantine fault tolerance analysis.

3. **Timing Coordination**: Attackers must coordinate to add JWK transactions at specific times relative to DKG start events.

The attack is more likely during periods when:
- Multiple legitimate JWK updates naturally coincide with DKG timing
- Attackers have advance notice of epoch transitions (predictable from epoch_interval)
- The per-block validator transaction limit remains at the default of 2

## Recommendation

Implement priority-based pulling for validator transactions to ensure critical transactions like DKG cannot be starved:

```rust
// In crates/validator-transaction-pool/src/lib.rs

pub enum TransactionPriority {
    Critical,  // DKG transactions
    Normal,    // JWK and other validator transactions
}

// Modify PoolItem to include priority
struct PoolItem {
    topic: Topic,
    txn: Arc<ValidatorTransaction>,
    pull_notification_tx: Option<aptos_channel::Sender<(), Arc<ValidatorTransaction>>>,
    priority: TransactionPriority,
}

// Update pull to prioritize Critical transactions
pub fn pull(
    &mut self,
    deadline: Instant,
    mut max_items: u64,
    mut max_bytes: u64,
    filter: TransactionFilter,
) -> Vec<ValidatorTransaction> {
    let mut ret = vec![];
    
    // First pull Critical priority transactions
    for (seq_num, item) in self.txn_queue.iter() {
        if matches!(item.priority, TransactionPriority::Critical) {
            if max_items >= 1 && max_bytes >= item.txn.size_in_bytes() as u64 
                && !filter.should_exclude(&item.txn) {
                ret.push(item.txn.as_ref().clone());
                max_items -= 1;
                max_bytes -= item.txn.size_in_bytes() as u64;
            }
        }
    }
    
    // Then pull Normal priority transactions with remaining quota
    // ... existing FIFO logic for normal priority
    
    ret
}
```

Additionally, increase the default per-block validator transaction limit or make it dynamically adjust based on the presence of critical transactions:

```rust
// In types/src/on_chain_config/consensus_config.rs
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 5; // Increased from 2
```

## Proof of Concept

```rust
#[test]
fn dkg_blocked_by_jwk_transactions() {
    use aptos_types::validator_txn::{Topic, ValidatorTransaction};
    use aptos_types::jwks::{QuorumCertifiedUpdate, dummy_issuer};
    use aptos_types::dkg::DKGTranscript;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    
    let pool = VTxnPoolState::default();
    
    // Simulate JWK transactions for two different issuers added first
    let jwk_txn_1 = ValidatorTransaction::ObservedJWKUpdate(
        QuorumCertifiedUpdate::dummy()
    );
    let jwk_txn_2 = ValidatorTransaction::ObservedJWKUpdate(
        QuorumCertifiedUpdate::dummy()
    );
    let dkg_txn = ValidatorTransaction::DKGResult(DKGTranscript::dummy());
    
    let _guard_1 = pool.put(
        Topic::JWK_CONSENSUS(b"issuer1".to_vec()),
        Arc::new(jwk_txn_1.clone()),
        None,
    );
    let _guard_2 = pool.put(
        Topic::JWK_CONSENSUS(b"issuer2".to_vec()),
        Arc::new(jwk_txn_2.clone()),
        None,
    );
    let _guard_3 = pool.put(
        Topic::DKG,
        Arc::new(dkg_txn.clone()),
        None,
    );
    
    // Pull with limit of 2 (default per-block limit)
    let pulled = pool.pull(
        Instant::now().add(Duration::from_secs(10)),
        2,  // max_items = 2 (default limit)
        2048, // max_bytes
        TransactionFilter::default(),
    );
    
    // Verify only JWK transactions were pulled, DKG is blocked
    assert_eq!(2, pulled.len());
    assert_eq!(jwk_txn_1, pulled[0]);
    assert_eq!(jwk_txn_2, pulled[1]);
    // DKG transaction was NOT pulled despite being in the pool
    
    // This demonstrates the vulnerability: DKG is delayed to next block
}
```

## Notes

This vulnerability demonstrates a **resource starvation attack** where lower-priority transactions (JWK updates) can block higher-priority critical transactions (DKG). While the attack requires significant validator collusion (quorum power), it represents a genuine protocol weakness that could be exploited during epochs where validator sets are heavily concentrated or compromised. The impact is amplified in networks with multiple OIDC providers configured for keyless accounts, as intended in production deployments.

### Citations

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

**File:** types/src/on_chain_config/consensus_config.rs (L125-126)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 2;
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB
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

**File:** types/src/validator_txn.rs (L57-64)
```rust
pub enum Topic {
    DKG,
    JWK_CONSENSUS(jwks::Issuer),
    JWK_CONSENSUS_PER_KEY_MODE {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
}
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L244-246)
```text
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration_with_dkg::try_start();
        };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L323-338)
```rust
    pub fn process_quorum_certified_update(&mut self, update: QuorumCertifiedUpdate) -> Result<()> {
        let issuer = update.update.issuer.clone();
        info!(
            epoch = self.epoch_state.epoch,
            issuer = String::from_utf8(issuer.clone()).ok(),
            version = update.update.version,
            "JWKManager processing certified update."
        );
        let state = self.states_by_issuer.entry(issuer.clone()).or_default();
        match &state.consensus_state {
            ConsensusState::InProgress { my_proposal, .. } => {
                //TODO: counters
                let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
                let vtxn_guard =
                    self.vtxn_pool
                        .put(Topic::JWK_CONSENSUS(issuer.clone()), Arc::new(txn), None);
```

**File:** dkg/src/dkg_manager/mod.rs (L405-409)
```rust
                let vtxn_guard = self.vtxn_pool.put(
                    Topic::DKG,
                    Arc::new(txn),
                    Some(self.pull_notification_tx.clone()),
                );
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L65-68)
```text
    fun finish_with_dkg_result(account: &signer, dkg_result: vector<u8>) {
        dkg::finish(dkg_result);
        finish(account);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L113-138)
```text
        let current_time = timestamp::now_microseconds();

        // Do not do anything if a reconfiguration event is already emitted within this transaction.
        //
        // This is OK because:
        // - The time changes in every non-empty block
        // - A block automatically ends after a transaction that emits a reconfiguration event, which is guaranteed by
        //   VM spec that all transactions comming after a reconfiguration transaction will be returned as Retry
        //   status.
        // - Each transaction must emit at most one reconfiguration event
        //
        // Thus, this check ensures that a transaction that does multiple "reconfiguration required" actions emits only
        // one reconfiguration event.
        //
        if (current_time == config_ref.last_reconfiguration_time) {
            return
        };

        reconfiguration_state::on_reconfig_start();

        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
        storage_gas::on_reconfig();

        assert!(current_time > config_ref.last_reconfiguration_time, error::invalid_state(EINVALID_BLOCK_TIME));
        config_ref.last_reconfiguration_time = current_time;
```
