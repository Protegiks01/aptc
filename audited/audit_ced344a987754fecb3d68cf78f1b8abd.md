# Audit Report

## Title
Consensus Leader Election Divergence Due to Inconsistent Event Pruning States Across Validators

## Summary
Validators with different event pruning configurations compute different valid proposers for consensus rounds, causing proposal rejections and consensus liveness failures. The leader reputation system uses event root hashes as part of the randomness seed for leader selection, but when events are pruned, it falls back to `HashValue::zero()`, causing validators to disagree on who should be the proposer.

## Finding Description

The vulnerability occurs in the consensus leader reputation system when validators have pruned events at different rates. The system breaks the **Deterministic Execution** invariant: all validators must agree on the valid proposer for each round.

**Attack Flow:**

1. **Configuration Divergence**: Validators can configure different `prune_window` values in their local `LedgerPrunerConfig` [1](#0-0) 

2. **Event Retrieval Failure**: When `get_latest_block_events()` is called for leader reputation calculation, it attempts to read events from the database [2](#0-1) 

3. **Pruned Event Handling**: If events have been pruned, `expect_new_block_event()` returns a `NotFound` error [3](#0-2) 

4. **Error Fallback to Zero Hash**: The error handler in `get_block_metadata()` catches this failure and returns an empty event list with `HashValue::zero()` [4](#0-3) 

5. **Divergent Leader Selection**: When `ProposerAndVoterV2` is configured (default), the system uses `root_hash` in the leader election seed. Validators with pruned events use `HashValue::zero()`, while validators with unpruned events use the correct root hash [5](#0-4) 

6. **Different Leaders Computed**: The `choose_index()` function hashes the state to select a leader. Different states produce different leaders [6](#0-5) 

7. **Proposal Rejection**: Validators reject proposals from authors they don't consider valid proposers [7](#0-6) 

This violates the consensus invariant that all validators must agree on the valid proposer for a given round.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

- **Significant Protocol Violation**: Validators disagree on fundamental consensus state (valid proposer)
- **Consensus Liveness Failure**: Proposals are rejected by validators who computed a different leader, preventing block finalization
- **Validator Node Impact**: Affects consensus operation and can cause slowdowns or stalls

While not causing immediate fund loss, this breaks consensus safety assumptions and can lead to chain halts requiring manual intervention.

## Likelihood Explanation

**High Likelihood**:

- Validators naturally have different `prune_window` configurations based on storage capacity
- `ProposerAndVoterV2` is the default leader reputation type, which enables `use_root_hash_for_seed` [8](#0-7) 
- No consensus mechanism enforces uniform pruning configurations across validators
- Occurs during normal operation without attacker intervention
- Once pruning windows diverge sufficiently, the issue will manifest repeatedly

## Recommendation

**Fix 1: Enforce Minimum Pruning Window for Leader Reputation History**

Add a check in `get_latest_block_events()` to ensure the requested history is not pruned:

```rust
fn get_latest_block_events(&self, num_events: usize) -> Result<Vec<EventWithVersion>> {
    gauged_api("get_latest_block_events", || {
        let latest_version = self.get_synced_version()?;
        
        // Calculate minimum required version for leader reputation
        let min_required_version = latest_version.unwrap_or(0)
            .saturating_sub(num_events as u64);
        
        // Ensure events are not pruned
        self.error_if_ledger_pruned("NewBlockEvent", min_required_version)?;
        
        // ... rest of implementation
    })
}
```

**Fix 2: Use Consensus-Safe Fallback When Events Are Pruned**

Instead of returning `HashValue::zero()`, the system should use a deterministic fallback that all validators agree on, such as using only epoch and round without the root hash:

```rust
let state = if self.use_root_hash && !events.is_empty() {
    [root_hash.to_vec(), self.epoch.to_le_bytes().to_vec(), round.to_le_bytes().to_vec()].concat()
} else {
    [self.epoch.to_le_bytes().to_vec(), round.to_le_bytes().to_vec()].concat()
};
```

**Fix 3: On-Chain Minimum Pruning Window Configuration**

Add an on-chain configuration parameter that specifies the minimum pruning window all validators must maintain for consensus-critical data.

## Proof of Concept

**Setup:**
1. Configure two validator nodes with different pruning windows:
   - Node A: `prune_window = 1000000` 
   - Node B: `prune_window = 100000`

2. Wait until Node B has pruned events that Node A still retains

3. Observe consensus behavior during leader election:

**Expected Behavior:**
- Both nodes compute the same valid proposer for round N
- Proposals are accepted and finalized

**Actual Behavior:**
- Node A computes proposer using `root_hash = actual_hash`
- Node B computes proposer using `root_hash = HashValue::zero()`  
- Different hashes → different `choose_index()` results → different proposers
- Node A accepts Alice's proposal, Node B rejects it
- Node B accepts Bob's proposal, Node A rejects it
- Consensus stalls or requires fallback mechanisms

**Test Scenario:**
```rust
// Pseudocode for reproduction
let window_size = 200;
let validator_a_has_events = true;
let validator_b_pruned_events = true;

let root_hash_a = if validator_a_has_events { compute_root_hash(events) } else { HashValue::zero() };
let root_hash_b = if !validator_b_pruned_events { compute_root_hash(events) } else { HashValue::zero() };

let state_a = [root_hash_a.to_vec(), epoch.to_le_bytes().to_vec(), round.to_le_bytes().to_vec()].concat();
let state_b = [root_hash_b.to_vec(), epoch.to_le_bytes().to_vec(), round.to_le_bytes().to_vec()].concat();

let proposer_a = choose_index(weights.clone(), state_a);
let proposer_b = choose_index(weights.clone(), state_b);

assert_ne!(proposer_a, proposer_b); // Demonstrates divergence
```

## Notes

This is not a traditional "event replay attack" where old events are resubmitted. Rather, it's a consensus divergence vulnerability triggered by the **absence** of events after pruning. The security impact stems from validators making different consensus decisions based on their local storage state, violating the fundamental assumption that all validators execute deterministically.

### Citations

**File:** config/src/config/storage_config.rs (L327-341)
```rust
pub struct LedgerPrunerConfig {
    /// Boolean to enable/disable the ledger pruner. The ledger pruner is responsible for pruning
    /// everything else except for states (e.g. transactions, events etc.)
    pub enable: bool,
    /// This is the default pruning window for any other store except for state store. State store
    /// being big in size, we might want to configure a smaller window for state store vs other
    /// store.
    pub prune_window: u64,
    /// Batch size of the versions to be sent to the ledger pruner - this is to avoid slowdown due to
    /// issuing too many DB calls and batch prune instead. For ledger pruner, this means the number
    /// of versions to prune a time.
    pub batch_size: usize,
    /// The offset for user pruning window to adjust
    pub user_pruning_window_offset: u64,
}
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L742-777)
```rust
    fn get_latest_block_events(&self, num_events: usize) -> Result<Vec<EventWithVersion>> {
        gauged_api("get_latest_block_events", || {
            let latest_version = self.get_synced_version()?;
            if !self.skip_index_and_usage {
                return self.get_events(
                    &new_block_event_key(),
                    u64::MAX,
                    Order::Descending,
                    num_events as u64,
                    latest_version.unwrap_or(0),
                );
            }

            let db = self.ledger_db.metadata_db_arc();
            let mut iter = db.rev_iter::<BlockInfoSchema>()?;
            iter.seek_to_last();

            let mut events = Vec::with_capacity(num_events);
            for item in iter {
                let (_block_height, block_info) = item?;
                let first_version = block_info.first_version();
                if latest_version.as_ref().is_some_and(|v| first_version <= *v) {
                    let event = self
                        .ledger_db
                        .event_db()
                        .expect_new_block_event(first_version)?;
                    events.push(EventWithVersion::new(first_version, event));
                    if events.len() == num_events {
                        break;
                    }
                }
            }

            Ok(events)
        })
    }
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L83-96)
```rust
    pub(crate) fn expect_new_block_event(&self, version: Version) -> Result<ContractEvent> {
        for event in self.get_events_by_version(version)? {
            if let Some(key) = event.event_key() {
                if *key == new_block_event_key() {
                    return Ok(event);
                }
            }
        }

        Err(AptosDbError::NotFound(format!(
            "NewBlockEvent at version {}",
            version,
        )))
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L179-184)
```rust
            if let Err(e) = self.refresh_db_result(&mut locked, latest_db_version) {
                warn!(
                    error = ?e, "[leader reputation] Fail to initialize db result",
                );
                return (vec![], HashValue::zero());
            }
```

**File:** consensus/src/liveness/leader_reputation.rs (L717-733)
```rust
        let state = if self.use_root_hash {
            [
                root_hash.to_vec(),
                self.epoch.to_le_bytes().to_vec(),
                round.to_le_bytes().to_vec(),
            ]
            .concat()
        } else {
            [
                self.epoch.to_le_bytes().to_vec(),
                round.to_le_bytes().to_vec(),
            ]
            .concat()
        };

        let chosen_index = choose_index(stake_weights, state);
        (proposers[chosen_index], voting_power_participation_ratio)
```

**File:** consensus/src/liveness/proposer_election.rs (L14-16)
```rust
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }
```

**File:** consensus/src/liveness/proposer_election.rs (L39-69)
```rust
fn next_in_range(state: Vec<u8>, max: u128) -> u128 {
    // hash = SHA-3-256(state)
    let hash = aptos_crypto::HashValue::sha3_256_of(&state).to_vec();
    let mut temp = [0u8; 16];
    copy_slice_to_vec(&hash[..16], &mut temp).expect("next failed");
    // return hash[0..16]
    u128::from_le_bytes(temp) % max
}

// chose index randomly, with given weight distribution
pub(crate) fn choose_index(mut weights: Vec<u128>, state: Vec<u8>) -> usize {
    let mut total_weight = 0;
    // Create cumulative weights vector
    // Since we own the vector, we can safely modify it in place
    for w in &mut weights {
        total_weight = total_weight
            .checked_add(w)
            .expect("Total stake shouldn't exceed u128::MAX");
        *w = total_weight;
    }
    let chosen_weight = next_in_range(state, total_weight);
    weights
        .binary_search_by(|w| {
            if *w <= chosen_weight {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        })
        .expect_err("Comparison never returns equals, so it's always guaranteed to be error")
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L541-544)
```rust
    pub fn use_root_hash_for_seed(&self) -> bool {
        // all versions after V1 should use root hash
        !matches!(self, Self::ProposerAndVoter(_))
    }
```
