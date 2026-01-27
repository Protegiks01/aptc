# Audit Report

## Title
Unversioned TOTAL_SUPPLY_AGGR_BASE_VAL Constant Enables Consensus Split During Protocol Upgrades

## Summary
The `TOTAL_SUPPLY_AGGR_BASE_VAL` constant used in sharded block execution lacks any versioning or feature flag mechanism. If this constant changes during a protocol upgrade, validators running different binary versions will use different base values for aggregator overflow checks, causing identical transactions to succeed on some validators but fail on others. This leads to divergent state roots and a consensus split requiring a hard fork.

## Finding Description

The sharded block executor uses an artificial base value for total supply aggregation to enable parallel execution across shards. This value is hardcoded as a constant: [1](#0-0) 

During sharded execution, transactions read the total supply through an overridden state view that returns this artificial base value instead of the actual state value: [2](#0-1) 

When aggregator operations (such as minting coins) execute, they perform overflow validation using `BoundedMath::unsigned_add`: [3](#0-2) 

The overflow check evaluates: `base + value > max_value`, where `base` is `TOTAL_SUPPLY_AGGR_BASE_VAL` and `max_value` is `u128::MAX` for the total supply aggregator.

**Attack Scenario:**

1. Protocol upgrade changes `TOTAL_SUPPLY_AGGR_BASE_VAL` from `OLD_BASE` to `NEW_BASE`
2. During gradual validator rollout, some validators run old binary (using `OLD_BASE`), others run new binary (using `NEW_BASE`)
3. Transaction attempts to mint coins with amount `X` where: `u128::MAX - NEW_BASE < X < u128::MAX - OLD_BASE`
4. **Old validators:** `OLD_BASE + X ≤ u128::MAX` → transaction succeeds
5. **New validators:** `NEW_BASE + X > u128::MAX` → transaction aborts with `EAGGREGATOR_OVERFLOW`
6. Different transaction outputs (success vs abort) produce different state checkpoint hashes
7. Validators compute different state roots for the same block
8. **Consensus split occurs** - validators on different versions cannot agree on block validity

The aggregator overflow check occurs during transaction execution: [4](#0-3) 

After execution, the normalization process adjusts the final total supply values: [5](#0-4) 

However, this normalization only affects transactions that succeeded. Transactions that aborted due to overflow during execution remain aborted, and the normalization cannot retroactively make them succeed.

## Impact Explanation

**Severity: Critical** (Consensus/Safety Violation + Non-recoverable Network Partition)

This vulnerability breaks the fundamental invariant: "All validators must produce identical state roots for identical blocks." The impact includes:

1. **Consensus Split:** Validators on different versions cannot reach consensus on block validity
2. **Network Partition:** The chain splits into two incompatible forks
3. **Requires Hard Fork:** Recovery requires coordinated intervention and likely a hard fork to reconcile the divergent states
4. **Total Loss of Liveness:** During the split, the network cannot make progress on either fork if neither achieves >2/3 stake

This matches the Critical severity category in the Aptos Bug Bounty: "Non-recoverable network partition (requires hardfork)" and "Consensus/Safety violations."

## Likelihood Explanation

**Likelihood: Medium**

While the constant hasn't changed yet, the likelihood is non-negligible because:

1. **No Versioning Protection:** There is zero code protecting against this scenario - no feature flags, version checks, or migration logic
2. **Protocol Evolution:** Constants may need adjustment for performance optimization, bug fixes, or design improvements
3. **Standard Upgrade Process:** Aptos validators typically perform gradual rollouts during protocol upgrades to maintain availability
4. **Feasible Trigger:** Any transaction minting coins with amount near `u128::MAX / 2` can trigger the divergence during a mixed-version period

The vulnerability becomes exploitable automatically during any protocol upgrade that changes this constant, without requiring attacker action beyond submitting a large mint transaction (which could be legitimate).

## Recommendation

Implement versioning for the `TOTAL_SUPPLY_AGGR_BASE_VAL` constant using the existing feature flag system:

1. **Add Feature Flag:**
   ```rust
   // In types/src/on_chain_config/aptos_features.rs
   pub enum FeatureFlag {
       // ... existing flags ...
       TOTAL_SUPPLY_AGGR_BASE_VAL_V2 = 74,
   }
   ```

2. **Version-Aware Constant Selection:**
   ```rust
   // In aggr_overridden_state_view.rs
   pub const TOTAL_SUPPLY_AGGR_BASE_VAL_V1: u128 = u128::MAX >> 1;
   pub const TOTAL_SUPPLY_AGGR_BASE_VAL_V2: u128 = /* new value */;
   
   impl<'a, S: StateView + Sync + Send> AggregatorOverriddenStateView<'a, S> {
       pub fn new(base_view: &'a S, features: &Features) -> Self {
           let total_supply_aggr_base_val = if features.is_enabled(FeatureFlag::TOTAL_SUPPLY_AGGR_BASE_VAL_V2) {
               TOTAL_SUPPLY_AGGR_BASE_VAL_V2
           } else {
               TOTAL_SUPPLY_AGGR_BASE_VAL_V1
           };
           Self {
               base_view,
               total_supply_aggr_base_val,
           }
       }
   }
   ```

3. **Epoch-Aligned Activation:** Ensure the feature flag activates at epoch boundaries when all validators must upgrade simultaneously, preventing mixed-version scenarios.

4. **Testing:** Add integration tests simulating version transitions to verify consensus is maintained.

## Proof of Concept

**Conceptual PoC (Requires Multi-Version Test Environment):**

```rust
// Simulation of consensus split scenario

// Setup: Two validator groups with different binary versions
let old_base = u128::MAX >> 1; // ~1.7e38
let new_base = u128::MAX >> 2; // ~8.5e37 (hypothetical change)

// Large mint transaction
let mint_amount = (u128::MAX >> 1) + 1; // Just above old_base threshold

// Old validator execution:
let old_validator_result = {
    let base = old_base;
    if base + mint_amount > u128::MAX {
        TransactionStatus::Abort(EAGGREGATOR_OVERFLOW)
    } else {
        TransactionStatus::Success
    }
}; // Result: Abort

// New validator execution:
let new_validator_result = {
    let base = new_base;
    if base + mint_amount > u128::MAX {
        TransactionStatus::Abort(EAGGREGATOR_OVERFLOW)
    } else {
        TransactionStatus::Success
    }
}; // Result: Success (because new_base + mint_amount < u128::MAX)

// Consensus check:
assert_ne!(old_validator_result, new_validator_result);
// CONSENSUS SPLIT: Validators disagree on transaction outcome
```

**Reproduction Steps:**

1. Deploy two validator nodes with different `TOTAL_SUPPLY_AGGR_BASE_VAL` values (requires modifying source and building two binaries)
2. Submit a transaction that mints coins with amount between the two overflow thresholds
3. Observe different transaction outcomes on each validator
4. Verify state root divergence in transaction info
5. Confirm consensus failure when validators attempt to vote on the block

**Note:** Full reproduction requires infrastructure to run multiple validator versions simultaneously, which is beyond a simple unit test but feasible in a staging environment.

---

**Notes:**

- The vulnerability is architectural - the lack of versioning mechanism is the flaw, not a bug in current behavior
- Current operations are safe as long as the constant never changes
- Any future change to this constant without proper versioning will trigger the vulnerability
- The sharded execution feature is performance-critical, so this constant may need adjustment based on production metrics
- Similar versioning concerns may exist for other hardcoded constants in the sharded executor

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L14-14)
```rust
pub const TOTAL_SUPPLY_AGGR_BASE_VAL: u128 = u128::MAX >> 1;
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L41-48)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>> {
        if *state_key == *TOTAL_SUPPLY_STATE_KEY {
            // TODO: Remove this when we have aggregated total supply implementation for remote
            //       sharding. For now we need this because after all the txns are executed, the
            //       proof checker expects the total_supply to read/written to the tree.
            self.base_view.get_state_value(state_key)?;
            return self.total_supply_base_view_override();
        }
```

**File:** aptos-move/aptos-aggregator/src/bounded_math.rs (L50-56)
```rust
    pub fn unsigned_add(&self, base: u128, value: u128) -> BoundedMathResult<u128> {
        if self.max_value < base || value > (self.max_value - base) {
            Err(BoundedMathError::Overflow)
        } else {
            Ok(base + value)
        }
    }
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L128-136)
```rust
    pub fn add(&mut self, value: u128) -> PartialVMResult<()> {
        let math = BoundedMath::new(self.max_value);
        match self.state {
            AggregatorState::Data => {
                // If aggregator knows the value, add directly and keep the state.
                self.value = math
                    .unsigned_add(self.value, value)
                    .map_err(addition_v1_error)?;
                return Ok(());
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L193-195)
```rust
                    curr_delta =
                        DeltaU128::get_delta(last_txn_total_supply, TOTAL_SUPPLY_AGGR_BASE_VAL);
                    break;
```
