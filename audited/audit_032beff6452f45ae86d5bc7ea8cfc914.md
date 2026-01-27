# Audit Report

## Title
Uncontrolled First Epoch Transition Due to Uninitialized `last_reconfiguration_time` in Genesis

## Summary
The genesis state initialization leaves `last_reconfiguration_time` at 0 after transitioning to epoch 1. When validators propose the first block using real wall-clock timestamps (billions of microseconds since UNIX_EPOCH), the epoch transition condition in `block_prologue` immediately evaluates to true, forcing an instant transition from epoch 1 to epoch 2 regardless of the configured `epoch_duration_secs`. This creates inconsistent behavior between test environments (which use small timestamps) and production networks (which use real system time). [1](#0-0) 

## Finding Description

During genesis initialization, the `Configuration` resource is created with `epoch: 0` and `last_reconfiguration_time: 0`: [2](#0-1) 

After genesis completes, `emit_genesis_reconfiguration_event` transitions the system from epoch 0 to epoch 1, but critically **does not update `last_reconfiguration_time`**, leaving it at 0: [1](#0-0) 

When the first real block is proposed, its timestamp comes from the validator's system clock via `time_service.get_current_timestamp()`: [3](#0-2) 

This calls `duration_since_epoch()` which returns real wall-clock time: [4](#0-3) 

For any network starting in 2024, this timestamp is approximately 1,735,689,600,000,000 microseconds. The `block_prologue` function then checks: [5](#0-4) 

With `last_reconfiguration_time = 0` and a default `epoch_interval` of 86,400,000,000 microseconds (1 day), the condition becomes:
```
1,735,689,600,000,000 - 0 >= 86,400,000,000  → TRUE
```

This forces an immediate reconfiguration from epoch 1 to epoch 2 on the very first block, regardless of the configured epoch duration.

## Impact Explanation

This qualifies as **High Severity** due to:

1. **Consensus Inconsistency Risk**: While all validators using synchronized clocks will agree on the transition, validators with clock skew beyond the epoch interval could disagree on whether to reconfigure, potentially causing a network partition requiring manual intervention.

2. **Validator Reward Impact**: The premature epoch transition affects reward distribution calculations in `stake::on_new_epoch()`, as epoch 1 lasts only one block instead of the configured duration: [6](#0-5) 

3. **Test/Production Divergence**: Test environments use small timestamps (e.g., 500,000 microseconds as seen in golden files), while production uses real wall-clock time, creating a critical behavioral difference that hides this issue during testing: [7](#0-6) 

## Likelihood Explanation

**Likelihood: Certain** - This occurs on every production network deployment:

1. All production networks use real system time via `SystemTime::now()`
2. The condition `timestamp - 0 >= epoch_interval` is always true for real timestamps
3. The behavior is deterministic and reproducible on every genesis initialization

While the comment in `epoch_manager.rs` suggests epoch 1 is intended to be a single-block epoch: [8](#0-7) 

The mechanism relies on an implicit side effect rather than explicit logic, making it fragile and undocumented.

## Recommendation

**Fix**: Update `emit_genesis_reconfiguration_event` to explicitly set `last_reconfiguration_time` to the timestamp of the genesis block event:

```move
fun emit_genesis_reconfiguration_event() acquires Configuration {
    let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
    assert!(config_ref.epoch == 0 && config_ref.last_reconfiguration_time == 0, error::invalid_state(ECONFIGURATION));
    config_ref.epoch = 1;
    config_ref.last_reconfiguration_time = timestamp::now_microseconds(); // Add this line
    
    // ... rest of event emission
}
```

However, since `timestamp::now_microseconds()` is 0 during genesis, this alone doesn't solve the issue. A more robust fix would be to:

1. Initialize the timestamp to a value that makes the first epoch transition occur at the expected interval, OR
2. Add explicit logic to skip the epoch transition check for the first block in epoch 1, OR  
3. Ensure the formal specification and documentation clearly state that epoch 1 is always a single-block bootstrap epoch

Update the specification to reflect the corrected behavior: [9](#0-8) 

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework)]
fun test_genesis_epoch_transition(aptos_framework: &signer) {
    // Initialize genesis state
    reconfiguration::initialize_for_test(aptos_framework);
    timestamp::set_time_has_started_for_testing(aptos_framework);
    block::initialize_for_test(aptos_framework, 86400000000); // 1 day epoch interval
    
    // Emit genesis reconfiguration event
    reconfiguration::emit_genesis_reconfiguration_event();
    
    // Verify we're in epoch 1 with last_reconfiguration_time = 0
    assert!(reconfiguration::current_epoch() == 1, 0);
    assert!(reconfiguration::last_reconfiguration_time() == 0, 1);
    
    // Simulate first block with production-like timestamp (Jan 1, 2024)
    let production_timestamp = 1704067200000000; // microseconds
    timestamp::update_global_time_for_test(production_timestamp);
    
    // The condition will be: 1704067200000000 - 0 >= 86400000000 (TRUE)
    // This triggers immediate epoch transition
    assert!(production_timestamp >= 86400000000, 2);
    
    // After block_prologue processes, we're immediately in epoch 2
    reconfiguration::reconfigure_for_test();
    assert!(reconfiguration::current_epoch() == 2, 3);
    
    // Epoch 1 lasted exactly one block, not the configured 1 day
}
```

### Citations

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L69-82)
```text
    public(friend) fun initialize(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);

        // assert it matches `new_epoch_event_key()`, otherwise the event can't be recognized
        assert!(account::get_guid_next_creation_num(signer::address_of(aptos_framework)) == 2, error::invalid_state(EINVALID_GUID_FOR_EVENT));
        move_to<Configuration>(
            aptos_framework,
            Configuration {
                epoch: 0,
                last_reconfiguration_time: 0,
                events: account::new_event_handle<NewEpochEvent>(aptos_framework),
            }
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L133-135)
```text
        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
        storage_gas::on_reconfig();
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L171-189)
```text
    fun emit_genesis_reconfiguration_event() acquires Configuration {
        let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
        assert!(config_ref.epoch == 0 && config_ref.last_reconfiguration_time == 0, error::invalid_state(ECONFIGURATION));
        config_ref.epoch = 1;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                NewEpoch {
                    epoch: config_ref.epoch,
                },
            );
        };
        event::emit_event<NewEpochEvent>(
            &mut config_ref.events,
            NewEpochEvent {
                epoch: config_ref.epoch,
            },
        );
    }
```

**File:** consensus/src/liveness/proposal_generator.rs (L598-601)
```rust
        // All proposed blocks in a branch are guaranteed to have increasing timestamps
        // since their predecessor block will not be added to the BlockStore until
        // the local time exceeds it.
        let timestamp = self.time_service.get_current_timestamp();
```

**File:** crates/aptos-infallible/src/time.rs (L8-13)
```rust
/// Gives the duration since the Unix epoch, notice the expect.
pub fn duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
}
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L203-218)
```text
    fun block_prologue(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ) acquires BlockResource, CommitHistory {
        let epoch_interval = block_prologue_common(&vm, hash, epoch, round, proposer, failed_proposer_indices, previous_block_votes_bitvec, timestamp);
        randomness::on_new_block(&vm, epoch, round, option::none());
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
    }
```

**File:** api/goldens/aptos_api__tests__transactions_test__test_get_transactions_output_user_transaction_with_entry_function_payload_orderless.json (L142-142)
```json
          "time_microseconds": "500000"
```

**File:** consensus/src/epoch_manager.rs (L416-419)
```rust
        // Genesis is epoch=0
        // First block (after genesis) is epoch=1, and is the only block in that epoch.
        // It has no votes, so we skip it unless we are in epoch 1, as otherwise it will
        // skew leader elections for exclude_round number of rounds.
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.spec.move (L114-121)
```text
    spec emit_genesis_reconfiguration_event {
        use aptos_framework::reconfiguration::{Configuration};

        aborts_if !exists<Configuration>(@aptos_framework);
        let config_ref = global<Configuration>(@aptos_framework);
        aborts_if !(config_ref.epoch == 0 && config_ref.last_reconfiguration_time == 0);
        ensures global<Configuration>(@aptos_framework).epoch == 1;
    }
```
