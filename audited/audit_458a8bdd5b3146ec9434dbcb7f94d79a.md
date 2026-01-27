# Audit Report

## Title
Gas Schedule Version Mismatch Between API Calculation and VM Execution in Transaction Simulation

## Summary
The `/transactions/simulate` endpoint exhibits a race condition where gas schedule parameters used for API-level calculations (from `get_gas_schedule()`) can be from a different version/epoch than the gas schedule used by the VM during actual simulation execution (from `latest_state_view_poem()`). This creates inconsistency when epoch boundaries occur during API request processing.

## Finding Description

The transaction simulation endpoint captures state information at different points, leading to potential version mismatches:

**Step 1:** Capture ledger info at version V1, epoch E [1](#0-0) 

**Step 2:** Retrieve gas schedule parameters from V1 using `state_view_at_version(ledger_info.version())` [2](#0-1) [3](#0-2) 

These parameters are used to calculate `max_number_of_gas_units` and `min_number_of_gas_units`: [4](#0-3) 

**Step 3:** Create state view for simulation using `latest_state_checkpoint_view()`, which may return version V2 > V1 if blocks were committed [5](#0-4) [6](#0-5) 

**Step 4:** VM loads gas parameters from the state view at V2 [7](#0-6) [8](#0-7) 

The `latest_state_checkpoint_view()` implementation retrieves the current checkpoint version independently: [9](#0-8) 

If an epoch boundary occurs between capturing `ledger_info` (step 1) and creating the simulation state view (step 3), the gas schedules will differ because gas schedule updates occur at epoch boundaries: [10](#0-9) 

## Impact Explanation

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because:

1. **Incorrect Gas Parameter Calculations**: API-level gas calculations (max/min gas units) use outdated parameters that don't match actual execution
2. **Misleading Simulation Results**: Users receive simulation results based on mismatched gas schedules, potentially leading to:
   - Transaction rejections when max_gas_amount exceeds new limits
   - Unexpected gas consumption if costs increased
   - Overpayment if gas costs decreased but max was calculated with old schedule

3. **No Direct Fund Loss**: While users may overpay for gas or experience rejections, this doesn't constitute direct theft or permanent fund loss

4. **Limited Scope**: Only affects simulation endpoint; actual transaction execution uses correct gas schedule from execution time

## Likelihood Explanation

**Likelihood: Low to Medium**

- **Timing Requirements**: Race condition requires epoch boundary to occur during the narrow window between line 616 and line 1640 (typically milliseconds)
- **Epoch Frequency**: Epochs change infrequently (hours to days on mainnet)
- **Gas Schedule Changes**: Not every epoch boundary includes gas schedule updates
- **Natural Occurrence**: This will happen occasionally without attacker intervention when users simulate near epoch boundaries
- **Not Directly Exploitable**: Attackers cannot control epoch timing, only observe and potentially time requests

## Recommendation

Ensure consistent version usage throughout the simulation flow by capturing the state view once and reusing it:

```rust
// In simulate_transaction endpoint (line 616)
let ledger_info = context.get_latest_ledger_info()?;
let state_view = context.latest_state_view_poem(&ledger_info)?;

// Use the same state_view for gas schedule retrieval
// Modify get_gas_schedule to accept a state_view parameter instead of ledger_info
let (_, gas_params) = context.get_gas_schedule_from_view(&state_view, &ledger_info)?;

// ... rest of simulation logic using the same state_view
```

Alternatively, change `simulate()` to use `state_view_at_version(ledger_info.version())` instead of `latest_state_view_poem()`:

```rust
// In simulate function (line 1640)
let state_view = self.context.state_view_at_version(ledger_info.version())
    .map_err(|e| SubmitTransactionError::internal_with_code(
        e, AptosErrorCode::InternalError, &ledger_info
    ))?;
```

## Proof of Concept

This race condition is difficult to reliably reproduce due to timing constraints. A theoretical PoC would require:

```rust
// Pseudocode demonstrating the race condition
#[test]
fn test_gas_schedule_version_mismatch() {
    // 1. Set up node at epoch E with gas schedule G1
    let mut test_env = setup_test_environment();
    
    // 2. Start simulation request (captures ledger_info at epoch E)
    let simulation_future = async {
        let ledger_info = get_latest_ledger_info(); // Epoch E
        let gas_params = get_gas_schedule(&ledger_info); // Reads from E
        
        // Inject delay to allow epoch change
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let state_view = latest_state_view_poem(&ledger_info); // Now reads from E+1
        simulate_transaction(&state_view, ...) // Uses E+1 gas schedule
    };
    
    // 3. Trigger epoch change during delay
    let epoch_change = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger_epoch_boundary_with_new_gas_schedule();
    };
    
    // 4. Verify mismatch
    tokio::join!(simulation_future, epoch_change);
    // Assert that gas_params epoch != state_view epoch
}
```

A production demonstration would require monitoring epoch boundaries and timing simulation requests to coincide.

## Notes

This issue represents a **consistency violation within API request processing** rather than a critical security vulnerability. The simulation endpoint is advisory—actual transaction execution always uses the correct gas schedule from execution time. While this can cause user inconvenience through incorrect estimates, it does not enable fund theft, consensus violations, or permanent state corruption.

### Citations

**File:** api/src/transactions.rs (L616-616)
```rust
            let ledger_info = context.get_latest_ledger_info()?;
```

**File:** api/src/transactions.rs (L653-653)
```rust
                let (_, gas_params) = context.get_gas_schedule(&ledger_info)?;
```

**File:** api/src/transactions.rs (L654-658)
```rust
                let min_number_of_gas_units =
                    u64::from(gas_params.vm.txn.min_transaction_gas_units)
                        / u64::from(gas_params.vm.txn.gas_unit_scaling_factor);
                let max_number_of_gas_units =
                    u64::from(gas_params.vm.txn.maximum_number_of_gas_units);
```

**File:** api/src/transactions.rs (L1640-1640)
```rust
        let state_view = self.context.latest_state_view_poem(&ledger_info)?;
```

**File:** api/src/context.rs (L160-168)
```rust
    pub fn latest_state_view_poem<E: InternalError>(
        &self,
        ledger_info: &LedgerInfo,
    ) -> Result<DbStateView, E> {
        self.db
            .latest_state_checkpoint_view()
            .context("Failed to read latest state checkpoint from DB")
            .map_err(|e| E::internal_with_code(e, AptosErrorCode::InternalError, ledger_info))
    }
```

**File:** api/src/context.rs (L1497-1502)
```rust
            let state_view = self
                .db
                .state_view_at_version(Some(ledger_info.version()))
                .map_err(|e| {
                    E::internal_with_code(e, AptosErrorCode::InternalError, ledger_info)
                })?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3357-3359)
```rust
        let env = AptosEnvironment::new(state_view);
        let mut vm = AptosVM::new(&env);
        vm.is_simulation = true;
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L246-247)
```rust
        let (gas_params, storage_gas_params, gas_feature_version) =
            get_gas_parameters(&mut sha3_256, &features, state_view);
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L82-90)
```rust
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L135-145)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<GasScheduleV2>()) {
            let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
            if (exists<GasScheduleV2>(@aptos_framework)) {
                *borrow_global_mut<GasScheduleV2>(@aptos_framework) = new_gas_schedule;
            } else {
                move_to(framework, new_gas_schedule);
            }
        }
    }
```
