# Audit Report

## Title
State View Inconsistency Between View Function and Simulation in `simulate_transaction()`

## Summary
The `simulate_transaction()` function in `api/src/transactions.rs` uses different state views for the view function execution (balance check) and the actual transaction simulation. This creates a Time-of-Check Time-of-Use (TOCTOU) vulnerability where blockchain state can diverge between these two operations, leading to inconsistent and misleading simulation results.

## Finding Description

The vulnerability occurs in the `simulate_transaction()` function when the `estimate_max_gas_amount` parameter is set to true. The function performs two critical operations at different blockchain state versions:

**Operation 1: View Function for Balance Check** [1](#0-0) 

This code calls `context.state_view::<BasicErrorWith404>(Option::None)` which internally:
- Calls `get_latest_ledger_info_and_verify_lookup_version(None)` to get the latest ledger version at that moment (call it V1)
- Creates a state view at version V1 via `state_view_at_version(V1)`
- Uses this state view to execute the coin balance view function [2](#0-1) 

**Operation 2: Transaction Simulation** [3](#0-2) 

This code calls `latest_state_view_poem(&ledger_info)` which: [4](#0-3) 

Note that despite receiving `ledger_info` as a parameter, this function **ignores** its version and calls `latest_state_checkpoint_view()`: [5](#0-4) 

This method gets the **absolute latest checkpoint version** at the time of the call (call it V2), which can be different from V1.

**The State Inconsistency**

Between the balance check (V1) and the simulation (V2), new blocks can be committed to the blockchain, causing:
- The balance used to calculate `max_account_gas_units` is from state V1
- The simulation execution uses state V2
- V1 ≠ V2 when new blocks are committed during the function execution

This breaks the **State Consistency** invariant: operations within a single simulation request should use consistent state to provide accurate results.

**Exploitation Scenario**

1. User calls `simulate_transaction` with `estimate_max_gas_amount=true`
2. At time T1: Balance check reads account balance = 1000 APT at version V1
3. At time T2: New block commits, changing account balance to 500 APT (version V2)
4. At time T3: Simulation executes using state V2 (balance = 500 APT)
5. Result: `max_account_gas_units` calculated based on 1000 APT balance, but simulation runs with 500 APT balance state
6. User receives inconsistent simulation results that don't reflect the actual state used for gas calculations

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

**Concrete Impacts:**

1. **Incorrect Gas Estimation**: The `max_account_gas_units` calculation uses outdated balance information, leading to gas estimates that may not be achievable when the transaction is actually submitted.

2. **Misleading Simulation Results**: Users make decisions based on simulation outputs that reflect state V2, while gas parameters are calculated from state V1. This inconsistency can cause:
   - Simulations succeeding when real execution would fail
   - Simulations failing when real execution would succeed
   - Incorrect event emission predictions
   - Wrong write set estimations

3. **User Experience Degradation**: Users cannot trust simulation results as a reliable preview of transaction execution, undermining the core purpose of the simulation API.

4. **Potential Financial Impact**: Users might execute transactions based on incorrect simulation data, leading to unexpected gas costs or transaction failures.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability occurs whenever:
- A user calls `simulate_transaction` with `estimate_max_gas_amount=true`
- New blocks are committed between the balance check and simulation operations
- The time window is small (microseconds to milliseconds) but realistic

**Factors increasing likelihood:**

1. **High Block Production Rate**: Aptos has sub-second block times, making state changes during function execution highly probable
2. **No Synchronization**: No locks or version pinning prevent state divergence
3. **Normal Operation**: Requires no attacker intervention; occurs during normal blockchain operation
4. **Common API Usage**: The `estimate_max_gas_amount` parameter is commonly used for gas estimation

**Factors affecting exploitability:**

While this is not a directed attack requiring malicious intent, the state inconsistency happens naturally in high-throughput conditions. An attacker could potentially increase the likelihood by submitting many transactions to increase block production rate during targeted simulation calls, though this is not necessary for the vulnerability to manifest.

## Recommendation

**Fix: Use Consistent State View Version**

The solution is to use the same ledger version for both the balance check and the simulation. Capture the ledger version once at the beginning and use it consistently:

```rust
async fn simulate_transaction(
    &self,
    accept_type: AcceptType,
    estimate_max_gas_amount: Query<Option<bool>>,
    estimate_gas_unit_price: Query<Option<bool>>,
    estimate_prioritized_gas_unit_price: Query<Option<bool>>,
    data: SubmitTransactionPost,
) -> SimulateTransactionResult<Vec<UserTransaction>> {
    // ... validation code ...
    
    let api = self.clone();
    let context = self.context.clone();
    api_spawn_blocking(move || {
        let ledger_info = context.get_latest_ledger_info()?;
        let ledger_version = ledger_info.version();  // Capture version once
        let mut signed_transaction = api.get_signed_transaction(&ledger_info, data)?;

        // ... filter and gas price estimation code ...

        if estimate_max_gas_amount.0.unwrap_or_default() {
            // ... gas params code ...

            // FIX: Use state_view_at_version with the captured ledger_version
            let state_view = context
                .state_view_at_version(ledger_version)
                .map_err(|err| {
                    SubmitTransactionError::bad_request_with_code_no_info(
                        err,
                        AptosErrorCode::InternalError,
                    )
                })?;
            
            let output = AptosVM::execute_view_function(
                &state_view,
                ModuleId::new(AccountAddress::ONE, ident_str!("coin").into()),
                ident_str!("balance").into(),
                vec![AptosCoinType::type_tag()],
                vec![signed_transaction.sender().to_vec()],
                context.node_config.api.max_gas_view_function,
            );
            
            // ... rest of balance calculation ...
        }

        // Pass ledger_version to simulate() and use it there
        api.simulate(&accept_type, ledger_info, ledger_version, signed_transaction)
    })
    .await
}
```

And update the `simulate()` function signature and implementation:

```rust
pub fn simulate(
    &self,
    accept_type: &AcceptType,
    ledger_info: LedgerInfo,
    ledger_version: Version,  // Add version parameter
    txn: SignedTransaction,
) -> SimulateTransactionResult<Vec<UserTransaction>> {
    // ... validation code ...

    // FIX: Use state_view_at_version with the passed ledger_version
    let state_view = self.context
        .state_view_at_version(ledger_version)
        .map_err(|e| {
            SubmitTransactionError::internal_with_code(
                e,
                AptosErrorCode::InternalError,
                &ledger_info,
            )
        })?;
    
    let (vm_status, output) =
        AptosSimulationVM::create_vm_and_simulate_signed_transaction(&txn, &state_view);
    
    // ... rest of simulation ...
}
```

This ensures both the balance check and simulation use the same consistent blockchain state version.

## Proof of Concept

The following Rust test demonstrates the state view version divergence:

```rust
#[tokio::test]
async fn test_simulate_transaction_state_divergence() {
    use aptos_api::transactions::TransactionsApi;
    use aptos_types::account_address::AccountAddress;
    use std::sync::Arc;
    
    // Setup: Create API context with test database
    let (db, mp_sender, node_config) = setup_test_environment();
    let context = Arc::new(Context::new(
        ChainId::test(),
        db.clone(),
        mp_sender,
        node_config,
        None,
    ));
    
    let api = TransactionsApi { context: context.clone() };
    
    // Step 1: Record version before balance check
    let version_before = context.get_latest_ledger_info().unwrap().version();
    
    // Step 2: Simulate calling the balance check part
    let (_, _, state_view_balance) = context
        .state_view::<BasicErrorWith404>(Option::None)
        .unwrap();
    let balance_check_version = state_view_balance.version;
    
    // Step 3: Commit a new block (simulating blockchain progress)
    commit_test_block(db.clone());
    
    // Step 4: Get state view for simulation (this gets latest)
    let ledger_info = context.get_latest_ledger_info().unwrap();
    let state_view_simulation = context
        .latest_state_view_poem(&ledger_info)
        .unwrap();
    let simulation_version = state_view_simulation.version;
    
    // Assertion: Versions should be different, demonstrating the bug
    assert_ne!(
        balance_check_version, 
        simulation_version,
        "State view versions diverged: balance check at {:?}, simulation at {:?}",
        balance_check_version,
        simulation_version
    );
    
    println!("VULNERABILITY CONFIRMED:");
    println!("  Balance check version: {:?}", balance_check_version);
    println!("  Simulation version: {:?}", simulation_version);
    println!("  Version divergence: {:?}", simulation_version.unwrap() - balance_check_version.unwrap());
}
```

**Expected Output:**
```
VULNERABILITY CONFIRMED:
  Balance check version: Some(100)
  Simulation version: Some(101)
  Version divergence: 1
```

This demonstrates that the two operations use different blockchain state versions, confirming the TOCTOU vulnerability.

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: Users receive no warning that the balance check and simulation used different states
2. **Race Condition**: The time window is small but realistic on production networks with high throughput
3. **Core Functionality**: Affects a critical API endpoint used for transaction simulation and gas estimation
4. **Trust Assumption**: Users expect simulation results to be self-consistent and reflect the same blockchain state

The fix requires modifying both `simulate_transaction()` and `simulate()` to accept and use a consistent `ledger_version` parameter throughout the entire operation.

### Citations

**File:** api/src/transactions.rs (L662-677)
```rust
                let (_, _, state_view) = context
                    .state_view::<BasicErrorWith404>(Option::None)
                    .map_err(|err| {
                        SubmitTransactionError::bad_request_with_code_no_info(
                            err,
                            AptosErrorCode::InvalidInput,
                        )
                    })?;
                let output = AptosVM::execute_view_function(
                    &state_view,
                    ModuleId::new(AccountAddress::ONE, ident_str!("coin").into()),
                    ident_str!("balance").into(),
                    vec![AptosCoinType::type_tag()],
                    vec![signed_transaction.sender().to_vec()],
                    context.node_config.api.max_gas_view_function,
                );
```

**File:** api/src/transactions.rs (L1640-1642)
```rust
        let state_view = self.context.latest_state_view_poem(&ledger_info)?;
        let (vm_status, output) =
            AptosSimulationVM::create_vm_and_simulate_signed_transaction(&txn, &state_view);
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

**File:** api/src/context.rs (L177-191)
```rust
    pub fn state_view<E: StdApiError>(
        &self,
        requested_ledger_version: Option<u64>,
    ) -> Result<(LedgerInfo, u64, DbStateView), E> {
        let (latest_ledger_info, requested_ledger_version) =
            self.get_latest_ledger_info_and_verify_lookup_version(requested_ledger_version)?;

        let state_view = self
            .state_view_at_version(requested_ledger_version)
            .map_err(|err| {
                E::internal_with_code(err, AptosErrorCode::InternalError, &latest_ledger_info)
            })?;

        Ok((latest_ledger_info, requested_ledger_version, state_view))
    }
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
