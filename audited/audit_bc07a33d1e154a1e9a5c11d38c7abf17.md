# Audit Report

## Title
State View Version Mismatch in Transaction Simulation API

## Summary
The `simulate_transaction()` function in `api/src/transactions.rs` captures the `ledger_info` version at one point in time but later uses `latest_state_checkpoint_view()` to obtain a state view, which may be at a different version. This causes the simulation to execute against one state version while reporting results as if they were generated at another version, leading to inconsistent and potentially misleading simulation results.

## Finding Description

The vulnerability exists in the transaction simulation flow spanning two functions:

1. In `simulate_transaction()` [1](#0-0) , the code captures the current ledger info with its version V1.

2. After potentially time-consuming operations (transaction parsing, filter checks, gas estimation including view function execution) [2](#0-1) , the code calls the `simulate()` function.

3. Within `simulate()` [3](#0-2) , the code calls `latest_state_view_poem(&ledger_info)` which internally invokes `latest_state_checkpoint_view()` [4](#0-3) .

4. The `latest_state_checkpoint_view()` implementation [5](#0-4)  retrieves the **latest** state checkpoint version from the database at the time of the call, which may be version V2 where V2 ≠ V1.

5. The simulation executes using state at version V2 [6](#0-5) , but the response tags the result with version V1 [7](#0-6) .

The blockchain can advance between step 1 and step 3 because the operations are not atomic. Additionally, state checkpoint versions can lag behind ledger versions [8](#0-7) , creating further version discrepancy.

**Contrast with Correct Implementation:**

Other API endpoints correctly use versioned state views. For example, the account resource retrieval explicitly uses `state_view(Some(self.ledger_version))` [9](#0-8) , which internally calls `state_view_at_version(requested_ledger_version)` [10](#0-9)  to ensure the state view matches the requested version.

## Impact Explanation

This qualifies as **Medium** severity under the Aptos bug bounty program criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**

1. **Incorrect Gas Estimation**: If gas parameters, account balances, or gas schedules change between V1 and V2, the gas estimation will be wrong. Users may under-estimate gas (causing transaction failure) or over-estimate (paying unnecessarily).

2. **Transaction Outcome Divergence**: If module code, resource values, or contract state changes between V1 and V2, the simulation may succeed while actual execution fails (or vice versa). This breaks the fundamental guarantee that simulations predict actual execution.

3. **API Contract Violation**: The API response claims the simulation was performed at version V1, but it actually used V2. This violates client expectations and can lead to incorrect automated decision-making by wallets, DeFi protocols, or other integrators.

4. **Timing-Dependent Behavior**: During high blockchain activity (frequent block production), the window between capturing ledger_info and state_view widens, making the issue more likely to manifest. The view function execution during gas estimation [11](#0-10)  can take significant time, increasing the race window.

While this does not directly lead to consensus violations or immediate fund loss, it creates state inconsistencies in the API layer that can cause users to make incorrect financial decisions based on misleading simulation results.

## Likelihood Explanation

**High Likelihood** - This issue occurs naturally during normal blockchain operation:

1. **Continuous Block Production**: Aptos has sub-second block times, meaning the blockchain frequently advances during API request processing.

2. **Long-Running Operations**: The simulation pipeline includes transaction parsing, validation, filter checks, and potentially complex view function execution for gas estimation, creating a multi-millisecond window for blockchain advancement.

3. **No Synchronization**: The code has no locks or synchronization to ensure the ledger_info version and state_view version match.

4. **Checkpoint Lag**: State checkpoints naturally lag behind the ledger version, creating an additional source of version mismatch even without blockchain advancement.

The issue does not require attacker action - it happens during legitimate API usage on any live network with active block production.

## Recommendation

**Fix**: Modify the `simulate()` function to use a state view at the specific ledger_info version instead of the latest checkpoint:

Change the state view acquisition from: [3](#0-2) 

To use the same pattern as account resource reads: [12](#0-11) 

This ensures the simulation executes against state at exactly the version claimed in the response, maintaining API consistency and matching the pattern used correctly in other endpoints.

## Proof of Concept

**Reproduction Steps:**

1. Deploy a test network with fast block production (e.g., 500ms block time)
2. Submit a simulation request with `estimate_max_gas_amount=true` (triggers view function execution for gas estimation)
3. Use a transaction that queries a frequently-updated resource
4. Monitor the versions: `ledger_info.version()` at capture time vs `state_checkpoint_version()` at simulation time
5. Observe version mismatch in responses during high blockchain activity

**Expected Outcome**: The simulation response will show version V1 in the ledger_info, but the simulation actually executed against state at version V2, where V2 > V1 or V2 < V1 depending on checkpoint lag and blockchain advancement.

**Validation**: Compare the gas estimates and transaction outcomes between:
- Simulation at claimed version V1
- Actual simulation execution (using V2)
- Real execution at time of submission (using V3)

The divergence demonstrates that simulation results do not accurately reflect the state version they claim to represent.

## Notes

This issue affects all simulation API calls and becomes more pronounced during:
- High transaction throughput periods
- Complex transactions requiring extensive validation
- Simulations with gas estimation enabled (which executes view functions)
- Networks with aggressive pruning where checkpoint lag is more significant

The fix should be implemented to maintain API consistency and ensure simulation results accurately represent the state version claimed in responses, matching the correct pattern already used in other API endpoints like account resource retrieval.

### Citations

**File:** api/src/transactions.rs (L616-616)
```rust
            let ledger_info = context.get_latest_ledger_info()?;
```

**File:** api/src/transactions.rs (L617-725)
```rust
            let mut signed_transaction = api.get_signed_transaction(&ledger_info, data)?;

            // Confirm the API simulation filter allows the transaction
            let api_filter = &context.node_config.transaction_filters.api_filter;
            if api_filter.is_enabled()
                && !api_filter
                    .transaction_filter()
                    .allows_transaction(&signed_transaction)
            {
                return Err(SubmitTransactionError::forbidden_with_code(
                    "Transaction not allowed by simulation filter",
                    AptosErrorCode::InvalidInput,
                    &ledger_info,
                ));
            }

            let estimated_gas_unit_price = match (
                estimate_gas_unit_price.0.unwrap_or_default(),
                estimate_prioritized_gas_unit_price.0.unwrap_or_default(),
            ) {
                (_, true) => {
                    let gas_estimation = context.estimate_gas_price(&ledger_info)?;
                    // The prioritized gas estimate should always be set, but if it's not use the gas estimate
                    Some(
                        gas_estimation
                            .prioritized_gas_estimate
                            .unwrap_or(gas_estimation.gas_estimate),
                    )
                },
                (true, false) => Some(context.estimate_gas_price(&ledger_info)?.gas_estimate),
                (false, false) => None,
            };

            // If estimate max gas amount is provided, we will just make it the maximum value
            let estimated_max_gas_amount = if estimate_max_gas_amount.0.unwrap_or_default() {
                // Retrieve max possible gas units
                let (_, gas_params) = context.get_gas_schedule(&ledger_info)?;
                let min_number_of_gas_units =
                    u64::from(gas_params.vm.txn.min_transaction_gas_units)
                        / u64::from(gas_params.vm.txn.gas_unit_scaling_factor);
                let max_number_of_gas_units =
                    u64::from(gas_params.vm.txn.maximum_number_of_gas_units);

                // Retrieve account balance to determine max gas available, right now this is using
                // a view function, but we may want to re-evaluate this based on performance
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
                let values = output.values.map_err(|status| {
                    let (err_string, vm_error_code) =
                        convert_view_function_error(&status, &state_view, &context);
                    SubmitTransactionError::bad_request_with_optional_vm_status_and_ledger_info(
                        anyhow::anyhow!(err_string),
                        AptosErrorCode::InvalidInput,
                        vm_error_code,
                        Some(&ledger_info),
                    )
                })?;
                let balance: u64 = bcs::from_bytes(&values[0]).map_err(|err| {
                    SubmitTransactionError::bad_request_with_code_no_info(
                        err,
                        AptosErrorCode::InvalidInput,
                    )
                })?;

                let gas_unit_price =
                    estimated_gas_unit_price.unwrap_or_else(|| signed_transaction.gas_unit_price());

                // With 0 gas price, we set it to max gas units, since we can't divide by 0
                let max_account_gas_units = if gas_unit_price == 0 {
                    balance
                } else {
                    balance / gas_unit_price
                };

                // To give better error messaging, we should not go below the minimum number of gas units
                let max_account_gas_units =
                    std::cmp::max(min_number_of_gas_units, max_account_gas_units);

                // Minimum of the max account and the max total needs to be used for estimation
                Some(std::cmp::min(
                    max_account_gas_units,
                    max_number_of_gas_units,
                ))
            } else {
                None
            };

            // If there is an estimation of either, replace the values
            if estimated_max_gas_amount.is_some() || estimated_gas_unit_price.is_some() {
                signed_transaction = override_gas_parameters(
                    &signed_transaction,
                    estimated_max_gas_amount,
                    estimated_gas_unit_price,
                );
            }
```

**File:** api/src/transactions.rs (L1640-1640)
```rust
        let state_view = self.context.latest_state_view_poem(&ledger_info)?;
```

**File:** api/src/transactions.rs (L1641-1642)
```rust
        let (vm_status, output) =
            AptosSimulationVM::create_vm_and_simulate_signed_transaction(&txn, &state_view);
```

**File:** api/src/transactions.rs (L1643-1643)
```rust
        let version = ledger_info.version();
```

**File:** api/src/context.rs (L164-165)
```rust
        self.db
            .latest_state_checkpoint_view()
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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L812-819)
```rust
    fn get_latest_state_checkpoint_version(&self) -> Result<Option<Version>> {
        gauged_api("get_latest_state_checkpoint_version", || {
            Ok(self
                .state_store
                .current_state_locked()
                .last_checkpoint()
                .version())
        })
```

**File:** api/src/accounts.rs (L658-659)
```rust
        let (ledger_info, requested_ledger_version, state_view) =
            self.context.state_view(Some(self.ledger_version))?;
```
