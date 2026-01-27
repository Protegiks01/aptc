# Audit Report

## Title
Fee Distribution Failure Due to Missing Fee Statement Event Dependency

## Summary
A critical design flaw exists where the block epilogue fee distribution mechanism relies on extracting `FeeStatement` from emitted events, but the emission is controlled by a separate feature flag (`EMIT_FEE_STATEMENT`) that is not enforced as a dependency of the fee distribution feature flag (`CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION`). This causes proposers to receive zero fees when fee distribution is enabled but fee statement event emission is disabled.

## Finding Description

The vulnerability stems from an inconsistency in how `fee_statement()` is retrieved before and after transaction output materialization:

**Before Materialization:** [1](#0-0) 
Returns the actual `FeeStatement` directly from `VMOutput`.

**After Materialization:** [2](#0-1) 
Attempts to extract `FeeStatement` from transaction events. If the event is not found, it returns `FeeStatement::zero()`.

The critical issue is that fee statement events are only emitted when the feature flag is enabled: [3](#0-2) 

However, `VMOutput` only stores `gas_used` when converting to `TransactionOutput`: [4](#0-3) 

The full `FeeStatement` details (execution gas, IO gas, storage fees) are lost unless emitted as an event.

During block epilogue generation, the system uses the after-materialization fee statement to calculate fee distribution to proposers: [5](#0-4) 

**The Attack Scenario:**
When `CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION` (flag 96) is enabled but `EMIT_FEE_STATEMENT` (flag 27) is disabled:
1. Users pay correct fees (burned during epilogue based on gas_used calculation)
2. Block gas limits are validated correctly (using before-materialization fee_statement)
3. After materialization returns `FeeStatement::zero()` because no event was emitted
4. `total_gas_unit = 0` and `storage_fee_used() = 0`
5. Proposers receive ZERO fees in the block epilogue distribution

## Impact Explanation

**Severity: HIGH (not Critical)**

This does **NOT** qualify as Critical because:
- Users still pay the correct fees (no theft or minting)
- No consensus divergence occurs (all validators follow same on-chain feature flags)
- The vulnerability described in the security question (attackers committing with lower fees) does not exist

However, it qualifies as **HIGH** severity because:
- Validator proposers lose their legitimate fee rewards
- It represents a significant protocol violation affecting economic incentives
- It breaks the staking security invariant: "Validator rewards must be calculated correctly"

## Likelihood Explanation

**Likelihood: LOW**

This requires:
1. On-chain governance to enable `CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION` 
2. While keeping `EMIT_FEE_STATEMENT` disabled
3. This configuration violates implicit assumptions but is technically possible
4. Not exploitable by unprivileged attackers as feature flags are controlled by governance

## Recommendation

Add explicit feature flag dependency enforcement:

```rust
pub fn is_calculate_transaction_fee_for_distribution_enabled(&self) -> bool {
    // Requires emit fee statement to function correctly
    self.is_emit_fee_statement_enabled() 
        && self.is_enabled(FeatureFlag::CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION)
}
```

Alternatively, modify the after-materialization implementation to fall back to `TransactionOutput.gas_used()` instead of zero when event extraction fails, and document that storage fee breakdown won't be available without the event.

## Proof of Concept

This vulnerability cannot be directly exploited by attackers as it requires governance-controlled feature flag configuration. However, a reproduction scenario would be:

1. Enable `CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION` via governance
2. Ensure `EMIT_FEE_STATEMENT` is disabled
3. Execute a block with user transactions
4. Observe block epilogue shows zero fee distribution to proposers
5. Verify users' accounts were still correctly debited

**Note:** While this represents a design flaw and protocol violation, it does NOT match the vulnerability described in the security question (attackers paying lower fees than validated), as users always pay the correct amount regardless of feature flag configuration.

### Citations

**File:** aptos-move/aptos-vm/src/block_executor/mod.rs (L106-111)
```rust
    fn fee_statement(&self) -> FeeStatement {
        if let Ok(Some(fee_statement)) = self.output.try_extract_fee_statement() {
            return fee_statement;
        }
        FeeStatement::zero()
    }
```

**File:** aptos-move/aptos-vm/src/block_executor/mod.rs (L123-126)
```rust
impl BeforeMaterializationOutput<SignatureVerifiedTransaction> for BeforeMaterializationGuard<'_> {
    fn fee_statement(&self) -> FeeStatement {
        *self.guard.fee_statement()
    }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L590-593)
```rust
    // Emit the FeeStatement event
    if features.is_emit_fee_statement_enabled() {
        emit_fee_statement(session, module_storage, fee_statement, traversal_context)?;
    }
```

**File:** aptos-move/aptos-vm-types/src/output.rs (L212-218)
```rust
        Ok(TransactionOutput::new(
            write_set,
            events,
            fee_statement.gas_used(),
            status,
            TransactionAuxiliaryData::default(),
        ))
```

**File:** aptos-move/block-executor/src/executor.rs (L2049-2069)
```rust
            let output_after_guard = output.after_materialization()?;
            let fee_statement = output_after_guard.fee_statement();

            let txn = signature_verified_block.get_txn(i as TxnIndex);
            if let Some(user_txn) = txn.try_as_signed_user_txn() {
                let auxiliary_info = signature_verified_block.get_auxiliary_info(i as TxnIndex);
                if let Some(proposer_index) = auxiliary_info.proposer_index() {
                    let gas_price = user_txn.gas_unit_price();
                    let total_gas_unit = fee_statement.gas_used();
                    // Total gas unit here includes the storage fee (deposit), which is not
                    // available for distribution. Only the execution gas and IO gas are available
                    // to distribute. Note here we deliberately NOT use the execution gas and IO
                    // gas value from the fee statement, because they might round up during the
                    // calculation and the sum of them could be larger than the actual value we
                    // burn. Instead we use the total amount (which is the total we've burnt)
                    // minus the storage deposit (round up), to avoid over distribution.
                    // We burn a fix amount of gas per gas unit.
                    let gas_price_to_burn = self.config.onchain.gas_price_to_burn();
                    if gas_price > gas_price_to_burn {
                        let gas_unit_available_to_distribute = total_gas_unit
                            .saturating_sub(fee_statement.storage_fee_used().div_ceil(gas_price));
```
