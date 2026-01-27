# Audit Report

## Title
Missing Zero-Sum Validation in Fee Distribution Allows Silent Fee Accounting Discrepancies

## Summary
The Aptos fee distribution system lacks critical validation to ensure that fees distributed to validators equal the fees collected from transactions. While a malicious proposer cannot directly exploit this due to deterministic block execution, the absence of this invariant check creates a systemic risk where calculation bugs could silently result in missing or minted funds without detection.

## Finding Description

The fee distribution flow in Aptos consists of three stages:

1. **Fee Collection**: During transaction execution, the epilogue burns fees from users [1](#0-0) 

2. **Fee Distribution Calculation**: The block executor calculates distributable fees using complex rounding logic [2](#0-1) 

3. **Fee Recording**: The Move framework records distributed fees to validator pending balances [3](#0-2) 

**Critical Missing Validation**: There is no check at any stage that verifies:
```
sum(fee_amounts_octa) == total_fees_burned - total_fees_to_burn
```

The `record_fee` function only validates vector length matching: [4](#0-3) 

The `gen_block_epilogue` calculation uses `saturating_sub` and `div_ceil` operations that introduce rounding, with an explicit comment acknowledging potential precision loss: [5](#0-4) 

**Why the Question's Premise is Incorrect**: A malicious proposer cannot directly create arbitrary `FeeDistribution` values because:
- Each validator independently computes the block epilogue during execution [6](#0-5) 
- The calculation is deterministic based on transaction outputs
- Validators would produce different state roots if epilogue transactions differed

## Impact Explanation

**Severity: Medium** 

This does not meet Critical severity criteria because there is no direct attack path for a malicious proposer to exploit this. However, it represents a significant protocol vulnerability:

1. **Undetectable Fee Loss**: If the calculation logic has bugs (e.g., off-by-one errors in rounding), fees could be under-distributed, resulting in permanent loss of funds that should have gone to validators.

2. **Undetectable Fee Minting**: Conversely, over-distribution bugs would mint tokens from nowhere, inflating supply.

3. **Consensus Risk**: If the calculation is non-deterministic in edge cases, different validators might compute different `FeeDistribution` values, causing consensus divergence.

4. **No Recovery Mechanism**: Without validation, there's no way to detect these discrepancies in production, and no mechanism to recover lost funds.

The impact is classified as "Limited funds loss or manipulation" and "State inconsistencies requiring intervention" per the Medium severity category.

## Likelihood Explanation

**Likelihood: Low to Medium**

This is not directly exploitable but could occur through:
- Calculation bugs in the complex rounding logic
- Integer overflow in fee accumulation (though `saturating_sub` mitigates this)
- Future code changes that introduce non-determinism

The likelihood increases over time as the codebase evolves without this invariant check acting as a safety net.

## Recommendation

Implement a zero-sum validation in the block epilogue processing:

**In Rust (`aptos-move/block-executor/src/executor.rs`):**
```rust
fn gen_block_epilogue(...) -> Result<T, PanicError> {
    let mut amount = BTreeMap::new();
    let mut total_distributed = 0u64;
    let mut total_burned = 0u64;
    
    for (i, output) in outputs.enumerate().take(epilogue_txn_idx as usize) {
        if !output.is_materialized_and_success() { continue; }
        
        let output_after_guard = output.after_materialization()?;
        let fee_statement = output_after_guard.fee_statement();
        
        // Track total burned (excluding storage refunds)
        let transaction_fee = gas_price * fee_statement.gas_used();
        total_burned += transaction_fee.saturating_sub(fee_statement.storage_fee_refund_octas());
        
        // Calculate distributable (existing logic)
        if let Some(proposer_index) = auxiliary_info.proposer_index() {
            let fee_to_distribute = /* existing calculation */;
            total_distributed += fee_to_distribute;
            *amount.entry(proposer_index).or_insert(0) += fee_to_distribute;
        }
    }
    
    // Validate zero-sum property (allowing for burn_percentage)
    let expected_distributed = total_burned.saturating_sub(
        total_burned * gas_price_to_burn / gas_price
    );
    
    assert!(
        total_distributed <= expected_distributed,
        "Fee distribution exceeds collected fees: distributed={}, expected_max={}",
        total_distributed, expected_distributed
    );
    
    Ok(T::block_epilogue_v1(block_id, block_end_info, FeeDistribution::new(amount)))
}
```

**In Move (`aptos-framework/sources/block.move`):**
Add a validation parameter to track expected total fees, though this requires protocol changes.

## Proof of Concept

This vulnerability cannot be demonstrated with a traditional exploit PoC because it's a missing validation rather than an exploitable bug. However, the following test would demonstrate the lack of validation:

```rust
#[test]
fn test_missing_fee_distribution_validation() {
    // Create a FeeDistribution with arbitrary amounts
    let mut amount = BTreeMap::new();
    amount.insert(0, 1000000); // 1 APT to validator 0
    amount.insert(1, 2000000); // 2 APT to validator 1
    // Total distributed: 3 APT
    
    let fee_dist = FeeDistribution::new(amount);
    
    // In a real scenario, if only 2 APT was actually burned,
    // this 1 APT discrepancy would go undetected
    // The system has no validation to catch this mismatch
    
    // Expected: Should fail if sum(distributed) != sum(collected)
    // Actual: Passes silently, allowing fee accounting errors
}
```

## Notes

While the security question's premise about a "malicious proposer" creating arbitrary `FeeDistribution` is incorrect due to Aptos's deterministic execution model, the underlying concern about missing zero-sum validation is valid. This represents a defense-in-depth failure that could mask calculation bugs and result in silent fund loss or minting. The validation should be added as a protocol-level invariant check to ensure fee accounting integrity.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L620-622)
```text
            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer, burn_amount);
```

**File:** aptos-move/block-executor/src/executor.rs (L2055-2078)
```rust
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
                        if gas_unit_available_to_distribute > 0 {
                            let fee_to_distribute =
                                gas_unit_available_to_distribute * (gas_price - gas_price_to_burn);
                            *amount.entry(proposer_index).or_insert(0) += fee_to_distribute;
                        }
                    }
                }
            }
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L2519-2526)
```rust
                        block_epilogue_txn = Some(self.gen_block_epilogue(
                            block_id,
                            signature_verified_block,
                            ret.iter(),
                            idx as TxnIndex,
                            block_limit_processor.get_block_end_info(),
                            module_cache_manager_guard.environment().features(),
                        )?);
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L616-635)
```text
    public(friend) fun record_fee(
        vm: &signer,
        fee_distribution_validator_indices: vector<u64>,
        fee_amounts_octa: vector<u64>,
    ) acquires PendingTransactionFee {
        // Operational constraint: can only be invoked by the VM.
        system_addresses::assert_vm(vm);

        assert!(fee_distribution_validator_indices.length() == fee_amounts_octa.length());

        let num_validators_to_distribute = fee_distribution_validator_indices.length();
        let pending_fee = borrow_global_mut<PendingTransactionFee>(@aptos_framework);
        let i = 0;
        while (i < num_validators_to_distribute) {
            let validator_index = fee_distribution_validator_indices[i];
            let fee_octa = fee_amounts_octa[i];
            pending_fee.pending_fee_by_validator.borrow_mut(&validator_index).add(fee_octa);
            i = i + 1;
        }
    }
```
