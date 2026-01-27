# Audit Report

## Title
Misleading Transaction Status Reporting in Chunked Package Publishing Hides Failed Staging Transactions

## Summary
The `submit_chunked_publish_transactions()` function incorrectly reports overall success when individual staging transactions fail during VM execution. Failed transactions (with `success: false`) are added to the `tx_hashes` vector without differentiation, and the function returns only the last transaction's result, potentially hiding critical failures in the chunked publish flow.

## Finding Description
The vulnerability exists in the transaction result handling logic within `submit_chunked_publish_transactions()`. [1](#0-0) 

When `dispatch_transaction` returns `Ok(tx_summary)`, the code unconditionally:
1. Adds the transaction hash to `tx_hashes` vector (line 1731) regardless of the `success` field value
2. Overwrites `publishing_result` with the current result (line 1732)
3. Continues to the next transaction

This means if transaction 2 of 5 has `success: Some(false)` (VM execution failed but transaction was committed), its hash is added to `tx_hashes`, and subsequent successful transactions overwrite the failure result.

The function then prints a misleading success message: [2](#0-1) 

And returns only the **last** transaction's result (line 1758), hiding any failures that occurred in earlier transactions.

**Why `success: false` can occur in `Ok(tx_summary)`:**

The `submit_transaction` function can return `Ok(Transaction)` even when VM execution fails. When `max_gas` is explicitly set, simulation is completely bypassed: [3](#0-2) 

After transaction submission, the function waits for commitment but performs **no validation** of the execution success status: [4](#0-3) 

It simply returns `Ok(response.into_inner())` regardless of whether `transaction.info.success` is `true` or `false`.

**Attack Scenario:**
1. User publishes a large Move package using `--chunked-publish` with `--max-gas` set
2. Transaction 3 of 7 fails during VM execution (e.g., due to resource constraints, state invariant violations, or invalid code)
3. The transaction is committed on-chain with `success: false`, meaning no code was staged
4. Transactions 4-7 succeed, overwriting the failure result
5. CLI prints "All Transactions Submitted Successfully" 
6. Function returns success based on transaction 7
7. User believes all code chunks were staged successfully
8. `StagingArea` resource contains incomplete data with missing code chunk 3
9. Subsequent operations fail unexpectedly, or worse, if the final publish transaction uses flawed validation logic, corrupted code could be deployed

## Impact Explanation
This vulnerability meets **Medium severity** criteria under "State inconsistencies requiring intervention":

1. **State Inconsistency**: The `StagingArea` resource is left with incomplete data, requiring manual cleanup via `aptos move clear-staging-area` [5](#0-4) 

2. **Misleading User Feedback**: Users and automated tooling receive incorrect success signals, potentially leading to:
   - Deployment of incomplete/corrupted Move modules
   - Confusion about package deployment status
   - Wasted gas on failed retry attempts
   - Difficulty debugging due to hidden failures

3. **Potential Funds Loss**: If corrupted code is deployed (though Move framework validation should prevent this), it could lead to limited funds loss through malfunctioning smart contracts.

The issue does NOT meet Critical/High severity because:
- It doesn't directly cause consensus violations
- Move framework validation during `assemble_module_code` should catch missing chunks
- Individual transaction status is printed to console (though easily missed)

## Likelihood Explanation
**Likelihood: Medium**

This vulnerability occurs when:
1. User explicitly sets `--max-gas` (bypassing simulation) - **Common** for experienced users optimizing gas costs
2. A staging transaction fails during VM execution - **Possible** under resource constraints, state changes, or code validation failures
3. Subsequent transactions succeed - **Likely** if only one chunk has issues

The combination is realistic and doesn't require sophisticated attack techniques. Any user publishing large packages in chunked mode is potentially affected.

## Recommendation
Implement aggregate validation to ensure ALL transactions succeeded before reporting overall success:

```rust
async fn submit_chunked_publish_transactions(
    payloads: Vec<TransactionPayload>,
    txn_options: &TransactionOptions,
    large_packages_module_address: AccountAddress,
) -> CliTypedResult<TransactionSummary> {
    let mut publishing_result = Err(CliError::UnexpectedError(
        "No payload provided for batch transaction run".to_string(),
    ));
    let payloads_length = payloads.len() as u64;
    let mut tx_hashes = vec![];
    let mut failed_txns = vec![]; // Track failed transactions

    let (_, account_address) = txn_options.get_public_key_and_address()?;

    // ... (existing staging area check) ...

    for (idx, payload) in payloads.into_iter().enumerate() {
        println!("Transaction {} of {}", idx + 1, payloads_length);
        let result = dispatch_transaction(payload, txn_options).await;

        match result {
            Ok(tx_summary) => {
                let tx_hash = tx_summary.transaction_hash.to_string();
                let success = tx_summary.success.unwrap_or(false);
                let status = if success {
                    "Success".to_string()
                } else {
                    "Failed".to_string()
                };
                println!("Transaction executed: {} ({})\n", status, &tx_hash);
                tx_hashes.push(tx_hash.clone());
                
                // Track failures
                if !success {
                    failed_txns.push((idx + 1, tx_hash));
                }
                
                publishing_result = Ok(tx_summary);
            },
            Err(e) => {
                println!("{}", "Caution: An error occurred...".bold());
                return Err(e);
            },
        }
    }

    // Check for any failed transactions
    if !failed_txns.is_empty() {
        let failed_list = failed_txns
            .iter()
            .map(|(idx, hash)| format!("  - Transaction {}: {}", idx, hash))
            .join("\n");
        return Err(CliError::UnexpectedError(format!(
            "Chunked publish failed. The following transactions failed during VM execution:\n{}\n\
            The StagingArea may contain incomplete data. Use `aptos move clear-staging-area` to clean up.",
            failed_list
        )));
    }

    println!(
        "{}",
        "All Transactions Executed Successfully.".bold().green()
    );
    // ... (existing hash formatting) ...
    publishing_result
}
```

**Key changes:**
1. Track failed transactions in a separate vector
2. Check aggregate success before printing success message
3. Return error if ANY transaction failed with detailed failure information
4. Change message to "All Transactions Executed Successfully" for accuracy

## Proof of Concept

```rust
// Reproduction steps (pseudo-code for integration test):

#[tokio::test]
async fn test_chunked_publish_hides_failures() {
    // Setup: Create a large package that will be chunked into 5 transactions
    let package = create_large_test_package();
    
    // Configure transaction options with max_gas set (bypass simulation)
    let txn_options = TransactionOptions {
        max_gas: Some(100000),
        // ... other options
    };
    
    // Mock dispatch_transaction to simulate failure on transaction 3
    // Transaction 1: Success
    // Transaction 2: Success  
    // Transaction 3: Ok(tx_summary { success: Some(false), ... })  <- VM execution failed
    // Transaction 4: Success
    // Transaction 5: Success
    
    let result = submit_chunked_publish_transactions(
        chunked_payloads,
        &txn_options,
        large_packages_module_address,
    ).await;
    
    // BUG: Function returns Ok(tx_summary_5) instead of error
    assert!(result.is_ok()); // This passes but shouldn't!
    
    // The tx_hashes vector contains all 5 hashes including the failed one
    // with no differentiation
    
    // User sees "All Transactions Submitted Successfully" message
    // despite transaction 3 failing
    
    // StagingArea is incomplete, missing code chunk 3
    // Subsequent package usage will fail unexpectedly
}
```

**Notes:**
- This vulnerability is a real implementation flaw in transaction result aggregation
- While individual transaction failures are printed to console, automated tooling and the final return value hide the aggregate failure status
- The misleading "All Transactions Submitted Successfully" message compounds the issue
- State inconsistency requires manual intervention to resolve via cleanup commands

### Citations

**File:** crates/aptos/src/move_tool/mod.rs (L1704-1714)
```rust
    if !is_staging_area_empty(txn_options, large_packages_module_address).await? {
        let message = format!(
            "The resource {}::large_packages::StagingArea under account {} is not empty.\
        \nThis may cause package publishing to fail if the data is unexpected. \
        \nUse the `aptos move clear-staging-area` command to clean up the `StagingArea` resource under the account.",
            large_packages_module_address, account_address,
        )
            .bold();
        println!("{}", message);
        prompt_yes_with_override("Do you want to proceed?", txn_options.prompt_options)?;
    }
```

**File:** crates/aptos/src/move_tool/mod.rs (L1720-1733)
```rust
        match result {
            Ok(tx_summary) => {
                let tx_hash = tx_summary.transaction_hash.to_string();
                let status = tx_summary.success.map_or_else(String::new, |success| {
                    if success {
                        "Success".to_string()
                    } else {
                        "Failed".to_string()
                    }
                });
                println!("Transaction executed: {} ({})\n", status, &tx_hash);
                tx_hashes.push(tx_hash);
                publishing_result = Ok(tx_summary);
            },
```

**File:** crates/aptos/src/move_tool/mod.rs (L1745-1758)
```rust
    println!(
        "{}",
        "All Transactions Submitted Successfully.".bold().green()
    );
    let tx_hash_formatted = format!(
        "Submitted Transactions:\n[\n    {}\n]",
        tx_hashes
            .iter()
            .map(|tx| format!("\"{}\"", tx))
            .collect::<Vec<_>>()
            .join(",\n    ")
    );
    println!("\n{}\n", tx_hash_formatted);
    publishing_result
```

**File:** crates/aptos/src/common/types.rs (L1979-1985)
```rust
        let max_gas = if let Some(max_gas) = self.gas_options.max_gas {
            // If the gas unit price was estimated ask, but otherwise you've chosen hwo much you want to spend
            if ask_to_confirm_price {
                let message = format!("Do you want to submit transaction for a maximum of {} Octas at a gas unit price of {} Octas?",  max_gas * gas_unit_price, gas_unit_price);
                prompt_yes_with_override(&message, self.prompt_options)?;
            }
            max_gas
```

**File:** crates/aptos/src/common/types.rs (L2117-2122)
```rust
        let response = client
            .wait_for_signed_transaction(&transaction)
            .await
            .map_err(|err| CliError::ApiError(err.to_string()))?;

        Ok(response.into_inner())
```
