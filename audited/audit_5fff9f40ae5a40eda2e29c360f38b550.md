# Audit Report

## Title
Rosetta API Input Validation Vulnerability: Negative Deposit Values Bypass Validation Leading to Integer Wrapping

## Summary
The `Transfer::extract_transfer()` function in the Aptos Rosetta API implementation fails to validate that deposit amounts must be positive, allowing negative i128 values to pass validation and wrap to extremely large u64 values during the cast at line 2919. However, this does not lead to exploitable fund theft due to on-chain balance checks.

## Finding Description

The vulnerability exists in the transfer amount validation logic: [1](#0-0) 

The function parses withdraw and deposit amounts as i128 values, then validates that they are negatives of each other. However, it only checks if `deposit_value > u64::MAX` but does NOT check if `deposit_value < 0`.

Per the Rosetta specification, withdraw operations should have negative amounts and deposit operations should have positive amounts: [2](#0-1) 

**Attack Scenario:**
An attacker provides operations with swapped signs:
- `withdraw_amount.value = "100"` (positive instead of negative)
- `deposit_amount.value = "-100"` (negative instead of positive)

Validation steps:
1. `withdraw_value = 100`, `deposit_value = -100`
2. Check: `-withdraw_value != deposit_value` → `-100 != -100` → false (passes ✓)
3. Check: `deposit_value > u64::MAX` → `-100 > u64::MAX` → false (passes ✓)
4. Cast: `deposit_value as u64` → `-100` wraps to `18446744073709551516` (≈184 billion APT)

The malformed transfer is then passed to the blockchain: [3](#0-2) 

## Impact Explanation

**Initial Assessment: Appears Critical**
The vulnerability allows an attacker to specify a small transfer amount (100) that gets validated but then wraps to an enormous amount (≈184 billion APT) in the actual transaction payload.

**Reality: Low/No Impact**
However, this does NOT result in actual fund theft because:
1. The transaction is submitted to the blockchain with the wrapped amount
2. On-chain validation enforces sender balance checks
3. The transaction fails during execution since no account has ≈184 billion APT
4. No funds are stolen or lost

**Regarding the Original Question:**
The security question asks: "Can deposit_value as u64 at line 2919 silently truncate large i128 values, causing transfer amounts to be **smaller** than intended?"

**Answer: NO** - The actual behavior is the opposite:
- Large positive values (>u64::MAX) ARE checked and rejected at line 2913
- Negative values are NOT checked, causing wrapping to LARGER values, not smaller
- The vulnerability makes amounts larger (not smaller), but on-chain checks prevent exploitation

This is a **validation bug** violating the Rosetta API specification, but does not meet **Medium severity or higher** impact criteria from the bug bounty program as no funds can actually be lost.

## Likelihood Explanation
**High likelihood** of the validation being bypassed by malicious input, but **zero likelihood** of actual exploitation for fund theft due to defense-in-depth from on-chain balance validation.

## Recommendation
Add explicit validation that deposit_value must be non-negative:

```rust
// After line 2902, add:
if deposit_value < 0 {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Deposit amount must be positive",
    )));
}

// Or alternatively, check the range:
if deposit_value < 0 || deposit_value > u64::MAX as i128 {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Transfer amount must be between 0 and u64::MAX",
    )));
}
```

## Proof of Concept

```rust
#[test]
fn test_negative_deposit_bypass() {
    use crate::types::objects::{Operation, Transfer, Amount, Currency};
    use crate::RosettaContext;
    
    let mut operations = vec![
        Operation {
            operation_identifier: OperationIdentifier { index: 0 },
            operation_type: "withdraw".to_string(),
            status: None,
            account: Some(AccountIdentifier::base_account(sender)),
            amount: Some(Amount {
                value: "100".to_string(),  // Positive (should be negative)
                currency: native_coin(),
            }),
            metadata: None,
        },
        Operation {
            operation_identifier: OperationIdentifier { index: 1 },
            operation_type: "deposit".to_string(),
            status: None,
            account: Some(AccountIdentifier::base_account(receiver)),
            amount: Some(Amount {
                value: "-100".to_string(),  // Negative (should be positive)
                currency: native_coin(),
            }),
            metadata: None,
        },
    ];
    
    let result = Transfer::extract_transfer(&server_context, &operations);
    // This should fail but currently passes validation
    assert!(result.is_ok());
    let transfer = result.unwrap();
    // Amount wraps to approximately 18446744073709551516
    assert_eq!(transfer.amount.0, 18446744073709551516u64);
}
```

---

**Notes:**
While this is a genuine validation bug that should be fixed, it does **not** meet the security impact threshold for a valid bug bounty submission because:
1. The original question asks about truncation causing SMALLER amounts (which is prevented by the existing check)
2. The actual bug causes LARGER amounts (via wrapping), but cannot be exploited due to on-chain validation
3. No funds can be stolen, no consensus issues arise, and no state corruption occurs
4. Impact level is below Medium severity criteria

The defense-in-depth provided by on-chain balance checks ensures this remains a code quality issue rather than a critical security vulnerability.

### Citations

**File:** crates/aptos-rosetta/src/types/objects.rs (L324-342)
```rust
    pub fn withdraw(
        operation_index: u64,
        status: Option<OperationStatusType>,
        account: AccountIdentifier,
        currency: Currency,
        amount: u64,
    ) -> Operation {
        Operation::new(
            OperationType::Withdraw,
            operation_index,
            status,
            account,
            Some(Amount {
                value: format!("-{}", amount),
                currency,
            }),
            None,
        )
    }
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2641-2650)
```rust
            InternalOperation::Transfer(transfer) => {
                // Check if the currency is known
                let currency = &transfer.currency;

                // We special case APT, because we don't want the behavior to change
                if currency == &native_coin() {
                    return Ok((
                        aptos_stdlib::aptos_account_transfer(transfer.receiver, transfer.amount.0),
                        transfer.sender,
                    ));
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2899-2919)
```rust
        let withdraw_value = i128::from_str(&withdraw_amount.value)
            .map_err(|_| ApiError::InvalidTransferOperations(Some("Withdraw amount is invalid")))?;
        let deposit_value = i128::from_str(&deposit_amount.value)
            .map_err(|_| ApiError::InvalidTransferOperations(Some("Deposit amount is invalid")))?;

        // We can't create or destroy coins, they must be negatives of each other
        if -withdraw_value != deposit_value {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Withdraw amount must be equal to negative of deposit amount",
            )));
        }

        // We converted to u128 to ensure no loss of precision in comparison,
        // but now we actually have to check it's a u64
        if deposit_value > u64::MAX as i128 {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Transfer amount must not be greater than u64 max",
            )));
        }

        let transfer_amount = deposit_value as u64;
```
