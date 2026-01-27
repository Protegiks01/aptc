# Audit Report

## Title
Integer Overflow Panic in Rosetta API Total Stake Balance Calculation

## Summary
The `parse_requested_balance` function in the Aptos Rosetta API lacks overflow protection when summing delegation stake balances, causing the API server to panic and crash when processing total stake queries if the sum exceeds `u64::MAX`.

## Finding Description

The `parse_requested_balance` function is responsible for parsing delegation pool stake balances returned from the blockchain's `get_stake` view function. When calculating total stake for the `is_total_stake()` account type, the function sums three u64 values (active, inactive, and pending_inactive stake) without overflow protection. [1](#0-0) 

The critical vulnerability occurs in the total stake calculation path where `.sum::<u64>()` is called on parsed balance values. When multiple stake components are summed and their total exceeds `u64::MAX` (18,446,744,073,709,551,615), the operation will panic in release builds.

This vulnerability is exacerbated by Aptos's explicit security configuration that enables overflow checks in production releases: [2](#0-1) 

The secure coding guidelines explicitly state that overflow-checks should not be overridden, ensuring arithmetic overflows cause panics to prevent security vulnerabilities: [3](#0-2) 

**Attack Vector:**

While the delegation pool Move contract enforces maximum stake limits, the default `maximum_stake` is set to `u64::MAX`, allowing individual stake pools to contain values approaching this limit. The `get_stake` view function returns three separate components: [4](#0-3) 

For operator beneficiaries, commission rewards are added to both active and pending_inactive stakes. If a delegator has:
- Active stake near `u64::MAX`
- Commission rewards (`commission_active`)
- Pending inactive stake with commission (`commission_pending_inactive`)

The sum can overflow when calculated in the Rosetta API, causing a panic and API server crash.

Additionally, the function silently treats parsing failures as zero with `.unwrap_or(0)`, which could mask data corruption or contract bugs, leading to incorrect balance reporting for exchanges and integrations. [5](#0-4) 

The existing test suite does not validate overflow scenarios, empty arrays, or malformed JSON edge cases: [6](#0-5) 

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "API crashes")

This vulnerability enables denial-of-service attacks against the Rosetta API, which is critical infrastructure for cryptocurrency exchanges and blockchain integrations. A crash in the Rosetta server affects:

1. **Exchange Operations**: CEXs rely on Rosetta for balance queries and transaction construction
2. **Service Availability**: The API becomes unavailable until manual restart
3. **Data Integrity**: Silent parsing failures could lead to incorrect balance reporting, potentially causing financial losses
4. **Defensive Security Violation**: The code fails to implement defense-in-depth principles by trusting upstream contract data without validation

The lack of overflow protection violates the principle of defensive programming emphasized in Aptos's secure coding guidelines.

## Likelihood Explanation

**Likelihood: Medium**

While the Move contract enforces stake limits, several scenarios could trigger the overflow:

1. **Commission Accumulation**: Operator beneficiaries receive commission on top of their delegated stake. Over time, accumulated commission rewards plus base stake could approach overflow thresholds.

2. **Contract Bugs**: Any bug in the delegation pool Move contract that incorrectly calculates stake amounts would propagate to the Rosetta API, causing crashes instead of graceful error handling.

3. **Edge Cases**: Epoch transitions, validator set changes, or reward distribution edge cases could create temporary states with unexpected balance calculations.

4. **Malformed Blockchain State**: Database corruption or state sync issues could result in invalid data being returned by view functions.

The vulnerability requires specific conditions but represents a clear failure in defensive programming that should handle all edge cases gracefully.

## Recommendation

Implement checked arithmetic and explicit overflow handling in the `parse_requested_balance` function:

```rust
fn parse_requested_balance(
    account_identifier: &AccountIdentifier,
    balances_result: Vec<serde_json::Value>,
) -> Option<String> {
    if account_identifier.is_delegator_active_stake() {
        return balances_result
            .first()
            .and_then(|v| v.as_str().map(|s| s.to_owned()));
    } else if account_identifier.is_delegator_inactive_stake() {
        return balances_result
            .get(1)
            .and_then(|v| v.as_str().map(|s| s.to_owned()));
    } else if account_identifier.is_delegator_pending_inactive_stake() {
        return balances_result
            .get(2)
            .and_then(|v| v.as_str().map(|s| s.to_owned()));
    } else if account_identifier.is_total_stake() {
        // Use checked arithmetic to prevent overflow panics
        let mut total: u64 = 0;
        for v in balances_result.iter() {
            if let Some(value_str) = v.as_str() {
                if let Ok(value) = value_str.parse::<u64>() {
                    total = total.checked_add(value).ok_or_else(|| {
                        log::error!("Overflow detected when summing stake balances");
                        // Return error or saturate at u64::MAX
                    })?;
                } else {
                    log::warn!("Failed to parse balance value: {}", value_str);
                    return None; // Fail explicitly instead of silent zero
                }
            } else {
                log::warn!("Balance value is not a string");
                return None;
            }
        }
        return Some(total.to_string());
    }

    None
}
```

Additionally, add comprehensive edge case tests covering overflow, empty arrays, and malformed JSON scenarios.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::types::SubAccountIdentifier;

    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    fn test_parse_requested_balance_overflow() {
        // Test that demonstrates overflow panic in current implementation
        let balances_result = vec![
            serde_json::Value::String(u64::MAX.to_string()),
            serde_json::Value::String("1".to_string()),
            serde_json::Value::String("0".to_string()),
        ];

        // This will panic due to overflow when summing u64::MAX + 1
        parse_requested_balance(
            &AccountIdentifier {
                address: "0x123".to_string(),
                sub_account: Some(SubAccountIdentifier::new_delegated_total_stake("0xabc")),
            },
            balances_result,
        );
    }

    #[test]
    fn test_parse_requested_balance_malformed_json() {
        let balances_result = vec![
            serde_json::Value::String("300".to_string()),
            serde_json::Value::String("not_a_number".to_string()),
            serde_json::Value::String("100".to_string()),
        ];

        // Current implementation treats parsing failures as 0, returning "400" instead of error
        let result = parse_requested_balance(
            &AccountIdentifier {
                address: "0x123".to_string(),
                sub_account: Some(SubAccountIdentifier::new_delegated_total_stake("0xabc")),
            },
            balances_result,
        );
        
        assert_eq!(Some("400".to_string()), result); // Silent failure masks bug
    }

    #[test]
    fn test_parse_requested_balance_empty_array() {
        let balances_result = vec![];

        let result = parse_requested_balance(
            &AccountIdentifier {
                address: "0x123".to_string(),
                sub_account: Some(SubAccountIdentifier::new_delegated_total_stake("0xabc")),
            },
            balances_result,
        );
        
        assert_eq!(Some("0".to_string()), result); // Returns 0 for empty array
    }
}
```

## Notes

While this vulnerability exists in the Rosetta API layer rather than core consensus logic, it represents a critical failure in defensive programming that violates Aptos's secure coding standards. The Rosetta API is essential infrastructure for exchange integrations, and its availability directly impacts the broader Aptos ecosystem. The lack of overflow protection, combined with silent parsing failures, creates both availability and correctness risks that should be addressed with proper input validation and error handling.

### Citations

**File:** crates/aptos-rosetta/src/types/misc.rs (L437-469)
```rust
fn parse_requested_balance(
    account_identifier: &AccountIdentifier,
    balances_result: Vec<serde_json::Value>,
) -> Option<String> {
    if account_identifier.is_delegator_active_stake() {
        return balances_result
            .first()
            .and_then(|v| v.as_str().map(|s| s.to_owned()));
    } else if account_identifier.is_delegator_inactive_stake() {
        return balances_result
            .get(1)
            .and_then(|v| v.as_str().map(|s| s.to_owned()));
    } else if account_identifier.is_delegator_pending_inactive_stake() {
        return balances_result
            .get(2)
            .and_then(|v| v.as_str().map(|s| s.to_owned()));
    } else if account_identifier.is_total_stake() {
        return Some(
            balances_result
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_owned())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0)
                })
                .sum::<u64>()
                .to_string(),
        );
    }

    None
}
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L484-548)
```rust
    fn test_parse_requested_balance() {
        let balances_result = vec![
            serde_json::Value::String("300".to_string()),
            serde_json::Value::String("200".to_string()),
            serde_json::Value::String("100".to_string()),
        ];

        // Total stake balance is sum of all 3
        assert_eq!(
            Some("600".to_string()),
            parse_requested_balance(
                &AccountIdentifier {
                    address: "0x123".to_string(),
                    sub_account: Some(SubAccountIdentifier::new_delegated_total_stake("0xabc")),
                },
                balances_result.clone()
            )
        );

        assert_eq!(
            Some("300".to_string()),
            parse_requested_balance(
                &AccountIdentifier {
                    address: "0x123".to_string(),
                    sub_account: Some(SubAccountIdentifier::new_delegated_active_stake("0xabc")),
                },
                balances_result.clone()
            )
        );

        assert_eq!(
            Some("200".to_string()),
            parse_requested_balance(
                &AccountIdentifier {
                    address: "0x123".to_string(),
                    sub_account: Some(SubAccountIdentifier::new_delegated_inactive_stake("0xabc")),
                },
                balances_result.clone()
            )
        );

        assert_eq!(
            Some("100".to_string()),
            parse_requested_balance(
                &AccountIdentifier {
                    address: "0x123".to_string(),
                    sub_account: Some(SubAccountIdentifier::new_delegated_pending_inactive_stake(
                        "0xabc"
                    )),
                },
                balances_result.clone()
            )
        );

        assert_eq!(
            None,
            parse_requested_balance(
                &AccountIdentifier {
                    address: "0x123".to_string(),
                    sub_account: Some(SubAccountIdentifier::new_active_stake()),
                },
                balances_result
            )
        );
    }
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** RUST_SECURE_CODING.md (L17-20)
```markdown
Utilize Cargo for project management without overriding variables like `debug-assertions` and `overflow-checks`.

- **`debug-assertions`**: This variable controls whether debug assertions are enabled. Debug assertions are checks that are only present in debug builds. They are used to catch bugs during development by validating assumptions made in the code.
- **`overflow-checks`**: This variable determines whether arithmetic overflow checks are performed. In Rust, when overflow checks are enabled (which is the default in debug mode), an integer operation that overflows will cause a panic in debug builds, preventing potential security vulnerabilities like buffer overflows.
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L683-693)
```text
        if (delegator_address == beneficiary_for_operator(get_operator(pool_address))) {
            active = active + commission_active;
            // in-flight pending_inactive commission can coexist with already inactive withdrawal
            if (lockup_cycle_ended) {
                inactive = inactive + commission_pending_inactive
            } else {
                pending_inactive = pending_inactive + commission_pending_inactive
            }
        };

        (active, inactive, pending_inactive)
```
