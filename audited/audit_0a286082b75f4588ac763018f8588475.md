# Audit Report

## Title
Inconsistent Error Code Handling in Native Vector move_range Function

## Summary
The native `move_range` function in the Move stdlib vector module uses inconsistent error code formatting, returning bare error code `1` instead of the canonical wrapped format `0x10001` in two error paths, violating the Aptos error code convention and potentially causing error handling confusion.

## Finding Description

The native implementation of `vector::move_range` exhibits inconsistent error code handling: [1](#0-0) 

The function defines `EINDEX_OUT_OF_BOUNDS = 1` and `EFEATURE_NOT_ENABLED = 2`, but applies error wrapping inconsistently:

**Correct usage (line 47):** [2](#0-1) 

**Incorrect usage (lines 66-68):** [3](#0-2) 

**Incorrect usage (lines 80-82):** [4](#0-3) 

The canonical error code system wraps error codes using categories: [5](#0-4) 

This means:
- **Correct**: `error::invalid_argument(1)` = `(0x1 << 16) + 1` = `0x10001` (category: INVALID_ARGUMENT, reason: 1)
- **Incorrect**: bare `1` = category 0 (no category), reason 1

Furthermore, the Move stdlib vector module expects a completely different error code: [6](#0-5) 

Multiple other modules define `EINDEX_OUT_OF_BOUNDS = 1` but properly wrap it: [7](#0-6) [8](#0-7) 

Error parsing code splits the category and reason: [9](#0-8) 

## Impact Explanation

This qualifies as **Low Severity** per Aptos bug bounty criteria ("Non-critical implementation bugs"). The issue affects:

1. **Test Reliability**: Tests expecting `std::vector::EINDEX_OUT_OF_BOUNDS` (0x20000) won't catch `move_range` failures
2. **Error Diagnostics**: Off-chain error parsing will see category 0 instead of INVALID_ARGUMENT (category 1)
3. **Error Code Collision**: Bare code `1` could collide with hundreds of other modules using error code 1
4. **Convention Violation**: Breaks the canonical error code standard used throughout Aptos

**This does NOT affect**:
- Chain consensus (errors cause aborts and state reverts)
- Funds security (no path to theft or minting)
- Network availability (no liveness impact)
- State integrity (errors don't corrupt state)

## Likelihood Explanation

**High likelihood** of occurring during development/testing:
- Any `move_range` call with invalid indices triggers the bug
- Developers writing tests with `#[expected_failure(abort_code = std::vector::EINDEX_OUT_OF_BOUNDS)]` for `move_range` will see unexpected failures
- Error monitoring systems will misclassify these errors

**However**: No security exploitation path exists since Move doesn't support try-catch, and error codes only affect diagnostics after state has already been reverted.

## Recommendation

Fix the inconsistent error code handling by wrapping all error returns with `error::invalid_argument()`:

```rust
// Line 67: Change from
abort_code: EINDEX_OUT_OF_BOUNDS,
// To:
abort_code: error::invalid_argument(EINDEX_OUT_OF_BOUNDS),

// Line 81: Change from
abort_code: EINDEX_OUT_OF_BOUNDS,
// To:
abort_code: error::invalid_argument(EINDEX_OUT_OF_BOUNDS),
```

Additionally, consider aligning the native error code with the Move module's expectation by either:
1. Changing the native to use `EINDEX_OUT_OF_BOUNDS = 0x20000`, or
2. Updating Move stdlib vector.move to use the canonical error format

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = 0x20000)] // Expects std::vector::EINDEX_OUT_OF_BOUNDS
fun test_move_range_out_of_bounds() {
    use std::vector;
    let v1 = vector[1, 2, 3];
    let v2 = vector[4, 5];
    // This will abort with error code 1 (bare), not 0x10001 or 0x20000
    vector::move_range(&mut v1, 10, 1, &mut v2, 0); // Invalid removal_position
}
```

This test will **fail** because `move_range` aborts with code `1` (lines 67), not the expected `0x20000`.

## Notes

While this is a valid implementation bug violating error code conventions, it does not meet the severity threshold (Critical/High/Medium) required for security vulnerabilities. It's a code quality issue affecting diagnostics and testing, without direct security implications on chain state, consensus, or funds.

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/vector.rs (L28-31)
```rust
pub const EINDEX_OUT_OF_BOUNDS: u64 = 1;

/// The feature is not enabled.
pub const EFEATURE_NOT_ENABLED: u64 = 2;
```

**File:** aptos-move/framework/move-stdlib/src/natives/vector.rs (L46-48)
```rust
    let map_err = |_| SafeNativeError::Abort {
        abort_code: error::invalid_argument(EINDEX_OUT_OF_BOUNDS),
    };
```

**File:** aptos-move/framework/move-stdlib/src/natives/vector.rs (L61-69)
```rust
    if removal_position
        .checked_add(length)
        .is_none_or(|end| end > from_len)
        || insert_position > to_len
    {
        return Err(SafeNativeError::Abort {
            abort_code: EINDEX_OUT_OF_BOUNDS,
        });
    }
```

**File:** aptos-move/framework/move-stdlib/src/natives/vector.rs (L74-84)
```rust
    context.charge(
        VECTOR_MOVE_RANGE_PER_INDEX_MOVED
            * NumArgs::new(
                (from_len - removal_position)
                    .checked_add(to_len - insert_position)
                    .and_then(|v| v.checked_add(length))
                    .ok_or_else(|| SafeNativeError::Abort {
                        abort_code: EINDEX_OUT_OF_BOUNDS,
                    })? as u64,
            ),
    )?;
```

**File:** types/src/error.rs (L154-162)
```rust
/// Construct a canonical error code from a category and a reason.
pub fn canonical(category: u64, reason: u64) -> u64 {
    (category << 16) + reason
}

/// Functions to construct a canonical error code of the given category.
pub fn invalid_argument(r: u64) -> u64 {
    canonical(INVALID_ARGUMENT, r)
}
```

**File:** aptos-move/framework/move-stdlib/sources/vector.move (L14-15)
```text
    /// The index into the vector is out of bounds
    const EINDEX_OUT_OF_BOUNDS: u64 = 0x20000;
```

**File:** aptos-move/framework/aptos-stdlib/sources/data_structures/big_vector.move (L7-8)
```text
    /// Vector index is out of bounds
    const EINDEX_OUT_OF_BOUNDS: u64 = 1;
```

**File:** aptos-move/framework/aptos-stdlib/sources/data_structures/big_vector.move (L65-67)
```text
    public fun borrow<T>(self: &BigVector<T>, i: u64): &T {
        assert!(i < self.length(), error::invalid_argument(EINDEX_OUT_OF_BOUNDS));
        self.buckets.borrow(i / self.bucket_size).borrow(i % self.bucket_size)
```

**File:** aptos-move/aptos-vm/src/errors.rs (L63-67)
```rust
fn error_split(code: u64) -> (u8, u64) {
    let reason = code & 0xFFFF;
    let category = ((code >> 16) & 0xFF) as u8;
    (category, reason)
}
```
