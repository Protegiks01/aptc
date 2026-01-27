# Audit Report

## Title
JWK Version Integer Overflow Enables Consensus State Corruption via Version Rollback

## Summary
The JWK consensus mechanism contains unchecked integer arithmetic that allows the version field to overflow from `u64::MAX` back to `0`, breaking the monotonic version increase invariant. While the Rust code uses `checked_add` to prevent creating version `u64::MAX + 1`, it fails to prevent reaching version `u64::MAX`, which then wraps to `0` on the next increment in both Rust validator logic and Move contract code.

## Finding Description
The vulnerability exists across three critical locations:

**1. Insufficient Test Coverage in Rust**
The test at line 433 only validates that `base_version: u64::MAX` fails (because `checked_add(1)` returns `None`), but doesn't test `base_version: u64::MAX - 1` where `checked_add(1)` succeeds and produces a `ProviderJWKs` with `version: u64::MAX`. [1](#0-0) 

**2. Unchecked Addition in Rust Validator Transaction Processor**
The version validation uses unchecked arithmetic. When `on_chain.version` equals `u64::MAX`, the expression `on_chain.version + 1` wraps to `0` in Rust's default wrapping semantics. [2](#0-1) 

**3. Unchecked Addition in Move Smart Contract**
The Move code performs unchecked version increments at two critical points. Line 478 validates the version, and line 493 performs the increment. Both use unchecked addition that wraps at `u64::MAX`. [3](#0-2) [4](#0-3) 

**Attack Scenario:**
1. Through normal JWK consensus operations, an issuer's on-chain version reaches `u64::MAX - 1`
2. Validators create a `KeyLevelUpdate` with `base_version: u64::MAX - 1`
3. In `try_as_issuer_level_repr()`, `checked_add(1)` succeeds, producing `ProviderJWKs` with `version: u64::MAX`
4. The validator transaction processor validates: `(u64::MAX - 1) + 1 != u64::MAX` evaluates to `u64::MAX != u64::MAX` (false), so check passes
5. Move validation passes: `cur_issuer_jwks.version + 1 == proposed_provider_jwks.version` → `u64::MAX - 1 + 1 == u64::MAX` ✓
6. Move assignment: `cur_issuer_jwks.version = u64::MAX` ✓
7. **On next update:** Current version is `u64::MAX`
8. Rust validator check: `u64::MAX + 1` wraps to `0`, so it expects `observed.version == 0`
9. Move validation: `u64::MAX + 1 == 0` (wraps) ✓
10. Move assignment: `cur_issuer_jwks.version = u64::MAX + 1 = 0` → **VERSION ROLLS BACK TO ZERO**

## Impact Explanation
This breaks **Critical Invariant #1: Deterministic Execution** and **#2: Consensus Safety**. 

The version field serves as a monotonically increasing sequence number for JWK consensus deduplication. Rolling it back to `0` could:
- Allow replay of previously committed JWK updates (versions 1, 2, 3...)
- Cause consensus disagreement between nodes that process updates in different orders
- Break keyless account authentication if stale JWKs are replayed
- Violate the fundamental assumption that versions always increase

Per Aptos bug bounty criteria, this qualifies as **Low Severity** because:
- While it would break consensus IF triggered, reaching `u64::MAX` requires ~18 quintillion updates (impractical)
- The test coverage gap and unchecked arithmetic represent code quality issues
- No realistic attack path exists for unprivileged actors

However, the unchecked arithmetic violates Rust best practices and leaves the codebase vulnerable if version numbers could ever be manipulated through other means.

## Likelihood Explanation
**Extremely Low in Production**, but **High Impact IF Triggered**.

Reaching version `u64::MAX` through normal operations is infeasible:
- Assuming 1 update per second: ~585 billion years to reach `u64::MAX`
- Assuming 1000 updates per second: ~585 million years
- Even at 1 million updates/second: ~585,000 years

However, the vulnerability is concerning because:
1. The test explicitly tries to prevent overflow but has a gap
2. Production code uses unchecked arithmetic in consensus-critical paths
3. Future code changes could introduce version manipulation capabilities
4. Test environments or state recovery scenarios might set arbitrary versions

## Recommendation
**1. Add Comprehensive Overflow Tests**
```rust
#[test]
fn repr_conversion_version_overflow_comprehensive() {
    // Test u64::MAX - fails correctly
    let key_level = KeyLevelUpdate {
        issuer: issuer_from_str("issuer-alice"),
        base_version: u64::MAX,
        kid: "kid123".as_bytes().to_vec(),
        to_upsert: None,
    };
    assert!(key_level.try_as_issuer_level_repr().is_err());
    
    // Test u64::MAX - 1 - should also fail to prevent reaching MAX
    let key_level = KeyLevelUpdate {
        issuer: issuer_from_str("issuer-alice"),
        base_version: u64::MAX - 1,
        kid: "kid123".as_bytes().to_vec(),
        to_upsert: None,
    };
    assert!(key_level.try_as_issuer_level_repr().is_err(), 
            "Should reject u64::MAX - 1 to prevent version overflow");
}
```

**2. Use Checked Arithmetic in Production Code**

In `aptos-move/aptos-vm/src/validator_txns/jwk.rs`:
```rust
// Replace line 128
let expected_version = on_chain.version
    .checked_add(1)
    .ok_or(Expected(IncorrectVersion))?;
if expected_version != observed.version {
    return Err(Expected(IncorrectVersion));
}
```

In `types/src/jwks/mod.rs`, add an upper bound check:
```rust
pub fn try_as_issuer_level_repr(&self) -> anyhow::Result<ProviderJWKs> {
    let jwk_repr = self.to_upsert.clone().unwrap_or_else(|| {
        JWK::Unsupported(UnsupportedJWK {
            id: self.kid.clone(),
            payload: DELETE_COMMAND_INDICATOR.as_bytes().to_vec(),
        })
    });
    
    // Reject if base_version is too close to overflow
    ensure!(self.base_version < u64::MAX - 1, 
            "base_version too close to u64::MAX");
    
    let version = self
        .base_version
        .checked_add(1)
        .context("KeyLevelUpdate::as_issuer_level_repr failed on version")?;
    
    Ok(ProviderJWKs {
        issuer: self.issuer.clone(),
        version,
        jwks: vec![JWKMoveStruct::from(jwk_repr)],
    })
}
```

**3. Add Move Overflow Protection**
In `jwks.move`, add assertion before increment:
```move
// Before line 493
assert!(cur_issuer_jwks.version < 18446744073709551614, EVERSION_OVERFLOW); // u64::MAX - 1
cur_issuer_jwks.version = cur_issuer_jwks.version + 1;
```

## Proof of Concept
```rust
#[test]
fn test_version_overflow_attack_scenario() {
    use crate::jwks::{KeyLevelUpdate, ProviderJWKs, issuer_from_str};
    
    // Step 1: Simulate on-chain state at u64::MAX - 1
    let current_version = u64::MAX - 1;
    
    // Step 2: Create update with base_version = u64::MAX - 1
    let update = KeyLevelUpdate {
        issuer: issuer_from_str("test-issuer"),
        base_version: current_version,
        kid: "test-kid".as_bytes().to_vec(),
        to_upsert: None,
    };
    
    // Step 3: This succeeds and creates version = u64::MAX
    let issuer_repr = update.try_as_issuer_level_repr().unwrap();
    assert_eq!(issuer_repr.version, u64::MAX);
    
    // Step 4: Simulate validator check (WRAPS!)
    let on_chain_version = u64::MAX;
    let next_expected = on_chain_version + 1; // Wraps to 0 in Rust
    assert_eq!(next_expected, 0, "Unchecked addition wraps to 0");
    
    // This demonstrates the vulnerability: after reaching u64::MAX,
    // the next increment wraps to 0, breaking version monotonicity
}
```

## Notes
While this vulnerability is theoretically valid, its practical exploitability is near-zero due to the astronomical number of updates required to reach `u64::MAX`. The primary concern is the code quality issue of using unchecked arithmetic in consensus-critical code and the test coverage gap that fails to validate the boundary condition at `u64::MAX - 1`.

### Citations

**File:** types/src/jwks/mod.rs (L429-437)
```rust
#[test]
fn repr_conversion_failures() {
    let key_level = KeyLevelUpdate {
        issuer: issuer_from_str("issuer-alice"),
        base_version: u64::MAX,
        kid: "kid123".as_bytes().to_vec(),
        to_upsert: None,
    };
    assert!(key_level.try_as_issuer_level_repr().is_err());
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-130)
```rust
        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L478-478)
```text
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L493-493)
```text
                cur_issuer_jwks.version = cur_issuer_jwks.version + 1;
```
