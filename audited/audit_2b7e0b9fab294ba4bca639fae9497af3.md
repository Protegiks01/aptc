# Audit Report

## Title
Integer Overflow Mismatch Between Rust and Move Causes Permanent DoS After Version Reaches u64::MAX

## Summary
The JWK consensus system uses unchecked arithmetic in Rust (wrapping on overflow) but checked arithmetic in Move (aborting on overflow). If the on-chain version reaches u64::MAX, all subsequent JWK updates will permanently fail, causing an irreversible denial-of-service for that issuer's JWK updates.

## Finding Description

The vulnerability stems from an inconsistency in how integer overflow is handled between the Rust validator code and the Move on-chain execution:

**In Rust:** When validators create a new JWK update, they compute the version using unchecked addition: [1](#0-0) 

If `on_chain_version()` returns `u64::MAX`, this addition wraps to `0` in Rust release builds.

**In Rust Validation:** The transaction validation also uses unchecked addition: [2](#0-1) 

When `on_chain.version` is `u64::MAX`, the expression `on_chain.version + 1` wraps to `0`, so the check accepts `observed.version = 0`.

**In Move Execution:** However, Move uses checked arithmetic that aborts on overflow: [3](#0-2) 

When `cur_issuer_jwks.version` is `u64::MAX`, the expression `cur_issuer_jwks.version + 1` causes an arithmetic overflow abort in Move VM before the comparison can execute.

**The Critical Sequence:**
1. On-chain version reaches `u64::MAX` (through incremental updates or other means)
2. Validators observe new JWKs and compute `version = u64::MAX + 1 = 0` (wraps in Rust)
3. Quorum is reached with version `0` (all honest validators compute the same wrapped value)
4. Rust validation at line 128 passes: `u64::MAX + 1 == 0` → `0 == 0` ✓
5. Move execution at line 478 attempts: `assert!(u64::MAX + 1 == 0)` → **ARITHMETIC_ERROR abort**
6. Transaction is discarded, on-chain version remains `u64::MAX`
7. All future update attempts repeat steps 2-6 indefinitely → **permanent DoS**

## Impact Explanation

**Severity Assessment: HIGH (not Critical due to precondition requirement)**

This qualifies as High severity under "Significant protocol violations" because:
- **Permanent DoS:** Once triggered, JWK updates for the affected issuer are permanently blocked
- **No Recovery Path:** There is no on-chain mechanism to reset the version or bypass the check
- **Affects Keyless Authentication:** JWK updates are critical for OIDC-based keyless account authentication

However, this is NOT Critical severity because:
- **Requires Precondition:** The on-chain version must reach `u64::MAX` first, which requires either:
  - `2^64` legitimate incremental updates (practically impossible - billions of years at 1 update/second)
  - Exploitation of a separate vulnerability that allows version manipulation
  - 2/3+ validator collusion (explicitly out of scope per bug bounty rules)

## Likelihood Explanation

**Likelihood: THEORETICAL (extremely low without additional vulnerabilities)**

The vulnerability is **real and confirmed** through code analysis, but its practical exploitability is **extremely limited** because:

1. **Incremental Path is Impractical:** Reaching `u64::MAX` through normal JWK updates would require approximately 18.4 quintillion updates, which is not feasible in any realistic timeframe.

2. **No Direct Manipulation Path:** The code enforces version increments of exactly 1: [4](#0-3) 
   
   All validators must agree on the exact same `ProviderJWKs` including version, preventing individual malicious validators from injecting arbitrary versions.

3. **Requires 2/3+ Collusion for Bypass:** The only way to skip versions would be 2/3+ malicious validators colluding, which is out of scope.

**However**, if another vulnerability exists that allows version manipulation, OR if the system runs long enough for version to naturally approach `u64::MAX`, this bug becomes a **critical time bomb**.

## Recommendation

**Fix 1: Use Checked Arithmetic in Rust (Immediate Fix)**

Replace unchecked addition with `checked_add` and handle overflow gracefully:

```rust
// In jwk_manager/mod.rs:199
let version = state
    .on_chain_version()
    .checked_add(1)
    .context("JWK version overflow - maximum version reached")?;

// In jwk.rs:128
let expected_version = on_chain
    .version
    .checked_add(1)
    .ok_or(Expected(IncorrectVersion))?;
if expected_version != observed.version {
    return Err(Expected(IncorrectVersion));
}
```

**Fix 2: Add Move-Side Version Overflow Check (Defense in Depth)**

In `jwks.move`, add explicit overflow checks before arithmetic:

```move
// Before line 478
assert!(cur_issuer_jwks.version < 18446744073709551615, error::out_of_range(EVERSION_OVERFLOW));
assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

**Fix 3: Add Version Cap (Long-term Solution)**

Consider implementing a maximum version cap (e.g., `u64::MAX / 2`) to provide early warning and prevent approaching the overflow boundary.

## Proof of Concept

```rust
// Rust test demonstrating the overflow mismatch
#[test]
fn test_jwk_version_overflow_dos() {
    // Setup: on-chain version at u64::MAX
    let on_chain_version = u64::MAX;
    
    // Rust computation (wrapping)
    let rust_next_version = on_chain_version.wrapping_add(1);
    assert_eq!(rust_next_version, 0); // Wraps to 0
    
    // Rust validation (wrapping)
    let rust_validation = on_chain_version.wrapping_add(1) == rust_next_version;
    assert!(rust_validation); // Passes
    
    // Move execution would abort here with ARITHMETIC_ERROR
    // because Move uses checked arithmetic: on_chain_version + 1 overflows
    
    // Result: Transaction discarded, version stuck at u64::MAX
    // All future updates fail permanently
}
```

**Move Test (Conceptual - would require test infrastructure):**

```move
#[test(fx = @aptos_framework)]
#[expected_failure(arithmetic_error, location = Self)]
fun test_version_overflow_abort(fx: &signer) {
    // Setup provider with version = u64::MAX
    let provider = ProviderJWKs {
        issuer: b"test",
        version: 18446744073709551615, // u64::MAX
        jwks: vector[],
    };
    
    // Attempt to verify version + 1 == 0
    // This will abort with arithmetic overflow
    assert!(provider.version + 1 == 0, 999);
}
```

## Notes

This vulnerability demonstrates a critical architectural issue: **Rust validation uses wrapping arithmetic while Move execution uses checked arithmetic**, creating a mismatch that can cause transaction validation to succeed but execution to fail. While the specific precondition (version at u64::MAX) is currently impractical to achieve, this represents a systemic design flaw that should be addressed to prevent future issues and ensure long-term system robustness.

The recommended fixes ensure consistency between Rust and Move arithmetic behavior, preventing this class of bugs entirely.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L197-201)
```rust
            let observed = ProviderJWKs {
                issuer: issuer.clone(),
                version: state.on_chain_version() + 1,
                jwks,
            };
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-130)
```rust
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L478-478)
```text
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-84)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```
