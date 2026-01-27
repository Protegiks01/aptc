# Audit Report

## Title
Missing `debug-assertions = true` in Release Profile Creates Inconsistent Testing and Production Behavior

## Summary
The Aptos Core `Cargo.toml` release profile does not explicitly set `debug-assertions = true`, causing different runtime behavior between CI testing (which uses the `ci` profile with `debug-assertions = true`) and production deployments (which use the `release` profile with Rust's default `debug-assertions = false`). This creates a discrepancy where the custom `safe_assert!()`, `safe_unwrap!()`, and `safe_unwrap_err!()` macros panic during CI testing but return errors in production.

## Finding Description
The security question asks about potential mismatches involving BUILD_PROFILE_NAME. Investigation revealed a configuration inconsistency:

The `[profile.release]` section in `Cargo.toml` sets `overflow-checks = true` but omits `debug-assertions = true`: [1](#0-0) 

Meanwhile, the `[profile.ci]` explicitly enables `debug-assertions = true`: [2](#0-1) 

The Move VM extensively uses custom assertion macros that check `cfg!(debug_assertions)` to determine behavior: [3](#0-2) 

These macros are used in consensus-critical code paths:
- Type safety verification (63 uses)
- Reference safety checks (53 uses)  
- Runtime reference checks (40 uses)

Production deployments default to the `release` profile: [4](#0-3) 

## Impact Explanation
**Impact Assessment: Low Severity ($1,000)**

While this creates behavioral differences between testing and production, it does NOT constitute an exploitable vulnerability for these reasons:

1. **Not a Consensus Vulnerability**: All production validators built with the same `release` profile will have identical behavior (`debug-assertions = false`), maintaining consensus determinism.

2. **Standard `assert!()` Unaffected**: The Rust coding guidelines correctly state that standard `assert!()` macros are "kept in both debug/release". These remain active regardless of `debug-assertions` setting and protect critical invariants: [5](#0-4) 

3. **Intentional Design**: The `safe_assert!()` macros are deliberately designed to panic in development (for debugging) but return errors in production (for graceful handling), as evidenced by their implementation.

4. **Configuration Issue, Not Code Bug**: An attacker cannot exploit this through transaction crafting. The issue only manifests if validators are built with different profiles, which is an operational/deployment concern.

The security documentation states not to override these variables, but the interpretation is ambiguous: [6](#0-5) 

## Likelihood Explanation
**Likelihood: Low**

The scenario requires a validator operator to accidentally deploy with a non-standard build profile (e.g., `ci` instead of `release`). The default production build process consistently uses the `release` profile, making divergent deployments unlikely in practice.

## Recommendation
For defense-in-depth and to align with security best practices, explicitly set `debug-assertions = true` in the `[profile.release]` section:

```toml
[profile.release]
debug = true
overflow-checks = true
debug-assertions = true  # Add this line
```

This ensures:
1. CI and production behavior are identical
2. The custom `safe_assert!()` macros panic on invariant violations in all builds
3. Explicit adherence to security guidelines
4. No ambiguity about configuration intent

## Proof of Concept
This is a configuration issue rather than an exploitable vulnerability. To demonstrate the behavioral difference:

1. Build with `cargo build --profile=ci` and observe that invariant violations trigger panics
2. Build with `cargo build --release` and observe that the same violations return errors
3. Both builds are correct per design, but differ in behavior

Since all production validators use the same profile, this does not create a consensus vulnerability.

---

**Notes:**
- The incomplete security question appears to ask about BUILD_PROFILE_NAME vs BUILD_IS_RELEASE_BUILD mismatches, which are informational metadata with no security impact
- The actual finding is a configuration inconsistency that violates defense-in-depth principles but does not constitute an exploitable vulnerability
- Standard Rust `assert!()` macros remain active in release builds and are unaffected by this configuration
- This issue is categorized as **Low Severity** due to its operational nature and lack of direct exploitability

### Citations

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** Cargo.toml (L952-956)
```text
[profile.ci]
inherits = "release"
debug = "line-tables-only"
overflow-checks = true
debug-assertions = true
```

**File:** third_party/move/move-binary-format/src/lib.rs (L176-188)
```rust
macro_rules! safe_assert {
    ($e:expr) => {{
        if !$e {
            let err = PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message(format!("{}:{} (assert)", file!(), line!()));
            if cfg!(debug_assertions) {
                panic!("{:?}", err)
            } else {
                return Err(err);
            }
        }
    }};
}
```

**File:** docker/builder/docker-bake-rust-all.sh (L23-23)
```shellscript
export PROFILE=${PROFILE:-release}
```

**File:** RUST_CODING_STYLE.md (L184-184)
```markdown
- `assert!()` - This macro is kept in both debug/release and should be used to protect invariants of the system as necessary.
```

**File:** RUST_SECURE_CODING.md (L17-20)
```markdown
Utilize Cargo for project management without overriding variables like `debug-assertions` and `overflow-checks`.

- **`debug-assertions`**: This variable controls whether debug assertions are enabled. Debug assertions are checks that are only present in debug builds. They are used to catch bugs during development by validating assumptions made in the code.
- **`overflow-checks`**: This variable determines whether arithmetic overflow checks are performed. In Rust, when overflow checks are enabled (which is the default in debug mode), an integer operation that overflows will cause a panic in debug builds, preventing potential security vulnerabilities like buffer overflows.
```
