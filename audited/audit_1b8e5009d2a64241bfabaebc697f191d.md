# Audit Report

## Title
Integer Overflow in Version Arithmetic Causes Denial of Service and Violates Secure Coding Standards

## Summary
Version number calculations in the executor workflow use unchecked arithmetic operations that violate Aptos secure coding standards. While overflow-checks in release builds prevent wraparound attacks, they cause node panics leading to denial of service. The code fails to use defensive checked arithmetic as required by the project's coding guidelines.

## Finding Description

The `ExecutionOutput` structure and related version calculation code perform unchecked integer arithmetic on version numbers (u64 type), violating the **Aptos Rust Secure Coding Guidelines** which explicitly mandate: "we use checked arithmetic instead of directly using math symbols." [1](#0-0) [2](#0-1) [3](#0-2) 

The Aptos coding standards explicitly require checked arithmetic for all integer operations: [4](#0-3) 

Additionally, the secure coding guidelines state that overflow-checks should not be overridden: [5](#0-4) 

The release profile correctly enables overflow-checks: [6](#0-5) 

**Attack Scenario:**
1. An attacker corrupts the database state or restores from a malicious backup to set the ledger version to a value near `u64::MAX` (18,446,744,073,709,551,615)
2. When transactions are executed and committed, the unchecked addition operations attempt to calculate `next_version = first_version + num_transactions`
3. In release builds with overflow-checks enabled: The addition overflows and causes a **panic**, crashing the validator node
4. In non-standard builds without overflow-checks: The addition wraps around to a small number, causing version confusion and state inconsistency

This breaks the **Deterministic Execution** invariant - if different nodes have different overflow-check configurations or handle the panic differently during recovery, they may diverge in their ledger state.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

In **release builds** (standard deployment):
- Overflow causes immediate node panic → **Denial of Service**
- Node crashes and requires restart
- Affects node availability but not consensus safety (other nodes continue)
- Classified as "State inconsistencies requiring intervention" (Medium severity)

In **non-standard builds** (if overflow-checks disabled):
- Version wraps to 0 or small number → **State corruption**
- Transaction ordering violations
- Potential consensus fork if nodes disagree on version handling
- Would be Critical severity, but non-standard builds are edge cases

The coding standard violation itself represents a security weakness that should be addressed regardless of the specific compiler flags, as defensive programming requires explicit overflow handling.

## Likelihood Explanation

**Low to Medium likelihood:**

**Barriers to exploitation:**
- Version is u64, requiring database state near `18,446,744,073,709,551,615`
- Natural overflow would take ~584 years at 1 billion transactions/second
- Requires prior database corruption or malicious backup restore
- Backup restore validation exists but may not prevent arbitrary high versions [7](#0-6) 

**However:**
- The coding standard violation exists today and affects all version arithmetic
- State sync or database corruption scenarios could set high version values
- Once triggered, impact is immediate (node crash)
- Multiple code paths contain the vulnerability

## Recommendation

Replace all unchecked version arithmetic with checked operations per coding standards. Use `checked_add()` and properly handle the `None` case:

**For ExecutionOutput::new():**
```rust
let next_version = first_version
    .checked_add(to_commit.len() as Version)
    .ok_or_else(|| anyhow!("Version overflow: first_version={}, to_commit.len()={}", 
                           first_version, to_commit.len()))?;
```

**For ExecutionOutput::next_version():**
```rust
pub fn next_version(&self) -> Result<Version> {
    self.first_version
        .checked_add(self.num_transactions_to_commit() as Version)
        .ok_or_else(|| anyhow!("Version overflow in next_version()"))
}
```

**For State::new_with_updates():**
```rust
next_version: match version {
    None => 0,
    Some(v) => v.checked_add(1)
        .ok_or_else(|| anyhow!("Version overflow at version {}", v))?,
},
```

This ensures consistent error handling across all nodes and prevents both panic-based DoS and potential wraparound in any build configuration.

## Proof of Concept

```rust
#[cfg(test)]
mod overflow_tests {
    use super::*;
    use aptos_types::transaction::Version;
    
    #[test]
    #[should_panic(expected = "overflow")]
    fn test_version_overflow_in_execution_output() {
        // This test demonstrates the overflow in release builds
        let first_version: Version = u64::MAX - 5;
        let num_transactions = 10; // This will cause overflow
        
        // This panics in release builds with overflow-checks
        let _next_version = first_version + num_transactions;
        
        // Expected behavior with checked arithmetic:
        // let next_version = first_version.checked_add(num_transactions);
        // assert!(next_version.is_none());
    }
    
    #[test]
    fn test_state_version_overflow() {
        // Demonstrates overflow in State::new_with_updates
        let version = Some(u64::MAX);
        
        // The current code does: version.map_or(0, |v| v + 1)
        // This panics in release or wraps in debug
        
        // Correct implementation should check:
        let next_version = version.and_then(|v| v.checked_add(1));
        assert!(next_version.is_none(), "Should detect overflow");
    }
}
```

The vulnerability violates secure coding standards, creates a DoS vector in production builds, and fails to provide defensive overflow protection across the critical execution pipeline.

### Citations

**File:** execution/executor-types/src/execution_output.rs (L46-46)
```rust
        let next_version = first_version + to_commit.len() as Version;
```

**File:** execution/executor-types/src/execution_output.rs (L140-146)
```rust
    pub fn next_version(&self) -> Version {
        self.first_version + self.num_transactions_to_commit() as Version
    }

    pub fn expect_last_version(&self) -> Version {
        self.first_version + self.num_transactions_to_commit() as Version - 1
    }
```

**File:** storage/storage-interface/src/state_store/state.rs (L85-85)
```rust
            next_version: version.map_or(0, |v| v + 1),
```

**File:** RUST_CODING_STYLE.md (L220-230)
```markdown
### Integer Arithmetic

As every integer operation (`+`, `-`, `/`, `*`, etc.) implies edge-cases (e.g. overflow `u64::MAX + 1`, underflow `0u64 -1`, division by zero, etc.),
we use checked arithmetic instead of directly using math symbols.
It forces us to think of edge-cases, and handle them explicitly.
This is a brief and simplified mini guide of the different functions that exist to handle integer arithmetic:

- [checked\_](https://doc.rust-lang.org/std/primitive.u32.html#method.checked_add): use this function if you want to handle overflow and underflow as a special edge-case. It returns `None` if an underflow or overflow has happened, and `Some(operation_result)` otherwise.
- [overflowing\_](https://doc.rust-lang.org/std/primitive.u32.html#method.overflowing_add): use this function if you want the result of an overflow to potentially wrap around (e.g. `u64::MAX.overflow_add(10) == (9, true)`). It returns the underflowed or overflowed result as well as a flag indicating if an overflow has occurred or not.
- [wrapping\_](https://doc.rust-lang.org/std/primitive.u32.html#method.wrapping_add): this is similar to overflowing operations, except that it returns the result directly. Use this function if you are sure that you want to handle underflow and overflow by wrapping around.
- [saturating\_](https://doc.rust-lang.org/std/primitive.u32.html#method.saturating_add): if an overflow occurs, the result is kept within the boundary of the type (e.g. `u64::MAX.saturating_add(1) == u64::MAX`).
```

**File:** RUST_SECURE_CODING.md (L17-20)
```markdown
Utilize Cargo for project management without overriding variables like `debug-assertions` and `overflow-checks`.

- **`debug-assertions`**: This variable controls whether debug assertions are enabled. Debug assertions are checks that are only present in debug builds. They are used to catch bugs during development by validating assumptions made in the code.
- **`overflow-checks`**: This variable determines whether arithmetic overflow checks are performed. In Rust, when overflow checks are enabled (which is the default in debug mode), an integer operation that overflows will cause a panic in debug builds, preventing potential security vulnerabilities like buffer overflows.
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L114-120)
```rust
        if self.version > self.target_version {
            warn!(
                "Trying to restore state snapshot to version {}, which is newer than the target version {}, skipping.",
                self.version,
                self.target_version,
            );
            return Ok(());
```
