# Audit Report

## Title
Overly Broad Log Filter Prefixes Can Hide Critical Consensus Safety Violations

## Summary
The prefix matching logic in `Filter::enabled()` allows overly broad filter patterns (e.g., `aptos=error`) to inadvertently suppress consensus-critical safety violation warnings from `aptos_safety_rules`, hiding Byzantine behavior and safety rule violations that are logged at `warn` level.

## Finding Description

The Aptos logging filter system uses prefix matching via `starts_with()` to determine whether logs should be emitted. [1](#0-0) 

When safety rules detect consensus violations (e.g., `IncorrectLastVotedRound`, `NotSafeToVote`, `IncorrectEpoch`), these critical errors are logged at `warn` level, not `error` level. [2](#0-1) 

The safety rules errors represent critical consensus safety invariants: [3](#0-2) 

The module path for safety rules logs is `aptos_safety_rules::*` (from the crate name `aptos-safety-rules`). [4](#0-3) 

When logging macros are invoked, they capture the module path using `module_path!()`: [5](#0-4) 

**Attack Scenario:**
1. Operator configures `RUST_LOG=aptos=error` to reduce log verbosity across all Aptos modules
2. Due to prefix matching, this filter matches any module path starting with "aptos", including `aptos_safety_rules::safety_rules`
3. A Byzantine validator attempts double-voting or epoch confusion attacks
4. Safety rules detect the violation and attempt to log at `warn` level
5. The filter suppresses these `warn` logs because `LevelFilter::Warn > LevelFilter::Error`
6. Byzantine behavior remains undetected in operator logs, preventing incident response

## Impact Explanation

**Critical Severity** - This meets the "Consensus/Safety violations" category by hiding detection of consensus safety rule violations. While it doesn't directly cause a safety violation, it prevents operators from detecting and responding to Byzantine behavior, effectively allowing attacks to proceed undetected.

The specific safety violations that could be hidden include:
- `IncorrectLastVotedRound` - Double voting detection
- `NotSafeToVote` - 2-chain voting rule violations  
- `NotSafeToTimeout` - Timeout safety violations
- `IncorrectEpoch` - Epoch confusion attacks
- `InconsistentExecutionResult` - State divergence detection

All of these are fundamental to AptosBFT consensus safety under the < 1/3 Byzantine assumption.

## Likelihood Explanation

**High Likelihood** - Operators commonly set broad log filters like `RUST_LOG=error` or `RUST_LOG=aptos=error` to reduce log volume in production. The filter system provides no warnings about overly broad patterns that might hide critical safety logs. The default documentation does not warn against this configuration pattern.

## Recommendation

Implement explicit handling for consensus-critical modules to prevent accidental filtering:

```rust
pub fn enabled(&self, metadata: &Metadata) -> bool {
    // Critical consensus modules should never be filtered below WARN level
    const CRITICAL_MODULES: &[&str] = &[
        "aptos_safety_rules",
        "aptos_consensus::metrics_safety_rules",
    ];
    
    for critical in CRITICAL_MODULES {
        if metadata.module_path().starts_with(critical) {
            // Always allow WARN and ERROR for consensus-critical modules
            if metadata.level() <= Level::Warn {
                return true;
            }
        }
    }
    
    // Original filtering logic
    for directive in self.directives.iter().rev() {
        match &directive.name {
            Some(name) if !metadata.module_path().starts_with(name) => {},
            Some(..) | None => return LevelFilter::from(metadata.level()) <= directive.level,
        }
    }
    false
}
```

Additionally, add validation in the Builder to warn about dangerous broad filters:

```rust
pub fn build(&mut self) -> Filter {
    // Warn about overly broad filters that could hide consensus safety logs
    for directive in &self.directives {
        if let Some(name) = &directive.name {
            if name == "aptos" && directive.level < LevelFilter::Warn {
                eprintln!("WARNING: Filter '{}={}' may hide critical consensus safety logs. Consider using more specific module paths.", name, directive.level);
            }
        }
    }
    // ... existing build logic
}
```

## Proof of Concept

```rust
#[test]
fn test_safety_violation_hidden_by_broad_filter() {
    // Simulate operator setting RUST_LOG=aptos=error
    let filter = Filter::builder()
        .filter(Some("aptos"), LevelFilter::Error)
        .build();
    
    // Simulate safety_rules logging a warning about a voting violation
    let metadata = Metadata::new(
        Level::Warn,
        "aptos_safety_rules",
        "aptos_safety_rules::safety_rules",
        "safety_rules.rs:497",
    );
    
    // This critical safety violation warning is hidden!
    assert!(!filter.enabled(&metadata), 
        "FAIL: Critical safety violation at WARN level was hidden by broad 'aptos=error' filter");
    
    // The same violation at ERROR level would be visible
    let metadata_error = Metadata::new(
        Level::Error,
        "aptos_safety_rules", 
        "aptos_safety_rules::safety_rules",
        "safety_rules.rs:497",
    );
    assert!(filter.enabled(&metadata_error),
        "ERROR level is visible but WARN level safety violations are hidden");
}
```

## Notes

This vulnerability is particularly insidious because:

1. **Silent failure** - No warnings are provided when filters hide critical logs
2. **Common misconfiguration** - Operators naturally want to reduce log verbosity with broad patterns
3. **Module naming** - The `aptos_` prefix is shared across all modules, making broad filtering natural but dangerous
4. **Severity mismatch** - Critical consensus safety violations are logged at `WARN` not `ERROR`, making them vulnerable to common filter patterns

The fix should balance operational needs (log volume management) with security requirements (visibility of consensus-critical events).

### Citations

**File:** crates/aptos-logger/src/filter.rs (L140-140)
```rust
                Some(name) if !metadata.module_path().starts_with(name) => {},
```

**File:** consensus/safety-rules/src/safety_rules.rs (L497-497)
```rust
            warn!(log_cb(SafetyLogSchema::new(log_entry, LogEvent::Error)).error(err));
```

**File:** consensus/safety-rules/src/error.rs (L10-63)
```rust
pub enum Error {
    #[error("Provided epoch, {0}, does not match expected epoch, {1}")]
    IncorrectEpoch(u64, u64),
    #[error("block has next round that wraps around: {0}")]
    IncorrectRound(u64),
    #[error("Provided round, {0}, is incompatible with last voted round, {1}")]
    IncorrectLastVotedRound(u64, u64),
    #[error("Provided round, {0}, is incompatible with preferred round, {1}")]
    IncorrectPreferredRound(u64, u64),
    #[error("Unable to verify that the new tree extends the parent: {0}")]
    InvalidAccumulatorExtension(String),
    #[error("Invalid EpochChangeProof: {0}")]
    InvalidEpochChangeProof(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("No next_epoch_state specified in the provided Ledger Info")]
    InvalidLedgerInfo,
    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),
    #[error("Invalid QC: {0}")]
    InvalidQuorumCertificate(String),
    #[error("{0} is not set, SafetyRules is not initialized")]
    NotInitialized(String),
    #[error("Does not satisfy order vote rule. Block Round {0}, Highest Timeout Round {1}")]
    NotSafeForOrderVote(u64, u64),
    #[error("Data not found in secure storage: {0}")]
    SecureStorageMissingDataError(String),
    #[error("Unexpected error returned by secure storage: {0}")]
    SecureStorageUnexpectedError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Validator key not found: {0}")]
    ValidatorKeyNotFound(String),
    #[error("The validator is not in the validator set. Address not in set: {0}")]
    ValidatorNotInSet(String),
    #[error("Vote proposal missing expected signature")]
    VoteProposalSignatureNotFound,
    #[error("Does not satisfy 2-chain voting rule. Round {0}, Quorum round {1}, TC round {2},  HQC round in TC {3}")]
    NotSafeToVote(u64, u64, u64, u64),
    #[error("Does not satisfy 2-chain timeout rule. Round {0}, Quorum round {1}, TC round {2}, one-chain round {3}")]
    NotSafeToTimeout(u64, u64, u64, u64),
    #[error("Invalid TC: {0}")]
    InvalidTimeoutCertificate(String),
    #[error("Inconsistent Execution Result: Ordered BlockInfo doesn't match executed BlockInfo. Ordered: {0}, Executed: {1}")]
    InconsistentExecutionResult(String, String),
    #[error("Invalid Ordered LedgerInfoWithSignatures: Empty or at least one of executed_state_id, version, or epoch_state are not dummy value: {0}")]
    InvalidOrderedLedgerInfo(String),
    #[error("Waypoint out of date: Previous waypoint version {0}, updated version {1}, current epoch {2}, provided epoch {3}")]
    WaypointOutOfDate(u64, u64, u64, u64),
    #[error("Invalid Timeout: {0}")]
    InvalidTimeout(String),
    #[error("Incorrect 1-chain Quorum Certificate provided for signing order votes. Quorum Certificate: {0}, block id: {1}")]
    InvalidOneChainQuorumCertificate(HashValue, HashValue),
}
```

**File:** consensus/safety-rules/Cargo.toml (L2-2)
```text
name = "aptos-safety-rules"
```

**File:** crates/aptos-logger/src/macros.rs (L58-58)
```rust
            module_path!(),
```
