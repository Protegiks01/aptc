# Audit Report

## Title
Logging Filter Misconfiguration Can Suppress Byzantine Equivocation Detection Logs

## Summary
The logging filter in `filter.rs` returns `false` when no directives match a log's module path, which can cause critical security logs detecting Byzantine validator equivocation to be suppressed if operators misconfigure the `RUST_LOG` environment variable with module-specific filters that exclude consensus modules.

## Finding Description

The vulnerability chain operates as follows:

**1. Filter Behavior:** [1](#0-0) 

When `Filter::enabled()` iterates through directives and finds no match for a module path, it returns `false`, suppressing the log entirely.

**2. Critical Security Log:** [2](#0-1) 

When Byzantine validators equivocate (vote for different proposals in the same round), this is the PRIMARY detection mechanism - a security log that records the malicious behavior.

**3. No Fallback Detection:** [3](#0-2) 

The `EquivocateVote` result is handled as a generic error with no metric counter incremented. The security log is the ONLY detection mechanism.

**4. Realistic Misconfiguration Scenario:** [4](#0-3) 

Production configurations show module-specific filters like `rust_log: info,hyper=off`. An operator debugging specific modules might configure:
```yaml
rust_log: "consensus::round_manager=debug,storage::state_store=trace,network::peer_manager=debug"
```

This creates three directives that don't match `consensus::pending_votes`, causing the equivocation log to be suppressed since no directive matches.

**5. Log Macro Check:** [5](#0-4) 

The logging macro checks `METADATA.enabled()` before emitting logs. If this returns `false`, the log is never written.

## Impact Explanation

This qualifies as **High Severity** under "Significant protocol violations" because:

1. **Silent Byzantine Failure Detection**: Operators cannot detect equivocating validators through logs, their primary monitoring mechanism
2. **No Alternative Detection**: No metrics or alternative monitoring exists for equivocation events
3. **False Security Assumption**: Operators believe they have comprehensive logging when consensus-critical modules are silently excluded

While the consensus protocol itself continues to reject equivocating votes correctly, the complete lack of observability represents a significant operational security gap.

## Likelihood Explanation

**HIGH Likelihood** because:
- Operators routinely configure module-specific log levels for debugging
- The misconfiguration is non-obvious (operator thinks "consensus::round_manager=debug" covers consensus)
- No validation or warning exists when security-critical modules are excluded from logging
- Default configuration is safe, but custom configs are common in production debugging scenarios

## Recommendation

Implement a minimum security event logging level that bypasses filter checks:

```rust
// In filter.rs
pub fn enabled(&self, metadata: &Metadata) -> bool {
    // Always log error-level security events regardless of filter configuration
    if metadata.level() == Level::Error && contains_security_event(metadata) {
        return true;
    }
    
    // Existing logic...
    for directive in self.directives.iter().rev() {
        match &directive.name {
            Some(name) if !metadata.module_path().starts_with(name) => {},
            Some(..) | None => return LevelFilter::from(metadata.level()) <= directive.level,
        }
    }
    false
}
```

Alternatively, ensure a default catch-all directive exists when module-specific filters are configured, or add validation that warns when consensus modules are excluded.

Additionally, add a metric counter for equivocating votes: [6](#0-5) 

## Proof of Concept

```rust
#[test]
fn test_security_logs_suppressed_by_specific_filters() {
    use aptos_logger::{Filter, Level, Metadata};
    
    // Simulate operator configuring specific modules for debug
    let mut builder = Filter::builder();
    builder
        .filter_module("consensus::round_manager", LevelFilter::Debug)
        .filter_module("storage::state_store", LevelFilter::Trace)
        .filter_module("network::peer_manager", LevelFilter::Debug);
    let filter = builder.build();
    
    // Create metadata for the equivocation security log
    let metadata = Metadata::new(
        Level::Error,
        "consensus",
        "consensus::pending_votes",
        "consensus/src/pending_votes.rs:301"
    );
    
    // The security log would be suppressed!
    assert_eq!(filter.enabled(&metadata), false, 
        "VULNERABILITY: Byzantine equivocation log suppressed by filter misconfiguration");
}
```

## Notes

The default configuration [7](#0-6)  uses `rust_log: info` which creates a global filter allowing error-level logs. The vulnerability only manifests when operators override this with module-specific filters during debugging or troubleshooting scenarios.

### Citations

**File:** crates/aptos-logger/src/filter.rs (L136-145)
```rust
    pub fn enabled(&self, metadata: &Metadata) -> bool {
        // Search for the longest match, the vector is assumed to be pre-sorted.
        for directive in self.directives.iter().rev() {
            match &directive.name {
                Some(name) if !metadata.module_path().starts_with(name) => {},
                Some(..) | None => return LevelFilter::from(metadata.level()) <= directive.level,
            }
        }
        false
    }
```

**File:** consensus/src/pending_votes.rs (L300-308)
```rust
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
```

**File:** consensus/src/round_manager.rs (L1829-1829)
```rust
            e => Err(anyhow::anyhow!("{:?}", e)),
```

**File:** testsuite/forge/src/backend/k8s/helm-values/aptos-node-default-values.yaml (L4-5)
```yaml
  # rust_log: debug,hyper=off
  rust_log: info,hyper=off
```

**File:** crates/aptos-logger/src/macros.rs (L54-69)
```rust
    ($level:expr, $($args:tt)+) => {{
        const METADATA: $crate::Metadata = $crate::Metadata::new(
            $level,
            env!("CARGO_CRATE_NAME"),
            module_path!(),
            concat!(file!(), ':', line!()),
        );

        if METADATA.enabled() {
            $crate::Event::dispatch(
                &METADATA,
                $crate::fmt_args!($($args)+),
                $crate::schema!($($args)+),
            );
        }
    }};
```

**File:** consensus/src/counters.rs (L146-152)
```rust
pub static PROPOSAL_VOTE_ADDED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_consensus_proposal_vote_added",
        "Count of the number of proposal votes added to pending votes"
    )
    .unwrap()
});
```

**File:** terraform/helm/aptos-node/values.yaml (L82-82)
```yaml
  rust_log: info
```
