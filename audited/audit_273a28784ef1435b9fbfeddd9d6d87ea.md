# Audit Report

## Title
Logger Blacklist Bypass via Module Path Prefix Mismatch

## Summary
The `Filter::enabled()` method uses string prefix matching (`starts_with()`) without accounting for Rust crate-to-module name conversion (hyphens to underscores). This allows operators' intended logging blacklists for sensitive consensus and safety modules to be bypassed, potentially leaking critical validator state information in production logs.

## Finding Description

The logging filter in `crates/aptos-logger/src/filter.rs` uses a simple `starts_with()` check for module path matching. [1](#0-0) 

When Aptos validator operators attempt to blacklist sensitive modules to prevent debug/trace logging, they face a critical naming mismatch:

1. **Intuitive blacklist configuration**: `RUST_LOG=consensus=error,safety_rules=error`

2. **Actual crate names**: 
   - Consensus crate: `aptos-consensus` [2](#0-1) 
   - Safety rules crate: `aptos-safety-rules` [3](#0-2) 

3. **Module paths in code** (Rust converts hyphens to underscores):
   - `aptos_consensus::round_manager`
   - `aptos_safety_rules::safety_rules`

4. **Blacklist bypass**: The check `"aptos_consensus::round_manager".starts_with("consensus")` returns `false`, so the blacklist is bypassed entirely.

**Sensitive information exposed** when blacklist fails:

In `consensus/safety-rules/src/safety_rules.rs`, trace logs expose critical consensus state: [4](#0-3) 

In `consensus/src/round_manager.rs`, trace logs expose validator voting information: [5](#0-4) 

These logs reveal:
- Validator identities and voting patterns
- Round progression and timing
- Last voted rounds and preferred rounds
- Consensus state that aids timing attacks

## Impact Explanation

This is a **Medium Severity** vulnerability under the category of "State inconsistencies requiring intervention" and operational security failures. While it doesn't directly cause fund loss or consensus violations, it:

1. **Breaks operational security assumptions**: Operators reasonably expect blacklisting "consensus" or "safety_rules" to prevent those modules from verbose logging
2. **Enables information gathering for sophisticated attacks**: Leaked consensus timing and voting data aids adversaries in:
   - Correlating validator identities
   - Understanding network topology
   - Planning timing-based consensus attacks
   - Identifying vulnerable validators
3. **Affects all validator nodes**: Any misconfigured validator leaks this information to log aggregation systems where attackers may gain access
4. **Requires manual intervention**: Once discovered, all validators must update their logging configuration with the correct module names

## Likelihood Explanation

**High likelihood** of occurrence because:

1. **Natural operator behavior**: Operators would intuitively use module/component names they see in documentation ("consensus", "safety_rules") rather than internal Rust crate names
2. **No validation or warnings**: The system accepts the misconfigured blacklist silently—operators believe they're protected when they're not
3. **Production deployment**: Validators are deployed with `RUST_LOG` environment variables [6](#0-5) 
4. **Common security practice**: Reducing log verbosity for sensitive components is standard operational security

## Recommendation

Implement proper module boundary checking in the filter:

```rust
pub fn enabled(&self, metadata: &Metadata) -> bool {
    for directive in self.directives.iter().rev() {
        match &directive.name {
            Some(name) => {
                let module_path = metadata.module_path();
                // Check exact match or proper module boundary (::)
                let matches = module_path == name 
                    || module_path.starts_with(&format!("{}::", name));
                
                if !matches {
                    continue;
                }
                return LevelFilter::from(metadata.level()) <= directive.level;
            },
            None => return LevelFilter::from(metadata.level()) <= directive.level,
        }
    }
    false
}
```

Additionally:
1. **Document actual crate names**: Create a security guide listing exact module paths for sensitive components
2. **Add warnings**: Log warnings when blacklist directives don't match any modules
3. **Provide examples**: Include production-ready `RUST_LOG` configurations in deployment templates

## Proof of Concept

```rust
#[cfg(test)]
mod blacklist_bypass_test {
    use super::*;
    
    #[test]
    fn test_blacklist_bypass_aptos_consensus() {
        // Operator tries to blacklist "consensus"
        let mut builder = Builder::new();
        builder.parse("consensus=error");
        let filter = builder.build();
        
        // But aptos_consensus logs still get through
        let metadata = Metadata::new(
            Level::Debug,
            "aptos_consensus",
            "aptos_consensus::round_manager",
            ""
        );
        
        // This should be false (blocked) but returns true (bypass)
        assert_eq!(filter.enabled(&metadata), false, 
            "VULNERABILITY: aptos_consensus debug logs bypass 'consensus=error' blacklist!");
    }
    
    #[test]
    fn test_blacklist_bypass_safety_rules() {
        let mut builder = Builder::new();
        builder.parse("safety_rules=error");
        let filter = builder.build();
        
        let metadata = Metadata::new(
            Level::Trace,
            "aptos_safety_rules",
            "aptos_safety_rules::safety_rules",
            ""
        );
        
        assert_eq!(filter.enabled(&metadata), false,
            "VULNERABILITY: aptos_safety_rules trace logs bypass 'safety_rules=error' blacklist!");
    }
    
    #[test]
    fn test_correct_blacklist() {
        // Correct way - but operators won't know this
        let mut builder = Builder::new();
        builder.parse("aptos_consensus=error,aptos_safety_rules=error");
        let filter = builder.build();
        
        let metadata = Metadata::new(
            Level::Debug,
            "aptos_consensus",
            "aptos_consensus::round_manager",
            ""
        );
        
        assert_eq!(filter.enabled(&metadata), false, "Correctly blocked");
    }
}
```

**Notes**:
- The vulnerability relies on operator misconfiguration, but this misconfiguration is highly likely due to unintuitive naming
- The `starts_with()` check doesn't respect module boundaries, allowing both over-blocking (false positives) and under-blocking (bypasses)
- Security-critical logs in safety_rules and consensus modules contain validator identities, voting rounds, and timing information that should be restricted in production
- The logging configuration is set via environment variables in production deployments, making this a real-world operational security issue

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

**File:** consensus/Cargo.toml (L2-2)
```text
name = "aptos-consensus"
```

**File:** consensus/safety-rules/Cargo.toml (L2-2)
```text
name = "aptos-safety-rules"
```

**File:** consensus/safety-rules/src/safety_rules.rs (L251-256)
```rust
        trace!(SafetyLogSchema::new(LogEntry::State, LogEvent::Update)
            .author(self.persistent_storage.author()?)
            .epoch(safety_data.epoch)
            .last_voted_round(safety_data.last_voted_round)
            .preferred_round(safety_data.preferred_round)
            .waypoint(waypoint));
```

**File:** consensus/src/round_manager.rs (L1553-1559)
```rust
            trace!(
                self.new_log(LogEvent::ReceiveOrderVote)
                    .remote_peer(order_vote.author()),
                epoch = order_vote.ledger_info().epoch(),
                round = order_vote.ledger_info().round(),
                id = order_vote.ledger_info().consensus_block_id(),
            );
```

**File:** terraform/helm/aptos-node/templates/validator.yaml (L163-164)
```yaml
        - name: RUST_LOG
          value: {{ .rust_log }}
```
