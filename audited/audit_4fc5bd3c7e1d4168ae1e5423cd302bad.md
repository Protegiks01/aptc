# Audit Report

## Title
Insecure Default Logging Level in Filter Parser Enables Information Disclosure via Telemetry

## Summary
The logging filter parser in `filter.rs` contains a dangerous fallback behavior: when a directive string fails to parse as a log level, it defaults to `LevelFilter::max()` (TRACE) instead of a restrictive level. When validators misconfigure `RUST_LOG_TELEMETRY` environment variable (e.g., setting `RUST_LOG_TELEMETRY=consensus` without specifying a level), all trace-level consensus logs including sensitive voting decisions are transmitted to remote telemetry services over the network.

## Finding Description

The vulnerability exists in the directive parsing logic: [1](#0-0) 

When parsing `RUST_LOG_TELEMETRY=consensus`, the parser attempts to interpret "consensus" as a log level. When this fails, it treats "consensus" as a module name and applies `LevelFilter::max()` which is TRACE: [2](#0-1) 

This enables trace-level logging for all consensus modules. The telemetry system is configured separately from local logging: [3](#0-2) 

When telemetry is enabled (default configuration), trace logs are sent to remote services: [4](#0-3) 

The telemetry sender compresses and transmits logs over HTTPS to remote endpoints: [5](#0-4) 

Sensitive consensus information logged at trace level includes: [6](#0-5) 

The `run_and_log` wrapper logs all voting operations at trace level: [7](#0-6) 

**Attack Scenario:**
1. Validator operator misconfigures `RUST_LOG_TELEMETRY=consensus` (common mistake - forgetting `=error` suffix)
2. Parser fails to interpret "consensus" as log level, defaults to TRACE for consensus module
3. All consensus trace logs now transmitted to telemetry backend
4. Attacker with access to telemetry service observes validator voting patterns, preferred rounds, last voted rounds, and strategic consensus state

## Impact Explanation

Per Aptos bug bounty criteria, this is classified as **Low Severity** - "Minor information leaks". However, it has concerning implications:

- Exposes validator voting strategy and internal state to telemetry backends
- Enables pattern analysis across multiple validators if telemetry is compromised
- Could facilitate timing attacks or consensus manipulation by sophisticated attackers
- Telemetry is enabled by default: [8](#0-7) 

While this doesn't directly break consensus safety or cause fund loss, strategic information disclosure could assist in more sophisticated attacks.

## Likelihood Explanation

**Moderate Likelihood** - Requires two conditions:
1. Operator misconfiguration (setting module name without level - a realistic mistake)
2. Attacker access to telemetry backend (compromised infrastructure or insider threat)

The misconfiguration is easy to make but requires operator-level access. Exploitation requires additional compromise of telemetry infrastructure.

## Recommendation

Change the fallback behavior to use a restrictive default instead of TRACE:

```rust
(Some(level_or_module), None, None) => match level_or_module.parse() {
    Ok(level) => (None, level),
    Err(_) => (Some(level_or_module), LevelFilter::Error), // Changed from max() to Error
},
```

Additionally, add validation warnings when directives parse as module names without explicit levels, and document proper RUST_LOG_TELEMETRY format in validator setup guides.

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
#[test]
fn test_misconfigured_module_defaults_to_trace() {
    use std::env;
    
    // Simulate operator misconfiguration
    env::set_var("RUST_LOG_TELEMETRY", "consensus");
    
    let mut builder = Filter::builder();
    builder.with_env("RUST_LOG_TELEMETRY");
    let filter = builder.build();
    
    // Create consensus module metadata
    let metadata = Metadata::new(Level::Trace, "consensus", "consensus::safety_rules", "");
    
    // Verify trace logs are enabled (vulnerability)
    assert!(filter.enabled(&metadata));
    
    // Expected behavior: should reject trace logs
    // assert!(!filter.enabled(&metadata));
}
```

## Notes

This vulnerability requires operator misconfiguration to trigger and access to telemetry infrastructure to exploit. While the impact is limited to information disclosure (Low severity per bug bounty), the insecure default in the parser is a legitimate security hardening concern. The fix is straightforward and should be implemented to prevent accidental exposure of sensitive validator state through telemetry channels.

### Citations

**File:** aptos-core-016/crates/aptos-logger/src/filter.rs (L22-26)
```rust

```

**File:** aptos-core-016/crates/aptos-logger/src/filter.rs (L171-173)
```rust

```

**File:** aptos-core-016/crates/aptos-logger/src/aptos_logger.rs (L406-420)
```rust

```

**File:** aptos-core-016/crates/aptos-logger/src/aptos_logger.rs (L642-652)
```rust

```

**File:** aptos-core-016/crates/aptos-telemetry/src/sender.rs (L195-214)
```rust

```

**File:** aptos-core-016/consensus/safety-rules/src/logging.rs (L11-23)
```rust

```

**File:** aptos-core-016/consensus/safety-rules/src/safety_rules.rs (L488-493)
```rust

```

**File:** aptos-core-016/config/src/config/logger_config.rs (L40-56)
```rust

```
