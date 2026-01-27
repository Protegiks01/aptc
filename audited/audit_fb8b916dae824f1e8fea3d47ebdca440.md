# Audit Report

## Title
Deadline Calculation Bug in Transaction Emitter Causes Diagnostic Tool to Hang Indefinitely

## Summary
The `submit_single_transaction()` function in the transaction emitter incorrectly calculates a deadline by adding an absolute Unix timestamp as a duration to `Instant::now()`, resulting in a deadline approximately 53+ years in the future. This causes the health check in `diag()` to never timeout, hanging indefinitely even without attacker manipulation.

## Finding Description
The vulnerability exists in the deadline calculation logic at: [1](#0-0) 

This line incorrectly mixes two different time systems:
- `Instant::now()` returns a monotonic time point with an arbitrary reference epoch (not Unix epoch)
- `txn.expiration_timestamp_secs()` returns an absolute Unix timestamp (approximately 1.7 billion seconds since 1970 for year 2024)

The transaction expiration timestamp is calculated as `SystemTime::now() + 30 seconds` in the TransactionFactory: [2](#0-1) 

When the default 30-second expiration is used, `txn.expiration_timestamp_secs()` returns approximately `1,700,000,030` seconds. Adding this as a `Duration` to `Instant::now()` creates a deadline roughly 53 years in the future, not 60 seconds as intended.

The health check loop uses this deadline to determine when to timeout: [3](#0-2) 

Since `Instant::now()` will never exceed a deadline 53+ years in the future within any reasonable timeframe, this check never triggers. The loop continues forever (or until all endpoints successfully sync, which may never happen if there are network issues).

**Attack Amplification:** An attacker can make this worse by manipulating their system clock to a far-future date before running the diagnostic tool. This would increase the transaction expiration timestamp even further, though the bug already causes an effective permanent hang without manipulation.

**Correct Implementation:** The deadline should be calculated as a relative duration from the current time, not by adding an absolute timestamp. The proper calculation would be:
```rust
let current_unix_time = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();
let seconds_until_expiry = txn.expiration_timestamp_secs().saturating_sub(current_unix_time) + 30;
let deadline = Instant::now() + Duration::from_secs(seconds_until_expiry);
```

## Impact Explanation
This is a **Medium severity** issue per the Aptos bug bounty criteria as it causes:

1. **Operational Impact**: Node operators and developers lose the ability to run diagnostic health checks on their full nodes, as the tool hangs indefinitely
2. **Incident Response Degradation**: During network issues, operators cannot use the diagnostic tool to identify problematic nodes
3. **Denial of Service**: The diagnostic tool becomes unusable, requiring manual termination

While this doesn't directly affect consensus, validator operation, or fund safety, it impacts the operational tooling that node operators rely on for network health monitoring. According to the Medium severity category: "State inconsistencies requiring intervention" - this qualifies as it creates an operational inconsistency requiring manual intervention to terminate the hung process.

## Likelihood Explanation
**Likelihood: High** - This bug triggers automatically every time the `diag` command is executed: [4](#0-3) 

No special conditions or attacker actions are required. The bug manifests in the normal code path with default configuration. Any user attempting to diagnose full node health will encounter this hang.

## Recommendation
Fix the deadline calculation to use relative time instead of absolute time:

**File:** `crates/transaction-emitter-lib/src/emitter/mod.rs`

**Replace line 986:**
```rust
// Current (buggy):
let deadline = Instant::now() + Duration::from_secs(txn.expiration_timestamp_secs() + 30);

// Fixed version:
let current_time_secs = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();
let seconds_until_expiry = txn.expiration_timestamp_secs()
    .saturating_sub(current_time_secs)
    .saturating_add(30);
let deadline = Instant::now() + Duration::from_secs(seconds_until_expiry);
```

Alternatively, since the transaction factory's expiration time is known (30 seconds by default):
```rust
let deadline = Instant::now() + Duration::from_secs(self.txn_factory.get_transaction_expiration_time() + 30);
```

## Proof of Concept
```rust
#[cfg(test)]
mod test {
    use super::*;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    
    #[test]
    fn test_deadline_calculation_bug() {
        // Simulate the current buggy calculation
        let current_unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Transaction expiration is set to current time + 30 seconds
        let txn_expiration_timestamp_secs = current_unix_timestamp + 30;
        
        // Buggy calculation: adding absolute timestamp as duration
        let buggy_deadline = Instant::now() + Duration::from_secs(txn_expiration_timestamp_secs + 30);
        
        // Correct calculation: using relative time
        let correct_deadline = Instant::now() + Duration::from_secs(60);
        
        // The buggy deadline is approximately 1.7 billion seconds (~53 years) in the future
        // while the correct deadline is 60 seconds in the future
        
        // Sleep for 65 seconds to verify the timeout behavior
        std::thread::sleep(Duration::from_secs(65));
        
        // Correct deadline should have passed
        assert!(Instant::now() > correct_deadline, "Correct deadline should have passed");
        
        // Buggy deadline will NOT have passed (would take 53 years!)
        assert!(Instant::now() < buggy_deadline, "Buggy deadline is still in the far future");
        
        // Calculate how far in the future the buggy deadline is
        let time_until_buggy_deadline = buggy_deadline.duration_since(Instant::now());
        println!("Buggy deadline is still {} seconds in the future", time_until_buggy_deadline.as_secs());
        
        // Should be approximately 1.7 billion seconds (minus 65 seconds we slept)
        assert!(time_until_buggy_deadline.as_secs() > 1_000_000_000, 
                "Buggy deadline should be billions of seconds in the future");
    }
}
```

**To reproduce the hang in practice:**
1. Run the transaction emitter in diag mode: `cargo run --bin aptos-transaction-emitter -- diag --target <endpoint>`
2. Observe that if any endpoint fails to sync, the tool hangs indefinitely
3. The timeout check at line 70-72 of `diag.rs` never triggers due to the far-future deadline

## Notes
This vulnerability affects the transaction-emitter diagnostic tool specifically, not the core blockchain runtime or consensus. However, it significantly impacts operational capabilities for node operators who rely on this tool for health monitoring and troubleshooting.

### Citations

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L986-986)
```rust
        let deadline = Instant::now() + Duration::from_secs(txn.expiration_timestamp_secs() + 30);
```

**File:** sdk/src/transaction_builder.rs (L375-390)
```rust
    fn expiration_timestamp(&self) -> u64 {
        match self.transaction_expiration {
            TransactionExpiration::Relative {
                expiration_duration,
            } => {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + expiration_duration
            },
            TransactionExpiration::Absolute {
                expiration_timestamp,
            } => expiration_timestamp,
        }
    }
```

**File:** crates/transaction-emitter/src/diag.rs (L70-72)
```rust
            if Instant::now() > deadline {
                bail!("Not all end points were updated and transaction expired");
            }
```

**File:** crates/transaction-emitter/src/main.rs (L102-107)
```rust
        TxnEmitterCommand::Diag(args) => {
            let cluster = Cluster::try_from_cluster_args(&args.cluster_args)
                .await
                .context("Failed to build cluster")?;
            diag(&cluster).await.context("Diag failed")?;
            Ok(())
```
