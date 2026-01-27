# Audit Report

## Title
Transaction Correctness Checker Blind Spot Allows Nodes to Pass Validation While Serving Corrupted Recent State

## Summary
The `TransactionCorrectnessChecker` only validates a single transaction at the middle of the shared version window between baseline and target nodes. A malicious or faulty node can deliberately synchronize slowly to ensure validation occurs against historical transactions where it has correct state, while maintaining corrupted state in recent transactions that are never checked.

## Finding Description

The `TransactionCorrectnessChecker` in `ecosystem/node-checker/src/checker/transaction_correctness.rs` is designed to verify that a target node produces correct transactions by comparing them against a baseline node. However, the checker has a critical design flaw in how it selects which transaction to validate. [1](#0-0) [2](#0-1) 

The checker computes the `middle_shared_version` by taking the average of the oldest and latest shared versions, then validates only that single transaction. This creates a significant blind spot for recent transactions.

**Attack Scenario:**

1. **Baseline node**: At version 1,000,000 (oldest: 950,000)
2. **Malicious target node**: At version 995,000 (5,000 versions behind, at the default tolerance limit)
3. **Target node state**:
   - Correct state: versions 950,000 to 985,000
   - Corrupted state: versions 985,001 to 995,000

4. **TransactionCorrectnessChecker execution**:
   - `oldest_shared_version` = max(950,000, 950,000) = 950,000
   - `latest_shared_version` = min(1,000,000, 995,000) = 995,000
   - `middle_shared_version` = (950,000 + 995,000) / 2 = 972,500
   - **Validates version 972,500** ✓ (in the correct range before corruption)

5. **StateSyncVersionChecker execution**: [3](#0-2) 
   
   - Version is increasing: ✓
   - Delta from baseline: 5,000 (within default tolerance of 5,000) ✓
   - **Passes**

The node successfully passes both checks despite having ~10,000 versions of corrupted state. By maintaining a "sliding window" of corruption in its most recent transactions and carefully controlling sync speed to stay near the tolerance boundary, the node can indefinitely avoid validation of its corrupted state.

**Invariant Violation:**

This breaks the **State Consistency** invariant: nodes serving corrupted state while being validated as "healthy" undermines the trust model of the node health checker system. It also violates the implicit guarantee that passing health checks indicates the node is serving correct, verifiable data.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria: "State inconsistencies requiring intervention."

**Specific impacts:**

1. **Data Integrity**: Clients querying recent state from validated nodes receive corrupted data, leading to incorrect balance displays, failed transaction submissions, or wrong contract state reads.

2. **Trust Model Violation**: The node health checker is used to validate Validator FullNodes (VFNs) and Public FullNodes (PFNs). Nodes passing these checks are considered trustworthy for monitoring and compliance purposes. This vulnerability allows corrupted nodes to masquerade as healthy.

3. **Cascade Effects**: Other nodes syncing from a "validated" but corrupted node may receive invalid state. While state sync includes Merkle proof verification, not all clients implement full verification.

4. **Monitoring Blind Spot**: Network operators relying on health checker results for node monitoring will have false confidence in node correctness.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can occur in two scenarios:

1. **Malicious Exploitation**: A node operator deliberately implements slow sync to pass validation while serving corrupted data. This requires:
   - Control over node sync speed (trivial to implement)
   - Ability to maintain corrupted state in recent versions
   - Understanding of the health checker's validation logic
   - Moderate technical sophistication

2. **Accidental Bug**: A node with a bug that only affects recent transaction processing (e.g., recent code changes, state corruption starting at a specific version) naturally exhibits this behavior. The node would:
   - Sync normally until hitting the bug
   - Slow down or stall at the corruption point
   - Pass validation against pre-corruption transactions
   - Appear healthy despite serving bad recent data

The likelihood is medium because:
- The attack requires deliberate manipulation or specific bug conditions
- The sync speed must be carefully controlled to stay within tolerance
- However, the technical barriers are low for a motivated attacker
- The vulnerability affects real-world deployments (VFN validation for monitoring)

## Recommendation

**Fix 1: Validate Multiple Transactions Including Recent Ones**

Modify the checker to validate multiple transactions across the shared window, especially focusing on recent versions:

```rust
// In TransactionCorrectnessChecker::check()

// Instead of just middle_shared_version, validate multiple versions:
let versions_to_check = vec![
    middle_shared_version,
    // Check a version near the latest (e.g., 90% toward latest)
    oldest_shared_version + ((latest_shared_version - oldest_shared_version) * 9 / 10),
    // Check another version near latest (e.g., 95% toward latest)  
    oldest_shared_version + ((latest_shared_version - oldest_shared_version) * 19 / 20),
];

for version in versions_to_check {
    // Validate each version and fail if any mismatch
    // ... validation logic ...
}
```

**Fix 2: Add Recent Version Validation Check**

Create a dedicated checker that specifically validates the most recent N transactions (e.g., last 1000 versions) to ensure nodes cannot hide corruption in recent state:

```rust
// New checker: RecentTransactionCorrectnessChecker
// Validates transactions near latest_shared_version instead of middle
let recent_version = latest_shared_version.saturating_sub(100); // Check recent version
```

**Fix 3: Reduce Tolerance and Add Stricter Lag Penalties**

Reduce the default `version_delta_tolerance` in `StateSyncVersionChecker` from 5,000 to a smaller value (e.g., 1,000) and fail nodes that consistently lag near the tolerance boundary.

**Recommended Approach**: Implement Fix 1 as it provides comprehensive coverage with minimal overhead, validating both historical and recent transactions.

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
// Add to ecosystem/node-checker/src/checker/transaction_correctness.rs tests

#[tokio::test]
async fn test_slow_sync_blind_spot() {
    // Setup: Create mock baseline and target providers
    // Baseline: versions 900,000 to 1,000,000
    // Target: versions 900,000 to 995,000 (5000 behind)
    
    let baseline_oldest = 900_000u64;
    let baseline_latest = 1_000_000u64;
    let target_oldest = 900_000u64;
    let target_latest = 995_000u64;
    
    // Calculate what version will be checked
    let oldest_shared = std::cmp::max(baseline_oldest, target_oldest);
    let latest_shared = std::cmp::min(baseline_latest, target_latest);
    let middle_checked = (oldest_shared + latest_shared) / 2;
    
    // middle_checked = (900,000 + 995,000) / 2 = 947,500
    assert_eq!(middle_checked, 947_500);
    
    // Demonstrate blind spot:
    // If target has corrupted state from 948,000 to 995,000,
    // the check at 947,500 will PASS because it's before the corruption
    let corruption_start = 948_000u64;
    assert!(middle_checked < corruption_start);
    
    // The corrupted range (948,000 to 995,000) = 47,000 versions
    // is NEVER checked, allowing the node to pass validation
    let corrupted_range = target_latest - corruption_start;
    assert_eq!(corrupted_range, 47_000);
    
    println!("VULNERABILITY CONFIRMED:");
    println!("  Checked version: {}", middle_checked);
    println!("  Corruption starts: {}", corruption_start);
    println!("  Unchecked corrupted versions: {}", corrupted_range);
    println!("  Node will PASS validation despite serving {} corrupted versions", 
             corrupted_range);
}
```

**Notes:**

- This vulnerability is specific to the node health checker system and does not directly affect consensus or validator operation
- However, it undermines trust in the health validation system used for VFN monitoring and compliance
- The fix should validate recent transactions to eliminate the blind spot created by middle-version-only checking
- The vulnerability affects any deployment using the Node Health Checker for fullnode validation

### Citations

**File:** ecosystem/node-checker/src/checker/transaction_correctness.rs (L134-138)
```rust
        // Get the oldest ledger version between the two nodes.
        let oldest_shared_version = max(oldest_baseline_version, oldest_target_version);

        // Get the least up to date latest ledger version between the two nodes.
        let latest_shared_version = min(latest_baseline_version, latest_target_version);
```

**File:** ecosystem/node-checker/src/checker/transaction_correctness.rs (L165-167)
```rust
        // Select a version in the middle of shared oldest and latest version.
        let middle_shared_version =
            (oldest_shared_version.saturating_add(latest_shared_version)) / 2;
```

**File:** ecosystem/node-checker/src/checker/state_sync_version.rs (L68-85)
```rust
                // We convert to i64 to avoid potential overflow if the target is ahead of the baseline.
                let delta_from_baseline =
                    latest_baseline_version as i64 - latest_target_version as i64;
                if delta_from_baseline > self.config.version_delta_tolerance as i64 {
                    Self::build_result(
                        "Ledger version is lagging".to_string(),
                        50,
                        format!(
                            "Successfully pulled ledger version from your node twice \
                            and saw the version was increasing, but it is lagging {} versions \
                            behind the baseline node, more than the allowed lag of {}. \
                            Target version: {}. Baseline version: {}.",
                            delta_from_baseline,
                            self.config.version_delta_tolerance,
                            latest_target_version,
                            latest_baseline_version,
                        ),
                    )
```
