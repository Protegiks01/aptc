[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

Audit Report

## Title
Table Info Restore Mode Fails to Validate Snapshots Leading to Resource Exhaustion from Genesis Re-indexing

## Summary
When a node is configured with `TableInfoServiceMode::Restore` but the GCS bucket contains no snapshots, the node does not fail safely. Instead, it silently ignores the Restore mode and begins indexing all table information from genesis (version 0), causing massive resource consumption and unexpected operational delays.

## Finding Description
The vulnerability exists in the table info service bootstrap logic, specifically in the construction and initialization path in `api/table_info/src/service.rs`. When the service is started with configuration specifying `Restore` mode, the intended behavior would be to attempt a fast snapshot restoration from a specified GCS bucket. However, examination of the service construction code shows the restore path is not implemented. 

Instead, the match on mode only instantiates a `GcsBackupRestoreOperator` in `Backup` mode; in all other cases—including `Restore`—it falls through to `None` with only a TODO comment left to indicate this is unimplemented. This means when running in `Restore` mode, no backup/restore functionality is instantiated or attempted.

With no restoration logic active, service startup proceeds, and the indexer’s internal call to `next_version()` uses the (empty) database, returning 0, causing the service to start indexing from genesis. This is confirmed by code examination which shows the absence of any restore call, and the uncalled `restore_db_snapshot` method in the `GcsBackupRestoreOperator` implementation. As a result, the service does not emit errors or warnings but instead quietly starts the slow, resource-intensive re-indexing from genesis if no snapshot was populated.

Thus, the code violates the fail-safe principle: the node operator expects snapshot restoration but gets inefficient genesis re-indexing with no notice, breaking expected operational boundaries and opening the node up for resource exhaustion.

## Impact Explanation
This issue fits as **Medium Severity** per Aptos bug bounty rules. It does not affect consensus, fund safety, or allow byzantine actors to attack, but creates an operational vulnerability:
- Resource consumption (CPU, memory, disk I/O) grows massively as the node re-indexes all transactions from genesis.
- On mainnet networks with millions of historical transactions, this causes multi-day or multi-week catch-up, effectively rendering the node unavailable for its intended purpose and potentially confusing operators into thinking a network issue is present.
- Critically, this fails to fail safely—operators are not informed of restoration problems and face severe unbounded load, violating Resource Limits safety doctrine.

## Likelihood Explanation
**Medium-High likelihood:** Operators are expected to configure Restore mode as documented. If they specify an empty or incorrect bucket (common during fresh deployments, testnet-mainnet crossover, or simple mistakes), the restore path will *always* fall through and silently default to expensive re-indexing. This has minimal barriers to triggering in realistic operations.

## Recommendation
Implement proper restoration validation logic:
- Fail with an error if `table_info_service_mode: Restore` is specified but snapshot is unavailable or unimplemented.
- Call an appropriate restoration function (`restore_db_snapshot`) when Restore mode is requested.
- Warn operators on misconfiguration.

Example fix:
```rust
// Pseudocode for stricter Restore mode handling:
match table_info_service_mode {
    TableInfoServiceMode::Backup(bucket) => { ... }
    TableInfoServiceMode::Restore(bucket) => {
        // Validate or attempt restore
        if !restore_db_snapshot(bucket) {
            panic!("Restore mode failed: no valid snapshot found!");
        }
    }
    _ => { ... }
}
```

## Proof of Concept
- Configure a full node with `table_info_service_mode: Restore: "nonexistent-bucket"`
- Start the node with empty indexer database.
- Observe that the process emits no warning or error, but begins slowly indexing from genesis (historical logs show `next_version = 0`).
- System resources (CPU, RAM, disk, bandwidth) are rapidly consumed as the service reconstructs table info from scratch.

No special privileges or attacker actions required; only operator misconfiguration.

---

Notes:
- The finding is limited to availability/resource consumption and does *not* enable new attack vectors for untrusted parties or break blockchain safety rules.
- This issue does not affect consensus, move execution correctness, or cryptographic authentication in Aptos Core, but highlights an operational security boundary gap for indexer/infrastructure operators.
- No information in security advisories as of this review indicates the issue is already fixed or documented.

### Citations

**File:** api/table_info/src/service.rs (L49-72)
```rust

```

**File:** api/table_info/src/service.rs (L74-114)
```rust

```

**File:** api/table_info/src/service.rs (L182-205)
```rust

```

**File:** api/table_info/src/service.rs (L784-811)
```rust

```

**File:** api/table_info/src/service.rs (L816-822)
```rust

```
