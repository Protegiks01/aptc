# Audit Report

## Title
Missing Automated Alerts for Core Mempool Invariant Violations Enable Undetected Denial-of-Service Attacks

## Summary
The `CORE_MEMPOOL_INVARIANT_VIOLATION_COUNT` metric tracks critical data structure corruption in the mempool's ParkingLotIndex, but no automated Prometheus alerts are configured to notify operators when this counter increments. This monitoring gap allows potential denial-of-service conditions to persist undetected, as corrupted parking lot state prevents transaction eviction when mempool is full. [1](#0-0) 

## Finding Description

The ParkingLotIndex maintains a critical invariant: for all accounts, `data.get(account_indices.get(account))` must return the account's parked transactions. When this invariant is violated, the counter increments and an error is logged, but the transaction insertion silently fails. [2](#0-1) [3](#0-2) 

When mempool reaches capacity, the eviction mechanism relies on `get_poppable()` to select transactions from the parking lot for removal. If the parking lot index is corrupted and returns stale transaction pointers, eviction fails immediately. [4](#0-3) 

The Prometheus alerting configuration contains various mempool alerts (capacity, growth rate, upstream peers) but lacks any alert for invariant violations. [5](#0-4) 

While a Grafana dashboard panel visualizes this metric, passive monitoring requires operators to actively check dashboards rather than receiving proactive alerts. [6](#0-5) 

## Impact Explanation

**Severity: Medium**

This is a security monitoring gap rather than a directly exploitable vulnerability. However, if the invariant violation occurs (through memory corruption, a latent concurrency bug, or an undiscovered attack vector), the consequences include:

1. **Denial of Service**: Corrupted parking lot prevents eviction, causing mempool to remain full and reject legitimate transactions
2. **Extended Attack Window**: Without alerts, the issue persists until manual detection via dashboard review or user complaints
3. **Service Degradation**: Affected nodes cannot process new transactions, reducing network throughput

The impact qualifies as **Medium severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" - the corrupted mempool state requires node restart or manual intervention to resolve.

## Likelihood Explanation

**Likelihood: Low to Medium**

While the mempool is protected by proper mutex synchronization and contains no unsafe code that would naturally trigger this condition, the invariant violation could occur through:

- Latent concurrency bugs not yet discovered
- Memory corruption from hardware failures or external attacks
- Future code changes introducing bugs in the swap_remove logic [7](#0-6) 

The lack of alerting transforms a potentially rare event into a more impactful incident by delaying detection and response.

## Recommendation

Add a Prometheus alert rule to `terraform/helm/monitoring/files/rules/alerts.yml` that triggers when the invariant violation counter increments:

```yaml
- alert: Core Mempool Invariant Violation Detected
  expr: increase(aptos_mempool_core_mempool_invariant_violated_count[5m]) > 0
  for: 1m
  labels:
    severity: error
    summary: "Core mempool data structure invariant violated"
  annotations:
    description: "The parking lot index invariant has been violated on {{$labels.kubernetes_pod_name}}, indicating potential memory corruption or concurrency bug. This may prevent transaction eviction and cause mempool DoS. Immediate investigation required."
```

Additionally, consider enhancing the error handling in the ParkingLotIndex to attempt recovery or fail-safe behavior rather than silently returning when the invariant is violated.

## Proof of Concept

**Note**: This finding identifies a monitoring gap rather than a directly exploitable vulnerability. A complete PoC would require triggering the underlying invariant violation, which depends on discovering the root cause (latent bug, memory corruption, etc.).

To verify the monitoring gap exists:

1. Check `terraform/helm/monitoring/files/rules/alerts.yml` - confirm no alert exists for `aptos_mempool_core_mempool_invariant_violated_count`
2. Deploy a test scenario that simulates the invariant violation by corrupting the ParkingLotIndex state
3. Verify that only logs and dashboard metrics update, but no alerts fire
4. Confirm that mempool eviction fails when the parking lot is corrupted, preventing new transaction acceptance

Without a known exploit path to trigger the invariant violation organically, this remains a **defense-in-depth monitoring gap** rather than a fully exploitable attack.

---

## Notes

After thorough analysis, while this represents a legitimate monitoring gap that reduces defense-in-depth, **I cannot identify a concrete, reproducible attack path that an unprivileged attacker could use to trigger the invariant violation**. The mempool code appears properly synchronized with mutex protection and contains no unsafe code blocks.

The finding highlights an observability weakness rather than a directly exploitable vulnerability. Given the extremely high validation bar required and the lack of a demonstrable exploit, this may not qualify for bug bounty classification despite being a valid security hardening recommendation.

### Citations

**File:** mempool/src/counters.rs (L624-630)
```rust
pub static CORE_MEMPOOL_INVARIANT_VIOLATION_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_mempool_core_mempool_invariant_violated_count",
        "Number of times a core mempool invariant was violated"
    )
    .unwrap()
});
```

**File:** mempool/src/core_mempool/index.rs (L530-536)
```rust
    // DS invariants:
    // 1. for each entry (account, txns) in `data`, `txns` is never empty
    // 2. for all accounts, data.get(account_indices.get(`account`)) == (account, sequence numbers of account's txns)
    data: Vec<(AccountAddress, BTreeSet<(u64, HashValue)>)>,
    account_indices: HashMap<AccountAddress, usize>,
    size: usize,
}
```

**File:** mempool/src/core_mempool/index.rs (L558-570)
```rust
                let is_new_entry = match self.account_indices.get(sender) {
                    Some(index) => {
                        if let Some((_account, seq_nums)) = self.data.get_mut(*index) {
                            seq_nums.insert((sequence_number, hash))
                        } else {
                            counters::CORE_MEMPOOL_INVARIANT_VIOLATION_COUNT.inc();
                            error!(
                                LogSchema::new(LogEntry::InvariantViolated),
                                "Parking lot invariant violated: for account {}, account index exists but missing entry in data",
                                sender
                            );
                            return;
                        }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L425-446)
```rust
            while let Some(txn_pointer) = self.parking_lot_index.get_poppable() {
                if let Some(txn) = self
                    .transactions
                    .get_mut(&txn_pointer.sender)
                    .and_then(|txns| txns.remove(&txn_pointer.replay_protector))
                {
                    debug!(
                        LogSchema::new(LogEntry::MempoolFullEvictedTxn).txns(TxnsLog::new_txn(
                            txn.get_sender(),
                            txn.get_replay_protector()
                        ))
                    );
                    evicted_bytes += txn.get_estimated_bytes() as u64;
                    evicted_txns += 1;
                    self.index_remove(&txn);
                    if !self.is_full() {
                        break;
                    }
                } else {
                    error!("Transaction not found in mempool while evicting from parking lot");
                    break;
                }
```

**File:** terraform/helm/monitoring/files/rules/alerts.yml (L44-79)
```yaml
    # Mempool alerts
  - alert: Mempool has no active upstream peers
    expr: (sum by (kubernetes_pod_name) (aptos_mempool_active_upstream_peers_count)) == 0
    for: 3m
    labels:
      severity: error
      summary: "Mempool has no active upstream peers (unable to forward transactions to anyone!)"
    annotations:
  - alert: Mempool is at >80% capacity (count)
    expr: aptos_core_mempool_index_size{index="system_ttl"} > 1600000 # assumes default mempool size 2_000_000
    for: 5m
    labels:
      severity: warning
      summary: "Mempool count is at >80% capacity (it may soon become full!)"
    annotations:
  - alert: Mempool is at >80% capacity (bytes)
    expr: aptos_core_mempool_index_size{index="size_bytes"} > 1717986918 # assumes default mempool size 2 * 1024 * 1024 * 1024
    for: 5m
    labels:
      severity: warning
      summary: "Mempool bytes is at >80% capacity (it may soon become full!)"
    annotations:
  - alert: Mempool is growing at a significant rate (count)
    expr: rate(aptos_core_mempool_index_size{index="system_ttl"}[1m]) > 60000 # 3% growth per minute - assumes default mempool size 2_000_000
    for: 10m
    labels:
      severity: warning
      summary: "Mempool count is growing at a significant rate (it may soon become full!)"
    annotations:
  - alert: Mempool is growing at a significant rate (bytes)
    expr: rate(aptos_core_mempool_index_size{index="size_bytes"}[1m]) > 64424509 # 3% growth per minute - assumes default mempool size 2 * 1024 * 1024 * 1024
    for: 10m
    labels:
      severity: warning
      summary: "Mempool bytes is growing at a significant rate (it may soon become full!)"
    annotations:
```

**File:** dashboards/mempool.json (L4360-4372)
```json
      "targets": [
        {
          "datasource": { "type": "prometheus", "uid": "${Datasource}" },
          "editorMode": "code",
          "expr": "rate(aptos_mempool_core_mempool_invariant_violated_count{chain_name=~\"$chain_name\", cluster=~\"$cluster\", metrics_source=~\"$metrics_source\", namespace=~\"$namespace\", kubernetes_pod_name=\"$kubernetes_pod_name\", role=\"$role\"}[$interval])",
          "legendFormat": "{{kubernetes_pod_name}}:{{role}}",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Core Mempool Invariant Violation",
      "type": "timeseries"
    },
```

**File:** mempool/src/shared_mempool/runtime.rs (L103-103)
```rust
    let mempool = Arc::new(Mutex::new(CoreMempool::new(config)));
```
