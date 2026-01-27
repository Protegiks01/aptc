# Audit Report

## Title
Integer Overflow Panic in Backup Service Transaction Range Proof Endpoint Causes Node Crash

## Summary
The backup service's `get_transaction_range_proof` endpoint performs unchecked arithmetic on attacker-controlled version numbers, leading to an integer overflow panic that crashes the node. An unauthenticated attacker can exploit this via a single HTTP request.

## Finding Description

The backup service exposes an HTTP endpoint that accepts transaction version ranges without proper validation. When computing the number of transactions in a range, the code performs unchecked addition that can overflow. [1](#0-0) 

The endpoint is directly exposed via HTTP without size limit validation: [2](#0-1) 

**Exploitation Path:**
1. Attacker sends HTTP request: `GET /transaction_range_proof/0/18446744073709551615` (where 18446744073709551615 = u64::MAX)
2. The handler extracts `first_version=0` and `last_version=u64::MAX` from URL parameters
3. Code executes: `let num_transactions = last_version - first_version + 1;`
4. Computation becomes: `u64::MAX - 0 + 1 = u64::MAX + 1`
5. With overflow checks enabled in release builds, this addition **panics**
6. The panic crashes the entire node process

The Cargo.toml configuration confirms overflow checks are enabled in production: [3](#0-2) 

The only validation present is a check that `last_version >= first_version`, which doesn't prevent the overflow when adding 1: [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns" and "API crashes". 

**Specific Impacts:**
- **Node Availability**: Complete node crash requiring manual restart
- **Validator Impact**: If validators run the backup service (common for disaster recovery), they become unavailable, potentially affecting consensus liveness
- **Service Disruption**: Backup operations fail, preventing disaster recovery capabilities
- **Attack Scale**: Single HTTP request can crash any exposed node

The vulnerability breaks the invariant: "Resource Limits: All operations must respect gas, storage, and computational limits" - the unchecked arithmetic allows a resource exhaustion attack.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack Complexity**: Trivial - single HTTP GET request
- **Authentication Required**: None - endpoint is unauthenticated
- **Attacker Requirements**: Network access to backup service port
- **Exploit Reliability**: 100% - deterministic panic with overflow-checks enabled
- **Discovery**: Easy to find through fuzzing or parameter boundary testing

The backup service is commonly exposed for disaster recovery purposes, making it accessible to potential attackers. The vulnerability is trivially exploitable with no special tools or knowledge required.

## Recommendation

Replace unchecked arithmetic with checked operations that return errors instead of panicking:

```rust
pub fn get_transaction_range_proof(
    &self,
    first_version: Version,
    last_version: Version,
) -> Result<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)> {
    ensure!(
        last_version >= first_version,
        "Bad transaction range: [{}, {}]",
        first_version,
        last_version
    );
    
    // Use checked arithmetic to prevent overflow panic
    let num_transactions = last_version
        .checked_sub(first_version)
        .and_then(|diff| diff.checked_add(1))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Transaction range too large: [{}, {}]",
                first_version,
                last_version
            )
        })?;
    
    // Rest of function...
}
```

Additionally, implement a maximum range size limit in the backup service endpoint to prevent excessively large requests.

Compare with the correct implementation already present in the codebase: [5](#0-4) 

## Proof of Concept

**HTTP Request:**
```bash
curl "http://<node-ip>:<backup-port>/transaction_range_proof/0/18446744073709551615"
```

**Expected Result:** Node panics with overflow error and crashes

**Rust Test Case:**
```rust
#[test]
#[should_panic(expected = "overflow")]
fn test_transaction_range_overflow() {
    let first_version: u64 = 0;
    let last_version: u64 = u64::MAX;
    
    // This will panic with overflow-checks enabled
    let _num_transactions = last_version - first_version + 1;
}
```

**Additional Vulnerable Locations:**

Similar unchecked arithmetic patterns exist throughout the codebase: [6](#0-5) [7](#0-6) [8](#0-7) 

All instances performing `end - start + 1` or similar patterns should be audited and fixed with checked arithmetic.

## Notes

This vulnerability demonstrates a systemic issue in the codebase where version range calculations assume valid inputs without defensive programming. While the `inclusive_range_len` function in storage-service shows the correct pattern, it hasn't been consistently applied across all version arithmetic operations. A comprehensive audit of all version subtraction operations is recommended.

### Citations

**File:** storage/aptosdb/src/backup/backup_handler.rs (L113-124)
```rust
    pub fn get_transaction_range_proof(
        &self,
        first_version: Version,
        last_version: Version,
    ) -> Result<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)> {
        ensure!(
            last_version >= first_version,
            "Bad transaction range: [{}, {}]",
            first_version,
            last_version
        );
        let num_transactions = last_version - first_version + 1;
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L112-122)
```rust
    // GET transaction_range_proof/<first_version>/<last_version>
    let bh = backup_handler;
    let transaction_range_proof = warp::path!(Version / Version)
        .map(move |first_version, last_version| {
            reply_with_bcs_bytes(
                TRANSACTION_RANGE_PROOF,
                &bh.get_transaction_range_proof(first_version, last_version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** state-sync/storage-service/server/src/storage.rs (L1485-1494)
```rust
fn inclusive_range_len(start: u64, end: u64) -> aptos_storage_service_types::Result<u64, Error> {
    // len = end - start + 1
    let len = end.checked_sub(start).ok_or_else(|| {
        Error::InvalidRequest(format!("end ({}) must be >= start ({})", end, start))
    })?;
    let len = len
        .checked_add(1)
        .ok_or_else(|| Error::InvalidRequest(format!("end ({}) must not be u64::MAX", end)))?;
    Ok(len)
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L252-252)
```rust
            let size = last_version - first_version + 1;
```

**File:** api/src/context.rs (L709-709)
```rust
            (last_version - first_version + 1) as u16,
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L202-202)
```rust
        for events in self.get_events_by_version_iter(start, (end - start) as usize)? {
```
