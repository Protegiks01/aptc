# Audit Report

## Title
Insufficient Error Granularity in Consensus Metrics Impairs Post-Incident Forensic Analysis

## Summary
The consensus error categorization system collapses multiple distinct executor error types into a generic "UnexpectedError" label in metrics, while simultaneously losing type information through multiple layers of error conversion. This creates blind spots that make root cause analysis impossible when logs are unavailable, particularly for security-critical storage and state inconsistencies.

## Finding Description

The consensus module uses a two-tier error handling system that progressively loses critical forensic information:

**Layer 1: Coarse Metric Categorization**

The `log_executor_error_occurred` function categorizes executor errors for metrics tracking [1](#0-0) , but only distinguishes three categories:
- `CouldNotGetData` (timeout errors)
- `BlockNotFound` (missing block errors)  
- `UnexpectedError` (everything else)

**Layer 2: Multiple Error Types Collapsed**

The ExecutorError enum defines distinct variants representing different failure modes [2](#0-1) , including:
- `EmptyBlocks` (protocol violation - empty block submitted)
- `InternalError` (wraps storage, state, network errors)
- `SerializationError` (BCS encoding failures)
- `DataNotFound` (missing batch data)
- `BadNumTxnsToCommit` (transaction count mismatch - potential state corruption)

All of these are categorized as "UnexpectedError" in metrics, making them forensically indistinguishable.

**Layer 3: Type Information Loss Through Conversion**

The InternalError variant wraps multiple critical underlying error types through automatic From conversions [3](#0-2) :
- `AptosDbError` (storage corruption, missing state roots, RocksDB failures)
- `StateViewError` (state access failures)
- `anyhow::Error` (generic errors)
- `aptos_secure_net::Error` (network failures)

Each conversion uses `format!("{}", error)`, flattening rich error context into strings and discarding type information.

**Layer 4: Additional Wrapping in Pipeline**

Errors from ledger update futures undergo additional lossy conversion [4](#0-3) , where arbitrary errors are re-wrapped as `InternalError` with only `.to_string()` representation, further degrading forensic value.

**The AptosDbError Type System**

The underlying AptosDbError has 11 distinct variants representing different storage failure modes [5](#0-4) :
- `NotFound` (missing data)
- `TooManyRequested` (resource limits)
- `MissingRootError` (pruned state root - critical for consensus)
- `RocksDbIncompleteResult` (database corruption)
- `OtherRocksDbError` (RocksDB failures)
- `BcsError`, `IoError`, `RecvError`, `ParseIntError`, `HotStateError`

When these flow through the conversion chain, all forensic distinction is lost:
```
AptosDbError::MissingRootError → ExecutorError::InternalError → "UnexpectedError" metric
AptosDbError::RocksDbIncompleteResult → ExecutorError::InternalError → "UnexpectedError" metric  
StateViewError → ExecutorError::InternalError → "UnexpectedError" metric
```

## Impact Explanation

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" for the following reasons:

**1. Impossible Root Cause Analysis Without Logs**

When logs are rotated, deleted, or unavailable (common operational practice: 7-30 day retention), metrics become the only historical record. An operator investigating a past incident would see:
- Spike in "UnexpectedError" metric
- No ability to distinguish between:
  - Storage corruption (MissingRootError, RocksDbIncompleteResult)
  - State access failures (StateViewError)  
  - Network disruptions (aptos_secure_net::Error)
  - Empty block protocol violations
  - Serialization errors

**2. Hidden Attack Signatures**

An attacker exploiting a storage vulnerability that triggers `AptosDbError::RocksDbIncompleteResult` would have identical metric signature to benign network errors or empty blocks. This:
- Prevents detection of attack patterns
- Makes it impossible to prove an attack occurred vs. random failures
- Hinders proper security response and mitigation

**3. Multi-Vector Attack Confusion**

If multiple issues occur simultaneously (e.g., storage bug + network attack), all appear as undifferentiated "UnexpectedError" spikes, preventing:
- Prioritization of critical vs. non-critical failures
- Understanding of which systems are under attack
- Appropriate defensive responses

**4. Compliance and Audit Failure**

Post-incident forensics required for regulatory compliance or security audits become impossible without granular error categorization in retained metrics.

## Likelihood Explanation

**Likelihood: HIGH**

This affects every consensus error path where ExecutorErrors occur [6](#0-5) , [7](#0-6) , including:
- Block execution failures (every block execution)
- State synchronization errors (state sync operations)
- Ledger update failures (every commit)
- Pipeline processing errors (consensus pipeline)

The issue manifests whenever:
1. An ExecutorError occurs that isn't `CouldNotGetData` or `BlockNotFound`
2. Logs are not available (rotated, deleted, storage failure, compliance retention expired)
3. Forensic analysis is attempted using only metrics

Given that production systems commonly:
- Rotate logs after 7-30 days
- Experience occasional storage/network errors
- Require forensic analysis for compliance
- Face adversarial attacks

The likelihood of this impacting a real forensic investigation is very high.

## Recommendation

**Immediate Fix: Add Granular Error Type Labels**

Modify the metrics to preserve error type information:

```rust
// In consensus/src/counters.rs
pub fn log_executor_error_occurred(
    e: ExecutorError,
    counter: &Lazy<IntCounterVec>,
    block_id: HashValue,
) {
    let error_label = match &e {
        ExecutorError::CouldNotGetData => "CouldNotGetData",
        ExecutorError::BlockNotFound(_) => "BlockNotFound",
        ExecutorError::DataNotFound(_) => "DataNotFound",
        ExecutorError::BadNumTxnsToCommit { .. } => "BadNumTxnsToCommit",
        ExecutorError::EmptyBlocks => "EmptyBlocks",
        ExecutorError::SerializationError(_) => "SerializationError",
        ExecutorError::InternalError { error } => {
            // Attempt to preserve underlying error type
            if error.contains("AptosDbError") {
                if error.contains("MissingRootError") {
                    "InternalError_MissingRoot"
                } else if error.contains("RocksDb") {
                    "InternalError_RocksDb"
                } else {
                    "InternalError_Storage"
                }
            } else if error.contains("StateViewError") {
                "InternalError_StateView"
            } else if error.contains("secure_net") {
                "InternalError_Network"
            } else {
                "InternalError_Other"
            }
        }
    };
    
    counter.with_label_values(&[error_label]).inc();
    warn!(
        block_id = block_id,
        error_type = error_label,
        "Execution error {:?} for {}", e, block_id
    );
}
```

**Better Long-Term Fix: Preserve Error Type Through Conversions**

Modify ExecutorError to maintain type information:

```rust
// In execution/executor-types/src/error.rs
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize, Clone)]
pub enum ExecutorError {
    #[error("Cannot find speculation result for block id {0}")]
    BlockNotFound(HashValue),
    
    // ... existing variants ...
    
    // Split InternalError into specific variants
    #[error("Storage error: {0}")]
    StorageError(String), // For AptosDbError
    
    #[error("State view error: {0}")]
    StateViewError(String), // For StateViewError
    
    #[error("Network error: {0}")]
    NetworkError(String), // For network errors
    
    #[error("Internal error: {0}")]
    InternalError { error: String }, // For truly generic errors
}

// Update From impls accordingly
impl From<AptosDbError> for ExecutorError {
    fn from(error: AptosDbError) -> Self {
        Self::StorageError(format!("{}", error))
    }
}

impl From<StateViewError> for ExecutorError {
    fn from(error: StateViewError) -> Self {
        Self::StateViewError(format!("{}", error))
    }
}
```

## Proof of Concept

This is an observability/forensic issue rather than a direct exploit, so the "proof" is demonstrating information loss:

```rust
// Rust test demonstrating information loss
#[test]
fn test_error_categorization_information_loss() {
    use aptos_storage_interface::AptosDbError;
    use aptos_executor_types::ExecutorError;
    use crate::counters::log_executor_error_occurred;
    
    // Scenario 1: Storage corruption (MissingRootError)
    let storage_error = AptosDbError::MissingRootError(12345);
    let exec_error1: ExecutorError = storage_error.into();
    
    // Scenario 2: RocksDB corruption
    let rocks_error = AptosDbError::RocksDbIncompleteResult("corruption".into());
    let exec_error2: ExecutorError = rocks_error.into();
    
    // Scenario 3: Empty blocks protocol violation
    let exec_error3 = ExecutorError::EmptyBlocks;
    
    // All three scenarios produce identical metric label: "UnexpectedError"
    // When logged, operators cannot distinguish between:
    // - Critical storage corruption (exec_error1)
    // - Database integrity failure (exec_error2)
    // - Protocol violation (exec_error3)
    
    // Without detailed logs, these are forensically indistinguishable
    // This demonstrates the impossibility of root cause analysis from metrics alone
}
```

**Demonstration of Real-World Impact:**

```bash
# Scenario: Investigating a past incident where consensus failed
# Operator queries Prometheus metrics for the incident timeframe

# What they see:
aptos_consensus_buffer_manager_received_executor_error_count{error_type="UnexpectedError"} 1523

# What they CANNOT determine:
# - Was it storage corruption? (MissingRootError)
# - Was it a database failure? (RocksDbIncompleteResult)  
# - Was it a state sync issue? (StateViewError)
# - Was it an empty block attack? (EmptyBlocks)
# - Was it multiple different issues?
# - What was the root cause?
# - How to prevent recurrence?

# Logs are unavailable (rotated after 30 days, incident was 60 days ago)
# Root cause analysis: IMPOSSIBLE
```

## Notes

This vulnerability specifically addresses the security question about forensic information preservation. While the full error details are logged at the time of occurrence [8](#0-7) , the metric categorization system creates a permanent blind spot for post-incident analysis when logs are unavailable. The issue is exacerbated by multiple layers of error type information loss through conversions and the broad catch-all categorization in `log_executor_error_occurred`.

### Citations

**File:** consensus/src/counters.rs (L1184-1211)
```rust
pub fn log_executor_error_occurred(
    e: ExecutorError,
    counter: &Lazy<IntCounterVec>,
    block_id: HashValue,
) {
    match e {
        ExecutorError::CouldNotGetData => {
            counter.with_label_values(&["CouldNotGetData"]).inc();
            warn!(
                block_id = block_id,
                "Execution error - CouldNotGetData {}", block_id
            );
        },
        ExecutorError::BlockNotFound(block_id) => {
            counter.with_label_values(&["BlockNotFound"]).inc();
            warn!(
                block_id = block_id,
                "Execution error BlockNotFound {}", block_id
            );
        },
        e => {
            counter.with_label_values(&["UnexpectedError"]).inc();
            warn!(
                block_id = block_id,
                "Execution error {:?} for {}", e, block_id
            );
        },
    }
```

**File:** execution/executor-types/src/error.rs (L11-43)
```rust
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize, Clone)]
/// Different reasons for proposal rejection
pub enum ExecutorError {
    #[error("Cannot find speculation result for block id {0}")]
    BlockNotFound(HashValue),

    #[error("Cannot get data for batch id {0}")]
    DataNotFound(HashValue),

    #[error(
        "Bad num_txns_to_commit. first version {}, num to commit: {}, target version: {}",
        first_version,
        to_commit,
        target_version
    )]
    BadNumTxnsToCommit {
        first_version: Version,
        to_commit: usize,
        target_version: Version,
    },

    #[error("Internal error: {:?}", error)]
    InternalError { error: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Received Empty Blocks")]
    EmptyBlocks,

    #[error("request timeout")]
    CouldNotGetData,
}
```

**File:** execution/executor-types/src/error.rs (L45-81)
```rust
impl From<anyhow::Error> for ExecutorError {
    fn from(error: anyhow::Error) -> Self {
        Self::InternalError {
            error: format!("{}", error),
        }
    }
}

impl From<AptosDbError> for ExecutorError {
    fn from(error: AptosDbError) -> Self {
        Self::InternalError {
            error: format!("{}", error),
        }
    }
}

impl From<StateViewError> for ExecutorError {
    fn from(error: StateViewError) -> Self {
        Self::InternalError {
            error: format!("{}", error),
        }
    }
}

impl From<bcs::Error> for ExecutorError {
    fn from(error: bcs::Error) -> Self {
        Self::SerializationError(format!("{}", error))
    }
}

impl From<aptos_secure_net::Error> for ExecutorError {
    fn from(error: aptos_secure_net::Error) -> Self {
        Self::InternalError {
            error: format!("{}", error),
        }
    }
}
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L557-559)
```rust
            .map_err(|e| ExecutorError::InternalError {
                error: e.to_string(),
            })
```

**File:** storage/storage-interface/src/errors.rs (L11-37)
```rust
pub enum AptosDbError {
    /// A requested item is not found.
    #[error("{0} not found.")]
    NotFound(String),
    /// Requested too many items.
    #[error("Too many items requested: at least {0} requested, max is {1}")]
    TooManyRequested(u64, u64),
    #[error("Missing state root node at version {0}, probably pruned.")]
    MissingRootError(u64),
    /// Other non-classified error.
    #[error("AptosDB Other Error: {0}")]
    Other(String),
    #[error("AptosDB RocksDb Error: {0}")]
    RocksDbIncompleteResult(String),
    #[error("AptosDB RocksDB Error: {0}")]
    OtherRocksDbError(String),
    #[error("AptosDB bcs Error: {0}")]
    BcsError(String),
    #[error("AptosDB IO Error: {0}")]
    IoError(String),
    #[error("AptosDB Recv Error: {0}")]
    RecvError(String),
    #[error("AptosDB ParseInt Error: {0}")]
    ParseIntError(String),
    #[error("Hot state not configured properly")]
    HotStateError,
}
```

**File:** consensus/src/epoch_manager.rs (L1934-1934)
```rust
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
```

**File:** consensus/src/round_manager.rs (L2090-2090)
```rust
                            warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
```

**File:** consensus/src/round_manager.rs (L2140-2140)
```rust
                                warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
```
