# Audit Report

## Title
Unbounded Prometheus Label Cardinality via User-Controlled Move Abort Error Names Causing Validator Memory Exhaustion

## Summary
The `PROCESSED_FAILED_TXNS_REASON_COUNT` Prometheus metric uses user-controlled Move module error names (`reason_name`) directly as a label value when the `detailed_counters` flag is enabled. An attacker can publish multiple Move modules with unique error codes, trigger transactions that abort with these codes, and create unbounded label cardinality, leading to validator memory exhaustion and potential out-of-memory (OOM) conditions. [1](#0-0) 

## Finding Description
The vulnerability exists in the transaction metrics collection system when `detailed_counters` is enabled. When a transaction fails with a `MoveAbort` execution status, the system extracts the `reason_name` field from the module's error map metadata and uses it directly as a Prometheus label value without validation or sanitization. [2](#0-1) 

The `reason_name` originates from Move module metadata that module publishers can control. When a module is deployed, it includes an `error_map` containing error descriptions with arbitrary `code_name` strings that become the `reason_name`: [3](#0-2) [4](#0-3) 

The error_code label is populated during transaction processing: [5](#0-4) 

**Attack Path:**
1. Attacker publishes multiple Move modules, each containing unique error codes with distinct `reason_name` values in their error maps
2. Attacker triggers transactions that call these modules and cause them to abort with different error codes
3. Each unique `reason_name` creates a new Prometheus time series: `aptos_processed_failed_txns_reason_count{is_detailed="true", process="execution", state="keep_rejected", reason="MoveAbort", error_code="<unique_reason_name>"}`
4. With N unique error names across modules, an attacker creates 2×N new time series (2 for process types × N error codes)
5. Prometheus stores metadata and samples for each time series, consuming memory linearly with cardinality
6. With sufficient unique error codes (tens of thousands), validator memory is exhausted

The vulnerability is only active when validators set `processed_transactions_detailed_counters = true`: [6](#0-5) 

Critically, there is no validation limiting the number or uniqueness of error codes in module metadata. The module complexity check does not examine error maps: [7](#0-6) [8](#0-7) 

The Aptos codebase demonstrates awareness of cardinality risks in other components with explicit protections: [9](#0-8) 

However, this protection is absent for executor metrics.

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns" (up to $50,000).

**Specific Impact:**
- **Validator Availability**: Validators with `detailed_counters` enabled experience progressive memory exhaustion as unique error codes accumulate, leading to OOM crashes or severe performance degradation
- **Network Liveness**: If multiple validators enable this feature and crash simultaneously, network liveness could be impacted
- **Resource Limits Invariant Violation**: Breaks the documented invariant "Resource Limits: All operations must respect gas, storage, and computational limits" - Prometheus memory consumption is unbounded

**Quantification:**
- Prometheus memory per time series: ~3KB baseline + samples
- 10,000 unique error codes ≈ 20,000 new time series ≈ 60MB+ memory
- 100,000 unique error codes ≈ 200,000 new time series ≈ 600MB+ memory
- Combined with normal metrics load, this can trigger OOM on validators with limited memory

## Likelihood Explanation
**Likelihood: Medium to High (when detailed_counters is enabled)**

**Factors Increasing Likelihood:**
- Module publishing is permissionless - any user can publish modules with arbitrary error maps
- No validation limits error_map size or uniqueness of error codes
- Each module can contain hundreds of error codes within transaction size limits
- Attacker can publish modules incrementally over time to avoid detection
- Transaction size limits constrain individual module size but not total across modules

**Factors Decreasing Likelihood:**
- `detailed_counters` must be explicitly enabled via node configuration (may not be default)
- Economic cost: Publishing modules and triggering transactions requires gas fees
- Attack requires sustained effort to create and trigger thousands of unique aborts

**Attacker Requirements:**
- Sufficient APT tokens for gas (moderate economic barrier)
- Basic Move module development capability
- Access to transaction submission (no special privileges required)

The vulnerability is **immediately exploitable** when the configuration flag is enabled, with no other prerequisites or complexity.

## Recommendation
Implement label value sanitization with cardinality limits for the error_code dimension:

1. **Immediate Fix**: Add a bounded set of allowed error_code values, replacing unknown values with a constant like "other":

```rust
// In metrics.rs, after line 270
const MAX_TRACKED_ERROR_CODES: usize = 1000;
static TRACKED_ERROR_CODES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| {
    Mutex::new(HashSet::new())
});

fn sanitize_error_code(error_code: String) -> String {
    let mut tracked = TRACKED_ERROR_CODES.lock().unwrap();
    if tracked.contains(&error_code) {
        error_code
    } else if tracked.len() < MAX_TRACKED_ERROR_CODES {
        tracked.insert(error_code.clone());
        error_code
    } else {
        "other".to_string()
    }
}

// Then use sanitize_error_code() when setting error_code label
```

2. **Long-term Fix**: Validate error_map size during module publishing:

```rust
// In module_metadata.rs, add to verify_module_metadata_for_module_publishing
const MAX_ERROR_MAP_SIZE: usize = 100;
if metadata.error_map.len() > MAX_ERROR_MAP_SIZE {
    return Err(MetaDataValidationError::Malformed(
        MalformedError::ModuleTooComplex
    ));
}
```

3. **Additional Protection**: Add Prometheus metric to track label cardinality and alert when approaching limits.

## Proof of Concept

**Step 1: Create a Move module with multiple unique error codes**

```move
module attacker::cardinality_bomb {
    // Define 1000 unique error codes
    const E_ERROR_0: u64 = 0;
    const E_ERROR_1: u64 = 1;
    // ... continue up to E_ERROR_999
    const E_ERROR_999: u64 = 999;
    
    public entry fun trigger_abort_0() {
        abort E_ERROR_0
    }
    
    public entry fun trigger_abort_1() {
        abort E_ERROR_1
    }
    
    // ... continue for all error codes
    
    public entry fun trigger_abort_999() {
        abort E_ERROR_999
    }
}
```

**Step 2: Publish 100 such modules with different error codes (total 100,000 unique errors)**

**Step 3: Submit transactions calling each abort function**

```rust
// Rust reproduction code
use aptos_sdk::transaction_builder::TransactionFactory;

for module_idx in 0..100 {
    for error_idx in 0..1000 {
        let payload = aptos_stdlib::encode_entry_function(
            format!("0xattacker::cardinality_bomb_{}::trigger_abort_{}", 
                    module_idx, error_idx)
        );
        // Submit transaction, it will abort and create new metric label
        client.submit_transaction(txn).await;
    }
}
```

**Step 4: Monitor validator memory**

```bash
# Query Prometheus metrics
curl http://validator:9101/metrics | grep aptos_processed_failed_txns_reason_count | wc -l
# Should show 100,000+ unique time series

# Monitor memory
ps aux | grep aptos-node
# Observe memory growth over time
```

**Expected Result**: Validator memory grows by hundreds of MB, eventually triggering OOM or severe performance degradation when combined with normal operational metrics load.

**Notes**
- This vulnerability only affects validators that explicitly enable `processed_transactions_detailed_counters` in their node configuration
- The economic cost of the attack scales with the number of modules and transactions, but remains feasible for a well-funded attacker
- The issue demonstrates a systemic lack of cardinality protection in executor metrics, contrasting with explicit protections implemented in other components like the keyless pepper service
- While the attack requires economic resources, the threshold for causing impact is significantly lower than a traditional 51% attack or stake-based attack vector

### Citations

**File:** execution/executor/src/metrics.rs (L175-182)
```rust
pub static PROCESSED_FAILED_TXNS_REASON_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_processed_failed_txns_reason_count",
        "Count of the transactions since last restart. state is success, failed or retry",
        &["is_detailed", "process", "state", "reason", "error_code"]
    )
    .unwrap()
});
```

**File:** execution/executor/src/metrics.rs (L291-301)
```rust
                ExecutionStatus::MoveAbort { info, .. } => (
                    "keep_rejected",
                    "MoveAbort",
                    if detailed_counters {
                        info.as_ref()
                            .map(|v| v.reason_name.to_lowercase())
                            .unwrap_or_else(|| "none".to_string())
                    } else {
                        "error".to_string()
                    },
                ),
```

**File:** execution/executor/src/metrics.rs (L364-374)
```rust
        if !error_code.is_empty() {
            PROCESSED_FAILED_TXNS_REASON_COUNT
                .with_label_values(&[
                    detailed_counters_label,
                    process_type,
                    state,
                    reason,
                    &error_code,
                ])
                .inc();
        }
```

**File:** types/src/vm/module_metadata.rs (L67-77)
```rust
pub struct RuntimeModuleMetadataV1 {
    /// The error map containing the description of error reasons as grabbed from the source.
    /// These are typically only a few entries so no relevant size difference.
    pub error_map: BTreeMap<u64, ErrorDescription>,

    /// Attributes attached to structs.
    pub struct_attributes: BTreeMap<String, Vec<KnownAttribute>>,

    /// Attributes attached to functions, by definition index.
    pub fun_attributes: BTreeMap<String, Vec<KnownAttribute>>,
}
```

**File:** types/src/vm/module_metadata.rs (L441-456)
```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    if features.is_enabled(FeatureFlag::SAFER_METADATA) {
        check_module_complexity(module)?;
    }

    if features.are_resource_groups_enabled() {
        check_metadata_format(module)?;
    }
    let metadata = if let Some(metadata) = get_metadata_from_compiled_code(module) {
        metadata
    } else {
        return Ok(());
    };
```

**File:** types/src/vm/module_metadata.rs (L548-556)
```rust
    pub fn extract_abort_info(&self, code: u64) -> Option<AbortInfo> {
        self.error_map
            .get(&(code & 0xFFF))
            .or_else(|| self.error_map.get(&code))
            .map(|descr| AbortInfo {
                reason_name: descr.code_name.clone(),
                description: descr.code_description.clone(),
            })
    }
```

**File:** types/src/vm/module_metadata.rs (L559-607)
```rust
/// Checks the complexity of a module.
fn check_module_complexity(module: &CompiledModule) -> Result<(), MetaDataValidationError> {
    let mut meter: usize = 0;
    for sig in module.signatures() {
        for tok in &sig.0 {
            check_sigtok_complexity(module, &mut meter, tok)?
        }
    }
    for handle in module.function_handles() {
        check_ident_complexity(module, &mut meter, handle.name)?;
        for tok in &safe_get_table(module.signatures(), handle.parameters.0)?.0 {
            check_sigtok_complexity(module, &mut meter, tok)?
        }
        for tok in &safe_get_table(module.signatures(), handle.return_.0)?.0 {
            check_sigtok_complexity(module, &mut meter, tok)?
        }
    }
    for handle in module.struct_handles() {
        check_ident_complexity(module, &mut meter, handle.name)?;
    }
    for def in module.struct_defs() {
        match &def.field_information {
            StructFieldInformation::Native => {},
            StructFieldInformation::Declared(fields) => {
                for field in fields {
                    check_ident_complexity(module, &mut meter, field.name)?;
                    check_sigtok_complexity(module, &mut meter, &field.signature.0)?
                }
            },
            StructFieldInformation::DeclaredVariants(variants) => {
                for variant in variants {
                    check_ident_complexity(module, &mut meter, variant.name)?;
                    for field in &variant.fields {
                        check_ident_complexity(module, &mut meter, field.name)?;
                        check_sigtok_complexity(module, &mut meter, &field.signature.0)?
                    }
                }
            },
        }
    }
    for def in module.function_defs() {
        if let Some(unit) = &def.code {
            for tok in &safe_get_table(module.signatures(), unit.locals.0)?.0 {
                check_sigtok_complexity(module, &mut meter, tok)?
            }
        }
    }
    Ok(())
}
```

**File:** aptos-node/src/utils.rs (L69-74)
```rust
    if node_config
        .execution
        .processed_transactions_detailed_counters
    {
        AptosVM::set_processed_transactions_detailed_counters();
    }
```

**File:** keyless/pepper/service/src/metrics.rs (L155-161)
```rust
    // Determine the request endpoint to use in the metrics (i.e., replace
    // invalid paths with a fixed label to avoid high cardinality).
    let request_endpoint = if is_known_path(request_endpoint) {
        request_endpoint
    } else {
        INVALID_PATH
    };
```
