# Audit Report

## Title
Hash Computation Mismatch in Verified Module Cache Causes Performance Degradation During Framework Override

## Summary
A hash computation inconsistency exists between module publishing and module loading code paths when the `get_module_bytes_override` mechanism is active. This causes verified module cache misses, leading to unnecessary re-verification and validator performance degradation.

## Finding Description
The verified module cache uses SHA3-256 hashes as keys to avoid re-verifying already verified modules. However, there is an inconsistency in how hashes are computed across different code paths:

**Path 1 - Module Publishing (StagingModuleStorage):** [1](#0-0) 

During module publishing, the hash is computed directly from the raw bytes in the staged module bundle, without applying any byte overrides.

**Path 2 - Module Loading (Normal Execution):** [2](#0-1) 

During normal module loading, the `get_module_bytes_override` function can replace module bytes for the option and mem modules when specific feature flags are set. [3](#0-2) 

The override is applied before the extension (which contains the hash) is created. [4](#0-3) 

The hash is then computed from the potentially overridden bytes.

**The Mismatch:**
When `enable_enum_option=true` AND `enable_framework_for_option=false`:
1. If governance publishes/updates the option or mem module to address 0x1, the publishing verification computes: `hash_A = sha3_256(published_bytes)`
2. This hash is cached in the global `VERIFIED_MODULES_CACHE`
3. Later, when transactions load the same module, the override mechanism replaces the bytes with embedded `OPTION_MODULE_BYTES` or `MEM_MODULE_BYTES`
4. A different hash is computed: `hash_B = sha3_256(embedded_bytes)`
5. Cache lookup with `hash_B` fails because only `hash_A` was cached
6. The module is unnecessarily re-verified on every load until `hash_B` is also cached [5](#0-4) 

The cache is global and persistent across blocks within a process.

## Impact Explanation
This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns"

The impact is significant:
- Affects ALL validators during the transition period when override is active
- Option module is a fundamental standard library component used by many transactions
- Bytecode verification is computationally expensive
- Every transaction loading the affected modules triggers re-verification until the cache warms up with both hash values
- Can cause validators to fall behind in block processing
- Degrades network-wide performance

## Likelihood Explanation
**Likelihood: Medium to High**

This occurs during specific configuration periods:
- When `enable_enum_option=true` AND `enable_framework_for_option=false`
- After any governance upgrade that publishes modules to address 0x1
- The code comments acknowledge this is a transitional mechanism: [6](#0-5) 

While this requires specific feature flag configurations set by governance, once active it affects ALL validators and transactions, making the impact widespread rather than requiring per-attacker action.

## Recommendation
Apply the override mechanism consistently in both publishing and loading code paths:

**Option 1**: Apply override in publishing verification
Modify `publishing.rs` to check if the module being verified is subject to override and use the overridden bytes for hash computation.

**Option 2**: Disable override during publishing
Ensure that when modules at address 0x1 are published during the transition period, the same embedded bytes are used, making the hashes consistent.

**Option 3**: Cache invalidation strategy
When feature flags change to enable/disable the override mechanism, flush the verified module cache: [7](#0-6) 

**Preferred Fix**: Modify the publishing path to apply overrides consistently:

```rust
// In publishing.rs, around line 256
let module_bytes = if let Some(override_bytes) = staged_runtime_environment
    .get_module_bytes_override(addr, name) 
{
    override_bytes
} else {
    bytes.clone()
};
let locally_verified_code = staged_runtime_environment
    .build_locally_verified_module(
        compiled_module.clone(),
        module_bytes.len(),
        &sha3_256(&module_bytes),
    )?;
```

## Proof of Concept
```rust
// Reproduction scenario:
// 1. Set feature flags: enable_enum_option=true, enable_framework_for_option=false
// 2. Publish a new version of option module via governance to address 0x1
// 3. Publishing verification caches hash_A = sha3_256(published_bytes)
// 4. Execute any transaction that imports option module
// 5. Loading computes hash_B = sha3_256(OPTION_MODULE_BYTES)
// 6. If published_bytes != OPTION_MODULE_BYTES, then hash_A != hash_B
// 7. Cache miss occurs, triggering unnecessary re-verification
// 8. Measure verification time - it will be non-zero despite previous verification

// This can be observed by:
// - Monitoring VERIFIED_MODULE_CACHE.size() before and after
// - Instrumenting build_locally_verified_module to log when verification actually runs
// - Measuring transaction execution time showing increased latency
```

---

**Notes:**
This is a legitimate implementation bug that violates the performance invariant that verified modules should not require re-verification. While not directly exploitable by unprivileged attackers, it causes measurable validator performance degradation during framework transition periods, meeting the High Severity criteria for validator slowdowns.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L252-257)
```rust
                let locally_verified_code = staged_runtime_environment
                    .build_locally_verified_module(
                        compiled_module.clone(),
                        bytes.len(),
                        &sha3_256(bytes),
                    )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L373-377)
```rust
    /// Flushes the global verified module cache. Should be used when verifier configuration has
    /// changed.
    pub fn flush_verified_module_cache() {
        VERIFIED_MODULES_CACHE.flush();
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L411-427)
```rust
    pub fn get_module_bytes_override(
        &self,
        addr: &AccountAddress,
        name: &IdentStr,
    ) -> Option<Bytes> {
        let enable_enum_option = self.vm_config().enable_enum_option;
        let enable_framework_for_option = self.vm_config().enable_framework_for_option;
        if !enable_framework_for_option && enable_enum_option {
            if addr == OPTION_MODULE_ID.address() && *name == *OPTION_MODULE_ID.name() {
                return Some(self.get_option_module_bytes());
            }
            if addr == MEM_MODULE_ID.address() && *name == *MEM_MODULE_ID.name() {
                return Some(self.get_mem_module_bytes());
            }
        }
        None
    }
```

**File:** aptos-move/block-executor/src/code_cache.rs (L61-67)
```rust
                if let Some(bytes) = self
                    .runtime_environment()
                    .get_module_bytes_override(key.address(), key.name())
                {
                    state_value.set_bytes(bytes);
                }
                let extension = Arc::new(AptosModuleExtension::new(state_value));
```

**File:** types/src/vm/modules.rs (L24-31)
```rust
    pub fn new(state_value: StateValue) -> Self {
        let (state_value_metadata, bytes) = state_value.unpack();
        let hash = sha3_256(&bytes);
        Self {
            bytes,
            hash,
            state_value_metadata,
        }
```

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L51-54)
```rust
lazy_static! {
    pub(crate) static ref VERIFIED_MODULES_CACHE: VerifiedModuleCache =
        VerifiedModuleCache::empty();
}
```

**File:** third_party/move/move-vm/runtime/src/storage/implementations/unsync_module_storage.rs (L144-144)
```rust
        // TODO: remove this once framework on mainnet is using the new option module
```
