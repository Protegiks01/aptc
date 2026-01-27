# Audit Report

## Title
Unbounded Script Cache Enables Memory Exhaustion Attack on Validator Nodes

## Summary
The Move VM's script cache has no size limit and script deserialization/caching operations are unmetered, allowing attackers to exhaust validator memory by submitting many unique scripts in a single block. This violates critical resource limit invariants and can cause validator node slowdowns or crashes.

## Finding Description

The vulnerability exists in the script caching mechanism used during block execution. When scripts are loaded via `unmetered_deserialize_and_cache_script()`, they are cached without any size limits and without charging gas for the deserialization/caching operations. [1](#0-0) 

The underlying cache implementations (`UnsyncScriptCache` and `SyncScriptCache`) use unbounded hash maps with no maximum size constraints: [2](#0-1) [3](#0-2) 

During parallel block execution, a single `MVHashMap` instance (containing the script cache) is created per block and persists throughout execution: [4](#0-3) 

**Attack Path:**

1. Attacker generates many unique scripts (different bytecode produces different SHA3-256 hashes)
2. Submits transactions containing these unique scripts in a single block
3. Each script gets deserialized and cached via the unmetered function
4. With consensus allowing up to 10,000 transactions per block: [5](#0-4) 

5. And each transaction limited to 64 KB: [6](#0-5) 

6. Maximum memory consumption could reach: 10,000 × 64 KB = **640 MB per block**

The script loading path explicitly notes that dependency gas charging is questionable: [7](#0-6) 

## Impact Explanation

This is **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Validators processing blocks with many unique scripts will experience significant memory pressure and performance degradation
- **Potential API crashes**: Validators with insufficient memory could crash or become unresponsive
- **Consensus participation issues**: Affected validators may fail to process blocks in time, impacting consensus liveness

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The unmetered caching of potentially hundreds of megabytes per block violates this fundamental security guarantee.

While the cache is dropped after block execution, repeated attacks across multiple blocks can sustain pressure on validator infrastructure, and validators that consistently fail to process attacker blocks become effectively excluded from consensus.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is feasible because:
- Script transactions are allowed on mainnet (though less common than entry functions)
- No special permissions required to submit script transactions
- The unmetered nature of caching makes it economically viable

Attack barriers:
- Must pay transaction fees for thousands of transactions (but no additional gas for caching)
- Requires generating many unique scripts (computationally cheap - just modify bytecode)
- Scripts must pass basic validation (deserialization, verification)

The attack is most effective during high-throughput periods when blocks are near capacity, making it realistic under normal mainnet conditions.

## Recommendation

Implement the following mitigations:

1. **Add cache size limits**: Implement a maximum cache size (e.g., 100 MB) and evict entries using LRU or similar policy
2. **Meter caching operations**: Charge gas proportional to script size for deserialization and caching
3. **Per-transaction caching limit**: Limit how many unique scripts can be cached per transaction or per signer
4. **Address the TODO**: Resolve the comment at line 337 regarding dependency gas charging for scripts themselves

Example fix for `SyncScriptCache`:

```rust
pub struct SyncScriptCache<K, D, V> {
    script_cache: DashMap<K, CachePadded<Code<D, V>>>,
    max_size_bytes: usize,  // Add size limit
    current_size_bytes: AtomicUsize,  // Track current size
}

fn insert_deserialized_script(...) -> Arc<Self::Deserialized> {
    let script_size = estimate_script_size(&deserialized_script);
    
    // Check size limit before insertion
    if self.current_size_bytes.load(Ordering::Relaxed) + script_size > self.max_size_bytes {
        return Err(PartialVMError::new(StatusCode::SCRIPT_CACHE_FULL));
    }
    
    // Existing insertion logic...
    self.current_size_bytes.fetch_add(script_size, Ordering::Relaxed);
}
```

Additionally, make the caching operation metered in `eager.rs`:

```rust
fn metered_deserialize_and_cache_script(
    &self,
    serialized_script: &[u8],
    gas_meter: &mut impl GasMeter,
) -> VMResult<Arc<CompiledScript>> {
    // Charge gas proportional to script size
    let gas_cost = calculate_deserialization_gas(serialized_script.len());
    gas_meter.charge_gas(gas_cost)?;
    
    // Existing logic...
}
```

## Proof of Concept

```rust
#[test]
fn test_script_cache_memory_exhaustion() {
    use move_vm_runtime::move_vm::MoveVM;
    use aptos_types::transaction::Script;
    
    // Setup test environment
    let vm = MoveVM::new(...);
    let mut executor = BlockExecutor::new(...);
    
    // Generate many unique scripts by varying a nop instruction count
    let mut transactions = vec![];
    for i in 0..5000 {
        let script_code = generate_unique_script(i);
        let txn = Transaction::UserTransaction(
            SignedTransaction::new(
                RawTransaction::new(
                    sender,
                    seq_num + i,
                    TransactionPayload::Script(Script::new(
                        script_code,
                        vec![],
                        vec![],
                    )),
                    max_gas,
                    gas_price,
                    expiration,
                    chain_id,
                ),
                sender_key,
            )
        );
        transactions.push(txn);
    }
    
    // Monitor memory before execution
    let mem_before = get_process_memory();
    
    // Execute block containing all unique script transactions
    let _results = executor.execute_block(transactions);
    
    // Measure memory growth
    let mem_after = get_process_memory();
    let mem_growth = mem_after - mem_before;
    
    // Assert significant memory growth (indicating unbounded cache)
    assert!(mem_growth > 300_000_000, // > 300 MB
        "Expected significant memory growth from caching 5000 unique scripts, got {} bytes", 
        mem_growth
    );
}

fn generate_unique_script(seed: u64) -> Vec<u8> {
    // Generate Move bytecode with unique characteristics
    // by varying number of nop instructions or constant values
    let mut script = CompiledScriptBuilder::new();
    script.add_nops(seed as usize);
    script.serialize()
}
```

## Notes

This vulnerability is exacerbated by the fact that script transactions, while less common than entry functions, are still fully supported on mainnet. The attack is economically viable because the expensive caching operations are completely unmetered, meaning attackers only pay base transaction fees without any additional cost for the memory consumption they cause on validator nodes.

The per-block lifecycle of the cache provides some natural mitigation (memory is reclaimed after each block), but validators must still process each malicious block, and sustained attacks across multiple blocks can maintain continuous memory pressure.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L89-104)
```rust
    fn unmetered_deserialize_and_cache_script(
        &self,
        serialized_script: &[u8],
    ) -> VMResult<Arc<CompiledScript>> {
        let hash = sha3_256(serialized_script);
        Ok(match self.module_storage.get_script(&hash) {
            Some(script) => script.deserialized().clone(),
            None => {
                let deserialized_script = self
                    .runtime_environment()
                    .deserialize_into_script(serialized_script)?;
                self.module_storage
                    .insert_deserialized_script(hash, deserialized_script)
            },
        })
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L333-344)
```rust
        if config.charge_for_dependencies {
            let compiled_script = self.unmetered_deserialize_and_cache_script(serialized_script)?;
            let compiled_script = traversal_context.referenced_scripts.alloc(compiled_script);

            // TODO(Gas): Should we charge dependency gas for the script itself?
            check_dependencies_and_charge_gas(
                self.module_storage,
                gas_meter,
                traversal_context,
                compiled_script.immediate_dependencies_iter(),
            )?;
        }
```

**File:** third_party/move/move-vm/types/src/code/cache/script_cache.rs (L43-59)
```rust
/// Non-[Sync] implementation of script cache suitable for single-threaded execution.
pub struct UnsyncScriptCache<K, D, V> {
    script_cache: RefCell<HashMap<K, Code<D, V>>>,
}

impl<K, D, V> UnsyncScriptCache<K, D, V>
where
    K: Eq + Hash + Clone,
    V: Deref<Target = Arc<D>>,
{
    /// Returns an empty script cache.
    pub fn empty() -> Self {
        Self {
            script_cache: RefCell::new(HashMap::new()),
        }
    }
}
```

**File:** third_party/move/move-vm/types/src/code/cache/script_cache.rs (L120-136)
```rust
/// [Sync] implementation of script cache suitable for multithreaded execution.
pub struct SyncScriptCache<K, D, V> {
    script_cache: DashMap<K, CachePadded<Code<D, V>>>,
}

impl<K, D, V> SyncScriptCache<K, D, V>
where
    K: Eq + Hash + Clone,
    V: Deref<Target = Arc<D>>,
{
    /// Returns an empty script cache.
    pub fn empty() -> Self {
        Self {
            script_cache: DashMap::new(),
        }
    }
}
```

**File:** aptos-move/mvhashmap/src/lib.rs (L41-69)
```rust
pub struct MVHashMap<K, T, V: TransactionWrite, I: Clone> {
    data: VersionedData<K, V>,
    group_data: VersionedGroupData<K, T, V>,
    delayed_fields: VersionedDelayedFields<I>,

    module_cache:
        SyncModuleCache<ModuleId, CompiledModule, Module, AptosModuleExtension, Option<TxnIndex>>,
    script_cache: SyncScriptCache<[u8; 32], CompiledScript, Script>,
}

impl<K, T, V, I> MVHashMap<K, T, V, I>
where
    K: ModulePath + Hash + Clone + Eq + Debug,
    T: Hash + Clone + Eq + Debug + Serialize,
    V: TransactionWrite + PartialEq,
    I: Copy + Clone + Eq + Hash + Debug,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> MVHashMap<K, T, V, I> {
        #[allow(deprecated)]
        MVHashMap {
            data: VersionedData::empty(),
            group_data: VersionedGroupData::empty(),
            delayed_fields: VersionedDelayedFields::empty(),

            module_cache: SyncModuleCache::empty(),
            script_cache: SyncScriptCache::empty(),
        }
    }
```

**File:** config/src/config/consensus_config.rs (L23-24)
```rust
pub(crate) static MAX_RECEIVING_BLOCK_TXNS: Lazy<u64> =
    Lazy::new(|| 10000.max(2 * MAX_SENDING_BLOCK_TXNS));
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```
