# Audit Report

## Title
Silent Transaction Deduper Type Divergence Leading to Consensus Failure

## Summary
The `create_transaction_deduper()` function and the epoch initialization logic fail to validate that all validators successfully deserialize the same `OnChainExecutionConfig` and use identical deduper implementations. If deserialization fails on some validators due to software version mismatches or bugs, they silently fall back to a default configuration, causing different validators to use different deduper types (`NoDedup` vs `TxnHashAndAuthenticatorV1`). This leads to validators including different transaction sets in blocks, resulting in state divergence and consensus failure.

## Finding Description
During epoch initialization in the consensus layer, validators retrieve the `OnChainExecutionConfig` from the on-chain state to determine which transaction deduper implementation to use. The configuration retrieval and deduper creation process has a critical flaw: [1](#0-0) 

When deserialization fails (returning `Err`), the code logs a warning but continues: [2](#0-1) 

Then silently falls back to a default value: [3](#0-2) 

The `default_if_missing()` returns `OnChainExecutionConfig::Missing`, which maps to `TransactionDeduperType::TxnHashAndAuthenticatorV1`: [4](#0-3) 

The `TransactionDeduperType` enum uses serde with `rename_all = "snake_case"`: [5](#0-4) 

When deserialization encounters an unknown enum variant (e.g., a new variant added in a software update), serde/BCS deserialization fails: [6](#0-5) 

The deduper is then created based on the potentially divergent type: [7](#0-6) [8](#0-7) 

During block preparation, different deduper implementations produce different transaction sets: [9](#0-8) 

The `NoOpDeduper` returns all transactions unchanged: [10](#0-9) 

While `TxnHashAndAuthenticatorDeduper` filters duplicates based on `(txn_hash, authenticator)` pairs: [11](#0-10) 

**Attack Scenario:**

1. Network runs with `OnChainExecutionConfig::V3+` configured with `transaction_deduper_type: NoDedup`
2. A governance proposal updates the config to use a new enum variant `TxnHashAndAuthenticatorV2` (added in new software version)
3. During the upgrade window:
   - Validators with updated software: Successfully deserialize → use `NoDedup` or new variant
   - Validators with old software: Deserialization fails → fallback to `Missing` → use `TxnHashAndAuthenticatorV1`
4. During block execution:
   - Old validators: Filter out duplicate transactions
   - New validators: Include all transactions (if using `NoDedup`)
5. Different transaction sets executed → different state roots → **consensus violation**

This breaks the critical invariant: "**Deterministic Execution: All validators must produce identical state roots for identical blocks**"

## Impact Explanation
This is a **Critical Severity** vulnerability per Aptos bug bounty criteria:

- **Consensus/Safety violation**: Different validators compute different state roots for the same block, breaking AptosBFT safety guarantees
- **Non-recoverable network partition**: Once validators diverge, they cannot reach consensus on subsequent blocks without manual intervention
- **Requires hardfork**: Recovery requires coordinating all validators to roll back to a common state and upgrade software

The vulnerability affects **all validators** in the network during software upgrade windows or when deserialization bugs occur. A network with even one validator using a different deduper type cannot maintain consensus.

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability will manifest during:

1. **Planned network upgrades** when new `TransactionDeduperType` variants are introduced:
   - Some validators upgrade early, others late
   - Upgrade window can last hours or days
   - High probability during major version transitions

2. **Governance config updates** that activate new features:
   - If activation precedes complete validator upgrade
   - Even a 5-minute window creates risk

3. **Deserialization bugs** in BCS or serde:
   - Edge cases in double deserialization logic
   - Platform-specific deserialization differences

The vulnerability is **not easily exploitable** by an external attacker (requires governance process or upgrade timing), but it's a **protocol design flaw** that creates consensus failure risk during normal operational procedures.

## Recommendation
Implement consensus-level validation that all validators successfully deserialized the same configuration:

1. **Add explicit validation** in epoch manager:
```rust
let execution_config = match onchain_execution_config {
    Ok(config) => config,
    Err(error) => {
        error!("CRITICAL: Failed to deserialize OnChainExecutionConfig: {}", error);
        panic!("Cannot proceed with incompatible execution config");
    }
};
```

2. **Include deduper type in consensus state** to detect divergence:
```rust
// In EpochState or similar consensus-critical structure
pub deduper_type: TransactionDeduperType,
```

3. **Add pre-activation validation** in governance proposals:
    - Check all active validators support new enum variants before activation
    - Implement feature flags to gate new variants
    - Add `#[serde(other)]` unknown variant handling with explicit error

4. **Improve error handling** in `create_transaction_deduper()`:
```rust
pub fn create_transaction_deduper(
    deduper_type: TransactionDeduperType,
) -> Result<Arc<dyn TransactionDeduper>, Error> {
    // Return Result instead of silent default
    // Log deduper type for debugging
    info!("Creating transaction deduper: {:?}", deduper_type);
    // ... rest of implementation
}
```

5. **Add monitoring/metrics** for deduper type mismatches across validators

## Proof of Concept
```rust
// This PoC demonstrates the vulnerability scenario
// It requires two validator nodes running different software versions

// Validator A (old software) - only knows about existing variants
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDeduperType {
    NoDedup,
    TxnHashAndAuthenticatorV1,
}

// Validator B (new software) - knows about new variant
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDeduperType {
    NoDedup,
    TxnHashAndAuthenticatorV1,
    TxnHashAndAuthenticatorV2, // New variant
}

// On-chain config updated via governance to use new variant
let config = OnChainExecutionConfig::V7(ExecutionConfigV7 {
    transaction_deduper_type: TransactionDeduperType::TxnHashAndAuthenticatorV2,
    // ... other fields
});

// Serialize and store on-chain
let bytes = bcs::to_bytes(&config).unwrap();

// Validator A attempts deserialization
let result_a: Result<OnChainExecutionConfig> = bcs::from_bytes(&bytes);
// Fails: unknown variant "txn_hash_and_authenticator_v2"
assert!(result_a.is_err());
// Falls back to Missing → TxnHashAndAuthenticatorV1

// Validator B attempts deserialization  
let result_b: Result<OnChainExecutionConfig> = bcs::from_bytes(&bytes);
// Succeeds: uses TxnHashAndAuthenticatorV2
assert!(result_b.is_ok());

// Result: Validators use different deduper implementations
// → Different transaction sets → State divergence → Consensus failure
```

**Notes**

The vulnerability stems from a fundamental design flaw: **lack of consensus-level validation** that all validators successfully parsed identical execution configurations. The silent fallback mechanism prioritizes availability over safety, violating the core blockchain invariant of deterministic execution. While not directly exploitable by an external attacker, this represents a critical protocol vulnerability that manifests during routine network operations (software upgrades, governance updates), making it a legitimate Critical severity issue requiring immediate remediation.

### Citations

**File:** consensus/src/epoch_manager.rs (L1178-1179)
```rust
        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
```

**File:** consensus/src/epoch_manager.rs (L1191-1193)
```rust
        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }
```

**File:** consensus/src/epoch_manager.rs (L1202-1203)
```rust
        let execution_config = onchain_execution_config
            .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
```

**File:** types/src/on_chain_config/execution_config.rs (L108-120)
```rust
    pub fn transaction_deduper_type(&self) -> TransactionDeduperType {
        match &self {
            // Note, this behavior was enabled before OnChainExecutionConfig was registered.
            OnChainExecutionConfig::Missing => TransactionDeduperType::TxnHashAndAuthenticatorV1,
            OnChainExecutionConfig::V1(_config) => TransactionDeduperType::NoDedup,
            OnChainExecutionConfig::V2(_config) => TransactionDeduperType::NoDedup,
            OnChainExecutionConfig::V3(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V4(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V5(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V6(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V7(config) => config.transaction_deduper_type.clone(),
        }
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L169-173)
```rust
    fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
        let raw_bytes: Vec<u8> = bcs::from_bytes(bytes)?;
        bcs::from_bytes(&raw_bytes)
            .map_err(|e| format_err!("[on-chain config] Failed to deserialize into config: {}", e))
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L265-270)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")] // cannot use tag = "type" as nested enums cannot work, and bcs doesn't support it
pub enum TransactionDeduperType {
    NoDedup,
    TxnHashAndAuthenticatorV1,
}
```

**File:** consensus/src/pipeline/execution_client.rs (L564-565)
```rust
        let transaction_deduper =
            create_transaction_deduper(onchain_execution_config.transaction_deduper_type());
```

**File:** consensus/src/transaction_deduper.rs (L14-21)
```rust
/// No Op Deduper to maintain backward compatibility
pub struct NoOpDeduper {}

impl TransactionDeduper for NoOpDeduper {
    fn dedup(&self, txns: Vec<SignedTransaction>) -> Vec<SignedTransaction> {
        txns
    }
}
```

**File:** consensus/src/transaction_deduper.rs (L23-33)
```rust
pub fn create_transaction_deduper(
    deduper_type: TransactionDeduperType,
) -> Arc<dyn TransactionDeduper> {
    match deduper_type {
        TransactionDeduperType::NoDedup => Arc::new(NoOpDeduper {}),
        TransactionDeduperType::TxnHashAndAuthenticatorV1 => {
            info!("Using simple hash set transaction deduper");
            Arc::new(TxnHashAndAuthenticatorDeduper::new())
        },
    }
}
```

**File:** consensus/src/block_preparer.rs (L99-99)
```rust
            let deduped_txns = txn_deduper.dedup(filtered_txns);
```

**File:** consensus/src/txn_hash_and_authenticator_deduper.rs (L38-95)
```rust
impl TransactionDeduper for TxnHashAndAuthenticatorDeduper {
    fn dedup(&self, transactions: Vec<SignedTransaction>) -> Vec<SignedTransaction> {
        let _timer = TXN_DEDUP_SECONDS.start_timer();
        let mut seen = HashMap::new();
        let mut is_possible_duplicate = false;
        let mut possible_duplicates = vec![false; transactions.len()];
        for (i, txn) in transactions.iter().enumerate() {
            match seen.get(&(txn.sender(), txn.replay_protector())) {
                None => {
                    seen.insert((txn.sender(), txn.replay_protector()), i);
                },
                Some(first_index) => {
                    is_possible_duplicate = true;
                    possible_duplicates[*first_index] = true;
                    possible_duplicates[i] = true;
                },
            }
        }
        if !is_possible_duplicate {
            TXN_DEDUP_FILTERED.observe(0 as f64);
            return transactions;
        }

        let num_txns = transactions.len();

        let hash_and_authenticators: Vec<_> = possible_duplicates
            .into_par_iter()
            .zip(&transactions)
            .with_min_len(optimal_min_len(num_txns, 48))
            .map(|(need_hash, txn)| match need_hash {
                true => Some((txn.committed_hash(), txn.authenticator())),
                false => None,
            })
            .collect();

        // TODO: Possibly parallelize. See struct comment.
        let mut seen_hashes = HashSet::new();
        let mut num_duplicates: usize = 0;
        let filtered: Vec<_> = hash_and_authenticators
            .into_iter()
            .zip(transactions)
            .filter_map(|(maybe_hash, txn)| match maybe_hash {
                None => Some(txn),
                Some(hash_and_authenticator) => {
                    if seen_hashes.insert(hash_and_authenticator) {
                        Some(txn)
                    } else {
                        num_duplicates += 1;
                        None
                    }
                },
            })
            .collect();

        TXN_DEDUP_FILTERED.observe(num_duplicates as f64);
        filtered
    }
}
```
