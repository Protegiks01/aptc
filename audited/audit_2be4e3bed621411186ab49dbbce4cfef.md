# Audit Report

## Title
Division by Zero Panic Due to Missing Validation of `num_sender_buckets` Configuration Parameter

## Summary
The `PrioritizedPeersState::new()` constructor and `TransactionStore::new()` do not validate the `num_sender_buckets` configuration parameter, allowing it to be set to zero. This causes immediate division-by-zero panics when transactions are processed, resulting in node crashes and denial of service.

## Finding Description

The mempool configuration parameter `num_sender_buckets` lacks validation in multiple critical code paths:

**1. Missing Constructor Validation**

The `PrioritizedPeersState::new()` constructor accepts `MempoolConfig` without validating `num_sender_buckets`: [1](#0-0) 

**2. Missing ConfigSanitizer Implementation**

The `MempoolConfig::sanitize()` method contains only a TODO comment and performs no validation: [2](#0-1) 

**3. Division by Zero in Bucket Calculation**

The `sender_bucket()` function performs modulo arithmetic without checking for zero: [3](#0-2) 

When `num_sender_buckets` is 0, the expression `% num_sender_buckets` triggers a division-by-zero panic.

**4. Empty Timeline Index Creation**

If `num_sender_buckets` is 0, the initialization loop in `TransactionStore::new()` never executes, leaving `timeline_index` empty: [4](#0-3) 

**5. Crash Paths**

Multiple code paths trigger the panic when processing transactions:

- **Transaction insertion**: [5](#0-4) 

- **Transaction removal**: [6](#0-5) 

- **Transaction ready processing**: [7](#0-6) 

## Impact Explanation

**Severity: High** - This meets the High Severity criteria for "API crashes" and "Validator node slowdowns" per the Aptos bug bounty program.

**Impact:**
- **Node Availability**: Any node with `num_sender_buckets: 0` crashes immediately upon receiving its first transaction
- **Network Degradation**: If multiple nodes are misconfigured, network transaction processing capacity is reduced
- **Validator Impact**: Validator nodes crash when attempting to process transactions, potentially affecting consensus participation
- **Recovery Difficulty**: Requires node restart with corrected configuration

**Limitation:** This is **not a remotely exploitable vulnerability**. It requires the ability to modify node configuration files, which is a privileged operation typically requiring filesystem access or administrative control.

## Likelihood Explanation

**Likelihood: Low to Medium** - depending on operational practices.

**Factors Increasing Likelihood:**
- The `ConfigSanitizer` has an explicit TODO comment indicating validation was intended but not implemented
- Configuration templates or automated deployment tools could propagate a zero value
- Operator error during manual configuration is possible
- No runtime warnings prevent this configuration

**Factors Decreasing Likelihood:**
- The default value is 4 (non-zero)
- Requires privileged access to modify configuration
- Most operators use default or tested configurations

## Recommendation

Implement validation in the `MempoolConfig::sanitize()` method:

```rust
impl ConfigSanitizer for MempoolConfig {
    fn sanitize(
        _node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // Validate num_sender_buckets
        if self.num_sender_buckets == 0 {
            return Err(Error::ConfigSanitizerFailed(
                "num_sender_buckets".to_string(),
                "Value must be greater than 0".to_string(),
            ));
        }
        
        // Add other validations as needed
        if self.capacity == 0 {
            return Err(Error::ConfigSanitizerFailed(
                "capacity".to_string(),
                "Value must be greater than 0".to_string(),
            ));
        }
        
        Ok(())
    }
}
```

Additionally, add defensive checks in the constructors or use the type system to prevent zero values (e.g., `NonZeroU8`).

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to calculate the remainder with a modulo of zero")]
fn test_zero_num_sender_buckets_causes_panic() {
    use aptos_config::config::{MempoolConfig, NodeConfig};
    use aptos_types::account_address::AccountAddress;
    
    // Create a config with num_sender_buckets = 0
    let mut mempool_config = MempoolConfig::default();
    mempool_config.num_sender_buckets = 0;
    
    let mut node_config = NodeConfig::default();
    node_config.mempool = mempool_config;
    
    // Create mempool with zero buckets
    let mut mempool = Mempool::new(&node_config);
    
    // Create a test transaction
    let sender = AccountAddress::random();
    let txn = create_test_signed_transaction(sender);
    
    // This will panic with division by zero
    let _ = mempool.add_txn(
        txn,
        100, // ranking_score
        Some(0), // account_sequence_number
        TimelineState::NotReady,
        true, // client_submitted
        None, // ready_time_at_sender
        None, // priority
    );
}
```

**Notes:**

This is a **defense-in-depth** issue rather than a remotely exploitable vulnerability. While the missing validation could lead to node crashes, it requires privileged access to modify configuration files. The finding is relevant for:

1. **Operational Security**: Preventing accidental misconfigurations that cause node crashes
2. **Code Quality**: Completing the intended ConfigSanitizer implementation (as evidenced by the TODO comment)
3. **Fail-Fast Principle**: Catching invalid configurations at startup rather than during runtime

The vulnerability does not meet the strict criteria for remote exploitation without privileged access, but represents a legitimate robustness and operational security concern that should be addressed through proper input validation.

### Citations

**File:** mempool/src/shared_mempool/priority.rs (L174-193)
```rust
    pub fn new(
        mempool_config: MempoolConfig,
        node_type: NodeType,
        time_service: TimeService,
    ) -> Self {
        let prioritized_peers = Arc::new(RwLock::new(Vec::new()));
        let peer_comparator =
            PrioritizedPeersComparator::new(mempool_config.clone(), time_service.clone());

        Self {
            mempool_config,
            prioritized_peers,
            peer_comparator,
            observed_all_ping_latencies: false,
            last_peer_priority_update: None,
            time_service,
            peer_to_sender_buckets: HashMap::new(),
            node_type,
        }
    }
```

**File:** config/src/config/mempool_config.rs (L176-184)
```rust
impl ConfigSanitizer for MempoolConfig {
    fn sanitize(
        _node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        Ok(()) // TODO: add reasonable verifications
    }
}
```

**File:** mempool/src/core_mempool/transaction_store.rs (L42-47)
```rust
pub fn sender_bucket(
    address: &AccountAddress,
    num_sender_buckets: MempoolSenderBucket,
) -> MempoolSenderBucket {
    address.as_ref()[address.as_ref().len() - 1] as MempoolSenderBucket % num_sender_buckets
}
```

**File:** mempool/src/core_mempool/transaction_store.rs (L104-111)
```rust
    pub(crate) fn new(config: &MempoolConfig) -> Self {
        let mut timeline_index = HashMap::new();
        for sender_bucket in 0..config.num_sender_buckets {
            timeline_index.insert(
                sender_bucket,
                MultiBucketTimelineIndex::new(config.broadcast_buckets.clone()).unwrap(),
            );
        }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L554-566)
```rust
                let sender_bucket = sender_bucket(address, self.num_sender_buckets);
                let ready_for_quorum_store = !self.priority_index.contains(txn);

                self.priority_index.insert(txn);

                // If timeline_state is `NonQualified`, then the transaction is never added to the timeline_index,
                // and never broadcasted to the shared mempool.
                let ready_for_mempool_broadcast = txn.timeline_state == TimelineState::NotReady;
                if ready_for_mempool_broadcast {
                    self.timeline_index
                        .get_mut(&sender_bucket)
                        .unwrap()
                        .insert(txn);
```

**File:** mempool/src/core_mempool/transaction_store.rs (L744-753)
```rust
        let sender_bucket = sender_bucket(&txn.get_sender(), self.num_sender_buckets);
        self.timeline_index
            .get_mut(&sender_bucket)
            .unwrap_or_else(|| {
                panic!(
                    "Unable to get the timeline index for the sender bucket {}",
                    sender_bucket
                )
            })
            .remove(txn);
```

**File:** mempool/src/core_mempool/mempool.rs (L353-359)
```rust
                .with_label_values(&[sender_bucket(
                    &sender,
                    self.transactions.num_sender_buckets(),
                )
                .to_string()
                .as_str()])
                .inc();
```
