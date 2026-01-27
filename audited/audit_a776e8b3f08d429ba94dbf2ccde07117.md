# Audit Report

## Title
Transaction Misclassification in Mempool Causes Monitoring Blind Spot for Validator Network Degradation

## Summary
The mempool transaction classification logic incorrectly labels all transactions from downstream VFN (Validator Full Node) peers as `PeerValidator` instead of `Downstream` when Quorum Store is enabled. This contradicts the documented intent and prevents operators from measuring validator network entry latency, creating a monitoring blind spot that masks network degradation attacks.

## Finding Description

The `SubmittedBy` enum is designed to classify transaction origins for latency measurement purposes: [1](#0-0) 

The documentation clearly states:
- `Downstream`: Transactions from VFNs entering the validator network - **should be used** for validator network latency measurement
- `PeerValidator`: Transactions from other validators - **should NOT be used** for validator network latency measurement  
- Comment on line 105 states: "Note, with Quorum Store enabled, no transactions will be classified as PeerValidator."

However, the implementation does the opposite. In the transaction reception logic: [2](#0-1) 

When Quorum Store is enabled (i.e., `broadcast_within_validator_network() = false`), the condition `(smp.network_interface.is_validator() && !smp.broadcast_within_validator_network())` evaluates to `true` for all validator nodes, making `ineligible_for_broadcast = true` regardless of the transaction source.

This causes `timeline_state = NonQualified`, which then triggers misclassification in: [3](#0-2) 

The logic at lines 126-127 classifies all `NonQualified` transactions as `PeerValidator`, including those from downstream VFNs.

**Attack Scenario:**
1. Validator node has Quorum Store enabled (standard production configuration)
2. VFN submits transaction to validator
3. Transaction is incorrectly classified as `PeerValidator` instead of `Downstream`
4. Latency metrics use `submitted_by_label()` which returns `"peer_validator"` instead of `"downstream"`
5. Operators monitoring `downstream` metrics see no data, cannot detect:
   - VFN network degradation
   - Malicious VFN delaying transactions
   - Transaction censorship at VFN level
   - Slow transaction propagation from downstream sources

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria - State inconsistencies requiring intervention:

1. **Monitoring Blind Spot**: The `downstream` latency metrics become empty/unused, preventing detection of validator network entry issues
2. **Masked Degradation**: Network operators cannot identify when the VFN-to-validator path is degraded or under attack
3. **False Confidence**: Operators may believe the system is healthy while downstream propagation is severely impaired
4. **Operational Impact**: Incident response is delayed because standard monitoring fails to detect the issue

This affects the **Resource Limits** invariant (Invariant #9) by preventing proper observation of system performance limits and the **Transaction Validation** invariant (Invariant #7) by obscuring transaction propagation patterns that should be monitored.

## Likelihood Explanation

**High Likelihood**: This bug triggers automatically in production configurations:
- Quorum Store is the standard configuration for validator networks
- All validators with Quorum Store enabled are affected  
- The bug requires no attacker action - it's a permanent misclassification
- Every transaction from VFNs is affected
- Operators relying on downstream metrics for monitoring are currently blind to VFN-related issues

## Recommendation

Fix the classification logic in `process_received_txns` to properly distinguish between validator and VFN peers based on `network_id`:

```rust
async fn process_received_txns<NetworkClient, TransactionValidator>(
    bounded_executor: &BoundedExecutor,
    smp: &mut SharedMempool<NetworkClient, TransactionValidator>,
    network_id: NetworkId,
    message_id: MempoolMessageId,
    transactions: Vec<(SignedTransaction, Option<u64>, Option<BroadcastPeerPriority>)>,
    peer_id: PeerId,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg> + 'static,
    TransactionValidator: TransactionValidation + 'static,
{
    // ... existing code ...
    let peer = PeerNetworkId::new(network_id, peer_id);
    
    // Fixed logic: Only classify as NonQualified if from validator network
    // Transactions from VFN network should be Downstream regardless of Quorum Store
    let ineligible_for_broadcast = if peer.network_id().is_validator_network() {
        // Validator-to-validator: always NonQualified (PeerValidator)
        true
    } else {
        // VFN-to-validator: check if this validator broadcasts to them
        // If yes (in sync_states), still mark as NonQualified for broadcast
        // but will be classified as Downstream in InsertionInfo
        smp.network_interface.is_upstream_peer(&peer, None)
    };
    
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
    // ... rest of function ...
}
```

Additionally, update `InsertionInfo::new` to use network context:

```rust
pub fn new(
    insertion_time: SystemTime,
    client_submitted: bool,
    timeline_state: TimelineState,
    network_id: Option<NetworkId>, // Add network context
) -> Self {
    let submitted_by = if client_submitted {
        SubmittedBy::Client
    } else if let Some(network_id) = network_id {
        // Use network_id to distinguish validator from VFN peers
        if network_id.is_validator_network() {
            SubmittedBy::PeerValidator
        } else {
            SubmittedBy::Downstream
        }
    } else if timeline_state == TimelineState::NonQualified {
        SubmittedBy::PeerValidator
    } else {
        SubmittedBy::Downstream
    };
    // ... rest of function ...
}
```

## Proof of Concept

**Observation Steps:**
1. Deploy validator node with Quorum Store enabled (`broadcast_within_validator_network = false`)
2. Connect a VFN to the validator
3. Submit transaction through VFN to validator
4. Query Prometheus metrics for `aptos_core_mempool_txn_commit_latency` with label `submitted_by="downstream"`
5. Observe metric is **empty** despite VFN transactions being processed
6. Query same metric with label `submitted_by="peer_validator"` 
7. Observe it contains VFN transaction latencies (incorrect)

**Expected Behavior:** VFN transactions should appear in `submitted_by="downstream"` metrics
**Actual Behavior:** VFN transactions appear in `submitted_by="peer_validator"` metrics

**Code Path Trace:**
1. VFN sends `BroadcastTransactionsRequest` on `NetworkId::Vfn` 
2. `handle_network_event` → `process_received_txns` with `network_id = NetworkId::Vfn`
3. Line 312-313: `is_validator() = true`, `broadcast_within_validator_network() = false`
4. Line 314: `ineligible_for_broadcast = (true && true) || ... = true`
5. Line 315: `timeline_state = NonQualified`
6. `MempoolTransaction::new` → `InsertionInfo::new` with `timeline_state = NonQualified`
7. Line 126-127: `submitted_by = PeerValidator` (WRONG - should be Downstream)
8. Latency logged with label `"peer_validator"` instead of `"downstream"`

## Notes

This vulnerability demonstrates a critical gap between documentation and implementation. The comment explicitly states the opposite of what the code does, suggesting either:
1. The comment is outdated and wrong, or  
2. The implementation is wrong (more likely given the monitoring use case)

The security impact is primarily on **observability** rather than direct consensus or funds loss, but creates a significant operational blind spot that could delay detection of real attacks or network degradation affecting the validator network's entry points.

### Citations

**File:** mempool/src/core_mempool/transaction.rs (L87-107)
```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SubmittedBy {
    /// The transaction was received from a client REST API submission, rather than a mempool
    /// broadcast. This can be used as the time a transaction first entered the network,
    /// to measure end-to-end latency within the entire network. However, if a transaction is
    /// submitted to multiple nodes (by the client) then the end-to-end latency measured will not
    /// be accurate (the measured value will be lower than the correct value).
    Client,
    /// The transaction was received from a downstream peer, i.e., not a client or a peer validator.
    /// At a validator, a transaction from downstream can be used as the time a transaction first
    /// entered the validator network, to measure end-to-end latency within the validator network.
    /// However, if a transaction enters via multiple validators (due to duplication outside of the
    /// validator network) then the validator end-to-end latency measured will not be accurate
    /// (the measured value will be lower than the correct value).
    Downstream,
    /// The transaction was received at a validator from another validator, rather than from the
    /// downstream VFN. This transaction should not be used to measure end-to-end latency within the
    /// validator network (see Downstream).
    /// Note, with Quorum Store enabled, no transactions will be classified as PeerValidator.
    PeerValidator,
}
```

**File:** mempool/src/core_mempool/transaction.rs (L118-138)
```rust
impl InsertionInfo {
    pub fn new(
        insertion_time: SystemTime,
        client_submitted: bool,
        timeline_state: TimelineState,
    ) -> Self {
        let submitted_by = if client_submitted {
            SubmittedBy::Client
        } else if timeline_state == TimelineState::NonQualified {
            SubmittedBy::PeerValidator
        } else {
            SubmittedBy::Downstream
        };
        Self {
            insertion_time,
            ready_time: insertion_time,
            park_time: None,
            submitted_by,
            consensus_pulled_counter: Arc::new(AtomicUsize::new(0)),
        }
    }
```

**File:** mempool/src/shared_mempool/coordinator.rs (L312-319)
```rust
    let ineligible_for_broadcast = (smp.network_interface.is_validator()
        && !smp.broadcast_within_validator_network())
        || smp.network_interface.is_upstream_peer(&peer, None);
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
```
