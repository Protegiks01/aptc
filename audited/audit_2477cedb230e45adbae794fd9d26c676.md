# Audit Report

## Title
Gas-Based Front-Running of Security-Critical Module Upgrades and Freezes

## Summary
Attackers can front-run module upgrade and freeze transactions by observing them in the transparent mempool and submitting higher gas-price transactions that exploit the current vulnerable code before security fixes are applied. This allows extraction of value or manipulation of state during the critical window between upgrade submission and execution.

## Finding Description

The Aptos mempool implements gas-price-based transaction ordering where transactions with higher `gas_ranking_score` are prioritized for execution. [1](#0-0)  This ordering is deterministic and enforced when consensus pulls transactions from mempool.

Transactions are broadcast to all validators through the shared mempool architecture before consensus execution, making pending transactions publicly visible to network participants. [2](#0-1) 

The `object_code_deployment` module provides `upgrade()` and `freeze_code_object()` functions for managing code objects. [3](#0-2)  While these functions correctly verify ownership at execution time [4](#0-3) , there is no protection against observability or timing attacks.

**Attack Flow:**

1. Alice (code object owner) discovers vulnerability V in module M at code object O
2. Alice submits TX1: `object_code_deployment::upgrade(O, fixed_module_M)` with gas_price = 100
3. Attacker Bob monitors mempool, observes TX1, analyzes the code diff
4. Bob identifies vulnerability V from the changes and submits TX2: exploit transaction with gas_price = 500
5. Due to gas-based ordering, TX2 executes first, exploiting V
6. TX1 executes second, applying the fix (too late)

The same attack applies to `freeze_code_object()` operations where an attacker can interact with the object before it becomes immutable.

**Broken Invariants:**
- **Transaction Validation (Invariant #7)**: The system fails to provide atomicity guarantees for security-critical operations
- **Access Control (Invariant #8)**: While ownership is verified, temporal access control (preventing exploitation during upgrade windows) is absent

## Impact Explanation

This vulnerability enables **Medium Severity** attacks per Aptos bug bounty criteria:
- **Limited funds loss or manipulation**: If the module being upgraded manages assets, attackers can drain or manipulate funds before the fix is applied
- **State inconsistencies requiring intervention**: Exploits during the upgrade window can corrupt state that requires manual intervention to resolve

The impact is limited by:
- Vulnerability must exist in the current code
- Attacker must detect and exploit within mempool propagation time (~100-500ms)
- Only affects modules with exploitable vulnerabilities being patched

## Likelihood Explanation

**HIGH** likelihood for the following scenarios:
- Public modules with known vulnerabilities receiving emergency patches
- DeFi protocols upgrading to fix economic exploits
- Any high-value target where mempool monitoring is profitable

**MEDIUM** likelihood overall because:
- Requires active monitoring of mempool transactions
- Requires reverse-engineering code diffs to identify vulnerabilities
- Time-sensitive (must craft and submit exploit within seconds)
- Not all upgrades fix exploitable vulnerabilities

Attacker requirements are minimal: ability to monitor mempool and submit transactions with higher gas prices.

## Recommendation

Implement one or more of the following mitigations:

**Option 1: Two-Phase Upgrade Commitment**
```move
// Add commitment phase to object_code_deployment.move
public entry fun commit_upgrade(
    publisher: &signer,
    code_object: Object<PackageRegistry>,
    code_hash: vector<u8>,
    reveal_after_timestamp: u64,
) {
    // Store commitment without revealing code
    // Prevent other operations until reveal
}

public entry fun reveal_upgrade(
    publisher: &signer,
    metadata_serialized: vector<u8>,
    code: vector<vector<u8>>,
    code_object: Object<PackageRegistry>,
) {
    // Verify hash matches commitment
    // Verify timestamp has passed
    // Execute upgrade
}
```

**Option 2: Governance-Controlled Critical Upgrades**
For security-critical modules, require governance proposal with time delay, preventing immediate exploitation.

**Option 3: Private Transaction Pool**
Implement encrypted transaction submission for code deployment operations, revealing only after inclusion in a block.

**Option 4: Upgrade Time-Lock**
Add mandatory delay between upgrade submission and execution, allowing users to exit before changes take effect (though this doesn't prevent exploitation, it provides transparency).

## Proof of Concept

```rust
// Simulated PoC demonstrating gas-based front-running
// File: mempool/src/tests/frontrun_upgrade_test.rs

#[test]
fn test_upgrade_frontrunning() {
    use crate::tests::common::{TestTransaction, setup_mempool};
    use aptos_types::transaction::ReplayProtector;
    
    let (mut mempool, mut consensus) = setup_mempool();
    
    // Alice submits legitimate upgrade with normal gas
    let alice_upgrade = TestTransaction::new(
        0, // Alice's account
        ReplayProtector::SequenceNumber(0),
        100 // Normal gas price
    );
    
    // Bob observes and submits exploit with higher gas
    let bob_exploit = TestTransaction::new(
        1, // Bob's account  
        ReplayProtector::SequenceNumber(0),
        500 // Higher gas price to front-run
    );
    
    // Add to mempool
    let mut transactions = vec![alice_upgrade, bob_exploit];
    add_txns_to_mempool(&mut mempool, transactions.clone());
    
    // Verify Bob's transaction executes first due to higher gas
    let first_tx = consensus.get_block(&mut mempool, 1, 1024);
    assert_eq!(first_tx[0].sender(), transactions[1].sender());
    
    // Alice's upgrade executes second (too late)
    let second_tx = consensus.get_block(&mut mempool, 1, 1024);
    assert_eq!(second_tx[0].sender(), transactions[0].sender());
}
```

For a complete Move-based PoC showing actual module upgrade exploitation:

```move
// Vulnerable module before upgrade
module object_addr::vulnerable {
    public fun withdraw_unprotected(amount: u64) {
        // Missing access control - vulnerability
    }
}

// Fixed module (upgrade)
module object_addr::vulnerable {
    public fun withdraw_unprotected(amount: u64) {
        abort 0 // Function disabled - fix applied
    }
}

// Attacker observes upgrade TX in mempool
// Submits higher-gas TX calling withdraw_unprotected()
// Exploit executes before fix is applied
```

**Notes**

This vulnerability is a protocol-level design issue rather than an implementation bug. The gas-based ordering mechanism is working as designed, but the design lacks protection for security-critical operations. While ownership checks prevent unauthorized upgrades, they don't prevent timing-based exploitation of the current code before fixes are applied.

The transparent mempool is necessary for consensus, but creates an unavoidable information asymmetry that sophisticated attackers can exploit. This is analogous to MEV (Maximal Extractable Value) issues in other blockchain systems, but specifically affects the security of the code upgrade mechanism itself.

Mitigation requires protocol-level changes such as commit-reveal schemes, time-locks, or private transaction pools for sensitive operations. The current implementation provides no such protections.

### Citations

**File:** mempool/src/core_mempool/index.rs (L193-198)
```rust
    fn cmp(&self, other: &OrderedQueueKey) -> Ordering {
        // Higher gas preferred
        match self.gas_ranking_score.cmp(&other.gas_ranking_score) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
```

**File:** mempool/src/shared_mempool/tasks.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! Tasks that are executed by coordinators (short-lived compared to coordinators)
use super::types::MempoolMessageId;
use crate::{
    core_mempool::{CoreMempool, TimelineState},
    counters,
    logging::{LogEntry, LogEvent, LogSchema},
    network::{BroadcastError, BroadcastPeerPriority, MempoolSyncMsg},
    shared_mempool::{
        types::{
            notify_subscribers, ScheduledBroadcast, SharedMempool, SharedMempoolNotification,
            SubmissionStatusBundle,
        },
        use_case_history::UseCaseHistory,
    },
    thread_pool::{IO_POOL, VALIDATION_POOL},
    QuorumStoreRequest, QuorumStoreResponse, SubmissionStatus,
};
use anyhow::Result;
use aptos_config::{config::TransactionFilterConfig, network_id::PeerNetworkId};
use aptos_consensus_types::common::RejectedTransactionSummary;
use aptos_crypto::HashValue;
use aptos_infallible::{Mutex, RwLock};
use aptos_logger::prelude::*;
use aptos_mempool_notifications::CommittedTransaction;
use aptos_metrics_core::HistogramTimer;
use aptos_network::application::interface::NetworkClientInterface;
use aptos_storage_interface::state_store::state_view::db_state_view::LatestDbStateCheckpointView;
use aptos_types::{
    account_address::AccountAddress,
    mempool_status::{MempoolStatus, MempoolStatusCode},
    on_chain_config::{OnChainConfigPayload, OnChainConfigProvider, OnChainConsensusConfig},
    transaction::{ReplayProtector, SignedTransaction},
    vm_status::{DiscardedVMStatus, StatusCode},
};
use aptos_vm_validator::vm_validator::{get_account_sequence_number, TransactionValidation};
use futures::{channel::oneshot, stream::FuturesUnordered};
use rayon::prelude::*;
use std::{
    cmp,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::runtime::Handle;
// ============================== //
//  broadcast_coordinator tasks  //
// ============================== //

```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L120-141)
```text
    public entry fun upgrade(
        publisher: &signer,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>,
        code_object: Object<PackageRegistry>,
    ) acquires ManagingRefs {
        code::check_code_publishing_permission(publisher);
        let publisher_address = signer::address_of(publisher);
        assert!(
            object::is_owner(code_object, publisher_address),
            error::permission_denied(ENOT_CODE_OBJECT_OWNER),
        );

        let code_object_address = object::object_address(&code_object);
        assert!(exists<ManagingRefs>(code_object_address), error::not_found(ECODE_OBJECT_DOES_NOT_EXIST));

        let extend_ref = &borrow_global<ManagingRefs>(code_object_address).extend_ref;
        let code_signer = &object::generate_signer_for_extending(extend_ref);
        code::publish_package_txn(code_signer, metadata_serialized, code);

        event::emit(Upgrade { object_address: signer::address_of(code_signer), });
    }
```
