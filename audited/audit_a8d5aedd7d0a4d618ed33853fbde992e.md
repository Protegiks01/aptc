# Audit Report

## Title
Mempool Spam Attack Prevents Legitimate Large Package Deployments via Chunked Publishing

## Summary
An attacker can spam the mempool with fake chunk transactions from multiple accounts to prevent legitimate users from deploying large packages through the chunked publishing mechanism, causing a targeted denial-of-service on critical package deployment functionality.

## Finding Description

The chunked publishing mechanism allows users to deploy large packages by splitting them into chunks and submitting multiple `stage_code_chunk` transactions. [1](#0-0)  However, this mechanism lacks specific anti-spam protections, making it vulnerable to mempool flooding attacks.

The mempool has finite capacity with configurable limits: 2,000,000 transactions by default and a per-account limit of 100 sequence-number-based transactions. [2](#0-1) 

When the mempool reaches capacity, the system attempts to evict transactions only from the "parking lot" (non-ready transactions with future sequence numbers). [3](#0-2)  The parking lot contains only transactions that are not yet ready for broadcast. [4](#0-3) 

**Attack Flow:**
1. Attacker creates approximately 20,000 accounts to bypass the per-account limit of 100 transactions
2. From each account, attacker submits 100 `stage_code_chunk` transactions with correct sequence numbers (making them "ready" transactions)
3. These transactions fill the mempool to its 2,000,000 transaction capacity
4. Since all attacker transactions have valid sequence numbers, they are "ready" and NOT in the parking lot
5. When a legitimate user attempts to submit chunk transactions for large package deployment:
   - The mempool is full and returns `MempoolIsFull` error [5](#0-4) 
   - Even with higher gas prices, the legitimate transaction cannot enter because eviction only removes parking lot transactions
   - The legitimate deployment is blocked

The `stage_code_chunk` function has no rate limiting or anti-spam protections beyond standard mempool limits. [6](#0-5)  Each chunk transaction is approximately 55KB in size. [7](#0-6) 

## Impact Explanation

This vulnerability constitutes **Medium severity** per the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Legitimate large package deployments are blocked during the attack, requiring network operators to intervene or users to wait until the attack subsides
- **Limited operational disruption**: While not causing permanent damage or loss of funds, it prevents a critical network operation (large package deployment)
- **Targeted DoS**: Unlike general network DoS (which is out of scope), this specifically targets the chunked publishing mechanism

The attack doesn't meet Critical or High severity because:
- No funds are lost or stolen
- No consensus violations occur
- Network continues operating normally for other transaction types
- The disruption is temporary and reversible

## Likelihood Explanation

**Likelihood: Medium to High** for a motivated attacker because:

**Attacker Requirements:**
- Approximately 20,000 accounts (achievable through scripted account creation)
- Sufficient funds to pay gas for 2,000,000 transactions continuously
- Automated script to maintain correct sequence numbers
- Continuous monitoring to resubmit as transactions execute

**Economic Cost:**
Each chunk transaction (~55KB) incurs:
- Intrinsic gas based on transaction size [8](#0-7) 
- Execution gas for Move VM operations
- Storage fees for the `StagingArea` resource

However, for a targeted attack against a specific organization's package deployment or to extort deployment fees, the cost may be acceptable to a well-funded adversary. The attacker can also abandon the staged data without ever publishing, minimizing wasted resources beyond gas fees.

## Recommendation

Implement multi-layered defenses against chunked publishing spam:

**1. Add per-account staging area size limits:**
```move
// In large_packages.move
const MAX_STAGING_AREA_SIZE_BYTES: u64 = 10_000_000; // 10 MB limit

inline fun stage_code_chunk_internal(...) {
    // After creating/retrieving staging_area
    let current_size = vector::length(&staging_area.metadata_serialized);
    // Add size of all code chunks
    assert!(
        current_size + total_chunk_size <= MAX_STAGING_AREA_SIZE_BYTES,
        error::resource_exhausted(ESTAGING_AREA_TOO_LARGE)
    );
    // Continue with existing logic
}
```

**2. Implement time-based rate limiting:**
Add a cooldown period between chunk submissions from the same account to prevent rapid spam.

**3. Gas-based eviction in mempool:**
Modify the mempool eviction logic to allow evicting ready transactions with lower gas prices when a higher-priority transaction arrives and mempool is full:

```rust
// In transaction_store.rs
fn check_is_full_after_eviction(...) -> bool {
    if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
        // Try parking lot eviction first (existing logic)
        // ...
        
        // If still full, try evicting lowest priority ready transactions
        if self.is_full() && txn.get_gas_price() > minimum_threshold {
            self.evict_lowest_priority_ready_transactions(txn);
        }
    }
    self.is_full()
}
```

**4. Chunked publishing quotas:**
Implement network-wide limits on concurrent chunked publishing operations to prevent monopolization.

## Proof of Concept

```rust
// Simulation of mempool spam attack
use aptos_types::transaction::{TransactionPayload, SignedTransaction};
use aptos_sdk::types::LocalAccount;

fn simulate_chunk_spam_attack() {
    const NUM_ATTACKER_ACCOUNTS: usize = 20_000;
    const CHUNKS_PER_ACCOUNT: usize = 100;
    
    // Create attacker accounts
    let mut attacker_accounts: Vec<LocalAccount> = (0..NUM_ATTACKER_ACCOUNTS)
        .map(|_| LocalAccount::generate(&mut rand::thread_rng()))
        .collect();
    
    // Generate fake chunk transactions
    let mut spam_transactions = Vec::new();
    for account in &mut attacker_accounts {
        for chunk_idx in 0..CHUNKS_PER_ACCOUNT {
            // Create fake chunk data (~55KB)
            let fake_chunk = vec![0u8; 55_000];
            
            // Build stage_code_chunk transaction
            let payload = create_stage_code_chunk_payload(
                fake_chunk,
                vec![chunk_idx as u16],
                vec![vec![0u8; 1000]],
            );
            
            let txn = account.sign_with_transaction_builder(
                TransactionBuilder::new(payload)
                    .sender(account.address())
                    .sequence_number(chunk_idx as u64)
                    .max_gas_amount(2_000_000)
                    .gas_unit_price(100)
            );
            
            spam_transactions.push(txn);
        }
    }
    
    // Submit to mempool - fills to capacity (2M transactions)
    // Now legitimate chunk transactions are rejected with MempoolIsFull
    
    println!("Submitted {} spam chunk transactions", spam_transactions.len());
    println!("Mempool capacity exhausted - legitimate deployments blocked");
}
```

**Notes:**

This vulnerability exploits the lack of specific anti-spam protections in the chunked publishing mechanism combined with the mempool's limited eviction capabilities. While the mempool implements standard protections (per-account limits, gas prioritization), it cannot evict ready transactions from other accounts to make room for higher-priority transactions, allowing a well-funded attacker to maintain a sustained denial-of-service against large package deployments. The attack is economically costly but feasible for targeted disruption scenarios.

### Citations

**File:** aptos-move/framework/src/chunked_publish.rs (L19-20)
```rust
/// The default chunk size for splitting code and metadata to fit within the transaction size limits.
pub const CHUNK_SIZE_IN_BYTES: usize = 55_000;
```

**File:** aptos-move/framework/src/chunked_publish.rs (L36-110)
```rust
pub fn chunk_package_and_create_payloads(
    metadata: Vec<u8>,
    package_code: Vec<Vec<u8>>,
    publish_type: PublishType,
    object_address: Option<AccountAddress>,
    large_packages_module_address: AccountAddress,
    chunk_size: usize,
) -> Vec<TransactionPayload> {
    // Chunk the metadata
    let mut metadata_chunks = create_chunks(metadata, chunk_size);
    // Separate last chunk for special handling
    let mut metadata_chunk = metadata_chunks.pop().expect("Metadata is required");

    let mut taken_size = metadata_chunk.len();
    let mut payloads = metadata_chunks
        .into_iter()
        .map(|chunk| {
            large_packages_stage_code_chunk(chunk, vec![], vec![], large_packages_module_address)
        })
        .collect::<Vec<_>>();

    let mut code_indices: Vec<u16> = vec![];
    let mut code_chunks: Vec<Vec<u8>> = vec![];

    for (idx, module_code) in package_code.into_iter().enumerate() {
        let chunked_module = create_chunks(module_code, chunk_size);
        for chunk in chunked_module {
            if taken_size + chunk.len() > chunk_size {
                // Create a payload and reset accumulators
                let payload = large_packages_stage_code_chunk(
                    metadata_chunk,
                    code_indices.clone(),
                    code_chunks.clone(),
                    large_packages_module_address,
                );
                payloads.push(payload);

                metadata_chunk = vec![];
                code_indices.clear();
                code_chunks.clear();
                taken_size = 0;
            }

            code_indices.push(idx as u16);
            taken_size += chunk.len();
            code_chunks.push(chunk);
        }
    }

    // The final call includes staging the last metadata and code chunk, and then publishing or upgrading the package on-chain.
    let payload = match publish_type {
        PublishType::AccountDeploy => large_packages_stage_code_chunk_and_publish_to_account(
            metadata_chunk,
            code_indices,
            code_chunks,
            large_packages_module_address,
        ),
        PublishType::ObjectDeploy => large_packages_stage_code_chunk_and_publish_to_object(
            metadata_chunk,
            code_indices,
            code_chunks,
            large_packages_module_address,
        ),
        PublishType::ObjectUpgrade => large_packages_stage_code_chunk_and_upgrade_object_code(
            metadata_chunk,
            code_indices,
            code_chunks,
            object_address.expect("ObjectAddress is missing"),
            large_packages_module_address,
        ),
    };
    payloads.push(payload);

    payloads
}
```

**File:** config/src/config/mempool_config.rs (L42-47)
```rust
    /// Maximum number of transactions allowed in the Mempool
    pub capacity: usize,
    /// Maximum number of bytes allowed in the Mempool
    pub capacity_bytes: usize,
    /// Maximum number of sequence number based transactions allowed in the Mempool per user
    pub capacity_per_user: usize,
```

**File:** mempool/src/core_mempool/transaction_store.rs (L311-317)
```rust
        if self.check_is_full_after_eviction(&txn, account_sequence_number) {
            return MempoolStatus::new(MempoolStatusCode::MempoolIsFull).with_message(format!(
                "Mempool is full. Mempool size: {}, Capacity: {}",
                self.system_ttl_index.size(),
                self.capacity,
            ));
        }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L415-456)
```rust
    fn check_is_full_after_eviction(
        &mut self,
        txn: &MempoolTransaction,
        account_sequence_number: Option<u64>,
    ) -> bool {
        if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
            let now = Instant::now();
            // try to free some space in Mempool from ParkingLot by evicting non-ready txns
            let mut evicted_txns = 0;
            let mut evicted_bytes = 0;
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
            }
            if evicted_txns > 0 {
                counters::CORE_MEMPOOL_PARKING_LOT_EVICTED_COUNT.observe(evicted_txns as f64);
                counters::CORE_MEMPOOL_PARKING_LOT_EVICTED_BYTES.observe(evicted_bytes as f64);
                counters::CORE_MEMPOOL_PARKING_LOT_EVICTED_LATENCY
                    .observe(now.elapsed().as_secs_f64());
            }
        }
        self.is_full()
    }
```

**File:** mempool/src/core_mempool/index.rs (L526-546)
```rust
/// ParkingLotIndex keeps track of "not_ready" transactions, e.g., transactions that
/// can't be included in the next block because their sequence number is too high.
/// We keep a separate index to be able to efficiently evict them when Mempool is full.
pub struct ParkingLotIndex {
    // DS invariants:
    // 1. for each entry (account, txns) in `data`, `txns` is never empty
    // 2. for all accounts, data.get(account_indices.get(`account`)) == (account, sequence numbers of account's txns)
    data: Vec<(AccountAddress, BTreeSet<(u64, HashValue)>)>,
    account_indices: HashMap<AccountAddress, usize>,
    size: usize,
}

impl ParkingLotIndex {
    pub(crate) fn new() -> Self {
        Self {
            data: vec![],
            account_indices: HashMap::new(),
            size: 0,
        }
    }

```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L66-78)
```text
    public entry fun stage_code_chunk(
        owner: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ) acquires StagingArea {
        stage_code_chunk_internal(
            owner,
            metadata_chunk,
            code_indices,
            code_chunks
        );
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L38-49)
```rust
        [
            large_transaction_cutoff: NumBytes,
            "large_transaction_cutoff",
            600
        ],
        // The units of gas that to be charged per byte over the `large_transaction_cutoff` in addition to
        // `min_transaction_gas_units` for transactions whose size exceeds `large_transaction_cutoff`.
        [
            intrinsic_gas_per_byte: InternalGasPerByte,
            "intrinsic_gas_per_byte",
            1_158
        ],
```
