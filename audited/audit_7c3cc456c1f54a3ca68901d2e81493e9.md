# Audit Report

## Title
Unbounded Memory Allocation in Parking Lot Address Query Leading to Node Slowdown and API Degradation

## Summary
The `process_parking_lot_addresses()` function constructs an unbounded `Vec<(AccountAddress, u64)>` response containing all accounts in the mempool's parking lot without pagination or size limits. An attacker can fill the parking lot with millions of unique addresses, causing memory exhaustion and CPU overhead when this endpoint is queried.

## Finding Description

The mempool maintains a "parking lot" index for transactions that are not yet ready for broadcast (typically transactions with sequence numbers higher than the current on-chain sequence number). The vulnerability exists in the chain of calls: [1](#0-0) 

This function retrieves ALL addresses from the parking lot without any bounds: [2](#0-1) 

Which delegates to: [3](#0-2) 

Which calls the underlying index method: [4](#0-3) 

**Attack Path:**

1. Attacker creates many unique account addresses (up to 2,000,000 based on default capacity)
2. For each address, submits ONE transaction with a sequence number significantly higher than the on-chain sequence number
3. These transactions are placed in the parking lot as "not ready"
4. The parking lot data structure grows unbounded based on unique addresses: [5](#0-4) 

5. When `get_parking_lot_addresses()` is called (via admin endpoint or internal monitoring), it constructs a Vec with potentially millions of entries

**Default Configuration Limits:** [6](#0-5) 

With `capacity = 2,000,000` and `capacity_per_user = 100`, an attacker submitting 1 transaction per unique address can have 2,000,000 unique addresses in the parking lot.

**Exposure via Admin Service:** [7](#0-6) 

The endpoint serializes the entire response with BCS, compounding the memory impact.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: When the parking lot address query is executed with millions of entries:
   - Allocates 80MB+ for Vec (2M entries × 40 bytes each)
   - Holds mempool lock during iteration, blocking other operations
   - BCS serialization creates additional allocations
   - HTTP response transmission consumes network bandwidth

2. **API Crashes**: The admin service becomes unresponsive when processing large parking lot queries, preventing legitimate debugging and monitoring.

3. **Breaks Resource Limits Invariant**: The system fails to respect computational and memory constraints for API responses, violating the documented invariant that "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Ability to submit transactions (requires gas payment)
- Access to create multiple unique addresses (trivial)
- Knowledge of mempool parking lot mechanism

**Attack Cost:**
To fill the parking lot with 2M addresses requires submitting 2M transactions, which has real gas costs. However, the attack is persistent (transactions remain until system TTL of 600 seconds) and the damage is done once the parking lot is filled - any subsequent query triggers the resource exhaustion.

**Feasibility:**
The attack is highly feasible because:
1. No specific rate limiting on parking lot filling
2. Transactions with invalid sequence numbers are accepted into mempool
3. The vulnerability is triggered by legitimate operators trying to debug issues
4. Per-user capacity limits don't prevent many unique addresses

## Recommendation

Implement pagination and maximum response size limits for the parking lot address query:

```rust
pub(crate) fn get_parking_lot_addresses(
    &self,
    offset: usize,
    limit: usize,
) -> (Vec<(AccountAddress, u64)>, usize) {
    let max_limit = 1000; // Maximum entries per query
    let actual_limit = std::cmp::min(limit, max_limit);
    
    let addresses: Vec<(AccountAddress, u64)> = self.data
        .iter()
        .skip(offset)
        .take(actual_limit)
        .map(|(addr, txns)| (*addr, txns.len() as u64))
        .collect();
    
    let total_count = self.data.len();
    (addresses, total_count)
}
```

Update the API signature: [8](#0-7) 

Change to include pagination parameters and return both the page and total count.

Additionally, consider implementing:
1. A separate limit on the number of unique addresses allowed in the parking lot
2. More aggressive eviction of parking lot entries when approaching capacity
3. Rate limiting on the admin endpoint itself

## Proof of Concept

```rust
// Test demonstrating parking lot fill attack
#[tokio::test]
async fn test_parking_lot_unbounded_response() {
    use aptos_types::account_address::AccountAddress;
    use aptos_types::transaction::{RawTransaction, Script, SignedTransaction};
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    
    // Create mempool with default config
    let mut mempool = Mempool::new(&NodeConfig::default());
    
    // Fill parking lot with many unique addresses
    // Each submits 1 transaction with high sequence number
    let num_addresses = 10_000; // Scale to 2M for full impact
    
    for i in 0..num_addresses {
        let address = AccountAddress::random();
        let private_key = Ed25519PrivateKey::generate_for_testing();
        
        // Create transaction with sequence number 1000 (will be parked if on-chain is 0)
        let raw_txn = RawTransaction::new(
            address,
            1000, // High sequence number
            TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
            100_000,
            1,
            0,
            ChainId::test(),
        );
        
        let signature = private_key.sign(&raw_txn).unwrap();
        let txn = SignedTransaction::new(raw_txn, private_key.public_key(), signature);
        
        // Submit transaction - it will be parked
        mempool.add_txn(txn, 1, Some(0), TimelineState::NotReady, false, None, None);
    }
    
    // Now query parking lot addresses
    let start = std::time::Instant::now();
    let addresses = mempool.get_parking_lot_addresses();
    let duration = start.elapsed();
    
    println!("Parking lot size: {}", addresses.len());
    println!("Query time: {:?}", duration);
    println!("Memory size: ~{} bytes", addresses.len() * 40);
    
    assert_eq!(addresses.len(), num_addresses);
    // With 2M addresses: ~80MB allocation, multi-second query time
}
```

**Notes:**
- The vulnerability exists in production code paths used for debugging and monitoring
- While the admin endpoint requires authentication, the attack vector is filling the parking lot, not calling the endpoint
- Legitimate operators triggering the query causes the resource exhaustion
- The issue becomes more severe as mempool capacity increases in the future

### Citations

**File:** mempool/src/shared_mempool/tasks.rs (L168-184)
```rust
pub(crate) async fn process_parking_lot_addresses<NetworkClient, TransactionValidator>(
    smp: SharedMempool<NetworkClient, TransactionValidator>,
    callback: oneshot::Sender<Vec<(AccountAddress, u64)>>,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg>,
    TransactionValidator: TransactionValidation + 'static,
{
    let addresses = smp.mempool.lock().get_parking_lot_addresses();

    if callback.send(addresses).is_err() {
        warn!(LogSchema::event_log(
            LogEntry::JsonRpc,
            LogEvent::CallbackFail
        ));
        counters::CLIENT_CALLBACK_FAIL.inc();
    }
}
```

**File:** mempool/src/core_mempool/mempool.rs (L660-662)
```rust
    pub fn get_parking_lot_addresses(&self) -> Vec<(AccountAddress, u64)> {
        self.transactions.get_parking_lot_addresses()
    }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L1051-1053)
```rust
    pub(crate) fn get_parking_lot_addresses(&self) -> Vec<(AccountAddress, u64)> {
        self.parking_lot_index.get_addresses()
    }
```

**File:** mempool/src/core_mempool/index.rs (L529-536)
```rust
pub struct ParkingLotIndex {
    // DS invariants:
    // 1. for each entry (account, txns) in `data`, `txns` is never empty
    // 2. for all accounts, data.get(account_indices.get(`account`)) == (account, sequence numbers of account's txns)
    data: Vec<(AccountAddress, BTreeSet<(u64, HashValue)>)>,
    account_indices: HashMap<AccountAddress, usize>,
    size: usize,
}
```

**File:** mempool/src/core_mempool/index.rs (L652-657)
```rust
    pub(crate) fn get_addresses(&self) -> Vec<(AccountAddress, u64)> {
        self.data
            .iter()
            .map(|(addr, txns)| (*addr, txns.len() as u64))
            .collect::<Vec<(AccountAddress, u64)>>()
    }
```

**File:** config/src/config/mempool_config.rs (L121-123)
```rust
            capacity: 2_000_000,
            capacity_bytes: 2 * 1024 * 1024 * 1024,
            capacity_per_user: 100,
```

**File:** crates/aptos-admin-service/src/server/mempool/mod.rs (L12-38)
```rust
pub async fn mempool_handle_parking_lot_address_request(
    _req: Request<Body>,
    mempool_client_sender: MempoolClientSender,
) -> hyper::Result<Response<Body>> {
    match get_parking_lot_addresses(mempool_client_sender).await {
        Ok(addresses) => {
            info!("Finished getting parking lot addresses from mempool.");
            match bcs::to_bytes(&addresses) {
                Ok(addresses) => Ok(reply_with(vec![], addresses)),
                Err(e) => {
                    info!("Failed to bcs serialize parking lot addresses from mempool: {e:?}");
                    Ok(reply_with_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        e.to_string(),
                    ))
                },
            }
        },
        Err(e) => {
            info!("Failed to get parking lot addresses from mempool: {e:?}");
            Ok(reply_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
            ))
        },
    }
}
```

**File:** mempool/src/shared_mempool/types.rs (L245-247)
```rust
    /// Retrieves all addresses with transactions in the mempool's parking lot and
    /// the number of transactions for each address
    GetAddressesFromParkingLot(oneshot::Sender<Vec<(AccountAddress, u64)>>),
```
