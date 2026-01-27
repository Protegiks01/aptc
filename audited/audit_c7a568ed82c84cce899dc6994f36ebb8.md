# Audit Report

## Title
Redis Data Poisoning in Indexer File Store Worker Bypasses Transaction Validation

## Summary
The indexer-grpc-file-store worker reads transaction data directly from Redis without performing any signature verification or authenticity checks. An attacker with write access to the Redis instance can inject arbitrary malicious transaction data that will be blindly uploaded to the file store, poisoning the entire indexer data infrastructure.

## Finding Description

The indexer architecture consists of two workers:
1. **Cache worker**: Receives validated transactions from fullnode via gRPC and stores them in Redis
2. **File store worker**: Reads transactions from Redis and uploads them to persistent file storage

The vulnerability exists in the file store worker's data processing pipeline. When fetching transactions from Redis, the worker performs only basic metadata validation (version numbers, chain ID) but completely bypasses cryptographic signature verification. [1](#0-0) 

The `get_transactions()` method simply decodes the cached data without validation: [2](#0-1) 

This method calls `get_transactions_with_durations()`, which performs a Redis MGET operation and decodes the results: [3](#0-2) 

The critical issue is in the `CacheEntry::into_transaction()` method, which only performs deserialization without any cryptographic validation: [4](#0-3) 

**Attack Flow:**
1. Attacker gains write access to Redis instance at `redis_main_instance_address`
2. Attacker crafts malicious Transaction protobuf messages with:
   - Fake transfer transactions showing false balances
   - Manipulated governance votes
   - Forged NFT ownership changes
   - Invalid or missing signatures
3. Attacker writes these to Redis using keys matching the cache format (`l4:{version}` or `{version}`)
4. File store worker reads poisoned data via `cache_operator.get_transactions()`
5. Worker uploads malicious data to file store without verification
6. All downstream indexer consumers (wallets, block explorers, analytics platforms) receive corrupted data

The only validations performed are version number sequence checks and chain ID matching, which an attacker can easily satisfy: [5](#0-4) 

## Impact Explanation

This vulnerability represents a **Medium Severity** issue under "State inconsistencies requiring intervention" criteria. While it does not directly compromise blockchain consensus or validator operations, it creates critical data integrity issues:

**Direct Impact:**
- **Indexer Data Corruption**: File store becomes authoritative source of poisoned transaction data
- **Ecosystem-Wide Misinformation**: All services consuming indexer data (wallets, explorers, DeFi platforms, analytics) display false information
- **Trust Degradation**: Users see incorrect balances, fake transaction history, manipulated governance records
- **Operational Disruption**: Requires manual intervention to identify and purge poisoned data batches

**Potential Escalation:**
- Social engineering attacks leveraging fake transaction history
- Market manipulation through false data displayed on explorers
- Governance manipulation by forging vote records
- Reputational damage to Aptos ecosystem

While this does not affect the blockchain state itself (which remains cryptographically secure), the indexer infrastructure is critical for ecosystem usability. Most users and applications interact with the chain through indexed data, not direct node queries.

## Likelihood Explanation

**Likelihood: Medium**

**Required Prerequisites:**
- Write access to Redis instance at `redis_main_instance_address`
- Knowledge of Redis key format and protobuf encoding

**Attacker Scenarios:**
1. **Compromised Infrastructure**: If Redis instance is exposed or improperly secured
2. **Insider Threat**: Malicious operator with infrastructure access
3. **Supply Chain Attack**: Compromised dependency with Redis access
4. **Cloud Misconfiguration**: Exposed Redis port or weak authentication

The attack is straightforward to execute once Redis access is obtained, requiring only basic protobuf manipulation skills. The lack of any cryptographic verification creates a complete trust boundary failure.

## Recommendation

Implement transaction signature verification in the file store worker before uploading data. The worker should validate that all transactions read from Redis have valid cryptographic signatures matching their claimed senders.

**Recommended Fix:**

Add signature verification to the file store worker's transaction processing pipeline:

```rust
// In ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs

use aptos_types::transaction::SignedTransaction;

// Add validation function
fn verify_transaction_authenticity(txn: &Transaction) -> Result<()> {
    // For UserTransactions, verify signature
    if let Some(user_txn) = &txn.user {
        // Reconstruct SignedTransaction from protobuf
        // Verify signature against sender's public key
        // This requires converting protobuf Transaction back to native types
        // and calling existing signature verification logic
    }
    // For system transactions (BlockMetadata, Genesis, etc.), 
    // verify against expected validators/system addresses
    Ok(())
}

// Modify transaction fetching in run() method (around line 162)
let transactions = cache_operator_clone
    .get_transactions(start_version, FILE_ENTRY_TRANSACTION_COUNT)
    .await
    .unwrap();

// Add verification loop
for txn in &transactions {
    verify_transaction_authenticity(txn)
        .context("Transaction signature verification failed")?;
}
```

**Additional Security Measures:**
1. **Redis Authentication**: Enforce strong authentication on Redis instance
2. **Network Isolation**: Place Redis in private network segment
3. **Integrity Checksums**: Add cryptographic checksums to cache entries
4. **Monitoring**: Alert on unexpected data patterns or version gaps
5. **Data Origin Tagging**: Tag cache entries with cryptographic proof of origin from fullnode

## Proof of Concept

```rust
// PoC: Inject malicious transaction data into Redis
// File: redis_poison_poc.rs

use redis::{Commands, Connection};
use prost::Message;
use aptos_protos::transaction::v1::Transaction;

fn poison_redis_cache(redis_url: &str) -> anyhow::Result<()> {
    let client = redis::Client::open(redis_url)?;
    let mut conn = client.get_connection()?;
    
    // Craft malicious transaction
    let malicious_txn = Transaction {
        version: 1000000, // Target version
        epoch: 100,
        block_height: 50000,
        // Craft fake user transaction with invalid signature
        user: Some(/* fake UserTransaction with manipulated data */),
        ..Default::default()
    };
    
    // Encode as protobuf
    let mut bytes = Vec::new();
    malicious_txn.encode(&mut bytes)?;
    
    // Write to Redis using cache key format
    let key = format!("l4:{}", malicious_txn.version);
    
    // Compress with LZ4 to match cache format
    let mut encoder = lz4::EncoderBuilder::new()
        .level(4)
        .build(Vec::new())?;
    std::io::Write::write_all(&mut encoder, &bytes)?;
    let compressed = encoder.finish().0;
    
    // Inject into Redis
    conn.set::<_, _, ()>(key, compressed)?;
    
    println!("Malicious transaction injected at version {}", malicious_txn.version);
    println!("File store worker will blindly upload this to file store");
    
    Ok(())
}

fn main() {
    let redis_url = "redis://redis_main_instance_address:6379";
    poison_redis_cache(redis_url).expect("Poisoning failed");
}
```

**Notes:**

This vulnerability affects the **indexer infrastructure** layer, not the core blockchain consensus. The blockchain state itself remains cryptographically secure and unaffected. However, since most ecosystem participants rely on indexed data rather than running full nodes, this data poisoning attack can have widespread impact on user experience, application functionality, and ecosystem trust. The fix requires adding the signature verification layer that was mistakenly omitted when implementing the trust boundary between Redis cache and file store persistence.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L162-165)
```rust
                    let transactions = cache_operator_clone
                        .get_transactions(start_version, FILE_ENTRY_TRANSACTION_COUNT)
                        .await
                        .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L179-181)
```rust
                    for (i, txn) in transactions.iter().enumerate() {
                        assert_eq!(txn.version, start_version + i as u64);
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L367-395)
```rust
    pub async fn get_transactions_with_durations(
        &mut self,
        start_version: u64,
        transaction_count: u64,
    ) -> anyhow::Result<(Vec<Transaction>, f64, f64)> {
        let start_time = std::time::Instant::now();
        let versions = (start_version..start_version + transaction_count)
            .map(|e| CacheEntry::build_key(e, self.storage_format))
            .collect::<Vec<String>>();
        let encoded_transactions: Vec<Vec<u8>> = self
            .conn
            .mget(versions)
            .await
            .context("Failed to mget from Redis")?;
        let io_duration = start_time.elapsed().as_secs_f64();
        let start_time = std::time::Instant::now();
        let mut transactions = vec![];
        for encoded_transaction in encoded_transactions {
            let cache_entry: CacheEntry = CacheEntry::new(encoded_transaction, self.storage_format);
            let transaction = cache_entry.into_transaction();
            transactions.push(transaction);
        }
        ensure!(
            transactions.len() == transaction_count as usize,
            "Failed to get all transactions from cache."
        );
        let decoding_duration = start_time.elapsed().as_secs_f64();
        Ok((transactions, io_duration, decoding_duration))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L398-407)
```rust
    pub async fn get_transactions(
        &mut self,
        start_version: u64,
        transaction_count: u64,
    ) -> anyhow::Result<Vec<Transaction>> {
        let (transactions, _, _) = self
            .get_transactions_with_durations(start_version, transaction_count)
            .await?;
        Ok(transactions)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L142-157)
```rust
    pub fn into_transaction(self) -> Transaction {
        match self {
            CacheEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                Transaction::decode(decompressed.as_slice()).expect("proto deserialization failed.")
            },
            CacheEntry::Base64UncompressedProto(bytes) => {
                let bytes: Vec<u8> = base64::decode(bytes).expect("base64 decoding failed.");
                Transaction::decode(bytes.as_slice()).expect("proto deserialization failed.")
            },
        }
    }
```
