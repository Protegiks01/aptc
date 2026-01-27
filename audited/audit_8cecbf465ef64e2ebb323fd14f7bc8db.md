# Audit Report

## Title
Indexer Memory Exhaustion via Unbounded PropertyMap Accumulation in Token Processing Batches

## Summary
The token processor in the Aptos indexer loads property maps from on-chain token data into an in-memory HashMap without enforcing explicit memory limits. While individual property maps are bounded by on-chain constraints (1MB per write operation), a batch of transactions can accumulate large property maps that collectively exhaust available memory, causing indexer crashes and API unavailability.

## Finding Description

The vulnerability exists in the token transaction processor's handling of TokenV2 property maps during batch processing. [1](#0-0) 

The processor creates a `TokenV2AggregatedDataMapping` HashMap to store token metadata including property maps for all tokens encountered in a transaction batch. [2](#0-1) 

Property maps are deserialized from on-chain write resources without size validation: [3](#0-2) 

Each PropertyMap contains a `serde_json::Value` that holds the deserialized property data: [4](#0-3) 

**On-chain constraints** that define maximum property map sizes:
- Maximum 1000 properties per map: [5](#0-4) 
- Maximum 1MB per write operation: [6](#0-5) 
- Maximum 10MB total write set per transaction: [7](#0-6) 

**Indexer constraints** that define batch processing:
- Default batch size of 500 transactions: [8](#0-7) 

**Attack scenario:**
1. Attacker creates multiple transactions (or exploits legitimate high-volume periods) where each transaction creates/updates a token with a property map approaching the 1MB limit
2. The indexer fetches a batch of 500 such transactions
3. During processing, the processor loads all property maps into the `token_v2_metadata_helper` HashMap without size checks
4. With 500 transactions × ~1MB property maps each, the indexer attempts to allocate 500MB+ of memory
5. The deserialized JSON representation may be larger than the BCS-encoded on-chain data, amplifying memory usage
6. On memory-constrained indexer nodes, this causes OOM errors, crashes, or severe performance degradation

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." While on-chain operations have gas-based limits, the indexer does not enforce corresponding memory limits when deserializing this data.

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty program based on "API crashes" criteria. When the indexer crashes or becomes unresponsive:

1. **API Unavailability**: Applications relying on the indexer API lose access to token data, NFT metadata, and transaction history
2. **Service Degradation**: Even without crashing, excessive memory consumption causes slow query responses and processing delays
3. **Cascading Failures**: If multiple indexer instances are affected simultaneously, the entire indexing infrastructure may become unavailable

While this does not affect consensus or validator operations, it impacts critical user-facing infrastructure that many applications depend on for querying blockchain state.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is feasible because:
1. **No special privileges required**: Any user can submit transactions with large property maps
2. **Exploitable through legitimate usage**: High-volume NFT mints with rich metadata can trigger this naturally without malicious intent
3. **Batch processing amplifies impact**: The 500-transaction batch size concentrates the memory pressure

The primary barrier is cost - creating 1MB property maps incurs significant storage fees (approximately 4+ APT per transaction based on storage costs [9](#0-8) ). However:
- Smaller property maps (100-500KB) are more economical while still causing cumulative memory issues
- Legitimate usage patterns (popular NFT drops) can trigger this without malicious intent
- Sustained or coordinated attacks become more feasible as the cost is spread over time

## Recommendation

Implement memory budget tracking and limits in the token processor:

1. **Add configurable memory limits**:
   - Add a `max_batch_memory_bytes` configuration parameter (e.g., 100MB default)
   - Track cumulative memory usage as property maps are added to the HashMap

2. **Implement size checks before insertion**:
   ```rust
   let property_map_size = estimate_property_map_size(&property_map);
   if accumulated_memory_size + property_map_size > config.max_batch_memory_bytes {
       // Log warning and skip this property map, or split into smaller batch
       aptos_logger::warn!(
           "Property map size {} exceeds remaining budget, skipping",
           property_map_size
       );
       continue;
   }
   accumulated_memory_size += property_map_size;
   ```

3. **Add batch splitting**:
   - When memory budget is exceeded mid-batch, commit the current batch and start a new one
   - This prevents single large batches from exhausting memory

4. **Add monitoring and alerts**:
   - Track peak memory usage per batch
   - Alert when approaching memory limits
   - Log property map sizes for forensics

## Proof of Concept

**Move script to create tokens with large property maps:**

```move
script {
    use aptos_framework::object;
    use aptos_token_objects::collection;
    use aptos_token_objects::token;
    use aptos_token_objects::property_map;
    use std::string::{Self, String};
    use std::vector;

    fun create_large_property_map_token(creator: &signer) {
        // Create collection
        let collection_name = string::utf8(b"Large Property Test");
        collection::create_unlimited_collection(
            creator,
            string::utf8(b"Test collection"),
            collection_name,
            option::none(),
            string::utf8(b"https://example.com"),
        );

        // Create token with large property map (approaching 1MB)
        let token_name = string::utf8(b"Large Token");
        let keys = vector::empty<String>();
        let types = vector::empty<String>();
        let values = vector::empty<vector<u8>>();
        
        // Add 1000 properties with ~1KB byte vectors each
        let i = 0;
        while (i < 1000) {
            let key = string::utf8(b"property_");
            string::append(&mut key, to_string(i));
            vector::push_back(&mut keys, key);
            vector::push_back(&mut types, string::utf8(b"vector<u8>"));
            
            // Create ~1KB byte vector
            let large_value = vector::empty<u8>();
            let j = 0;
            while (j < 1000) {
                vector::push_back(&mut large_value, 0xFF);
                j = j + 1;
            };
            vector::push_back(&mut values, large_value);
            
            i = i + 1;
        };

        let properties = property_map::prepare_input(keys, types, values);
        
        token::create_named_token(
            creator,
            collection_name,
            string::utf8(b"Description"),
            token_name,
            properties,
            string::utf8(b"https://example.com/token"),
        );
    }
}
```

**Reproduction steps:**
1. Submit 500 transactions using the above script within a short time window
2. Monitor indexer memory usage during batch processing
3. Observe memory spike to 500MB+ as property maps are deserialized
4. On constrained nodes, observe OOM crashes or severe performance degradation

---

**Notes:**
- This is an availability/robustness issue in auxiliary infrastructure (indexer), not a consensus or funds safety issue
- The core blockchain validators are unaffected
- Mitigation is relatively straightforward through memory budget enforcement
- Consider this a capacity planning and defensive programming issue that warrants addressing to ensure reliable indexer operations

### Citations

**File:** crates/indexer/src/processors/token_processor.rs (L1072-1072)
```rust
    let mut token_v2_metadata_helper: TokenV2AggregatedDataMapping = HashMap::new();
```

**File:** crates/indexer/src/processors/token_processor.rs (L1137-1141)
```rust
                        if let Some(property_map) =
                            PropertyMap::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.property_map = Some(property_map);
                        }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L30-30)
```rust
pub type TokenV2AggregatedDataMapping = HashMap<CurrentObjectPK, TokenV2AggregatedData>;
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L404-408)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PropertyMap {
    #[serde(deserialize_with = "deserialize_token_object_property_map_from_bcs_hexstring")]
    pub inner: serde_json::Value,
}
```

**File:** aptos-move/framework/aptos-token-objects/sources/property_map.move (L33-33)
```text
    const MAX_PROPERTY_MAP_SIZE: u64 = 1000;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-157)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L159-162)
```rust
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L195-199)
```rust
            storage_fee_per_state_byte: FeePerByte,
            { 14.. => "storage_fee_per_state_byte" },
            // 0.8 million APT for 2 TB state bytes
            40,
        ],
```

**File:** config/src/config/indexer_config.rs (L20-20)
```rust
pub const DEFAULT_BATCH_SIZE: u16 = 500;
```
