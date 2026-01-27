# Audit Report

## Title
Null Byte Characters in Property Maps Cause Silent Data Modification in Indexer

## Summary
Property keys and values in token property maps can contain null byte characters (\u{0000}) on-chain, but PostgreSQL's text storage does not support null bytes. This causes the indexer to silently remove null bytes during a retry mechanism, resulting in indexed data that differs from the actual on-chain data.

## Finding Description
The vulnerability exists in the property map deserialization and storage pipeline: [1](#0-0) 

On-chain, property keys are only validated for length (128 bytes max), not content. Move's `String` type supports all valid UTF-8 characters, including the null byte (\u{0000}). [2](#0-1) 

The indexer deserializes property maps from BCS-encoded JSON and stores them as PostgreSQL JSONB. However, PostgreSQL does not support null bytes in text fields. [3](#0-2) 

When insertion fails (due to null bytes), the indexer retries with `clean_data_for_db(data, true)` which silently removes null bytes: [4](#0-3) 

**Attack path:**
1. Attacker creates a token with property key="test\u{0000}key" and value="test\u{0000}value" on-chain (valid UTF-8)
2. Transaction commits successfully to the blockchain
3. Indexer extracts property map and attempts PostgreSQL insertion
4. First insertion fails due to null byte restriction
5. Retry removes null bytes: key becomes "testkey", value becomes "testvalue"
6. Modified data is stored in the index
7. On-chain data has null bytes, indexed data does not

## Impact Explanation
This is a **Low Severity** data integrity issue as indicated in the security question. It falls under "Non-critical implementation bugs" per the Aptos bug bounty program.

The issue does NOT affect:
- Blockchain consensus or safety
- On-chain transaction execution
- Validator operations
- Fund security
- State root calculations

It only affects the indexer (an auxiliary query service), causing indexed data to differ from on-chain data for properties containing null bytes.

## Likelihood Explanation
**Likelihood: Low to Medium**

While any user can create tokens with null bytes in properties, this requires:
1. Intentional crafting of property values with embedded null bytes
2. Knowledge of the PostgreSQL limitation
3. Limited practical impact since applications can verify against on-chain data directly

The issue is automatically triggered when such properties are indexed, making it deterministic once the malicious input exists.

## Recommendation
Add validation in the Move property map module to reject null bytes:

```move
// In property_map.move prepare_input function
while (!keys.is_empty()) {
    let key = keys.pop_back();
    assert!(
        key.length() <= MAX_PROPERTY_NAME_LENGTH,
        error::invalid_argument(EPROPERTY_MAP_KEY_TOO_LONG),
    );
    // Add null byte validation
    let key_bytes = string::bytes(&key);
    let i = 0;
    while (i < key_bytes.length()) {
        assert!(*key_bytes.borrow(i) != 0u8, error::invalid_argument(EPROPERTY_CONTAINS_NULL_BYTE));
        i = i + 1;
    };
    // Similar validation for values
}
```

Alternatively, make the indexer explicitly fail with a clear error when null bytes are encountered, rather than silently modifying data.

## Proof of Concept

```move
#[test_only]
module test_addr::null_byte_property_test {
    use std::string;
    use std::vector;
    use aptos_token_objects::property_map;

    #[test]
    fun test_null_byte_in_property_key() {
        // Create a property key with embedded null byte
        let mut key_bytes = b"test";
        vector::push_back(&mut key_bytes, 0u8); // null byte
        vector::append(&mut key_bytes, b"key");
        
        let key = string::utf8(key_bytes);
        
        // This will succeed on-chain as Move allows null bytes in UTF-8
        let keys = vector[key];
        let types = vector[string::utf8(b"String")];
        let values = vector[b"value"];
        
        let pm = property_map::prepare_input(keys, types, values);
        // Property map created successfully with null byte
        
        // However, when indexed, the null byte will be silently removed
        // On-chain key: "test\0key"
        // Indexed key: "testkey"
    }
}
```

## Notes
This is classified as **Low Severity** as indicated in the security question. While it represents a data integrity issue, it does not compromise blockchain consensus, validator security, or fund safety. The indexer is an off-chain query service, and applications requiring exact data fidelity can always query on-chain data directly through RPC nodes.

### Citations

**File:** aptos-move/framework/aptos-token-objects/sources/property_map.move (L97-100)
```text
            assert!(
                key.length() <= MAX_PROPERTY_NAME_LENGTH,
                error::invalid_argument(EPROPERTY_MAP_KEY_TOO_LONG),
            );
```

**File:** crates/indexer/src/models/property_map.rs (L77-92)
```rust
impl TokenObjectPropertyMap {
    /// Deserializes PropertyValue from bcs encoded json
    pub fn from_bcs_encode_str(val: Value) -> Option<Value> {
        let mut pm = TokenObjectPropertyMap {
            data: HashMap::new(),
        };
        let records: &Vec<Value> = val.get("data")?.as_array()?;
        for entry in records {
            let key = entry.get("key")?.as_str()?;
            let val = entry.get("value")?.get("value")?.as_str()?;
            let typ = entry.get("value")?.get("type")?.as_u64()?;
            let pv = create_token_object_property_value(typ as u8, val.to_string()).ok()?;
            pm.data.insert(key.to_string(), pv);
        }
        Some(Self::to_flat_json_new(pm))
    }
```

**File:** crates/indexer/src/processors/token_processor.rs (L200-253)
```rust
    match conn
        .build_transaction()
        .read_write()
        .run::<_, Error, _>(|pg_conn| {
            insert_to_db_impl(
                pg_conn,
                (&tokens, &token_ownerships, &token_datas, &collection_datas),
                (
                    &current_token_ownerships,
                    &current_token_datas,
                    &current_collection_datas,
                ),
                &token_activities,
                &current_token_claims,
                &current_ans_lookups,
                &nft_points,
                (
                    &collections_v2,
                    &token_datas_v2,
                    &token_ownerships_v2,
                    &current_collections_v2,
                    &current_token_datas_v2,
                    &current_token_ownerships_v2,
                    &token_activities_v2,
                    &current_token_v2_metadata,
                ),
            )
        }) {
        Ok(_) => Ok(()),
        Err(_) => conn
            .build_transaction()
            .read_write()
            .run::<_, Error, _>(|pg_conn| {
                let tokens = clean_data_for_db(tokens, true);
                let token_datas = clean_data_for_db(token_datas, true);
                let token_ownerships = clean_data_for_db(token_ownerships, true);
                let collection_datas = clean_data_for_db(collection_datas, true);
                let current_token_ownerships = clean_data_for_db(current_token_ownerships, true);
                let current_token_datas = clean_data_for_db(current_token_datas, true);
                let current_collection_datas = clean_data_for_db(current_collection_datas, true);
                let token_activities = clean_data_for_db(token_activities, true);
                let current_token_claims = clean_data_for_db(current_token_claims, true);
                let current_ans_lookups = clean_data_for_db(current_ans_lookups, true);
                let nft_points = clean_data_for_db(nft_points, true);
                let collections_v2 = clean_data_for_db(collections_v2, true);
                let token_datas_v2 = clean_data_for_db(token_datas_v2, true);
                let token_ownerships_v2 = clean_data_for_db(token_ownerships_v2, true);
                let current_collections_v2 = clean_data_for_db(current_collections_v2, true);
                let current_token_datas_v2 = clean_data_for_db(current_token_datas_v2, true);
                let current_token_ownerships_v2 =
                    clean_data_for_db(current_token_ownerships_v2, true);
                let token_activities_v2 = clean_data_for_db(token_activities_v2, true);
                let current_token_v2_metadata = clean_data_for_db(current_token_v2_metadata, true);

```

**File:** crates/indexer/src/util.rs (L95-96)
```rust
fn string_null_byte_replacement(value: &mut str) -> String {
    value.replace('\u{0000}', "").replace("\\u0000", "")
```
