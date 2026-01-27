# Audit Report

## Title
HashMap Collision in Token V2 Metadata Indexing Due to Resource Type Truncation

## Summary
The `parse_v2_token()` function in the token processor uses a composite key `(object_address, resource_type)` for the `current_token_v2_metadata` HashMap, where `resource_type` is truncated to 128 characters. This truncation can cause collisions when multiple distinct resource types on the same object have identical first 128 characters, resulting in metadata loss in the indexer database.

## Finding Description
In the token indexer's metadata tracking system, resource types are truncated to 128 characters before being used as part of a HashMap key. [1](#0-0) 

Move resource type strings follow the format `{address}::{module}::{struct_name}<{generic_params}>`. With standardized addresses being 66 characters and module/struct names up to 255 characters each (as per Move's `IDENTIFIER_SIZE_MAX` limit), [2](#0-1)  resource type strings can easily exceed 128 characters, especially with nested generic parameters.

The vulnerability occurs in the following flow:

1. During transaction processing, the indexer extracts token metadata from `WriteResource` changes
2. Resource types are truncated using `truncate_str(&resource.type_, NAME_LENGTH)` where `NAME_LENGTH = 128` [3](#0-2) 
3. The truncated resource type is used as part of the HashMap key [4](#0-3) 
4. If two different resources on the same object have resource types that share the same first 128 characters, the second `HashMap::insert()` overwrites the first
5. Only the last metadata entry survives to the database insertion [5](#0-4) 

The database schema confirms this limitation: [6](#0-5) 

Since Aptos objects can have multiple resources of different types stored at the same address (as evidenced by production transactions), and `HashMap::insert()` silently overwrites existing entries with the same key, metadata can be permanently lost.

## Impact Explanation
This vulnerability affects the **indexer subsystem only**, which is an off-chain data aggregation service. It does not impact:
- Blockchain consensus or safety
- Transaction execution or validation  
- On-chain state or storage (AptosDB)
- Funds, assets, or tokens themselves
- Validator operations or staking

The impact is limited to **indexer data quality**: applications and users querying token metadata through the indexer may receive incomplete or incorrect metadata when collisions occur. However, this is a **data availability/quality issue in an off-chain service**, not a blockchain security vulnerability.

Per the Aptos bug bounty criteria, this does not meet Critical, High, or Medium severity thresholds as it doesn't affect funds, consensus, protocol violations, or require intervention in the blockchain itself. At most, this would be a Low severity issue (non-critical implementation bug) outside the core security scope.

## Likelihood Explanation
While technically feasible, exploitation requires:
- Intentional deployment of Move modules with carefully crafted long resource type names
- Multiple resources with colliding truncated types on the same object
- Both processed in the same indexer batch

This is unlikely to occur accidentally but could be deliberately engineered by a motivated attacker to cause indexer data corruption.

## Recommendation
Replace the truncation approach with one of these solutions:

**Option 1**: Use a hash of the full resource type string instead of truncating:
```rust
let resource_type_hash = hash_str(&resource.type_);
```

**Option 2**: Store the full resource type in the database and remove the 128-character column limit, using TEXT type instead of VARCHAR(128).

**Option 3**: Add validation to detect and log collisions before insertion:
```rust
if current_token_v2_metadata.contains_key(&(object_address.clone(), resource_type.clone())) {
    aptos_logger::warn!("Resource type collision detected for object {} with type {}", object_address, resource_type);
}
```

## Proof of Concept
```rust
// Proof of concept demonstrating the collision scenario
// Two resource types that differ only after character 128

let object_addr = "0x0000000000000000000000000000000000000000000000000000000000000001";

// Both resource types have identical first 128 characters
let type1 = format!(
    "0x0000000000000000000000000000000000000000000000000000000000000001::my_module::MyStruct<0x{}AAAA>",
    "0".repeat(60)
);

let type2 = format!(
    "0x0000000000000000000000000000000000000000000000000000000000000001::my_module::MyStruct<0x{}BBBB>",
    "0".repeat(60)
);

// When truncated to 128 chars, both become identical
let truncated1 = truncate_str(&type1, 128);
let truncated2 = truncate_str(&type2, 128);

assert_eq!(truncated1, truncated2); // Collision!
assert_ne!(type1, type2); // But original types are different

// In HashMap, the second insert would overwrite the first
let mut metadata_map = HashMap::new();
metadata_map.insert((object_addr.to_string(), truncated1), metadata1);
metadata_map.insert((object_addr.to_string(), truncated2), metadata2); // Overwrites!
assert_eq!(metadata_map.len(), 1); // Only one entry survives
```

---

## Notes

**Important Clarification**: While this is a legitimate bug in the indexer implementation that can cause data quality issues, it does **not** qualify as a blockchain security vulnerability for this audit's scope. The vulnerability:

- Affects only the off-chain indexer service
- Does not impact consensus, execution, storage (AptosDB), governance, or staking
- Does not affect on-chain state or assets
- Does not meet the Critical, High, or Medium severity criteria defined in the bug bounty program

The indexer is a data aggregation tool separate from the core blockchain protocol. Issues here affect query results but not blockchain security invariants. Given the audit's explicit focus on "consensus vulnerabilities, Move VM implementation bugs, state management attacks, and on-chain governance security," and the strict validation requirement that findings must affect "funds, consensus, or availability," this indexer bug falls outside the primary security scope.

### Citations

**File:** crates/indexer/src/models/token_models/v2_token_metadata.rs (L57-57)
```rust
                let resource_type = truncate_str(&resource.type_, NAME_LENGTH);
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L67-67)
```rust
pub const IDENTIFIER_SIZE_MAX: u64 = 255;
```

**File:** crates/indexer/src/models/token_models/token_utils.rs (L17-17)
```rust
pub const NAME_LENGTH: usize = 128;
```

**File:** crates/indexer/src/processors/token_processor.rs (L819-844)
```rust
fn insert_current_token_v2_metadatas(
    conn: &mut PgConnection,
    items_to_insert: &[CurrentTokenV2Metadata],
) -> Result<(), diesel::result::Error> {
    use schema::current_token_v2_metadata::dsl::*;

    let chunks = get_chunks(items_to_insert.len(), CurrentTokenV2Metadata::field_count());

    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::current_token_v2_metadata::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict((object_address, resource_type))
                .do_update()
                .set((
                    data.eq(excluded(data)),
                    state_key_hash.eq(excluded(state_key_hash)),
                    last_transaction_version.eq(excluded(last_transaction_version)),
                    inserted_at.eq(excluded(inserted_at)),
                )),
            Some(" WHERE current_token_v2_metadata.last_transaction_version <= excluded.last_transaction_version "),
        )?;
    }
    Ok(())
}
```

**File:** crates/indexer/src/processors/token_processor.rs (L1472-1478)
```rust
                            current_token_v2_metadata.insert(
                                (
                                    token_metadata.object_address.clone(),
                                    token_metadata.resource_type.clone(),
                                ),
                                token_metadata,
                            );
```

**File:** crates/indexer/src/schema.rs (L459-460)
```rust
        #[max_length = 128]
        resource_type -> Varchar,
```
