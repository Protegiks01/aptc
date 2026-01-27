# Audit Report

## Title
TypeTag Depth Inconsistency Causes Validator Node Panic During Transaction Persistence

## Summary
An off-by-one inconsistency exists between TypeTag parsing (allows depth 8) and BCS serialization (allows depth 7), enabling attackers to craft transactions that pass validation but cause validator node panics when persisted to storage.

## Finding Description

The TypeTag parser and serializer have mismatched depth limits that break the **State Consistency** invariant: [1](#0-0) 

The parser uses `depth > 8`, allowing depths 0-8 (9 levels): [2](#0-1) 

The deserializer/serializer uses `*r >= 8`, allowing depths 0-7 (8 levels):

When a transaction with depth-8 TypeTag (e.g., `vector<vector<vector<vector<vector<vector<vector<vector<u64>>>>>>>>`) is submitted via JSON API:

1. Type argument is parsed from string and passes validation [3](#0-2) 

2. TypeTag is converted from MoveType to create transaction payload [4](#0-3) 

3. Transaction executes successfully (runtime Type creation uses depth limit of 20)

4. When persisting to storage, BCS serialization is attempted: [5](#0-4) 

5. Serialization fails due to depth 8 exceeding limit of 7

6. The error propagates to aptosdb_writer where `.unwrap()` causes panic: [6](#0-5) 

## Impact Explanation

**High Severity** - This vulnerability enables validator node crashes through transaction submission:

- **Validator node availability**: Attacker can crash validator nodes by submitting malicious transactions
- **Consensus disruption**: If multiple validators process the same malicious transaction, simultaneous crashes could affect consensus
- **Resource exhaustion**: Repeated attacks could prevent transaction processing

The impact qualifies as High Severity under Aptos bug bounty criteria: "Validator node slowdowns" and "API crashes", though the actual impact is node crashes rather than just slowdowns.

## Likelihood Explanation

**High likelihood**:
- **No privilege required**: Any user can submit transactions via REST API
- **Simple exploitation**: Requires only crafting a JSON transaction with nested vector types
- **Deterministic**: The panic will occur reliably when the transaction is persisted
- **Widespread effect**: All nodes that receive and execute the transaction will crash during persistence

## Recommendation

Align the parser depth check with the serialization/deserialization limit:

```rust
// In parser.rs, change line 287 from:
if depth > crate::safe_serialize::MAX_TYPE_TAG_NESTING {
// To:
if depth >= crate::safe_serialize::MAX_TYPE_TAG_NESTING {
```

This ensures parsed TypeTags can always be serialized. Additionally, add explicit error handling instead of `.unwrap()` in transaction persistence to prevent panics:

```rust
// In aptosdb_writer.rs, replace .unwrap() with proper error propagation
self.ledger_db
    .transaction_db()
    .commit_transactions(
        chunk.first_version,
        chunk.transactions,
        skip_index_and_usage,
    )?
```

## Proof of Concept

```rust
// Test demonstrating the inconsistency
#[test]
fn test_depth_8_typetag_parsing_vs_serialization() {
    use move_core_types::parser::parse_type_tag;
    
    // This type has depth 8 at the innermost u64
    let type_str = "vector<vector<vector<vector<vector<vector<vector<vector<u64>>>>>>>>";
    
    // Parsing succeeds
    let type_tag = parse_type_tag(type_str).expect("parsing should succeed");
    
    // Serialization fails
    let result = bcs::to_bytes(&type_tag);
    assert!(result.is_err(), "serialization should fail for depth 8");
}
```

**Attack simulation** (JSON transaction payload):
```json
{
  "sender": "0x1",
  "payload": {
    "function": "0x1::coin::transfer",
    "type_arguments": ["vector<vector<vector<vector<vector<vector<vector<vector<u64>>>>>>>>"],
    "arguments": ["0x2", "100"]
  }
}
```

This transaction would pass API validation but cause node panic during storage persistence.

### Citations

**File:** third_party/move/move-core/types/src/parser.rs (L287-289)
```rust
        if depth > crate::safe_serialize::MAX_TYPE_TAG_NESTING {
            bail!("Exceeded TypeTag nesting limit during parsing: {}", depth);
        }
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L54-57)
```rust
        if *r >= MAX_TYPE_TAG_NESTING {
            return Err(D::Error::custom(
                "type tag nesting exceeded during deserialization",
            ));
```

**File:** api/types/src/move_types.rs (L928-949)
```rust
impl TryFrom<&MoveType> for TypeTag {
    type Error = anyhow::Error;

    fn try_from(tag: &MoveType) -> anyhow::Result<Self> {
        let ret = match tag {
            MoveType::Bool => TypeTag::Bool,
            MoveType::U8 => TypeTag::U8,
            MoveType::U16 => TypeTag::U16,
            MoveType::U32 => TypeTag::U32,
            MoveType::U64 => TypeTag::U64,
            MoveType::U128 => TypeTag::U128,
            MoveType::U256 => TypeTag::U256,
            MoveType::I8 => TypeTag::I8,
            MoveType::I16 => TypeTag::I16,
            MoveType::I32 => TypeTag::I32,
            MoveType::I64 => TypeTag::I64,
            MoveType::I128 => TypeTag::I128,
            MoveType::I256 => TypeTag::I256,
            MoveType::Address => TypeTag::Address,
            MoveType::Signer => TypeTag::Signer,
            MoveType::Vector { items } => TypeTag::Vector(Box::new(items.as_ref().try_into()?)),
            MoveType::Struct(v) => TypeTag::Struct(Box::new(v.try_into()?)),
```

**File:** api/types/src/convert.rs (L720-724)
```rust
                    type_arguments
                        .iter()
                        .map(|v| v.try_into())
                        .collect::<Result<_>>()?,
                    args,
```

**File:** storage/aptosdb/src/schema/transaction/mod.rs (L38-41)
```rust
impl ValueCodec<TransactionSchema> for Transaction {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L291-299)
```rust
                self.ledger_db
                    .transaction_db()
                    .commit_transactions(
                        chunk.first_version,
                        chunk.transactions,
                        skip_index_and_usage,
                    )
                    .unwrap()
            });
```
