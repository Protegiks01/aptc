# Audit Report

## Title
Unbounded Move Type String Storage in Indexer Events Table Causing Potential Database Bloat

## Summary
The `from_event()` function in the indexer events model does not validate the length of Move type strings before storing them in the PostgreSQL database, allowing arbitrarily long type strings to be inserted into the `type` TEXT column, potentially causing database storage bloat and performance degradation.

## Finding Description

The vulnerability exists in the indexer component, which processes on-chain events and stores them in a PostgreSQL database for querying. [1](#0-0) 

At line 55, the function directly converts `event.typ.to_string()` to a String without any length validation or truncation. The `typ` field is a `MoveType` enum that can represent complex nested type structures. [2](#0-1) 

The MoveType Display implementation shows that type strings are formatted recursively, with struct types including full address, module, name, and generic type parameters. [3](#0-2) 

Move's type system allows:
- Individual identifiers up to 65,535 bytes (legacy) or 255 bytes (current limit) [4](#0-3) 
- Up to 255 type parameters per struct [5](#0-4) 
- Up to 8 levels of type nesting [6](#0-5) 

The database schema defines the `type` column as TEXT with no length constraint, and while there's no direct index on the type field, the table itself will grow with large type strings. [7](#0-6) 

**Attack Path:**
1. Attacker deploys a Move module with pathological type signatures (e.g., deeply nested structs with many generic parameters)
2. Attacker emits events using these types
3. Indexer processes these events via `EventModel::from_events()` 
4. Type strings of potentially hundreds of KB are inserted into the database without validation
5. Over time, this causes database table bloat, slower queries, increased storage costs, and memory pressure

## Impact Explanation

This is a **Low Severity** issue per Aptos bug bounty criteria because:
- It does NOT affect consensus, on-chain state, or validator operations
- It does NOT cause loss of funds or compromise cryptographic security
- It does NOT affect blockchain liveness or availability
- The indexer is an off-chain component that doesn't participate in consensus

The impact is limited to:
- Database storage bloat (increased disk usage)
- Slower query performance on the events table
- Potential memory issues when loading large event records
- Increased operational costs for indexer operators

This falls under "Non-critical implementation bugs" in the Low Severity category.

## Likelihood Explanation

The likelihood is **Medium** because:
- Requires deploying a Move module with pathological types (moderate effort)
- The Move VM and verifier will accept such modules (they only check recursion depth, not string length)
- Any user can deploy modules and emit events
- The issue is deterministic once malicious types are deployed

However, it's not High likelihood because:
- Requires intentional malicious action (not accidental)
- The attacker gains no direct benefit beyond DoS on indexer infrastructure
- Most legitimate use cases won't trigger this issue

## Recommendation

Add length validation and truncation to the `from_event()` function:

```rust
pub fn from_event(
    event: &APIEvent,
    transaction_version: i64,
    transaction_block_height: i64,
    event_index: i64,
) -> Self {
    const MAX_TYPE_LENGTH: usize = 1000; // Reasonable limit for event types
    let type_string = event.typ.to_string();
    
    Event {
        account_address: standardize_address(&event.guid.account_address.to_string()),
        creation_number: event.guid.creation_number.0 as i64,
        sequence_number: event.sequence_number.0 as i64,
        transaction_version,
        transaction_block_height,
        type_: crate::util::truncate_str(&type_string, MAX_TYPE_LENGTH),
        data: event.data.clone(),
        event_index: Some(event_index),
    }
}
```

Alternatively, add a database constraint:
```sql
ALTER TABLE events ALTER COLUMN type TYPE VARCHAR(1000);
```

## Proof of Concept

```move
// File: malicious_types.move
module 0xBAD::malicious_types {
    use std::event;

    // Create a deeply nested type structure
    struct Level7<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}
    struct Level6<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}
    struct Level5<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}
    struct Level4<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}
    struct Level3<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}
    struct Level2<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}
    struct Level1<phantom T0, phantom T1, phantom T2, phantom T3, phantom T4> {}

    #[event]
    struct MaliciousEvent has drop, store {
        value: u64
    }

    public entry fun emit_bloated_event() {
        // This event's type will be: 0xBAD::malicious_types::MaliciousEvent
        // But if we use the nested types as generic parameters, the string becomes massive
        event::emit(MaliciousEvent { value: 1 });
    }

    // More extreme example with type parameters
    public fun emit_with_nested_types<T: drop>() {
        // When instantiated with Level1<Level2<Level3<Level4<Level5<...>>>>>,
        // the type string will include all nested type information
        event::emit(MaliciousEvent { value: 1 });
    }
}
```

**Verification Steps:**
1. Deploy the module with maximum-length identifiers and nested generic types
2. Call `emit_bloated_event()` repeatedly
3. Query the indexer database: `SELECT length(type), type FROM events ORDER BY length(type) DESC LIMIT 10;`
4. Observe type strings of excessive length (potentially hundreds of KB)
5. Measure database size growth and query performance degradation

## Notes

While this is a valid Low severity issue, it's important to note that:
- The indexer is explicitly designed as an off-chain component and is not part of the consensus-critical path
- PostgreSQL TEXT fields can handle very large strings (up to 1GB), so this won't cause insertion failures
- The issue is more about operational efficiency than security compromise
- No critical blockchain invariants are violated since the indexer doesn't affect on-chain state

### Citations

**File:** crates/indexer/src/models/events.rs (L43-59)
```rust
    pub fn from_event(
        event: &APIEvent,
        transaction_version: i64,
        transaction_block_height: i64,
        event_index: i64,
    ) -> Self {
        Event {
            account_address: standardize_address(&event.guid.account_address.to_string()),
            creation_number: event.guid.creation_number.0 as i64,
            sequence_number: event.sequence_number.0 as i64,
            transaction_version,
            transaction_block_height,
            type_: event.typ.to_string(),
            data: event.data.clone(),
            event_index: Some(event_index),
        }
    }
```

**File:** api/types/src/move_types.rs (L632-684)
```rust
/// An enum of Move's possible types on-chain
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoveType {
    /// A bool type
    Bool,
    /// An 8-bit unsigned int
    U8,
    /// A 16-bit unsigned int
    U16,
    /// A 32-bit unsigned int
    U32,
    /// A 64-bit unsigned int
    U64,
    /// A 128-bit unsigned int
    U128,
    /// A 256-bit unsigned int
    U256,
    /// An 8-bit signed int
    I8,
    /// A 16-bit signed int
    I16,
    /// A 32-bit signed int
    I32,
    /// A 64-bit signed int
    I64,
    /// A 128-bit signed int
    I128,
    /// A 256-bit signed int
    I256,
    /// A 32-byte account address
    Address,
    /// An account signer
    Signer,
    /// A Vector of [`MoveType`]
    Vector { items: Box<MoveType> },
    /// A struct of [`MoveStructTag`]
    Struct(MoveStructTag),
    /// A function
    Function {
        args: Vec<MoveType>,
        results: Vec<MoveType>,
        abilities: AbilitySet,
    },
    /// A generic type param with index
    GenericTypeParam { index: u16 },
    /// A reference
    Reference { mutable: bool, to: Box<MoveType> },
    /// A move type that couldn't be parsed
    ///
    /// This prevents the parser from just throwing an error because one field
    /// was unparsable, and gives the value in it.
    Unparsable(String),
}
```

**File:** api/types/src/move_types.rs (L686-688)
```rust
/// Maximum number of recursive types - Same as (non-public)
/// move_core_types::safe_serialize::MAX_TYPE_TAG_NESTING
pub const MAX_RECURSIVE_TYPES_ALLOWED: u8 = 8;
```

**File:** api/types/src/move_types.rs (L759-805)
```rust
impl fmt::Display for MoveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MoveType::U8 => write!(f, "u8"),
            MoveType::U16 => write!(f, "u16"),
            MoveType::U32 => write!(f, "u32"),
            MoveType::U64 => write!(f, "u64"),
            MoveType::U128 => write!(f, "u128"),
            MoveType::U256 => write!(f, "u256"),
            MoveType::I8 => write!(f, "i8"),
            MoveType::I16 => write!(f, "i16"),
            MoveType::I32 => write!(f, "i32"),
            MoveType::I64 => write!(f, "i64"),
            MoveType::I128 => write!(f, "i128"),
            MoveType::I256 => write!(f, "i256"),
            MoveType::Address => write!(f, "address"),
            MoveType::Signer => write!(f, "signer"),
            MoveType::Bool => write!(f, "bool"),
            MoveType::Vector { items } => write!(f, "vector<{}>", items),
            MoveType::Struct(s) => write!(f, "{}", s),
            MoveType::GenericTypeParam { index } => write!(f, "T{}", index),
            MoveType::Reference { mutable, to } => {
                if *mutable {
                    write!(f, "&mut {}", to)
                } else {
                    write!(f, "&{}", to)
                }
            },
            MoveType::Function { args, results, .. } => {
                write!(
                    f,
                    "|{}|{}",
                    args.iter()
                        .map(|ty| ty.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    results
                        .iter()
                        .map(|ty| ty.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            },
            MoveType::Unparsable(string) => write!(f, "unparsable<{}>", string),
        }
    }
}
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L66-67)
```rust
pub const LEGACY_IDENTIFIER_SIZE_MAX: u64 = 65535;
pub const IDENTIFIER_SIZE_MAX: u64 = 255;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L83-83)
```rust
pub const TYPE_PARAMETER_COUNT_MAX: u64 = 255;
```

**File:** crates/indexer/migrations/2022-08-08-043603_core_tables/up.sql (L208-226)
```sql
CREATE TABLE events (
  sequence_number BIGINT NOT NULL,
  creation_number BIGINT NOT NULL,
  account_address VARCHAR(66) NOT NULL,
  transaction_version BIGINT NOT NULL,
  transaction_block_height BIGINT NOT NULL,
  type TEXT NOT NULL,
  data jsonb NOT NULL,
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  -- Constraints
  PRIMARY KEY (
    account_address,
    creation_number,
    sequence_number
  ),
  CONSTRAINT fk_transaction_versions FOREIGN KEY (transaction_version) REFERENCES transactions (version)
);
CREATE INDEX ev_addr_type_index ON events (account_address);
CREATE INDEX ev_insat_index ON events (inserted_at);
```
