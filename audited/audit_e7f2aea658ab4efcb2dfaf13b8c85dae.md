# Audit Report

## Title
Indexer Crash via Unhandled Deserialization Errors in Transaction Processing

## Summary
The indexer's coin processor and default processor use `.unwrap()` when calling functions that return `Result` types during JSON deserialization of write resources. If deserialization fails due to data format mismatches, the indexer will panic and crash, causing service disruption.

## Finding Description

The vulnerability exists in two locations where the indexer processes blockchain transactions:

1. **Coin Processor** - [1](#0-0) 

2. **Default Processor** - [2](#0-1) 

Both processors call methods that can return errors during JSON deserialization but use `.unwrap()` instead of proper error handling. The call chain involves:

**AccountTransaction Path (Coin Processor):**
- [3](#0-2) 
- [4](#0-3) 

**Object Path (Default Processor):**
- [5](#0-4) 

Both paths eventually call `ObjectWithMetadata::from_write_resource`, which performs JSON deserialization:
- [6](#0-5) 

The deserialization uses `V2TokenResource::from_resource`, which calls `serde_json::from_value` and can fail:
- [7](#0-6) 

**Failure Scenarios:**

The deserialization can fail when:
1. Custom deserializers like `deserialize_from_string` encounter invalid formats (e.g., [8](#0-7) )
2. Field type mismatches between API output and indexer expectations
3. Version mismatches between on-chain contracts and indexer code
4. Edge cases in API JSON generation

## Impact Explanation

**Severity: HIGH** - Validator node slowdowns / API crashes

Per Aptos bug bounty criteria, this qualifies as HIGH severity because:
- **API crashes**: The indexer is a critical service that provides queryable blockchain data
- **Service disruption**: When the indexer crashes, it stops processing new transactions until manually restarted
- **Cascading failures**: Multiple indexer instances could crash on the same problematic transaction

However, this does NOT qualify as CRITICAL because:
- It does not affect consensus or validator operation
- It does not cause loss of funds
- The blockchain itself continues operating
- Recovery is possible by restarting the indexer

## Likelihood Explanation

**Likelihood: MEDIUM-LOW**

The likelihood is tempered by several factors:

**Reducing factors:**
- Move VM enforces strict type safety during execution
- System modules (0x1::object) cannot be modified by users
- The API layer uses actual on-chain type layouts for serialization
- Most transactions process successfully in production

**Increasing factors:**
- The indexer code is tightly coupled to specific struct shapes with custom deserializers
- Contract upgrades or framework changes could introduce mismatches
- Edge cases in number formatting or special values could trigger failures
- No defensive error handling means ANY deserialization failure causes a crash

The vulnerability is most likely to manifest during:
1. Framework upgrades that change struct definitions
2. Processing of edge case data values
3. Bugs in the API serialization layer
4. Version mismatches between components

## Recommendation

Replace all `.unwrap()` calls with proper error handling that logs the error and continues processing or returns a proper error result:

**For coin_processor.rs line 314:**
```rust
// Replace:
account_transactions.extend(AccountTransaction::from_transaction(txn).unwrap());

// With:
match AccountTransaction::from_transaction(txn) {
    Ok(txns) => account_transactions.extend(txns),
    Err(e) => {
        aptos_logger::error!(
            transaction_version = txn.version(),
            error = ?e,
            "Failed to parse AccountTransaction from transaction"
        );
        // Continue processing other transactions
    }
}
```

**For default_processor.rs line 550:**
```rust
// Replace:
if let Some((object, current_object)) =
    &Object::from_write_resource(inner, txn_version, index).unwrap()

// With:
match Object::from_write_resource(inner, txn_version, index) {
    Ok(Some((object, current_object))) => {
        all_objects.push(object.clone());
        all_current_objects.insert(object.object_address.clone(), current_object.clone());
    },
    Ok(None) => {
        // Not an object resource, skip
    },
    Err(e) => {
        aptos_logger::error!(
            transaction_version = txn_version,
            write_set_change_index = index,
            error = ?e,
            "Failed to parse Object from write resource"
        );
        // Continue processing other write set changes
    }
}
```

Additionally, consider adding integration tests that verify graceful handling of malformed data.

## Proof of Concept

While I cannot provide a working exploit (as this requires triggering specific conditions in the API layer or Move VM that produce malformed JSON), here's a conceptual reproduction:

```rust
// Conceptual test demonstrating the panic condition
#[test]
#[should_panic]
fn test_indexer_panics_on_deserialization_error() {
    // Create a WriteResource with ObjectCore type but malformed data
    let write_resource = WriteResource {
        address: Address::from_hex_literal("0x1").unwrap(),
        state_key_hash: "test_hash".to_string(),
        data: MoveResource {
            typ: MoveStructTag::from_str("0x1::object::ObjectCore").unwrap(),
            data: MoveStructValue(BTreeMap::from([
                // Invalid: guid_creation_num should be string, but provide object
                (
                    IdentifierWrapper::from_str("guid_creation_num").unwrap(),
                    serde_json::json!({"invalid": "object"}),
                ),
                (
                    IdentifierWrapper::from_str("owner").unwrap(),
                    serde_json::json!("0x1"),
                ),
                (
                    IdentifierWrapper::from_str("allow_ungated_transfer").unwrap(),
                    serde_json::json!(true),
                ),
            ])),
        },
    };
    
    // This will panic due to unwrap() on deserialization error
    let result = ObjectWithMetadata::from_write_resource(&write_resource, 1);
    // If we reach here with an Err, the unwrap() in production code would panic
    assert!(result.is_err());
}
```

**Notes:**

This vulnerability represents a **defensive programming failure** rather than a directly exploitable attack vector. The core issue is that the indexer assumes all data from the API layer is well-formed and uses `.unwrap()` instead of graceful error handling. While triggering this condition through malicious input is difficult due to Move VM type safety, the lack of error handling makes the system fragile and prone to crashes from unexpected edge cases, version mismatches, or bugs in other components.

### Citations

**File:** crates/indexer/src/processors/coin_processor.rs (L314-314)
```rust
            account_transactions.extend(AccountTransaction::from_transaction(txn).unwrap());
```

**File:** crates/indexer/src/processors/default_processor.rs (L550-550)
```rust
                            &Object::from_write_resource(inner, txn_version, index).unwrap()
```

**File:** crates/indexer/src/models/coin_models/account_transactions.rs (L38-86)
```rust
    pub fn from_transaction(
        transaction: &Transaction,
    ) -> anyhow::Result<HashMap<AccountTransactionPK, Self>> {
        let (events, wscs, signatures, txn_version) = match transaction {
            Transaction::UserTransaction(inner) => (
                &inner.events,
                &inner.info.changes,
                UserTransaction::get_signatures(inner, inner.info.version.0 as i64, 0),
                inner.info.version.0 as i64,
            ),
            Transaction::GenesisTransaction(inner) => (
                &inner.events,
                &inner.info.changes,
                vec![],
                inner.info.version.0 as i64,
            ),
            Transaction::BlockMetadataTransaction(inner) => (
                &inner.events,
                &inner.info.changes,
                vec![],
                inner.info.version.0 as i64,
            ),
            _ => {
                return Ok(HashMap::new());
            },
        };
        let mut account_transactions = HashMap::new();
        for sig in &signatures {
            account_transactions.insert((sig.signer.clone(), txn_version), Self {
                transaction_version: txn_version,
                account_address: sig.signer.clone(),
            });
        }
        for event in events {
            account_transactions.extend(Self::from_event(event, txn_version));
        }
        for wsc in wscs {
            match wsc {
                WriteSetChange::DeleteResource(res) => {
                    account_transactions.extend(Self::from_delete_resource(res, txn_version)?);
                },
                WriteSetChange::WriteResource(res) => {
                    account_transactions.extend(Self::from_write_resource(res, txn_version)?);
                },
                _ => {},
            }
        }
        Ok(account_transactions)
    }
```

**File:** crates/indexer/src/models/coin_models/account_transactions.rs (L100-118)
```rust
    fn from_write_resource(
        write_resource: &WriteResource,
        txn_version: i64,
    ) -> anyhow::Result<HashMap<AccountTransactionPK, Self>> {
        let mut result = HashMap::new();
        let account_address = standardize_address(&write_resource.address.to_string());
        result.insert((account_address.clone(), txn_version), Self {
            transaction_version: txn_version,
            account_address,
        });
        if let Some(inner) = &ObjectWithMetadata::from_write_resource(write_resource, txn_version)?
        {
            result.insert((inner.object_core.get_owner_address(), txn_version), Self {
                transaction_version: txn_version,
                account_address: inner.object_core.get_owner_address(),
            });
        }
        Ok(result)
    }
```

**File:** crates/indexer/src/models/v2_objects.rs (L69-102)
```rust
    pub fn from_write_resource(
        write_resource: &WriteResource,
        txn_version: i64,
        write_set_change_index: i64,
    ) -> anyhow::Result<Option<(Self, CurrentObject)>> {
        if let Some(inner) = ObjectWithMetadata::from_write_resource(write_resource, txn_version)? {
            let resource = MoveResource::from_write_resource(
                write_resource,
                0, // Placeholder, this isn't used anyway
                txn_version,
                0, // Placeholder, this isn't used anyway
            );
            let object_core = &inner.object_core;
            Ok(Some((
                Self {
                    transaction_version: txn_version,
                    write_set_change_index,
                    object_address: resource.address.clone(),
                    owner_address: object_core.get_owner_address(),
                    state_key_hash: resource.state_key_hash.clone(),
                    guid_creation_num: object_core.guid_creation_num.clone(),
                    allow_ungated_transfer: object_core.allow_ungated_transfer,
                    is_deleted: false,
                },
                CurrentObject {
                    object_address: resource.address,
                    owner_address: object_core.get_owner_address(),
                    state_key_hash: resource.state_key_hash,
                    allow_ungated_transfer: object_core.allow_ungated_transfer,
                    last_guid_creation_num: object_core.guid_creation_num.clone(),
                    last_transaction_version: txn_version,
                    is_deleted: false,
                },
            )))
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L68-74)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObjectCore {
    pub allow_ungated_transfer: bool,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub guid_creation_num: BigDecimal,
    owner: String,
}
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L89-114)
```rust
    pub fn from_write_resource(
        write_resource: &WriteResource,
        txn_version: i64,
    ) -> anyhow::Result<Option<Self>> {
        let type_str = format!(
            "{}::{}::{}",
            write_resource.data.typ.address,
            write_resource.data.typ.module,
            write_resource.data.typ.name
        );
        if !V2TokenResource::is_resource_supported(type_str.as_str()) {
            return Ok(None);
        }
        if let V2TokenResource::ObjectCore(inner) = V2TokenResource::from_resource(
            &type_str,
            &serde_json::to_value(&write_resource.data.data).unwrap(),
            txn_version,
        )? {
            Ok(Some(Self {
                object_core: inner,
                state_key_hash: standardize_address(write_resource.state_key_hash.as_str()),
            }))
        } else {
            Ok(None)
        }
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L466-503)
```rust
    pub fn from_resource(
        data_type: &str,
        data: &serde_json::Value,
        txn_version: i64,
    ) -> Result<Self> {
        match data_type {
            "0x1::object::ObjectCore" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::ObjectCore(inner)))
            },
            "0x4::collection::Collection" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::Collection(inner)))
            },
            "0x4::collection::FixedSupply" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::FixedSupply(inner)))
            },
            "0x4::collection::UnlimitedSupply" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::UnlimitedSupply(inner)))
            },
            "0x4::aptos_token::AptosCollection" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::AptosCollection(inner)))
            },
            "0x4::token::Token" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::TokenV2(inner)))
            },
            "0x4::property_map::PropertyMap" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::PropertyMap(inner)))
            },
            _ => Ok(None),
        }
        .context(format!(
            "version {} failed! failed to parse type {}, data {:?}",
            txn_version, data_type, data
        ))?
        .context(format!(
            "Resource unsupported! Call is_resource_supported first. version {} type {}",
            txn_version, data_type
        ))
    }
```
