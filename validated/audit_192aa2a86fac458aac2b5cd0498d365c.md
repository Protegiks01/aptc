Based on my comprehensive analysis of the codebase, I can confirm this is a **valid HIGH severity vulnerability**. Here is the complete audit report:

# Audit Report

## Title
Panic in Resource Viewer When Annotating Closures With Runtime-Layout Vector Captures

## Summary
The `MoveValueAnnotator` in the resource viewer panics when attempting to annotate closures that capture vectors of structs with `Runtime` layouts. This occurs because line 911 calls `.unwrap()` on `type_tag()` for vector element types, which returns an error for `Runtime` and `RuntimeVariants` types. Since closures can be stored in global storage and viewed via the Aptos API, this creates an exploitable denial-of-service vector against API infrastructure.

## Finding Description
The vulnerability exists in the intersection of three code paths:

1. **Error-returning type_tag() function**: The `FatType::type_tag()` method explicitly returns `UNKNOWN_INVARIANT_VIOLATION_ERROR` for `Runtime` and `RuntimeVariants` types, as these represent internal VM representations without proper type metadata. [1](#0-0) 

2. **Unsafe unwrap() on vector annotation**: When annotating a `Vector` value, the code calls `ty.type_tag(limit).unwrap()` on the element type without error handling. If `ty` is `Runtime` or `RuntimeVariants`, this unwrap causes a panic. [2](#0-1) 

3. **Runtime layouts from closure captures**: The `annotate_closure` function converts captured variable layouts to `FatType` using `from_runtime_layout`, which produces `FatType::Runtime` for structs with `MoveStructLayout::Runtime` layouts. [3](#0-2) [4](#0-3) 

4. **Captured layouts always use Runtime**: When constructing layouts for persistent closures, `construct_captured_layouts` calls `type_to_type_layout_with_delayed_fields` which uses non-annotated mode, resulting in `MoveStructLayout::Runtime` for all struct types. [5](#0-4) [6](#0-5) [7](#0-6) 

**Attack Path:**

1. An attacker deploys a Move module that creates a closure with `store` ability (using `#[persistent]` attribute)
2. The closure captures a `vector<SomeStruct>` where `SomeStruct` is any struct type
3. The closure is stored in global storage using `move_to` [8](#0-7) 
4. When the API attempts to view this resource via `AptosValueAnnotator::view_resource()`, it triggers the annotation path [9](#0-8) [10](#0-9) 
5. The `from_runtime_layout` call creates `FatType::Vector(Box::new(FatType::Runtime(...)))`
6. When annotating the vector, line 911 calls `Runtime.type_tag().unwrap()` which panics

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program under "API Crashes (High)":

- **API Crashes**: Any API call attempting to view a resource containing such a closure will panic, crashing the API server process
- **Validator Node Disruption**: If validators run APIs or indexers that attempt to view these resources, they experience service disruption
- **Availability Impact**: The panic is triggered by off-chain viewing code, but it affects the ability of nodes to serve state queries consistently

The vulnerability does not directly affect consensus or state commitment (which use different code paths), but it breaks the availability guarantees of the API infrastructure. An attacker can force any node running the Aptos API to crash by simply querying a maliciously crafted resource.

## Likelihood Explanation
**Likelihood: High**

The attack is straightforward to execute:
- Closures with `store` ability are a supported Move feature requiring only the `#[persistent]` attribute
- No special permissions or validator access required
- Attack cost is minimal (just gas for module deployment and resource storage)
- The vulnerability is deterministic - any view operation on the malicious resource triggers the panic
- The captured vector contains structs with Runtime layouts, which occurs naturally when the VM serializes closure captures without full type decoration (all persistent closures use non-annotated layouts by design)

## Recommendation
Replace the `.unwrap()` call with proper error handling. The fix should handle `Runtime` and `RuntimeVariants` types gracefully:

```rust
_ => AnnotatedMoveValue::Vector(
    ty.type_tag(limit)?,  // Use ? operator instead of unwrap()
    a.iter()
        .map(|v| self.annotate_value(v, ty.as_ref(), limit))
        .collect::<anyhow::Result<_>>()?,
),
```

Alternatively, if Runtime types should not be viewable via the API, add a check in `annotate_closure` to reject closures with Runtime layouts in captured values before attempting annotation.

## Proof of Concept
A Move module demonstrating the vulnerability would need to:

1. Define a struct with `store` ability
2. Create a closure with `#[persistent]` attribute that captures `vector<MyStruct>`
3. Store this closure in a resource with `key` ability
4. Publish the resource to global storage
5. Attempt to view the resource via the REST API

The API call to view this resource will cause the server to panic at line 911 when attempting to get the type tag for the Runtime-layout struct within the captured vector.

## Notes
- This vulnerability specifically affects the resource viewing code path used by the REST API, not the consensus or execution paths
- The issue arises from the architectural decision to use non-annotated (Runtime) layouts for closure captured values for efficiency, combined with the assumption that all viewable types can produce valid type tags
- Other usages of `type_tag()` in the codebase properly use the `?` operator for error handling (lines 977-978), making this unwrap at line 911 an isolated oversight

### Citations

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L458-463)
```rust
            Reference(_) | MutableReference(_) | TyParam(_) | RuntimeVariants(_) | Runtime(..) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(format!("cannot derive type tag for {:?}", self)),
                )
            },
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L491-493)
```rust
            Struct(MoveStructLayout::Runtime(tys)) => {
                FatType::Runtime(Self::from_layout_slice(tys, limit)?)
            },
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L863-869)
```rust
        let captured = captured
            .iter()
            .map(|(layout, value)| {
                let fat_type = FatType::from_runtime_layout(layout, limit)
                    .map_err(|e| anyhow!("failed to annotate captured value: {}", e))?;
                self.annotate_value(value, &fat_type, limit)
            })
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L910-915)
```rust
                _ => AnnotatedMoveValue::Vector(
                    ty.type_tag(limit).unwrap(),
                    a.iter()
                        .map(|v| self.annotate_value(v, ty.as_ref(), limit))
                        .collect::<anyhow::Result<_>>()?,
                ),
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L345-354)
```rust
        mask.extract(fun.param_tys(), true)
            .into_iter()
            .map(|ty| {
                let layout = if fun.ty_args.is_empty() {
                    layout_converter.type_to_type_layout_with_delayed_fields(
                        gas_meter,
                        traversal_context,
                        ty,
                        true,
                    )?
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L512-514)
```rust
                            } else {
                                MoveStructLayout::new(field_layouts)
                            },
```

**File:** third_party/move/move-core/types/src/value.rs (L491-493)
```rust
    pub fn new(types: Vec<MoveTypeLayout>) -> Self {
        Self::Runtime(types)
    }
```

**File:** third_party/move/move-compiler-v2/transactional-tests/tests/no-v1-comparison/closures/funs_as_storage_key.move (L95-111)
```text
    struct VecWrapper<T> has key {
        fvs: vector<T>
    }

    #[persistent]
    fun test(ref: &u64, _mut_ref: &mut u8): &u64 {
        ref
    }

    fun initialize(acc: &signer) {
        move_to<VecWrapper<|&u64, &mut u8|&u64 has copy+store+drop>>(acc, VecWrapper { fvs: vector[0x42::mod5::test]});
    }

    fun check_exists(_acc: &signer) {
        let exists = exists<VecWrapper<|&u64, &mut u8|&u64 has copy+store+drop>>(@0x42);
        assert!(exists, 404);
    }
```

**File:** api/types/src/convert.rs (L89-94)
```rust
        data.map(|(typ, bytes)| self.inner.view_resource(&typ, bytes)?.try_into())
            .collect()
    }

    pub fn try_into_resource(&self, tag: &StructTag, bytes: &'_ [u8]) -> Result<MoveResource> {
        self.inner.view_resource(tag, bytes)?.try_into()
```

**File:** aptos-move/aptos-resource-viewer/src/lib.rs (L68-74)
```rust
    pub fn view_resource(
        &self,
        tag: &StructTag,
        blob: &[u8],
    ) -> anyhow::Result<AnnotatedMoveStruct> {
        self.0.view_resource(tag, blob)
    }
```
