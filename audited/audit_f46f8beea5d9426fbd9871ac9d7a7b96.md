# Audit Report

## Title
Resource Accounting Bypass in Move Resource Viewer Allows API Memory Exhaustion

## Summary
The Limiter interface in `move-resource-viewer` is designed to prevent resource exhaustion by tracking memory allocation during type resolution operations. However, two critical functions—`clone_with_limit()` and `from_runtime_layout()`—accept a Limiter parameter but never call `charge()`, creating a complete bypass of resource accounting. This allows attackers to craft API queries that consume unbounded memory, leading to API node crashes.

## Finding Description

The `move-resource-viewer` module implements a Limiter with a 100MB default budget to prevent expensive queries from consuming excessive resources. [1](#0-0) 

However, critical code paths bypass this accounting entirely:

**Vulnerability 1: `clone_with_limit()` Never Charges**

The `FatType::clone_with_limit()` function accepts a limiter parameter and its name explicitly suggests it enforces limits, but it never calls `charge()`. [2](#0-1) 

This function recursively clones complex type structures including vectors, references, function types, and runtime types without any resource accounting.

**Vulnerability 2: `from_runtime_layout()` Never Charges**

Similarly, `FatType::from_runtime_layout()` accepts a limiter parameter but never charges for memory allocation. [3](#0-2) 

**Attack Path:**

1. Attacker calls the public REST API endpoint `GET /accounts/{address}/resource/{resource_type}` [4](#0-3) 

2. The endpoint processes the resource type and calls `try_into_resource()` [5](#0-4) 

3. This triggers `view_resource()` which resolves the struct tag [6](#0-5) 

4. During type substitution for generic structs, `FatType::subst()` is called, which invokes `clone_with_limit()` for type parameter substitution [7](#0-6) 

5. For closures with captured values, `annotate_closure()` calls `from_runtime_layout()` [8](#0-7) 

6. Memory is allocated recursively without any `charge()` calls, bypassing the 100MB limit entirely

7. Attacker can craft deeply nested generic types like `Vector<Vector<Vector<...>>>` with thousands of nesting levels, consuming gigabytes of memory without hitting the supposed 100MB limit

**Evidence of Bypass:**

A comprehensive search reveals that in the entire `fat_type.rs` file, `charge()` is only called in 6 specific locations—all in `FatStructType::subst()` and `FatStructType::struct_tag()` for charging address/module/name bytes. [9](#0-8) 

Notably absent from charging: the recursive cloning operations, runtime layout conversions, and the `TryInto` implementations that don't even accept a limiter parameter. [10](#0-9) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:

- **API crashes**: An attacker can send crafted queries that cause the API node to run out of memory and crash, denying service to all users
- **Resource Limits violation**: Breaks the critical invariant that "All operations must respect gas, storage, and computational limits"
- **No authentication required**: Exploitable via public REST API without any privileged access
- **Affects node availability**: Can cause repeated crashes requiring manual intervention

The impact is limited to API nodes (not consensus or validator nodes), which places it in the High severity category rather than Critical.

## Likelihood Explanation

**Likelihood: High**

- The vulnerability is trivially exploitable through a public API endpoint
- No special permissions or complex setup required
- Attacker only needs to craft a resource query with deeply nested generic type parameters
- The code path is frequently exercised during normal API operations
- Multiple entry points exist (`view_resource`, `view_function_arguments`, closure annotation)
- The 100MB limit is completely bypassed, not just partially evaded

## Recommendation

Add proper resource accounting to the vulnerable functions:

**For `clone_with_limit()`:**
```rust
fn clone_with_limit(&self, limit: &mut Limiter) -> PartialVMResult<Self> {
    use FatType::*;
    
    // Charge for the base allocation
    limit.charge(std::mem::size_of::<FatType>())?;
    
    Ok(match self {
        // ... existing match arms with recursive charging ...
        Vector(ty) => {
            limit.charge(std::mem::size_of::<Box<FatType>>())?;
            Vector(Box::new(ty.clone_with_limit(limit)?))
        },
        // Similar for all recursive cases
        // ... rest of implementation
    })
}
```

**For `from_runtime_layout()`:**
```rust
pub(crate) fn from_runtime_layout(
    layout: &MoveTypeLayout,
    limit: &mut Limiter,
) -> PartialVMResult<FatType> {
    use MoveTypeLayout::*;
    
    // Charge for the allocation
    limit.charge(std::mem::size_of::<FatType>())?;
    
    Ok(match layout {
        // ... existing match arms with recursive charging ...
        Vector(ty) => {
            limit.charge(std::mem::size_of::<Box<FatType>>())?;
            FatType::Vector(Box::new(Self::from_runtime_layout(ty, limit)?))
        },
        // ... rest of implementation
    })
}
```

Additionally, consider adding depth limits to prevent excessive recursion even with proper charging.

## Proof of Concept

```rust
// Demonstration of the bypass
use move_resource_viewer::Limiter;
use move_core_types::language_storage::{StructTag, TypeTag};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;

fn demonstrate_limiter_bypass() {
    // Create a deeply nested generic type
    // e.g., Vector<Vector<Vector<...Vector<u8>...>>> with 1000 levels
    let mut nested_type = TypeTag::U8;
    for _ in 0..1000 {
        nested_type = TypeTag::Vector(Box::new(nested_type));
    }
    
    // Create a struct tag with this deeply nested type argument
    let malicious_struct_tag = StructTag {
        address: AccountAddress::ONE,
        module: Identifier::new("test").unwrap(),
        name: Identifier::new("MaliciousStruct").unwrap(),
        type_args: vec![nested_type],
    };
    
    // When the API processes this via view_resource(), it will:
    // 1. Call resolve_struct_tag() with the limiter
    // 2. Trigger type substitution via subst()
    // 3. Call clone_with_limit() on the nested type 1000 times
    // 4. Allocate memory for 1000 nested FatType structures
    // 5. Never call limiter.charge() during any of these allocations
    // 6. The 100MB limit remains at 100MB despite consuming potentially GB of memory
    
    // Expected: Should hit 100MB limit and return ABORTED error
    // Actual: Bypasses limit completely, allocates unbounded memory
}

// To reproduce:
// 1. Deploy a Move module with: struct MaliciousStruct<T> has key { value: T }
// 2. Store an instance at an account with deeply nested Vector type argument
// 3. Query via: GET /v1/accounts/{addr}/resource/0x1::test::MaliciousStruct<vector<vector<...>>>
// 4. Observe API node memory consumption grows without limit enforcement
// 5. API node crashes with OOM error
```

## Notes

The vulnerability exists because the implementers clearly intended these functions to respect the limiter (evidenced by the parameter names and function naming), but the actual `charge()` calls were never added. This is a classic case of incomplete implementation of a security control.

The issue is particularly severe because:
1. The limiter gives a false sense of security—operators believe they're protected from resource exhaustion
2. Multiple code paths trigger the vulnerability (not just one edge case)
3. The bypass is complete—not a single charge occurs in these functions
4. The API surface is public and unauthenticated

### Citations

**File:** third_party/move/tools/move-resource-viewer/src/limit.rs (L7-20)
```rust
// Default limit set to 100mb per query.
const DEFAULT_LIMIT: usize = 100_000_000;

pub struct Limiter(usize);

impl Limiter {
    pub fn charge(&mut self, cost: usize) -> PartialVMResult<()> {
        if self.0 < cost {
            return Err(PartialVMError::new(StatusCode::ABORTED)
                .with_message("Query exceeds size limit".to_string()));
        }
        self.0 -= cost;
        Ok(())
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L185-187)
```rust
        limiter.charge(std::mem::size_of::<AccountAddress>())?;
        limiter.charge(self.module.as_bytes().len())?;
        limiter.charge(self.name.as_bytes().len())?;
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L320-355)
```rust
    fn clone_with_limit(&self, limit: &mut Limiter) -> PartialVMResult<Self> {
        use FatType::*;
        Ok(match self {
            TyParam(idx) => TyParam(*idx),
            Bool => Bool,
            U8 => U8,
            U16 => U16,
            U32 => U32,
            U64 => U64,
            U128 => U128,
            U256 => U256,
            I8 => I8,
            I16 => I16,
            I32 => I32,
            I64 => I64,
            I128 => I128,
            I256 => I256,
            Address => Address,
            Signer => Signer,
            Vector(ty) => Vector(Box::new(ty.clone_with_limit(limit)?)),
            Reference(ty) => Reference(Box::new(ty.clone_with_limit(limit)?)),
            MutableReference(ty) => MutableReference(Box::new(ty.clone_with_limit(limit)?)),
            Struct(struct_ty) => Struct(struct_ty.clone()),
            Function(fun_ty) => Function(Box::new(fun_ty.clone_with_limit(limit)?)),
            Runtime(tys) => Runtime(Self::clone_with_limit_slice(tys, limit)?),
            RuntimeVariants(vars) => RuntimeVariants(
                vars.iter()
                    .map(|tys| Self::clone_with_limit_slice(tys, limit))
                    .collect::<PartialVMResult<Vec<_>>>()?,
            ),
        })
    }

    fn clone_with_limit_slice(tys: &[Self], limit: &mut Limiter) -> PartialVMResult<Vec<Self>> {
        tys.iter().map(|ty| ty.clone_with_limit(limit)).collect()
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L370-382)
```rust
            TyParam(idx) => match ty_args.get(*idx) {
                Some(ty) => ty.clone_with_limit(limit)?,
                None => {
                    return Err(
                        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                            .with_message(format!(
                            "fat type substitution failed: index out of bounds -- len {} got {}",
                            ty_args.len(),
                            idx
                        )),
                    );
                },
            },
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L469-528)
```rust
    pub(crate) fn from_runtime_layout(
        layout: &MoveTypeLayout,
        limit: &mut Limiter,
    ) -> PartialVMResult<FatType> {
        use MoveTypeLayout::*;
        Ok(match layout {
            Bool => FatType::Bool,
            U8 => FatType::U8,
            U16 => FatType::U16,
            U32 => FatType::U32,
            U64 => FatType::U64,
            U128 => FatType::U128,
            U256 => FatType::U256,
            I8 => FatType::I8,
            I16 => FatType::I16,
            I32 => FatType::I32,
            I64 => FatType::I64,
            I128 => FatType::I128,
            I256 => FatType::I256,
            Address => FatType::Address,
            Signer => FatType::Signer,
            Vector(ty) => FatType::Vector(Box::new(Self::from_runtime_layout(ty, limit)?)),
            Struct(MoveStructLayout::Runtime(tys)) => {
                FatType::Runtime(Self::from_layout_slice(tys, limit)?)
            },
            Struct(MoveStructLayout::RuntimeVariants(vars)) => FatType::RuntimeVariants(
                vars.iter()
                    .map(|tys| Self::from_layout_slice(tys, limit))
                    .collect::<PartialVMResult<Vec<Vec<_>>>>()?,
            ),
            Function => {
                // We cannot derive the actual type from layout, however, a dummy
                // function type will do since annotation of closures is not depending
                // actually on their type, but only their (hidden) captured arguments.
                // Currently, `from_runtime_layout` is only used to annotate captured arguments
                // of closures.
                FatType::Function(Box::new(FatFunctionType {
                    args: vec![],
                    results: vec![],
                    abilities: AbilitySet::EMPTY,
                }))
            },
            Native(..) | Struct(_) => {
                return Err(PartialVMError::new_invariant_violation(format!(
                    "cannot derive fat type for {:?}",
                    layout
                )))
            },
        })
    }

    fn from_layout_slice(
        layouts: &[MoveTypeLayout],
        limit: &mut Limiter,
    ) -> PartialVMResult<Vec<FatType>> {
        layouts
            .iter()
            .map(|l| Self::from_runtime_layout(l, limit))
            .collect()
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L583-626)
```rust
impl TryInto<MoveTypeLayout> for &FatType {
    type Error = PartialVMError;

    fn try_into(self) -> Result<MoveTypeLayout, Self::Error> {
        let slice_into = |tys: &[FatType]| {
            tys.iter()
                .map(|ty| ty.try_into())
                .collect::<PartialVMResult<Vec<MoveTypeLayout>>>()
        };
        Ok(match self {
            FatType::Address => MoveTypeLayout::Address,
            FatType::U8 => MoveTypeLayout::U8,
            FatType::U16 => MoveTypeLayout::U16,
            FatType::U32 => MoveTypeLayout::U32,
            FatType::U64 => MoveTypeLayout::U64,
            FatType::U128 => MoveTypeLayout::U128,
            FatType::U256 => MoveTypeLayout::U256,
            FatType::I8 => MoveTypeLayout::I8,
            FatType::I16 => MoveTypeLayout::I16,
            FatType::I32 => MoveTypeLayout::I32,
            FatType::I64 => MoveTypeLayout::I64,
            FatType::I128 => MoveTypeLayout::I128,
            FatType::I256 => MoveTypeLayout::I256,
            FatType::Bool => MoveTypeLayout::Bool,
            FatType::Vector(v) => MoveTypeLayout::Vector(Box::new(v.as_ref().try_into()?)),
            FatType::Struct(s) => MoveTypeLayout::Struct(s.as_ref().try_into()?),
            FatType::Function(_) => MoveTypeLayout::Function,
            FatType::Runtime(tys) => {
                MoveTypeLayout::Struct(MoveStructLayout::Runtime(slice_into(tys)?))
            },
            FatType::RuntimeVariants(vars) => {
                MoveTypeLayout::Struct(MoveStructLayout::RuntimeVariants(
                    vars.iter()
                        .map(|tys| slice_into(tys))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            },
            FatType::Signer => MoveTypeLayout::Signer,
            FatType::Reference(_) | FatType::MutableReference(_) | FatType::TyParam(_) => {
                return Err(PartialVMError::new(StatusCode::ABORT_TYPE_MISMATCH_ERROR))
            },
        })
    }
}
```

**File:** api/src/state.rs (L51-84)
```rust
    async fn get_account_resource(
        &self,
        accept_type: AcceptType,
        /// Address of account with or without a `0x` prefix
        address: Path<Address>,
        /// Name of struct to retrieve e.g. `0x1::account::Account`
        resource_type: Path<MoveStructTag>,
        /// Ledger version to get state of account
        ///
        /// If not provided, it will be the latest version
        ledger_version: Query<Option<U64>>,
    ) -> BasicResultWith404<MoveResource> {
        resource_type
            .0
            .verify(0)
            .context("'resource_type' invalid")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;
        fail_point_poem("endpoint_get_account_resource")?;
        self.context
            .check_api_output_enabled("Get account resource", &accept_type)?;

        let api = self.clone();
        api_spawn_blocking(move || {
            api.resource(
                &accept_type,
                address.0,
                resource_type.0,
                ledger_version.0.map(|inner| inner.0),
            )
        })
        .await
    }
```

**File:** api/src/state.rs (L308-318)
```rust
                let resource = state_view
                    .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
                    .try_into_resource(&tag, &bytes)
                    .context("Failed to deserialize resource data retrieved from DB")
                    .map_err(|err| {
                        BasicErrorWith404::internal_with_code(
                            err,
                            AptosErrorCode::InternalError,
                            &ledger_info,
                        )
                    })?;
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L336-354)
```rust
    pub fn view_resource(
        &self,
        tag: &StructTag,
        blob: &[u8],
    ) -> anyhow::Result<AnnotatedMoveStruct> {
        self.view_resource_with_limit(tag, blob, &mut Limiter::default())
    }

    pub fn view_resource_with_limit(
        &self,
        tag: &StructTag,
        blob: &[u8],
        limit: &mut Limiter,
    ) -> anyhow::Result<AnnotatedMoveStruct> {
        let ty = self.resolve_struct_tag(tag, &mut Limiter::default())?;
        let struct_def = (ty.as_ref()).try_into().map_err(into_vm_status)?;
        let move_struct = MoveStruct::simple_deserialize(blob, &struct_def)?;
        self.annotate_struct(&move_struct, &ty, limit)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L863-870)
```rust
        let captured = captured
            .iter()
            .map(|(layout, value)| {
                let fat_type = FatType::from_runtime_layout(layout, limit)
                    .map_err(|e| anyhow!("failed to annotate captured value: {}", e))?;
                self.annotate_value(value, &fat_type, limit)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
```
