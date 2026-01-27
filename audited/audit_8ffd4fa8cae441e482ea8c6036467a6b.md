# Audit Report

## Title
Type Node Count Bypass in Function Type Creation via Uncounted Reference Wrappers

## Summary
The `TypeBuilder::create_ty_impl()` function undercounts type nodes when creating Function types containing Reference/MutableReference parameters. Reference wrapper nodes are created without incrementing the node counter, allowing attackers to bypass the `max_ty_size` limit by creating types with approximately 2X the intended node count.

## Finding Description

In `TypeBuilder::create_ty_impl()`, when processing Function types (lines 1493-1523), Reference and MutableReference nodes are created without proper node counting: [1](#0-0) 

The Reference and MutableReference wrapper nodes are constructed directly (lines 1505-1510) without calling `create_ty_impl()` on them, meaning they bypass the count increment that occurs at line 1447: [2](#0-1) 

The node counter is checked against `max_ty_size` to prevent resource exhaustion: [3](#0-2) 

With `max_ty_size = 128`: [4](#0-3) 

An attacker can craft a Function type with 127 Reference parameters:
```
Function { args: [Reference(U64), Reference(U64), ..., Reference(U64)] }  // 127 times
```

This creates:
- 1 Function node (counted)
- 127 Reference nodes (NOT counted) 
- 127 U64 nodes (counted)
- **Total actual nodes: 255**
- **Total counted: 128**

The type passes all checks during creation but has double the intended node count.

**Mitigation Factor**: Gas charging DOES account for all nodes correctly via `num_nodes()`: [5](#0-4) 

The `num_nodes()` implementation correctly counts all nodes including References: [6](#0-5) 

## Impact Explanation

**Severity Assessment: LOW**

While this is a node counting bypass, the security impact is limited:

1. **Gas is charged correctly**: The `num_nodes()` function used for gas accounting properly counts all nodes via preorder traversal, so users are charged appropriate gas fees.

2. **Limited DoS potential**: Creating 255 nodes instead of 128 represents only a 2X resource amplification, insufficient for effective denial-of-service against validators.

3. **No consensus divergence detected**: All validators would process the type identically since `create_ty_impl()` is deterministic.

4. **Memory impact minimal**: The additional 127 Reference nodes are not significant enough to cause memory exhaustion on validator nodes.

The main issue is that the `max_ty_size` limit is meant to bound resource usage during type creation, but this bypass allows temporary exceedance during construction (though gas accounting remains correct).

## Likelihood Explanation

**Likelihood: MEDIUM**

Attackers can easily craft malicious TypeTags in transaction payloads with nested Functions containing Reference parameters. The MAX_TYPE_TAG_NESTING limit of 8 restricts nesting depth but doesn't prevent wide Function signatures with many Reference parameters. [7](#0-6) 

However, exploitation provides minimal benefit since gas charging correctly accounts for actual node counts.

## Recommendation

Increment the node counter for Reference/MutableReference wrapper nodes during Function type creation:

```rust
FunctionParamOrReturnTag::Reference(t) => {
    *count += 1;  // Count the Reference wrapper
    Reference(Box::new(
        self.create_ty_impl(t, resolver, count, depth + 2)?,
    ))
},
FunctionParamOrReturnTag::MutableReference(t) => {
    *count += 1;  // Count the MutableReference wrapper
    MutableReference(
        Box::new(self.create_ty_impl(t, resolver, count, depth + 2)?),
    )
},
```

Also add depth checks for the Reference nodes themselves before jumping depth by +2, to be consistent with `apply_subst`: [8](#0-7) 

## Proof of Concept

```rust
#[test]
fn test_reference_node_counting_bypass() {
    use move_core_types::language_storage::*;
    use move_vm_types::loaded_data::runtime_types::*;
    
    let ty_builder = TypeBuilder::with_limits(128, 20);
    
    // Create Function with 127 Reference(U64) parameters
    let mut args = Vec::new();
    for _ in 0..127 {
        args.push(FunctionParamOrReturnTag::Reference(TypeTag::U64));
    }
    
    let func_tag = FunctionTag {
        args,
        results: vec![],
        abilities: AbilitySet::EMPTY,
    };
    
    let type_tag = TypeTag::Function(Box::new(func_tag));
    
    // This should fail with max_ty_size=128 but succeeds due to uncounted References
    let result = ty_builder.create_ty(&type_tag, |_| {
        Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR))
    });
    
    assert!(result.is_ok(), "Type creation should succeed");
    let ty = result.unwrap();
    
    // Actual node count is 255 (1 Function + 127 References + 127 U64s)
    assert_eq!(ty.num_nodes(), 255, "Type has 255 nodes, bypassing limit of 128");
}
```

## Notes

This vulnerability demonstrates an inconsistency between node counting during type creation versus post-creation node traversal. While the security impact is limited due to correct gas accounting, it represents a defense-in-depth failure where resource limits can be bypassed during the creation phase. The issue should be fixed to maintain invariant consistency, even though it doesn't meet Critical or High severity criteria due to mitigating factors.

### Citations

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L849-851)
```rust
    pub fn num_nodes(&self) -> usize {
        self.preorder_traversal().count()
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1195-1203)
```rust
    fn check(&self, count: &mut u64, depth: u64) -> PartialVMResult<()> {
        if *count >= self.max_ty_size {
            return self.too_many_nodes_error();
        }
        if depth > self.max_ty_depth {
            return self.too_large_depth_error();
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1380-1387)
```rust
            Reference(inner_ty) => {
                let inner_ty = Self::apply_subst(inner_ty, subst, count, depth + 1, check)?;
                Reference(Box::new(inner_ty))
            },
            MutableReference(inner_ty) => {
                let inner_ty = Self::apply_subst(inner_ty, subst, count, depth + 1, check)?;
                MutableReference(Box::new(inner_ty))
            },
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1446-1447)
```rust
        self.check(count, depth)?;
        *count += 1;
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1504-1514)
```rust
                            Ok(match t {
                                FunctionParamOrReturnTag::Reference(t) => Reference(Box::new(
                                    self.create_ty_impl(t, resolver, count, depth + 2)?,
                                )),
                                FunctionParamOrReturnTag::MutableReference(t) => MutableReference(
                                    Box::new(self.create_ty_impl(t, resolver, count, depth + 2)?),
                                ),
                                FunctionParamOrReturnTag::Value(t) => {
                                    self.create_ty_impl(t, resolver, count, depth + 1)?
                                },
                            })
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L265-269)
```rust
        [
            max_ty_size: NumTypeNodes,
            { RELEASE_V1_15.. => "max_ty_size" },
            128,
        ],
```

**File:** third_party/move/move-vm/runtime/src/frame.rs (L178-178)
```rust
                gas_meter.charge_create_ty(NumTypeNodes::new(ty.num_nodes() as u64))?;
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-11)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;
```
