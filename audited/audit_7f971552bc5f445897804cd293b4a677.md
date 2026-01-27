# Audit Report

## Title
Gas Metering Undercharge in VecUnpack Operation Allows Unpaid Computation Before Validation

## Summary
The `charge_vec_unpack()` function charges gas based on `expect_num_elements` parameter, but the actual unpacking operation processes all elements in the vector before validating the count. This allows attackers to pay gas for fewer elements while forcing validators to perform O(n) work, where n is the actual vector size, violating the Move VM's gas metering invariants.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Gas Charging** [1](#0-0) 

The gas meter charges based only on `expect_num_elements`, completely ignoring the actual vector size passed in `_elems`.

**2. VM Execution** [2](#0-1) 

The interpreter charges gas BEFORE calling `vec_val.unpack(*num)`, meaning validators have already committed to undercharged gas when validation fails.

**3. Unpack Implementation** [3](#0-2) 

The `unpack()` method first calls `unpack_unchecked()` which iterates through ALL actual elements, then checks if the count matches.

**Attack Flow:**

1. Attacker publishes a Move module with bytecode containing `VecUnpack(signature_index, 1)` in a function that accepts a vector parameter or loads a vector from storage

2. The function is called with a vector containing 100,000 elements

3. Gas charged: `VEC_UNPACK_BASE + VEC_UNPACK_PER_EXPECTED_ELEM * 1 = 1838 + 147 = 1985` internal gas units [4](#0-3) 

4. The VM calls `unpack_unchecked()` which iterates through all 100,000 elements, wrapping each in a Value container [5](#0-4) 

5. Only after this O(n) work, the validation check `if expected_num as usize == elements.len()` detects the mismatch

6. Transaction aborts with `VEC_UNPACK_PARITY_MISMATCH`, but validators have already performed work proportional to 100,000 elements while being paid for 1 element

**Invariant Violations:**

- **Move VM Safety**: "Bytecode execution must respect gas limits and memory constraints" - Gas charged (O(expected)) does not match work performed (O(actual))
- **Resource Limits**: "All operations must respect gas, storage, and computational limits" - Computational work exceeds gas payment

The bytecode verifier cannot prevent this because vector lengths are dynamic runtime values, not static bytecode properties.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

**1. Validator Node Slowdowns (High Category):** Attackers can cause validators to perform disproportionate CPU work relative to gas paid. While attackers must pay for vector creation/loading (which provides some economic protection), the unpack operation itself creates a work amplification factor of up to expected_num/actual_num.

**2. Significant Protocol Violation (High Category):** The gas metering system is a fundamental security mechanism ensuring validators are compensated for computational work. This bug allows work to be performed with insufficient compensation, violating a core protocol invariant.

**3. DoS Potential:** At scale, coordinated attackers could spam transactions that:
   - Load large vectors from storage (paying IO gas based on bytes)
   - Attempt unpacking with minimal expected elements
   - Force validators to iterate through millions of elements
   - Cause transactions to abort after work is done

While the total transaction cost includes vector creation/loading, the marginal cost of the unpack work amplification could enable resource exhaustion attacks if exploited systematically.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Ability to publish Move modules (standard capability)
- Knowledge to craft bytecode with mismatched VecUnpack instructions (requires IR/manual bytecode but feasible)
- Capital to pay for transaction fees and storage

**Ease of Exploitation:**
- The Move IR compiler directly translates `VecUnpack(num)` instructions with user-specified `num` parameter
- Bytecode verifier cannot prevent this (runtime vector lengths unknown)
- Attackers can publish modules that appear legitimate but contain mismatched unpacks
- Vectors can be passed as arguments or loaded from storage cheaply relative to iteration cost

**Practical Scenario:**
A malicious module with a public function:
```
public fun process(v: vector<u64>) {
    // Bytecode contains VecUnpack(si, 2)
    // Caller passes vector with 50,000 elements
    // Pays gas for 2, VM does work for 50,000
}
```

## Recommendation

**Fix the gas charging to account for actual vector size:**

Modify the `charge_vec_unpack()` implementation to charge based on the minimum of expected and actual elements, or validate the length BEFORE performing any iteration work:

```rust
fn charge_vec_unpack(
    &mut self,
    expect_num_elements: NumArgs,
    elems: impl ExactSizeIterator<Item = impl ValueView>,
) -> PartialVMResult<()> {
    // Charge for actual elements that will be processed
    let actual_len = NumArgs::new(elems.len() as u64);
    let charge_amount = std::cmp::max(expect_num_elements, actual_len);
    
    self.algebra
        .charge_execution(VEC_UNPACK_BASE + VEC_UNPACK_PER_EXPECTED_ELEM * charge_amount)
}
```

**Alternative: Early length validation in Vector::unpack():**

```rust
pub fn unpack(self, expected_num: u64) -> PartialVMResult<Vec<Value>> {
    // Check length BEFORE doing any work
    let actual_len = self.len()?;
    if expected_num as usize != actual_len {
        return Err(PartialVMError::new(StatusCode::VECTOR_OPERATION_ERROR)
            .with_sub_status(VEC_UNPACK_PARITY_MISMATCH));
    }
    self.unpack_unchecked()
}
```

This requires adding a `len()` method that checks the count without iteration.

## Proof of Concept

**Move IR PoC:**

```move-ir
module 0x1::VecUnpackExploit {
    public fun exploit(v: vector<u64>) {
        label b0:
        // This will charge gas for 1 element
        // but process however many elements v actually contains
        _ = vec_unpack_1<u64>(move(v));
        return;
    }
}

// Caller transaction:
script {
    use 0x1::VecUnpackExploit;
    
    fun main() {
        let v: vector<u64>;
        label b0:
        // Create vector with 10,000 elements
        v = vec_pack_0<u64>();
        {
            let i: u64 = 0;
            label loop:
            if (copy(i) >= 10000) goto done;
            vec_push_back<u64>(&mut v, copy(i));
            i = move(i) + 1;
            goto loop;
            label done:
        }
        
        // Call exploit - pays gas for 1, VM does work for 10,000
        VecUnpackExploit::exploit(move(v));
        
        return;
    }
}
```

**Expected Behavior:**
- Gas charged for VecUnpack: 1838 + 147*1 = 1,985 gas
- Actual work: Iterate and wrap 10,000 elements
- Transaction aborts with VEC_UNPACK_PARITY_MISMATCH
- Validator has performed O(10,000) work for O(1) gas payment

## Notes

While the total transaction cost includes vector creation/loading gas (which provides economic protection), the core issue remains: the VM performs O(actual_length) computational work during unpacking while only charging O(expected_length) gas. This work-vs-payment mismatch occurs before the validation check, creating an exploitable asymmetry. The fix should ensure gas charged matches work performed, maintaining the critical invariant that validators are fairly compensated for all computational resources consumed.

### Citations

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L495-502)
```rust
    fn charge_vec_unpack(
        &mut self,
        expect_num_elements: NumArgs,
        _elems: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        self.algebra
            .charge_execution(VEC_UNPACK_BASE + VEC_UNPACK_PER_EXPECTED_ELEM * expect_num_elements)
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L3008-3017)
```rust
                    Instruction::VecUnpack(si, num) => {
                        let vec_val = interpreter.operand_stack.pop_as::<Vector>()?;
                        let (_, ty_count) = frame_cache.get_signature_index_type(*si, self)?;
                        gas_meter.charge_create_ty(ty_count)?;
                        gas_meter.charge_vec_unpack(NumArgs::new(*num), vec_val.elem_views())?;
                        let elements = vec_val.unpack(*num)?;
                        for value in elements {
                            interpreter.operand_stack.push(value)?;
                        }
                    },
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4071-4136)
```rust
    pub fn unpack_unchecked(self) -> PartialVMResult<Vec<Value>> {
        let elements: Vec<_> = match self.0 {
            Container::VecU8(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::u8)
                .collect(),
            Container::VecU16(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::u16)
                .collect(),
            Container::VecU32(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::u32)
                .collect(),
            Container::VecU64(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::u64)
                .collect(),
            Container::VecU128(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::u128)
                .collect(),
            Container::VecU256(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::u256)
                .collect(),
            Container::VecI8(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::i8)
                .collect(),
            Container::VecI16(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::i16)
                .collect(),
            Container::VecI32(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::i32)
                .collect(),
            Container::VecI64(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::i64)
                .collect(),
            Container::VecI128(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::i128)
                .collect(),
            Container::VecI256(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::i256)
                .collect(),
            Container::VecBool(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::bool)
                .collect(),
            Container::VecAddress(r) => take_unique_ownership(r)?
                .into_iter()
                .map(Value::address)
                .collect(),
            Container::Vec(r) => take_unique_ownership(r)?.into_iter().collect(),
            Container::Locals(_) | Container::Struct(_) => {
                return Err(PartialVMError::new_invariant_violation(
                    "Unexpected non-vector container",
                ))
            },
        };
        Ok(elements)
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4139-4147)
```rust
    pub fn unpack(self, expected_num: u64) -> PartialVMResult<Vec<Value>> {
        let elements = self.unpack_unchecked()?;
        if expected_num as usize == elements.len() {
            Ok(elements)
        } else {
            Err(PartialVMError::new(StatusCode::VECTOR_OPERATION_ERROR)
                .with_sub_status(VEC_UNPACK_PARITY_MISMATCH))
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/instr.rs (L164-165)
```rust
        [vec_unpack_base: InternalGas, "vec_unpack.base", 1838],
        [vec_unpack_per_expected_elem: InternalGasPerArg, "vec_unpack.per_expected_elem", 147],
```
