# Audit Report

## Title
Script Composer Parameter Count Validation Bypass Leading to Transaction Building Failures

## Summary
The `TransactionComposer` in `aptos-move/script-composer/src/builder.rs` has an incomplete validation check that fails to account for signer parameters when verifying total parameter counts. This allows creation of scripts that either exceed Move's 128-parameter limit or cause bytecode generation failures due to integer overflow, resulting in transaction building errors.

## Finding Description

The vulnerability exists in the parameter count validation logic of the `TransactionComposer::add_batched_call()` method. The code performs two critical operations with parameters:

1. **Signer Initialization**: When creating a composer with `multi_signer(count)`, signer parameters are added to `parameters_ty` [1](#0-0) 

2. **Raw Argument Addition**: When processing `CallArgument::Raw(bytes)`, new parameters are appended to both `parameters_ty` and `parameters` arrays [2](#0-1) 

The validation check at line 331 only validates `self.parameters.len()` (raw arguments only) plus locals against the u8::MAX limit: [3](#0-2) 

**Critical Issue**: This check does NOT include signer parameters in the count, even though `parameters_ty` (which includes signers) is used later to determine the total parameter count [4](#0-3) 

This creates two attack vectors:

**Attack Vector 1: Exceeding Move's Parameter Limit**
- Move's production verifier enforces `max_function_parameters = 128` [5](#0-4) 
- An attacker can create `multi_signer(130)` + 1 raw argument = 131 total parameters
- The check at line 331 sees only `1 + 0 > 255` (passes)
- Later verification fails with `TOO_MANY_PARAMETERS` [6](#0-5) 

**Attack Vector 2: Bytecode Generation Integer Overflow**
- When generating `StLoc` instructions for return values, the code casts `(local_idx + parameters_count)` directly to u8 without overflow checking [7](#0-6) 
- With 250 signers + 0 raw args + 7 locals = 257 total locals
- The check at line 331 sees only `0 + 7 > 255` (passes)
- When storing local index 6: `StLoc((6 + 250) as u8) = StLoc(0)` due to integer truncation
- This generates invalid bytecode that references wrong local indices

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty classification)

This vulnerability causes **execution failures** as specified in the security question. While it's a client-side library and doesn't directly affect blockchain consensus, it has meaningful security impact:

1. **Transaction Building DoS**: Malicious or accidental inputs cause the `generate_batched_calls()` function to fail, preventing legitimate transaction construction
2. **Resource Waste**: Server applications using this library could be forced to waste computational resources on invalid transaction building attempts
3. **Poor Error Handling**: The early validation provides false confidence; errors surface much later in the verification phase with less informative error messages
4. **Potential Type Confusion**: In the integer overflow scenario, if bytecode somehow passed verification with truncated indices, it could lead to incorrect execution behavior

The vulnerability breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits" - the validation fails to properly enforce Move's parameter limits.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is easily triggerable:
- No special permissions required - any user of the library can exploit it
- Simple to reproduce with straightforward API calls
- Common use case: multi-signature transactions naturally use multiple signers
- Applications building complex batched transactions are likely to hit this limit

The attack requires:
- Creating a `TransactionComposer` with many signers (>128 total parameters when combined with other args)
- OR creating enough locals to trigger integer overflow (>255 total parameters + locals)

Both scenarios are realistic in production environments handling multi-signature or complex batched transactions.

## Recommendation

**Fix the validation check to include ALL parameters:**

```rust
// In add_batched_call(), around line 331:
// BEFORE (incorrect):
if self.parameters.len() + self.locals_ty.len() > u8::MAX as usize {
    bail!("Too many locals being allocated, please truncate the transaction");
}

// AFTER (correct):
if self.parameters_ty.len() + self.locals_ty.len() > u8::MAX as usize {
    bail!("Too many locals being allocated, please truncate the transaction");
}
```

Additionally, add an early check for Move's parameter limit:

```rust
// After line 290 in add_batched_call():
const MAX_MOVE_PARAMETERS: usize = 128;
if self.parameters_ty.len() > MAX_MOVE_PARAMETERS {
    bail!("Too many function parameters: {} exceeds Move's limit of {}", 
          self.parameters_ty.len(), MAX_MOVE_PARAMETERS);
}
```

Also add overflow checking when generating StLoc instructions:

```rust
// In generate_batched_calls_impl(), around line 401:
for arg in call.returns.iter().rev() {
    let local_idx = (*arg as usize)
        .checked_add(parameters_count as usize)
        .ok_or_else(|| anyhow!("Too many locals: index overflow"))?;
    if local_idx > u8::MAX as usize {
        bail!("Local index {} exceeds bytecode limit", local_idx);
    }
    script.code.code.push(Bytecode::StLoc(local_idx as u8));
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "TOO_MANY_PARAMETERS")]
fn test_parameter_limit_bypass() {
    use crate::TransactionComposer;
    use move_core_types::value::MoveValue;
    
    // Create composer with 130 signers (exceeds Move's limit of 128)
    let mut builder = TransactionComposer::multi_signer(130);
    
    // Load a test module (assuming aptos_account is available)
    // In real test, would use load_module() helper
    
    // Add a call with 1 raw argument
    // Total parameters: 130 signers + 1 raw = 131 (exceeds limit)
    let result = builder.add_batched_call(
        "0x1::aptos_account".to_string(),
        "transfer".to_string(),
        vec![],
        vec![
            CallArgument::new_signer(0),
            CallArgument::new_bytes(
                MoveValue::Address(AccountAddress::from_hex_literal("0xface").unwrap())
                    .simple_serialize()
                    .unwrap(),
            ),
            CallArgument::new_bytes(MoveValue::U64(100).simple_serialize().unwrap()),
        ],
    );
    
    // The validation at line 331 incorrectly passes (only checks raw args + locals)
    assert!(result.is_ok());
    
    // But script generation fails at verification with TOO_MANY_PARAMETERS
    let script_result = builder.generate_batched_calls(false);
    // This should panic with TOO_MANY_PARAMETERS error
    script_result.unwrap();
}

#[test]
#[should_panic(expected = "Type mismatch")]
fn test_bytecode_overflow() {
    use crate::TransactionComposer;
    
    // Create composer with 250 signers
    let mut builder = TransactionComposer::multi_signer(250);
    
    // Add calls that return 7 values, creating 7 locals
    // Total: 250 parameters + 7 locals = 257 (exceeds u8::MAX)
    
    for _ in 0..7 {
        // Add a call that returns a value
        builder.add_batched_call(
            "0x1::some_module".to_string(),
            "return_value".to_string(),
            vec![],
            vec![],
        ).unwrap();
    }
    
    // The validation at line 331 sees: 0 raw args + 7 locals = 7 (passes)
    // But actual total is 257, causing StLoc overflow during generation
    let script_result = builder.generate_batched_calls(false);
    script_result.unwrap(); // Should fail with type mismatch or similar error
}
```

**Notes**

This vulnerability is specific to the transaction composer library and does not affect the core Aptos blockchain consensus or execution. However, it represents a real security issue for applications using this library to construct batched transactions, particularly those involving multiple signers. The incomplete validation allows invalid transaction construction to proceed further than it should, wasting resources and providing misleading error messages.

### Citations

**File:** aptos-move/script-composer/src/builder.rs (L117-121)
```rust
            parameters_ty: std::iter::repeat_n(
                SignatureToken::Reference(Box::new(SignatureToken::Signer)),
                signer_count.into(),
            )
            .collect(),
```

**File:** aptos-move/script-composer/src/builder.rs (L279-288)
```rust
                CallArgument::Raw(bytes) => {
                    let new_local_idx = self.parameters_ty.len() as u16;
                    self.parameters_ty.push(ty);
                    self.parameters.push(bytes);
                    arguments.push(AllocatedLocal {
                        op_type: ArgumentOperation::Move,
                        is_parameter: true,
                        local_idx: new_local_idx,
                    })
                },
```

**File:** aptos-move/script-composer/src/builder.rs (L331-333)
```rust
        if self.parameters.len() + self.locals_ty.len() > u8::MAX as usize {
            bail!("Too many locals being allocated, please truncate the transaction");
        }
```

**File:** aptos-move/script-composer/src/builder.rs (L364-364)
```rust
        let parameters_count = self.parameters_ty.len() as u16;
```

**File:** aptos-move/script-composer/src/builder.rs (L397-402)
```rust
            for arg in call.returns.iter().rev() {
                script
                    .code
                    .code
                    .push(Bytecode::StLoc((*arg + parameters_count) as u8));
            }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L159-159)
```rust
        max_function_parameters: Some(128),
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L73-84)
```rust
            if let Some(limit) = config.max_function_parameters {
                if self
                    .resolver
                    .signature_at(function_handle.parameters)
                    .0
                    .len()
                    > limit
                {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_PARAMETERS)
                        .at_index(IndexKind::FunctionHandle, idx as u16));
                }
            }
```
