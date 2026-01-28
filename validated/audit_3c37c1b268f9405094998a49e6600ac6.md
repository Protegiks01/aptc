# Audit Report

## Title
max_push_size Bypass via Basic Block Splitting Allows 100x Excessive Stack Operations

## Summary
The Move bytecode verifier's `max_push_size` limit (10,000 in production) is enforced per-basic-block instead of per-function, allowing attackers to bypass the intended security control by splitting operations across multiple blocks using branch instructions. This enables functions with 1,000,000+ push operations, exceeding the intended limit by 100x.

## Finding Description

The `VerifierConfig` explicitly documents `max_push_size` as limiting pushes "in one function": [1](#0-0) 

The production configuration sets this limit to 10,000: [2](#0-1) 

However, the implementation in `StackUsageVerifier` declares `overall_push` as a local variable **inside** `verify_block()`: [3](#0-2) 

Since `verify_block()` is called separately for each basic block in the control flow graph: [4](#0-3) 

The `overall_push` counter resets to zero at the start of each block, effectively making the limit per-block rather than per-function.

**Attack Vector**: Branch instructions (`Branch`, `BrTrue`, `BrFalse`) create new basic blocks. The control flow graph construction identifies branch targets and following instructions as block boundaries: [5](#0-4) 

An attacker can craft bytecode with N basic blocks (up to `max_basic_blocks = 1024`), each containing 9,999 push operations: [6](#0-5) 

Total achievable pushes: 1024 × 9,999 = 10,238,976 operations (1,024x the intended 10,000 limit).

Each block satisfies the stack balance requirement by popping as many values as it pushes: [7](#0-6) 

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria

This vulnerability enables validator node slowdowns through:

1. **Verification DoS**: Processing 1,000,000+ push operations during module verification significantly increases CPU time, potentially causing validator timeouts during transaction execution. The bytecode verifier must iterate through all instructions and calculate stack effects for each.

2. **Execution DoS**: Functions with excessive operations execute slowly. If called repeatedly (e.g., in loops or by malicious users), this degrades validator performance during block execution.

3. **Bypassed Security Control**: The production configuration explicitly enables `max_push_size`, indicating this is a relied-upon security control. The bypass renders it ineffective, violating the security model.

Notably, the `max_per_fun_meter_units` limit is **not enforced** for stack usage verification: [8](#0-7) 

The meter parameter is unused (marked with TODO), so the secondary protection mentioned in typical configurations does not apply here.

This qualifies as **High Severity** under Aptos bug bounty criteria: "Validator node slowdowns" through resource exhaustion.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack Complexity**: Low - any user can publish Move modules with crafted bytecode using standard compiler tools or direct bytecode construction
- **Prerequisites**: None - requires only the ability to submit transactions (no special privileges)
- **Economic Barrier**: Minimal - only standard gas costs for module publishing
- **Detection**: Difficult - modules pass all verification checks and appear valid
- **Exploitability**: Immediate - the bypass is trivial to implement by inserting branch instructions

The production configuration's explicit use of `max_push_size` indicates this is treated as an active security control, making its bypass a critical issue.

## Recommendation

Move the `overall_push` counter declaration outside `verify_block()` to accumulate pushes across all basic blocks in a function:

```rust
pub(crate) fn verify(
    config: &VerifierConfig,
    resolver: &'a BinaryIndexedView<'a>,
    function_view: &'a FunctionView,
    _meter: &mut impl Meter,
) -> PartialVMResult<()> {
    let verifier = Self {
        resolver,
        current_function: function_view.index(),
        code: function_view.code(),
        return_: function_view.return_(),
    };

    let mut overall_push = 0u64; // Move counter here
    
    for block_id in function_view.cfg().blocks() {
        verifier.verify_block(config, block_id, function_view.cfg(), &mut overall_push)?
    }
    Ok(())
}

fn verify_block(
    &self,
    config: &VerifierConfig,
    block_id: BlockId,
    cfg: &dyn ControlFlowGraph,
    overall_push: &mut u64, // Pass as mutable reference
) -> PartialVMResult<()> {
    // Remove local declaration, use passed reference
    // ... rest of function
}
```

## Proof of Concept

While a full executable PoC would require constructing valid bytecode, the logic is demonstrated by the existing test structure. A malicious module would contain:

```rust
// Conceptual bytecode structure (not executable)
function malicious() {
    Block0: 
        LdU64(0) × 9999  // 9999 pushes
        Pop × 9999        // 9999 pops (stack balanced)
        Branch(Block1)    // Create new block
    
    Block1:
        LdU64(0) × 9999  // overall_push RESETS, another 9999 pushes
        Pop × 9999
        Branch(Block2)
    
    // Repeat for 1024 blocks
    // Total: 1024 × 9999 = 10,238,976 pushes (passes verification)
    
    BlockN:
        Ret
}
```

Each block passes the `overall_push <= 10000` check individually, but the cumulative effect far exceeds the intended function-level limit.

---

**Notes**: This is a clear logic bug where the implementation does not match the documented intent. The comment explicitly states "in one function" but the code enforces "per basic block". The vulnerability is exacerbated by the unused meter parameter, which could have provided secondary protection but currently does not.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L235-236)
```rust
            // Max number of pushes in one function
            max_push_size: None,
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L292-292)
```rust
            max_basic_blocks: Some(1024),
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L296-296)
```rust
            max_push_size: Some(10000),
```

**File:** third_party/move/move-bytecode-verifier/src/stack_usage_verifier.rs (L33-33)
```rust
        _meter: &mut impl Meter, // TODO: metering
```

**File:** third_party/move/move-bytecode-verifier/src/stack_usage_verifier.rs (L42-44)
```rust
        for block_id in function_view.cfg().blocks() {
            verifier.verify_block(config, block_id, function_view.cfg())?
        }
```

**File:** third_party/move/move-bytecode-verifier/src/stack_usage_verifier.rs (L48-73)
```rust
    fn verify_block(
        &self,
        config: &VerifierConfig,
        block_id: BlockId,
        cfg: &dyn ControlFlowGraph,
    ) -> PartialVMResult<()> {
        let code = &self.code.code;
        let mut stack_size_increment = 0;
        let block_start = cfg.block_start(block_id);
        let mut overall_push = 0;
        for i in block_start..=cfg.block_end(block_id) {
            let (num_pops, num_pushes) = self.instruction_effect(&code[i as usize])?;
            if let Some(new_pushes) = u64::checked_add(overall_push, num_pushes) {
                overall_push = new_pushes
            } else {
                return Err(PartialVMError::new(StatusCode::VALUE_STACK_PUSH_OVERFLOW)
                    .at_code_offset(self.current_function(), block_start));
            };

            // Check that the accumulated pushes does not exceed a pre-defined max size
            if let Some(max_push_size) = config.max_push_size {
                if overall_push > max_push_size as u64 {
                    return Err(PartialVMError::new(StatusCode::VALUE_STACK_PUSH_OVERFLOW)
                        .at_code_offset(self.current_function(), block_start));
                }
            }
```

**File:** third_party/move/move-bytecode-verifier/src/stack_usage_verifier.rs (L106-113)
```rust
        if stack_size_increment == 0 {
            Ok(())
        } else {
            Err(
                PartialVMError::new(StatusCode::POSITIVE_STACK_SIZE_AT_BLOCK_END)
                    .at_code_offset(self.current_function(), block_start),
            )
        }
```

**File:** third_party/move/move-binary-format/src/control_flow_graph.rs (L238-248)
```rust
    fn record_block_ids(pc: CodeOffset, code: &[Bytecode], block_ids: &mut Set<BlockId>) {
        let bytecode = &code[pc as usize];

        if let Some(offset) = bytecode.offset() {
            block_ids.insert(*offset);
        }

        if bytecode.is_branch() && pc + 1 < (code.len() as CodeOffset) {
            block_ids.insert(pc + 1);
        }
    }
```
