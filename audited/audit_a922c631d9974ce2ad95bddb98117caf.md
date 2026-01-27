# Audit Report

## Title
Consensus Divergence via Conditionally Compiled Fail Points in Block Output Size Calculation

## Summary
The `aptos-mvhashmap` crate contains an active fail point in production code that can manipulate block output size calculations when built with the `failpoints` feature. This allows attackers with build configuration control to cause consensus divergence by making different validators disagree on when to terminate block execution.

## Finding Description

The `bytes_len()` method in `ValueWithLayout<V>` contains a fail point that can return arbitrary values: [1](#0-0) 

This fail point is in production code (not test-only), and the `fail` crate dependency is listed in regular dependencies: [2](#0-1) 

Critically, the `aptos-mvhashmap` crate does NOT define its own `failpoints` feature flag. When `aptos-node` is built with `--features failpoints`, Cargo's feature unification mechanism enables the `fail/failpoints` feature globally across all workspace crates: [3](#0-2) 

The `bytes_len()` value flows into consensus-critical calculations:

1. **Write operation sizing**: The `write_op_size()` method uses `bytes().unwrap().len()` to determine write length: [4](#0-3) 

2. **Block output size calculation**: The `materialized_size()` aggregates write sizes for transaction outputs: [5](#0-4) 

3. **Block termination decisions**: The `BlockGasLimitProcessor` uses accumulated output size to determine when to stop adding transactions: [6](#0-5) 

When the fail point is activated via the `/v1/set_failpoint` API endpoint (which checks compile-time feature and runtime config): [7](#0-6) 

An attacker who controls build configuration can:

1. Build validator binaries with `cargo build --release --features failpoints`
2. Deploy on non-mainnet networks (testnet/devnet) where the sanitizer permits failpoints: [8](#0-7) 

3. Activate the fail point: `POST /v1/set_failpoint?name=value_with_layout_bytes_len&actions=return(Some(10))`
4. Cause all `bytes_len()` calls to return 10 instead of actual sizes

This breaks **Invariant #1: Deterministic Execution** - if different validators have different failpoint settings, they will calculate different `accumulated_approx_output_size` values, leading to disagreement on when to terminate block execution and producing different block contents.

## Impact Explanation

This is a **Critical severity** consensus safety violation. Different validators will:
- Calculate different block output sizes
- Make different decisions about when to stop block execution  
- Include different transaction sets in blocks
- Produce different state roots

This violates the fundamental AptosBFT safety guarantee that honest validators agree on block contents. While the config sanitizer prevents this on mainnet, the vulnerability exists on testnets and private networks, and represents a defense-in-depth failure.

The existing test demonstrates the fail point's functionality: [9](#0-8) 

## Likelihood Explanation

**Medium-to-Low likelihood** in practice because exploitation requires:
1. Adversarial control over build configuration (CI/CD compromise or malicious operator)
2. Deployment on networks where config sanitizer doesn't block failpoints (non-mainnet)
3. Ability to call the `/v1/set_failpoint` API with `api.failpoints_enabled = true`
4. Coordination to ensure different validators have different settings

However, the **architectural flaw** is that production code contains debug instrumentation that can be conditionally compiled, violating the principle that production binaries should not contain testing hooks.

## Recommendation

Remove fail points from production code paths. Options:

1. **Move fail point to test-only code**: Wrap with `#[cfg(test)]` or move `bytes_len()` testing to dedicated test module

2. **Create separate test implementation**: Use conditional compilation to provide different implementations:
```rust
#[cfg(not(test))]
pub fn bytes_len(&self) -> Option<usize> {
    match self {
        ValueWithLayout::RawFromStorage(value) | ValueWithLayout::Exchanged(value, _) => {
            value.bytes().map(|b| b.len())
        },
    }
}

#[cfg(test)]
pub fn bytes_len(&self) -> Option<usize> {
    fail_point!("value_with_layout_bytes_len", |_| { Some(10) });
    match self {
        ValueWithLayout::RawFromStorage(value) | ValueWithLayout::Exchanged(value, _) => {
            value.bytes().map(|b| b.len())
        },
    }
}
```

3. **Make mvhashmap explicitly opt-out of failpoints**: Add feature flag to mvhashmap that must be explicitly enabled, preventing accidental inclusion via feature unification

4. **Add compile-time assertion**: Prevent compilation of release builds with failpoints enabled via build scripts

## Proof of Concept

The existing test provides a working PoC. To demonstrate consensus divergence:

**Setup**: Two validator nodes, one with failpoints enabled and activated, one without

**Validator A** (failpoints disabled): Calculates actual output sizes, terminates block at transaction N when accumulated_approx_output_size exceeds block_output_limit

**Validator B** (failpoints enabled with `value_with_layout_bytes_len` returning 10): Underestimates all output sizes, continues adding transactions past N until different termination point

**Result**: Validators propose different block contents, consensus cannot make progress or produces fork

The test at line 1360 already demonstrates the fail point activation: [10](#0-9) 

## Notes

While the config sanitizer provides mainnet protection, the architectural pattern of including debug instrumentation in production code creates supply chain risk. If the sanitizer is bypassed, circumvented, or has edge cases, the underlying vulnerability remains. Defense-in-depth requires removing fail points from production code entirely.

### Citations

**File:** aptos-move/mvhashmap/src/types.rs (L162-169)
```rust
    pub fn bytes_len(&self) -> Option<usize> {
        fail_point!("value_with_layout_bytes_len", |_| { Some(10) });
        match self {
            ValueWithLayout::RawFromStorage(value) | ValueWithLayout::Exchanged(value, _) => {
                value.bytes().map(|b| b.len())
            },
        }
    }
```

**File:** aptos-move/mvhashmap/Cargo.toml (L26-26)
```text
fail = { workspace = true }
```

**File:** aptos-node/Cargo.toml (L95-95)
```text
failpoints = ["fail/failpoints", "aptos-consensus/failpoints", "aptos-executor/failpoints", "aptos-mempool/failpoints", "aptos-api/failpoints", "aptos-config/failpoints"]
```

**File:** types/src/write_set.rs (L415-426)
```rust
    fn write_op_size(&self) -> WriteOpSize {
        use WriteOpKind::*;
        match self.write_op_kind() {
            Creation => WriteOpSize::Creation {
                write_len: self.bytes().unwrap().len() as u64,
            },
            Modification => WriteOpSize::Modification {
                write_len: self.bytes().unwrap().len() as u64,
            },
            Deletion => WriteOpSize::Deletion,
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/output.rs (L124-138)
```rust
    pub fn materialized_size(&self) -> u64 {
        let mut size = 0;
        for (state_key, write_size) in self
            .change_set
            .write_set_size_iter()
            .chain(self.module_write_set.write_set_size_iter())
        {
            size += state_key.size() as u64 + write_size.write_len().unwrap_or(0);
        }

        for event in self.change_set.events_iter() {
            size += event.size() as u64;
        }
        size
    }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L143-154)
```rust
        if let Some(per_block_output_limit) = self.block_gas_limit_type.block_output_limit() {
            let accumulated_output = self.get_accumulated_approx_output_size();
            if accumulated_output >= per_block_output_limit {
                counters::EXCEED_PER_BLOCK_OUTPUT_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_output {} >= PER_BLOCK_OUTPUT_LIMIT {}",
                    mode, accumulated_output, per_block_output_limit,
                );
                return true;
            }
        }
```

**File:** api/src/set_failpoints.rs (L21-40)
```rust
#[cfg(feature = "failpoints")]
#[handler]
pub fn set_failpoint_poem(
    context: Data<&std::sync::Arc<Context>>,
    Query(failpoint_conf): Query<FailpointConf>,
) -> poem::Result<String> {
    if context.failpoints_enabled() {
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        info!(
            "Configured failpoint {} to {}",
            failpoint_conf.name, failpoint_conf.actions
        );
        Ok(format!("Set failpoint {}", failpoint_conf.name))
    } else {
        Err(poem::Error::from(anyhow::anyhow!(
            "Failpoints are not enabled at a config level"
        )))
    }
}
```

**File:** config/src/config/config_sanitizer.rs (L82-90)
```rust
    // Verify that failpoints are not enabled in mainnet
    let failpoints_enabled = are_failpoints_enabled();
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() && failpoints_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are not supported on mainnet nodes!".into(),
            ));
        }
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L1357-1367)
```rust
        let scenario = FailScenario::setup();
        assert!(fail::has_failpoints());
        // Failpoint returns 10 as bytes length.
        fail::cfg("value_with_layout_bytes_len", "return").unwrap();
        assert!(!fail::list().is_empty());

        versioned_data.set_base_value(
            (),
            ValueWithLayout::Exchanged(Arc::new(TestValueWithMetadata::new(10, 100)), None),
        );
        assert_eq!(versioned_data.total_base_value_size(), 10);
```
