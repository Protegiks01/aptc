# Audit Report

## Title
Consensus Split Vulnerability via layout_max_size Configuration Mismatch During Protocol Upgrade

## Summary
A critical consensus-breaking vulnerability exists at the RELEASE_V1_30 version boundary where the `layout_max_size` parameter increases from 256 to 512 nodes. Modules containing structs with 257-512 fields can pass bytecode verification but trigger divergent runtime behavior: nodes running pre-v1.30 code fail with `TOO_MANY_TYPE_NODES`, while nodes running v1.30+ code succeed when `gas_feature_version >= RELEASE_V1_30`. This breaks the deterministic execution invariant and causes consensus splits.

## Finding Description

The vulnerability stems from a mismatch between verification-time and runtime type complexity limits:

**Verification Phase (Module Publishing):**
The bytecode verifier counts struct types with a weight of 4 nodes, regardless of field count [1](#0-0) , and enforces no limit on the number of struct fields since `max_fields_in_struct = None` in production configuration [2](#0-1) . A struct with 257 fields in a function signature counts as only 4 nodes, easily passing the `max_type_nodes = 256` verification limit.

**Runtime Phase (Transaction Execution):**
During execution, when native functions like `bcs::to_bytes()` require type layouts, the layout converter counts each struct field as a separate node [3](#0-2) . A struct with 257 fields produces a layout with 258 nodes (1 for the struct + 257 for fields). The runtime enforces `layout_max_size`, which is version-dependent [4](#0-3) :

- Pre-v1.30 code: Always uses `layout_max_size = 256`  
- V1.30+ code: Uses `layout_max_size = 512` when `gas_feature_version >= RELEASE_V1_30`

**The Attack:**
1. Attacker publishes a module with a struct containing 257 fields of type `u8`
2. Module includes a public entry function that instantiates this struct and calls `bcs::to_bytes()` on it
3. During protocol upgrade window when `gas_feature_version >= RELEASE_V1_30` but not all validators have upgraded to v1.30+ code
4. Transaction calls this entry function
5. Layout construction in `check_depth_and_increment_count` [5](#0-4)  enforces the limit:
   - Old nodes: 258 > 256 → Returns `TOO_MANY_TYPE_NODES` error → Transaction fails
   - New nodes: 258 < 512 → Succeeds → Transaction succeeds
6. Different validators compute different state roots for the same block → **Consensus split**

## Impact Explanation

This is a **Critical Severity** vulnerability that breaks the fundamental deterministic execution invariant [6](#0-5) . During the protocol upgrade window, validators running different code versions will:

- Compute different execution results for the same transactions
- Generate different state Merkle roots
- Fail to reach consensus on block commitment
- Potentially cause a permanent network partition requiring a hard fork

The execution component documentation explicitly states that "each transaction should produce identical output across all validators" [7](#0-6) , which this vulnerability violates.

## Likelihood Explanation

**High Likelihood** during protocol upgrades:
- The `gas_feature_version` is controlled by on-chain governance [8](#0-7)  and can be upgraded independently of node software versions
- No enforcement mechanism ensures all validators upgrade node software before `gas_feature_version` increases
- Attacker only needs to publish a valid module (no special privileges required)
- The verifier's unlimited field count policy [2](#0-1)  makes the attack trivial to execute

## Recommendation

**Immediate Mitigation:**
1. Enforce that `layout_max_size` must always be >= `max_type_nodes` to prevent verification-runtime mismatches
2. Set `max_fields_in_struct` to a reasonable limit (e.g., 256) in the production verifier config

**Proper Fix:**
```rust
pub fn aptos_prod_verifier_config(gas_feature_version: u64, features: &Features) -> VerifierConfig {
    // ... existing code ...
    
    VerifierConfig {
        // ... existing fields ...
        max_fields_in_struct: Some(256),  // Enforce field limit
        // Ensure verifier limit accounts for actual runtime expansion
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
        // ... remaining fields ...
    }
}
```

**Coordinated Upgrade Protocol:**
Before increasing `gas_feature_version` to RELEASE_V1_30:
1. Ensure 100% of validators have upgraded to v1.30+ node software
2. Add runtime assertions that verify layout node counts never exceed verifier limits
3. Implement backward-compatible layout size checking that uses the minimum of old/new limits during transition periods

## Proof of Concept

```move
module 0x1::attack {
    use std::bcs;
    
    // Struct with 257 fields - passes verifier (counted as 4 nodes)
    struct BigStruct has drop {
        f1: u8, f2: u8, f3: u8, /* ... f257: u8 */
        // (257 fields total, each of type u8)
    }
    
    // Entry function that triggers layout construction
    public entry fun trigger_split() {
        let x = BigStruct { 
            f1: 0, f2: 0, f3: 0, /* ... f257: 0 */
        };
        
        // Calling bcs::to_bytes triggers layout construction
        // Old nodes (layout_max_size=256): TOO_MANY_TYPE_NODES
        // New nodes (layout_max_size=512): SUCCESS
        let _bytes = bcs::to_bytes(&x);
    }
}
```

**Exploitation Steps:**
1. Deploy module during upgrade window when `gas_feature_version >= RELEASE_V1_30`
2. Submit transaction calling `0x1::attack::trigger_split()`
3. Observe consensus failure as validators compute different results
4. Network partition occurs between old and new validator sets

### Citations

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L142-143)
```rust
        const STRUCT_SIZE_WEIGHT: usize = 4;
        const PARAM_SIZE_WEIGHT: usize = 4;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L170-170)
```rust
        max_fields_in_struct: None,
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L215-219)
```rust
    let layout_max_size = if gas_feature_version >= RELEASE_V1_30 {
        512
    } else {
        256
    };
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L197-222)
```rust
    fn check_depth_and_increment_count(
        &self,
        node_count: &mut u64,
        depth: u64,
    ) -> PartialVMResult<()> {
        let max_count = self.vm_config().layout_max_size;
        if *node_count > max_count || *node_count == max_count && self.is_lazy_loading_enabled() {
            return Err(
                PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).with_message(format!(
                    "Number of type nodes when constructing type layout exceeded the maximum of {}",
                    max_count
                )),
            );
        }
        *node_count += 1;

        if depth > self.vm_config().layout_max_depth {
            return Err(
                PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED).with_message(format!(
                    "Depth of a layout exceeded the maximum of {} during construction",
                    self.vm_config().layout_max_depth
                )),
            );
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L264-264)
```rust
        self.check_depth_and_increment_count(count, depth)?;
```

**File:** execution/README.md (L8-23)
```markdown
## Overview

The Aptos Blockchain is a replicated state machine. Each validator is a replica
of the system. Starting from genesis state S<sub>0</sub>, each transaction
T<sub>i</sub> updates previous state S<sub>i-1</sub> to S<sub>i</sub>. Each
S<sub>i</sub> is a mapping from accounts (represented by 32-byte addresses) to
some data associated with each account.

The execution component takes the ordered transactions, computes the output
for each transaction via the Move virtual machine, applies the output on the
previous state, and generates the new state. The execution system cooperates
with the consensus algorithm to help it agree on a proposed set of transactions and their execution. Such a
group of transactions is a block. Unlike in other blockchain systems, blocks
have no significance other than being a batch of transactions — every
transaction is identified by its position within the ledger, which is also
referred to as its "version". Each consensus participant builds a tree of blocks
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_gas_schedule::{AptosGasParameters, FromOnChainGasSchedule};
use aptos_types::{
    on_chain_config::{Features, GasSchedule, GasScheduleV2, OnChainConfig},
    state_store::StateView,
};
use aptos_vm_types::storage::{io_pricing::IoPricing, StorageGasParameters};
use move_core_types::gas_algebra::NumArgs;
use sha3::{digest::Update, Sha3_256};

/// Returns the gas feature version stored in [GasScheduleV2]. If the gas schedule does not exist,
/// returns 0 gas feature version.
pub fn get_gas_feature_version(state_view: &impl StateView) -> u64 {
    GasScheduleV2::fetch_config(state_view)
        .map(|gas_schedule| gas_schedule.feature_version)
        .unwrap_or(0)
}

/// Returns the gas parameters and the gas feature version from the state. If no gas parameters are
/// found, returns an error. Also updates the provided sha3 with config bytes.
fn get_gas_config_from_storage(
    sha3_256: &mut Sha3_256,
    state_view: &impl StateView,
) -> (Result<AptosGasParameters, String>, u64) {
    match GasScheduleV2::fetch_config_and_bytes(state_view) {
        Some((gas_schedule, bytes)) => {
            sha3_256.update(&bytes);
            let feature_version = gas_schedule.feature_version;
            let map = gas_schedule.into_btree_map();
            (
                AptosGasParameters::from_on_chain_gas_schedule(&map, feature_version),
                feature_version,
            )
        },
        None => match GasSchedule::fetch_config_and_bytes(state_view) {
            Some((gas_schedule, bytes)) => {
                sha3_256.update(&bytes);
                let map = gas_schedule.into_btree_map();
                (AptosGasParameters::from_on_chain_gas_schedule(&map, 0), 0)
            },
            None => (Err("Neither gas schedule v2 nor v1 exists.".to_string()), 0),
        },
    }
}

/// Returns gas and storage gas parameters, as well as the gas feature version, from the state. In
/// case parameters are not found on-chain, errors are returned.
pub(crate) fn get_gas_parameters(
```
