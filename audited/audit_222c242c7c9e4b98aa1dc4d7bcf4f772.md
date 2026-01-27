# Audit Report

## Title
Silent Fallback to Default Type Size Limits Enables Consensus Divergence

## Summary
Validators that fail to load on-chain gas parameters silently fall back to hardcoded default `max_ty_size` values, while validators that successfully load gas parameters use on-chain configured values. When these values differ, validators execute the same transactions with different results, breaking consensus and causing network partition.

## Finding Description

The Aptos VM creates a fresh execution environment for each block by reading gas parameters from on-chain state. The `max_ty_size` parameter controls the maximum complexity of types allowed during transaction execution. [1](#0-0) 

When gas parameter loading fails, the code silently falls back to hardcoded defaults instead of halting execution: [2](#0-1) 

The `max_ty_size` value is used during transaction argument validation to check type complexity: [3](#0-2) 

The type size check occurs via `TypeBuilder::create_ty_with_subst`, which enforces the configured limits: [4](#0-3) 

**Attack Scenario:**

1. Governance updates on-chain `GasScheduleV2` to set `max_ty_size = 256` (different from default 128)
2. During block execution, some validators successfully read gas parameters (→ `max_ty_size = 256`)
3. Other validators encounter transient failures loading gas parameters (state corruption, I/O errors, parsing errors) and fall back to defaults (→ `max_ty_size = 128`)
4. Attacker submits transaction with entry function using type arguments resulting in 200 type nodes
5. Validators with `max_ty_size = 256`: Transaction argument validation succeeds, transaction executes
6. Validators with `max_ty_size = 128`: Validation fails with `TOO_MANY_TYPE_NODES`, transaction is discarded
7. Validators compute different state roots and cannot reach consensus on the block

## Impact Explanation

This is a **Critical severity** vulnerability (Consensus/Safety violation category):

- Breaks the fundamental invariant: "All validators must produce identical state roots for identical blocks"
- Causes network partition when validators disagree on transaction execution results
- Requires hard fork to recover once divergence occurs
- State root disagreement prevents BFT consensus from completing [5](#0-4) 

The consensus mechanism requires all validators to agree on the transaction accumulator hash, which is derived from execution results. Different execution outcomes produce different hashes, preventing quorum formation.

## Likelihood Explanation

**LOW but NON-ZERO likelihood**:

**Prerequisites:**
1. On-chain `max_ty_size` must differ from default (128) - requires governance proposal
2. Gas parameter loading must fail on subset of validators - rare but possible:
   - State database corruption on specific nodes
   - Disk I/O errors during config read
   - Parsing errors from corrupted on-chain data
   - Version mismatch in gas schedule format
   - Race conditions during state synchronization

**Why this matters despite low likelihood:**
- Consensus-critical code should NEVER have silent fallbacks allowing divergence
- Single occurrence causes catastrophic failure requiring hard fork
- Defense-in-depth principle: eliminate divergence paths even if unlikely

Gas parameter loading can fail here: [6](#0-5) 

## Recommendation

**Remove silent fallback behavior and fail-fast when gas parameters cannot be loaded:**

```rust
// In aptos-move/aptos-vm-environment/src/environment.rs
let (gas_params, storage_gas_params, gas_feature_version) =
    get_gas_parameters(&mut sha3_256, &features, state_view);

let (native_gas_params, misc_gas_params, ty_builder) = match &gas_params {
    Ok(gas_params) => {
        let ty_builder = aptos_prod_ty_builder(gas_feature_version, gas_params);
        (
            gas_params.natives.clone(),
            gas_params.vm.misc.clone(),
            ty_builder,
        )
    },
    Err(err) => {
        // CRITICAL: Halt execution instead of using fallback
        panic!(
            "FATAL: Cannot load gas parameters from on-chain state: {}. \
             This indicates state corruption or inconsistency. \
             Node cannot continue execution to prevent consensus divergence.",
            err
        );
    },
};
```

**Alternative approach** (if graceful handling required):
- Return error from `AptosEnvironment::new()` instead of creating invalid environment
- Propagate error to block execution layer
- Validators vote to skip block or retry with backoff
- Never allow execution with mismatched configurations

## Proof of Concept

```rust
// Proof of concept demonstrating the divergence scenario
// File: aptos-move/aptos-vm/tests/consensus_divergence_test.rs

#[test]
fn test_type_size_consensus_divergence() {
    use aptos_types::state_store::MockStateView;
    use aptos_vm_environment::environment::AptosEnvironment;
    use move_vm_types::loaded_data::runtime_types::TypeBuilder;
    
    // Validator A: Successfully loads gas params with max_ty_size=256
    let mut state_with_updated_gas = MockStateView::empty();
    // ... set up state with GasScheduleV2 having max_ty_size=256
    let env_a = AptosEnvironment::new(&state_with_updated_gas);
    let ty_builder_a = &env_a.vm_config().ty_builder;
    // ty_builder_a has max_ty_size = 256
    
    // Validator B: Fails to load gas params, falls back to default
    let corrupted_state = MockStateView::empty(); // No gas schedule
    let env_b = AptosEnvironment::new(&corrupted_state);
    let ty_builder_b = &env_b.vm_config().ty_builder;
    // ty_builder_b has max_ty_size = 128 (default)
    
    // Create a type with 200 nodes (between 128 and 256)
    let large_type = /* construct type with 200 nodes */;
    
    // Validator A accepts
    let result_a = ty_builder_a.create_ty_with_subst(&large_type, &[]);
    assert!(result_a.is_ok()); // Success on validator A
    
    // Validator B rejects  
    let result_b = ty_builder_b.create_ty_with_subst(&large_type, &[]);
    assert!(result_b.is_err()); // Failure on validator B with TOO_MANY_TYPE_NODES
    
    // This divergence in type validation leads to different transaction
    // execution results and different state roots, breaking consensus
}
```

**Notes:**
- Complete PoC requires setting up full transaction execution environment
- Key demonstration: Same transaction produces different validation results with different `max_ty_size` values
- In production, this manifests as validators unable to agree on block commits

### Citations

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L246-265)
```rust
        let (gas_params, storage_gas_params, gas_feature_version) =
            get_gas_parameters(&mut sha3_256, &features, state_view);
        let (native_gas_params, misc_gas_params, ty_builder) = match &gas_params {
            Ok(gas_params) => {
                let ty_builder = aptos_prod_ty_builder(gas_feature_version, gas_params);
                (
                    gas_params.natives.clone(),
                    gas_params.vm.misc.clone(),
                    ty_builder,
                )
            },
            Err(_) => {
                let ty_builder = aptos_default_ty_builder();
                (
                    NativeGasParameters::zeros(),
                    MiscGasParameters::zeros(),
                    ty_builder,
                )
            },
        };
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L132-134)
```rust
pub fn aptos_default_ty_builder() -> TypeBuilder {
    TypeBuilder::with_limits(128, 20)
}
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L136-149)
```rust
    let ty_builder = &loader.runtime_environment().vm_config().ty_builder;

    // Need to keep this here to ensure we return the historic correct error code for replay
    for ty in func.param_tys()[signer_param_cnt..].iter() {
        let subst_res = ty_builder.create_ty_with_subst(ty, func.ty_args());
        let ty = subst_res.map_err(|e| e.finish(Location::Undefined).into_vm_status())?;
        let valid = is_valid_txn_arg(loader.runtime_environment(), &ty, allowed_structs);
        if !valid {
            return Err(VMStatus::error(
                StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE,
                None,
            ));
        }
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1195-1223)
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

    #[cold]
    fn too_many_nodes_error(&self) -> PartialVMResult<()> {
        Err(
            PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).with_message(format!(
                "Type size is larger than maximum {}",
                self.max_ty_size
            )),
        )
    }

    #[cold]
    fn too_large_depth_error(&self) -> PartialVMResult<()> {
        Err(
            PartialVMError::new(StatusCode::VM_MAX_TYPE_DEPTH_REACHED).with_message(format!(
                "Type depth is larger than maximum {}",
                self.max_ty_depth
            )),
        )
    }
```

**File:** consensus/consensus-types/src/vote_proposal.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{block::Block, vote_data::VoteData};
use aptos_crypto::hash::{TransactionAccumulatorHasher, ACCUMULATOR_PLACEHOLDER_HASH};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::{
    epoch_state::EpochState,
    proof::{accumulator::InMemoryTransactionAccumulator, AccumulatorExtensionProof},
};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// This structure contains all the information needed by safety rules to
/// evaluate a proposal / block for correctness / safety and to produce a Vote.
#[derive(Clone, Debug, CryptoHasher, Deserialize, BCSCryptoHash, Serialize)]
pub struct VoteProposal {
    /// Contains the data necessary to construct the parent's execution output state
    /// and the childs in a verifiable way
    accumulator_extension_proof: AccumulatorExtensionProof<TransactionAccumulatorHasher>,
    /// The block / proposal to evaluate
    #[serde(bound(deserialize = "Block: Deserialize<'de>"))]
    block: Block,
    /// An optional field containing the next epoch info.
    next_epoch_state: Option<EpochState>,
    /// Represents whether the executed state id is dummy or not.
    decoupled_execution: bool,
}

impl VoteProposal {
    pub fn new(
        accumulator_extension_proof: AccumulatorExtensionProof<TransactionAccumulatorHasher>,
        block: Block,
        next_epoch_state: Option<EpochState>,
        decoupled_execution: bool,
    ) -> Self {
        Self {
            accumulator_extension_proof,
            block,
            next_epoch_state,
            decoupled_execution,
        }
    }

    pub fn accumulator_extension_proof(
        &self,
    ) -> &AccumulatorExtensionProof<TransactionAccumulatorHasher> {
        &self.accumulator_extension_proof
    }

```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L23-46)
```rust
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
```
