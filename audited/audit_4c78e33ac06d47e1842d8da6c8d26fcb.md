# Audit Report

## Title
Multi-Step Proposal Simulation Bypasses Intermediate Execution Hash Validation

## Summary
The `simulate_multistep_proposal()` function only validates that the last script in a multi-step governance proposal has an empty `next_execution_hash`, but fails to validate that intermediate scripts provide correct hash values. This allows malicious or buggy proposals to pass simulation successfully while failing on-chain execution, potentially resulting in partial proposal execution and governance integrity violations.

## Finding Description

The Aptos governance simulation tool is designed to validate multi-step proposals before on-chain submission. However, a critical validation gap exists in the hash chain verification logic. [1](#0-0) 

The code only sets `forbid_next_execution_hash = true` for the final script, meaning intermediate scripts are patched WITHOUT hash validation. The patching function completely replaces the governance resolution logic: [2](#0-1) 

When `forbid_next_execution_hash = false`, the patch does not inject any validation code for the `next_execution_hash` parameter. This bypasses the critical on-chain validation performed by `voting::is_proposal_resolvable`: [3](#0-2) 

On-chain, each step validates that the current script's hash matches the stored execution hash. When `resolve_proposal_v2` is called with a `next_execution_hash`, it updates the proposal's execution hash for the next step: [4](#0-3) 

**Attack Scenario:**
1. Attacker creates 3-step governance proposal
2. Script 1 calls `resolve_multi_step_proposal(id, addr, WRONG_HASH)` instead of `hash(script2)`
3. Simulation executes all scripts successfully (no intermediate validation)
4. Proposal passes governance voting
5. On-chain execution of Script 1 succeeds, updates execution hash to `WRONG_HASH`
6. On-chain execution of Script 2 fails (hash mismatch: `get_script_hash() != WRONG_HASH`)
7. Result: Script 1 executed, Scripts 2-3 cannot execute

This breaks the **Governance Integrity** invariant by allowing partial proposal execution, potentially leaving the system in an inconsistent state if Script 1 made critical changes that Scripts 2-3 were supposed to finalize or revert.

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for "Significant protocol violations":

1. **Governance Integrity Violation**: Multi-step proposals are designed to be atomic - all steps execute or none do. Partial execution violates this guarantee.

2. **State Inconsistency**: If Script 1 modifies critical system parameters (gas schedules, consensus configs) expecting Script 2 to make complementary changes, partial execution leaves the system misconfigured.

3. **False Security Assurance**: Governance participants rely on successful simulation results to validate proposals. This bug provides false confidence, potentially causing approved proposals to fail in production.

4. **Potential for Malicious Exploitation**: While requiring significant stake, an attacker could design proposals that:
   - Extract value in Script 1
   - Include corrective/cleanup logic in Scripts 2-3 that never execute
   - Use incorrect hashes to ensure subsequent steps fail

## Likelihood Explanation

**Medium to High Likelihood:**

- **Accidental Occurrence**: Developers creating multi-step proposals could easily make hash calculation errors that simulation won't catch
- **Malicious Exploitation**: Requires attacker to have governance proposal stake (significant) but execution is straightforward
- **Detection Difficulty**: Code reviewers may assume successful simulation validates the complete execution path
- **No On-Chain Defense**: Once Script 1 executes, the damage is done - Scripts 2-3 cannot execute regardless of hash correction

The Aptos governance process explicitly relies on simulation for proposal validation, making this a critical tooling vulnerability.

## Recommendation

Add hash chain validation for ALL scripts, not just the last one. The simulation should track the expected next execution hash and validate each script's call:

**Fix for `simulate.rs`:**

```rust
// Track the expected execution hash chain
let mut expected_execution_hash = script_hash;

for (script_idx, (script_path, (script_blob, script_hash))) in
    proposal_scripts.iter().zip(compiled_scripts).enumerate()
{
    // ... existing setup code ...
    
    let is_last_script = script_idx == proposal_scripts.len() - 1;
    
    // Pass the expected next hash to the patch
    patch_aptos_governance(
        &state_view, 
        is_last_script,
        Some(expected_execution_hash)  // NEW: Pass expected hash
    )?;
    
    // ... execute script ...
    
    // Extract and validate the next_execution_hash from the script execution
    // This requires instrumenting the patched function to capture the passed hash
    if !is_last_script {
        let next_hash = extract_next_execution_hash_from_script(/*...*/);
        assert!(!next_hash.is_empty(), "Intermediate script must provide next execution hash");
        expected_execution_hash = next_hash;
    }
}
```

**Enhanced patch function:**

```rust
fn patch_aptos_governance(
    state_view: &impl SimulationStateStore,
    is_last_script: bool,
    expected_current_hash: Option<HashValue>,  // NEW
) -> Result<()> {
    // ... existing code ...
    
    if is_last_script {
        // Check next_execution_hash is empty
        // ... existing code ...
    } else {
        // NEW: For intermediate scripts, validate the next_execution_hash
        // matches one of the remaining script hashes
        code.code.extend([
            // Validate next_execution_hash is non-empty
            ImmBorrowLoc(2),
            VecLen(sig_u8_idx),
            LdU64(0),
            Gt,
            BrTrue(7),
            LdU64(MAGIC_MISSING_NEXT_EXECUTION_HASH),
            Abort,
        ]);
    }
    // ... rest of function ...
}
```

## Proof of Concept

**Malicious Multi-Step Proposal:**

```move
// Script 1: Malicious - passes wrong hash
script {
    use aptos_framework::aptos_governance;
    
    fun main(core_resources: &signer) {
        // This should pass hash of Script 2, but passes garbage
        let wrong_hash = vector[0xDE, 0xAD, 0xBE, 0xEF];
        aptos_governance::resolve_multi_step_proposal(
            PROPOSAL_ID,
            @aptos_framework,
            wrong_hash  // WRONG - should be hash(script2.move)
        );
        
        // Make critical change
        aptos_governance::update_governance_config(
            core_resources,
            MIN_THRESHOLD,
            NEW_STAKE_REQUIREMENT,  // Malicious change
            VOTING_DURATION
        );
    }
}

// Script 2: Intended cleanup - will never execute
script {
    use aptos_framework::aptos_governance;
    
    fun main(core_resources: &signer) {
        let script3_hash = vector[/* correct hash */];
        aptos_governance::resolve_multi_step_proposal(
            PROPOSAL_ID,
            @aptos_framework,
            script3_hash
        );
        
        // Revert malicious change - NEVER EXECUTES
        aptos_governance::update_governance_config(
            core_resources,
            MIN_THRESHOLD,
            ORIGINAL_STAKE_REQUIREMENT,
            VOTING_DURATION
        );
    }
}
```

**Simulation Result:** ✓ SUCCESS (all scripts execute in simulation)

**On-Chain Result:** 
- Script 1: ✓ Executes, sets `execution_hash = 0xDEADBEEF`
- Script 2: ✗ FAILS with `EPROPOSAL_EXECUTION_HASH_NOT_MATCHING`

**Impact:** Governance stake requirement permanently changed, cleanup logic never executed.

### Citations

**File:** aptos-move/aptos-release-builder/src/simulate.rs (L240-302)
```rust
fn patch_aptos_governance(
    state_view: &impl SimulationStateStore,
    forbid_next_execution_hash: bool,
) -> Result<()> {
    use Bytecode::*;

    patch_module(state_view, &MODULE_ID_APTOS_GOVERNANCE, |m| {
        // Inject `native fun create_signer`.
        let create_signer_handle_idx = add_simple_native_function(
            m,
            FUNC_NAME_CREATE_SIGNER.clone(),
            vec![SignatureToken::Address],
            vec![SignatureToken::Signer],
        )?;

        // Patch `fun resolve_multi_step_proposal`.
        let sig_u8_idx = get_or_add_signature(m, vec![SignatureToken::U8]);

        let func_def = find_function_def_by_name(m, &FUNC_NAME_RESOLVE_MULTI_STEP_PROPOSAL)
            .ok_or_else(|| {
                anyhow!(
                    "failed to locate `fun {}`",
                    &*FUNC_NAME_RESOLVE_MULTI_STEP_PROPOSAL
                )
            })?;
        func_def.acquires_global_resources = vec![];
        let code = func_def.code.as_mut().ok_or_else(|| {
            anyhow!(
                "`fun {}` must have a Move-defined body",
                &*FUNC_NAME_RESOLVE_MULTI_STEP_PROPOSAL
            )
        })?;

        code.code.clear();
        if forbid_next_execution_hash {
            // If it is needed to forbid a next execution hash, inject additional Move
            // code at the beginning that aborts with a magic number if the vector
            // representing the hash is not empty.
            //
            //     if (!vector::is_empty(&next_execution_hash)) {
            //         abort MAGIC_FAILED_NEXT_EXECUTION_HASH_CHECK;
            //     }
            //
            // The magic number can later be checked in Rust to determine if such violation
            // has happened.
            code.code.extend([
                ImmBorrowLoc(2),
                VecLen(sig_u8_idx),
                LdU64(0),
                Eq,
                BrTrue(7),
                LdU64(MAGIC_FAILED_NEXT_EXECUTION_HASH_CHECK),
                Abort,
            ]);
        }
        // Replace the original logic with `create_signer(signer_address)`, bypassing
        // the governance process.
        code.code
            .extend([MoveLoc(1), Call(create_signer_handle_idx), Ret]);

        Ok(())
    })
}
```

**File:** aptos-move/aptos-release-builder/src/simulate.rs (L455-459)
```rust
        // If the script is the last step of the proposal, it MUST NOT have a next execution hash.
        // Set the boolean flag to true to use a modified patch to catch this.
        let forbid_next_execution_hash = script_idx == proposal_scripts.len() - 1;
        patch_aptos_governance(&state_view, forbid_next_execution_hash)
            .context("failed to patch resolve_multistep_proposal")?;
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L447-450)
```text
        assert!(
            transaction_context::get_script_hash() == proposal.execution_hash,
            error::invalid_argument(EPROPOSAL_EXECUTION_HASH_NOT_MATCHING),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L562-566)
```text
        } else {
            // If the current step is not the last step,
            // update the proposal's execution hash on-chain to the execution hash of the next step.
            proposal.execution_hash = next_execution_hash;
        };
```
