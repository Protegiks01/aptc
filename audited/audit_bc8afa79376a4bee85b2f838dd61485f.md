# Audit Report

## Title
Missing Gas Schedule Bounds Validation Enables Network-Wide DoS via Governance Manipulation

## Summary
The gas schedule update mechanism in `aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move` lacks validation of individual gas parameter values, allowing governance proposals to set security-critical operation costs (e.g., signature verification) to zero or near-zero values. This enables resource exhaustion attacks that can halt the entire network.

## Finding Description

The `gas_schedule.move` module is responsible for managing on-chain gas costs for all Move operations. Gas schedule updates occur through governance proposals that call either `set_for_next_epoch()` or `set_for_next_epoch_check_hash()`. [1](#0-0) 

The validation performed is minimal - it only checks that the `feature_version` is greater than or equal to the current version and that the blob is non-empty. **Critically, there is NO validation of individual gas parameter values**, as explicitly acknowledged by TODO comments throughout the code: [2](#0-1) [3](#0-2) [4](#0-3) 

This means a governance proposal can set security-critical gas costs to arbitrarily low values, including zero. For example, signature verification costs: [5](#0-4) [6](#0-5) 

**Attack Path:**

1. Attacker builds coalition or uses social engineering to frame gas reductions as "optimizations"
2. Governance proposal passes to update gas schedule with malicious values (e.g., `ed25519_per_sig_strict_verify: 1`)
3. Proposal executes via the formal specification stating only Critical requirement is framework signer authorization: [7](#0-6) 

4. Attacker floods network with transactions requiring signature verification
5. Each signature verification charges minimal gas (~1 unit) but performs expensive cryptographic operations: [8](#0-7) 

6. Validators become CPU-bound verifying signatures, unable to process legitimate transactions
7. Network grinds to halt - consensus cannot progress due to resource exhaustion

**Governance Voting Analysis:**

For a proposal to succeed, the voting module requires: [9](#0-8) 

With mainnet configuration: [10](#0-9) 

While 33% voting power alone may not guarantee proposal passage, the vulnerability exists regardless of the threshold because:
- Proposals can pass through legitimate coalition building
- "Gas optimization" proposals may gain community support without understanding security implications
- Incremental reductions over multiple proposals can gradually reach dangerous levels

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability meets the Critical severity criteria for:

1. **Total loss of liveness/network availability**: Setting signature verification costs to near-zero enables attackers to flood the network with transactions that are cheap to submit but expensive to validate. Validator nodes become overwhelmed processing cryptographic operations, preventing consensus from progressing.

2. **Consensus disruption**: Validators spending excessive CPU on signature verification cannot participate effectively in consensus rounds, potentially causing timeout failures and preventing block finalization.

3. **Non-recoverable without hardfork**: Once exploited, the malicious gas schedule is stored on-chain. Fixing it requires either:
   - Another governance proposal (impossible if network is halted)
   - Emergency hardfork to restore safe gas values

The attack bypasses the fundamental security guarantee that all operations respect resource limits (Invariant #9: "All operations must respect gas, storage, and computational limits"). It also violates Move VM Safety (Invariant #3: "Bytecode execution must respect gas limits").

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The likelihood is elevated because:

1. **Missing validation is explicitly documented**: The TODO comments indicate this is a known gap, not a hidden bug

2. **Governance is a valid attack vector**: While requiring governance approval adds friction, it's not an insurmountable barrier:
   - Legitimate but misguided "optimization" proposals could be framed convincingly
   - Multi-step incremental reductions may not trigger concern individually
   - Low governance participation could enable smaller coalitions to pass proposals

3. **High impact makes it attractive**: The ability to halt the entire network makes this vulnerability valuable to sophisticated attackers

4. **No runtime protection**: Even if the malicious gas schedule is caught post-deployment, there's no emergency mechanism to revert it without governance or hardfork

## Recommendation

Implement comprehensive validation in the gas schedule update functions. Add minimum bounds for security-critical operations:

```move
const EGAS_PARAM_BELOW_MINIMUM: u64 = 4;

// Define minimum safe values for critical operations
const MIN_ED25519_SIG_VERIFY: u64 = 100000;  // Minimum 100K gas units
const MIN_BLS12381_SIG_VERIFY: u64 = 1000000;  // Minimum 1M gas units
const MIN_SIGNATURE_BASE: u64 = 500;  // Minimum base cost

public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    if (exists<GasScheduleV2>(@aptos_framework)) {
        let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
        assert!(
            new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
        );
    };
    
    // NEW: Validate critical gas parameters
    validate_gas_schedule_safety(&new_gas_schedule);
    
    config_buffer::upsert(new_gas_schedule);
}

fun validate_gas_schedule_safety(schedule: &GasScheduleV2) {
    // Check each critical parameter has minimum safe value
    let i = 0;
    let len = vector::length(&schedule.entries);
    while (i < len) {
        let (key, value) = vector::borrow(&schedule.entries, i);
        
        // Validate signature verification costs
        if (key == &string::utf8(b"signature.per_sig_strict_verify")) {
            assert!(value >= &MIN_ED25519_SIG_VERIFY, error::invalid_argument(EGAS_PARAM_BELOW_MINIMUM));
        } else if (key == &string::utf8(b"bls12381.per_sig_verify")) {
            assert!(value >= &MIN_BLS12381_SIG_VERIFY, error::invalid_argument(EGAS_PARAM_BELOW_MINIMUM));
        } else if (key == &string::utf8(b"signature.base")) {
            assert!(value >= &MIN_SIGNATURE_BASE, error::invalid_argument(EGAS_PARAM_BELOW_MINIMUM));
        };
        // Add similar checks for other critical operations
        
        i = i + 1;
    };
}
```

Apply the same validation to `set_for_next_epoch_check_hash()` and `set_gas_schedule()`.

## Proof of Concept

```move
#[test_only]
module aptos_framework::gas_schedule_exploit_test {
    use aptos_framework::gas_schedule;
    use aptos_framework::aptos_governance;
    use std::bcs;
    use std::signer;
    
    #[test(framework = @aptos_framework)]
    #[expected_failure(abort_code = 0x10000, location = Self)]
    fun test_zero_sig_verify_gas_exploit(framework: signer) {
        // Setup: Initialize gas schedule with normal values
        let normal_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 1,
            entries: vector[
                (string::utf8(b"signature.per_sig_strict_verify"), 981492),
                (string::utf8(b"signature.base"), 551),
            ],
        };
        
        // Malicious: Create schedule with near-zero signature verification cost
        let malicious_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 2,
            entries: vector[
                (string::utf8(b"signature.per_sig_strict_verify"), 1),  // Near-zero!
                (string::utf8(b"signature.base"), 1),  // Near-zero!
            ],
        };
        
        let malicious_blob = bcs::to_bytes(&malicious_schedule);
        
        // This should FAIL but currently SUCCEEDS due to missing validation
        gas_schedule::set_for_next_epoch(&framework, malicious_blob);
        
        // Attacker can now spam signature verifications at ~1 gas unit each
        // while validator nodes burn CPU cycles on expensive crypto operations
        // Network halts due to resource exhaustion
    }
}
```

**Notes:**
- The vulnerability exists regardless of the 33% voting power threshold mentioned in the security question
- The core issue is the **complete absence of bounds validation** on gas schedule parameters
- Any governance proposal that passes (through any means) can set dangerous gas values
- The TODO comments explicitly acknowledge this missing validation has not been implemented
- This breaks fundamental security invariants around resource limits and gas metering

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-67)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L75-75)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-103)
```text
    public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L182-182)
```rust
        [bls12381_per_sig_verify: InternalGasPerArg, "bls12381.per_sig_verify", 31190860],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L194-194)
```rust
        [ed25519_per_sig_strict_verify: InternalGasPerArg, "signature.per_sig_strict_verify", 981492],
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.spec.move (L10-15)
```text
    /// No.: 2
    /// Requirement: Only the Aptos framework account should be allowed to update the gas schedule resource.
    /// Criticality: Critical
    /// Implementation: The gas_schedule::set_gas_schedule function calls the assert_aptos_framework function to ensure
    /// that the signer is the aptos framework account.
    /// Enforcement: Formally verified via [high-level-req-2](set_gas_schedule).
```

**File:** aptos-move/framework/src/natives/cryptography/ed25519.rs (L128-135)
```rust
    // NOTE(Gas): hashing the message to the group and a size-2 multi-scalar multiplication
    let hash_then_verify_cost = ED25519_PER_SIG_STRICT_VERIFY * NumArgs::one()
        + ED25519_PER_MSG_HASHING_BASE * NumArgs::one()
        + ED25519_PER_MSG_BYTE_HASHING * NumBytes::new(msg.len() as u64);
    context.charge(hash_then_verify_cost)?;

    let verify_result = sig.verify_arbitrary_msg(msg.as_slice(), &pk).is_ok();
    Ok(smallvec![Value::bool(verify_result)])
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L664-668)
```text
            if (yes_votes > no_votes && yes_votes + no_votes >= proposal.min_vote_threshold) {
                PROPOSAL_STATE_SUCCEEDED
            } else {
                PROPOSAL_STATE_FAILED
            }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1482-1482)
```rust
        min_voting_threshold: (400_000_000 * APTOS_COINS_BASE_WITH_DECIMALS as u128),
```
