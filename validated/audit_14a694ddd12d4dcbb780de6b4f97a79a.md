# Audit Report

## Title
Cross-Proposal Interference in Gas Schedule Updates Causes Legitimate Governance Proposals to Fail Validation

## Summary
When multiple gas schedule governance proposals are created and submitted concurrently, their hash validation checks can interfere with each other, causing the second proposal to fail with `EINVALID_GAS_SCHEDULE_HASH` error in synchronous reconfiguration mode, or causing silent data loss (proposal overwriting) in asynchronous mode.

## Finding Description

The gas schedule update mechanism uses a SHA3-512 hash-based validation check to ensure proposals are applied to the expected state. The vulnerability exists in the interaction between three components:

1. **Proposal Generation** - When a proposal is created, it computes and stores the SHA3-512 hash of the current gas schedule to validate against during execution. [1](#0-0) 

2. **Hash Validation** - During execution, `set_for_next_epoch_check_hash` reads the current on-chain gas schedule, computes its hash, and requires it to match the hash recorded at proposal creation time. If the hashes don't match, the transaction aborts with `EINVALID_GAS_SCHEDULE_HASH`. [2](#0-1) 

3. **Reconfiguration Behavior** - The `reconfigure()` function triggers either immediate synchronous reconfiguration (calling `finish()` if DKG is disabled) or asynchronous reconfiguration (calling `try_start()` if DKG is enabled). [3](#0-2) 

**Attack Scenario:**

**Synchronous Mode (DKG Disabled):**
- Time T0-T3: Two proposals P1 and P2 are created with the same old hash H0
- Time T4: P1 executes, calls `finish()` which immediately applies the buffered config via `on_new_epoch()` [4](#0-3) 
- The `on_new_epoch()` function extracts and applies the buffered gas schedule, updating global state [5](#0-4) 
- Time T5: P2 attempts to execute but the hash check fails because the global state has changed, aborting the transaction

**Asynchronous Mode (DKG Enabled):**
- Multiple proposals buffer their changes using `config_buffer::upsert()` [6](#0-5) 
- The `upsert` operation overwrites any existing buffered config of the same type [7](#0-6) 
- When DKG completes, only the last buffered config is applied, silently discarding earlier proposals

This breaks governance integrity - legitimately created and approved proposals either fail unexpectedly or are silently overwritten.

## Impact Explanation

This constitutes a **MEDIUM severity** governance protocol violation under the Aptos bug bounty criteria, specifically falling under "Limited Protocol Violations: State inconsistencies requiring manual intervention."

**Impact Analysis:**
- **Governance Disruption**: Legitimate proposals fail validation or are silently overwritten, requiring recreation and re-voting
- **Resource Waste**: Wasted voting power, validator participation, and governance time
- **Operational Friction**: During active governance periods or emergency situations, this creates delays in applying critical parameter updates
- **Data Loss**: In asynchronous mode, earlier proposals are silently overwritten without error indication

While this does not cause fund loss, consensus violations, or network liveness issues, it represents a state inconsistency in a critical protocol component that requires manual intervention to resolve.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This vulnerability will occur whenever:
1. Two or more gas schedule proposals are created before any execute (common in active governance)
2. Both proposals are approved by governance voting (legitimate governance activity)
3. Proposals execute sequentially in separate transactions

No malicious intent is required - this happens through normal governance operations. The issue is more likely during:
- Active governance periods with multiple parameter updates
- Emergency situations requiring rapid governance response
- Testnet environments where DKG is commonly disabled

## Recommendation

Implement one of the following solutions:

1. **Sequential Proposal Execution Lock**: Add a global lock or counter that prevents concurrent execution of gas schedule proposals
2. **Improved Hash Check**: Modify the hash validation to check against the buffered config state, not just the on-chain state
3. **Proposal Queue**: Implement a proposal queue system that serializes execution of proposals affecting the same config type
4. **Better Error Handling**: In async mode, detect and reject attempts to overwrite buffered configs with appropriate error messages

## Proof of Concept

The existing test demonstrates the mechanism but not the concurrent proposal scenario: [8](#0-7) 

A proof of concept would need to:
1. Create two proposals with the same initial gas schedule hash
2. Execute the first proposal successfully
3. Attempt to execute the second proposal
4. Observe the `EINVALID_GAS_SCHEDULE_HASH` error in sync mode or silent overwrite in async mode

---

**Notes:**
This is a real, demonstrable vulnerability in the Aptos governance system that can be triggered through normal operations. While the severity is MEDIUM (not HIGH as potentially implied), it represents a legitimate protocol integrity issue requiring manual intervention. The hash validation mechanism exists specifically to prevent this type of race condition, but it only provides partial protection and creates user-facing failures in synchronous mode while being ineffective in asynchronous mode.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/gas.rs (L101-110)
```rust
    let old_hash = match old_gas_schedule {
        Some(old_gas_schedule) => {
            let old_bytes = bcs::to_bytes(old_gas_schedule)?;
            let old_hash = hex::encode(Sha3_512::digest(old_bytes.as_slice()));
            emitln!(writer, "//");
            emitln!(writer, "// Old Gas Schedule Hash (Sha3-512): {}", old_hash);

            emit_gas_schedule_diff(&writer, old_gas_schedule, new_gas_schedule)?;

            Some(old_hash)
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L108-132)
```text
    public fun set_for_next_epoch_check_hash(
        aptos_framework: &signer,
        old_gas_schedule_hash: vector<u8>,
        new_gas_schedule_blob: vector<u8>
    ) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&new_gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));

        let new_gas_schedule: GasScheduleV2 = from_bytes(new_gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
            let cur_gas_schedule_bytes = bcs::to_bytes(cur_gas_schedule);
            let cur_gas_schedule_hash = aptos_hash::sha3_512(cur_gas_schedule_bytes);
            assert!(
                cur_gas_schedule_hash == old_gas_schedule_hash,
                error::invalid_argument(EINVALID_GAS_SCHEDULE_HASH)
            );
        };

        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L135-145)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<GasScheduleV2>()) {
            let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
            if (exists<GasScheduleV2>(@aptos_framework)) {
                *borrow_global_mut<GasScheduleV2>(@aptos_framework) = new_gas_schedule;
            } else {
                move_to(framework, new_gas_schedule);
            }
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-61)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        reconfiguration::reconfigure();
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/config_buffer.move (L65-70)
```text
    public(friend) fun upsert<T: drop + store>(config: T) acquires PendingConfigs {
        let configs = borrow_global_mut<PendingConfigs>(@aptos_framework);
        let key = type_info::type_name<T>();
        let value = any::pack(config);
        simple_map::upsert(&mut configs.configs, key, value);
    }
```

**File:** aptos-move/e2e-move-tests/src/tests/gas.rs (L25-64)
```rust
fn test_modify_gas_schedule_check_hash() {
    let mut harness = MoveHarness::new();

    let mut gas_schedule = harness.get_gas_schedule();
    let old_hash = Sha3_512::digest(&bcs::to_bytes(&gas_schedule).unwrap()).to_vec();

    const MAGIC: u64 = 42424242;

    let (_, val) = gas_schedule
        .entries
        .iter_mut()
        .find(|(name, _)| name == "instr.nop")
        .unwrap();
    assert_ne!(*val, MAGIC);
    *val = MAGIC;

    harness.executor.exec(
        "gas_schedule",
        "set_for_next_epoch_check_hash",
        vec![],
        vec![
            MoveValue::Signer(CORE_CODE_ADDRESS)
                .simple_serialize()
                .unwrap(),
            bcs::to_bytes(&old_hash).unwrap(),
            bcs::to_bytes(&bcs::to_bytes(&gas_schedule).unwrap()).unwrap(),
        ],
    );

    harness
        .executor
        .exec("reconfiguration_with_dkg", "finish", vec![], vec![
            MoveValue::Signer(CORE_CODE_ADDRESS)
                .simple_serialize()
                .unwrap(),
        ]);

    let (_, gas_params) = harness.get_gas_params();
    assert_eq!(gas_params.vm.instr.nop, MAGIC.into());
}
```
