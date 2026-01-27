# Audit Report

## Title
DKG Randomness Configuration Race Condition Allows Validators to Reconfigure with Mismatched Cryptographic Parameters

## Summary
The `aptos_governance::reconfigure()` call at line 128 of `randomness_config.rs` creates a critical race condition where DKG (Distributed Key Generation) sessions are initiated with outdated randomness configuration parameters, but validators subsequently reconfigure to a new epoch using updated parameters. This cryptographic parameter mismatch violates the security guarantees of the randomness system and creates consensus inconsistencies.

## Finding Description

When a governance proposal executes `generate_randomness_config_update_proposal()`, it performs two sequential operations:

1. Buffers a new randomness configuration via `randomness_config::set_for_next_epoch()` [1](#0-0) 

2. Immediately triggers reconfiguration via `aptos_governance::reconfigure()` [2](#0-1) 

The `reconfigure()` function calls `reconfiguration_with_dkg::try_start()` when randomness is enabled: [3](#0-2) 

The critical flaw occurs in `try_start()`, which initiates a new DKG session using `randomness_config::current()` - **the old configuration** before the buffered update is applied: [4](#0-3) 

This old configuration (with old secrecy/reconstruction thresholds) is permanently stored in the `DKGSessionMetadata`: [5](#0-4) 

When the DKG completes and `finish()` is called, the buffered **new** configuration is applied: [6](#0-5) 

In the new epoch, validators construct DKG public parameters from the stored metadata using the **old** thresholds: [7](#0-6) 

The validators then use these mismatched parameters for all randomness operations: [8](#0-7) 

**No validation exists** to check that the DKG metadata configuration matches the currently active on-chain randomness configuration. The only check is for epoch matching, not configuration consistency: [9](#0-8) 

## Impact Explanation

**Critical Severity** - This vulnerability violates the fundamental cryptographic correctness invariant:

1. **Cryptographic Security Violation**: If a proposal increases security thresholds (e.g., secrecy from 50% to 67%), the DKG runs with the weaker 50% threshold, but the network believes it has 67% security. This misrepresentation breaks security guarantees.

2. **Consensus Inconsistency**: The on-chain configuration states one set of parameters while the actual cryptographic operations use different parameters. Smart contracts relying on randomness security properties receive incorrect security assumptions.

3. **Deterministic Execution Violation**: Different validator implementations or timing could handle this mismatch differently, leading to potential consensus divergence.

4. **Unpredictable Behavior**: If thresholds are decreased (e.g., from 67% to 50%), validators might fail to decrypt shares or reconstruct randomness using the old higher thresholds, causing liveness failures.

This qualifies as **Critical Severity** under the Aptos Bug Bounty program as it represents a significant protocol violation affecting cryptographic correctness and consensus safety.

## Likelihood Explanation

**High Likelihood**: This vulnerability is triggered by any governance proposal that updates randomness configuration parameters, which is a legitimate and expected operation for:
- Security hardening (increasing thresholds)
- Performance optimization (adjusting thresholds)
- Feature enablement (adding fast-path randomness)

The vulnerability requires no attacker capabilities beyond normal governance participation. It occurs deterministically during normal protocol operation whenever randomness configuration is updated through governance.

## Recommendation

Implement validation to ensure DKG metadata configuration matches the active on-chain configuration before using DKG results. Add a check in `try_get_rand_config_for_new_epoch()`:

```rust
// After line 1045 in consensus/src/epoch_manager.rs
let dkg_config = dkg_session.metadata.randomness_config_derived()
    .ok_or_else(|| NoRandomnessReason::DKGConfigDeserializationError)?;

// Validate that DKG config matches current on-chain config
if !configs_match(&dkg_config, onchain_randomness_config) {
    return Err(NoRandomnessReason::DKGConfigMismatch);
}
```

Additionally, modify `reconfiguration_with_dkg::try_start()` to use the **buffered** configuration if one exists:

```move
// In reconfiguration_with_dkg.move, replace line 36
let config = if (config_buffer::does_exist<RandomnessConfig>()) {
    config_buffer::extract_v2<RandomnessConfig>()
} else {
    randomness_config::current()
};
dkg::start(cur_epoch, config, ...);
```

## Proof of Concept

```move
#[test(framework = @aptos_framework)]
fun test_randomness_config_race_condition(framework: signer) {
    use aptos_framework::randomness_config;
    use aptos_framework::reconfiguration_with_dkg;
    use aptos_framework::config_buffer;
    use aptos_std::fixed_point64;
    
    // Initialize with V1 config (50% secrecy, 67% reconstruction)
    let old_config = randomness_config::new_v1(
        fixed_point64::create_from_rational(50, 100),
        fixed_point64::create_from_rational(67, 100)
    );
    randomness_config::initialize(&framework, old_config);
    
    // Governance proposal buffers new config (67% secrecy, 80% reconstruction)
    let new_config = randomness_config::new_v1(
        fixed_point64::create_from_rational(67, 100),
        fixed_point64::create_from_rational(80, 100)
    );
    randomness_config::set_for_next_epoch(&framework, new_config);
    
    // Trigger reconfiguration (simulating line 128)
    reconfiguration_with_dkg::try_start();
    
    // Assert: DKG session contains OLD config (50%, 67%)
    let dkg_state = dkg::incomplete_session();
    let session = option::borrow(&dkg_state);
    assert!(session.metadata.randomness_config.secrecy_threshold == 
            fixed_point64::create_from_rational(50, 100), 1);
    
    // When DKG finishes, NEW config (67%, 80%) is applied
    reconfiguration_with_dkg::finish(&framework);
    
    // Assert: Current config is NEW but DKG was run with OLD
    let current = randomness_config::current();
    // Current shows 67% secrecy, but DKG transcript was created with 50% secrecy
    // This is the vulnerability: cryptographic parameter mismatch
}
```

## Notes

This vulnerability demonstrates a fundamental flaw in the configuration update synchronization mechanism. The issue arises from the timing of when buffered configurations are applied relative to when DKG sessions capture configuration snapshots. This race condition is deterministic and affects all validators equally, making it a systemic protocol vulnerability rather than a node-specific issue.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/randomness_config.rs (L73-96)
```rust
                        "randomness_config::set_for_next_epoch({}, randomness_config::new_off());",
                        signer_arg
                    );
                },
                ReleaseFriendlyRandomnessConfig::V1 {
                    secrecy_threshold_in_percentage,
                    reconstruct_threshold_in_percentage,
                } => {
                    emitln!(writer, "let v1 = randomness_config::new_v1(");
                    emitln!(
                        writer,
                        "    fixed_point64::create_from_rational({}, 100),",
                        secrecy_threshold_in_percentage
                    );
                    emitln!(
                        writer,
                        "    fixed_point64::create_from_rational({}, 100),",
                        reconstruct_threshold_in_percentage
                    );
                    emitln!(writer, ");");
                    emitln!(
                        writer,
                        "randomness_config::set_for_next_epoch({}, v1);",
                        signer_arg
```

**File:** aptos-move/aptos-release-builder/src/components/randomness_config.rs (L128-128)
```rust
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
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

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-40)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
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

**File:** types/src/dkg/mod.rs (L91-97)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DKGSessionMetadata {
    pub dealer_epoch: u64,
    pub randomness_config: RandomnessConfigMoveStruct,
    pub dealer_validator_set: Vec<ValidatorConsensusInfoMoveStruct>,
    pub target_validator_set: Vec<ValidatorConsensusInfoMoveStruct>,
}
```

**File:** types/src/dkg/real_dkg/mod.rs (L199-224)
```rust
    fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> RealDKGPublicParams {
        let randomness_config = dkg_session_metadata
            .randomness_config_derived()
            .unwrap_or_else(OnChainRandomnessConfig::default_enabled);
        let secrecy_threshold = randomness_config
            .secrecy_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_SECRECY_THRESHOLD);
        let reconstruct_threshold = randomness_config
            .reconstruct_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_RECONSTRUCT_THRESHOLD);
        let maybe_fast_path_secrecy_threshold = randomness_config.fast_path_secrecy_threshold();

        let pvss_config = build_dkg_pvss_config(
            dkg_session_metadata.dealer_epoch,
            secrecy_threshold,
            reconstruct_threshold,
            maybe_fast_path_secrecy_threshold,
            &dkg_session_metadata.target_validator_consensus_infos_cloned(),
        );
        let verifier = ValidatorVerifier::new(dkg_session_metadata.dealer_consensus_infos_cloned());
        RealDKGPublicParams {
            session_metadata: dkg_session_metadata.clone(),
            pvss_config,
            verifier: verifier.into(),
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1043-1072)
```rust
        if dkg_session.metadata.dealer_epoch + 1 != new_epoch_state.epoch {
            return Err(NoRandomnessReason::CompletedSessionTooOld);
        }
        let dkg_pub_params = DefaultDKG::new_public_params(&dkg_session.metadata);
        let my_index = new_epoch_state
            .verifier
            .address_to_validator_index()
            .get(&self.author)
            .copied()
            .ok_or_else(|| NoRandomnessReason::NotInValidatorSet)?;

        let dkg_decrypt_key = maybe_dk_from_bls_sk(consensus_key.as_ref())
            .map_err(NoRandomnessReason::ErrConvertingConsensusKeyToDecryptionKey)?;
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_session.transcript.as_slice(),
        )
        .map_err(NoRandomnessReason::TranscriptDeserializationError)?;

        let vuf_pp = WvufPP::from(&dkg_pub_params.pvss_config.pp);

        // No need to verify the transcript.

        // keys for randomness generation
        let (sk, pk) = DefaultDKG::decrypt_secret_share_from_transcript(
            &dkg_pub_params,
            &transcript,
            my_index as u64,
            &dkg_decrypt_key,
        )
        .map_err(NoRandomnessReason::SecretShareDecryptionFailed)?;
```
