# Audit Report

## Title
Race Condition During Consensus Key Rotation Causes ValidatorKeyNotFound and Consensus Disruption

## Summary
A timing-dependent vulnerability exists in the consensus key rotation mechanism where legitimate validator keys can trigger `ValidatorKeyNotFound` errors during epoch transitions, causing affected validators to be unable to participate in consensus. This occurs when the on-chain validator set updates with a new public key before the corresponding private key is stored in the validator's secure storage, creating a critical window where epoch transitions cause consensus participation failure.

## Finding Description

The vulnerability manifests in the key reconciliation logic during SafetyRules initialization at epoch boundaries. When a validator rotates their consensus key, two separate state updates must occur:

1. **On-chain update**: The `rotate_consensus_key` function updates the validator's public key in the `ValidatorConfig` resource [1](#0-0) 

2. **Off-chain update**: The new private key must be stored in secure storage with the format `consensus_key_{public_key_hex}` [2](#0-1) 

**The Race Condition:**

During epoch transition, `SafetyRules::guarded_initialize()` attempts to load the consensus key matching the new epoch's validator set. The key lookup in `consensus_sk_by_pk()` follows this logic: [3](#0-2) 

If the epoch transition occurs before the operator stores the new private key:
1. The explicit key lookup for `consensus_key_{new_pk_hex}` fails
2. The function falls back to `default_consensus_sk()` which returns the old private key
3. The validation check `if key.public_key() != pk` fails because old_sk doesn't match new_pk
4. Returns `SecureStorageMissingDataError`, converted to `ValidatorKeyNotFound` [4](#0-3) 

When initialization fails with `ValidatorKeyNotFound`, the error handler sets `validator_signer = None`: [5](#0-4) 

Subsequently, all consensus operations (signing proposals, votes, timeouts) fail because `signer()` returns `NotInitialized` error: [6](#0-5) 

The `MetricsSafetyRules::retry()` mechanism catches `NotInitialized` and attempts re-initialization, but this triggers `ValidatorKeyNotFound` again, which is **NOT** in the retry list: [7](#0-6) 

The validator remains unable to participate in consensus for the entire epoch, requiring manual intervention.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

**Consensus Liveness Risk:**
- Single validator affected: Reduced voting power, but consensus continues if >2/3 remain active
- Multiple validators affected simultaneously: If a coordinated key rotation (e.g., security incident response) causes >1/3 validators to hit this race condition, consensus liveness fails
- Network partition risk if validators remain stuck across epoch boundaries

**Operational Impact:**
- Validator cannot sign blocks, votes, or timeout certificates
- Lost staking rewards for affected epoch(s)
- Requires manual intervention: store correct key + node restart
- No automatic recovery mechanism within the epoch

The vulnerability is confirmed by the test case that explicitly validates this behavior: [8](#0-7) 

## Likelihood Explanation

**Medium-High likelihood** in the following scenarios:

1. **Operator Error**: Validators who submit on-chain key rotation before updating local storage
2. **Automated Systems**: Configuration management tools with deployment lag between on-chain and off-chain updates
3. **Emergency Rotations**: Security incidents requiring rapid coordinated key rotation across multiple validators
4. **Staging/Production Mismatch**: Incorrect deployment sequences in multi-environment setups

The test from the smoke test suite shows the expected sequence: stop node → generate new key → update config with new key → restart node → submit on-chain rotation → wait for epoch transition: [9](#0-8) 

However, operators may not follow this exact sequence, especially under time pressure.

## Recommendation

**Immediate Mitigation:**

1. **Add ValidatorKeyNotFound to retry list** in `metrics_safety_rules.rs` to enable automatic recovery if the key becomes available:

```rust
fn retry<T, F: FnMut(&mut Box<dyn TSafetyRules + Send + Sync>) -> Result<T, Error>>(
    &mut self,
    mut f: F,
) -> Result<T, Error> {
    let result = f(&mut self.inner);
    match result {
        Err(Error::NotInitialized(_))
        | Err(Error::IncorrectEpoch(_, _))
        | Err(Error::WaypointOutOfDate(_, _, _, _))
        | Err(Error::ValidatorKeyNotFound(_))  // ADD THIS LINE
        => {
            self.perform_initialize()?;
            f(&mut self.inner)
        },
        _ => result,
    }
}
```

2. **Add grace period check** in `consensus_sk_by_pk()` to poll for new key with exponential backoff before failing:

```rust
pub fn consensus_sk_by_pk(
    &self,
    pk: bls12381::PublicKey,
) -> Result<bls12381::PrivateKey, Error> {
    let pk_hex = hex::encode(pk.to_bytes());
    let explicit_storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
    
    // Try multiple times with backoff for new key rotation scenarios
    let mut attempts = 3;
    let mut delay_ms = 100;
    
    while attempts > 0 {
        if let Ok(sk) = self.internal_store
            .get::<bls12381::PrivateKey>(explicit_storage_key.as_str())
            .map(|v| v.value) 
        {
            if sk.public_key() == pk {
                return Ok(sk);
            }
        }
        
        if attempts > 1 {
            std::thread::sleep(Duration::from_millis(delay_ms));
            delay_ms *= 2;
            attempts -= 1;
        } else {
            break;
        }
    }
    
    // Existing fallback logic...
    let default_sk = self.default_consensus_sk();
    // ... rest of function
}
```

3. **Operator tooling**: Add pre-flight checks in `aptos` CLI to verify private key storage before submitting on-chain rotation

## Proof of Concept

The existing test demonstrates the vulnerability: [8](#0-7) 

**Reproduction steps:**

1. Validator has consensus key pair (pk_old, sk_old) in epoch N
2. Operator generates new key pair (pk_new, sk_new)
3. Operator submits on-chain `rotate_consensus_key(pk_new)` transaction
4. Transaction commits, updating ValidatorConfig
5. **Epoch N+1 begins before sk_new is stored in secure storage**
6. SafetyRules initialization calls `consensus_sk_by_pk(pk_new)`
7. Explicit key not found, falls back to default (sk_old)
8. Validation check: `sk_old.public_key() != pk_new` → FAIL
9. Returns `ValidatorKeyNotFound`
10. Validator cannot sign consensus messages for entire epoch
11. If >1/3 validators affected: consensus liveness failure

**Notes**

This vulnerability represents a design weakness in the distributed state synchronization between on-chain (public key in validator set) and off-chain (private key in secure storage) components. While the test shows this behavior is known, the lack of automatic recovery mechanisms and retry logic for `ValidatorKeyNotFound` makes this a genuine operational vulnerability that can cause consensus disruptions, particularly during coordinated key rotations or emergency security responses.

The proper mitigation requires both code-level improvements (retry logic, grace periods) and operational best practices (enforced rotation sequences, pre-flight validation).

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L910-932)
```text
    public entry fun rotate_consensus_key(
        operator: &signer,
        pool_address: address,
        new_consensus_pubkey: vector<u8>,
        proof_of_possession: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);

        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));

        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_consensus_pubkey = validator_info.consensus_pubkey;
        // Checks the public key has a valid proof-of-possession to prevent rogue-key attacks.
        let pubkey_from_pop = &bls12381::public_key_from_bytes_with_pop(
            new_consensus_pubkey,
            &proof_of_possession_from_bytes(proof_of_possession)
        );
        assert!(option::is_some(pubkey_from_pop), error::invalid_argument(EINVALID_PUBLIC_KEY));
        validator_info.consensus_pubkey = new_consensus_pubkey;
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L79-99)
```rust
        // Ensuring all the overriding consensus keys are in the storage.
        let timer = Instant::now();
        for blob in config
            .initial_safety_rules_config
            .overriding_identity_blobs()
            .unwrap_or_default()
        {
            if let Some(sk) = blob.consensus_private_key {
                let pk_hex = hex::encode(PublicKey::from(&sk).to_bytes());
                let storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
                match storage.internal_store().set(storage_key.as_str(), sk) {
                    Ok(_) => {
                        info!("Setting {storage_key} succeeded.");
                    },
                    Err(e) => {
                        warn!("Setting {storage_key} failed with internal store set error: {e}");
                    },
                }
            }
        }
        info!("Overriding key work time: {:?}", timer.elapsed());
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L106-132)
```rust
    pub fn consensus_sk_by_pk(
        &self,
        pk: bls12381::PublicKey,
    ) -> Result<bls12381::PrivateKey, Error> {
        let _timer = counters::start_timer("get", CONSENSUS_KEY);
        let pk_hex = hex::encode(pk.to_bytes());
        let explicit_storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
        let explicit_sk = self
            .internal_store
            .get::<bls12381::PrivateKey>(explicit_storage_key.as_str())
            .map(|v| v.value);
        let default_sk = self.default_consensus_sk();
        let key = match (explicit_sk, default_sk) {
            (Ok(sk_0), _) => sk_0,
            (Err(_), Ok(sk_1)) => sk_1,
            (Err(_), Err(_)) => {
                return Err(Error::ValidatorKeyNotFound("not found!".to_string()));
            },
        };
        if key.public_key() != pk {
            return Err(Error::SecureStorageMissingDataError(format!(
                "Incorrect sk saved for {:?} the expected pk",
                pk
            )));
        }
        Ok(key)
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L123-127)
```rust
    pub(crate) fn signer(&self) -> Result<&ValidatorSigner, Error> {
        self.validator_signer
            .as_ref()
            .ok_or_else(|| Error::NotInitialized("validator_signer".into()))
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L326-336)
```rust
                    match self.persistent_storage.consensus_sk_by_pk(expected_key) {
                        Ok(consensus_key) => {
                            self.validator_signer =
                                Some(ValidatorSigner::new(author, Arc::new(consensus_key)));
                            Ok(())
                        },
                        Err(Error::SecureStorageMissingDataError(error)) => {
                            Err(Error::ValidatorKeyNotFound(error))
                        },
                        Err(error) => Err(error),
                    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L340-343)
```rust
        initialize_result.inspect_err(|error| {
            info!(SafetyLogSchema::new(LogEntry::KeyReconciliation, LogEvent::Error).error(error),);
            self.validator_signer = None;
        })
```

**File:** consensus/src/metrics_safety_rules.rs (L71-85)
```rust
    fn retry<T, F: FnMut(&mut Box<dyn TSafetyRules + Send + Sync>) -> Result<T, Error>>(
        &mut self,
        mut f: F,
    ) -> Result<T, Error> {
        let result = f(&mut self.inner);
        match result {
            Err(Error::NotInitialized(_))
            | Err(Error::IncorrectEpoch(_, _))
            | Err(Error::WaypointOutOfDate(_, _, _, _)) => {
                self.perform_initialize()?;
                f(&mut self.inner)
            },
            _ => result,
        }
    }
```

**File:** consensus/safety-rules/src/tests/suite.rs (L641-676)
```rust
// Tests for fetching a missing validator key from persistent storage.
fn test_key_not_in_store(safety_rules: &Callback) {
    let (mut safety_rules, signer) = safety_rules();
    let (mut proof, genesis_qc) = test_utils::make_genesis(&signer);
    let round = genesis_qc.certified_block().round();

    safety_rules.initialize(&proof).unwrap();

    let a1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc, &signer);

    // Update to an epoch where the validator fails to retrive the respective key
    // from persistent storage
    let mut next_epoch_state = EpochState::empty();
    next_epoch_state.epoch = 1;
    let rand_signer = ValidatorSigner::random([0xFu8; 32]);
    next_epoch_state.verifier =
        ValidatorVerifier::new_single(signer.author(), rand_signer.public_key()).into();
    let a2 = test_utils::make_proposal_with_parent_and_overrides(
        Payload::empty(false, true),
        round + 2,
        &a1,
        Some(&a1),
        &signer,
        Some(1),
        Some(next_epoch_state),
    );
    proof
        .ledger_info_with_sigs
        .push(a2.block().quorum_cert().ledger_info().clone());

    // Expected failure due to validator key not being found.
    safety_rules.initialize(&proof).unwrap_err();

    let state = safety_rules.consensus_state().unwrap();
    assert!(!state.in_validator_set());
}
```

**File:** testsuite/smoke-test/src/consensus_key_rotation.rs (L54-116)
```rust
    let (operator_addr, new_pk, pop, operator_idx) =
        if let Some(validator) = swarm.validators_mut().nth(n - 1) {
            let operator_sk = validator
                .account_private_key()
                .as_ref()
                .unwrap()
                .private_key();
            let operator_idx = cli.add_account_to_cli(operator_sk);
            info!("Stopping the last node.");

            validator.stop();
            tokio::time::sleep(Duration::from_secs(5)).await;

            let new_identity_path = PathBuf::from(
                format!(
                    "/tmp/{}-new-validator-identity.yaml",
                    thread_rng().r#gen::<u64>()
                )
                .as_str(),
            );
            info!(
                "Generating and writing new validator identity to {:?}.",
                new_identity_path
            );
            let new_sk = bls12381::PrivateKey::generate(&mut thread_rng());
            let pop = bls12381::ProofOfPossession::create(&new_sk);
            let new_pk = bls12381::PublicKey::from(&new_sk);
            let mut validator_identity_blob = validator
                .config()
                .consensus
                .safety_rules
                .initial_safety_rules_config
                .identity_blob()
                .unwrap();
            validator_identity_blob.consensus_private_key = Some(new_sk);
            let operator_addr = validator_identity_blob.account_address.unwrap();

            Write::write_all(
                &mut File::create(&new_identity_path).unwrap(),
                serde_yaml::to_string(&validator_identity_blob)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();

            info!("Updating the node config accordingly.");
            let config_path = validator.config_path();
            let mut validator_override_config =
                OverrideNodeConfig::load_config(config_path.clone()).unwrap();
            validator_override_config
                .override_config_mut()
                .consensus
                .safety_rules
                .initial_safety_rules_config
                .overriding_identity_blob_paths_mut()
                .push(new_identity_path);
            validator_override_config.save_config(config_path).unwrap();

            info!("Restarting the node.");
            validator.start().unwrap();
            info!("Let it bake for 5 secs.");
            tokio::time::sleep(Duration::from_secs(5)).await;
            (operator_addr, new_pk, pop, operator_idx)
```
