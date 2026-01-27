# Audit Report

## Title
Critical Stake-Weight Bypass in Secret Sharing Causing Denial of Service for Encrypted Transaction Decryption

## Summary
The secret sharing configuration returns a constant weight of 1 for all validators instead of using their actual stake-based weights, causing a critical threshold/weight mismatch that makes secret reconstruction impossible. This results in permanent inability to decrypt encrypted transactions when the feature is enabled.

## Finding Description

While investigating `SecretSharingConfig::get_peer_weight()` in the file mentioned in the security question, I discovered that struct appears to be unused in production consensus code. However, the **identical vulnerability exists in the actively-used `SecretShareConfig`** in `types/src/secret_sharing.rs`.

The vulnerability occurs because of a mismatch between threshold calculation and weight counting:

**The Bug:**
The `get_peer_weight()` function returns a hardcoded value of 1 for all validators, ignoring their actual stake: [1](#0-0) 

**How Weighted Configs Should Work:**
During DKG setup, validator stakes are properly converted to weights through the rounding algorithm: [2](#0-1) 

The `WeightedConfig` is created with stake-proportional weights and a threshold based on stake ratios (e.g., 2/3 of total stake): [3](#0-2) 

**The Threshold Calculation:**
The threshold returned by `SecretShareConfig` comes from the weighted config's threshold value: [4](#0-3) 

**Where the Bug Manifests:**
During secret share aggregation, weights from `get_peer_weight()` are summed and compared against the threshold: [5](#0-4) 

Each validator's share is counted with weight=1: [6](#0-5) 

**Attack Scenario:**
Consider 4 validators with stakes: A=40%, B=30%, C=20%, D=10%

After DKG rounding with 2/3 reconstruction threshold:
- Validator weights might be: [10, 7, 5, 2] (total=24)
- Reconstruction threshold: ~16 (2/3 of 24)

With the bug:
- Each validator contributes weight=1 regardless of stake
- Maximum achievable weight: 4 (only 4 validators)
- Required threshold: 16
- **4 < 16: Secret reconstruction is IMPOSSIBLE**

This violates the fundamental stake-weighted security assumption where validators with >2/3 stake should be able to reconstruct secrets.

## Impact Explanation

**Critical Severity - Complete Denial of Service**

When encrypted transactions are enabled, this bug causes:

1. **Permanent Inability to Decrypt**: The secret sharing threshold can never be reached, making encrypted transaction decryption impossible
2. **Protocol Deadlock**: All encrypted transactions remain permanently encrypted and unusable
3. **Stake-Weight Security Violation**: Low-stake validators have equal influence as high-stake validators (all contribute weight=1), completely breaking the stake-weighted security model

The bug affects the encrypted transaction decryption pipeline: [7](#0-6) 

This meets **Critical Severity** criteria per Aptos bug bounty:
- Total loss of liveness for encrypted transaction feature
- Requires protocol changes to fix once deployed

## Likelihood Explanation

**Likelihood: High (when feature is enabled)**

The vulnerability will **automatically trigger** when:
1. Encrypted transactions feature is enabled in production
2. Any block contains encrypted transactions
3. Validators attempt to aggregate secret shares for decryption

Currently, the encrypted transaction feature appears to be under development based on TODO comments in the codebase, so it may not be enabled on mainnet yet. However, the code is integrated into the consensus pipeline and will cause immediate DoS when activated.

No attacker action is required - the bug causes automatic failure of the secret sharing protocol.

## Recommendation

**Fix:** Implement `get_peer_weight()` to return actual validator weights from the underlying weighted config.

The fix should retrieve weights from the `WeightedConfig` similar to how `RandConfig` correctly implements it: [8](#0-7) 

**Suggested Implementation:**

In `types/src/secret_sharing.rs`, modify the `SecretShareConfig` struct to:
1. Store validator weights in the `weights` HashMap during initialization
2. Populate weights from the underlying threshold config  
3. Return actual weights from `get_peer_weight()`

Additionally, initialize the `weights` field (currently empty) during config creation from the underlying `WeightedConfig`.

## Proof of Concept

The vulnerability can be demonstrated by examining the threshold calculation flow:

**Step 1:** DKG creates weighted config with stake-based weights [9](#0-8) 

**Step 2:** Threshold is set based on these weights (e.g., 16 out of 24) [10](#0-9) 

**Step 3:** But aggregation counts each validator as weight=1 [11](#0-10) 

**Step 4:** Threshold check fails: 4 < 16 [12](#0-11) 

A concrete test would require:
1. Setting up a 4-validator network with different stakes
2. Enabling encrypted transactions
3. Submitting an encrypted transaction
4. Observing that secret share aggregation never reaches the threshold
5. Confirming encrypted transactions remain undecryptable

## Notes

The security question specifically mentioned `consensus/src/rand/secret_sharing/types.rs`, which contains a `SecretSharingConfig` struct with the same `get_peer_weight()` bug. However, that struct appears unused in production code. The actively exploited vulnerability exists in the related `SecretShareConfig` in `types/src/secret_sharing.rs`, which is used by `SecretShareManager` for encrypted transaction decryption.

Both structs share the same fundamental flaw: ignoring validator stakes in favor of equal weighting, violating stake-weighted security assumptions and causing threshold impossibility.

### Citations

**File:** types/src/secret_sharing.rs (L188-190)
```rust
    pub fn threshold(&self) -> u64 {
        self.config.get_threshold_config().t as u64
    }
```

**File:** types/src/secret_sharing.rs (L196-198)
```rust
    pub fn get_peer_weight(&self, _peer: &Author) -> u64 {
        1
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L97-146)
```rust
pub fn build_dkg_pvss_config(
    cur_epoch: u64,
    secrecy_threshold: U64F64,
    reconstruct_threshold: U64F64,
    maybe_fast_path_secrecy_threshold: Option<U64F64>,
    next_validators: &[ValidatorConsensusInfo],
) -> DKGPvssConfig {
    let validator_stakes: Vec<u64> = next_validators.iter().map(|vi| vi.voting_power).collect();
    let timer = Instant::now();
    let DKGRounding {
        profile,
        wconfig,
        fast_wconfig,
        rounding_error,
        rounding_method,
    } = DKGRounding::new(
        &validator_stakes,
        secrecy_threshold,
        reconstruct_threshold,
        maybe_fast_path_secrecy_threshold,
    );
    let rounding_time = timer.elapsed();
    let validator_consensus_keys: Vec<bls12381::PublicKey> = next_validators
        .iter()
        .map(|vi| vi.public_key.clone())
        .collect();

    let consensus_keys: Vec<EncPK> = validator_consensus_keys
        .iter()
        .map(|k| k.to_bytes().as_slice().try_into().unwrap())
        .collect::<Vec<_>>();

    let pp = DkgPP::default_with_bls_base();

    let rounding_summary = RoundingSummary {
        method: rounding_method,
        output: profile,
        exec_time: rounding_time,
        error: rounding_error,
    };

    DKGPvssConfig::new(
        cur_epoch,
        wconfig,
        fast_wconfig,
        pp,
        consensus_keys,
        rounding_summary,
    )
}
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L98-106)
```rust
        let wconfig = WeightedConfigBlstrs::new(
            profile.reconstruct_threshold_in_weights as usize,
            profile
                .validator_weights
                .iter()
                .map(|w| *w as usize)
                .collect(),
        )
        .unwrap();
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L295-331)
```rust
fn compute_profile_fixed_point(
    validator_stakes: &Vec<u64>,
    stake_per_weight: U64F64,
    secrecy_threshold_in_stake_ratio: U64F64,
    maybe_fast_secrecy_threshold_in_stake_ratio: Option<U64F64>,
) -> DKGRoundingProfile {
    // Use fixed-point arithmetic to ensure the same result across machines.
    // See paper for details of the rounding algorithm
    // https://eprint.iacr.org/2024/198
    let one = U64F64::from_num(1);
    let stake_sum: u64 = validator_stakes.iter().sum::<u64>();
    let stake_sum_fixed = U64F64::from_num(stake_sum);
    let mut delta_down_fixed = U64F64::from_num(0);
    let mut delta_up_fixed = U64F64::from_num(0);
    let mut validator_weights: Vec<u64> = vec![];
    for stake in validator_stakes {
        let ideal_weight_fixed = U64F64::from_num(*stake) / stake_per_weight;
        // rounded to the nearest integer
        let rounded_weight_fixed = (ideal_weight_fixed + (one / 2)).floor();
        let rounded_weight = rounded_weight_fixed.to_num::<u64>();
        validator_weights.push(rounded_weight);
        if ideal_weight_fixed > rounded_weight_fixed {
            delta_down_fixed += ideal_weight_fixed - rounded_weight_fixed;
        } else {
            delta_up_fixed += rounded_weight_fixed - ideal_weight_fixed;
        }
    }
    let weight_total: u64 = validator_weights.clone().into_iter().sum();
    let delta_total_fixed = delta_down_fixed + delta_up_fixed;
    let reconstruct_threshold_in_weights_fixed =
        (secrecy_threshold_in_stake_ratio * stake_sum_fixed / stake_per_weight + delta_up_fixed)
            .ceil()
            + one;
    let reconstruct_threshold_in_weights: u64 = min(
        weight_total,
        reconstruct_threshold_in_weights_fixed.to_num::<u64>(),
    );
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L32-36)
```rust
    pub fn add_share(&mut self, share: SecretShare, weight: u64) {
        if self.shares.insert(share.author, share).is_none() {
            self.total_weight += weight;
        }
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L38-46)
```rust
    pub fn try_aggregate(
        self,
        secret_share_config: &SecretShareConfig,
        metadata: SecretShareMetadata,
        decision_tx: Sender<SecretSharedKey>,
    ) -> Either<Self, SecretShare> {
        if self.total_weight < secret_share_config.threshold() {
            return Either::Left(self);
        }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-260)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L27-54)
```rust
    pub(crate) async fn decrypt_encrypted_txns(
        materialize_fut: TaskFuture<MaterializeResult>,
        block: Arc<Block>,
        author: Author,
        secret_share_config: Option<SecretShareConfig>,
        derived_self_key_share_tx: oneshot::Sender<Option<SecretShare>>,
        secret_shared_key_rx: oneshot::Receiver<Option<SecretSharedKey>>,
    ) -> TaskResult<DecryptionResult> {
        let mut tracker = Tracker::start_waiting("decrypt_encrypted_txns", &block);
        let (input_txns, max_txns_from_block_to_execute, block_gas_limit) = materialize_fut.await?;

        tracker.start_working();

        if secret_share_config.is_none() {
            return Ok((input_txns, max_txns_from_block_to_execute, block_gas_limit));
        }

        let (encrypted_txns, unencrypted_txns): (Vec<_>, Vec<_>) = input_txns
            .into_iter()
            .partition(|txn| txn.is_encrypted_txn());

        // TODO: figure out handling of
        if encrypted_txns.is_empty() {
            return Ok((
                unencrypted_txns,
                max_txns_from_block_to_execute,
                block_gas_limit,
            ));
```

**File:** consensus/src/rand/rand_gen/types.rs (L676-681)
```rust
    pub fn get_peer_weight(&self, peer: &Author) -> u64 {
        let player = Player {
            id: self.get_id(peer),
        };
        self.wconfig.get_player_weight(&player) as u64
    }
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L152-155)
```rust
    /// Returns the threshold weight required to reconstruct the secret.
    pub fn get_threshold_weight(&self) -> usize {
        self.tc.get_threshold()
    }
```
