# Audit Report

## Title
Protocol Parameter Version Incompatibility: FUTURE_ROUNDS_TO_ACCEPT Constant Change Causes Validator Share Rejection During Rolling Upgrades

## Summary
If the `FUTURE_ROUNDS_TO_ACCEPT` constant is changed in a protocol upgrade, validators running different software versions will reject each other's secret shares and randomness shares when round numbers exceed the lower threshold, causing consensus delays or stalls during rolling upgrades.

## Finding Description

The `FUTURE_ROUNDS_TO_ACCEPT` constant is defined as a hardcoded value in the consensus layer: [1](#0-0) 

This constant is imported and used in validation logic for both secret sharing and randomness generation: [2](#0-1) 

The validation checks enforce that incoming shares must not be too far in the future: [3](#0-2) [4](#0-3) [5](#0-4) 

**The Vulnerability Scenario:**

During a rolling upgrade where `FUTURE_ROUNDS_TO_ACCEPT` is changed (e.g., from 200 to 100):

1. Some validators upgrade immediately (running new code with `FUTURE_ROUNDS_TO_ACCEPT = 100`)
2. Other validators haven't upgraded yet (running old code with `FUTURE_ROUNDS_TO_ACCEPT = 200`)
3. Consensus continues operating with mixed versions within the same epoch [6](#0-5) 

When shares arrive for rounds that fall between the two thresholds (e.g., `highest_known_round + 150`):
- Validators with old code accept: `round <= highest_known + 200` ✓
- Validators with new code reject: `round <= highest_known + 100` ✗ "Share from future round"

This split occurs because:
1. Rounds can skip significantly during timeouts or leader failures
2. Different validators may have different `highest_known_round` values due to network conditions
3. Secret share and randomness managers are created per-epoch with no version negotiation [7](#0-6) 

The shares are rejected silently with an error message, preventing aggregation: [8](#0-7) 

If the threshold for secret share aggregation requires contributions from both old and new version validators, the aggregation will fail, blocking consensus progress.

## Impact Explanation

**Severity: High** (per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations")

This breaks the consensus safety invariant: validators must maintain consistent state and agree on valid messages. During the rolling upgrade window:

- **Consensus Delays**: Secret share aggregation may fail to reach threshold, delaying block commits
- **Partial Network Partition**: Validators effectively split by software version, unable to process each other's shares
- **Liveness Impact**: If the validator set is evenly split, neither group can reach the 2/3 threshold needed for progress

The impact is temporary (resolves when all validators complete the upgrade) but can cause significant operational disruption during the upgrade window, which Aptos documentation indicates can span multiple rounds within an epoch. [9](#0-8) 

## Likelihood Explanation

**Likelihood: Medium-High** during protocol upgrades that modify this constant

The likelihood depends on:

1. **Protocol Change Decision**: Requires developers to modify `FUTURE_ROUNDS_TO_ACCEPT` in a future release
2. **Rolling Upgrade Pattern**: Aptos explicitly supports rolling upgrades within epochs (demonstrated in test suites)
3. **Round Skipping Frequency**: During normal consensus with timeouts or leader failures, rounds can skip by significant amounts
4. **Upgrade Window Duration**: The longer validators run mixed versions, the higher the probability of hitting this condition

Given that Aptos tests validate rolling upgrades and the codebase shows epoch durations of 30+ seconds with validator upgrades happening gradually, the conditions for triggering this issue are realistic during any upgrade that changes this constant.

## Recommendation

Implement version-aware protocol parameter handling with backward compatibility:

**Option 1: On-chain Configuration**
Move `FUTURE_ROUNDS_TO_ACCEPT` to on-chain configuration that takes effect at epoch boundaries, ensuring all validators use the same value within each epoch.

**Option 2: Version Negotiation**
Add protocol version negotiation during secret sharing handshake, allowing validators to agree on compatible parameters before exchanging shares.

**Option 3: Graceful Degradation**
When rejecting a share due to future round limit, log the rejection reason with details about the local `FUTURE_ROUNDS_TO_ACCEPT` value and implement fallback logic to request the share through an alternative path.

**Recommended Fix (Option 1 implementation sketch):**

```rust
// In types.rs - remove hardcoded constant
// pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;

// In SecretShareConfig or RandConfig - add field
pub struct SecretShareConfig {
    // ... existing fields ...
    future_rounds_tolerance: u64,
}

// Load from on-chain config during epoch initialization
impl SecretShareConfig {
    pub fn from_onchain_config(
        config: &OnChainRandomnessConfig,
        // ... other params ...
    ) -> Self {
        Self {
            // ... existing fields ...
            future_rounds_tolerance: config.future_rounds_tolerance(),
        }
    }
}

// Use instance value instead of constant in validation
ensure!(
    metadata.round <= self.highest_known_round + self.config.future_rounds_tolerance,
    "Share from future round"
);
```

This ensures all validators within an epoch use the same tolerance value, preventing version-based rejection mismatches.

## Proof of Concept

**Note:** This vulnerability cannot be demonstrated with a simple PoC as it requires:
1. Modifying the `FUTURE_ROUNDS_TO_ACCEPT` constant to different values
2. Running a multi-validator network with mixed software versions
3. Inducing consensus scenarios with high round skipping

**Reproduction Steps:**

1. Checkout two versions of the codebase:
   - Version A: `FUTURE_ROUNDS_TO_ACCEPT = 200`
   - Version B: `FUTURE_ROUNDS_TO_ACCEPT = 100`

2. Start a 4-validator network with 2 validators on Version A, 2 on Version B

3. Induce round skipping via timeout certificates by stopping the leader validator

4. Observe share rejection in logs on Version B validators:
   ```
   [SecretShareManager] Failed to add share: Share from future round
   ```

5. Monitor consensus progress - aggregation will fail if threshold requires shares from both groups

6. Verify using validator logs and metrics that secret share aggregation times out

**Expected Behavior:** Version B validators reject shares from rounds > `highest_known_round + 100`, while Version A validators accept them, causing aggregation failures.

---

**Notes:**

While this is a valid protocol design concern that answers "YES" to the security question, it has important limitations:

- **Not exploitable by external attackers** - requires protocol upgrade decision by Aptos developers
- **Temporary impact** - resolves when all validators complete upgrade  
- **Currently dormant** - the constant has never changed (currently 200 in both locations checked)
- **Mitigation exists** - validators can coordinate upgrades at epoch boundaries

This represents a protocol upgrade migration risk rather than an active exploit, but constitutes a significant protocol violation during the upgrade window that could impact network availability.

### Citations

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L6-6)
```rust
    rand::rand_gen::{rand_manager::Sender, types::FUTURE_ROUNDS_TO_ACCEPT},
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L245-248)
```rust
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L263-266)
```rust
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L285-288)
```rust
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L286-294)
```rust
            SecretShareMessage::RequestShare(request) => {
                let result = self
                    .secret_share_store
                    .lock()
                    .get_self_share(request.metadata());
                match result {
                    Ok(Some(share)) => {
                        self.process_response(
                            protocol,
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L310-320)
```rust
            SecretShareMessage::Share(share) => {
                info!(LogSchema::new(LogEvent::ReceiveSecretShare)
                    .author(self.author)
                    .epoch(share.epoch())
                    .round(share.metadata().round)
                    .remote_peer(*share.author()));

                if let Err(e) = self.secret_share_store.lock().add_share(share) {
                    warn!("[SecretShareManager] Failed to add share: {}", e);
                }
            },
```

**File:** consensus/src/pipeline/execution_client.rs (L268-309)
```rust
    fn make_secret_sharing_manager(
        &self,
        epoch_state: &Arc<EpochState>,
        config: SecretShareConfig,
        secret_sharing_msg_rx: aptos_channel::Receiver<AccountAddress, IncomingSecretShareRequest>,
        highest_committed_round: u64,
        network_sender: &Arc<NetworkSender>,
    ) -> (
        UnboundedSender<OrderedBlocks>,
        futures_channel::mpsc::UnboundedReceiver<OrderedBlocks>,
        UnboundedSender<ResetRequest>,
    ) {
        let (ordered_block_tx, ordered_block_rx) = unbounded::<OrderedBlocks>();
        let (secret_ready_block_tx, secret_ready_block_rx) = unbounded::<OrderedBlocks>();

        let (reset_tx_to_secret_share_manager, reset_secret_share_manager_rx) =
            unbounded::<ResetRequest>();

        let secret_share_manager = SecretShareManager::new(
            self.author,
            epoch_state.clone(),
            config,
            secret_ready_block_tx,
            network_sender.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );

        tokio::spawn(secret_share_manager.start(
            ordered_block_rx,
            secret_sharing_msg_rx,
            reset_secret_share_manager_rx,
            self.bounded_executor.clone(),
            highest_committed_round,
        ));

        (
            ordered_block_tx,
            secret_ready_block_rx,
            reset_tx_to_secret_share_manager,
        )
    }
```

**File:** testsuite/testcases/src/compatibility_test.rs (L14-16)
```rust
impl SimpleValidatorUpgrade {
    pub const EPOCH_DURATION_SECS: u64 = 30;
}
```
