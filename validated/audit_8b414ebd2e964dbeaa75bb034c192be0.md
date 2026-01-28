# Audit Report

## Title
Validator Crash via Panic in SecretShareManager When Processing Blocks Without Encrypted Transactions

## Summary
When secret sharing is enabled, any validator processing a block with no encrypted transactions triggers a panic in `SecretShareManager::process_incoming_block()` that crashes the entire validator process due to Aptos's global panic handler calling `process::exit(12)`.

## Finding Description

The vulnerability occurs in the secret sharing pipeline when blocks without encrypted transactions are processed. The complete execution flow is:

1. **SecretShareManager spawned as tokio task**: The SecretShareManager is spawned via `tokio::spawn` in the execution client initialization. [1](#0-0) 

2. **Pipeline future setup with oneshot channel**: When building pipeline futures for each block, a oneshot channel is created for `secret_sharing_derive_self_fut`. The receiver is wrapped in a future that returns an error if the sender is dropped without sending. [2](#0-1) 

3. **Early return drops sender without sending**: In `decrypt_encrypted_txns`, when a block has no encrypted transactions, the function returns early without sending anything through the oneshot channel, causing the sender to be dropped. [3](#0-2) 

4. **Panic on .expect()**: The SecretShareManager awaits the future and uses `.expect()` which panics when the channel returns an error (cancelled/dropped). [4](#0-3) 

5. **Global panic handler kills validator**: Aptos sets up a global panic handler at node startup that overrides Tokio's default panic-catching behavior. [5](#0-4) [6](#0-5) 

6. **Process termination**: The panic handler calls `process::exit(12)` for any panic except those in the Move bytecode verifier or deserializer, terminating the entire validator process. [7](#0-6) 

This violates the **Consensus Liveness** invariant by causing validators to crash and potentially halting network progress if enough validators are affected simultaneously.

## Impact Explanation

**Critical Severity** - This meets the "Total loss of liveness/network availability" criterion for Critical severity (up to $1,000,000) for the following reasons:

1. **Complete validator crash**: The entire validator process terminates via `process::exit(12)`, not just the task
2. **Deterministic trigger**: ANY block without encrypted transactions will trigger this when secret sharing is enabled
3. **Natural occurrence**: Most blocks will have no encrypted transactions during normal operation (encrypted transactions are not the default)
4. **Network-wide impact**: All validators with secret sharing enabled will crash when processing the same block
5. **Consensus halt risk**: If enough validators crash simultaneously, the network cannot reach the 2/3 threshold required for consensus

The vulnerability effectively creates a network-wide denial of service condition when the secret sharing feature is enabled.

## Likelihood Explanation

**Extremely High Likelihood**:

1. **No attacker needed**: This occurs naturally during normal operation - any block proposer can trigger it simply by proposing a block with no encrypted transactions
2. **Default behavior**: Encrypted transactions are not the norm; most blocks contain only regular unencrypted transactions
3. **Feature enabled**: When the secret sharing feature is enabled on the network, all validators running with this configuration are vulnerable [8](#0-7) 
4. **Zero complexity**: No special crafting, timing, or exploitation technique required
5. **Immediate trigger**: Occurs on the first block without encrypted transactions after secret sharing is enabled

This is essentially a guaranteed crash condition during normal network operation when secret sharing is active.

## Recommendation

Fix the `decrypt_encrypted_txns` function to always send through the `derived_self_key_share_tx` channel, even when returning early:

```rust
// In decrypt_encrypted_txns
if encrypted_txns.is_empty() {
    // Send None before returning
    let _ = derived_self_key_share_tx.send(None);
    return Ok((
        unencrypted_txns,
        max_txns_from_block_to_execute,
        block_gas_limit,
    ));
}
```

Additionally, the `process_incoming_block` function should handle the `None` case gracefully instead of using `.expect("Must not be None")`, or restructure the logic to not require the channel when there are no encrypted transactions.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a validator node with secret sharing enabled (SecretShareConfig provided)
2. Proposing a block that contains only regular transactions (no encrypted transactions)
3. Observing the validator crash with exit code 12

The crash occurs deterministically due to the unhandled channel cancellation in the secret sharing pipeline when the decryption step returns early without sending the expected value through the oneshot channel.

### Citations

**File:** consensus/src/pipeline/execution_client.rs (L296-302)
```rust
        tokio::spawn(secret_share_manager.start(
            ordered_block_rx,
            secret_sharing_msg_rx,
            reset_secret_share_manager_rx,
            self.bounded_executor.clone(),
            highest_committed_round,
        ));
```

**File:** consensus/src/pipeline/execution_client.rs (L400-422)
```rust
            (Some(rand_config), Some(secret_sharing_config)) => {
                let (rand_manager_input_tx, rand_ready_block_rx, reset_tx_to_rand_manager) = self
                    .make_rand_manager(
                        &epoch_state,
                        fast_rand_config,
                        rand_msg_rx,
                        highest_committed_round,
                        &network_sender,
                        rand_config,
                        consensus_sk,
                    );

                let (
                    secret_share_manager_input_tx,
                    secret_ready_block_rx,
                    reset_tx_to_secret_share_manager,
                ) = self.make_secret_sharing_manager(
                    &epoch_state,
                    secret_sharing_config,
                    secret_sharing_msg_rx,
                    highest_committed_round,
                    &network_sender,
                );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L447-455)
```rust
        let (derived_self_key_share_tx, derived_self_key_share_rx) = oneshot::channel();
        let secret_sharing_derive_self_fut = spawn_shared_fut(
            async move {
                derived_self_key_share_rx
                    .await
                    .map_err(|_| TaskError::from(anyhow!("commit proof tx cancelled")))
            },
            Some(&mut abort_handles),
        );
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L49-54)
```rust
        if encrypted_txns.is_empty() {
            return Ok((
                unencrypted_txns,
                max_txns_from_block_to_execute,
                block_gas_limit,
            ));
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L134-137)
```rust
        let self_secret_share = futures
            .secret_sharing_derive_self_fut
            .await
            .expect("Decryption share computation is expected to succeed")
```

**File:** aptos-node/src/lib.rs (L234-234)
```rust
    aptos_crash_handler::setup_panic_handler();
```

**File:** crates/crash-handler/src/lib.rs (L26-29)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
```

**File:** crates/crash-handler/src/lib.rs (L52-57)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```
