# Audit Report

## Title
Byzantine Validator Timing Attack Causes Redundant RequestShare RPC Messages

## Summary
A Byzantine validator can deliberately delay broadcasting their randomness share until after the 300ms timeout in `spawn_aggregate_shares_task()`, causing all honest validators to send redundant `RequestShare` RPC messages. When the Byzantine validator subsequently broadcasts their share through the normal path but ignores the RequestShare RPCs, these requests timeout after 10 seconds and trigger exponential backoff retries, wasting network bandwidth and connection resources.

## Finding Description

The randomness generation mechanism in Aptos consensus implements a 300ms delay before requesting missing shares from validators. [1](#0-0) 

When a block arrives, each validator:
1. Generates and broadcasts their share immediately [2](#0-1) 
2. Spawns an async task that sleeps for 300ms
3. After the timeout, checks which validators haven't sent shares [3](#0-2) 
4. Multicasts RequestShare messages to missing validators [4](#0-3) 

A Byzantine validator can exploit this timing window by:
1. Delaying their share broadcast until T+301ms (just after the timeout)
2. At T+300ms, all N-1 honest validators send RequestShare RPCs to the Byzantine validator
3. At T+301ms, the Byzantine validator broadcasts their share via the normal Share message path
4. Honest validators receive and process the share through the standard handler [5](#0-4) 
5. The Byzantine validator deliberately doesn't respond to the RequestShare RPCs
6. Each RequestShare RPC times out after 10 seconds [6](#0-5) 
7. The reliable broadcast implementation retries with exponential backoff (base 2ms, factor 100, max 10s) [7](#0-6) 
8. Multiple retry attempts occur before eventual timeout

The RequestShare task and the normal Share message handler operate on independent code paths. When a share arrives via broadcast, it's added to `rand_store` directly, but the RequestShare RPC task continues waiting for a response independently. There's no mechanism to cancel pending RequestShare RPCs when the share arrives through the broadcast path.

With N validators and B Byzantine validators employing this strategy:
- Total redundant RPCs per round: (N-B) × B
- Each RPC occupies network connections, memory, and processing for 10+ seconds
- Example: 100 validators, 10 Byzantine = 900 concurrent redundant RPCs per round

## Impact Explanation

This is a **Low Severity** vulnerability per the Aptos bug bounty program criteria for "Non-critical implementation bugs." The impact is limited to:

1. **Network bandwidth waste**: Each redundant RequestShare RPC consumes bandwidth for the request, timeout period (~10s), and retry attempts
2. **Resource consumption**: Concurrent RPC connection slots, memory for pending requests, CPU time for timeout handling
3. **No consensus impact**: Randomness generation still completes correctly; shares arrive via broadcast
4. **No safety violation**: Does not affect BFT safety guarantees or consensus correctness
5. **No liveness impact**: Does not prevent the network from making progress

The attack cannot:
- Steal or freeze funds
- Cause consensus splits or safety violations
- Prevent randomness generation
- Cause permanent network degradation
- Affect state consistency

The 300ms timeout itself is a deliberate design trade-off to balance waiting for natural share arrival versus actively requesting missing shares.

## Likelihood Explanation

**High likelihood** - This attack is trivial for any Byzantine validator to execute:
- Requires only the ability to delay message broadcasting (simple timing control)
- No cryptographic attacks or complex exploitation required
- Can be executed every round with minimal cost to the attacker
- Multiple Byzantine validators can compound the effect
- No detection mechanism exists to identify validators using this strategy

However, the impact per instance is limited, and the system continues functioning correctly despite the resource waste.

## Recommendation

Implement one or more of the following mitigations:

1. **Early termination on share arrival**: When a share arrives via normal broadcast, check if there are pending RequestShare tasks for that validator and cancel them using the DropGuard mechanism.

2. **Check rand_store before RPC**: In the RequestShare RPC handler, verify that the share doesn't already exist in rand_store before processing the request:

```rust
// In RandMessage::RequestShare handler
let result = self.rand_store.lock().get_self_share(request.rand_metadata());
match result {
    Ok(Some(share)) => {
        // Share already exists, respond immediately
        self.process_response(protocol, response_sender, RandMessage::Share(share));
    },
    Ok(None) => {
        // Generate share if not found
        let share = S::generate(&self.config, request.rand_metadata().clone());
        // ... rest of logic
    },
    Err(e) => { /* error handling */ }
}
```

3. **Shorter RPC timeout**: Reduce `rpc_timeout_ms` for RequestShare specifically to limit resource waste per attempt.

4. **Byzantine validator tracking**: Track validators who consistently don't respond to RequestShare messages and adjust timeout/retry strategy accordingly.

## Proof of Concept

The following scenario demonstrates the attack:

```rust
// Simulation setup:
// - 100 validators
// - 1 Byzantine validator delays share broadcast
// - Threshold: 67 shares needed

// T=0: Block with round 100 arrives at all validators
// All honest validators broadcast shares immediately

// Byzantine validator implements delay strategy:
tokio::time::sleep(Duration::from_millis(350)).await;
network_sender.broadcast_without_self(RandMessage::Share(self_share));

// At T=300ms, all 99 honest validators execute:
let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
// Returns Some(set) with 99 shares (Byzantine missing)

let targets = epoch_state.verifier
    .get_ordered_account_addresses_iter()
    .filter(|author| !existing_shares.contains(author))
    .collect::<Vec<_>>();
// targets = [byzantine_validator]

// 99 RequestShare RPCs sent to Byzantine validator
rb.multicast(request, aggregate_state, targets).await

// At T=350ms, Byzantine validator broadcasts share
// All honest validators receive and add to rand_store

// Byzantine validator ignores all 99 RequestShare RPCs
// Each RPC times out after 10 seconds (T=10.3s)
// Exponential backoff triggers retries
// Total waste: 99 * (10s + retries) of network resources
```

## Notes

The 300ms delay is a reasonable design parameter that balances network efficiency under normal conditions. The vulnerability arises from the lack of coordination between the RequestShare task and the normal share broadcast path. While the impact is limited to resource waste and doesn't affect consensus correctness, Byzantine validators can exploit this timing window to cause measurable network overhead. The issue is classified as Low severity because it represents a non-critical implementation inefficiency rather than a security-critical vulnerability affecting funds, consensus safety, or network availability.

### Citations

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L146-167)
```rust
        let self_share = S::generate(&self.config, metadata.metadata.clone());
        info!(LogSchema::new(LogEvent::BroadcastRandShare)
            .epoch(self.epoch_state.epoch)
            .author(self.author)
            .round(metadata.round()));
        let mut rand_store = self.rand_store.lock();
        rand_store.update_highest_known_round(metadata.round());
        rand_store
            .add_share(self_share.clone(), PathType::Slow)
            .expect("Add self share should succeed");

        if let Some(fast_config) = &self.fast_config {
            let self_fast_share =
                FastShare::new(S::generate(fast_config, metadata.metadata.clone()));
            rand_store
                .add_share(self_fast_share.rand_share(), PathType::Fast)
                .expect("Add self share for fast path should succeed");
        }

        rand_store.add_rand_metadata(metadata.clone());
        self.network_sender
            .broadcast_without_self(RandMessage::<S, D>::Share(self_share).into_network_message());
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L274-274)
```rust
            tokio::time::sleep(Duration::from_millis(300)).await;
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L275-283)
```rust
            let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L290-292)
```rust
                rb.multicast(request, aggregate_state, targets)
                    .await
                    .expect("Broadcast cannot fail");
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L414-423)
```rust
                        RandMessage::Share(share) => {
                            trace!(LogSchema::new(LogEvent::ReceiveProactiveRandShare)
                                .author(self.author)
                                .epoch(share.epoch())
                                .round(share.metadata().round)
                                .remote_peer(*share.author()));

                            if let Err(e) = self.rand_store.lock().add_share(share, PathType::Slow) {
                                warn!("[RandManager] Failed to add share: {}", e);
                            }
```

**File:** config/src/config/consensus_config.rs (L373-378)
```rust
            rand_rb_config: ReliableBroadcastConfig {
                backoff_policy_base_ms: 2,
                backoff_policy_factor: 100,
                backoff_policy_max_delay_ms: 10000,
                rpc_timeout_ms: 10000,
            },
```
