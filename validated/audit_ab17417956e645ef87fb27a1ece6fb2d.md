# Audit Report

## Title
Validator Transaction Pool Permanent Starvation Due to Size-Based Filtering Logic Flaw

## Summary
The validator transaction pool's `pull()` function uses size-based filtering that permanently excludes transactions exceeding the `max_bytes` quota. DKG transcripts required for epoch transitions can exceed the 2 MB per-block limit when the validator set reaches ~14,562+ validators, causing permanent exclusion from blocks and blocking epoch transitions indefinitely until manual governance intervention.

## Finding Description

The validator transaction pool implements a size-based filtering mechanism that creates a permanent starvation condition for oversized transactions.

**Pool Filtering Logic:**
The `pull()` method filters transactions using a size check that skips any transaction where `size_in_bytes() > max_bytes`: [1](#0-0) 

**Critical Flaw - Transactions Remain in Pool:**
Transactions that fail the size check are skipped by the iterator but are NOT removed from the pool. The `seq_num_lower_bound` variable is reset to 0 on each `pull()` call: [2](#0-1) 

This causes the same oversized transaction to be re-evaluated and filtered out on every subsequent `pull()` call indefinitely.

**DKG Transcript Size Formula:**
For unweighted DAS DKG transcripts, the expected size is `G2_PROJ_NUM_BYTES + (n+1) * (G2_PROJ_NUM_BYTES + G1_PROJ_NUM_BYTES)`: [3](#0-2) 

With the constants defined as: [4](#0-3) 

This equals `96 + (n+1) * 144` bytes, which exceeds 2 MB at 14,562+ validators (2,097,168 bytes).

**Per-Block Limit:**
The default validator transaction per-block byte limit is 2 MB: [5](#0-4) 

**Topic-Based Pool Constraint:**
The pool maintains only one transaction per topic. When adding a new transaction with the same topic, the old one is removed: [6](#0-5) 

Since DKG uses `Topic::DKG`, only one DKG transcript can exist in the pool: [7](#0-6) 

**No Size Validation When Adding:**
DKG transcripts are added to the pool without any size validation: [8](#0-7) 

**Pull Called with Size Limit:**
During block formation, `pull()` is called with `max_bytes = min(params.max_txns.size_in_bytes(), per_block_limit_total_bytes)`: [9](#0-8) 

**Epoch Transition Blocking Mechanism:**
When epoch timeout occurs, `block_prologue_ext` calls `reconfiguration_with_dkg::try_start()`: [10](#0-9) 

The `try_start()` function checks if there's already an incomplete DKG session for the current epoch and returns early without forcing epoch transition: [11](#0-10) 

**Recovery Requires Manual Intervention:**
Only the `force_end_epoch()` function can clear the incomplete DKG session and force epoch transition: [12](#0-11) 

This calls `reconfiguration_with_dkg::finish()` which clears the incomplete session: [13](#0-12) 

## Impact Explanation

**Critical Severity** - This vulnerability causes a permanent protocol-level liveness failure:

1. **Epoch Transition Blockage**: DKG transcripts are required for epoch transitions when randomness is enabled. Without the ability to include oversized DKG transcripts in blocks, epoch transitions cannot complete. The incomplete DKG session persists indefinitely because `try_start()` returns early when detecting an existing session for the current epoch.

2. **Protocol Functions Disabled**: While block production and user transaction processing continue, critical protocol functions become permanently disabled:
   - Validator set cannot be updated
   - Validator stakes cannot be unlocked after lockup periods
   - On-chain configuration changes cannot take effect
   - Governance proposals requiring epoch transitions cannot be applied

3. **Non-recoverable Without Manual Intervention**: The only resolution is governance action to call `force_end_epoch()`, which clears the incomplete DKG session and forces epoch transition without randomness. This requires coordination and may take significant time.

4. **Design Flaw**: The vulnerability represents a fundamental incompatibility between the protocol's scalability assumptions (supporting thousands of validators) and the transaction pool's size constraints (2 MB per-block limit).

## Likelihood Explanation

**Current State (Low):** Existing networks with <1,000 validators produce DKG transcripts of ~144 KB, well below the 2 MB limit.

**Future State (High):** The vulnerability becomes deterministic at scale:
- At 10,000 validators: DKG transcript = 1,440,240 bytes (1.37 MB, approaching limit)
- At 14,562+ validators: DKG transcript = 2,097,168 bytes (exceeds 2 MB limit)

**Triggering Conditions:**
- Natural validator set growth (no malicious actor required)
- Deterministic trigger when validator count reaches threshold
- No automatic recovery mechanism exists

The vulnerability manifests as a time-bomb that will trigger as the network scales to support larger validator sets.

## Recommendation

**Short-term Fix:**
1. Implement size validation when adding transactions to the validator pool
2. Add a mechanism to remove oversized transactions from the pool with appropriate logging
3. Increase `per_block_limit_total_bytes` via governance to accommodate larger validator sets

**Long-term Fix:**
1. Implement chunked DKG transcript submission that splits large transcripts across multiple validator transactions
2. Use weighted DKG schemes that produce smaller transcripts
3. Add automatic timeout mechanisms for incomplete DKG sessions with fallback to non-DKG epoch transitions
4. Implement dynamic per-block limits that scale with validator set size

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a network with 14,562+ validators
2. Initiating a DKG ceremony via epoch timeout
3. Observing that the aggregated DKG transcript exceeds 2 MB
4. Verifying the transcript is added to the pool but never included in blocks
5. Confirming epoch transitions are blocked indefinitely
6. Demonstrating recovery only occurs after governance calls `force_end_epoch()`

The mathematical proof is straightforward: With `G1_PROJ_NUM_BYTES = 48` and `G2_PROJ_NUM_BYTES = 96`, the transcript size is `96 + (14563 * 144) = 2,097,168` bytes, which exceeds the 2,097,152 byte limit by 16 bytes.

## Notes

While block production and user transaction processing continue during this condition, the inability to transition epochs represents a critical protocol-level failure. Essential protocol functions that depend on epoch transitions (validator updates, stake operations, config changes) become permanently disabled until manual governance intervention occurs. This qualifies as a severe liveness issue even though the network continues processing regular transactions.

### Citations

**File:** crates/validator-transaction-pool/src/lib.rs (L74-76)
```rust
        if let Some(old_seq_num) = pool.seq_nums_by_topic.insert(topic.clone(), seq_num) {
            pool.txn_queue.remove(&old_seq_num);
        }
```

**File:** crates/validator-transaction-pool/src/lib.rs (L160-160)
```rust
        let mut seq_num_lower_bound = 0;
```

**File:** crates/validator-transaction-pool/src/lib.rs (L165-173)
```rust
            if let Some(seq_num) = self
                .txn_queue
                .range(seq_num_lower_bound..)
                .filter(|(_, item)| {
                    item.txn.size_in_bytes() as u64 <= max_bytes
                        && !filter.should_exclude(&item.txn)
                })
                .map(|(seq_num, _)| *seq_num)
                .next()
```

**File:** crates/aptos-dkg/tests/pvss.rs (L408-413)
```rust
    if T::scheme_name() == unweighted_protocol::DAS_SK_IN_G1 {
        G2_PROJ_NUM_BYTES
            + (sc.get_total_num_players() + 1) * (G2_PROJ_NUM_BYTES + G1_PROJ_NUM_BYTES)
    } else {
        panic!("Did not implement support for '{}' yet", T::scheme_name())
    }
```

**File:** crates/aptos-crypto/src/blstrs/mod.rs (L27-31)
```rust
/// The size in bytes of a compressed G1 point (efficiently deserializable into projective coordinates)
pub const G1_PROJ_NUM_BYTES: usize = 48;

/// The size in bytes of a compressed G2 point (efficiently deserializable into projective coordinates)
pub const G2_PROJ_NUM_BYTES: usize = 96;
```

**File:** types/src/on_chain_config/consensus_config.rs (L126-126)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB
```

**File:** types/src/validator_txn.rs (L57-59)
```rust
pub enum Topic {
    DKG,
    JWK_CONSENSUS(jwks::Issuer),
```

**File:** dkg/src/dkg_manager/mod.rs (L397-409)
```rust
                let txn = ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: self.epoch_state.epoch,
                        author: self.my_addr,
                    },
                    transcript_bytes: bcs::to_bytes(&agg_trx)
                        .map_err(|e| anyhow!("transcript serialization error: {e}"))?,
                });
                let vtxn_guard = self.vtxn_pool.put(
                    Topic::DKG,
                    Arc::new(txn),
                    Some(self.pull_notification_tx.clone()),
                );
```

**File:** consensus/src/payload_client/mixed.rs (L69-76)
```rust
                min(
                    params.max_txns.count(),
                    self.validator_txn_config.per_block_limit_txn_count(),
                ),
                min(
                    params.max_txns.size_in_bytes(),
                    self.validator_txn_config.per_block_limit_total_bytes(),
                ),
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L244-246)
```text
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration_with_dkg::try_start();
        };
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L25-30)
```text
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-48)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L700-703)
```text
    public entry fun force_end_epoch(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        reconfiguration_with_dkg::finish(aptos_framework);
    }
```
