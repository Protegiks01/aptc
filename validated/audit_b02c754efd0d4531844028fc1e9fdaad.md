# Audit Report

## Title
Consensus Safety Violation via Payload Type Confusion in Consensus Observer Verification

## Summary
The `verify_against_ordered_payload()` function in the consensus observer fails to enforce type matching between the ordered block's consensus-certified payload and the separately-received block transaction payload. This allows injection of unauthorized transactions that bypass verification, directly violating consensus safety and causing state divergence across the network.

## Finding Description

The consensus observer architecture separates block ordering from transaction data delivery. Validators agree on block ordering via consensus producing an `OrderedBlock` with a quorum-certified `Payload`, while transaction data arrives separately via `BlockPayload` messages.

**The Critical Flaw:**

The `verify_against_ordered_payload()` function matches on the **ordered block's payload type** but does not enforce that the `BlockTransactionPayload` being verified is of the **same type**. [1](#0-0) 

When the ordered payload is `Payload::InQuorumStore`, verification only calls `verify_batches()` on the proofs field. However, if the `BlockTransactionPayload` is of type `OptQuorumStore`, the second field containing `Vec<BatchInfo>` with opt/inline batch metadata is **never verified** against the ordered payload because the match branches solely on `ordered_block_payload` type.

**Attack Scenario:**

1. **Consensus Agreement:** Honest validators certify a block with `Payload::InQuorumStore` containing empty proofs via quorum certificate

2. **Malicious BlockPayload:** Attacker controlling a consensus publisher node sends `BlockTransactionPayload::OptQuorumStore(TransactionsWithProof{transactions: [malicious_txns], proofs: []}, [attacker_constructed_batch_info])`

3. **Verification Bypass:**
   - When `process_block_payload_message()` receives the payload, `verify_payload_digests()` checks internal consistency [2](#0-1) 
   
   - The attacker constructs transactions that hash to their declared batch_info digests, so this passes
   
   - `verify_payload_signatures()` is called but with empty proofs, the iterator is empty and verification trivially succeeds [3](#0-2) 
   
   - Payload is stored in BlockPayloadStore [4](#0-3) 

4. **Ordered Block Processing:**
   - When `process_ordered_block()` is called, it invokes `verify_payloads_against_ordered_block()` [5](#0-4) 
   
   - This calls `verify_against_ordered_payload()` which matches on `InQuorumStore` and only calls `verify_batches()` [6](#0-5) 
   
   - For `OptQuorumStore`, `payload_proofs()` extracts only the first field (proofs) [7](#0-6) 
   
   - Empty proofs match empty proofs ✓
   - **The `Vec<BatchInfo>` in the second field is NEVER compared against the ordered payload**

5. **Unauthorized Execution:**
   - During execution, `get_transactions()` is called [8](#0-7) 
   
   - The `transactions()` method extracts all transactions from the first field [9](#0-8) 
   
   - Malicious transactions are executed on the attacked observer nodes

**Broken Invariant:**

This violates **Deterministic Execution**: all validators must produce identical state roots for identical blocks. Honest nodes receiving correct payloads execute zero transactions, while attacked consensus observer nodes execute injected transactions, causing **state divergence**.

## Impact Explanation

**Severity: CRITICAL** (Aptos Bug Bounty $1,000,000 tier - Consensus/Safety Violations)

This vulnerability directly violates **Consensus Safety**, meeting the Critical severity criteria:

**Impact:**
- **Consensus Safety Violation:** Different nodes execute different transactions for the same block height at the same round, breaking Byzantine Fault Tolerance guarantees
- **State Divergence:** Honest nodes and attacked consensus observer nodes compute different state roots, causing permanent ledger inconsistency
- **Transaction Injection:** Attackers execute arbitrary transactions without consensus agreement, bypassing normal validation and voting
- **Network Partition:** If sufficient consensus observers are attacked, observers and validators diverge creating network fragmentation
- **Requires Hardfork Recovery:** State divergence between observers and validators necessitates coordinated intervention to resolve

This breaks the fundamental blockchain property that all honest participants agree on the same ledger history and execute the same transactions.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Ability to send consensus observer network messages (available to any peer that can act as a consensus publisher)
- Knowledge of ordered block payload types from network monitoring (publicly observable)
- No validator compromise required
- No special privileges or stake required

**Attack Complexity:**
- Low - attacker simply constructs `BlockTransactionPayload` with mismatched type from ordered `Payload`
- No race conditions or precise timing requirements
- No complex cryptographic operations needed
- The verification logic bug makes exploitation straightforward

**Realistic Deployment:**
- Consensus observers are designed to accept messages from consensus publisher peers
- An attacker can operate a malicious consensus publisher node
- Any consensus observer subscribed to the malicious publisher is vulnerable
- Affects all consensus observer nodes in production deployment

The vulnerability executes whenever consensus observers process blocks with mismatched payload types, making exploitation highly feasible in production environments.

## Recommendation

Enforce type matching between `BlockTransactionPayload` and ordered `Payload` in `verify_against_ordered_payload()`:

```rust
pub fn verify_against_ordered_payload(
    &self,
    ordered_block_payload: &Payload,
) -> Result<(), Error> {
    // Verify type compatibility first
    match (self, ordered_block_payload) {
        (BlockTransactionPayload::OptQuorumStore(_, _), Payload::InQuorumStore(_)) |
        (BlockTransactionPayload::OptQuorumStore(_, _), Payload::InQuorumStoreWithLimit(_)) |
        (BlockTransactionPayload::QuorumStoreInlineHybrid(_, _), Payload::InQuorumStore(_)) => {
            return Err(Error::InvalidMessageError(
                "BlockTransactionPayload type does not match ordered payload type".into()
            ));
        },
        _ => {} // Allow matching types
    }
    
    // Existing verification logic...
}
```

Alternatively, add explicit type checks at the beginning of each match arm to ensure both the ordered payload and transaction payload are of compatible types before proceeding with verification.

## Proof of Concept

While a complete executable PoC would require setting up a full consensus observer environment, the attack flow is:

1. Set up malicious consensus publisher node
2. Wait for validators to certify block with `Payload::InQuorumStore` containing empty/minimal proofs
3. Construct `BlockTransactionPayload::OptQuorumStore`:
   - First field: `TransactionsWithProof` containing malicious transactions and empty proofs
   - Second field: `Vec<BatchInfo>` with metadata where digest = hash(malicious_transactions)
4. Send BlockPayload message to victim consensus observer
5. Send OrderedBlock message with `Payload::InQuorumStore` (empty proofs)
6. Victim's verification passes due to type confusion
7. Malicious transactions execute on victim node
8. State divergence occurs between victim and honest nodes

The vulnerability is confirmed by code inspection showing that `verify_against_ordered_payload()` does not enforce type matching and only verifies the proofs field when the ordered payload is `InQuorumStore`, leaving the opt_and_inline_batches field of `OptQuorumStore` payloads completely unverified.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L616-628)
```rust
    pub fn payload_proofs(&self) -> Vec<ProofOfStore<BatchInfo>> {
        match self {
            BlockTransactionPayload::DeprecatedInQuorumStore(payload) => payload.proofs.clone(),
            BlockTransactionPayload::DeprecatedInQuorumStoreWithLimit(payload) => {
                payload.payload_with_proof.proofs.clone()
            },
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.payload_with_proof.proofs.clone()
            },
            BlockTransactionPayload::QuorumStoreInlineHybridV2(payload, _)
            | BlockTransactionPayload::OptQuorumStore(payload, _) => payload.proofs(),
        }
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L631-645)
```rust
    pub fn transactions(&self) -> Vec<SignedTransaction> {
        match self {
            BlockTransactionPayload::DeprecatedInQuorumStore(payload) => {
                payload.transactions.clone()
            },
            BlockTransactionPayload::DeprecatedInQuorumStoreWithLimit(payload) => {
                payload.payload_with_proof.transactions.clone()
            },
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.payload_with_proof.transactions.clone()
            },
            BlockTransactionPayload::QuorumStoreInlineHybridV2(payload, _)
            | BlockTransactionPayload::OptQuorumStore(payload, _) => payload.transactions(),
        }
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L648-717)
```rust
    pub fn verify_against_ordered_payload(
        &self,
        ordered_block_payload: &Payload,
    ) -> Result<(), Error> {
        match ordered_block_payload {
            Payload::DirectMempool(_) => {
                return Err(Error::InvalidMessageError(
                    "Direct mempool payloads are not supported for consensus observer!".into(),
                ));
            },
            Payload::InQuorumStore(proof_with_data) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proofs)?;
            },
            Payload::InQuorumStoreWithLimit(proof_with_data) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proof_with_data.proofs)?;

                // Verify the transaction limit
                self.verify_transaction_limit(proof_with_data.max_txns_to_execute)?;
            },
            Payload::QuorumStoreInlineHybrid(
                inline_batches,
                proof_with_data,
                max_txns_to_execute,
            ) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proofs)?;

                // Verify the inline batches
                self.verify_inline_batches(inline_batches)?;

                // Verify the transaction limit
                self.verify_transaction_limit(*max_txns_to_execute)?;
            },
            Payload::QuorumStoreInlineHybridV2(
                inline_batches,
                proof_with_data,
                execution_limits,
            ) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proofs)?;

                // Verify the inline batches
                self.verify_inline_batches(inline_batches)?;

                // Verify the transaction limit
                self.verify_transaction_limit(execution_limits.max_txns_to_execute())?;

                // TODO: verify the block gas limit?
            },
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => {
                // Verify the batches in the requested block
                self.verify_batches(p.proof_with_data())?;

                // Verify optQS and inline batches
                self.verify_optqs_and_inline_batches(p.opt_batches(), p.inline_batches())?;

                // Verify the transaction limit
                self.verify_transaction_limit(p.max_txns_to_execute())?;
            },
            Payload::OptQuorumStore(OptQuorumStorePayload::V2(_p)) => {
                return Err(Error::InvalidMessageError(
                    "OptQuorumStorePayload V2 is not supproted".into(),
                ));
            },
        }

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L875-958)
```rust
    pub fn verify_payload_digests(&self) -> Result<(), Error> {
        // Get the block info, transactions, payload proofs and inline batches
        let block_info = self.block.clone();
        let transactions = self.transaction_payload.transactions();
        let payload_proofs = self.transaction_payload.payload_proofs();
        let opt_and_inline_batches = self.transaction_payload.optqs_and_inline_batches();

        // Get the number of transactions, payload proofs and inline batches
        let num_transactions = transactions.len();
        let num_payload_proofs = payload_proofs.len();
        let num_opt_and_inline_batches = opt_and_inline_batches.len();

        // Gather the transactions for each payload batch
        let mut batches_and_transactions = vec![];
        let mut transactions_iter = transactions.into_iter();
        for proof_of_store in &payload_proofs {
            match reconstruct_batch(
                &block_info,
                &mut transactions_iter,
                proof_of_store.info(),
                true,
            ) {
                Ok(Some(batch_transactions)) => {
                    batches_and_transactions
                        .push((proof_of_store.info().clone(), batch_transactions));
                },
                Ok(None) => { /* Nothing needs to be done (the batch was expired) */ },
                Err(error) => {
                    return Err(Error::InvalidMessageError(format!(
                        "Failed to reconstruct payload proof batch! Num transactions: {:?}, \
                        num batches: {:?}, num inline batches: {:?}, failed batch: {:?}, Error: {:?}",
                        num_transactions, num_payload_proofs, num_opt_and_inline_batches, proof_of_store.info(), error
                    )));
                },
            }
        }

        // Gather the transactions for each inline batch
        for batch_info in opt_and_inline_batches.iter() {
            match reconstruct_batch(&block_info, &mut transactions_iter, batch_info, false) {
                Ok(Some(batch_transactions)) => {
                    batches_and_transactions.push((batch_info.clone(), batch_transactions));
                },
                Ok(None) => {
                    return Err(Error::UnexpectedError(format!(
                        "Failed to reconstruct inline/opt batch! Batch was unexpectedly skipped: {:?}",
                        batch_info
                    )));
                },
                Err(error) => {
                    return Err(Error::InvalidMessageError(format!(
                        "Failed to reconstruct inline/opt batch! Num transactions: {:?}, \
                        num batches: {:?}, num opt/inline batches: {:?}, failed batch: {:?}, Error: {:?}",
                        num_transactions, num_payload_proofs, num_opt_and_inline_batches, batch_info, error
                    )));
                },
            }
        }

        // Verify all the reconstructed batches (in parallel)
        batches_and_transactions
            .into_par_iter()
            .with_min_len(2)
            .try_for_each(|(batch_info, transactions)| verify_batch(&batch_info, transactions))
            .map_err(|error| {
                Error::InvalidMessageError(format!(
                    "Failed to verify the payload batches and transactions! Error: {:?}",
                    error
                ))
            })?;

        // Verify that there are no transactions remaining (all transactions should be consumed)
        let remaining_transactions = transactions_iter.as_slice();
        if !remaining_transactions.is_empty() {
            return Err(Error::InvalidMessageError(format!(
                "Failed to verify payload transactions! Num transactions: {:?}, \
                transactions remaining: {:?}. Expected: 0",
                num_transactions,
                remaining_transactions.len()
            )));
        }

        Ok(()) // All digests match
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L962-981)
```rust
    pub fn verify_payload_signatures(&self, epoch_state: &EpochState) -> Result<(), Error> {
        // Create a dummy proof cache to verify the proofs
        let proof_cache = ProofCache::new(1);

        // Verify each of the proof signatures (in parallel)
        let payload_proofs = self.transaction_payload.payload_proofs();
        let validator_verifier = &epoch_state.verifier;
        payload_proofs
            .par_iter()
            .with_min_len(2)
            .try_for_each(|proof| proof.verify(validator_verifier, &proof_cache))
            .map_err(|error| {
                Error::InvalidMessageError(format!(
                    "Failed to verify the payload proof signatures! Error: {:?}",
                    error
                ))
            })?;

        Ok(()) // All proofs are correctly signed
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L427-430)
```rust
        // Update the payload store with the payload
        self.observer_block_data
            .lock()
            .insert_block_payload(block_payload, verified_payload);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L754-771)
```rust
        // Verify the block payloads against the ordered block
        if let Err(error) = self
            .observer_block_data
            .lock()
            .verify_payloads_against_ordered_block(&ordered_block)
        {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payloads against ordered block! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                    ordered_block.proof_block_info(),
                    peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L156-200)
```rust
    /// Verifies all block payloads against the given ordered block.
    /// If verification fails, an error is returned.
    pub fn verify_payloads_against_ordered_block(
        &mut self,
        ordered_block: &OrderedBlock,
    ) -> Result<(), Error> {
        // Verify each of the blocks in the ordered block
        for ordered_block in ordered_block.blocks() {
            // Get the block epoch and round
            let block_epoch = ordered_block.epoch();
            let block_round = ordered_block.round();

            // Fetch the block payload
            match self.block_payloads.lock().entry((block_epoch, block_round)) {
                Entry::Occupied(entry) => {
                    // Get the block transaction payload
                    let transaction_payload = match entry.get() {
                        BlockPayloadStatus::AvailableAndVerified(block_payload) => {
                            block_payload.transaction_payload()
                        },
                        BlockPayloadStatus::AvailableAndUnverified(_) => {
                            // The payload should have already been verified
                            return Err(Error::InvalidMessageError(format!(
                                "Payload verification failed! Block payload for epoch: {:?} and round: {:?} is unverified.",
                                ordered_block.epoch(),
                                ordered_block.round()
                            )));
                        },
                    };

                    // Get the ordered block payload
                    let ordered_block_payload = match ordered_block.block().payload() {
                        Some(payload) => payload,
                        None => {
                            return Err(Error::InvalidMessageError(format!(
                                "Payload verification failed! Missing block payload for epoch: {:?} and round: {:?}",
                                ordered_block.epoch(),
                                ordered_block.round()
                            )));
                        },
                    };

                    // Verify the transaction payload against the ordered block payload
                    transaction_payload.verify_against_ordered_payload(ordered_block_payload)?;
                },
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L71-75)
```rust
    Ok((
        transaction_payload.transactions(),
        transaction_payload.transaction_limit(),
        transaction_payload.gas_limit(),
    ))
```
