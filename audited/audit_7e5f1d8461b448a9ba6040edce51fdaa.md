# Audit Report

## Title
Consensus Safety Violation via Payload Type Confusion in Consensus Observer Verification

## Summary
The `verify_against_ordered_payload()` function in the consensus observer fails to enforce type consistency between the ordered block's consensus-certified payload and the separately-received block transaction payload. This type confusion allows injection of unauthorized transactions that pass verification but were never agreed upon by consensus, causing state divergence across the network.

## Finding Description

The consensus observer architecture separates block ordering from transaction data delivery. Validators agree on an `OrderedBlock` with a specific `Payload` type through consensus, while transaction data arrives separately via `BlockPayload` messages. The `verify_against_ordered_payload()` function must ensure these match.

**The Critical Flaw:**

The verification function matches on the **ordered payload's type** without enforcing that the received `BlockTransactionPayload` is of the same type. [1](#0-0) 

When the ordered payload is `Payload::InQuorumStore`, verification only calls `verify_batches()` to check proofs. [2](#0-1) 

However, if the `BlockTransactionPayload` is `OptQuorumStore` (different type), it contains an additional field of opt/inline batches that are never validated. [3](#0-2) 

**Attack Scenario:**

1. Consensus agrees on `Payload::InQuorumStore` with empty proofs
2. Attacker sends `BlockTransactionPayload::OptQuorumStore` with:
   - Empty proofs (matches ordered payload)
   - Non-empty opt/inline batches with arbitrary transactions
3. `verify_payload_digests()` passes - it reconstructs all batches and verifies digests match [4](#0-3) 
4. `verify_against_ordered_payload()` passes - it only checks proofs (both empty) and never validates the opt/inline batches
5. During execution, `transactions()` returns all transactions including the injected ones [5](#0-4) 

The opt/inline batches in `OptQuorumStore` are unsigned `BatchInfo` metadata that an attacker can fabricate with correct digests for arbitrary transactions. Since verification only checks the ordered payload type's fields, mismatched payload types bypass validation.

The execution flow confirms the vulnerability: [6](#0-5)  calls `verify_payloads_against_ordered_block()` [7](#0-6)  which invokes the vulnerable verification, then proceeds to finalize and execute the block. [8](#0-7) 

## Impact Explanation

**Severity: CRITICAL**

This qualifies as a **Consensus/Safety Violation** under the Aptos Bug Bounty program's Critical severity category (up to $1,000,000).

**Impact:**
- **Consensus Safety Violation**: Different nodes execute different transactions for the same consensus-agreed block, breaking Byzantine Fault Tolerance guarantees
- **State Divergence**: Honest observers execute zero transactions while attacked observers execute injected transactions, producing different state roots
- **Network Partition**: Sufficient attacked nodes cause network fragmentation
- **Deterministic Execution Broken**: Violates the fundamental blockchain invariant that all honest nodes produce identical state for identical blocks

The vulnerability enables an attacker to make consensus observer nodes execute transactions that were never voted on by validators, directly violating the security guarantees of AptosBFT consensus.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Must be a consensus observer publisher peer (or compromise one)
- Network monitoring to observe ordered block payload types
- No validator compromise or special privileges required beyond network peer status

**Attack Complexity:**
- Low technical complexity - construct mismatched payload types
- No race conditions or timing requirements
- Straightforward exploitation once publisher access is obtained

**Realistic Deployment:**
- Consensus observers subscribe to publisher peers for block data
- Publishers are typically validators or well-connected infrastructure nodes
- A compromised validator, malicious infrastructure provider, or adversarial peer that gains subscription could exploit this
- Observers are production components in the Aptos network

The practical barrier is that observers typically subscribe to trusted peers, but the threat model includes any network peer as potentially malicious. A single compromised publisher can attack all its subscribers.

## Recommendation

Enforce strict type matching between the ordered payload and block transaction payload in `verify_against_ordered_payload()`:

1. Add a type consistency check at the start of verification
2. Ensure `BlockTransactionPayload` variant matches `Payload` variant
3. Reject mismatched types with a clear error

The fix should verify that when consensus agrees on `InQuorumStore`, only `DeprecatedInQuorumStore` or `DeprecatedInQuorumStoreWithLimit` block transaction payloads are accepted, preventing type confusion attacks.

## Proof of Concept

The report does not include a working PoC. However, the vulnerability is confirmed through code analysis showing the execution path allows mismatched payload types to bypass validation, enabling unauthorized transaction injection.

**Notes**

This vulnerability affects the consensus observer component, which is part of Aptos Core's consensus layer. The type confusion occurs because verification logic branches on the ordered (consensus-agreed) payload type without validating that the received payload is of the same type. Since opt/inline batches in `OptQuorumStore` are unsigned metadata (just `BatchInfo` structs), an attacker can fabricate them with correct digests for arbitrary transactions. The digest verification in `verify_payload_digests()` only ensures transactions match their declared batches, not that those batches were agreed upon by consensus. This breaks the trust chain between consensus agreement and execution.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L504-507)
```rust
    OptQuorumStore(
        TransactionsWithProof,
        /* OptQS and Inline Batches */ Vec<BatchInfo>,
    ),
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L275-301)
```rust
        for block in ordered_block.blocks() {
            let commit_callback =
                block_data::create_commit_callback(self.observer_block_data.clone());
            self.pipeline_builder().build_for_observer(
                block,
                parent_fut.take().expect("future should be set"),
                commit_callback,
            );
            parent_fut = Some(block.pipeline_futs().expect("pipeline futures just built"));
        }

        // Send the ordered block to the execution pipeline
        if let Err(error) = self
            .execution_client
            .finalize_order(
                ordered_block.blocks().clone(),
                WrappedLedgerInfo::new(VoteData::dummy(), ordered_block.ordered_proof().clone()),
            )
            .await
        {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to finalize ordered block! Error: {:?}",
                    error
                ))
            );
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L718-771)
```rust
    async fn process_ordered_block(
        &mut self,
        pending_block_with_metadata: Arc<PendingBlockWithMetadata>,
    ) {
        // Unpack the pending block
        let (peer_network_id, message_received_time, observed_ordered_block) =
            pending_block_with_metadata.unpack();
        let ordered_block = observed_ordered_block.ordered_block().clone();

        // Verify the ordered block proof
        let epoch_state = self.get_epoch_state();
        if ordered_block.proof_block_info().epoch() == epoch_state.epoch {
            if let Err(error) = ordered_block.verify_ordered_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify ordered proof! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        ordered_block.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
                return;
            }
        } else {
            // Drop the block and log an error (the block should always be for the current epoch)
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received ordered block for a different epoch! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
            return;
        };

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

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L158-213)
```rust
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
                Entry::Vacant(_) => {
                    // The payload is missing (this should never happen)
                    return Err(Error::InvalidMessageError(format!(
                        "Payload verification failed! Missing block payload for epoch: {:?} and round: {:?}",
                        ordered_block.epoch(),
                        ordered_block.round()
                    )));
                },
            }
        }

        Ok(())
    }
```
