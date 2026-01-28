# Audit Report

## Title
Payload Variant Type Confusion Allows Transaction Injection in Consensus Observer

## Summary
The `BlockTransactionPayload::verify_against_ordered_payload()` function fails to validate that the received payload variant type matches the consensus-agreed payload variant. This allows a malicious consensus observer publisher to inject unauthorized transactions by sending a `QuorumStoreInlineHybrid` payload when consensus only agreed on a simpler `InQuorumStoreWithLimit` payload, bypassing consensus safety guarantees.

## Finding Description

The vulnerability exists in the consensus observer's payload verification logic. When validating a `BlockTransactionPayload` against an ordered block's payload, the system fails to enforce that the variant types match.

**Vulnerable Code Path:**

The verification function matches on the `ordered_block_payload` enum variant but never validates that the received `BlockTransactionPayload` is of a compatible variant type. [1](#0-0) 

When the ordered payload is `Payload::InQuorumStoreWithLimit`, the verification only calls `verify_batches()` and `verify_transaction_limit()`: [2](#0-1) 

These methods extract and compare fields without checking the variant type: [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. Consensus agrees on a block with `Payload::InQuorumStoreWithLimit` containing proof batches `[P1, P2]`, limit 100
2. Malicious VFN publisher sends the legitimate `OrderedBlock` with valid proof
3. Malicious publisher sends `BlockPayload` with `BlockTransactionPayload::QuorumStoreInlineHybrid` containing:
   - Matching proof batches `[P1, P2]`
   - Matching limit 100
   - **Additional inline batches with malicious transactions**
4. Verification passes because only batches and limit are checked
5. During execution, the `transactions()` method returns ALL transactions including malicious inline batch transactions: [5](#0-4) 

The consensus observer payload manager uses these transactions for execution: [6](#0-5) 

**Threat Model Compliance:**

Consensus observer publishers run on both validators and Validator Fullnodes (VFNs): [7](#0-6) 

VFNs are NOT validator operators (who are trusted roles). VFNs are fullnodes that can be run by any network participant. Observers subscribe to publishers based on distance and latency: [8](#0-7) 

Therefore, a malicious VFN publisher is within the threat model as an untrusted network peer.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets the Aptos bug bounty CRITICAL severity criteria:

1. **Consensus Safety Violation**: Different consensus observer nodes execute different transactions for the same consensus-agreed block hash, violating the fundamental safety guarantee that all nodes produce identical state roots for identical blocks.

2. **Loss of Funds**: Injected transactions can transfer funds, mint tokens, or perform any on-chain operation without consensus validation.

3. **State Inconsistency**: Observer nodes processing malicious payloads diverge from honest nodes, potentially requiring emergency intervention or hard fork to recover.

The attack bypasses the entire consensus mechanism by exploiting type confusion in payload verification. The ordered proof cryptographically commits to a specific payload type in the block hash: [9](#0-8) 

However, the separately-transmitted `BlockTransactionPayload` is not verified to match this committed type, allowing transaction injection.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly exploitable because:

1. **No Special Privileges**: Any actor can run a VFN with a malicious publisher. Observers will subscribe to well-connected VFNs based on network proximity and latency.

2. **Trivial Execution**: The attacker only needs to:
   - Run a VFN and enable the publisher
   - Receive legitimate ordered blocks from validators
   - Construct modified `BlockPayload` messages with additional inline batches
   - Forward to subscribed observers

3. **No Detection**: The verification checks pass normally, providing no indication of attack.

4. **Immediate Impact**: Injected transactions execute immediately upon block processing without any additional steps.

## Recommendation

Add variant type validation in `verify_against_ordered_payload()`:

```rust
pub fn verify_against_ordered_payload(
    &self,
    ordered_block_payload: &Payload,
) -> Result<(), Error> {
    match ordered_block_payload {
        Payload::InQuorumStore(proof_with_data) => {
            // Verify self is DeprecatedInQuorumStore variant
            if !matches!(self, BlockTransactionPayload::DeprecatedInQuorumStore(_)) {
                return Err(Error::InvalidMessageError(
                    "Payload variant mismatch: expected InQuorumStore".into()
                ));
            }
            self.verify_batches(&proof_with_data.proofs)?;
        },
        Payload::InQuorumStoreWithLimit(proof_with_data) => {
            // Verify self is DeprecatedInQuorumStoreWithLimit variant
            if !matches!(self, BlockTransactionPayload::DeprecatedInQuorumStoreWithLimit(_)) {
                return Err(Error::InvalidMessageError(
                    "Payload variant mismatch: expected InQuorumStoreWithLimit".into()
                ));
            }
            self.verify_batches(&proof_with_data.proof_with_data.proofs)?;
            self.verify_transaction_limit(proof_with_data.max_txns_to_execute)?;
        },
        // Add similar checks for other variants...
    }
    Ok(())
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus observer node subscribed to a malicious VFN publisher
2. Having the malicious publisher send:
   - Legitimate `OrderedBlock` with `Payload::InQuorumStoreWithLimit` 
   - Modified `BlockPayload` with `BlockTransactionPayload::QuorumStoreInlineHybrid` containing extra inline batches
3. Observing that verification passes and malicious transactions execute

The verification flow is exercised here: [10](#0-9) 

And called during ordered block processing: [11](#0-10)

### Citations

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

**File:** consensus/src/consensus_observer/network/observer_message.rs (L719-737)
```rust
    /// Verifies the payload batches against the expected batches
    fn verify_batches(&self, expected_proofs: &[ProofOfStore<BatchInfo>]) -> Result<(), Error> {
        // Get the batches in the block transaction payload
        let payload_proofs = self.payload_proofs();
        let payload_batches: Vec<&BatchInfo> =
            payload_proofs.iter().map(|proof| proof.info()).collect();

        // Compare the expected batches against the payload batches
        let expected_batches: Vec<&BatchInfo> =
            expected_proofs.iter().map(|proof| proof.info()).collect();
        if expected_batches != payload_batches {
            return Err(Error::InvalidMessageError(format!(
                "Transaction payload failed batch verification! Expected batches {:?}, but found {:?}!",
                expected_batches, payload_batches
            )));
        }

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L805-836)
```rust
    /// Verifies the payload limit against the expected limit
    fn verify_transaction_limit(
        &self,
        expected_transaction_limit: Option<u64>,
    ) -> Result<(), Error> {
        // Get the payload limit
        let limit = match self {
            BlockTransactionPayload::DeprecatedInQuorumStore(_) => {
                return Err(Error::InvalidMessageError(
                    "Transaction payload does not contain a limit!".to_string(),
                ))
            },
            BlockTransactionPayload::DeprecatedInQuorumStoreWithLimit(payload) => {
                payload.transaction_limit
            },
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.transaction_limit
            },
            BlockTransactionPayload::QuorumStoreInlineHybridV2(payload, _)
            | BlockTransactionPayload::OptQuorumStore(payload, _) => payload.transaction_limit(),
        };

        // Compare the expected limit against the payload limit
        if expected_transaction_limit != limit {
            return Err(Error::InvalidMessageError(format!(
                "Transaction payload failed limit verification! Expected limit: {:?}, Found limit: {:?}",
                expected_transaction_limit, limit
            )));
        }

        Ok(())
    }
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L70-76)
```rust
    // Return the transactions and the transaction limit
    Ok((
        transaction_payload.transactions(),
        transaction_payload.transaction_limit(),
        transaction_payload.gas_limit(),
    ))
}
```

**File:** config/src/config/consensus_observer_config.rs (L112-128)
```rust
            NodeType::Validator => {
                if ENABLE_ON_VALIDATORS && !publisher_manually_set {
                    // Only enable the publisher for validators
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
            },
            NodeType::ValidatorFullnode => {
                if ENABLE_ON_VALIDATOR_FULLNODES
                    && !observer_manually_set
                    && !publisher_manually_set
                {
                    // Enable both the observer and the publisher for VFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L275-350)
```rust
/// Sorts the peers by subscription optimality (in descending order of
/// optimality). This requires: (i) sorting the peers by distance from the
/// validator set and ping latency (lower values are more optimal); and (ii)
/// filtering out peers that don't support consensus observer.
///
/// Note: we prioritize distance over latency as we want to avoid close
/// but not up-to-date peers. If peers don't have sufficient metadata
/// for sorting, they are given a lower priority.
pub fn sort_peers_by_subscription_optimality(
    peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) -> Vec<PeerNetworkId> {
    // Group peers and latencies by validator distance, i.e., distance -> [(peer, latency)]
    let mut unsupported_peers = Vec::new();
    let mut peers_and_latencies_by_distance = BTreeMap::new();
    for (peer_network_id, peer_metadata) in peers_and_metadata {
        // Verify that the peer supports consensus observer
        if !supports_consensus_observer(peer_metadata) {
            unsupported_peers.push(*peer_network_id);
            continue; // Skip the peer
        }

        // Get the distance and latency for the peer
        let distance = get_distance_for_peer(peer_network_id, peer_metadata);
        let latency = get_latency_for_peer(peer_network_id, peer_metadata);

        // If the distance is not found, use the maximum distance
        let distance =
            distance.unwrap_or(aptos_peer_monitoring_service_types::MAX_DISTANCE_FROM_VALIDATORS);

        // If the latency is not found, use a large latency
        let latency = latency.unwrap_or(MAX_PING_LATENCY_SECS);

        // Add the peer and latency to the distance group
        peers_and_latencies_by_distance
            .entry(distance)
            .or_insert_with(Vec::new)
            .push((*peer_network_id, OrderedFloat(latency)));
    }

    // If there are peers that don't support consensus observer, log them
    if !unsupported_peers.is_empty() {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Found {} peers that don't support consensus observer! Peers: {:?}",
                unsupported_peers.len(),
                unsupported_peers
            ))
        );
    }

    // Sort the peers by distance and latency. Note: BTreeMaps are
    // sorted by key, so the entries will be sorted by distance in ascending order.
    let mut sorted_peers_and_latencies = Vec::new();
    for (_, mut peers_and_latencies) in peers_and_latencies_by_distance {
        // Sort the peers by latency
        peers_and_latencies.sort_by_key(|(_, latency)| *latency);

        // Add the peers to the sorted list (in sorted order)
        sorted_peers_and_latencies.extend(peers_and_latencies);
    }

    // Log the sorted peers and latencies
    info!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Sorted {} peers by subscription optimality! Peers and latencies: {:?}",
            sorted_peers_and_latencies.len(),
            sorted_peers_and_latencies
        ))
    );

    // Only return the sorted peers (without the latencies)
    sorted_peers_and_latencies
        .into_iter()
        .map(|(peer, _)| peer)
        .collect()
}
```

**File:** consensus/consensus-types/src/block_data.rs (L105-134)
```rust
impl CryptoHash for BlockData {
    type Hasher = BlockDataHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        if self.is_opt_block() {
            #[derive(Serialize)]
            struct OptBlockDataForHash<'a> {
                epoch: u64,
                round: Round,
                timestamp_usecs: u64,
                quorum_cert_vote_data: &'a VoteData,
                block_type: &'a BlockType,
            }

            let opt_block_data_for_hash = OptBlockDataForHash {
                epoch: self.epoch,
                round: self.round,
                timestamp_usecs: self.timestamp_usecs,
                quorum_cert_vote_data: self.quorum_cert.vote_data(),
                block_type: &self.block_type,
            };
            bcs::serialize_into(&mut state, &opt_block_data_for_hash)
                .expect("OptBlockDataForHash must be serializable");
        } else {
            bcs::serialize_into(&mut state, &self).expect("BlockData must be serializable");
        }
        state.finish()
    }
}
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L156-213)
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
