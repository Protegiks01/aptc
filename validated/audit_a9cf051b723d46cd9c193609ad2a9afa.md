# Audit Report

## Title
Block Retrieval Retry Logic Bypass via Malicious IdNotFound Response Enables Denial-of-Service on Validator Synchronization

## Summary
A critical flaw in the consensus layer's block retrieval mechanism allows a single malicious validator to prevent other validators from synchronizing blocks by returning false `IdNotFound` responses. The retry logic incorrectly treats any `Ok()` network response as successful and returns immediately, bypassing the intended multi-peer retry mechanism when the response contains an application-level failure status.

## Finding Description

The block retrieval system implements a retry mechanism intended to fetch blocks from multiple peers when synchronization is needed. However, a fundamental flaw exists in how responses are processed.

In `retrieve_block_chunk`, any `Ok()` response from the network layer causes immediate function return, without examining the `BlockRetrievalStatus` field: [1](#0-0) 

When a peer responds with `BlockRetrievalResponse { status: IdNotFound, blocks: [] }`, this passes through `NetworkSender::request_block` verification because the verification only checks internal consistency (status matches blocks array), not whether the status indicates success: [2](#0-1) [3](#0-2) 

The verification confirms that an `IdNotFound` status with empty blocks is internally consistent and valid. However, when `retrieve_blocks` receives this response, it immediately fails without attempting alternative peers: [4](#0-3) 

**Critical Design Flaw**: On the first retrieval attempt, only the preferred peer is contacted: [5](#0-4) [6](#0-5) 

The preferred peer is typically the QC leader or the validator who sent a sync message. If this peer is malicious and responds with `IdNotFound`, the immediate return at line 728 prevents any retry to honest validators.

**Attack Execution Path**:
1. Validator A needs to sync blocks (during consensus catch-up, fast-forward sync, or QC insertion)
2. Malicious Validator B is the preferred peer (QC leader or sync message sender)
3. `retrieve_blocks_in_range` → `retrieve_blocks` → `retrieve_block_chunk` is called
4. First attempt contacts only Validator B (the preferred peer)
5. Validator B responds: `BlockRetrievalResponse { status: IdNotFound, blocks: [] }` even though blocks exist
6. Response passes verification (internal consistency check only)
7. Line 728 returns immediately with `Ok(response)`
8. Control returns to `retrieve_blocks` which bails at line 852-859
9. Block synchronization fails completely without trying honest peers
10. Validator A cannot participate in consensus for affected blocks

This affects critical synchronization paths including `fetch_quorum_cert`, `fast_forward_sync`, and `add_certs`: [7](#0-6) [8](#0-7) 

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria for "Validator node slowdowns" and "Significant protocol violations."

The vulnerability enables:

1. **Validator Operational Degradation**: Validators unable to retrieve blocks cannot process new proposals, vote on blocks, or participate in consensus rounds, reducing effective network fault tolerance below the intended Byzantine threshold.

2. **Targeted Liveness Attacks**: A malicious validator with < 1% stake can selectively target specific validators by becoming their preferred peer (through QC leadership or sync message timing), causing those validators to lag behind consensus.

3. **Fast-Forward Sync Denial**: During epoch transitions and recovery scenarios, validators rely on fast-forward sync to catch up. Blocking this mechanism prevents validators from rejoining consensus after temporary disconnections.

4. **Cascading Synchronization Failures**: When multiple validators select the same malicious peer as preferred peer (e.g., the round leader), they experience synchronized sync failures, amplifying the impact.

While this does not cause permanent network halt or fund loss, it significantly degrades validator operational capability and creates a denial-of-service vector that violates the protocol's Byzantine fault tolerance assumptions. The system assumes that honest validators (>2/3) can provide blocks, but the retry logic fails to leverage this redundancy when the first-attempted peer is malicious.

This is NOT a traditional "Network DoS attack" (bandwidth flooding, packet storms) but rather a protocol logic vulnerability where valid messages exploit flawed retry behavior.

## Likelihood Explanation

**High Likelihood**:

1. **Low Attack Complexity**: A malicious validator simply returns `IdNotFound` responses to legitimate block retrieval requests. Requires no sophisticated timing, cryptographic breaks, or complex orchestration.

2. **Frequent Trigger Conditions**: Block retrieval occurs continuously during:
   - Normal consensus operation (validators catching up by 1-2 rounds)
   - Network partition recovery  
   - Epoch transitions (fast-forward sync)
   - Validator restart/resync operations
   - QC insertion when blocks are missing

3. **Probabilistic Success**: The malicious validator gains opportunities through:
   - Being selected as QC leader (rotates among validators)
   - Being the author of sync messages sent to lagging validators
   - Random peer selection when preferred peer unavailable
   
4. **No Detection or Attribution**: The system cannot distinguish between:
   - Legitimate `IdNotFound` (block genuinely doesn't exist on that peer)
   - Malicious `IdNotFound` (peer lying about block existence)
   
   There is no reputation system, slashing mechanism, or anomaly detection to identify malicious behavior.

5. **Repeatable Exploitation**: The attack can be executed repeatedly across multiple sync attempts, prolonging the denial-of-service effect.

## Recommendation

Modify `retrieve_block_chunk` to check the `BlockRetrievalStatus` before returning and only treat `Succeeded` or `SucceededWithTarget` as successful responses. For other statuses (`IdNotFound`, `NotEnoughBlocks`), continue the retry loop to attempt additional peers:

```rust
Some((peer, response)) = futures.next() => {
    match response {
        Ok(result) => {
            match result.status() {
                BlockRetrievalStatus::Succeeded | BlockRetrievalStatus::SucceededWithTarget => {
                    return Ok(result);
                },
                _ => {
                    // Treat application-level failures like network errors
                    warn!(
                        remote_peer = peer,
                        block_id = block_id,
                        status = ?result.status(),
                        "Peer returned unsuccessful status, retrying with other peers"
                    );
                    failed_attempt += 1;
                }
            }
        },
        e => {
            warn!(
                remote_peer = peer,
                block_id = block_id,
                "{:?}, Failed to fetch block",
                e,
            );
            failed_attempt += 1;
        },
    }
},
```

Additionally, consider implementing:
1. **Reputation tracking**: Record peers that frequently return `IdNotFound` for blocks that other peers successfully provide
2. **Parallel first-attempt**: Contact 2-3 peers on the first attempt rather than only the preferred peer
3. **Status logging**: Enhanced observability for block retrieval failures to detect patterns

## Proof of Concept

While a complete end-to-end PoC would require a full testnet environment, the vulnerability can be demonstrated through the existing test infrastructure by modifying `test_rpc`: [9](#0-8) 

This test shows that `IdNotFound` responses are accepted as valid. To demonstrate the vulnerability:

1. Modify the test to track whether retry attempts to alternative peers occur after `IdNotFound`
2. Verify that no additional peer requests are made after the preferred peer returns `IdNotFound`
3. Confirm that `retrieve_blocks` fails immediately rather than attempting the other available validator

The existing code structure makes this vulnerability directly observable: setting a breakpoint at line 728 will show immediate return on `IdNotFound`, and checking the futures queue will reveal no pending requests to alternative peers.

## Notes

This vulnerability exists at the intersection of network protocol design and retry logic implementation. The core issue is treating network-level success (`Ok()`) as application-level success, when in fact the `BlockRetrievalStatus` enum exists specifically to distinguish between successful retrieval and various failure modes.

The system's Byzantine fault tolerance depends on the ability to retrieve blocks from honest validators (>2/3 of the network). By accepting the first response regardless of status, the retry mechanism fails to leverage this redundancy, effectively creating a single point of failure where one malicious validator can deny service.

The vulnerability is particularly impactful because the preferred peer is often the round leader or a well-connected validator, giving malicious actors in these positions disproportionate ability to disrupt synchronization.

### Citations

**File:** consensus/src/block_storage/sync_manager.rs (L249-257)
```rust
            let mut blocks = retriever
                .retrieve_blocks_in_range(
                    retrieve_qc.certified_block().id(),
                    1,
                    target_block_retrieval_payload,
                    qc.ledger_info()
                        .get_voters(&retriever.validator_addresses()),
                )
                .await?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L394-403)
```rust
        let mut blocks = retriever
            .retrieve_blocks_in_range(
                highest_quorum_cert.certified_block().id(),
                num_blocks,
                target_block_retrieval_payload,
                highest_quorum_cert
                    .ledger_info()
                    .get_voters(&retriever.validator_addresses()),
            )
            .await?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L726-728)
```rust
                    Some((peer, response)) = futures.next() => {
                        match response {
                            Ok(result) => return Ok(result),
```

**File:** consensus/src/block_storage/sync_manager.rs (L742-749)
```rust
                        let next_peers = if cur_retry < num_retries {
                            let first_attempt = cur_retry == 0;
                            cur_retry += 1;
                            self.pick_peers(
                                first_attempt,
                                &mut peers,
                                if first_attempt { 1 } else {request_num_peers}
                            )
```

**File:** consensus/src/block_storage/sync_manager.rs (L836-859)
```rust
            match response {
                Ok(result) if matches!(result.status(), BlockRetrievalStatus::Succeeded) => {
                    // extend the result blocks
                    let batch = result.blocks().clone();
                    progress += batch.len() as u64;
                    last_block_id = batch.last().expect("Batch should not be empty").parent_id();
                    result_blocks.extend(batch);
                },
                Ok(result)
                    if matches!(result.status(), BlockRetrievalStatus::SucceededWithTarget) =>
                {
                    // if we found the target, end the loop
                    let batch = result.blocks().clone();
                    result_blocks.extend(batch);
                    break;
                },
                res => {
                    bail!(
                        "Failed to fetch block {}, for original start {}, returned status {:?}",
                        last_block_id,
                        block_id,
                        res
                    );
                },
```

**File:** consensus/src/block_storage/sync_manager.rs (L918-935)
```rust
    fn pick_peer(&self, first_atempt: bool, peers: &mut Vec<AccountAddress>) -> AccountAddress {
        assert!(!peers.is_empty(), "pick_peer on empty peer list");

        if first_atempt {
            // remove preferred_peer if its in list of peers
            // (strictly speaking it is not required to be there)
            for i in 0..peers.len() {
                if peers[i] == self.preferred_peer {
                    peers.remove(i);
                    break;
                }
            }
            return self.preferred_peer;
        }

        let peer_idx = thread_rng().gen_range(0, peers.len());
        peers.remove(peer_idx)
    }
```

**File:** consensus/src/network.rs (L301-313)
```rust
        // Verify response against retrieval request
        response
            .verify(retrieval_request, &self.validators)
            .map_err(|e| {
                error!(
                    SecurityEvent::InvalidRetrievedBlock,
                    request_block_response = response,
                    error = ?e,
                );
                e
            })?;

        Ok(response)
```

**File:** consensus/consensus-types/src/block_retrieval.rs (L260-281)
```rust
    pub fn verify(
        &self,
        retrieval_request: BlockRetrievalRequest,
        sig_verifier: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        self.verify_inner(&retrieval_request)?;

        self.blocks
            .iter()
            .try_fold(retrieval_request.block_id(), |expected_id, block| {
                block.validate_signature(sig_verifier)?;
                block.verify_well_formed()?;
                ensure!(
                    block.id() == expected_id,
                    "blocks doesn't form a chain: expect {}, get {}",
                    expected_id,
                    block.id()
                );
                Ok(block.parent_id())
            })
            .map(|_| ())
    }
```

**File:** consensus/src/network_tests.rs (L824-839)
```rust
                let response =
                    BlockRetrievalResponse::new(BlockRetrievalStatus::IdNotFound, vec![]);
                let response = ConsensusMsg::BlockRetrievalResponse(Box::new(response));
                let bytes = Bytes::from(serde_json::to_vec(&response).unwrap());
                // TODO: @bchocho @hariria can change after all nodes upgrade to release with enum BlockRetrievalRequest (not struct)
                match request {
                    IncomingRpcRequest::DeprecatedBlockRetrieval(request) => {
                        request.response_sender.send(Ok(bytes)).unwrap()
                    },
                    // TODO @bchocho @hariria fix after release, this is a sanity check to make sure
                    // we're not making new BlockRetrievalRequest network requests anywhere
                    IncomingRpcRequest::BlockRetrieval(request) => {
                        request.response_sender.send(Ok(bytes)).unwrap()
                    },
                    request => panic!("test_rpc unexpected message {:?}", request),
                }
```
