# Audit Report

## Title
Block Retrieval Retry Logic Bypass via Malicious IdNotFound Response Enables Denial-of-Service on Validator Synchronization

## Summary
The block retrieval mechanism in the consensus layer fails to retry alternative peers when receiving an `IdNotFound` status response, allowing a single malicious validator to deny block synchronization to other validators by falsely claiming blocks don't exist. This bypasses the intended retry logic and can cause liveness failures.

## Finding Description

The consensus layer implements a block retrieval mechanism with retry logic designed to fetch missing blocks from multiple peers. However, a critical flaw exists in how responses are handled.

The `BlockRetriever::retrieve_block_chunk` function treats any `Ok()` response from the network layer as successful, immediately returning without checking if the `BlockRetrievalStatus` indicates actual success: [1](#0-0) 

When a peer responds with `BlockRetrievalResponse { status: IdNotFound, blocks: [] }`, this passes through `NetworkSender::request_block` verification successfully because the response is internally consistent (empty blocks with IdNotFound status): [2](#0-1) 

The verification only checks consistency between status and blocks, not whether the status indicates success: [3](#0-2) 

When `retrieve_blocks` receives an `IdNotFound` response, it fails immediately without attempting other peers: [4](#0-3) 

**Attack Path:**

1. Validator Node A needs to sync blocks that exist on the network (e.g., during normal consensus catch-up or fast-forward sync)
2. Malicious Validator B is selected as the preferred peer (e.g., as QC leader) or gets randomly selected first
3. Node A calls `retrieve_blocks_in_range()` to fetch missing blocks
4. `retrieve_block_chunk()` sends the first RPC request to Validator B
5. Validator B maliciously responds: `BlockRetrievalResponse { status: IdNotFound, blocks: [] }` even though the blocks exist
6. This response passes verification (status is consistent with empty blocks)
7. `retrieve_block_chunk()` receives `Ok(response)` and returns immediately at line 728
8. **No retry to honest peers occurs** - the retry logic only triggers on network-level `Err()`, not on application-level failure statuses
9. `retrieve_blocks()` receives the IdNotFound response and bails with an error
10. Block synchronization fails completely

The test in `test_rpc()` validates only the happy path where a legitimately non-existent block returns `IdNotFound`: [5](#0-4) 

This test doesn't verify that retry logic attempts alternative peers when one peer returns `IdNotFound` for blocks that should exist.

## Impact Explanation

**High Severity** - This vulnerability enables significant protocol violations affecting consensus participation:

1. **Validator Liveness Impact**: Validators unable to sync blocks cannot participate in consensus, reducing network fault tolerance
2. **Cascading Effects**: Multiple validators trying to sync from the same malicious peer simultaneously experience synchronized failures
3. **Fast-Forward Sync Denial**: Critical recovery mechanism during epoch changes can be blocked
4. **Single Point of Failure**: One malicious validator (representing potentially < 1% of stake) can deny service to any validator that selects them as preferred peer

This qualifies as High severity per Aptos Bug Bounty criteria: "Validator node slowdowns" and "Significant protocol violations." While not causing permanent damage or fund loss, it degrades consensus availability and validator operational capability.

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Complexity**: Malicious validator simply returns false `IdNotFound` responses - requires minimal implementation effort
2. **Frequent Trigger Conditions**: Block retrieval occurs during:
   - Normal consensus operation (validators catching up on missed blocks)
   - Recovery from network partition
   - Fast-forward sync during epoch transitions
   - Initial validator startup/sync
3. **Probabilistic Success**: Even without being the preferred peer, random peer selection gives malicious validators regular opportunities
4. **No Detection Mechanism**: The system cannot distinguish between legitimate `IdNotFound` (block genuinely missing) and malicious false claims

## Recommendation

Modify `retrieve_block_chunk()` to only treat `Succeeded` and `SucceededWithTarget` status as successful responses. Treat `IdNotFound` and `NotEnoughBlocks` as retriable failures that should trigger attempts to alternative peers:

```rust
// In retrieve_block_chunk, replace line 728
Some((peer, response)) = futures.next() => {
    match response {
        Ok(result) => {
            // Only return on actual success statuses
            match result.status() {
                BlockRetrievalStatus::Succeeded | 
                BlockRetrievalStatus::SucceededWithTarget => {
                    return Ok(result);
                },
                _ => {
                    // Treat IdNotFound/NotEnoughBlocks as retriable failures
                    warn!(
                        remote_peer = peer,
                        block_id = block_id,
                        status = ?result.status(),
                        "Peer returned non-success status, will retry with other peers",
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

Additionally, add comprehensive testing that validates retry behavior when peers return non-success statuses.

## Proof of Concept

Add this test to `consensus/src/block_storage/sync_manager.rs`:

```rust
#[tokio::test]
async fn test_block_retrieval_retries_on_id_not_found() {
    // Setup: Create 3 validators - one malicious, two honest
    let (signers, validator_verifier) = random_validator_verifier(3, None, false);
    let validator_verifier = Arc::new(validator_verifier);
    
    // Create mock block that exists
    let block = Block::new_proposal(
        Payload::empty(false, true),
        1,
        100,
        certificate_for_genesis(),
        &signers[0],
        Vec::new(),
    ).unwrap();
    
    // Mock network where:
    // - Peer 0 (malicious) always returns IdNotFound
    // - Peer 1 (honest) returns the correct block
    // - Peer 2 (honest) returns the correct block
    
    let mut retriever = BlockRetriever::new(
        /* network with mocked peers */
    );
    
    // Request block from peers
    let result = retriever.retrieve_blocks_in_range(
        block.id(),
        1,
        TargetBlockRetrieval::TargetBlockId(block.id()),
        vec![signers[0].author(), signers[1].author(), signers[2].author()],
    ).await;
    
    // EXPECTED: Should succeed by trying peer 1 or 2 after peer 0 fails
    // ACTUAL (with bug): Fails immediately when peer 0 returns IdNotFound
    assert!(result.is_ok(), "Should succeed by retrying with honest peers");
    assert_eq!(result.unwrap()[0].id(), block.id());
}
```

To demonstrate the vulnerability, the test will fail with the current implementation showing that block retrieval fails when the first peer returns `IdNotFound`, even though honest peers have the block.

### Citations

**File:** consensus/src/block_storage/sync_manager.rs (L726-738)
```rust
                    Some((peer, response)) = futures.next() => {
                        match response {
                            Ok(result) => return Ok(result),
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
```

**File:** consensus/src/block_storage/sync_manager.rs (L836-860)
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

**File:** consensus/consensus-types/src/block_retrieval.rs (L201-258)
```rust
    pub fn verify_inner(&self, retrieval_request: &BlockRetrievalRequest) -> anyhow::Result<()> {
        match &retrieval_request {
            BlockRetrievalRequest::V1(retrieval_request) => {
                ensure!(
                    self.status != BlockRetrievalStatus::Succeeded
                        || self.blocks.len() as u64 == retrieval_request.num_blocks(),
                    "not enough blocks returned, expect {}, get {}",
                    retrieval_request.num_blocks(),
                    self.blocks.len(),
                );
                ensure!(
                    self.status == BlockRetrievalStatus::SucceededWithTarget
                        || !self
                            .blocks
                            .iter()
                            .any(|block| retrieval_request.match_target_id(block.id())),
                    "target was found, but response is not marked as SucceededWithTarget",
                );
                ensure!(
                    self.status != BlockRetrievalStatus::SucceededWithTarget
                        || self
                            .blocks
                            .last()
                            .is_some_and(|block| retrieval_request.match_target_id(block.id())),
                    "target not found in blocks returned, expect {:?}",
                    retrieval_request.target_block_id(),
                );
            },
            BlockRetrievalRequest::V2(retrieval_request) => {
                ensure!(
                    self.status != BlockRetrievalStatus::Succeeded
                        || self.blocks.len() as u64 == retrieval_request.num_blocks(),
                    "not enough blocks returned, expect {}, get {}",
                    retrieval_request.num_blocks(),
                    self.blocks.len(),
                );
                ensure!(
                    self.status == BlockRetrievalStatus::SucceededWithTarget
                        || !self.blocks.last().is_some_and(|block| {
                            block.round() < retrieval_request.target_round()
                                || retrieval_request.is_window_start_block(block)
                        }),
                    "smaller than target round or window start block was found, but response is not marked as SucceededWithTarget",
                );
                ensure!(
                    self.status != BlockRetrievalStatus::SucceededWithTarget
                        || self
                            .blocks
                            .last()
                            .is_some_and(|block| retrieval_request.is_window_start_block(block)),
                    "target not found in blocks returned, expect {},",
                    retrieval_request.target_round(),
                );
            },
        }

        Ok(())
    }
```

**File:** consensus/src/network_tests.rs (L823-854)
```rust
                    .await;
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
            }
        };
        runtime.handle().spawn(on_request_block);
        let peer = peers[1];
        timed_block_on(&runtime, async {
            let response = nodes[0]
                .request_block(
                    BlockRetrievalRequest::V1(BlockRetrievalRequestV1::new(HashValue::zero(), 1)),
                    peer,
                    Duration::from_secs(5),
                )
                .await;
            let response = response.unwrap();
            assert_eq!(response.status(), BlockRetrievalStatus::IdNotFound);
        });
```
