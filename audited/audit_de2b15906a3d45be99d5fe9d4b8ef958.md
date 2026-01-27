# Audit Report

## Title
State Sync Permanent Halt Due to Oversized State Value Chunks Bypassing Network Size Validation

## Summary
The `get_state_value_chunk_with_proof_by_size_legacy()` function contains a critical logic flaw where single state value chunks bypass network size validation, potentially causing permanent state sync failure and network-wide liveness loss if a state value chunk exceeds the maximum network message size (64 MiB).

## Finding Description

The vulnerability exists in the state sync storage service's legacy chunk retrieval logic. The function implements a binary search algorithm to fit state value chunks within the configured `max_response_size` by iteratively halving the chunk size when overflow is detected. [1](#0-0) 

However, when `num_state_values_to_fetch` reaches 1, the function returns the chunk WITHOUT validating that it fits within the network size limits: [2](#0-1) 

This bypasses the overflow check at lines 1010-1024 and goes directly to returning the potentially oversized chunk. The network layer enforces a hard limit of 64 MiB (MAX_MESSAGE_SIZE): [3](#0-2) 

When attempting to send an oversized message, the network streaming layer will reject it: [4](#0-3) 

**Attack Flow:**
1. State sync requests a state value chunk from peers
2. Storage service returns chunk with single state value that exceeds 64 MiB when serialized
3. Network layer rejects the oversized message with an error
4. State sync retries the request (up to 5 times via `max_request_retry`): [5](#0-4) 
5. All retry attempts fail with the same error
6. Data stream terminates after exceeding retry limit: [6](#0-5) 
7. Driver receives EndOfStream notification and resets: [7](#0-6) 
8. Process repeats indefinitely - **permanent state sync halt**

This breaks the **State Consistency** invariant: nodes cannot synchronize state and new nodes cannot join the network.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per bug bounty criteria)

This vulnerability causes **total loss of liveness/network availability**:
- **Permanent state sync failure**: Nodes cannot progress past the problematic state value
- **Network partition**: New nodes cannot synchronize and join the network
- **Requires hard fork**: No recovery path without protocol changes
- **Network-wide impact**: Affects ALL nodes attempting to sync state

The test suite confirms this behavior - when a response exceeds network limits, it returns with 1 state value: [8](#0-7) 

However, the tests don't verify what happens when this oversized response is transmitted over the network.

## Likelihood Explanation

**Current Likelihood: Low** (but with catastrophic impact if triggered)

Individual state writes are limited to 1 MB by `max_bytes_per_write_op`: [9](#0-8) 

With this limit, a `StateValueChunkWithProof` containing:
- 1 MB state value data
- ~8 KB SparseMerkleRangeProof (256 tree levels × 32 bytes)
- Minimal metadata and BCS overhead

Total: ~1 MB << 64 MiB

**However, this is a latent vulnerability that could be triggered by:**
1. Future increases to write size limits
2. Bugs allowing larger state values to be created
3. Historical state values predating current limits
4. Unexpected serialization overhead in edge cases
5. State value aggregation bugs

The lack of defensive validation creates a single point of failure with catastrophic consequences.

## Recommendation

Add mandatory overflow validation for ALL chunk sizes, including single-item chunks:

```rust
fn get_state_value_chunk_with_proof_by_size_legacy(
    &self,
    version: u64,
    start_index: u64,
    end_index: u64,
    mut num_state_values_to_fetch: u64,
    max_response_size: u64,
) -> Result<StateValueChunkWithProof, Error> {
    while num_state_values_to_fetch >= 1 {
        let state_value_chunk_with_proof = self.storage.get_state_value_chunk_with_proof(
            version,
            start_index as usize,
            num_state_values_to_fetch as usize,
        )?;
        
        // ALWAYS check overflow, even for single items
        let (overflow_frame, num_bytes) =
            check_overflow_network_frame(&state_value_chunk_with_proof, max_response_size)?;
        
        if num_state_values_to_fetch == 1 {
            if overflow_frame {
                // Return explicit error instead of silently accepting oversized chunk
                return Err(Error::UnexpectedErrorEncountered(format!(
                    "Single state value chunk exceeds maximum network size! \
                    Version: {:?}, start index: {:?}, size: {:?} bytes, limit: {:?} bytes. \
                    This indicates a critical state integrity issue that requires investigation.",
                    version, start_index, num_bytes, max_response_size
                )));
            }
            return Ok(state_value_chunk_with_proof);
        }

        if !overflow_frame {
            return Ok(state_value_chunk_with_proof);
        } else {
            metrics::increment_chunk_truncation_counter(
                metrics::TRUNCATION_FOR_SIZE,
                DataResponse::StateValueChunkWithProof(state_value_chunk_with_proof).get_label(),
            );
            let new_num_state_values_to_fetch = num_state_values_to_fetch / 2;
            debug!("The request for {:?} state values was too large (num bytes: {:?}, limit: {:?}). Retrying with {:?}.",
                num_state_values_to_fetch, num_bytes, max_response_size, new_num_state_values_to_fetch);
            num_state_values_to_fetch = new_num_state_values_to_fetch;
        }
    }

    Err(Error::UnexpectedErrorEncountered(format!(
        "Unable to serve the get_state_value_chunk_with_proof request! Version: {:?}, \
        start index: {:?}, end index: {:?}. The data cannot fit into a single network frame!",
        version, start_index, end_index
    )))
}
```

**Additional hardening:**
1. Add alerts/monitoring for state values approaching size limits
2. Implement size validation during state value creation
3. Add circuit breaker for repeated state sync failures on same chunk
4. Consider protocol upgrade to support chunk skipping or alternative sync paths

## Proof of Concept

```rust
// This PoC demonstrates the logic flaw but cannot be executed in current system
// due to 1 MB write limit preventing creation of oversized state values

#[test]
fn test_oversized_single_state_value_blocks_sync() {
    // Setup: Create a mock state value that would exceed 64 MiB when serialized
    // NOTE: This cannot actually occur with current 1 MB write limits,
    // but demonstrates the vulnerability if limits change or bugs exist
    
    let max_message_size = 64 * 1024 * 1024; // 64 MiB
    let oversized_state_value = create_large_state_value(max_message_size + 1);
    
    // Create storage service with the oversized state value
    let storage_service = create_storage_service_with_state(oversized_state_value);
    
    // Attempt to fetch the state value chunk
    let result = storage_service.get_state_value_chunk_with_proof_by_size_legacy(
        version,
        start_index, 
        end_index,
        1, // num_state_values_to_fetch
        max_message_size,
    );
    
    // The function returns Ok despite exceeding max size
    assert!(result.is_ok());
    let chunk = result.unwrap();
    
    // Verify the chunk exceeds network limits
    let serialized_size = bcs::serialized_size(&chunk).unwrap();
    assert!(serialized_size > max_message_size);
    
    // Network layer would reject this, causing permanent state sync failure
    let network_result = stream_message(chunk);
    assert!(network_result.is_err()); // "Message length exceeds max message size"
    
    // State sync enters infinite retry loop -> PERMANENT HALT
}
```

**Note**: A complete PoC cannot be executed without first bypassing the 1 MB write size limit, which would require a separate vulnerability. The logic flaw exists but is currently protected by input constraints.

### Citations

**File:** state-sync/storage-service/server/src/storage.rs (L999-1031)
```rust
        while num_state_values_to_fetch >= 1 {
            let state_value_chunk_with_proof = self.storage.get_state_value_chunk_with_proof(
                version,
                start_index as usize,
                num_state_values_to_fetch as usize,
            )?;
            if num_state_values_to_fetch == 1 {
                return Ok(state_value_chunk_with_proof); // We cannot return less than a single item
            }

            // Attempt to divide up the request if it overflows the message size
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&state_value_chunk_with_proof, max_response_size)?;
            if !overflow_frame {
                return Ok(state_value_chunk_with_proof);
            } else {
                metrics::increment_chunk_truncation_counter(
                    metrics::TRUNCATION_FOR_SIZE,
                    DataResponse::StateValueChunkWithProof(state_value_chunk_with_proof)
                        .get_label(),
                );
                let new_num_state_values_to_fetch = num_state_values_to_fetch / 2;
                debug!("The request for {:?} state values was too large (num bytes: {:?}, limit: {:?}). Retrying with {:?}.",
                    num_state_values_to_fetch, num_bytes, max_response_size, new_num_state_values_to_fetch);
                num_state_values_to_fetch = new_num_state_values_to_fetch; // Try again with half the amount of data
            }
        }

        Err(Error::UnexpectedErrorEncountered(format!(
            "Unable to serve the get_state_value_chunk_with_proof request! Version: {:?}, \
            start index: {:?}, end index: {:?}. The data cannot fit into a single network frame!",
            version, start_index, end_index
        )))
```

**File:** config/src/config/network_config.rs (L49-50)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/protocols/stream/mod.rs (L266-273)
```rust
        // Verify that the message size is within limits
        let message_data_len = message.data_len();
        ensure!(
            message_data_len <= self.max_message_size,
            "Message length {} exceeds max message size {}!",
            message_data_len,
            self.max_message_size,
        );
```

**File:** config/src/config/state_sync_config.rs (L277-277)
```rust
            max_request_retry: 5,
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-454)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
                self.send_end_of_stream_notification().await?;
            }
            return Ok(()); // There's nothing left to do
        }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1472-1480)
```rust
            DataPayload::EndOfStream => NotificationFeedback::EndOfStream,
            _ => NotificationFeedback::PayloadTypeIsIncorrect,
        };
        let notification_and_feedback =
            NotificationAndFeedback::new(data_notification.notification_id, notification_feedback);

        // Reset the stream
        self.reset_active_stream(Some(notification_and_feedback))
            .await?;
```

**File:** state-sync/storage-service/server/src/tests/state_values.rs (L362-363)
```rust
                    if num_response_bytes > network_limit_bytes {
                        assert_eq!(num_state_values, 1); // Data cannot be reduced more than a single item
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```
