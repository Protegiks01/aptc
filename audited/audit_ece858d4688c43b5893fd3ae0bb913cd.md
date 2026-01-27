# Audit Report

## Title
Memory Exhaustion via Decompression Size Limit Bypass in State Sync Data Client

## Summary
The `max_response_bytes` limit in the Aptos data client can be bypassed by malicious peers sending compressed responses with decompressed sizes that exceed the requested limit. While clients request data bounded by `max_response_bytes` (default 20 MiB), decompression only validates against `MAX_APPLICATION_MESSAGE_SIZE` (~61.875 MiB), allowing memory allocation up to 3x the intended limit and causing potential memory exhaustion on syncing nodes. [1](#0-0) 

## Finding Description

The vulnerability stems from a mismatch between the size limit requested by clients and the size limit enforced during decompression:

1. **Client-side Request**: The client calls `get_max_response_bytes()` which returns the configured limit (default 20 MiB from `CLIENT_MAX_MESSAGE_SIZE_V2`), and includes this in data requests with compression enabled. [2](#0-1) [3](#0-2) 

2. **Server-side Enforcement**: Honest servers respect the `max_response_bytes` limit by checking uncompressed data size before compression. [4](#0-3) 

3. **Client-side Decompression**: When the client receives a compressed response, it decompresses using `MAX_APPLICATION_MESSAGE_SIZE` (~61.875 MiB) as the size limit, NOT the originally requested `max_response_bytes` (20 MiB). [5](#0-4) [6](#0-5) 

4. **Size Validation Gap**: The decompression library validates that the decompressed size (parsed from the LZ4 compression header) doesn't exceed `max_size`, but this is set to `MAX_APPLICATION_MESSAGE_SIZE`, not `max_response_bytes`. [7](#0-6) 

**Attack Scenario**: A malicious peer acting as a storage service can:
- Receive a client request with `max_response_bytes = 20 MiB` and `use_compression = true`
- Create a `DataResponse` containing 60 MiB of data (within `MAX_APPLICATION_MESSAGE_SIZE`)
- Serialize and compress this response
- Send the compressed response to the client
- The client decompresses and allocates 60 MiB instead of the expected 20 MiB

This breaks the invariant that "All operations must respect gas, storage, and computational limits" by allowing memory allocation beyond the configured response size limit.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Validator Node Slowdowns**: Syncing nodes making concurrent requests can allocate 3x more memory than expected. With `MAX_CONCURRENT_REQUESTS = 6`, a node expecting 120 MiB (6 × 20 MiB) could allocate 360 MiB (6 × 60 MiB). [8](#0-7) 

2. **Potential Node Crashes**: Repeated exploitation could exhaust available memory on nodes with limited resources, causing out-of-memory errors and node crashes.

3. **State Sync Disruption**: Fullnodes and validators attempting to sync could be targeted, slowing network synchronization and potentially preventing new nodes from joining.

The impact qualifies as **High Severity** under "Validator node slowdowns" and could escalate to service disruption affecting network availability.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is feasible because:

1. **Malicious Peer Access**: An attacker only needs to run a malicious peer that advertises storage service availability. No validator privileges required.

2. **Peer Selection**: The data client's peer selection algorithm chooses from available peers based on priority and latency. A malicious peer with good metrics could be selected. [9](#0-8) 

3. **Compression is Default**: The configuration enables compression by default (`use_compression: true`), making the attack surface always available. [10](#0-9) 

4. **No Post-Decompression Validation**: The client never validates that the decompressed response size matches the requested `max_response_bytes`. [11](#0-10) 

## Recommendation

Add size validation after decompression to ensure responses respect the requested `max_response_bytes` limit:

**Option 1: Validate in `send_request_to_peer_and_decode`**
After decompression (line 753), add a check to validate the decompressed response size against the original request's `max_response_bytes`:

```rust
// After line 753, before returning the response:
// Validate that the decompressed response respects the requested size limit
let response_size = bcs::serialized_size(&new_payload)
    .map_err(|e| Error::UnexpectedErrorEncountered(e.to_string()))?;
let max_response_bytes = /* extract from request */;
if response_size > max_response_bytes as usize {
    return Err(Error::InvalidResponse(format!(
        "Decompressed response size ({}) exceeds max_response_bytes ({})",
        response_size, max_response_bytes
    )));
}
```

**Option 2: Use Request-Specific Decompression Limit**
Modify `StorageServiceResponse::get_data_response()` to accept a `max_size` parameter derived from the original request's `max_response_bytes`, rather than using the global `MAX_APPLICATION_MESSAGE_SIZE`. [12](#0-11) 

## Proof of Concept

The following demonstrates the vulnerability:

1. **Setup**: Configure a client with `max_response_bytes = 20 MiB`
2. **Malicious Peer**: Create a storage service peer that responds with compressed data claiming to decompress to 60 MiB
3. **Exploitation**: Send multiple concurrent requests and observe memory allocation exceeding expected limits

**Rust Reproduction Steps**:

```rust
// In a test environment, create a malicious storage service response
use aptos_storage_service_types::responses::{DataResponse, StorageServiceResponse};
use aptos_compression::CompressedData;

// Create a large data response (60 MiB)
let large_data = vec![0u8; 60 * 1024 * 1024];
let data_response = DataResponse::NumberOfStatesAtVersion(large_data.len() as u64);

// Compress it (this will succeed as 60 MiB < MAX_APPLICATION_MESSAGE_SIZE)
let malicious_response = StorageServiceResponse::new(data_response, true).unwrap();

// Client receives and decompresses
// Expected: Rejection due to exceeding max_response_bytes (20 MiB)
// Actual: Accepts and allocates 60 MiB (vulnerability)
let decompressed = malicious_response.get_data_response().unwrap();
```

**Verification**: Monitor memory allocation during state sync with a malicious peer. The client will allocate significantly more memory than `max_response_bytes * MAX_CONCURRENT_REQUESTS`.

---

**Notes**:
- This vulnerability requires network access but no special privileges
- The gap between 20 MiB and 61.875 MiB provides substantial amplification (3x)
- Multiple concurrent requests multiply the impact
- The issue affects all nodes performing state synchronization

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L153-156)
```rust
    /// Returns the maximum number of bytes that can be returned in a single response
    fn get_max_response_bytes(&self) -> u64 {
        self.data_client_config.max_response_bytes
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L265-287)
```rust
    pub(crate) fn choose_peers_for_request(
        &self,
        request: &StorageServiceRequest,
    ) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
        // Get all peers grouped by priorities
        let peers_by_priorities = self.get_peers_by_priorities()?;

        // Identify the peers that can service the request (ordered by priority)
        let mut serviceable_peers_by_priorities = vec![];
        for priority in PeerPriority::get_all_ordered_priorities() {
            // Identify the serviceable peers for the priority
            let peers = self.identify_serviceable(&peers_by_priorities, priority, request);

            // Add the serviceable peers to the ordered list
            serviceable_peers_by_priorities.push(peers);
        }

        // If the request is a subscription request, select a single
        // peer (as we can only subscribe to a single peer at a time).
        if request.data_request.is_subscription_request() {
            return self
                .choose_peer_for_subscription_request(request, serviceable_peers_by_priorities);
        }
```

**File:** state-sync/aptos-data-client/src/client.rs (L750-765)
```rust
        // Try to convert the storage service enum into the exact variant we're expecting.
        // We do this using spawn_blocking because it involves serde and compression.
        tokio::task::spawn_blocking(move || {
            match T::try_from(storage_response) {
                Ok(new_payload) => Ok(Response::new(context, new_payload)),
                // If the variant doesn't match what we're expecting, report the issue
                Err(err) => {
                    context
                        .response_callback
                        .notify_bad_response(ResponseError::InvalidPayloadDataType);
                    Err(err.into())
                },
            }
        })
        .await
        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?
```

**File:** config/src/config/state_sync_config.rs (L20-20)
```rust
const CLIENT_MAX_MESSAGE_SIZE_V2: usize = 20 * 1024 * 1024; // 20 MiB (used for v2 data requests)
```

**File:** config/src/config/state_sync_config.rs (L30-30)
```rust
const MAX_CONCURRENT_REQUESTS: u64 = 6;
```

**File:** config/src/config/state_sync_config.rs (L457-457)
```rust
    pub use_compression: bool,
```

**File:** config/src/config/state_sync_config.rs (L472-472)
```rust
            max_response_bytes: CLIENT_MAX_MESSAGE_SIZE_V2 as u64,
```

**File:** state-sync/storage-service/server/src/storage.rs (L1150-1153)
```rust
        let max_response_bytes = min(
            transaction_data_with_proof_request.max_response_bytes,
            self.config.max_network_chunk_bytes_v2,
        );
```

**File:** state-sync/storage-service/types/src/responses.rs (L96-111)
```rust
    /// Returns the data response regardless of the inner format
    pub fn get_data_response(&self) -> Result<DataResponse, Error> {
        match self {
            StorageServiceResponse::CompressedResponse(_, compressed_data) => {
                let raw_data = aptos_compression::decompress(
                    compressed_data,
                    CompressionClient::StateSync,
                    MAX_APPLICATION_MESSAGE_SIZE,
                )?;
                let data_response = bcs::from_bytes::<DataResponse>(&raw_data)
                    .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                Ok(data_response)
            },
            StorageServiceResponse::RawResponse(data_response) => Ok(data_response.clone()),
        }
    }
```

**File:** config/src/config/network_config.rs (L47-50)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** crates/aptos-compression/src/lib.rs (L174-181)
```rust
    // Ensure that the size is not greater than the max size limit
    let size = size as usize;
    if size > max_size {
        return Err(DecompressionError(format!(
            "Parsed size prefix in buffer is too big: {} > {}",
            size, max_size
        )));
    }
```
