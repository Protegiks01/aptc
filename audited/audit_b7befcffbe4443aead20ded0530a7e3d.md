# Audit Report

## Title
Missing gRPC Message Size Limits on FullnodeDataServer Allows Memory Exhaustion via Oversized TransactionsOutput Messages

## Summary
The `FullnodeDataServer` in the indexer-grpc-fullnode service does not configure `max_encoding_message_size` limits, allowing it to send arbitrarily large `TransactionsOutput` messages. Combined with clients configured to accept unlimited message sizes (`usize::MAX`), this creates a memory exhaustion vulnerability where a compromised fullnode or buggy chunking logic can crash indexer infrastructure.

## Finding Description
The vulnerability exists in the gRPC server configuration for the fullnode data streaming service. When `FullnodeDataServer` is instantiated, it does not set message size limits: [1](#0-0) 

This contrasts with other gRPC services in the codebase which properly configure these limits. For example, the RawDataServer sets both encoding and decoding limits to 256MB: [2](#0-1) [3](#0-2) 

Similarly, the GrpcManagerServer also sets these limits: [4](#0-3) [5](#0-4) 

Without explicit configuration, the generated gRPC server defaults to `usize::MAX` for `max_encoding_message_size`: [6](#0-5) 

While the application code implements chunking to limit `TransactionsOutput` messages to 15MB: [7](#0-6) [8](#0-7) 

This application-level limit is NOT enforced at the protocol layer. Clients are configured to accept unlimited message sizes: [9](#0-8) 

**Attack Scenario:**
1. A compromised fullnode server or a bug in the chunking logic bypasses the 15MB application-level chunking
2. The server sends a `TransactionsOutput` message containing hundreds or thousands of large transactions (e.g., 100MB+)
3. The gRPC layer allows encoding this message (server has `usize::MAX` limit)
4. Clients attempt to decode the message (clients also have `usize::MAX` limit)
5. Client memory is exhausted, causing crashes or severe performance degradation

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation
This vulnerability qualifies as **HIGH severity** per the Aptos bug bounty criteria:
- **API crashes**: Indexer clients and services can crash from memory exhaustion
- **Validator node slowdowns**: If validators run indexer clients, their performance degrades
- **Significant protocol violations**: Lack of defense-in-depth violates secure design principles

The impact is significant because:
1. Indexer infrastructure is critical for ecosystem tooling (wallets, explorers, analytics)
2. Memory exhaustion can cause cascading failures across dependent services
3. The vulnerability affects all clients connecting to fullnode data streams
4. No authentication is required - any client can connect to exposed fullnode endpoints

## Likelihood Explanation
The likelihood is **MEDIUM to HIGH**:

**Factors increasing likelihood:**
1. Fullnodes can be operated by untrusted parties (not validators)
2. A single bug in chunking logic eliminates all protection
3. Large transactions are legitimate on Aptos (complex Move operations, large write sets)
4. The pattern of setting message size limits is established elsewhere in the codebase but missing here

**Factors decreasing likelihood:**
1. Requires either a compromised fullnode OR a specific chunking bug
2. Application-level chunking provides some protection currently
3. No known active exploitation

However, this is a **defense-in-depth failure**. Security should not rely solely on application logic when protocol-level enforcement is available and used elsewhere in the same codebase.

## Recommendation
Set explicit `max_encoding_message_size` and `max_decoding_message_size` limits on `FullnodeDataServer` consistent with other gRPC services. The limit should be set to a reasonable value (256MB as used in other services, or lower if appropriate).

**Fixed code for `ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs`:**

Add at the top of the file:
```rust
const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20); // 256MB, consistent with other services
```

Modify the server instantiation (lines 108-111):
```rust
let svc = FullnodeDataServer::new(server)
    .send_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Gzip)
    .max_encoding_message_size(MAX_MESSAGE_SIZE)
    .max_decoding_message_size(MAX_MESSAGE_SIZE);
```

This provides protocol-level enforcement as a safety net, complementing the existing application-level chunking.

## Proof of Concept
**Rust reproduction steps:**

1. Create a malicious gRPC server that bypasses chunking:
```rust
// malicious_server.rs
use aptos_protos::internal::fullnode::v1::{TransactionsOutput, TransactionsFromNodeResponse};
use aptos_protos::transaction::v1::Transaction;

// Create an oversized TransactionsOutput
let mut huge_message = TransactionsOutput {
    transactions: vec![],
};

// Add enough transactions to exceed reasonable memory limits
for _ in 0..100_000 {
    let large_txn = Transaction {
        version: 1,
        // Fill with large data fields...
        ..Default::default()
    };
    huge_message.transactions.push(large_txn);
}

// Send this via the gRPC stream
// Normal chunking logic is bypassed
let response = TransactionsFromNodeResponse {
    response: Some(transactions_from_node_response::Response::Data(huge_message)),
    chain_id: 1,
};
// send(response) will succeed because max_encoding_message_size is usize::MAX
```

2. Connect a normal client (using the code from lib.rs):
```rust
let client = FullnodeDataClient::connect(malicious_server_url)
    .await?
    .max_decoding_message_size(usize::MAX); // Client accepts any size

let mut stream = client.get_transactions_from_node(request).await?;
while let Some(response) = stream.message().await? {
    // Client attempts to decode the huge message
    // Memory exhaustion occurs here
}
```

3. **Expected result**: Client experiences memory exhaustion and crashes or becomes unresponsive.

**Notes:**
- The vulnerability can also be triggered by legitimate bugs in `chunk_transactions()` function
- Large individual transactions (e.g., from complex smart contracts) could contribute to the problem
- Without gRPC-level limits, the system has no safety net against application-level failures

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L108-111)
```rust
                let svc = FullnodeDataServer::new(server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L31-31)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L240-241)
```rust
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L15-15)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L99-100)
```rust
        .max_encoding_message_size(MAX_MESSAGE_SIZE)
        .max_decoding_message_size(MAX_MESSAGE_SIZE);
```

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.tonic.rs (L238-245)
```rust
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L18-19)
```rust
// Limit the message size to 15MB. By default the downstream can receive up to 15MB.
pub const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024 * 15;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L186-196)
```rust
                    for chunk in chunk_transactions(chunk.to_vec(), MESSAGE_SIZE_LIMIT) {
                        let item = TransactionsFromNodeResponse {
                            response: Some(transactions_from_node_response::Response::Data(
                                TransactionsOutput {
                                    transactions: chunk,
                                },
                            )),
                            chain_id: ledger_chain_id as u32,
                        };
                        responses.push(item);
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L45-46)
```rust
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX)
```
