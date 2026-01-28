# Audit Report

## Title
Async Cancellation Causes Connection Counter Leak in wait_by_hash Endpoint Leading to Denial of Service

## Summary
The `wait_transaction_by_hash()` function contains an async cancellation bug where the connection counter permanently leaks when clients disconnect before receiving responses, eventually causing all new requests to be rejected once the counter reaches the configured maximum (default: 100).

## Finding Description
The vulnerability exists in the connection counting logic of the `/transactions/wait_by_hash/:txn_hash` endpoint.

The function increments the connection counter at line 243 using `fetch_add(1)` [1](#0-0) . The safe path exists when the counter exceeds the limit, where it immediately decrements and returns [2](#0-1) .

However, the critical issue occurs in the normal execution path. The function calls `wait_transaction_by_hash_inner().await` [3](#0-2) , and the cleanup code that decrements the counter is located after this await point [4](#0-3) .

In Rust's async runtime, when a Future is dropped due to client disconnect or cancellation, code after the last `.await` point that hasn't executed yet will never run. This means the cleanup code at lines 273-276 never executes if the task is cancelled during the await at line 271.

The counter is defined as an `Arc<AtomicUsize>` shared across all requests [5](#0-4)  and initialized to zero [6](#0-5) .

The default maximum active connections is 100 [7](#0-6) .

**Attack Scenario:**
1. Attacker sends HTTP GET requests to `/transactions/wait_by_hash/:hash` with non-existent transaction hashes
2. Each request enters the wait loop in `wait_transaction_by_hash_inner()` [8](#0-7) 
3. Attacker immediately disconnects, causing the Future to be dropped
4. Each cancellation leaks +1 to the counter permanently
5. After 100 cancelled requests, the limit check rejects all subsequent requests [9](#0-8) 
6. The wait_by_hash endpoint becomes completely non-functional until node restart

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty criteria:

**State Inconsistencies Requiring Intervention**: The leaked counter represents incorrect state that can only be fixed by restarting the node, which requires manual intervention by node operators.

**Limited Availability Impact**: This causes denial of service affecting only the `/transactions/wait_by_hash` endpoint. Other API endpoints, including the regular `/transactions/by_hash` endpoint, continue functioning normally. Core blockchain operations (consensus, transaction processing, state management) are completely unaffected.

**No Funds or Consensus Impact**: This vulnerability does not affect funds custody, consensus safety, validator operations, or blockchain state integrity.

**Recoverable Without Data Loss**: Node restart completely clears the leaked counters with no permanent damage to blockchain state or data.

The impact does not reach High severity because it doesn't cause validator node slowdowns (only affects API layer), doesn't crash the entire API (only one endpoint), and doesn't violate consensus invariants or protocol rules.

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of being exploited:

**Low Attack Complexity**: Any HTTP client can trigger this by making requests and disconnecting. No authentication, special privileges, or complex setup required.

**Low Resource Requirements**: Only 100 cancelled requests needed to completely disable the endpoint with default configuration.

**Obvious Attack Vector**: The wait_by_hash endpoint is publicly documented and easily discoverable.

**No Detection Difficulty**: Simple HTTP clients that disconnect are sufficient to exploit this vulnerability.

**Persistent Impact**: Once exploited, the DoS persists until manual node restart. A single successful attack iteration lasts indefinitely.

## Recommendation
Implement a drop guard pattern to ensure the counter is decremented even when the Future is cancelled. The cleanup code should be moved into a guard struct that implements `Drop`, or use Rust's scope guards to guarantee cleanup occurs regardless of how the function exits.

Example fix approach:
- Wrap the counter increment/decrement in a RAII guard struct
- The guard's `Drop` implementation should decrement the counter
- Reference existing patterns in the codebase like `DropGuard` implementations found in the reliable-broadcast crate [10](#0-9) 

## Proof of Concept
A proof of concept would involve:
1. Starting an Aptos node with the API enabled
2. Writing a script that sends 100+ concurrent HTTP GET requests to `/transactions/wait_by_hash/[non-existent-hash]`
3. Immediately closing the TCP connections before receiving responses
4. Verifying that subsequent requests to the same endpoint receive immediate rejections
5. Confirming the counter value is stuck at or above the configured maximum

The vulnerability can be triggered using standard HTTP clients (curl, Python requests, etc.) with connection timeout or explicit connection termination.

## Notes
This is an application-level resource leak bug in the API layer, not a network infrastructure DoS attack. The vulnerability is caused by improper handling of async cancellation in Rust, which is a well-documented pattern requiring careful cleanup code placement. The codebase already contains examples of proper drop guard patterns that could be applied to fix this issue.

### Citations

**File:** api/src/transactions.rs (L240-252)
```rust
        if self
            .context
            .wait_for_hash_active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            >= self
                .context
                .node_config
                .api
                .wait_by_hash_max_active_connections
        {
            self.context
                .wait_for_hash_active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
```

**File:** api/src/transactions.rs (L264-271)
```rust
        let result = self
            .wait_transaction_by_hash_inner(
                &accept_type,
                txn_hash.0,
                self.context.node_config.api.wait_by_hash_timeout_ms,
                self.context.node_config.api.wait_by_hash_poll_interval_ms,
            )
            .await;
```

**File:** api/src/transactions.rs (L273-276)
```rust
        WAIT_TRANSACTION_GAUGE.dec();
        self.context
            .wait_for_hash_active_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
```

**File:** api/src/transactions.rs (L893-940)
```rust
    async fn wait_transaction_by_hash_inner(
        &self,
        accept_type: &AcceptType,
        hash: HashValue,
        wait_by_hash_timeout_ms: u64,
        wait_by_hash_poll_interval_ms: u64,
    ) -> BasicResultWith404<Transaction> {
        let start_time = std::time::Instant::now();
        loop {
            let context = self.context.clone();
            let accept_type = accept_type.clone();

            let (internal_ledger_info_opt, storage_ledger_info) =
                api_spawn_blocking(move || context.get_latest_internal_and_storage_ledger_info())
                    .await?;
            let storage_version = storage_ledger_info.ledger_version.into();
            let internal_ledger_version = internal_ledger_info_opt
                .as_ref()
                .map(|info| info.ledger_version.into());
            let latest_ledger_info = internal_ledger_info_opt.unwrap_or(storage_ledger_info);
            let txn_data = self
                .get_by_hash(hash.into(), storage_version, internal_ledger_version)
                .await
                .context(format!("Failed to get transaction by hash {}", hash))
                .map_err(|err| {
                    BasicErrorWith404::internal_with_code(
                        err,
                        AptosErrorCode::InternalError,
                        &latest_ledger_info,
                    )
                })?
                .context(format!("Failed to find transaction with hash: {}", hash))
                .map_err(|_| transaction_not_found_by_hash(hash, &latest_ledger_info))?;

            if matches!(txn_data, TransactionData::Pending(_))
                && (start_time.elapsed().as_millis() as u64) < wait_by_hash_timeout_ms
            {
                tokio::time::sleep(Duration::from_millis(wait_by_hash_poll_interval_ms)).await;
                continue;
            }

            let api = self.clone();
            return api_spawn_blocking(move || {
                api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info)
            })
            .await;
        }
    }
```

**File:** api/src/context.rs (L84-84)
```rust
    pub wait_for_hash_active_connections: Arc<AtomicUsize>,
```

**File:** api/src/context.rs (L136-136)
```rust
            wait_for_hash_active_connections: Arc::new(AtomicUsize::new(0)),
```

**File:** config/src/config/api_config.rs (L144-144)
```rust
            wait_by_hash_max_active_connections: 100,
```

**File:** crates/reliable-broadcast/src/lib.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_bounded_executor::BoundedExecutor;
use aptos_consensus_types::common::Author;
use aptos_logger::{debug, sample, sample::SampleRate, warn};
use aptos_time_service::{TimeService, TimeServiceTrait};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{
    stream::{AbortHandle, FuturesUnordered},
    Future, FutureExt, StreamExt,
};
use std::{collections::HashMap, fmt::Debug, sync::Arc, time::Duration};

pub trait RBMessage: Send + Sync + Clone {}

#[async_trait]
pub trait RBNetworkSender<Req: RBMessage, Res: RBMessage = Req>: Send + Sync {
    async fn send_rb_rpc_raw(
        &self,
        receiver: Author,
        message: Bytes,
        timeout: Duration,
    ) -> anyhow::Result<Res>;

    async fn send_rb_rpc(
        &self,
        receiver: Author,
        message: Req,
        timeout: Duration,
    ) -> anyhow::Result<Res>;

    /// Serializes the given message into bytes using each peers' preferred protocol.
    fn to_bytes_by_protocol(
        &self,
        peers: Vec<Author>,
        message: Req,
    ) -> anyhow::Result<HashMap<Author, Bytes>>;

    fn sort_peers_by_latency(&self, peers: &mut [Author]);
}

pub trait BroadcastStatus<Req: RBMessage, Res: RBMessage = Req>: Send + Sync + Clone {
    type Aggregated: Send;
    type Message: Into<Req> + TryFrom<Req> + Clone;
    type Response: Into<Res> + TryFrom<Res> + Clone;

    fn add(
        &self,
```
