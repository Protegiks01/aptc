# Audit Report

## Title
Indexer-gRPC Data Service Infinite Loop at Genesis (Version 0) Prevents Service Initialization

## Summary
The indexer-grpc data service v2 connection manager incorrectly treats version 0 as an uninitialized state, when it is actually a valid blockchain version (the genesis block). This causes the service to hang indefinitely in an initialization loop when connected to a blockchain at genesis, resulting in a denial of service.

## Finding Description

The vulnerability exists in the initialization logic of `ConnectionManager::new()` which waits for `known_latest_version` to become non-zero before completing initialization: [1](#0-0) 

This loop assumes that `known_latest_version == 0` indicates an uninitialized state. However, version 0 is the valid genesis block version in Aptos: [2](#0-1) 

The genesis block is created with `GENESIS_VERSION` explicitly set to 0: [3](#0-2) 

When genesis is calculated, the version is set to 0: [4](#0-3) 

After genesis is committed to the database, `get_synced_version()` returns `Some(0)`: [5](#0-4) 

The fullnode reports this version in its ping responses: [6](#0-5) [7](#0-6) 

The metadata manager propagates this version in heartbeat responses: [8](#0-7) [9](#0-8) 

When the connection manager receives version 0 from the heartbeat response, it updates its local state: [10](#0-9) 

However, the `update_known_latest_version()` function uses `fetch_max()`, which keeps the value at 0: [11](#0-10) 

Since `fetch_max(0, 0) = 0`, the condition `known_latest_version == 0` in the initialization loop remains true forever, preventing the service from ever completing initialization.

## Impact Explanation

This is a **Medium severity** issue per the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: The indexer-grpc data service cannot initialize and requires manual code changes or workarounds
- **Service unavailability**: No transaction data can be served to indexers until the blockchain progresses past version 0
- **Limited scope**: Only affects new blockchain deployments at genesis, not established networks

This does not reach High or Critical severity because:
- It does not affect consensus, validator operations, or funds
- It only impacts the indexer-grpc infrastructure layer, not core blockchain functionality
- Established networks (mainnet, existing testnets) are past genesis and unaffected

## Likelihood Explanation

**High likelihood** for affected scenarios:
- **New testnet deployments**: Every new testnet starts at genesis (version 0)
- **Local development**: Developers running local testnets with `indexer_grpc_local.py` will encounter this
- **Forge testing**: Automated test environments that spin up fresh chains will fail
- **Devnet resets**: Any devnet reset to genesis will trigger this bug

**Not applicable** to:
- Mainnet and existing testnets that are already past version 0
- Historical data services indexing from later versions

The bug triggers deterministically—no attacker interaction required. Any deployment attempting to start indexer-grpc services on a genesis blockchain will immediately encounter this infinite loop.

## Recommendation

Replace the u64-based version tracking with an `Option<u64>` to distinguish between "uninitialized" (None) and "at genesis" (Some(0)):

```rust
// In ConnectionManager struct
known_latest_version: Mutex<Option<u64>>,

// Initialization in new()
known_latest_version: Mutex::new(None),

// Initialization loop
while res.known_latest_version.lock().unwrap().is_none() {
    for entry in res.grpc_manager_connections.iter() {
        let address = entry.key();
        if let Err(e) = res.heartbeat(address).await {
            warn!("Error during heartbeat: {e}.");
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
}

// Update function
pub(crate) fn update_known_latest_version(&self, version: u64) {
    let mut latest = self.known_latest_version.lock().unwrap();
    *latest = Some(latest.map_or(version, |v| v.max(version)));
}

// Getter function
pub(crate) fn known_latest_version(&self) -> u64 {
    self.known_latest_version.lock().unwrap().unwrap_or(0)
}
```

Alternatively, use a separate initialization flag to track whether any heartbeat response has been received.

## Proof of Concept

**Reproduction Steps:**

1. Start a fresh local testnet with genesis at version 0:
```bash
cd testsuite
python3 indexer_grpc_local.py
```

2. Deploy the indexer-grpc-data-service-v2 configured to connect to the local testnet's grpc-manager

3. Observe the service logs - it will show repeated heartbeat attempts but never complete initialization

4. Check the service's `known_latest_version` metric - it will remain at 0

5. Verify the service never begins serving requests by attempting to connect a client

**Expected behavior:** Service should initialize successfully even at genesis

**Actual behavior:** Service hangs indefinitely in the initialization loop at line 132-140 of `connection_manager.rs`

**Verification:**
```rust
// Add debug logging in the initialization loop to confirm:
while res.known_latest_version.load(Ordering::SeqCst) == 0 {
    warn!("Still waiting for known_latest_version != 0, current value: {}", 
          res.known_latest_version.load(Ordering::SeqCst));
    // ... rest of loop
}
```

The logs will show continuous warnings with "current value: 0" even after successful heartbeats that return version 0 from genesis.

## Notes

This vulnerability demonstrates a classic off-by-one error where 0 is used as both a sentinel value (uninitialized) and a valid data value (genesis version). The Aptos codebase explicitly defines `GENESIS_VERSION = 0`, making this a valid blockchain state that must be handled correctly throughout the system.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L132-140)
```rust
        while res.known_latest_version.load(Ordering::SeqCst) == 0 {
            for entry in res.grpc_manager_connections.iter() {
                let address = entry.key();
                if let Err(e) = res.heartbeat(address).await {
                    warn!("Error during heartbeat: {e}.");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L185-188)
```rust
    pub(crate) fn update_known_latest_version(&self, version: u64) {
        self.known_latest_version
            .fetch_max(version, Ordering::SeqCst);
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L293-295)
```rust
        if let Some(known_latest_version) = response.known_latest_version {
            info!("Received known_latest_version ({known_latest_version}) from GrpcManager {address}.");
            self.update_known_latest_version(known_latest_version);
```

**File:** types/src/block_info.rs (L21-21)
```rust
pub const GENESIS_VERSION: Version = 0;
```

**File:** types/src/block_info.rs (L126-126)
```rust
            version: GENESIS_VERSION,
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L123-123)
```rust
    let genesis_version = ledger_summary.version().map_or(0, |v| v + 1);
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L76-78)
```rust
    pub(crate) fn get_synced_version(&self) -> Result<Option<Version>> {
        get_progress(&self.db, &DbMetadataKey::OverallCommitProgress)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L212-217)
```rust
        let known_latest_version = self
            .service_context
            .context
            .db
            .get_synced_version()
            .map_err(|e| Status::internal(format!("{e}")))?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L235-239)
```rust
        let info = FullnodeInfo {
            chain_id: self.service_context.context.chain_id().id() as u64,
            timestamp: Some(timestamp),
            known_latest_version,
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L42-44)
```rust
        Ok(Response::new(HeartbeatResponse {
            known_latest_version: Some(self.metadata_manager.get_known_latest_version()),
        }))
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L401-403)
```rust
    pub(crate) fn get_known_latest_version(&self) -> u64 {
        self.known_latest_version.load(Ordering::SeqCst)
    }
```
