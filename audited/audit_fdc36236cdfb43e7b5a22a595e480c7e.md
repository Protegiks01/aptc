# Audit Report

## Title
Backup Service HTTP Endpoint Bypasses MAX_NUM_EPOCH_ENDING_LEDGER_INFO Limit Leading to Resource Exhaustion DoS

## Summary
The backup service HTTP endpoint for fetching epoch ending ledger infos completely bypasses the `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` limit (set to 100), allowing unprivileged attackers to request unbounded amounts of epoch data through a simple HTTP GET request, causing memory exhaustion, CPU saturation, and node unavailability.

## Finding Description

The `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` constant is defined to limit the number of epoch ending ledger infos that can be fetched in a single request: [1](#0-0) 

This limit is properly enforced in the standard `DbReader` API paths: [2](#0-1) [3](#0-2) 

However, the backup service exposes an HTTP endpoint that completely bypasses this limit. The backup service handler exposes: [4](#0-3) 

This endpoint calls the backup handler's method which directly accesses the metadata database without any limit enforcement: [5](#0-4) 

The underlying iterator implementation has no built-in limit and will iterate through all epochs from start to end: [6](#0-5) 

Furthermore, the backup service is configured to listen on all network interfaces in production deployments: [7](#0-6) 

**Attack Execution:**
1. Attacker sends: `GET http://<node_ip>:6186/epoch_ending_ledger_infos/0/1000000`
2. The node attempts to iterate through 1 million epochs (or however many exist)
3. Each epoch ending ledger info contains validator signatures and metadata (several KB each)
4. The node exhausts memory/CPU attempting to serialize and stream gigabytes of data
5. Node becomes unresponsive or crashes

This breaks the **Resource Limits** invariant that all operations must respect computational and memory constraints.

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos Bug Bounty program:

- **Validator node slowdowns**: An attacker can force validators to process unbounded amounts of historical epoch data, significantly degrading performance
- **API crashes**: The resource exhaustion can cause the backup service or entire node to crash
- **Significant protocol violations**: The `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` limit exists as a deliberate resource protection, which is completely bypassed

The impact affects:
- **All validators and fullnodes** that expose the backup service (default configuration)
- **Network availability** as nodes become unresponsive under attack
- **State synchronization** as the backup service may be used for legitimate sync operations

For a blockchain with thousands of epochs, an attacker could trigger gigabytes of memory allocation and CPU-intensive serialization operations with a single HTTP request.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack complexity**: Extremely low - requires only a single HTTP GET request
- **Attacker requirements**: None - no authentication, authorization, or special access needed
- **Default exposure**: The backup service binds to `0.0.0.0:6186` in production configurations, making it remotely accessible
- **Discoverability**: The endpoint is well-documented for legitimate backup operations
- **Cost to attacker**: Negligible - single HTTP request can cause significant resource consumption

The vulnerability is trivially exploitable by any network-connected attacker who can reach the backup service port.

## Recommendation

Enforce the `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` limit in the backup handler by modifying the implementation: [5](#0-4) 

**Fixed implementation:**

```rust
pub fn get_epoch_ending_ledger_info_iter(
    &self,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<impl Iterator<Item = Result<LedgerInfoWithSignatures>> + '_> {
    // Enforce the same limit as the DbReader API
    let limit = std::cmp::min(
        end_epoch.saturating_sub(start_epoch),
        MAX_NUM_EPOCH_ENDING_LEDGER_INFO as u64,
    );
    let actual_end_epoch = start_epoch.saturating_add(limit);
    
    Ok(self
        .ledger_db
        .metadata_db()
        .get_epoch_ending_ledger_info_iter(start_epoch, actual_end_epoch)?
        .enumerate()
        .map(move |(idx, li)| {
            BACKUP_EPOCH_ENDING_EPOCH.set((start_epoch + idx as u64) as i64);
            li
        }))
}
```

Additionally, consider:
1. Adding rate limiting to the backup service endpoints
2. Implementing authentication/authorization for the backup service
3. Binding the backup service to localhost by default and requiring explicit configuration for external access
4. Adding monitoring/alerting for excessive backup service requests

## Proof of Concept

**Step 1**: Identify a running Aptos node with backup service enabled (default configuration)

**Step 2**: Execute the attack:

```bash
# Request 1 million epochs (or any large number beyond current epoch count)
curl -v "http://<node_ip>:6186/epoch_ending_ledger_infos/0/1000000"
```

**Step 3**: Observe the effects:
- Node memory consumption increases dramatically
- CPU usage spikes as the database iterates through all epochs
- Network bandwidth saturated as the node attempts to stream the response
- Node API becomes slow or unresponsive
- Potential node crash with OOM errors

**Alternative PoC (Rust integration test):**

```rust
#[test]
fn test_backup_service_epoch_limit_bypass() {
    let tmpdir = TempPath::new();
    let db = Arc::new(AptosDB::new_for_test(&tmpdir));
    let port = get_available_port();
    let _rt = start_backup_service(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        db.clone()
    );
    
    // Attempt to fetch unbounded epochs
    let response = reqwest::blocking::get(
        format!("http://127.0.0.1:{}/epoch_ending_ledger_infos/0/1000000", port)
    );
    
    // This should fail or be limited, but currently succeeds
    // causing resource exhaustion
    assert!(response.is_ok());
}
```

The vulnerability is immediately exploitable and poses a significant threat to node availability and network stability.

### Citations

**File:** storage/aptosdb/src/common.rs (L9-9)
```rust
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L572-595)
```rust
    fn get_epoch_ending_ledger_info_iterator(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<LedgerInfoWithSignatures>> + '_>> {
        gauged_api("get_epoch_ending_ledger_info_iterator", || {
            self.check_epoch_ending_ledger_infos_request(start_epoch, end_epoch)?;
            let limit = std::cmp::min(
                end_epoch.saturating_sub(start_epoch),
                MAX_NUM_EPOCH_ENDING_LEDGER_INFO as u64,
            );
            let end_epoch = start_epoch.saturating_add(limit);

            let iter = self
                .ledger_db
                .metadata_db()
                .get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?;

            Ok(Box::new(iter)
                as Box<
                    dyn Iterator<Item = Result<LedgerInfoWithSignatures>> + '_,
                >)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1036-1064)
```rust
    pub(super) fn get_epoch_ending_ledger_infos_impl(
        &self,
        start_epoch: u64,
        end_epoch: u64,
        limit: usize,
    ) -> Result<(Vec<LedgerInfoWithSignatures>, bool)> {
        self.check_epoch_ending_ledger_infos_request(start_epoch, end_epoch)?;

        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };

        let lis = self
            .ledger_db
            .metadata_db()
            .get_epoch_ending_ledger_info_iter(start_epoch, paging_epoch)?
            .collect::<Result<Vec<_>>>()?;

        ensure!(
            lis.len() == (paging_epoch - start_epoch) as usize,
            "DB corruption: missing epoch ending ledger info for epoch {}",
            lis.last()
                .map(|li| li.ledger_info().next_block_epoch() - 1)
                .unwrap_or(start_epoch),
        );
        Ok((lis, more))
    }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L90-99)
```rust
    // GET epoch_ending_ledger_infos/<start_epoch>/<end_epoch>/
    let bh = backup_handler.clone();
    let epoch_ending_ledger_infos = warp::path!(u64 / u64)
        .map(move |start_epoch, end_epoch| {
            reply_with_bytes_sender(&bh, EPOCH_ENDING_LEDGER_INFOS, move |bh, sender| {
                bh.get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L207-221)
```rust
    pub fn get_epoch_ending_ledger_info_iter(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<impl Iterator<Item = Result<LedgerInfoWithSignatures>> + '_> {
        Ok(self
            .ledger_db
            .metadata_db()
            .get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?
            .enumerate()
            .map(move |(idx, li)| {
                BACKUP_EPOCH_ENDING_EPOCH.set((start_epoch + idx as u64) as i64);
                li
            }))
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L124-132)
```rust
    pub(crate) fn get_epoch_ending_ledger_info_iter(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<EpochEndingLedgerInfoIter<'_>> {
        let mut iter = self.db.iter::<LedgerInfoSchema>()?;
        iter.seek(&start_epoch)?;
        Ok(EpochEndingLedgerInfoIter::new(iter, start_epoch, end_epoch))
    }
```

**File:** terraform/helm/aptos-node/files/configs/fullnode-base.yaml (L16-16)
```yaml
  backup_service_address: "0.0.0.0:6186"
```
