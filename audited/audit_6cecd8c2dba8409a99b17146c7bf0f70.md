# Audit Report

## Title
Backup Service Lacks Validator-Specific Configuration Validation and Always-On Design Creates Misconfiguration Risk

## Summary
The backup service is unconditionally enabled on all Aptos nodes without opt-in configuration and lacks validator-specific security sanitization to prevent binding to public network interfaces. While the default configuration is safe (localhost-only), production deployment examples expose it publicly for fullnodes, creating a copy-paste misconfiguration risk that could expose validator production databases without authentication.

## Finding Description

The backup service has multiple security concerns:

**1. Always-On Design (No Opt-In):**
The backup service starts unconditionally on all nodes in `bootstrap_db()`: [1](#0-0) [2](#0-1) 

There is no configuration flag to disable the service - it always runs.

**2. Safe Default But No Validation:**
The default binding is localhost-only, which is secure: [3](#0-2) 

However, the `StorageConfig` sanitizer lacks validation to prevent public binding: [4](#0-3) 

Compare this to `InspectionServiceConfig`, which DOES prevent mainnet validators from exposing configuration: [5](#0-4) 

**3. No Authentication:**
The backup service exposes sensitive data through unauthenticated HTTP endpoints: [6](#0-5) 

**4. Production Examples Use Public Binding:**
Fullnode Helm charts explicitly configure public binding, creating copy-paste risk: [7](#0-6) [8](#0-7) 

**Documentation confirms the security model relies on localhost binding:** [9](#0-8) 

## Impact Explanation

This represents a **High severity** configuration vulnerability because:

1. **Information Disclosure**: If misconfigured to bind to `0.0.0.0`, an attacker gains unauthenticated access to the entire blockchain database, including state snapshots, all transactions, and account data.

2. **No Defense-in-Depth**: Unlike `InspectionServiceConfig`, there's no sanitizer to catch mainnet validator misconfigurations before the node starts.

3. **No Opt-Out**: Validators cannot disable the service even if they don't need backup functionality, violating the principle of least privilege.

4. **Significant Protocol Violation** (per Aptos bug bounty High severity criteria): The lack of security controls that exist for similar services represents an inconsistent security model.

## Likelihood Explanation

**Likelihood: Medium**

While the default configuration is safe, the risk is non-trivial because:

- Production Helm charts demonstrate `0.0.0.0` binding for fullnodes
- Operators copying configurations between node types could accidentally expose validators
- No runtime warning or validation prevents the misconfiguration
- The service cannot be disabled, forcing all validators to manage this attack surface

The vulnerability requires operator error, reducing likelihood, but the lack of defensive controls increases risk.

## Recommendation

Implement three security improvements:

**1. Add Validator-Specific Configuration Sanitization:**

Add to `StorageConfig::sanitize()` in `config/src/config/storage_config.rs`:

```rust
// Verify that mainnet validators do not expose backup service publicly
if let Some(chain_id) = chain_id {
    if node_type.is_validator()
        && chain_id.is_mainnet()
        && config.backup_service_address.ip().is_unspecified()
    {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Mainnet validators must not bind backup service to 0.0.0.0. Use 127.0.0.1 instead.".to_string(),
        ));
    }
}
```

**2. Add Opt-In Configuration:**

Add `enable_backup_service: bool` field to `StorageConfig` (default: `true` for backward compatibility) and conditionally start the service in `bootstrap_db()`.

**3. Add Authentication:**

Implement token-based authentication for backup service endpoints or document that it should only be used behind authenticated reverse proxies.

## Proof of Concept

**Manual Configuration Test:**

1. Create a validator config with:
```yaml
storage:
  backup_service_address: "0.0.0.0:6186"
```

2. Start the validator node

3. From external network:
```bash
curl http://VALIDATOR_IP:6186/db_state
# Returns unauthenticated database state

curl http://VALIDATOR_IP:6186/state_snapshot/1000000
# Returns state snapshot without authentication
```

**Note**: This PoC demonstrates the misconfiguration risk, not a code exploit. The vulnerability is the lack of validation to prevent this scenario.

---

**Notes:**

The default configuration IS secure - validators use localhost-only binding unless explicitly misconfigured. However, the lack of validator-specific sanitization (which exists for `InspectionServiceConfig`) represents an inconsistent security model. The always-on design and unauthenticated endpoints create unnecessary attack surface. While this requires operator error to exploit, the absence of defensive controls that prevent such errors is itself a security gap.

### Citations

**File:** aptos-node/src/storage.rs (L70-71)
```rust
            let db_backup_service =
                start_backup_service(node_config.storage.backup_service_address, db_arc.clone());
```

**File:** aptos-node/src/storage.rs (L95-96)
```rust
            let db_backup_service =
                start_backup_service(node_config.storage.backup_service_address, fast_sync_db);
```

**File:** config/src/config/storage_config.rs (L436-436)
```rust
            backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
```

**File:** config/src/config/storage_config.rs (L682-798)
```rust
impl ConfigSanitizer for StorageConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.storage;

        let ledger_prune_window = config
            .storage_pruner_config
            .ledger_pruner_config
            .prune_window;
        let state_merkle_prune_window = config
            .storage_pruner_config
            .state_merkle_pruner_config
            .prune_window;
        let epoch_snapshot_prune_window = config
            .storage_pruner_config
            .epoch_snapshot_pruner_config
            .prune_window;
        let user_pruning_window_offset = config
            .storage_pruner_config
            .ledger_pruner_config
            .user_pruning_window_offset;

        if ledger_prune_window < 50_000_000 {
            warn!("Ledger prune_window is too small, harming network data availability.");
        }
        if state_merkle_prune_window < 100_000 {
            warn!("State Merkle prune_window is too small, node might stop functioning.");
        }
        if epoch_snapshot_prune_window < 50_000_000 {
            warn!("Epoch snapshot prune_window is too small, harming network data availability.");
        }
        if user_pruning_window_offset > 1_000_000 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "user_pruning_window_offset too large, so big a buffer is unlikely necessary. Set something < 1 million.".to_string(),
            ));
        }
        if user_pruning_window_offset > ledger_prune_window {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "user_pruning_window_offset is larger than the ledger prune window, the API will refuse to return any data.".to_string(),
            ));
        }

        if let Some(db_path_overrides) = config.db_path_overrides.as_ref() {
            if !config.rocksdb_configs.enable_storage_sharding {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "db_path_overrides is allowed only if sharding is enabled.".to_string(),
                ));
            }

            if let Some(ledger_db_path) = db_path_overrides.ledger_db_path.as_ref() {
                if !ledger_db_path.is_absolute() {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        format!(
                            "Path {ledger_db_path:?} in db_path_overrides is not an absolute path."
                        ),
                    ));
                }
            }

            if let Some(state_kv_db_path) = db_path_overrides.state_kv_db_path.as_ref() {
                if let Some(metadata_path) = state_kv_db_path.metadata_path.as_ref() {
                    if !metadata_path.is_absolute() {
                        return Err(Error::ConfigSanitizerFailed(
                            sanitizer_name,
                            format!("Path {metadata_path:?} in db_path_overrides is not an absolute path."),
                        ));
                    }
                }

                if let Err(e) = state_kv_db_path.get_shard_paths() {
                    return Err(Error::ConfigSanitizerFailed(sanitizer_name, e.to_string()));
                }
            }

            if let Some(state_merkle_db_path) = db_path_overrides.state_merkle_db_path.as_ref() {
                if let Some(metadata_path) = state_merkle_db_path.metadata_path.as_ref() {
                    if !metadata_path.is_absolute() {
                        return Err(Error::ConfigSanitizerFailed(
                            sanitizer_name,
                            format!("Path {metadata_path:?} in db_path_overrides is not an absolute path."),
                        ));
                    }
                }

                if let Err(e) = state_merkle_db_path.get_shard_paths() {
                    return Err(Error::ConfigSanitizerFailed(sanitizer_name, e.to_string()));
                }
            }

            if let Some(hot_state_merkle_db_path) =
                db_path_overrides.hot_state_merkle_db_path.as_ref()
            {
                if let Some(metadata_path) = hot_state_merkle_db_path.metadata_path.as_ref() {
                    if !metadata_path.is_absolute() {
                        return Err(Error::ConfigSanitizerFailed(
                            sanitizer_name,
                            format!("Path {metadata_path:?} in db_path_overrides is not an absolute path."),
                        ));
                    }
                }

                if let Err(e) = hot_state_merkle_db_path.get_shard_paths() {
                    return Err(Error::ConfigSanitizerFailed(sanitizer_name, e.to_string()));
                }
            }
        }

        Ok(())
    }
```

**File:** config/src/config/inspection_service_config.rs (L54-64)
```rust
        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L27-147)
```rust
pub(crate) fn get_routes(backup_handler: BackupHandler) -> BoxedFilter<(impl Reply,)> {
    // GET db_state
    let bh = backup_handler.clone();
    let db_state = warp::path::end()
        .map(move || reply_with_bcs_bytes(DB_STATE, &bh.get_db_state()?))
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_range_proof/<version>/<end_key>
    let bh = backup_handler.clone();
    let state_range_proof = warp::path!(Version / HashValue)
        .map(move |version, end_key| {
            reply_with_bcs_bytes(
                STATE_RANGE_PROOF,
                &bh.get_account_state_range_proof(end_key, version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_snapshot/<version>
    let bh = backup_handler.clone();
    let state_snapshot = warp::path!(Version)
        .map(move |version| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT, move |bh, sender| {
                bh.get_state_item_iter(version, 0, usize::MAX)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

    // GET state_item_count/<version>
    let bh = backup_handler.clone();
    let state_item_count = warp::path!(Version)
        .map(move |version| {
            reply_with_bcs_bytes(
                STATE_ITEM_COUNT,
                &(bh.get_state_item_count(version)? as u64),
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_snapshot_chunk/<version>/<start_idx>/<limit>
    let bh = backup_handler.clone();
    let state_snapshot_chunk = warp::path!(Version / usize / usize)
        .map(move |version, start_idx, limit| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT_CHUNK, move |bh, sender| {
                bh.get_state_item_iter(version, start_idx, limit)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

    // GET state_root_proof/<version>
    let bh = backup_handler.clone();
    let state_root_proof = warp::path!(Version)
        .map(move |version| {
            reply_with_bcs_bytes(STATE_ROOT_PROOF, &bh.get_state_root_proof(version)?)
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

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

    // GET transaction_range_proof/<first_version>/<last_version>
    let bh = backup_handler;
    let transaction_range_proof = warp::path!(Version / Version)
        .map(move |first_version, last_version| {
            reply_with_bcs_bytes(
                TRANSACTION_RANGE_PROOF,
                &bh.get_transaction_range_proof(first_version, last_version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // Route by endpoint name.
    let routes = warp::any()
        .and(warp::path(DB_STATE).and(db_state))
        .or(warp::path(STATE_RANGE_PROOF).and(state_range_proof))
        .or(warp::path(STATE_SNAPSHOT).and(state_snapshot))
        .or(warp::path(STATE_ITEM_COUNT).and(state_item_count))
        .or(warp::path(STATE_SNAPSHOT_CHUNK).and(state_snapshot_chunk))
        .or(warp::path(STATE_ROOT_PROOF).and(state_root_proof))
        .or(warp::path(EPOCH_ENDING_LEDGER_INFOS).and(epoch_ending_ledger_infos))
        .or(warp::path(TRANSACTIONS).and(transactions))
        .or(warp::path(TRANSACTION_RANGE_PROOF).and(transaction_range_proof));

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

**File:** terraform/helm/fullnode/files/fullnode-base.yaml (L68-68)
```yaml
  backup_service_address: "0.0.0.0:6186"
```

**File:** terraform/helm/aptos-node/files/configs/fullnode-base.yaml (L16-16)
```yaml
  backup_service_address: "0.0.0.0:6186"
```

**File:** storage/README.md (L64-66)
```markdown
  # Address the backup service listens on. By default the port is open to only
  # the localhost, so the backup cli tool can only access data in the same host.
  backup_service_address: "127.0.0.1:6186"
```
