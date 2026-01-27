# Audit Report

## Title
Authentication Token Leakage Through Error Logging in Backup Service Client

## Summary
The backup service client logs full URLs containing authentication credentials when HTTP errors occur, exposing sensitive tokens to centralized log aggregation systems. Attackers with access to compromised logging infrastructure can harvest these credentials and gain unauthorized access to the backup service, potentially exposing complete blockchain state history.

## Finding Description

The vulnerability exists in the error handling mechanism of the backup service client. When HTTP requests fail, the client logs the complete URL including any embedded authentication credentials. [1](#0-0) 

The `err_notes()` function is called with the full URL as a parameter on lines 66 and 68. This function unconditionally logs the URL when an error occurs: [2](#0-1) 

**Attack Scenario:**

1. **Credential-in-URL Configuration**: Operators deploy the backup service behind an API gateway or reverse proxy requiring authentication. Common patterns include:
   - Query parameter tokens: `http://backup-gateway.example.com:6186?token=Bearer_xyz123`
   - HTTP Basic Auth: `http://admin:password@backup-gateway.example.com:6186`
   - API key parameters: `http://backup.example.com:6186?api_key=sk-abc123def456`

2. **Error Triggering**: When any HTTP error occurs (network failure, 401/403/500 responses, timeouts), the `err_notes()` call logs the complete URL with embedded credentials via the `aptos-logger` error macro.

3. **Log Aggregation**: Production deployments typically forward logs to centralized systems (Splunk, ELK, CloudWatch, Datadog) for monitoring and debugging.

4. **Credential Harvesting**: An attacker who compromises the log aggregation infrastructure (or has insider access) can extract authentication tokens from log entries:
   ```
   error = "HTTP request failed", notes = "http://backup-gateway.example.com/db_state?token=Bearer_xyz123"
   ```

5. **Unauthorized Access**: Using the harvested credentials, attackers directly access the backup service to:
   - Download complete blockchain state history
   - Access all transactions and Merkle proofs
   - Exfiltrate sensitive validator data
   - Study infrastructure for further attacks

The backup service exposes critical endpoints without additional authorization checks: [3](#0-2) 

All endpoints serve data directly without authentication middleware, relying entirely on network-level access control.

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability enables unauthorized access to the backup service, which exposes:

1. **Complete Blockchain State History**: All account states, balances, and smart contract data across all versions
2. **Transaction History**: Full transaction logs enabling forensic analysis of validator operations
3. **State Merkle Proofs**: Cryptographic proofs that could aid in understanding validator infrastructure
4. **Potential Infrastructure Intelligence**: Access patterns and data could reveal validator deployment architecture

While this doesn't directly cause consensus violations or fund theft, it represents a significant **protocol violation** and **data exfiltration risk**. The backup service is designed for disaster recovery and explicitly documented to contain the "entire history of transactions": [4](#0-3) 

Unauthorized access to this data constitutes a major security breach. Additionally, if the backup service has write capabilities or the attacker can manipulate backup restoration processes, it could lead to state inconsistencies requiring intervention (Medium severity) or worse.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Several factors make this vulnerability realistic:

1. **Common Deployment Patterns**: Production systems frequently:
   - Expose services through API gateways with token authentication
   - Use query parameters for authentication (AWS Signature, GCS Signed URLs pattern)
   - Centralize logging for compliance and monitoring

2. **Log Aggregation as Attack Target**: Centralized logging systems are:
   - High-value targets containing credentials and sensitive data
   - Often less secured than production infrastructure
   - Accessible to broader operational teams (insider threat)
   - Subject to third-party service compromises

3. **No Built-in Authentication**: The backup service lacks native authentication: [5](#0-4) 

This encourages operators to add external authentication layers that may use URL-based credentials.

4. **Default localhost-only binding** mitigates risk but doesn't eliminate it, as operators must expose the service for remote backup operations.

The vulnerability requires specific deployment configuration, but these configurations are common in production environments.

## Recommendation

Implement URL sanitization before logging to remove sensitive credentials:

```rust
// In storage/backup/backup-cli/src/utils/backup_service_client.rs

use url::Url;

fn sanitize_url_for_logging(url_str: &str) -> String {
    match Url::parse(url_str) {
        Ok(mut url) => {
            // Remove userinfo (HTTP basic auth credentials)
            if url.username() != "" || url.password().is_some() {
                let _ = url.set_username("");
                let _ = url.set_password(None);
            }
            
            // Remove sensitive query parameters
            if let Some(query) = url.query() {
                let filtered_params: Vec<String> = query
                    .split('&')
                    .filter(|param| {
                        let key = param.split('=').next().unwrap_or("");
                        !["token", "api_key", "apikey", "auth", "signature", 
                          "access_token", "bearer", "key", "secret"].iter()
                            .any(|sensitive| key.to_lowercase().contains(sensitive))
                    })
                    .map(String::from)
                    .collect();
                
                if filtered_params.is_empty() {
                    url.set_query(None);
                } else {
                    url.set_query(Some(&filtered_params.join("&")));
                }
            }
            
            url.to_string()
        }
        Err(_) => url_str.to_string(), // Fallback to original if parsing fails
    }
}

// Update the get() method:
async fn get(&self, endpoint: &'static str, params: &str) -> Result<impl AsyncRead + use<>> {
    let _timer = BACKUP_TIMER.timer_with(&[&format!("backup_service_client_get_{endpoint}")]);
    
    let url = if params.is_empty() {
        format!("{}/{}", self.address, endpoint)
    } else {
        format!("{}/{}/{}", self.address, endpoint, params)
    };
    
    let sanitized_url = sanitize_url_for_logging(&url);
    let timeout = Duration::from_secs(Self::TIMEOUT_SECS);
    
    let reader = tokio::time::timeout(timeout, self.client.get(&url).send())
        .await?
        .err_notes(&sanitized_url)?  // Log sanitized URL
        .error_for_status()
        .err_notes(&sanitized_url)?  // Log sanitized URL
        .bytes_stream()
        // ... rest of implementation
}
```

**Additional Recommendations:**

1. **Use HTTP Headers for Authentication**: Encourage operators to use `Authorization` headers instead of URL-based credentials
2. **Add Configuration Validation**: Warn if `backup-service-address` contains suspicious patterns (e.g., `@` or common token parameter names)
3. **Implement Native Authentication**: Add optional OAuth2/JWT authentication support directly in the backup service
4. **Audit Logging Configuration**: Review all logging statements across the codebase for potential credential leakage

## Proof of Concept

```rust
// File: storage/backup/backup-cli/src/utils/test_credential_leakage.rs

#[cfg(test)]
mod credential_leakage_test {
    use super::*;
    use aptos_logger::Logger;
    use std::sync::{Arc, Mutex};
    
    #[tokio::test]
    async fn test_url_credentials_leaked_in_logs() {
        // Setup logger to capture log output
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let buffer_clone = log_buffer.clone();
        
        // Initialize logger with custom writer
        Logger::builder()
            .is_async(false)
            .printer(Box::new(move |record| {
                buffer_clone.lock().unwrap().push(format!("{}", record));
            }))
            .build();
        
        // Create backup client with URL containing credentials
        let client = BackupServiceClient::new(
            "http://admin:secret_password@backup.example.com:6186?token=Bearer_xyz123".to_string()
        );
        
        // Attempt to connect (will fail since address is fake)
        let result = client.get_db_state().await;
        assert!(result.is_err()); // Expected to fail
        
        // Verify credentials were logged
        let logs = log_buffer.lock().unwrap();
        let logs_str = logs.join("\n");
        
        // These should appear in logs (vulnerability)
        assert!(logs_str.contains("secret_password"), 
            "Password leaked in logs!");
        assert!(logs_str.contains("Bearer_xyz123"), 
            "Bearer token leaked in logs!");
        
        println!("VULNERABILITY CONFIRMED: Credentials logged in error messages");
        println!("Log excerpt: {}", logs_str);
    }
    
    #[test]
    fn test_sanitize_url_removes_credentials() {
        // Test HTTP basic auth removal
        let url1 = "http://user:pass@example.com/path";
        let sanitized1 = sanitize_url_for_logging(url1);
        assert!(!sanitized1.contains("user"));
        assert!(!sanitized1.contains("pass"));
        
        // Test query parameter token removal
        let url2 = "http://example.com/api?token=secret123&other=value";
        let sanitized2 = sanitize_url_for_logging(url2);
        assert!(!sanitized2.contains("secret123"));
        assert!(sanitized2.contains("other=value"));
        
        // Test API key removal
        let url3 = "http://example.com/backup?api_key=sk-abc&debug=true";
        let sanitized3 = sanitize_url_for_logging(url3);
        assert!(!sanitized3.contains("sk-abc"));
        assert!(sanitized3.contains("debug=true"));
    }
}
```

**To reproduce:**
1. Configure backup client with credentials in URL: `--backup-service-address "http://token:secret@example.com?key=value"`
2. Trigger any HTTP error (invalid hostname, connection refused, timeout)
3. Observe credentials in error logs via centralized logging dashboard
4. Extract credentials and replay against actual backup service endpoint

## Notes

This vulnerability represents a **defense-in-depth failure** where sensitive credentials are inadvertently exposed through logging. While the backup service itself doesn't require authentication by default (designed for localhost-only access), production deployments that expose it remotely commonly add authentication layers that use URL-based credentials.

The fix requires minimal code changes but provides significant security improvement by preventing credential leakage across all deployment scenarios. This aligns with security best practices and industry standards (OWASP, CWE-532: Insertion of Sensitive Information into Log File).

### Citations

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L64-68)
```rust
        let reader = tokio::time::timeout(timeout, self.client.get(&url).send())
            .await?
            .err_notes(&url)?
            .error_for_status()
            .err_notes(&url)?
```

**File:** storage/backup/backup-cli/src/utils/error_notes.rs (L12-17)
```rust
    fn err_notes(self, notes: N) -> Result<T, E> {
        if let Err(e) = &self {
            error!(error = %e, notes = ?notes, "Error raised, see notes.");
        }
        self
    }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L27-146)
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
```

**File:** storage/README.md (L15-21)
```markdown
* the backup system which persists the entire history of transactions. The
backups are not required for running the blockchain in normal situations, but
can be critical when emergency happens were an AptosDB needs to be recreated
a. without the help of widely available healthy running Aptos Nodes b. to
recover a historical state back in time. c. specifically, to do b. in order to
create an alternative ledger and redistribute the result to overcome
unforeseeable catastrophic situations (to hard fork)
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
