# Audit Report

## Title
Insecure Log File Permissions Expose PII and Transaction Metadata in Local Testnet

## Summary
The local testnet logging configuration creates log files without explicit permission restrictions, allowing group and world-readable access to files containing Personally Identifiable Information (PII) including user email addresses, application names, and transaction metadata. [1](#0-0) 

## Finding Description
When the Aptos local testnet is run with file-based logging (default behavior when `--log-to-stdout` is not specified), the `create_file` function creates log files using `OpenOptions` without setting explicit file permissions. On Unix systems, this results in files being created with the default umask permissions (typically `0o644` or `0o664`), making them readable by group and/or world users.

The vulnerability exists because:

1. **No Permission Restrictions**: The file creation code does not call `.mode(0o600)` to restrict access [2](#0-1) 

2. **Predictable Location**: Log files are stored in predictable paths: `test_dir/thread_name_no_number/tracing.log` [3](#0-2) 

3. **Sensitive Data Logged**: The logs contain PII through the `log_grpc_step` function which records:
   - `request_email` (user email addresses)
   - `request_application_name` (application names)
   - `processor_name`, `request_identifier`, `connection_id`
   - Transaction versions, timestamps, and processing metrics [4](#0-3) 

4. **PII Definition**: The metadata structure explicitly contains email and application identifiers: [5](#0-4) 

**Attack Path:**
1. Attacker gains local access to a system running Aptos local testnet (e.g., compromised user account, shared development server)
2. Attacker locates log files in the test directory (typically `.aptos/testnet/`)
3. Attacker reads world/group-readable log files without any permission barrier
4. Attacker extracts PII, application metadata, and transaction patterns for privacy violations or targeted attacks

**Contrast with Secure Pattern:**
The codebase correctly implements secure file creation for sensitive data elsewhere: [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **Medium severity** per the Aptos bug bounty program criteria for the following reasons:

1. **Information Disclosure**: Exposes PII (email addresses, application names) and transaction metadata
2. **Privacy Violation**: User emails logged in indexer metadata could be harvested for spam, phishing, or business intelligence
3. **Compliance Risk**: Potential violations of privacy regulations (GDPR, CCPA) when PII is not properly secured
4. **Limited Scope**: Requires local system access, limiting the attack surface compared to remote vulnerabilities

While this is primarily an information leak (which might be Low severity), the exposure of PII elevates it to the lower-Medium range, consistent with the security question's classification.

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability is moderately likely to be exploited when:
- Local testnet is run on shared development servers or cloud instances
- Multiple users have access to the same system
- Attackers compromise a low-privilege user account
- Log files persist after testnet shutdown

The attack requires:
- Local access to the system (✓ common in development environments)
- Knowledge of log file location (✓ predictable path)
- No technical expertise needed (✓ simple file read)

## Recommendation
Apply the same secure file permissions pattern used for confidential files elsewhere in the codebase. Modify the `create_file` function to restrict permissions to user-only access:

```rust
fn create_file(base_dir: PathBuf, thread_name_no_number: String) -> File {
    let dir_path = base_dir.join(thread_name_no_number);
    create_dir_all(&dir_path).expect("Failed to create log directory");
    let log_path = dir_path.join("tracing.log");
    
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);  // Add this line: user read/write only
    
    opts.create(true)
        .append(true)
        .open(log_path)
        .unwrap()
}
```

Additionally, consider:
1. Adding a security notice in documentation about PII in logs
2. Implementing log rotation with secure permissions
3. Sanitizing or redacting PII from logs when possible

## Proof of Concept

**Reproduction Steps:**

1. Run Aptos local testnet without `--log-to-stdout`:
```bash
aptos node run-local-testnet --with-indexer-api
```

2. Check log file permissions:
```bash
ls -la ~/.aptos/testnet/*/tracing.log
# Expected (vulnerable): -rw-r--r-- (0644) - world readable
# Expected (secure):     -rw------- (0600) - user only
```

3. Verify PII in logs from another user account:
```bash
# As different user (if on shared system)
grep -E "request_email|request_application_name" ~/.aptos/testnet/*/tracing.log
# Will show email addresses and application names if permissions allow
```

4. Demonstrate the fix works:
```bash
# After applying the fix, verify restricted permissions
ls -la ~/.aptos/testnet/*/tracing.log
# Should show: -rw------- (0600) - user only access
```

**Expected vs Actual Behavior:**
- **Expected**: Log files containing PII should be readable only by the owner (0o600)
- **Actual**: Log files are created with default umask, typically world/group-readable (0o644/0o664)

## Notes

**Scope Clarification:**
- The primary indexer-grpc-file-store service logs to stdout by default (secure) [7](#0-6) 

- The vulnerability specifically affects the local testnet when file logging is configured [8](#0-7) 

- This is a valid security concern as the question explicitly asks about "if logging is configured to write to files," which is exactly what the local testnet does by default

### Citations

**File:** crates/aptos/src/node/local_testnet/logging.rs (L56-65)
```rust
fn create_file(base_dir: PathBuf, thread_name_no_number: String) -> File {
    let dir_path = base_dir.join(thread_name_no_number);
    create_dir_all(&dir_path).expect("Failed to create log directory");
    let log_path = dir_path.join("tracing.log");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .unwrap()
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/counters.rs (L287-306)
```rust
        tracing::info!(
            start_version,
            end_version,
            start_txn_timestamp_iso,
            end_txn_timestamp_iso,
            num_transactions,
            duration_in_secs,
            size_in_bytes,
            // Request metadata variables
            processor_name = &request_metadata.processor_name,
            request_identifier_type = &request_metadata.request_identifier_type,
            request_identifier = &request_metadata.request_identifier,
            request_email = &request_metadata.request_email,
            request_application_name = &request_metadata.request_application_name,
            connection_id = &request_metadata.request_connection_id,
            service_type,
            step = step.get_step(),
            "{}",
            step.get_label(),
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L41-55)
```rust
pub struct IndexerGrpcRequestMetadata {
    pub processor_name: String,
    /// See `REQUEST_HEADER_APTOS_IDENTIFIER_TYPE` for more information.
    pub request_identifier_type: String,
    /// See `REQUEST_HEADER_APTOS_IDENTIFIER` for more information.
    pub request_identifier: String,
    /// See `REQUEST_HEADER_APTOS_EMAIL` for more information.
    pub request_email: String,
    /// See `REQUEST_HEADER_APTOS_APPLICATION_NAME` for more information.
    pub request_application_name: String,
    pub request_connection_id: String,
    // Token is no longer needed behind api gateway.
    #[deprecated]
    pub request_token: String,
}
```

**File:** crates/aptos/src/common/utils.rs (L224-229)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L36-36)
```rust
        setup_logging(None);
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L259-267)
```rust
        if !self.log_to_stdout {
            // Set up logging for anything that uses tracing. These logs will go to
            // different directories based on the name of the runtime.
            let td = test_dir.clone();
            let make_writer = move || {
                ThreadNameMakeWriter::new(td.clone()).make_writer() as Box<dyn std::io::Write>
            };
            setup_logging(Some(Box::new(make_writer)));
        }
```
