# Audit Report

## Title
PostgreSQL Credential Exposure in Local Testnet Indexer API Logging

## Summary
The `run_service()` function in the Indexer API manager logs the PostgreSQL connection string containing plaintext credentials to application logs, Docker logs, and console output. When users run the local testnet with `--use-host-postgres` and `--host-postgres-password`, database credentials are exposed in multiple locations accessible to unprivileged users.

## Finding Description

The vulnerability exists in the local testnet indexer API service initialization. When configured to use a host PostgreSQL instance with password authentication, the connection string (format: `postgres://username:password@host:port/database`) is logged in plaintext at multiple points:

**Primary Exposure Points:**

1. **Direct connection string logging** - The connection string is logged via the `info!()` macro immediately before container creation: [1](#0-0) 

2. **Docker configuration logging** - The entire Docker container config (including environment variables with the connection string) is logged: [2](#0-1) 

3. **Environment variables exposure** - The config object contains environment variables that include the postgres_connection_string three times: [3](#0-2) 

4. **Health checker output** - The Postgres health checker exposes the connection string in console output via `address_str()`: [4](#0-3) 

5. **Console output** - Connection string printed to stdout when services become ready: [5](#0-4) 

**Connection String Construction:**

The connection string is constructed with password included when `use_host_postgres` is true: [6](#0-5) 

**Additional Exposure in Error Handling:**

Error contexts also include the connection string: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** information disclosure because:

1. **Credential Exposure**: Full database credentials (username and password) are logged in plaintext
2. **Multiple Exposure Vectors**: Credentials appear in application logs, Docker container logs, console output, and error messages
3. **Persistent Storage**: Logs are persisted to disk in the test directory and in Docker's logging system
4. **Wide Accessibility**: Anyone with access to:
   - The host system running the localnet
   - Docker logs command (`docker logs local-testnet-indexer-api`)
   - Application log files in the test directory
   - Console/terminal output
   can retrieve the database credentials

5. **Potential for Unauthorized Access**: Exposed credentials could enable:
   - Unauthorized database access
   - Data manipulation or theft from the indexer database
   - Lateral movement if credentials are reused
   - Compromise of indexer API data integrity

While this affects the local testnet (development tooling) rather than production blockchain infrastructure, credential exposure represents a significant security weakness that could affect developers' systems and any shared development environments.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically whenever a user runs:
```bash
aptos node run-local-testnet --with-indexer-api --use-host-postgres --host-postgres-password "password123"
```

No special conditions or race conditions are required. The credentials are logged immediately upon service startup and remain accessible in:
- Terminal scrollback
- Log files (persistent)
- Docker logs (persistent until container removal)

The issue affects all users who:
- Use the local testnet with indexer API enabled
- Connect to a host PostgreSQL instance
- Provide password authentication

This is a common development scenario, making the likelihood of exposure very high.

## Recommendation

**Immediate Fix**: Sanitize connection strings before logging by redacting credentials.

Implement a helper function to sanitize PostgreSQL connection strings:

```rust
fn sanitize_connection_string(conn_str: &str) -> String {
    // Replace password in postgres://user:password@host:port/db format
    if let Some(at_pos) = conn_str.find('@') {
        if let Some(scheme_end) = conn_str.find("://") {
            let scheme = &conn_str[..scheme_end + 3];
            let after_at = &conn_str[at_pos..];
            
            // Check if there's a password (indicated by colon before @)
            let prefix = &conn_str[scheme_end + 3..at_pos];
            if let Some(colon_pos) = prefix.find(':') {
                let user = &prefix[..colon_pos];
                return format!("{}{}:***REDACTED***{}", scheme, user, after_at);
            }
        }
    }
    conn_str.to_string()
}
```

Apply sanitization at all logging points:

```rust
// Line 217-220: Sanitize before logging
info!(
    "Using postgres connection string: {}",
    sanitize_connection_string(&postgres_connection_string)
);

// Line 249: Don't log config with credentials, or sanitize env vars
info!("Starting indexer API container (config contains credentials, not logged)");
```

**Additional Recommendations:**

1. **HealthChecker::Postgres**: Modify `address_str()` to return a sanitized version or just "postgres" instead of the full connection string
2. **Error contexts**: Sanitize connection strings in error contexts
3. **Environment variables**: Consider using Docker secrets or config files instead of environment variables for credentials
4. **Documentation**: Add security warnings about credential handling in local testnet documentation

## Proof of Concept

**Setup:**
```bash
# Start a PostgreSQL instance
docker run -d --name test-postgres \
  -e POSTGRES_PASSWORD=secretpass123 \
  -p 5432:5432 \
  postgres:14

# Create the database
docker exec test-postgres psql -U postgres -c "CREATE DATABASE local_testnet;"
```

**Exploit:**
```bash
# Run local testnet with password authentication
aptos node run-local-testnet \
  --with-indexer-api \
  --use-host-postgres \
  --host-postgres-password "secretpass123"

# Credentials are immediately visible in console output showing:
# "Using postgres connection string: postgres://postgres:secretpass123@127.0.0.1:5432/local_testnet"

# Retrieve from Docker logs
docker logs local-testnet-indexer-api 2>&1 | grep "postgres://"
# Output shows: postgres://postgres:secretpass123@host.docker.internal:5432/local_testnet

# Retrieve from application logs
cat .aptos/testnet/indexer-api/logs/* | grep "postgres://"
# Shows the same credential exposure
```

**Expected Result:** The password "secretpass123" appears in plaintext in all three locations, accessible to any user with access to the Docker daemon, log files, or terminal output.

**Verification:**
The exposed credentials can be used to connect to the database:
```bash
psql "postgres://postgres:secretpass123@127.0.0.1:5432/local_testnet"
# Successfully connects, confirming credentials are valid and exposed
```

### Citations

**File:** crates/aptos/src/node/local_testnet/indexer_api.rs (L217-220)
```rust
        info!(
            "Using postgres connection string: {}",
            postgres_connection_string
        );
```

**File:** crates/aptos/src/node/local_testnet/indexer_api.rs (L227-233)
```rust
            env: Some(vec![
                format!("PG_DATABASE_URL={}", postgres_connection_string),
                format!(
                    "HASURA_GRAPHQL_METADATA_DATABASE_URL={}",
                    postgres_connection_string
                ),
                format!("INDEXER_V2_POSTGRES_URL={}", postgres_connection_string),
```

**File:** crates/aptos/src/node/local_testnet/indexer_api.rs (L249-249)
```rust
        info!("Starting indexer API with this config: {:?}", config);
```

**File:** crates/aptos/src/node/local_testnet/health_checker.rs (L162-162)
```rust
            HealthChecker::Postgres(url) => url.as_str(),
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L162-166)
```rust
                    println!(
                        "{} is ready. Endpoint: {}",
                        health_checker,
                        health_checker.address_str()
                    );
```

**File:** crates/aptos/src/node/local_testnet/postgres.rs (L92-116)
```rust
    pub fn get_connection_string(&self, database: Option<&str>, external: bool) -> String {
        let password = match self.use_host_postgres {
            true => match &self.host_postgres_password {
                Some(password) => format!(":{}", password),
                None => "".to_string(),
            },
            false => "".to_string(),
        };
        let port = self.get_postgres_port(external);
        let database = match database {
            Some(database) => database,
            None => &self.postgres_database,
        };
        let host = match self.use_host_postgres {
            true => &self.host_postgres_host,
            false => match external {
                true => "127.0.0.1",
                false => POSTGRES_CONTAINER_NAME,
            },
        };
        format!(
            "postgres://{}{}@{}:{}/{}",
            self.postgres_user, password, host, port, database,
        )
    }
```

**File:** crates/aptos/src/node/local_testnet/processors.rs (L137-140)
```rust
            let mut conn: AsyncConnectionWrapper<AsyncPgConnection> =
                AsyncConnectionWrapper::establish(&connection_string).with_context(|| {
                    format!("Failed to connect to postgres at {}", connection_string)
                })?;
```
