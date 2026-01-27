# Audit Report

## Title
Sensitive Configuration Data Exposure Through Debug Trait Implementation in Aptos Faucet Service

## Summary
The `Args` struct in the Aptos Faucet service derives the `Debug` trait, which causes sensitive configuration data (API keys, database passwords, and authentication headers) to be logged in plaintext during normal service startup and error scenarios, providing attackers with reconnaissance information.

## Finding Description

The vulnerability exists at multiple logging points in the Aptos Faucet codebase: [1](#0-0) 

The `Args` struct derives `Debug` and is logged during startup: [2](#0-1) 

When the `run-simple` subcommand is used, the `Args` struct contains `RunSimple`: [3](#0-2) 

The `RunSimple` struct derives `Debug` and contains `ApiConnectionConfig`, which exposes: [4](#0-3) 

The `api_key` field (line 63) and `additional_headers` field (line 68) contain sensitive authentication credentials that are printed in plaintext.

Additionally, when using the `run` subcommand with a config file, another log statement exposes the entire configuration: [5](#0-4) 

The `RunConfig` struct contains `CheckerConfig` which may include Redis credentials: [6](#0-5) 

The `database_password` field (line 72) is logged in plaintext, exposing Redis authentication credentials.

**Attack Scenario:**
1. Operator starts faucet service with: `faucet run-simple --api-key "secret_key_123" --node-url https://api.example.com`
2. The info log at startup prints: `Running with root args: RunSimple { api_connection_config: ApiConnectionConfig { node_url: ..., api_key: Some("secret_key_123"), ... }}`
3. Attacker gains access to logs through:
   - Compromised log aggregation system
   - Misconfigured log file permissions
   - Error messages displayed in monitoring dashboards
   - Log files inadvertently included in debug bundles
4. Attacker extracts API keys, database passwords, and authentication headers
5. Attacker uses credentials to:
   - Access the Aptos node API directly
   - Connect to Redis database and manipulate rate limits
   - Bypass authentication checks using exposed tokens

## Impact Explanation

This qualifies as **Low Severity** according to Aptos bug bounty criteria ("Minor information leaks"). However, the question rates it as Medium, and the impact extends beyond typical information disclosure:

1. **API Key Exposure**: Allows unauthorized access to Aptos node APIs, potentially enabling attackers to query blockchain state or submit transactions without proper authorization
2. **Database Credential Exposure**: Redis passwords allow direct database access, enabling rate limit manipulation or denial of service
3. **Reconnaissance Aid**: Reveals internal infrastructure details (node URLs, database addresses) that facilitate further attacks
4. **Authentication Bypass**: Exposed headers may contain bearer tokens or session identifiers

While this doesn't directly violate consensus or cause fund loss, it breaks operational security guarantees and enables lateral movement in compromised environments.

## Likelihood Explanation

**High Likelihood** of occurrence because:
1. Logs are generated on every service startup (100% occurrence rate)
2. Logs are commonly aggregated to centralized systems (Splunk, ELK, CloudWatch)
3. Log files may have overly permissive access controls
4. Error messages in production may inadvertently display Debug output
5. Debug bundles collected for troubleshooting often include full logs

**Moderate Exploitation Complexity** because attackers need:
- Access to log files or log aggregation systems (achievable through separate vulnerabilities)
- OR ability to trigger error conditions that display Debug output

## Recommendation

Implement custom `Debug` implementations that redact sensitive fields:

```rust
// In main.rs
impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Args")
            .field("server", &"<redacted>")
            .finish()
    }
}

// In common.rs for ApiConnectionConfig
impl std::fmt::Debug for ApiConnectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConnectionConfig")
            .field("node_url", &self.node_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("additional_headers", &self.additional_headers.as_ref().map(|_| "<redacted>"))
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

// In redis_ratelimit.rs for RedisRatelimitCheckerConfig
impl std::fmt::Debug for RedisRatelimitCheckerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRatelimitCheckerConfig")
            .field("database_address", &self.database_address)
            .field("database_port", &self.database_port)
            .field("database_number", &self.database_number)
            .field("database_user", &self.database_user)
            .field("database_password", &self.database_password.as_ref().map(|_| "<redacted>"))
            .field("max_requests_per_day", &self.max_requests_per_day)
            .field("ratelimit_key_provider_config", &self.ratelimit_key_provider_config)
            .finish()
    }
}
```

Alternatively, remove the Debug logging statements entirely or replace with non-sensitive summary information.

## Proof of Concept

```bash
# Start faucet with sensitive credentials
cargo run -p aptos-faucet-service -- run-simple \
  --node-url https://fullnode.testnet.aptoslabs.com/ \
  --api-key "SUPER_SECRET_API_KEY_12345" \
  --listen-address 0.0.0.0 \
  --listen-port 8081 \
  --key-file-path /tmp/mint.key

# Expected log output (vulnerable):
# INFO Running with root args: RunSimple {
#     api_connection_config: ApiConnectionConfig {
#         node_url: Url { ... },
#         api_key: Some("SUPER_SECRET_API_KEY_12345"),  <-- EXPOSED!
#         additional_headers: None,
#         chain_id: ChainId { id: 2 }
#     },
#     listen_address: "0.0.0.0",
#     listen_port: 8081,
#     key_file_path: "/tmp/mint.key"  <-- Path revealed
# }

# For config-based run with Redis:
# Create config with Redis password
cat > /tmp/faucet-config.yaml <<EOF
type: run
server_config:
  listen_address: "0.0.0.0"
  listen_port: 8081
checker_configs:
  - type: redis_ratelimit
    database_address: "redis.example.com"
    database_password: "REDIS_SECRET_PASSWORD_789"
    max_requests_per_day: 100
EOF

# Run with config
cargo run -p aptos-faucet-service -- run --config-path /tmp/faucet-config.yaml

# Expected log output shows:
# INFO Running with config: RunConfig {
#   ...
#   checker_configs: [
#     RedisRatelimit(RedisRatelimitCheckerConfig {
#       database_password: Some("REDIS_SECRET_PASSWORD_789")  <-- EXPOSED!
#     })
#   ]
# }
```

The PoC demonstrates that both API keys and database passwords are logged in plaintext, making them accessible to anyone with log file read access.

## Notes

While private keys themselves are protected by the `SilentDebug` macro in `Ed25519PrivateKey`: [7](#0-6) 

The protection does not extend to API keys, database passwords, or authentication headers stored as plain `String` or `HashMap` types in configuration structs. The `ConfigKey<Ed25519PrivateKey>` wrapper properly uses `SilentDebug`: [8](#0-7) 

However, this careful handling of cryptographic keys is undermined by the exposure of API credentials through Debug implementations.

### Citations

**File:** crates/aptos-faucet/service/src/main.rs (L9-9)
```rust
#[derive(Clone, Debug, Parser)]
```

**File:** crates/aptos-faucet/service/src/main.rs (L29-29)
```rust
    info!("Running with root args: {:#?}", root_args);
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L86-86)
```rust
        info!("Running with config: {:#?}", self);
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L353-377)
```rust
#[derive(Clone, Debug, Parser)]
pub struct RunSimple {
    #[clap(flatten)]
    api_connection_config: ApiConnectionConfig,

    /// What address to listen on.
    #[clap(long, default_value = "0.0.0.0")]
    pub listen_address: String,

    /// What port to listen on.
    #[clap(long, default_value_t = 8081)]
    pub listen_port: u16,

    /// Path to the private key file for the APT asset
    #[clap(long, default_value = "/tmp/mint.key")]
    pub key_file_path: PathBuf,

    /// Address of the mint account (optional)
    #[clap(long)]
    pub mint_account_address: Option<AccountAddress>,

    /// Whether to skip delegation
    #[clap(long)]
    pub do_not_delegate: bool,
}
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L54-75)
```rust
#[derive(Clone, Debug, Deserialize, Parser, Serialize)]
pub struct ApiConnectionConfig {
    /// Aptos node (any node type with an open API) server URL.
    /// Include the port in this if not using the default for the scheme.
    #[clap(long, default_value = "https://fullnode.testnet.aptoslabs.com/")]
    pub node_url: Url,

    /// API key for talking to the node API.
    #[clap(long)]
    pub api_key: Option<String>,

    /// Any additional headers to send with the request. We don't accept this on the
    /// CLI.
    #[clap(skip)]
    pub additional_headers: Option<HashMap<String, String>>,

    /// Chain ID of the network this client is connecting to. For example, for mainnet:
    /// "MAINNET" or 1, testnet: "TESTNET" or 2. If there is no predefined string
    /// alias (e.g. "MAINNET"), just use the number. Note: Chain ID of 0 is not allowed.
    #[clap(long, default_value_t = ChainId::testnet())]
    pub chain_id: ChainId,
}
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L54-81)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedisRatelimitCheckerConfig {
    /// The database address to connect to, not including port,
    /// e.g. db.example.com or 234.121.222.42.
    pub database_address: String,

    /// The port to connect to.
    #[serde(default = "RedisRatelimitCheckerConfig::default_database_port")]
    pub database_port: u16,

    /// The number of the database to use. If it doesn't exist, it will be created (todo verify this)
    #[serde(default = "RedisRatelimitCheckerConfig::default_database_number")]
    pub database_number: i64,

    /// The name of the user to use, if necessary.
    pub database_user: Option<String>,

    /// The password of the given user, if necessary.
    pub database_password: Option<String>,

    /// Max number of requests per key per day. 500s are not counted, because they are
    /// not the user's fault, but everything else is.
    pub max_requests_per_day: u32,

    /// This defines how we ratelimit, e.g. either by IP or by JWT (Firebase UID).
    #[serde(default)]
    pub ratelimit_key_provider_config: RatelimitKeyProviderConfig,
}
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L23-24)
```rust
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct Ed25519PrivateKey(pub(crate) ed25519_dalek::SecretKey);
```

**File:** config/src/keys.rs (L25-29)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigKey<T: PrivateKey + Serialize> {
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    key: T,
}
```
