# Audit Report

## Title
Database Credential Exposure via Ready Server Health Check Endpoint in Aptos Localnet

## Summary
The Aptos localnet's ready server exposes PostgreSQL connection strings, including passwords, through an unauthenticated HTTP endpoint. While `get_processor_config()` itself does not have direct access to database credentials, the configuration objects it creates are later combined with database credentials that are then leaked through the `HealthChecker` serialization mechanism in the ready server's JSON response.

## Finding Description

The vulnerability exists in the localnet's health checking infrastructure, not directly in `get_processor_config()`. The function `get_processor_config()` returns a `ProcessorConfig` containing only processor-specific configuration without database credentials. [1](#0-0) 

However, this configuration is subsequently combined with database credentials when creating `IndexerProcessorConfig` objects in `ProcessorManager::new()`. [2](#0-1) 

The connection string, which may contain passwords when `--use-host-postgres` and `--host-postgres-password` flags are used, is constructed in `PostgresArgs::get_connection_string()`. [3](#0-2) 

The critical vulnerability occurs when these credentials are exposed through the `HealthChecker` enum. The `ProcessorManager::get_health_checkers()` method creates a `HealthChecker::Processor` variant containing the full connection string. [4](#0-3) 

The `HealthChecker` enum derives `Serialize` without any custom implementation to sanitize sensitive data. [5](#0-4) 

Finally, these health checkers are exposed via the ready server's unauthenticated HTTP endpoint at `/`, which returns JSON containing all `HealthChecker` objects in the `ready` and `not_ready` arrays. [6](#0-5) 

**Attack Path:**
1. Victim runs localnet with `aptos node run-localnet --with-indexer-api --use-host-postgres --host-postgres-password secretpass`
2. Attacker sends GET request to `http://127.0.0.1:8070/`
3. Response contains JSON with `HealthChecker::Processor` objects serialized as: `{"Processor": ["postgres://user:secretpass@host:port/db", "processor_name"]}`
4. Attacker extracts the connection string with password

## Impact Explanation

This is a **Medium Severity** information disclosure vulnerability under the Aptos bug bounty criteria ("Minor information leaks"). The exposure of database credentials could allow an attacker with network access to:

1. Connect to the PostgreSQL database with full credentials
2. Read, modify, or delete indexer data
3. Potentially pivot to other attacks if the database is shared or has additional privileges

While this vulnerability affects the localnet (a development tool) rather than production validator nodes, it still represents a genuine security risk for developers running localnets with external PostgreSQL databases, particularly if the localnet is exposed on a network or the database contains sensitive development data.

## Likelihood Explanation

**Likelihood: Medium-High** for developers who:
- Use `--use-host-postgres` flag (connecting to external database)
- Set `--host-postgres-password` flag (providing a password)
- Expose the ready server endpoint (default port 8070) on a network accessible to attackers
- Run localnet in environments where the network is not fully trusted (e.g., shared development networks, cloud environments)

The vulnerability is easily exploitable requiring only an HTTP GET request with no authentication. However, the impact is limited to development/testing environments rather than production blockchain infrastructure.

## Recommendation

Implement custom `Serialize` for `HealthChecker` to sanitize connection strings before exposing them via HTTP. Similar to the existing `IndexerConfig` implementation that masks passwords in its `Debug` trait, the `HealthChecker` should sanitize credentials:

```rust
impl Serialize for HealthChecker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            HealthChecker::Postgres(connection_string) => {
                let sanitized = sanitize_connection_string(connection_string);
                serializer.serialize_newtype_variant("HealthChecker", 3, "Postgres", &sanitized)
            },
            HealthChecker::Processor(connection_string, processor_name) => {
                let sanitized = sanitize_connection_string(connection_string);
                serializer.serialize_tuple_variant("HealthChecker", 4, "Processor", 2)
                    .and_then(|mut s| {
                        s.serialize_field(&sanitized)?;
                        s.serialize_field(processor_name)?;
                        s.end()
                    })
            },
            // Other variants can use default serialization
            _ => self.serialize_default(serializer),
        }
    }
}

fn sanitize_connection_string(conn_str: &str) -> String {
    if let Ok(mut url) = url::Url::parse(conn_str) {
        if url.password().is_some() {
            url.set_password(Some("***")).unwrap();
        }
        url.to_string()
    } else {
        "***".to_string()
    }
}
```

Alternatively, remove the `Serialize` derive and only expose sanitized display information through the ready server endpoint.

## Proof of Concept

**Steps to reproduce:**

```bash
# 1. Start localnet with host postgres and password
aptos node run-localnet \
  --with-indexer-api \
  --use-host-postgres \
  --host-postgres-password "MySecretPassword123" \
  --postgres-database testdb

# 2. Wait for services to start, then query ready server
curl http://127.0.0.1:8070/

# 3. Observe the JSON response contains:
# {
#   "ready": [
#     {
#       "Processor": [
#         "postgres://postgres:MySecretPassword123@127.0.0.1:5432/testdb",
#         "default_processor"
#       ]
#     },
#     ...
#   ]
# }
```

The response will expose the full connection string including the password "MySecretPassword123" in plaintext, allowing any network observer to extract the database credentials.

**Notes**

This vulnerability is specific to the Aptos localnet development tool and does not affect production validator nodes or the core blockchain protocol. However, it represents a genuine security issue for developers who run localnets with external databases in network-accessible environments. The fix should be implemented to follow security best practices and prevent credential leakage, similar to how the `IndexerConfig` already sanitizes postgres URIs in its `Debug` implementation.

### Citations

**File:** crates/aptos-localnet/src/processors.rs (L14-89)
```rust
pub fn get_processor_config(processor_name: &ProcessorName) -> Result<ProcessorConfig> {
    Ok(match processor_name {
        ProcessorName::AccountTransactionsProcessor => {
            ProcessorConfig::AccountTransactionsProcessor(Default::default())
        },
        ProcessorName::AccountRestorationProcessor => {
            ProcessorConfig::AccountRestorationProcessor(Default::default())
        },
        ProcessorName::AnsProcessor => {
            bail!("ANS processor is not supported in the localnet")
        },
        ProcessorName::DefaultProcessor => ProcessorConfig::DefaultProcessor(Default::default()),
        ProcessorName::EventsProcessor => ProcessorConfig::EventsProcessor(Default::default()),
        ProcessorName::FungibleAssetProcessor => {
            ProcessorConfig::FungibleAssetProcessor(Default::default())
        },
        ProcessorName::GasFeeProcessor => {
            bail!("GasFeeProcessor is not supported in the localnet")
        },
        ProcessorName::MonitoringProcessor => {
            bail!("Monitoring processor is not supported in the localnet")
        },
        ProcessorName::ObjectsProcessor => {
            ProcessorConfig::ObjectsProcessor(ObjectsProcessorConfig {
                default_config: Default::default(),
                query_retries: Default::default(),
                query_retry_delay_ms: Default::default(),
            })
        },
        ProcessorName::ParquetDefaultProcessor => {
            bail!("ParquetDefaultProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetFungibleAssetProcessor => {
            bail!("ParquetFungibleAssetProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetTransactionMetadataProcessor => {
            bail!("ParquetTransactionMetadataProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetAnsProcessor => {
            bail!("ParquetAnsProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetEventsProcessor => {
            bail!("ParquetEventsProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetTokenV2Processor => {
            bail!("ParquetTokenV2Processor is not supported in the localnet")
        },
        ProcessorName::ParquetUserTransactionProcessor => {
            bail!("ParquetUserTransactionProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetObjectsProcessor => {
            bail!("ParquetObjectsProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetAccountTransactionsProcessor => {
            bail!("ParquetAccountTransactionsProcessor is not supported in the localnet")
        },
        ProcessorName::ParquetStakeProcessor => {
            bail!("ParquetStakeProcessor is not supported in the localnet")
        },
        ProcessorName::StakeProcessor => ProcessorConfig::StakeProcessor(StakeProcessorConfig {
            default_config: Default::default(),
            query_retries: Default::default(),
            query_retry_delay_ms: Default::default(),
        }),
        ProcessorName::TokenV2Processor => {
            ProcessorConfig::TokenV2Processor(TokenV2ProcessorConfig {
                default_config: Default::default(),
                query_retries: Default::default(),
                query_retry_delay_ms: Default::default(),
            })
        },
        ProcessorName::UserTransactionProcessor => {
            ProcessorConfig::UserTransactionProcessor(Default::default())
        },
    })
}
```

**File:** crates/aptos/src/node/local_testnet/processors.rs (L64-101)
```rust
impl ProcessorManager {
    fn new(
        processor_name: &ProcessorName,
        prerequisite_health_checkers: HashSet<HealthChecker>,
        data_service_url: Url,
        postgres_connection_string: String,
    ) -> Result<Self> {
        let processor_config = get_processor_config(processor_name)?;
        let config = IndexerProcessorConfig {
            processor_config,
            transaction_stream_config: TransactionStreamConfig {
                indexer_grpc_data_service_address: data_service_url,
                auth_token: "notused".to_string(),
                starting_version: Some(0),
                request_ending_version: None,
                request_name_header: "notused".to_string(),
                additional_headers: Default::default(),
                indexer_grpc_http2_ping_interval_secs: Default::default(),
                indexer_grpc_http2_ping_timeout_secs: 60,
                indexer_grpc_reconnection_timeout_secs: 60,
                indexer_grpc_response_item_timeout_secs: 60,
                indexer_grpc_reconnection_max_retries: Default::default(),
                transaction_filter: Default::default(),
            },
            db_config: DbConfig::PostgresConfig(PostgresConfig {
                connection_string: postgres_connection_string,
                db_pool_size: 8,
            }),
            processor_mode: ProcessorMode::Default(BootStrapConfig {
                initial_starting_version: 0,
            }),
        };
        let manager = Self {
            config,
            prerequisite_health_checkers,
        };
        Ok(manager)
    }
```

**File:** crates/aptos/src/node/local_testnet/processors.rs (L155-166)
```rust
    fn get_health_checkers(&self) -> HashSet<HealthChecker> {
        let connection_string = match &self.config.db_config {
            DbConfig::PostgresConfig(postgres_config) => postgres_config.connection_string.clone(),
            DbConfig::ParquetConfig(_) => {
                panic!("Parquet is not supported in the localnet");
            },
        };
        hashset! {HealthChecker::Processor(
            connection_string,
            self.config.processor_config.name().to_string(),
        ) }
    }
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

**File:** crates/aptos/src/node/local_testnet/health_checker.rs (L24-42)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum HealthChecker {
    /// Check that a HTTP API is up. The second param is the name of the HTTP service.
    Http(Url, String),
    /// Check that the node API is up. This is just a specific case of Http for extra
    /// guarantees around liveliness.
    NodeApi(Url),
    /// Check that a data service GRPC stream is up.
    DataServiceGrpc(Url),
    /// Check that a postgres instance is up.
    Postgres(String),
    /// Check that a processor is successfully processing txns. The first value is the
    /// postgres connection string. The second is the name of the processor. We check
    /// the that last_success_version in the processor_status table is present and > 0.
    Processor(String, String),
    /// Check that the indexer API is up and the metadata has been applied. We only use
    /// this one in the ready server.
    IndexerApiMetadata(Url),
}
```

**File:** crates/aptos/src/node/local_testnet/ready_server.rs (L104-131)
```rust
#[derive(Serialize)]
struct ReadyData {
    pub ready: Vec<HealthChecker>,
    pub not_ready: Vec<HealthChecker>,
}

#[handler]
async fn root(health_checkers: Data<&HealthCheckers>) -> impl IntoResponse + use<> {
    let mut ready = vec![];
    let mut not_ready = vec![];
    for health_checker in &health_checkers.health_checkers {
        // Use timeout since some of these checks can take quite a while if the
        // underlying service is not ready. This is best effort of course, see the docs
        // for tokio::time::timeout for more information.
        match timeout(Duration::from_secs(3), health_checker.check()).await {
            Ok(Ok(())) => ready.push(health_checker.clone()),
            _ => {
                not_ready.push(health_checker.clone());
            },
        }
    }
    let status_code = if not_ready.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Json(ReadyData { ready, not_ready }).with_status(status_code)
}
```
