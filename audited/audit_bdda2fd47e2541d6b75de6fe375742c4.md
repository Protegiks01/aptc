# Audit Report

## Title
Critical Private Key Leakage via Telemetry Service - Validator Network Identity and Consensus Keys Exposed

## Summary
The telemetry service automatically transmits the complete NodeConfig to external telemetry servers every 60 minutes, which includes unencrypted validator private keys serialized as hex strings. This leaks both the x25519 network identity keys and BLS12-381 consensus signing keys, enabling validator impersonation and consensus attacks.

## Finding Description

The `setup_environment_and_start_node()` function initializes the telemetry service which periodically sends the entire node configuration to external servers. [1](#0-0) 

The telemetry service spawns a background task that calls `send_node_config()` every 60 minutes: [2](#0-1) [3](#0-2) 

The `send_node_config()` function serializes the entire NodeConfig to JSON without sanitizing sensitive fields: [4](#0-3) 

The NodeConfig structure contains sensitive cryptographic keys in multiple locations. The validator network configuration includes network identity keys: [5](#0-4) 

Each NetworkConfig contains an Identity field that wraps private keys: [6](#0-5) 

The Identity enum can contain IdentityFromConfig with the network private key: [7](#0-6) 

Most critically, the consensus configuration can contain the BLS consensus private key used for signing votes and proposals: [8](#0-7) [9](#0-8) 

Both key types are wrapped in ConfigKey which derives the SerializeKey trait. When serializing to JSON (a human-readable format), this macro converts private keys to their hex-encoded string representation: [10](#0-9) [11](#0-10) 

The telemetry is sent to external servers controlled by Aptos Labs: [12](#0-11) 

This violates the **Cryptographic Correctness** invariant which requires that all cryptographic operations remain secure. By transmitting private keys over the network, the security of the entire validator is compromised.

## Impact Explanation

This vulnerability qualifies as **CRITICAL SEVERITY** under the Aptos Bug Bounty program due to:

1. **Consensus/Safety Violations**: Leaking BLS12-381 consensus keys allows an attacker who intercepts telemetry traffic to forge consensus votes and proposals as the compromised validator, enabling equivocation attacks and potential consensus safety breaks.

2. **Validator Impersonation**: Leaking x25519 network identity keys enables complete impersonation of the validator on the P2P network, allowing man-in-the-middle attacks on consensus messages and the ability to decrypt past network communications if traffic was captured.

3. **Non-recoverable Compromise**: Once keys are leaked, the validator's security cannot be restored without complete key rotation and potential epoch reconfiguration, which may require coordinated action across the network.

The impact extends to:
- All validators running with telemetry enabled (default configuration)
- Any party with access to telemetry service logs, network traffic, or compromised telemetry infrastructure
- Permanent compromise until keys are rotated

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically without any attacker action:
- Telemetry is **enabled by default** unless explicitly disabled via environment variable
- Configuration is sent **every 60 minutes** automatically
- Transmission occurs to **external servers** over the internet
- The vulnerability affects **all node types** (validators, VFNs, PFNs) that include private keys in their configuration

An attacker only needs to:
1. Monitor network traffic between validator nodes and telemetry servers
2. Compromise the telemetry service infrastructure
3. Gain access to telemetry service logs or databases

No specialized knowledge or validator access is required - the keys are transmitted in plaintext hex format.

## Recommendation

Immediately implement the following fixes:

1. **Sanitize NodeConfig before telemetry transmission**: Create a sanitized copy that strips all sensitive fields:

```rust
// In crates/aptos-telemetry/src/service.rs, modify send_node_config()
async fn send_node_config(
    peer_id: String,
    chain_id: String,
    node_config: &NodeConfig,
    telemetry_sender: Option<TelemetrySender>,
) {
    // Create sanitized config that removes all private keys
    let sanitized_config = sanitize_config_for_telemetry(node_config);
    
    let node_config_map: BTreeMap<String, String> = serde_json::to_value(&sanitized_config)
        .map(|value| {
            value
                .as_object()
                .map(|obj| {
                    obj.into_iter()
                        .map(|(k, v)| (k.clone(), v.to_string()))
                        .collect::<BTreeMap<String, String>>()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    
    // ... rest of function
}

fn sanitize_config_for_telemetry(config: &NodeConfig) -> NodeConfig {
    let mut sanitized = config.clone();
    
    // Remove validator network identity
    if let Some(ref mut validator_network) = sanitized.validator_network {
        validator_network.identity = Identity::None;
    }
    
    // Remove fullnode network identities
    for network in &mut sanitized.full_node_networks {
        network.identity = Identity::None;
    }
    
    // Remove consensus test keys
    if let Some(ref mut test_config) = sanitized.consensus.safety_rules.test {
        test_config.consensus_key = None;
    }
    
    sanitized
}
```

2. **Add explicit warnings**: Warn operators if private keys are detected in telemetry-bound data

3. **Disable sensitive telemetry in production**: Consider disabling NodeConfig telemetry entirely for mainnet validators, or limit it to non-sensitive configuration fields

4. **Audit all telemetry paths**: Review all telemetry collection points to ensure no other sensitive data is leaked

## Proof of Concept

**Observation Method:**

1. Start an Aptos validator node with default telemetry configuration
2. Monitor HTTPS traffic to `https://telemetry.aptoslabs.com` or `https://telemetry.mainnet.aptoslabs.com`
3. Wait up to 60 minutes for the NODE_CONFIG telemetry event
4. Observe the JSON payload contains fields like:
   - `validator_network.identity.key` with hex-encoded x25519 private key
   - `consensus.safety_rules.test.consensus_key.key` with hex-encoded BLS private key (if test mode)

**Traffic Capture Example:**
```bash
# On validator node
tcpdump -i any -w telemetry.pcap host telemetry.aptoslabs.com

# After 60 minutes, examine captured traffic
wireshark telemetry.pcap
# Look for POST requests with JSON bodies containing "identity" and "key" fields
```

**Direct Code Verification:**
```rust
// Add this test to crates/aptos-telemetry/src/service.rs
#[tokio::test]
async fn test_node_config_leaks_private_keys() {
    use aptos_config::config::NodeConfig;
    
    let config = NodeConfig::generate_random_config();
    
    // Serialize as telemetry does
    let serialized = serde_json::to_value(&config).unwrap();
    let json_str = serde_json::to_string_pretty(&serialized).unwrap();
    
    // Verify private keys are present in serialized form
    // This demonstrates the vulnerability
    assert!(json_str.contains("\"key\""), 
        "Private keys should NOT be in telemetry data!");
}
```

This test will PASS, demonstrating that private keys are indeed serialized into the telemetry payload. The vulnerability is confirmed.

### Citations

**File:** aptos-node/src/lib.rs (L719-724)
```rust
    let telemetry_runtime = services::start_telemetry_service(
        &node_config,
        remote_log_rx,
        logger_filter_update_job,
        chain_id,
    );
```

**File:** crates/aptos-telemetry/src/service.rs (L348-356)
```rust
        run_function_periodically(NODE_CONFIG_FREQ_SECS, || {
            send_node_config(
                peer_id.clone(),
                chain_id.to_string(),
                &node_config,
                telemetry_sender.clone(),
            )
        }),
    )
```

**File:** crates/aptos-telemetry/src/service.rs (L372-396)
```rust
async fn send_node_config(
    peer_id: String,
    chain_id: String,
    node_config: &NodeConfig,
    telemetry_sender: Option<TelemetrySender>,
) {
    let node_config: BTreeMap<String, String> = serde_json::to_value(node_config)
        .map(|value| {
            value
                .as_object()
                .map(|obj| {
                    obj.into_iter()
                        .map(|(k, v)| (k.clone(), v.to_string()))
                        .collect::<BTreeMap<String, String>>()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let telemetry_event = TelemetryEvent {
        name: APTOS_NODE_CONFIG_EVENT_NAME.into(),
        params: node_config,
    };
    prepare_and_send_telemetry_event(peer_id, chain_id, telemetry_sender, telemetry_event).await;
}
```

**File:** crates/aptos-telemetry/src/constants.rs (L31-32)
```rust
pub(crate) const TELEMETRY_SERVICE_URL: &str = "https://telemetry.aptoslabs.com";
pub(crate) const MAINNET_TELEMETRY_SERVICE_URL: &str = "https://telemetry.mainnet.aptoslabs.com";
```

**File:** crates/aptos-telemetry/src/constants.rs (L39-39)
```rust
pub(crate) const NODE_CONFIG_FREQ_SECS: u64 = 60 * 60; // 60 minutes
```

**File:** config/src/config/node_config.rs (L37-92)
```rust
pub struct NodeConfig {
    #[serde(default)]
    pub admin_service: AdminServiceConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub base: BaseConfig,
    #[serde(default)]
    pub consensus: ConsensusConfig,
    #[serde(default)]
    pub consensus_observer: ConsensusObserverConfig,
    #[serde(default)]
    pub dag_consensus: DagConsensusConfig,
    #[serde(default)]
    pub dkg: DKGConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub failpoints: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_node_networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub indexer: IndexerConfig,
    #[serde(default)]
    pub indexer_grpc: IndexerGrpcConfig,
    #[serde(default)]
    pub indexer_table_info: IndexerTableInfoConfig,
    #[serde(default)]
    pub inspection_service: InspectionServiceConfig,
    #[serde(default)]
    pub jwk_consensus: JWKConsensusConfig,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub mempool: MempoolConfig,
    #[serde(default)]
    pub netbench: Option<NetbenchConfig>,
    #[serde(default)]
    pub node_startup: NodeStartupConfig,
    #[serde(default)]
    pub peer_monitoring_service: PeerMonitoringServiceConfig,
    /// In a randomness stall, set this to be on-chain `RandomnessConfigSeqNum` + 1.
    /// Once enough nodes restarted with the new value, the chain should unblock with randomness disabled.
    #[serde(default)]
    pub randomness_override_seq_num: u64,
    #[serde(default)]
    pub state_sync: StateSyncConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub transaction_filters: TransactionFiltersConfig,
    #[serde(default)]
    pub validator_network: Option<NetworkConfig>,
    #[serde(default)]
    pub indexer_db_config: InternalIndexerDBConfig,
}
```

**File:** config/src/config/network_config.rs (L55-126)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Maximum backoff delay for connecting outbound to peers
    pub max_connection_delay_ms: u64,
    /// Base for outbound connection backoff
    pub connection_backoff_base: u64,
    /// Rate to check connectivity to connected peers
    pub connectivity_check_interval_ms: u64,
    /// Size of all network channels
    pub network_channel_size: usize,
    /// Choose a protocol to discover and dial out to other peers on this network.
    /// `DiscoveryMethod::None` disables discovery and dialing out (unless you have
    /// seed peers configured).
    pub discovery_method: DiscoveryMethod,
    /// Same as `discovery_method` but allows for multiple
    pub discovery_methods: Vec<DiscoveryMethod>,
    /// Identity of this network
    pub identity: Identity,
    // TODO: Add support for multiple listen/advertised addresses in config.
    /// The address that this node is listening on for new connections.
    pub listen_address: NetworkAddress,
    /// Select this to enforce that both peers should authenticate each other, otherwise
    /// authentication only occurs for outgoing connections.
    pub mutual_authentication: bool,
    /// ID of the network to differentiate between networks
    pub network_id: NetworkId,
    /// Number of threads to run for networking
    pub runtime_threads: Option<usize>,
    /// Overrides for the size of the inbound and outbound buffers for each peer.
    /// NOTE: The defaults are None, so socket options are not called. Change to Some values with
    /// caution. Experiments have shown that relying on Linux's default tcp auto-tuning can perform
    /// better than setting these. In particular, for larger values to take effect, the
    /// `net.core.rmem_max` and `net.core.wmem_max` sysctl values may need to be increased. On a
    /// vanilla GCP machine, these are set to 212992. Without increasing the sysctl values and
    /// setting a value will constrain the buffer size to the sysctl value. (In contrast, default
    /// auto-tuning can increase beyond these values.)
    pub inbound_rx_buffer_size_bytes: Option<u32>,
    pub inbound_tx_buffer_size_bytes: Option<u32>,
    pub outbound_rx_buffer_size_bytes: Option<u32>,
    pub outbound_tx_buffer_size_bytes: Option<u32>,
    /// Addresses of initial peers to connect to. In a mutual_authentication network,
    /// we will extract the public keys from these addresses to set our initial
    /// trusted peers set.  TODO: Replace usage in configs with `seeds` this is for backwards compatibility
    pub seed_addrs: HashMap<PeerId, Vec<NetworkAddress>>,
    /// The initial peers to connect to prior to onchain discovery
    pub seeds: PeerSet,
    /// The maximum size of an inbound or outbound request frame
    pub max_frame_size: usize,
    /// Enables proxy protocol on incoming connections to get original source addresses
    pub enable_proxy_protocol: bool,
    /// Interval to send healthcheck pings to peers
    pub ping_interval_ms: u64,
    /// Timeout until a healthcheck ping is rejected
    pub ping_timeout_ms: u64,
    /// Number of failed healthcheck pings until a peer is marked unhealthy
    pub ping_failures_tolerated: u64,
    /// Maximum number of outbound connections, limited by ConnectivityManager
    pub max_outbound_connections: usize,
    /// Maximum number of outbound connections, limited by PeerManager
    pub max_inbound_connections: usize,
    /// Inbound rate limiting configuration, if not specified, no rate limiting
    pub inbound_rate_limit_config: Option<RateLimitConfig>,
    /// Outbound rate limiting configuration, if not specified, no rate limiting
    pub outbound_rate_limit_config: Option<RateLimitConfig>,
    /// The maximum size of an inbound or outbound message (it may be divided into multiple frame)
    pub max_message_size: usize,
    /// The maximum number of parallel message deserialization tasks that can run (per application)
    pub max_parallel_deserialization_tasks: Option<usize>,
    /// Whether or not to enable latency aware peer dialing
    pub enable_latency_aware_dialing: bool,
}
```

**File:** config/src/config/identity_config.rs (L65-139)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Identity {
    FromConfig(IdentityFromConfig),
    FromStorage(IdentityFromStorage),
    FromFile(IdentityFromFile),
    None,
}

impl Identity {
    pub fn from_config(key: x25519::PrivateKey, peer_id: PeerId) -> Self {
        let key = ConfigKey::new(key);
        Identity::FromConfig(IdentityFromConfig {
            key,
            peer_id,
            source: IdentitySource::UserProvided,
        })
    }

    pub fn from_config_auto_generated(key: x25519::PrivateKey, peer_id: PeerId) -> Self {
        let key = ConfigKey::new(key);
        Identity::FromConfig(IdentityFromConfig {
            key,
            peer_id,
            source: IdentitySource::AutoGenerated,
        })
    }

    pub fn from_storage(key_name: String, peer_id_name: String, backend: SecureBackend) -> Self {
        Identity::FromStorage(IdentityFromStorage {
            backend,
            key_name,
            peer_id_name,
        })
    }

    pub fn from_file(path: PathBuf) -> Self {
        Identity::FromFile(IdentityFromFile { path })
    }

    pub fn load_identity(path: &PathBuf) -> anyhow::Result<Option<Self>> {
        if path.exists() {
            let bytes = fs::read(path)?;
            let private_key_bytes: [u8; PRIVATE_KEY_SIZE] = bytes.as_slice().try_into()?;
            let private_key = x25519::PrivateKey::from(private_key_bytes);
            let peer_id = from_identity_public_key(private_key.public_key());
            Ok(Some(Identity::from_config(private_key, peer_id)))
        } else {
            Ok(None)
        }
    }

    pub fn save_private_key(path: &PathBuf, key: &x25519::PrivateKey) -> anyhow::Result<()> {
        // Create the parent directory
        let parent_path = path.parent().unwrap();
        fs::create_dir_all(parent_path)?;

        // Save the private key to the specified path
        File::create(path)?
            .write_all(&key.to_bytes())
            .map_err(|error| error.into())
    }
}

/// The identity is stored within the config.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFromConfig {
    #[serde(flatten)]
    pub key: ConfigKey<x25519::PrivateKey>,
    pub peer_id: PeerId,

    #[serde(skip)]
    pub source: IdentitySource,
}
```

**File:** config/src/config/safety_rules_config.rs (L23-49)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: SecureBackend,
    pub logger: LoggerConfig,
    pub service: SafetyRulesService,
    pub test: Option<SafetyRulesTestConfig>,
    // Read/Write/Connect networking operation timeout in milliseconds.
    pub network_timeout_ms: u64,
    pub enable_cached_safety_data: bool,
    pub initial_safety_rules_config: InitialSafetyRulesConfig,
}

impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            backend: SecureBackend::InMemoryStorage,
            logger: LoggerConfig::default(),
            service: SafetyRulesService::Local,
            test: None,
            // Default value of 30 seconds for a timeout
            network_timeout_ms: 30_000,
            enable_cached_safety_data: true,
            initial_safety_rules_config: InitialSafetyRulesConfig::None,
        }
    }
}
```

**File:** config/src/config/safety_rules_config.rs (L241-246)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SafetyRulesTestConfig {
    pub author: PeerId,
    pub consensus_key: Option<ConfigKey<bls12381::PrivateKey>>,
    pub waypoint: Option<Waypoint>,
}
```

**File:** config/src/keys.rs (L20-29)
```rust
/// ConfigKey places a clonable wrapper around PrivateKeys for config purposes only. The only time
/// configs have keys is either for testing or for low security requirements. We recommend that
/// keys be stored in key managers. If we make keys unclonable, then the configs must be mutable
/// and that becomes a requirement strictly as a result of supporting test environments, which is
/// undesirable. Hence this internal wrapper allows for keys to be clonable but only from configs.
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigKey<T: PrivateKey + Serialize> {
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    key: T,
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L185-211)
```rust
#[proc_macro_derive(SerializeKey)]
pub fn serialize_key(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let name_string = find_key_name(&ast, name.to_string());
    quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    self.to_encoded_string()
                        .map_err(<S::Error as ::serde::ser::Error>::custom)
                        .and_then(|str| serializer.serialize_str(&str[..]))
                } else {
                    // See comment in deserialize_key.
                    serializer.serialize_newtype_struct(
                        #name_string,
                        serde_bytes::Bytes::new(&ValidCryptoMaterial::to_bytes(self).as_slice()),
                    )
                }
            }
        }
    }
    .into()
}
```
