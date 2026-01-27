# Audit Report

## Title
Consensus Private Keys Stored in Plaintext via Unvalidated SafetyRulesConfig in JWK Consensus Runtime

## Summary
The `start_jwk_consensus_runtime()` function accepts a `SafetyRulesConfig` without validating that the configured storage backend properly encrypts consensus private keys. When `OnDiskStorage` or `InMemoryStorage` backends are used, consensus private keys are stored in plaintext JSON files or unencrypted memory, allowing any unauthorized process with filesystem access to extract them and compromise consensus safety.

## Finding Description

The `start_jwk_consensus_runtime()` function accepts a `SafetyRulesConfig` parameter and passes it directly to `EpochManager::new()` without validation: [1](#0-0) 

The `EpochManager` then uses this configuration to create a `PersistentSafetyStorage` via the `storage()` function: [2](#0-1) 

The `storage()` function stores consensus private keys directly in the configured backend: [3](#0-2) 

When the backend is `OnDiskStorage`, keys are written as **plaintext JSON** to disk with no encryption: [4](#0-3) 

The code explicitly warns this is insecure and should not be used in production, yet official validator configuration files in the repository use `OnDiskStorage`: [5](#0-4) [6](#0-5) 

The config sanitizer only blocks `InMemoryStorage` on mainnet, but allows `OnDiskStorage` which is equally insecure: [7](#0-6) 

**Attack Path:**
1. Validator configures JWK consensus with `OnDiskStorage` backend (as shown in default configs)
2. `start_jwk_consensus_runtime()` accepts the config without validation
3. Consensus private keys are stored in plaintext at the configured path (e.g., `secure-data.json`)
4. Attacker with filesystem read access (compromised process, container escape, backup access) reads the file
5. Attacker extracts consensus private key from plaintext JSON
6. Attacker can now sign malicious consensus messages, causing safety violations

## Impact Explanation

This vulnerability enables complete compromise of consensus security, qualifying as **Critical Severity** under the Aptos bug bounty program:

- **Consensus/Safety Violations**: An attacker with the consensus private key can sign arbitrary blocks and votes, enabling double-signing/equivocation attacks that break AptosBFT safety guarantees
- **Breaks Invariant #10 (Cryptographic Correctness)**: BLS signatures and key operations must be secure, but storing keys in plaintext violates this fundamental requirement
- **Breaks Invariant #2 (Consensus Safety)**: AptosBFT safety depends on honest validators protecting their signing keys; plaintext storage allows key compromise

The impact matches the Critical category: "Consensus/Safety violations" (up to $1,000,000 bounty).

## Likelihood Explanation

**High Likelihood** - This vulnerability is likely to be exploited because:

1. **Default Configurations Use Insecure Backend**: Official validator configs in the repository use `OnDiskStorage`, making this the default deployment pattern
2. **Low Attack Complexity**: Attacker only needs filesystem read access, achievable via:
   - Compromised co-located process on validator node
   - Container escape in Kubernetes deployments
   - Backup system access
   - Log file exposure
   - Insider threat with SSH access
3. **No Detection Required**: Attacker doesn't need to interact with the network or trigger any detectable behavior
4. **Multiple Attack Vectors**: Any privilege escalation, container escape, or filesystem disclosure vulnerability leads to key compromise

## Recommendation

**Immediate Fix:**

Add validation in `start_jwk_consensus_runtime()` to reject insecure storage backends:

```rust
pub fn start_jwk_consensus_runtime(
    my_addr: AccountAddress,
    safety_rules_config: &SafetyRulesConfig,
    network_client: NetworkClient<JWKConsensusMsg>,
    network_service_events: NetworkServiceEvents<JWKConsensusMsg>,
    reconfig_events: ReconfigNotificationListener<DbBackedOnChainConfig>,
    jwk_updated_events: EventNotificationListener,
    vtxn_pool_writer: VTxnPoolState,
) -> Runtime {
    // Validate that the backend is secure
    if !matches!(safety_rules_config.backend, SecureBackend::Vault(_)) {
        panic!(
            "JWK consensus requires encrypted key storage. OnDiskStorage and InMemoryStorage \
             store keys in plaintext and must not be used. Configure SecureBackend::Vault instead."
        );
    }
    
    // ... rest of function
}
```

**Long-term Fix:**

1. Update `SafetyRulesConfig::sanitize()` to reject `OnDiskStorage` and `InMemoryStorage` for all production validators
2. Update all validator configuration templates to use `VaultStorage`
3. Add runtime checks in `PersistentSafetyStorage::initialize()` to prevent plaintext key storage
4. Consider deprecating or removing `OnDiskStorage` entirely from production builds

## Proof of Concept

```rust
use aptos_config::config::{SafetyRulesConfig, SecureBackend, OnDiskStorageConfig};
use aptos_jwk_consensus::start_jwk_consensus_runtime;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_plaintext_key_exposure() {
    // Create a SafetyRulesConfig with OnDiskStorage (as in default configs)
    let mut safety_rules_config = SafetyRulesConfig::default();
    safety_rules_config.backend = SecureBackend::OnDiskStorage(OnDiskStorageConfig {
        path: PathBuf::from("/tmp/test-secure-data.json"),
        namespace: None,
        data_dir: PathBuf::from("/tmp"),
    });
    
    // Start JWK consensus runtime (accepts insecure config without validation)
    let _runtime = start_jwk_consensus_runtime(
        AccountAddress::random(),
        &safety_rules_config,
        network_client,
        network_service_events,
        reconfig_events,
        jwk_updated_events,
        vtxn_pool_writer,
    );
    
    // Read the file from disk - keys are stored in plaintext JSON
    let contents = fs::read_to_string("/tmp/test-secure-data.json")
        .expect("Should be able to read storage file");
    
    // Parse JSON and verify consensus key is in plaintext
    let data: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert!(data.get("consensus_key").is_some(), 
            "Consensus private key is stored in plaintext!");
    
    // Any attacker with filesystem access can now extract the key
    // and compromise consensus security
}
```

**Notes:**
- Only `VaultStorage` provides proper encryption via HashiCorp Vault's Transit engine
- The vulnerability affects both regular consensus and JWK consensus, as they share the same `SafetyRulesConfig` mechanism
- This is not just a theoretical issue - the official Docker Compose and Helm validator templates in the repository use the insecure `OnDiskStorage` backend

### Citations

**File:** crates/aptos-jwk-consensus/src/lib.rs (L25-50)
```rust
pub fn start_jwk_consensus_runtime(
    my_addr: AccountAddress,
    safety_rules_config: &SafetyRulesConfig,
    network_client: NetworkClient<JWKConsensusMsg>,
    network_service_events: NetworkServiceEvents<JWKConsensusMsg>,
    reconfig_events: ReconfigNotificationListener<DbBackedOnChainConfig>,
    jwk_updated_events: EventNotificationListener,
    vtxn_pool_writer: VTxnPoolState,
) -> Runtime {
    let runtime = aptos_runtimes::spawn_named_runtime("jwk".into(), Some(4));
    let (self_sender, self_receiver) = aptos_channels::new(1_024, &counters::PENDING_SELF_MESSAGES);
    let jwk_consensus_network_client = JWKConsensusNetworkClient::new(network_client);
    let epoch_manager = EpochManager::new(
        my_addr,
        safety_rules_config,
        reconfig_events,
        jwk_updated_events,
        self_sender,
        jwk_consensus_network_client,
        vtxn_pool_writer,
    );
    let (network_task, network_receiver) = NetworkTask::new(network_service_events, self_receiver);
    runtime.spawn(network_task.start());
    runtime.spawn(epoch_manager.start(network_receiver));
    runtime
}
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L69-91)
```rust
    pub fn new(
        my_addr: AccountAddress,
        safety_rules_config: &SafetyRulesConfig,
        reconfig_events: ReconfigNotificationListener<P>,
        jwk_updated_events: EventNotificationListener,
        self_sender: aptos_channels::Sender<Event<JWKConsensusMsg>>,
        network_sender: JWKConsensusNetworkClient<NetworkClient<JWKConsensusMsg>>,
        vtxn_pool: VTxnPoolState,
    ) -> Self {
        Self {
            my_addr,
            key_storage: storage(safety_rules_config),
            epoch_state: None,
            reconfig_events,
            jwk_updated_events,
            self_sender,
            network_sender,
            vtxn_pool,
            jwk_updated_event_txs: None,
            jwk_rpc_msg_tx: None,
            jwk_manager_close_tx: None,
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L21-103)
```rust
pub fn storage(config: &SafetyRulesConfig) -> PersistentSafetyStorage {
    let backend = &config.backend;
    let internal_storage: Storage = backend.into();
    if let Err(error) = internal_storage.available() {
        panic!("Storage is not available: {:?}", error);
    }

    if let Some(test_config) = &config.test {
        let author = test_config.author;
        let consensus_private_key = test_config
            .consensus_key
            .as_ref()
            .expect("Missing consensus key in test config")
            .private_key();
        let waypoint = test_config.waypoint.expect("No waypoint in config");

        PersistentSafetyStorage::initialize(
            internal_storage,
            author,
            consensus_private_key,
            waypoint,
            config.enable_cached_safety_data,
        )
    } else {
        let storage =
            PersistentSafetyStorage::new(internal_storage, config.enable_cached_safety_data);

        let mut storage = if storage.author().is_ok() {
            storage
        } else if !matches!(
            config.initial_safety_rules_config,
            InitialSafetyRulesConfig::None
        ) {
            let identity_blob = config
                .initial_safety_rules_config
                .identity_blob()
                .expect("No identity blob in initial safety rules config");
            let waypoint = config.initial_safety_rules_config.waypoint();

            let backend = &config.backend;
            let internal_storage: Storage = backend.into();
            PersistentSafetyStorage::initialize(
                internal_storage,
                identity_blob
                    .account_address
                    .expect("AccountAddress needed for safety rules"),
                identity_blob
                    .consensus_private_key
                    .expect("Consensus key needed for safety rules"),
                waypoint,
                config.enable_cached_safety_data,
            )
        } else {
            panic!(
                "Safety rules storage is not initialized, provide an initial safety rules config"
            )
        };

        // Ensuring all the overriding consensus keys are in the storage.
        let timer = Instant::now();
        for blob in config
            .initial_safety_rules_config
            .overriding_identity_blobs()
            .unwrap_or_default()
        {
            if let Some(sk) = blob.consensus_private_key {
                let pk_hex = hex::encode(PublicKey::from(&sk).to_bytes());
                let storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
                match storage.internal_store().set(storage_key.as_str(), sk) {
                    Ok(_) => {
                        info!("Setting {storage_key} succeeded.");
                    },
                    Err(e) => {
                        warn!("Setting {storage_key} failed with internal store set error: {e}");
                    },
                }
            }
        }
        info!("Overriding key work time: {:?}", timer.elapsed());

        storage
    }
}
```

**File:** secure/storage/src/on_disk.rs (L16-70)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
pub struct OnDiskStorage {
    file_path: PathBuf,
    temp_path: TempPath,
    time_service: TimeService,
}

impl OnDiskStorage {
    pub fn new(file_path: PathBuf) -> Self {
        Self::new_with_time_service(file_path, TimeService::real())
    }

    fn new_with_time_service(file_path: PathBuf, time_service: TimeService) -> Self {
        if !file_path.exists() {
            File::create(&file_path)
                .unwrap_or_else(|_| panic!("Unable to create storage at path: {:?}", file_path));
        }

        // The parent will be one when only a filename is supplied. Therefore use the current
        // working directory provided by PathBuf::new().
        let file_dir = file_path
            .parent()
            .map_or_else(PathBuf::new, |p| p.to_path_buf());

        Self {
            file_path,
            temp_path: TempPath::new_with_temp_dir(file_dir),
            time_service,
        }
    }

    fn read(&self) -> Result<HashMap<String, Value>, Error> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if contents.is_empty() {
            return Ok(HashMap::new());
        }
        let data = serde_json::from_str(&contents)?;
        Ok(data)
    }

    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** docker/compose/aptos-node/validator.yaml (L7-19)
```yaml
consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L10-22)
```yaml
consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml
```

**File:** config/src/config/safety_rules_config.rs (L71-117)
```rust
impl ConfigSanitizer for SafetyRulesConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let safety_rules_config = &node_config.consensus.safety_rules;

        // If the node is not a validator, there's nothing to be done
        if !node_type.is_validator() {
            return Ok(());
        }

        if let Some(chain_id) = chain_id {
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }

            // Verify that the safety rules service is set to local for optimal performance
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }

            // Verify that the safety rules test config is not enabled in mainnet
            if chain_id.is_mainnet() && safety_rules_config.test.is_some() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The safety rules test config should not be used in mainnet!".to_string(),
                ));
            }
        }

        Ok(())
    }
}
```
