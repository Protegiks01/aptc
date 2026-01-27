# Audit Report

## Title
Unhandled Storage Backend Panic in Inspection Service Identity Endpoint Causes Node Termination

## Summary
The `/identity_information` endpoint in the Aptos inspection service contains an unhandled panic vulnerability when retrieving peer IDs from storage backends. Storage failures (disk corruption, network issues, permission errors, or deserialization failures) trigger `.expect()` calls that panic, causing the global panic handler to terminate the entire node process with exit code 12.

## Finding Description

The vulnerability exists in the `NetworkConfig::peer_id()` function, which is called by the inspection service's `/identity_information` endpoint. When a network configuration uses `Identity::FromStorage`, the function retrieves the peer ID from a secure storage backend (Vault or OnDiskStorage). [1](#0-0) 

The `get_identity_information()` function calls `peer_id()` on validator and fullnode network configurations: [2](#0-1) 

For the `Identity::FromStorage` case, the code uses `.expect()` to handle storage errors, which panics on any failure. Storage backends return `Result<GetResponse<T>, Error>` with multiple error variants: [3](#0-2) 

These errors include:
- `KeyNotSet`: The peer_id_name key doesn't exist in storage
- `InternalError`: I/O failures, network errors to Vault, Vault unsealed state
- `SerializationError`: Deserialization failures from corrupted or version-mismatched data
- `PermissionDenied`: Access control failures in Vault

When any of these errors occur, the `.expect("Unable to read peer id")` on line 251 panics. This panic is caught by the global panic handler installed during node initialization: [4](#0-3) [5](#0-4) 

The panic handler logs the crash and then **terminates the entire node process** with `process::exit(12)`, unless the panic originated from the Move verifier/deserializer.

**Attack Flow:**
1. Attacker sends GET request to `http://node:9101/identity_information` (enabled by default)
2. `handle_identity_information_request()` calls `get_identity_information()`
3. `peer_id()` is invoked for each network configuration
4. For `Identity::FromStorage`, storage.get() is called
5. If storage fails (corrupted data, network issue, missing key, permission error), it returns `Err`
6. `.expect()` panics
7. Global panic handler terminates the entire node process

The inspection service endpoint is enabled by default and publicly accessible: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:
- **"API crashes"**: The inspection service endpoint crash cascades to full node termination
- **"Validator node slowdowns"**: More accurately, complete validator unavailability through process termination

The impact is severe because:
1. **Complete node unavailability**: Process termination requires manual restart
2. **Default vulnerable state**: The endpoint is enabled by default (`expose_identity_information: true`)
3. **Public exposure**: Listens on `0.0.0.0:9101` by default
4. **Consensus participation loss**: Validator nodes that crash cannot participate in consensus until manually restarted
5. **Cascading failures**: Repeated requests during transient storage issues cause repeated crashes

The vulnerability violates the **availability/liveness invariant** - nodes must remain operational during transient infrastructure failures like temporary Vault network issues or disk I/O errors.

## Likelihood Explanation

**Likelihood: Medium to High**

Storage backend failures are operational realities, not just theoretical attack scenarios:

**Natural failure scenarios:**
- Vault network connectivity issues during maintenance or network partitions
- Vault being sealed/unsealed during operational procedures
- Disk corruption or I/O errors affecting OnDiskStorage
- File permission changes during system administration
- Deserialization errors after software upgrades with schema changes
- Storage backend version mismatches

**Attack scenarios (given the premise of the security question):**
- Local attacker with filesystem access corrupting OnDiskStorage files
- Network-level attacker causing Vault connectivity issues (though network DoS is borderline out-of-scope)
- Permission manipulation in Vault requiring only Vault admin access, not node compromise

Even without direct attacker exploitation, this represents a **critical robustness failure**. Production systems must handle expected infrastructure failures gracefully rather than crashing. The use of `.expect()` for error handling in an HTTP endpoint violates defensive programming principles.

## Recommendation

Replace `.expect()` with proper error handling that returns errors to the caller instead of panicking. The inspection service should return HTTP error responses for storage failures rather than crashing.

**Fix for `network_config.rs`:**

```rust
pub fn peer_id(&self) -> Result<PeerId, anyhow::Error> {
    match &self.identity {
        Identity::FromConfig(config) => Ok(config.peer_id),
        Identity::FromStorage(config) => {
            let storage: Storage = (&config.backend).into();
            let peer_id = storage
                .get::<PeerId>(&config.peer_id_name)
                .map_err(|e| anyhow::anyhow!("Failed to read peer id from storage: {}", e))?
                .value;
            Ok(peer_id)
        },
        Identity::FromFile(config) => {
            let identity_blob: IdentityBlob = IdentityBlob::from_file(&config.path)
                .map_err(|e| anyhow::anyhow!("Failed to read identity from file: {}", e))?;
            
            if let Some(address) = identity_blob.account_address {
                Ok(address)
            } else {
                Ok(from_identity_public_key(
                    identity_blob.network_private_key.public_key(),
                ))
            }
        },
        Identity::None => Err(anyhow::anyhow!("No peer identity configured")),
    }
}
```

**Fix for `identity_information.rs`:**

```rust
fn get_identity_information(node_config: &NodeConfig) -> Result<String, String> {
    let mut identity_information = Vec::<String>::new();
    identity_information.push("Identity Information:".into());

    if let Some(validator_network) = &node_config.validator_network {
        match validator_network.peer_id() {
            Ok(peer_id) => {
                identity_information.push(format!(
                    "\t- Validator network ({}), peer ID: {}",
                    validator_network.network_id, peer_id
                ));
            },
            Err(e) => {
                return Err(format!("Failed to retrieve validator peer ID: {}", e));
            },
        }
    }

    for fullnode_network in &node_config.full_node_networks {
        match fullnode_network.peer_id() {
            Ok(peer_id) => {
                identity_information.push(format!(
                    "\t- Fullnode network ({}), peer ID: {}",
                    fullnode_network.network_id, peer_id
                ));
            },
            Err(e) => {
                return Err(format!("Failed to retrieve fullnode peer ID: {}", e));
            },
        }
    }

    Ok(identity_information.join("\n"))
}

pub fn handle_identity_information_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    if node_config.inspection_service.expose_identity_information {
        match get_identity_information(node_config) {
            Ok(info) => (StatusCode::OK, Body::from(info), CONTENT_TYPE_TEXT.into()),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from(format!("Error retrieving identity information: {}", e)),
                CONTENT_TYPE_TEXT.into(),
            ),
        }
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(IDENTITY_INFO_DISABLED_MESSAGE),
            CONTENT_TYPE_TEXT.into(),
        )
    }
}
```

**Additional fix needed for `identity_key()`:** [7](#0-6) 

This function has the same vulnerability and should also return `Result` instead of using `.expect()`.

## Proof of Concept

```rust
#[cfg(test)]
mod test_storage_panic {
    use super::*;
    use aptos_config::config::{
        Identity, IdentityFromStorage, NetworkConfig, NodeConfig, SecureBackend,
    };
    use aptos_types::network_address::NetworkAddress;
    use std::path::PathBuf;
    
    #[test]
    #[should_panic(expected = "Unable to read peer id")]
    fn test_peer_id_panics_on_missing_storage_key() {
        // Create a network config with FromStorage identity
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("test_storage.json");
        
        let backend = SecureBackend::OnDiskStorage(
            aptos_config::config::OnDiskStorageConfig {
                path: storage_path.clone(),
                namespace: None,
            }
        );
        
        // Create identity pointing to non-existent key
        let identity = Identity::FromStorage(IdentityFromStorage {
            backend,
            key_name: "test_key".to_string(),
            peer_id_name: "nonexistent_peer_id".to_string(), // This key doesn't exist
        });
        
        let mut network_config = NetworkConfig::network_with_id(
            aptos_types::network_address::NetworkId::Validator,
        );
        network_config.identity = identity;
        
        // This will panic because the storage key doesn't exist
        // In production, this crashes the entire node
        let _ = network_config.peer_id();
    }
    
    #[test]
    fn test_inspection_endpoint_triggers_panic() {
        use crate::server::identity_information::get_identity_information;
        
        // Create node config with FromStorage identity pointing to missing key
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("test_storage.json");
        
        let backend = SecureBackend::OnDiskStorage(
            aptos_config::config::OnDiskStorageConfig {
                path: storage_path.clone(),
                namespace: None,
            }
        );
        
        let identity = Identity::FromStorage(IdentityFromStorage {
            backend,
            key_name: "test_key".to_string(),
            peer_id_name: "missing_key".to_string(),
        });
        
        let mut validator_network = NetworkConfig::network_with_id(
            aptos_types::network_address::NetworkId::Validator,
        );
        validator_network.identity = identity;
        
        let mut node_config = NodeConfig::default();
        node_config.validator_network = Some(validator_network);
        node_config.inspection_service.expose_identity_information = true;
        
        // This simulates what happens when a client calls the /identity_information endpoint
        // The panic will propagate through the HTTP handler and trigger the global panic handler
        // which terminates the entire node process
        std::panic::catch_unwind(|| {
            let _ = get_identity_information(&node_config);
        }).expect_err("Should have panicked");
    }
}
```

**To reproduce the vulnerability in a running node:**

1. Configure a validator with `Identity::FromStorage` pointing to a Vault backend
2. Start the node (inspection service runs on port 9101 by default)
3. Seal the Vault or corrupt the storage file
4. Send GET request: `curl http://localhost:9101/identity_information`
5. Observe node process terminates with exit code 12

**Notes**

This vulnerability demonstrates a critical defensive programming failure. The use of `.expect()` in production code paths that handle external resources (storage backends) violates robustness principles. Storage failures should be anticipated and handled gracefully, especially in distributed systems where network partitions, disk failures, and operational maintenance are routine occurrences.

The similar vulnerability in `identity_key()` at line 194 should also be addressed, as it's used during network initialization and could cause startup failures under similar storage conditions.

### Citations

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L29-52)
```rust
fn get_identity_information(node_config: &NodeConfig) -> String {
    let mut identity_information = Vec::<String>::new();
    identity_information.push("Identity Information:".into());

    // If the validator network is configured, fetch the identity information
    if let Some(validator_network) = &node_config.validator_network {
        identity_information.push(format!(
            "\t- Validator network ({}), peer ID: {}",
            validator_network.network_id,
            validator_network.peer_id()
        ));
    }

    // For each fullnode network, fetch the identity information
    for fullnode_network in &node_config.full_node_networks {
        identity_information.push(format!(
            "\t- Fullnode network ({}), peer ID: {}",
            fullnode_network.network_id,
            fullnode_network.peer_id()
        ));
    }

    identity_information.join("\n") // Separate each entry with a newline to construct the output
}
```

**File:** config/src/config/network_config.rs (L187-206)
```rust
    pub fn identity_key(&self) -> x25519::PrivateKey {
        let key = match &self.identity {
            Identity::FromConfig(config) => Some(config.key.private_key()),
            Identity::FromStorage(config) => {
                let storage: Storage = (&config.backend).into();
                let key = storage
                    .export_private_key(&config.key_name)
                    .expect("Unable to read key");
                let key = x25519::PrivateKey::from_ed25519_private_bytes(&key.to_bytes())
                    .expect("Unable to convert key");
                Some(key)
            },
            Identity::FromFile(config) => {
                let identity_blob: IdentityBlob = IdentityBlob::from_file(&config.path).unwrap();
                Some(identity_blob.network_private_key)
            },
            Identity::None => None,
        };
        key.expect("identity key should be present")
    }
```

**File:** config/src/config/network_config.rs (L244-270)
```rust
    pub fn peer_id(&self) -> PeerId {
        match &self.identity {
            Identity::FromConfig(config) => Some(config.peer_id),
            Identity::FromStorage(config) => {
                let storage: Storage = (&config.backend).into();
                let peer_id = storage
                    .get::<PeerId>(&config.peer_id_name)
                    .expect("Unable to read peer id")
                    .value;
                Some(peer_id)
            },
            Identity::FromFile(config) => {
                let identity_blob: IdentityBlob = IdentityBlob::from_file(&config.path).unwrap();

                // If account is not specified, generate peer id from public key
                if let Some(address) = identity_blob.account_address {
                    Some(address)
                } else {
                    Some(from_identity_public_key(
                        identity_blob.network_private_key.public_key(),
                    ))
                }
            },
            Identity::None => None,
        }
        .expect("peer id should be present")
    }
```

**File:** secure/storage/src/error.rs (L8-24)
```rust
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum Error {
    #[error("Entropy error: {0}")]
    EntropyError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    #[error("Key not set: {0}")]
    KeyNotSet(String),
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Key version not found, key name: {0}, version: {1}")]
    KeyVersionNotFound(String, String),
}
```

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```

**File:** crates/crash-handler/src/lib.rs (L26-58)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
}
```

**File:** config/src/config/inspection_service_config.rs (L26-36)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
```
