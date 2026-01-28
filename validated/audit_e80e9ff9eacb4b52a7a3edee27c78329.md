# Audit Report

## Title
Unhandled Storage Backend Panic in Inspection Service Identity Endpoint Causes Node Termination

## Summary
The `/identity_information` endpoint in the Aptos inspection service contains an unhandled panic vulnerability when retrieving peer IDs from storage backends. Storage failures trigger `.expect()` calls that panic, causing the global panic handler to terminate the entire node process with exit code 12.

## Finding Description

The vulnerability exists in the `NetworkConfig::peer_id()` function, which is called by the inspection service's `/identity_information` endpoint. When a network configuration uses `Identity::FromStorage`, the function retrieves the peer ID from a secure storage backend. [1](#0-0) 

The `get_identity_information()` function calls `peer_id()` on validator and fullnode network configurations, which for `Identity::FromStorage` uses `.expect()` to handle storage errors: [2](#0-1) 

When storage.get() returns an error, the `.expect("Unable to read peer id")` on line 251 panics. Storage backends return multiple error variants including KeyNotSet, InternalError, SerializationError, and PermissionDenied: [3](#0-2) 

This panic is caught by the global panic handler installed during node initialization: [4](#0-3) 

The panic handler logs the crash and terminates the entire node process with `process::exit(12)`: [5](#0-4) 

**Attack Flow:**
1. Attacker sends GET request to `http://node:9101/identity_information` (enabled by default)
2. `handle_identity_information_request()` calls `get_identity_information()`
3. `peer_id()` is invoked for each network configuration
4. For `Identity::FromStorage`, storage.get() is called
5. If storage fails, it returns `Err`
6. `.expect()` panics
7. Global panic handler terminates the entire node process

The inspection service endpoint is enabled by default and publicly accessible: [6](#0-5) [7](#0-6) 

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

The vulnerability violates the **availability/liveness invariant** - nodes must remain operational during transient infrastructure failures.

## Likelihood Explanation

**Likelihood: Medium to High**

Storage backend failures are operational realities:

**Natural failure scenarios:**
- Vault network connectivity issues during maintenance or network partitions
- Vault being sealed/unsealed during operational procedures
- Disk corruption or I/O errors affecting OnDiskStorage
- File permission changes during system administration
- Deserialization errors after software upgrades with schema changes

**Attack scenarios:**
- Local attacker with filesystem access corrupting OnDiskStorage files
- Timing GET requests during known maintenance windows
- Vault permission manipulation requiring only Vault admin access

Even without direct attacker exploitation, this represents a critical robustness failure. Production systems must handle expected infrastructure failures gracefully. The use of `.expect()` for error handling in an HTTP endpoint violates defensive programming principles.

## Recommendation

Replace `.expect()` with proper error handling that returns an error instead of panicking:

```rust
pub fn peer_id(&self) -> Result<PeerId, Error> {
    match &self.identity {
        Identity::FromConfig(config) => Ok(config.peer_id),
        Identity::FromStorage(config) => {
            let storage: Storage = (&config.backend).into();
            let peer_id = storage
                .get::<PeerId>(&config.peer_id_name)?
                .value;
            Ok(peer_id)
        },
        Identity::FromFile(config) => {
            // Similar handling
        },
        Identity::None => {
            Err(Error::InternalError("peer id should be present".to_string()))
        }
    }
}
```

Update `get_identity_information()` to handle errors gracefully and return appropriate HTTP error responses instead of crashing the node.

## Proof of Concept

To reproduce:
1. Configure a node with `Identity::FromStorage` using OnDiskStorage
2. Corrupt or delete the peer ID file in storage
3. Send GET request to `http://localhost:9101/identity_information`
4. Observe node process terminates with exit code 12

The vulnerability can be verified by examining the code paths shown in the citations above.

### Citations

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L29-51)
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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L127-131)
```rust
        IDENTITY_INFORMATION_PATH => {
            // /identity_information
            // Exposes the identity information of the node
            identity_information::handle_identity_information_request(&node_config)
        },
```
