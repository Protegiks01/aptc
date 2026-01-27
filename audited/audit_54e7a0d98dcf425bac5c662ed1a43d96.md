# Audit Report

## Title
Unvalidated gRPC Address Format in Indexer Manager Enables Denial of Service and SSRF Attacks

## Summary
The `self_advertised_address` field in the indexer-grpc components lacks format validation, allowing malicious actors to crash the GrpcManager service via panic or conduct SSRF attacks against internal network resources.

## Finding Description

The indexer-grpc system uses a `self_advertised_address` configuration field to identify services in distributed heartbeat messages. This address is defined as a plain `String` type with no validation at the configuration level. [1](#0-0) [2](#0-1) 

When data services or other GrpcManager instances send heartbeats, they include their `self_advertised_address` in the message: [3](#0-2) 

The receiving GrpcManager extracts this address without validation: [4](#0-3) 

When processing heartbeats from previously unknown services, the system attempts to create gRPC client connections to these addresses using `or_insert` operations: [5](#0-4) [6](#0-5) 

These service constructors unconditionally call `Channel::from_shared().expect()`, which panics on invalid URI formats: [7](#0-6) [8](#0-7) 

**Attack Scenario 1 - Denial of Service:**
1. Attacker deploys a malicious data service with `self_advertised_address: "not-a-valid-uri"`
2. Service sends heartbeat to GrpcManager
3. GrpcManager attempts to parse invalid URI
4. `Channel::from_shared()` returns `Err`
5. `expect("Bad address.")` panics
6. Entire GrpcManager process crashes

**Attack Scenario 2 - Server-Side Request Forgery:**
1. Attacker configures `self_advertised_address: "http://internal-admin-panel:8080"`
2. GrpcManager creates client connection to internal service
3. Periodic health checks in the main loop attempt to connect: [9](#0-8) 

4. Attacker can probe internal network topology, bypass firewalls, or trigger actions on internal services

## Impact Explanation

This vulnerability achieves **Medium Severity** under the Aptos bug bounty criteria:

1. **API Crashes**: The panic causes immediate termination of the GrpcManager service, disrupting the indexer infrastructure that applications rely on for querying blockchain data efficiently.

2. **State Inconsistencies**: While the blockchain itself is unaffected, the indexer service state becomes inconsistent, requiring manual intervention to restart and potentially losing tracking of active data service connections.

3. **SSRF Risk**: Valid but malicious addresses enable reconnaissance and potential exploitation of internal network services that should not be accessible from external networks.

The vulnerability does not directly impact consensus, validator operations, or on-chain state, preventing it from reaching Critical or High severity. However, the indexer infrastructure is critical for ecosystem functionality, and its disruption impacts user experience and application availability.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

1. **Low Barrier to Entry**: Any entity capable of running an indexer data service can exploit this vulnerability
2. **No Authentication Required**: The heartbeat mechanism accepts connections from any network peer that can establish a gRPC connection
3. **Simple Exploitation**: Requires only configuration file modification and service startup
4. **Immediate Impact**: Single malformed heartbeat message causes instant crash
5. **Detection Difficulty**: Appears as legitimate service registration until the crash occurs

The only mitigation is network-level access controls, which may not be consistently deployed across all GrpcManager instances.

## Recommendation

Implement strict validation of the `self_advertised_address` at multiple layers:

**1. Configuration-time validation:**
```rust
use url::Url;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcManagerConfig {
    // ... other fields ...
    #[serde(deserialize_with = "validate_grpc_address")]
    pub(crate) self_advertised_address: GrpcAddress,
    // ... other fields ...
}

fn validate_grpc_address<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let address = String::deserialize(deserializer)?;
    
    // Parse as URL to ensure valid format
    let url = Url::parse(&address).map_err(serde::de::Error::custom)?;
    
    // Ensure http/https scheme
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(serde::de::Error::custom("Address must use http or https scheme"));
    }
    
    // Ensure host is present
    if url.host().is_none() {
        return Err(serde::de::Error::custom("Address must contain a valid host"));
    }
    
    // Optionally: validate against allowlist or block internal IPs
    if let Some(host) = url.host_str() {
        if host == "localhost" || host.starts_with("127.") || host.starts_with("10.") 
            || host.starts_with("192.168.") || host.starts_with("172.") {
            return Err(serde::de::Error::custom("Internal/localhost addresses not allowed"));
        }
    }
    
    Ok(address)
}
```

**2. Runtime validation in service constructors:**
Replace all `expect()` calls with proper error handling:

```rust
impl Peer {
    fn new(address: GrpcAddress) -> Result<Self, anyhow::Error> {
        let channel = Channel::from_shared(address.clone())
            .map_err(|e| anyhow::anyhow!("Invalid address {}: {}", address, e))?
            .connect_lazy();
        let client = GrpcManagerClient::new(channel)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd)
            .max_encoding_message_size(MAX_MESSAGE_SIZE)
            .max_decoding_message_size(MAX_MESSAGE_SIZE);
        Ok(Self {
            client,
            recent_states: VecDeque::new(),
        })
    }
}
```

**3. Handle errors gracefully in heartbeat processing:**
```rust
fn handle_live_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: LiveDataServiceInfo,
) -> Result<()> {
    let entry = self.live_data_services.entry(address.clone());
    let entry = match entry {
        Entry::Occupied(e) => e,
        Entry::Vacant(e) => {
            match LiveDataService::new(address.clone()) {
                Ok(service) => e.insert(service),
                Err(err) => {
                    warn!("Failed to create client for {}: {}", address, err);
                    return Ok(()); // Skip this service rather than crashing
                }
            }
        }
    };
    // ... rest of function
}
```

## Proof of Concept

**Step 1: Create malicious configuration**
```yaml
# malicious_config.yaml
chain_id: 1
service_config:
  listen_address: "0.0.0.0:50051"
live_data_service_config:
  enabled: true
  num_slots: 1000000
  size_limit_bytes: 1000000000
historical_data_service_config:
  enabled: false
  file_store_config:
    file_store_type: "GCS"
    gcs_file_store_bucket_name: "test-bucket"
grpc_manager_addresses:
  - "http://target-manager:50051"
self_advertised_address: "this-is-not-a-valid-url-!@#$%"  # Invalid URI
max_transaction_filter_size_bytes: 10485760
data_service_response_channel_size: 5
```

**Step 2: Start malicious data service**
```bash
# The data service will start and immediately send a heartbeat
# with the malformed self_advertised_address
./aptos-indexer-grpc-data-service-v2 --config malicious_config.yaml
```

**Step 3: Observe GrpcManager crash**
```
thread 'tokio-runtime-worker' panicked at 'Bad address.': 
InvalidUri(InvalidFormat)
```

**Alternative PoC for SSRF:**
```yaml
self_advertised_address: "http://169.254.169.254/latest/meta-data/"  # AWS metadata service
```
The GrpcManager will attempt to connect to and probe the cloud metadata service during health checks.

## Notes

This vulnerability affects the indexer-grpc infrastructure, not the core blockchain consensus or execution layers. While the blockchain itself continues to operate normally, the indexer service disruption impacts:

1. **Application Availability**: DApps relying on indexed data cannot query historical transactions efficiently
2. **User Experience**: Block explorers and wallets experience degraded performance
3. **Operational Costs**: Requires manual intervention to restart services and investigate crashes
4. **Security Posture**: SSRF capabilities enable reconnaissance of internal network architecture

The same validation issues exist in the data service configuration as well: [10](#0-9) 

All components using `self_advertised_address` should implement the recommended validation to prevent both DoS and SSRF attack vectors.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L16-16)
```rust
pub(crate) type GrpcAddress = String;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L37-37)
```rust
    pub(crate) self_advertised_address: GrpcAddress,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L277-279)
```rust
        let service_info = ServiceInfo {
            address: Some(self.self_advertised_address.clone()),
            info,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L115-121)
```rust
        if let Some(service_info) = request.service_info {
            if let Some(address) = service_info.address {
                if let Some(info) = service_info.info {
                    return self
                        .handle_heartbeat(address, info)
                        .await
                        .map_err(|e| Status::internal(format!("Error handling heartbeat: {e}")));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L89-92)
```rust
    fn new(address: GrpcAddress) -> Self {
        let channel = Channel::from_shared(address)
            .expect("Bad address.")
            .connect_lazy();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L111-114)
```rust
    fn new(address: GrpcAddress) -> Self {
        let channel = Channel::from_shared(address)
            .expect("Bad address.")
            .connect_lazy();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L217-247)
```rust
                for kv in &self.live_data_services {
                    let (address, live_data_service) = kv.pair();
                    let unreachable = live_data_service.recent_states.back().is_some_and(|s| {
                        Self::is_stale_timestamp(
                            s.timestamp.unwrap_or_default(),
                            Duration::from_secs(60),
                        )
                    });
                    if unreachable {
                        unreachable_live_data_services.push(address.clone());
                        continue;
                    }
                    let need_ping = live_data_service.recent_states.back().is_none_or(|s| {
                        Self::is_stale_timestamp(
                            s.timestamp.unwrap_or_default(),
                            Duration::from_secs(5),
                        )
                    });
                    if need_ping {
                        let address = address.clone();
                        let client = live_data_service.client.clone();
                        s.spawn(async move {
                            if let Err(e) =
                                self.ping_live_data_service(address.clone(), client).await
                            {
                                warn!("Failed to ping live data service ({address}): {e:?}.");
                            } else {
                                trace!("Successfully pinged live data service ({address}).");
                            }
                        });
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L494-497)
```rust
        let mut entry = self
            .live_data_services
            .entry(address.clone())
            .or_insert(LiveDataService::new(address));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L516-519)
```rust
        let mut entry = self
            .historical_data_services
            .entry(address.clone())
            .or_insert(HistoricalDataService::new(address));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L91-91)
```rust
    pub(crate) self_advertised_address: String,
```
