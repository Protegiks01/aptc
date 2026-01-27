# Audit Report

## Title
Division by Zero Panic in Peer Selection Due to Unvalidated Configuration Values

## Summary
The `AptosDataClient` accepts configuration values without validation, allowing a division by zero panic when `multi_fetch_peer_bucket_size` is set to 0. This causes the state synchronization component to crash during normal peer selection operations.

## Finding Description

The `AptosDataClient::new()` function accepts an `AptosDataClientConfig` parameter and wraps it in an `Arc` without performing any validation on the configuration values. [1](#0-0) 

Unlike other critical configuration structures in Aptos Core that implement the `ConfigSanitizer` trait to validate configuration values before use, `AptosDataClientConfig` has no such validation. [2](#0-1) 

The `AptosDataMultiFetchConfig` structure, which is embedded in `AptosDataClientConfig`, contains a `multi_fetch_peer_bucket_size` field with no constraints. [3](#0-2) 

During peer selection for data requests, when multi-fetch is enabled, the code performs an unchecked division operation using this configuration value. [4](#0-3) 

If `multi_fetch_peer_bucket_size` is set to 0, the division operation triggers a panic, crashing the state sync component. This breaks the **Resource Limits** invariant that "all operations must respect gas, storage, and computational limits" by allowing an unhandled arithmetic operation to panic the system.

**Attack Path:**
1. Node operator (or compromised configuration source) sets `data_multi_fetch_config.multi_fetch_peer_bucket_size = 0` in the node configuration
2. Configuration is loaded and passed to `AptosDataClient::new()` without validation
3. Node starts successfully but state sync component is in vulnerable state
4. Any peer selection operation for a non-subscription request triggers the division by zero
5. State sync component panics and crashes, disrupting node synchronization

Similarly, `latency_filtering_reduction_factor` can cause the same issue during latency-based peer filtering if set to 0. [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:
- **API crashes**: The state sync component crashes when attempting peer selection
- **Validator node slowdowns**: Nodes cannot synchronize state, affecting their ability to participate in consensus
- **Significant protocol violations**: Breaks the resource limits invariant by allowing unhandled panics

The impact is significant because:
1. State synchronization is critical for node operation - validators and fullnodes need it to catch up with the network
2. The crash occurs during normal operation, not edge cases
3. Recovery requires configuration change and node restart
4. Affects node availability and reliability

While not a **Critical Severity** issue (doesn't cause fund loss or permanent network partition), it significantly impacts individual node operations.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is likely to occur because:

1. **No validation barrier**: Configuration values are accepted without any checks, so malicious or erroneous values are not caught
2. **Default values are non-zero** but custom configurations may inadvertently or maliciously set values to 0
3. **Triggered during normal operation**: Any data request that requires peer selection will trigger the vulnerable code path
4. **Serialization from YAML/TOML**: Configuration files that don't explicitly set these values or have typos could result in 0 values

The main requirement is that someone with access to the node's configuration must set the problematic value, which could occur through:
- Misconfiguration by node operators
- Malicious insider with configuration access
- Compromised configuration management systems
- Automated configuration generation with bugs

## Recommendation

Implement a `ConfigSanitizer` for `AptosDataClientConfig` to validate all configuration values before use. The sanitizer should check:

1. `multi_fetch_peer_bucket_size > 0`
2. `latency_filtering_reduction_factor > 0`
3. `max_peers_for_multi_fetch >= min_peers_for_multi_fetch`
4. All timeout values > 0
5. All byte limit values > 0

**Recommended Fix:**

```rust
impl ConfigSanitizer for AptosDataClientConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.state_sync.aptos_data_client;
        
        // Validate multi-fetch configuration
        if config.data_multi_fetch_config.multi_fetch_peer_bucket_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "multi_fetch_peer_bucket_size must be greater than 0".to_string(),
            ));
        }
        
        if config.data_multi_fetch_config.max_peers_for_multi_fetch 
            < config.data_multi_fetch_config.min_peers_for_multi_fetch {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "max_peers_for_multi_fetch must be >= min_peers_for_multi_fetch".to_string(),
            ));
        }
        
        // Validate latency filtering configuration
        if config.latency_filtering_config.latency_filtering_reduction_factor == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "latency_filtering_reduction_factor must be greater than 0".to_string(),
            ));
        }
        
        // Validate timeout values are non-zero
        if config.response_timeout_ms == 0 
            || config.max_response_timeout_ms == 0 
            || config.subscription_response_timeout_ms == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "All timeout values must be greater than 0".to_string(),
            ));
        }
        
        Ok(())
    }
}
```

Additionally, update the `StateSyncConfig::sanitize()` method to call the new sanitizer for `AptosDataClientConfig`.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_division_by_zero_with_invalid_config() {
    use aptos_config::config::{AptosDataClientConfig, AptosDataMultiFetchConfig, BaseConfig};
    use aptos_storage_service_types::requests::{DataRequest, StorageServiceRequest};
    use aptos_time_service::TimeService;
    use std::sync::Arc;
    
    // Create a malicious configuration with multi_fetch_peer_bucket_size = 0
    let malicious_config = AptosDataClientConfig {
        data_multi_fetch_config: AptosDataMultiFetchConfig {
            enable_multi_fetch: true,
            multi_fetch_peer_bucket_size: 0, // Malicious value
            min_peers_for_multi_fetch: 2,
            max_peers_for_multi_fetch: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    
    let base_config = BaseConfig::default();
    let time_service = TimeService::mock();
    let (storage, _) = MockDbReader::new();
    let (network_client, _) = MockStorageServiceClient::new();
    
    // Create client with malicious config - no validation occurs
    let (client, _poller) = AptosDataClient::new(
        malicious_config,
        base_config,
        time_service,
        Arc::new(storage),
        network_client,
        None,
    );
    
    // Trigger peer selection with a non-subscription request
    let request = StorageServiceRequest::new(
        DataRequest::GetEpochEndingLedgerInfos(EpochEndingLedgerInfoRequest {
            start_epoch: 0,
            expected_end_epoch: 10,
        }),
        false,
    );
    
    // This will panic with division by zero when choose_peers_for_request
    // reaches line 306: num_serviceable_peers / multi_fetch_peer_bucket_size
    let _ = client.choose_peers_for_request(&request);
}
```

## Notes

This vulnerability demonstrates a systemic issue: critical configuration structures lack validation. While `StateSyncDriverConfig` has sanitization for specific scenarios, the `AptosDataClientConfig` used throughout state synchronization has none. This pattern should be reviewed across all configuration structures to ensure defensive validation exists at configuration load time rather than relying on runtime behavior.

The division by zero could also occur with `latency_filtering_reduction_factor = 0` in a different code path, indicating multiple attack vectors from the same root cause.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L111-146)
```rust
    pub fn new(
        data_client_config: AptosDataClientConfig,
        base_config: BaseConfig,
        time_service: TimeService,
        storage: Arc<dyn DbReader>,
        storage_service_client: StorageServiceClient<NetworkClient<StorageServiceMessage>>,
        runtime: Option<Handle>,
    ) -> (Self, DataSummaryPoller) {
        // Wrap the configs in an Arc (to be shared across components)
        let base_config = Arc::new(base_config);
        let data_client_config = Arc::new(data_client_config);

        // Create the data client
        let data_client = Self {
            base_config,
            data_client_config: data_client_config.clone(),
            storage_service_client: storage_service_client.clone(),
            active_subscription_state: Arc::new(Mutex::new(None)),
            peer_states: Arc::new(PeerStates::new(data_client_config.clone())),
            global_summary_cache: Arc::new(ArcSwap::from(Arc::new(GlobalDataSummary::empty()))),
            response_id_generator: Arc::new(U64IdGenerator::new()),
            time_service: time_service.clone(),
        };

        // Create the data summary poller
        let data_summary_poller = DataSummaryPoller::new(
            data_client_config,
            data_client.clone(),
            storage_service_client.get_peers_and_metadata(),
            runtime,
            storage,
            time_service,
        );

        (data_client, data_summary_poller)
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L304-308)
```rust
            // Calculate the number of peers to select for the request
            let peer_ratio_for_request =
                num_serviceable_peers / multi_fetch_config.multi_fetch_peer_bucket_size;
            let mut num_peers_for_request = multi_fetch_config.min_peers_for_multi_fetch
                + (peer_ratio_for_request * multi_fetch_config.additional_requests_per_peer_bucket);
```

**File:** config/src/config/state_sync_config.rs (L362-388)
```rust
pub struct AptosDataMultiFetchConfig {
    /// Whether or not to enable multi-fetch for data client requests
    pub enable_multi_fetch: bool,
    /// The number of additional requests to send per peer bucket
    pub additional_requests_per_peer_bucket: usize,
    /// The minimum number of peers for each multi-fetch request
    pub min_peers_for_multi_fetch: usize,
    /// The maximum number of peers for each multi-fetch request
    pub max_peers_for_multi_fetch: usize,
    /// The number of peers per multi-fetch bucket. We use buckets
    /// to track the number of peers that can service a multi-fetch
    /// request and determine the number of requests to send based on
    /// the configured min, max and additional requests per bucket.
    pub multi_fetch_peer_bucket_size: usize,
}

impl Default for AptosDataMultiFetchConfig {
    fn default() -> Self {
        Self {
            enable_multi_fetch: true,
            additional_requests_per_peer_bucket: 1,
            min_peers_for_multi_fetch: 2,
            max_peers_for_multi_fetch: 3,
            multi_fetch_peer_bucket_size: 10,
        }
    }
}
```

**File:** config/src/config/state_sync_config.rs (L487-520)
```rust
impl ConfigSanitizer for StateSyncConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // Sanitize the state sync driver config
        StateSyncDriverConfig::sanitize(node_config, node_type, chain_id)
    }
}

impl ConfigSanitizer for StateSyncDriverConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let state_sync_driver_config = &node_config.state_sync.state_sync_driver;

        // Verify that auto-bootstrapping is not enabled for
        // nodes that are fast syncing.
        let fast_sync_enabled = state_sync_driver_config.bootstrapping_mode.is_fast_sync();
        if state_sync_driver_config.enable_auto_bootstrapping && fast_sync_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Auto-bootstrapping should not be enabled for nodes that are fast syncing!"
                    .to_string(),
            ));
        }

        Ok(())
    }
}
```

**File:** state-sync/aptos-data-client/src/utils.rs (L99-109)
```rust
    if ignore_high_latency_peers {
        let latency_filtering_config = &data_client_config.latency_filtering_config;
        let peer_ratio_per_request = num_peers_to_consider / num_peers_to_choose;
        if num_peers_to_consider >= latency_filtering_config.min_peers_for_latency_filtering
            && peer_ratio_per_request
                >= latency_filtering_config.min_peer_ratio_for_latency_filtering
        {
            // Consider a subset of peers with the lowest latencies
            num_peers_to_consider /= latency_filtering_config.latency_filtering_reduction_factor
        }
    }
```
