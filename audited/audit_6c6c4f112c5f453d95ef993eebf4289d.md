# Audit Report

## Title
Unsafe Unwrap in Indexer Status Page Causes Panic on None Timestamps

## Summary
The `get_throughput_from_samples` function contains multiple unsafe `.unwrap()` calls on optional timestamp fields that can cause panics and crash the status page HTTP handler when processing malformed stream progress data.

## Finding Description

The security question asks whether the nested Option handling in `render_stream_table()` properly covers all None cases. While the specific code mentioned at lines 312-317 is safe, there is a related vulnerability in the same function. [1](#0-0) 

The code above safely handles None cases using `.and_then()` and `.map()`. However, the vulnerability exists in the calls to `get_throughput_from_samples`: [2](#0-1) 

The `get_throughput_from_samples` function contains unsafe `.unwrap()` calls on optional timestamps: [3](#0-2) [4](#0-3) 

The protobuf definition shows timestamp is optional: [5](#0-4) 

**Attack Path:**
1. A malicious or buggy data service sends `StreamInfo` with `StreamProgress` samples where `timestamp` is `None`
2. When the status page endpoint is accessed, `render_stream_table()` calls `get_throughput_from_samples()`
3. The function panics on `.unwrap()` when encountering `None` timestamps
4. The HTTP handler thread crashes, making the status page unavailable

The same vulnerability exists in the data-service-v2 component: [6](#0-5) 

## Impact Explanation

This issue is classified as **Low Severity** per Aptos bug bounty criteria ("Non-critical implementation bugs"). While it causes an API crash, it only affects:

- The monitoring/status page endpoint of off-chain indexer services
- No impact on consensus, execution, storage, or core blockchain operation
- No impact on funds, validator operations, or network security
- The main indexer APIs remain functional

The status page is a monitoring tool, not a critical production API.

## Likelihood Explanation

**Likelihood: Medium**
- Any connected data service can trigger this by sending malformed data
- Could occur accidentally due to bugs in data service implementations
- Does not require privileged access or complex exploitation

## Recommendation

Replace all `.unwrap()` calls with proper None handling:

```rust
pub fn get_throughput_from_samples(
    progress: Option<&StreamProgress>,
    duration: Duration,
) -> String {
    if let Some(progress) = progress {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        let index = progress.samples.partition_point(|p| {
            // Handle None timestamp gracefully
            if let Some(ts) = p.timestamp.as_ref() {
                let diff = now - timestamp_to_unixtime(ts);
                diff > duration.as_secs_f64()
            } else {
                false  // Treat samples without timestamps as too old
            }
        });

        if index + 1 < progress.samples.len() {
            let sample_a = &progress.samples[index];
            let sample_b = progress.samples.last().unwrap();
            
            // Check both timestamps exist
            if let (Some(ts_a), Some(ts_b)) = (
                sample_a.timestamp.as_ref(),
                sample_b.timestamp.as_ref()
            ) {
                let time_diff = timestamp_to_unixtime(ts_b) - timestamp_to_unixtime(ts_a);
                if time_diff > 0.0 {
                    let tps = (sample_b.version - sample_a.version) as f64 / time_diff;
                    let bps = (sample_b.size_bytes - sample_a.size_bytes) as f64 / time_diff;
                    return format!(
                        "{} tps, {} / s",
                        tps as u64,
                        bytesize::to_string(bps as u64, false)
                    );
                }
            }
        }
    }

    "No data".to_string()
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::indexer::v1::{StreamProgress, StreamProgressSampleProto};

    #[test]
    #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
    fn test_throughput_panic_on_none_timestamp() {
        let mut progress = StreamProgress {
            samples: vec![
                StreamProgressSampleProto {
                    timestamp: None,  // This will cause panic
                    version: 100,
                    size_bytes: 1000,
                },
                StreamProgressSampleProto {
                    timestamp: None,
                    version: 200,
                    size_bytes: 2000,
                },
            ],
        };

        // This will panic on unwrap
        get_throughput_from_samples(Some(&progress), Duration::from_secs(10));
    }
}
```

## Notes

While this is a legitimate implementation bug that should be fixed, it does not meet the minimum severity threshold (Critical/High/Medium) required for the Aptos bug bounty program validation checklist. The issue is confined to monitoring endpoints in off-chain indexer services and does not affect any core blockchain functionality, consensus, execution, or funds.

The specific code mentioned in the security question (lines 312-317) correctly handles None cases. The vulnerability exists in a different location within the same function (lines 327-342 calling `get_throughput_from_samples`).

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L312-317)
```rust
                        .with_cell(TableCell::new(TableCellType::Data).with_raw(format!(
                            "{:?}",
                            active_stream.progress.as_ref().and_then(|progress| {
                                progress.samples.last().map(|sample| sample.version)
                            })
                        )))
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L326-343)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs (L94-96)
```rust
        let index = progress.samples.partition_point(|p| {
            let diff = now - timestamp_to_unixtime(p.timestamp.as_ref().unwrap());
            diff > duration.as_secs_f64()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs (L102-106)
```rust
            let sample_a = progress.samples[index];
            let sample_b = progress.samples.last().unwrap();
            let time_diff = timestamp_to_unixtime(sample_b.timestamp.as_ref().unwrap())
                - timestamp_to_unixtime(sample_a.timestamp.as_ref().unwrap());
            let tps = (sample_b.version - sample_a.version) as f64 / time_diff;
```

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L160-167)
```rust
pub struct StreamProgressSampleProto {
    #[prost(message, optional, tag="1")]
    pub timestamp: ::core::option::Option<super::super::util::timestamp::Timestamp>,
    #[prost(uint64, tag="2")]
    pub version: u64,
    #[prost(uint64, tag="3")]
    pub size_bytes: u64,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/status_page.rs (L81-98)
```rust
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
```
