# Audit Report

## Title
Validator Operator Correlation via Telemetry System Hostname and Hardware Fingerprinting

## Summary
The Aptos telemetry system exposes system hostnames, hardware specifications, and timing patterns that enable adversaries to correlate multiple validators operated by the same entity, violating operational security and validator privacy assumptions.

## Finding Description

The telemetry system collects and transmits sensitive system information to a centralized telemetry service that enables correlation attacks across validators. The vulnerability manifests through multiple information leakage vectors:

**Primary Leakage Vector - System Hostname:** [1](#0-0) 

The `collect_sys_info` function calls `system.lock().host_name()` and inserts it as `SYSTEM_HOST_NAME`, which is then sent as part of the `APTOS_NODE_SYSTEM_INFORMATION` telemetry event. This occurs every 5 minutes. [2](#0-1) 

**Hardware Fingerprinting Vectors:** [3](#0-2) 

CPU brand, vendor ID, frequency, and core count are collected and transmitted, creating a hardware fingerprint. [4](#0-3) 

Memory specifications (total, used, available) and disk configurations are also collected.

**Timing Correlation Vector:** [5](#0-4) 

A random `TELEMETRY_TOKEN` is generated once per node startup and included in all telemetry events, enabling correlation of events from the same node instance. [6](#0-5) 

**Configuration Correlation Vector:** [7](#0-6) 

The entire `NodeConfig` is serialized and sent every hour, potentially revealing configuration patterns used by the same operator.

**Attack Scenario:**

1. Adversary gains access to telemetry service data (via compromise, insider access, or legal disclosure)
2. Collects telemetry events from all validators over time
3. Correlates validators by:
   - **Hostname patterns**: e.g., "validator-acme-node1", "validator-acme-node2"
   - **Hardware fingerprints**: Identical CPU/memory/disk specifications indicating same cloud provider or hardware procurement
   - **Build fingerprints**: Identical commit hash and build timestamp indicating single build deployed to multiple validators
   - **Timing patterns**: Simultaneous updates/restarts across validators (matching `TELEMETRY_TOKEN` generation times)
   - **Configuration similarity**: Nearly identical `NodeConfig` parameters
4. Identifies validator clusters operated by same entity
5. Enables targeted attacks, censorship, or cartel analysis

## Impact Explanation

**Severity: Medium**

This vulnerability fits the **Medium Severity** category as defined in the Aptos bug bounty program:
- **"Minor information leaks"** - Reveals validator operator clustering and infrastructure details
- **Operational Security Impact** - Enables adversary to map validator operator landscape
- **Privacy Violation** - Breaks validator pseudonymity assumptions
- **Attack Enablement** - Facilitates targeted attacks on specific operators or detection of operator collusion

The impact does not reach Critical or High severity because:
- Does not directly affect consensus safety or liveness
- Does not cause loss of funds or state corruption
- Requires adversary access to centralized telemetry service

However, the impact is significant for:
- **Targeted attacks**: Adversary can identify and attack all validators of a specific operator
- **Censorship**: Reveals which validators to target for censorship
- **Privacy**: Violates reasonable expectations that validators maintain operational privacy
- **Compliance**: May violate privacy regulations in jurisdictions requiring operator anonymity

## Likelihood Explanation

**Likelihood: Medium to High**

The attack likelihood depends on adversary capabilities:

**High likelihood if:**
- Adversary compromises the telemetry service (single point of failure)
- Adversary has legal access to telemetry data (subpoena, regulatory demand)
- Insider threat at Aptos Labs or telemetry service provider

**Medium likelihood if:**
- Adversary performs network traffic analysis to intercept telemetry data (protected by TLS but metadata may leak)

**Attack complexity: Low** once access is obtained:
- Correlation algorithms are straightforward pattern matching
- Multiple redundant correlation vectors ensure high confidence
- No cryptographic or consensus protocol knowledge required

**Factors increasing likelihood:**
- Telemetry is enabled by default for all validators
- System hostname is commonly set to descriptive names by operators
- Cloud providers use similar hardware within regions, strengthening fingerprints
- Operators often use configuration templates, increasing similarity

## Recommendation

**Immediate Mitigation:**

1. **Remove system hostname from telemetry:** [1](#0-0) 

Remove or hash the `SYSTEM_HOST_NAME` field before transmission:

```rust
// DO NOT send raw hostname
// utils::insert_optional_value(
//     system_information,
//     SYSTEM_HOST_NAME,
//     system.lock().host_name(),
// );

// Instead, send hashed hostname or omit entirely
utils::insert_optional_value(
    system_information,
    SYSTEM_HOST_NAME,
    system.lock().host_name().map(|h| {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(h.as_bytes());
        format!("{:x}", hasher.finalize())
    }),
);
```

2. **Add noise to hardware fingerprints:**

Quantize or add noise to CPU frequency, memory sizes to prevent exact matching while preserving telemetry value.

3. **Add configuration sanitization:** [7](#0-6) 

Filter sensitive configuration fields before sending (network addresses, peer lists, custom parameters).

4. **Implement differential privacy:**

Add calibrated noise to timing patterns (random delays in telemetry submission) to break timing correlation.

**Long-term Solution:**

1. Implement local telemetry aggregation with differential privacy guarantees
2. Use secure multi-party computation for aggregated statistics without revealing individual validator data
3. Provide clear opt-out mechanism with granular controls
4. Document exactly what telemetry data is collected and transmitted
5. Implement telemetry data retention and deletion policies

## Proof of Concept

The following demonstrates correlation via hostname patterns:

```rust
// Simulated telemetry data collection showing correlation
use std::collections::HashMap;

#[derive(Debug)]
struct TelemetrySnapshot {
    peer_id: String,
    system_host_name: String,
    cpu_brand: String,
    memory_total: u64,
    build_commit_hash: String,
    telemetry_token: String,
}

fn correlate_validators(snapshots: Vec<TelemetrySnapshot>) -> Vec<Vec<String>> {
    let mut operator_groups: HashMap<String, Vec<String>> = HashMap::new();
    
    // Correlation by hostname pattern
    for snapshot in &snapshots {
        let hostname_prefix = snapshot.system_host_name
            .split('-')
            .take(2)
            .collect::<Vec<_>>()
            .join("-");
        
        operator_groups
            .entry(hostname_prefix)
            .or_insert_with(Vec::new)
            .push(snapshot.peer_id.clone());
    }
    
    // Additional correlation by hardware fingerprint
    let mut hw_groups: HashMap<(String, u64, String), Vec<String>> = HashMap::new();
    for snapshot in &snapshots {
        let fingerprint = (
            snapshot.cpu_brand.clone(),
            snapshot.memory_total,
            snapshot.build_commit_hash.clone(),
        );
        hw_groups
            .entry(fingerprint)
            .or_insert_with(Vec::new)
            .push(snapshot.peer_id.clone());
    }
    
    operator_groups.values().cloned().collect()
}

// Example showing correlation:
fn main() {
    let snapshots = vec![
        TelemetrySnapshot {
            peer_id: "validator_1".into(),
            system_host_name: "acme-validator-01".into(),
            cpu_brand: "Intel Xeon E5-2686".into(),
            memory_total: 64_000_000_000,
            build_commit_hash: "abc123".into(),
            telemetry_token: "TOKEN_12345".into(),
        },
        TelemetrySnapshot {
            peer_id: "validator_2".into(),
            system_host_name: "acme-validator-02".into(),
            cpu_brand: "Intel Xeon E5-2686".into(),
            memory_total: 64_000_000_000,
            build_commit_hash: "abc123".into(),
            telemetry_token: "TOKEN_12346".into(),
        },
    ];
    
    let groups = correlate_validators(snapshots);
    println!("Correlated validator groups: {:?}", groups);
    // Output: [["validator_1", "validator_2"]] - Same operator identified!
}
```

## Notes

- The `write()` function in `telemetry_log_writer.rs` is the transport mechanism; the vulnerability exists in what data is collected upstream
- Multiple correlation vectors provide redundancy - even if hostname is sanitized, hardware fingerprinting combined with timing patterns can still reveal operator clustering
- The telemetry service at `https://telemetry.aptoslabs.com` becomes a single point of privacy failure
- Operators can disable telemetry via `APTOS_DISABLE_TELEMETRY` environment variable, but this is not documented as a privacy requirement
- The issue affects all validators who have not explicitly disabled telemetry (which is the default configuration)

### Citations

**File:** crates/aptos-telemetry/src/system_information.rs (L71-93)
```rust
fn collect_cpu_info(
    system_information: &mut BTreeMap<String, String>,
    system: &Lazy<Mutex<System>>,
) {
    // Collect the number of CPUs and cores
    let system_lock = system.lock();
    let cpus = system_lock.cpus();
    system_information.insert(CPU_COUNT.into(), cpus.len().to_string());
    utils::insert_optional_value(
        system_information,
        CPU_CORE_COUNT,
        system_lock
            .physical_core_count()
            .map(|count| count.to_string()),
    );

    // Collect the overall CPU info
    let global_cpu = system_lock.global_cpu_info();
    system_information.insert(CPU_BRAND.into(), global_cpu.brand().into());
    system_information.insert(CPU_FREQUENCY.into(), global_cpu.frequency().to_string());
    system_information.insert(CPU_NAME.into(), global_cpu.name().into());
    system_information.insert(CPU_VENDOR_ID.into(), global_cpu.vendor_id().into());
}
```

**File:** crates/aptos-telemetry/src/system_information.rs (L138-150)
```rust
fn collect_memory_info(
    system_information: &mut BTreeMap<String, String>,
    system: &Lazy<Mutex<System>>,
) {
    // Collect the information for the memory
    let system_lock = system.lock();
    system_information.insert(
        MEMORY_AVAILABLE.into(),
        system_lock.available_memory().to_string(),
    );
    system_information.insert(MEMORY_TOTAL.into(), system_lock.total_memory().to_string());
    system_information.insert(MEMORY_USED.into(), system_lock.used_memory().to_string());
}
```

**File:** crates/aptos-telemetry/src/system_information.rs (L157-162)
```rust
    utils::insert_optional_value(
        system_information,
        SYSTEM_HOST_NAME,
        system.lock().host_name(),
    );
    utils::insert_optional_value(
```

**File:** crates/aptos-telemetry/src/constants.rs (L38-38)
```rust
pub(crate) const NODE_SYS_INFO_FREQ_SECS: u64 = 5 * 60; // 5 minutes
```

**File:** crates/aptos-telemetry/src/service.rs (L43-47)
```rust
static TELEMETRY_TOKEN: Lazy<String> = Lazy::new(|| {
    let mut rng = OsRng;
    let token = rng.r#gen::<u32>();
    format!("TOKEN_{:?}", token)
});
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

**File:** crates/aptos-telemetry/src/service.rs (L432-442)
```rust
pub(crate) async fn prepare_and_send_telemetry_event(
    peer_id: String,
    chain_id: String,
    telemetry_sender: Option<TelemetrySender>,
    telemetry_event: TelemetryEvent,
) -> JoinHandle<()> {
    // Update the telemetry event with the ip address and random token
    let TelemetryEvent { name, mut params } = telemetry_event;
    params.insert(TELEMETRY_TOKEN_KEY.to_string(), TELEMETRY_TOKEN.clone());
    params.insert(CHAIN_ID_KEY.into(), chain_id);
    let telemetry_event = TelemetryEvent { name, params };
```
