# Audit Report

## Title
Information Disclosure via Unsanitized Metric Label Values in JSON Encoder

## Summary
The `flatten_metric_with_labels()` function in the inspection service's JSON encoder concatenates metric label values into metric names without sanitization, causing sensitive operational data (IP addresses, hostnames, node identifiers) to leak through the unauthenticated `/json_metrics` endpoint.

## Finding Description
The `flatten_metric_with_labels()` function processes Prometheus metrics by extracting label values and joining them with dot separators to create flat metric names for JSON export. [1](#0-0) 

The function performs no sanitization or filtering of label values before concatenation. Several components in the Aptos codebase use sensitive information as metric labels:

1. **Hostnames**: The `BasicNodeInfoCollector` retrieves the system hostname and uses it as a metric label value. [2](#0-1) 

2. **Socket Addresses**: The gRPC network service uses socket addresses (containing IP:port) as label values in the `NETWORK_HANDLER_TIMER` metric. [3](#0-2) [4](#0-3) 

3. **Peer IDs**: Network counters extensively use peer IDs as label values throughout the networking layer. [5](#0-4) 

The `/json_metrics` endpoint is always accessible without authentication or authorization checks. [6](#0-5) 

The inspection service binds to `0.0.0.0` by default, making it accessible from any network interface. [7](#0-6) 

**Exploitation Path:**
1. Attacker sends HTTP GET request to `http://[validator-node]:9101/json_metrics`
2. JsonEncoder processes all registered metrics via `flatten_metric_with_labels()`
3. Sensitive label values (hostnames, IPs, peer IDs) are concatenated into metric names
4. Response includes entries like: `node_hostname.validator-prod-01.internal.example.com: 1.0` or `network_handler_timer.10.0.1.50:8080.inbound_msgs: 0.023`
5. Attacker obtains internal infrastructure details

## Impact Explanation
According to the Aptos bug bounty severity categories, this qualifies as **Low Severity** - "Minor information leaks" (up to $1,000). [8](#0-7) 

The leaked information includes operational infrastructure details but does not directly enable:
- Loss of funds or asset theft
- Consensus safety violations
- State corruption or manipulation
- Validator or network unavailability

However, the disclosed information could facilitate reconnaissance for secondary attacks such as targeted DDoS, network penetration attempts, or social engineering against specific validators.

## Likelihood Explanation
**Likelihood: HIGH**
- The endpoint is exposed by default without authentication
- Exploitation requires only a single HTTP GET request
- All nodes running the inspection service are affected
- No special privileges or insider access required

## Recommendation
Implement label value sanitization in `flatten_metric_with_labels()` to redact or hash sensitive information:

```rust
fn flatten_metric_with_labels(name: &str, metric: &Metric) -> String {
    let name_string = String::from(name);
    if metric.get_label().is_empty() {
        return name_string;
    }

    // Sanitize label values to prevent sensitive data leakage
    let values: Vec<String> = metric
        .get_label()
        .iter()
        .map(|label| sanitize_label_value(label.get_name(), label.get_value()))
        .filter(|x| !x.is_empty())
        .collect();
    
    if values.is_empty() {
        return name_string;
    }
    
    format!("{}.{}", name_string, values.join("."))
}

fn sanitize_label_value(label_name: &str, value: &str) -> String {
    match label_name {
        "hostname" | "node_addr" | "remote_peer_id" => {
            // Hash or redact sensitive labels
            format!("redacted_{}", &sha256(value)[..8])
        },
        _ => value.to_string()
    }
}
```

Additionally, consider implementing authentication for the metrics endpoints or restricting them to localhost only by default.

## Proof of Concept
```bash
# Query the inspection service JSON metrics endpoint
curl http://[validator-node-ip]:9101/json_metrics | jq .

# Expected output reveals sensitive information:
# {
#   "node_hostname.validator-prod-01.internal.example.com": 1.0,
#   "network_handler_timer.10.0.1.50:8080.inbound_msgs": 0.023,
#   "aptos_network_peer_connected.validator.vfn.abc123.def456": 1.0
# }
```

**Notes:**

While this vulnerability represents a valid information disclosure issue, it does **not** meet the strict validation criteria requiring demonstration of harm to funds, consensus, or availability, nor does it violate any of the documented critical invariants. Under the Aptos bug bounty program, this would be categorized as **Low Severity** rather than Medium, as it constitutes a "minor information leak" that does not directly compromise blockchain security guarantees.

### Citations

**File:** aptos-core-082/crates/aptos-inspection-service/src/server/json_encoder.rs (L97-120)
```rust

```

**File:** aptos-core-082/crates/node-resource-metrics/src/collectors/basic_node_info_collector.rs (L75-81)
```rust

```

**File:** aptos-core-082/secure/net/src/grpc_network_service/mod.rs (L25-28)
```rust

```

**File:** aptos-core-082/secure/net/src/grpc_network_service/mod.rs (L97-99)
```rust

```

**File:** aptos-core-082/network/framework/src/counters.rs (L95-106)
```rust

```

**File:** aptos-core-082/crates/aptos-inspection-service/src/server/mod.rs (L137-141)
```rust

```

**File:** aptos-core-082/config/src/config/inspection_service_config.rs (L26-37)
```rust

```
