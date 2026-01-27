# Audit Report

## Title
Validator Identity Exposure Through Public /info API Endpoint

## Summary
The publicly accessible `/v1/info` endpoint, documented in the OpenAPI specification, exposes validator network peer IDs when the API is enabled on validator nodes. This allows attackers to identify which public API endpoints belong to actual validators versus full nodes, enabling targeted reconnaissance and potential follow-on attacks. [1](#0-0) 

## Finding Description
The `/info` endpoint unconditionally includes `validator_network_peer_id` in its response when the node configuration contains a `validator_network` section. This endpoint is part of the `BasicApi` which is included in the OpenAPI service and documented in the public specification. [2](#0-1) 

The vulnerability chain is:

1. **Validator nodes have API enabled by default** - The default validator configuration enables the public API: [3](#0-2) 

2. **The /info endpoint is publicly documented** - It appears in the OpenAPI spec served by `spec_endpoint_json()`: [4](#0-3) 

3. **Validator peer IDs are exposed** - The endpoint reveals both validator and full node network peer IDs: [5](#0-4) 

An attacker can:
- Query `/v1/info` on any public API endpoint
- Check for the presence of `validator_network_peer_id` field
- Identify which endpoints belong to actual validators
- Map the validator network topology
- Use configuration details (state sync mode, indexer settings) to understand attack surface

**Note**: The spec endpoint correctly excludes admin service endpoints like `/set_failpoint`, `/profilez`, and `/debug/*` routes. However, the issue is that a legitimately public endpoint exposes sensitive validator identity information. [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **Low Severity** per Aptos Bug Bounty criteria ("Minor information leaks"). While it enables validator identification and network reconnaissance, it does not directly cause:
- Consensus violations or safety breaks
- Fund theft or manipulation  
- Node crashes or liveness failures
- Direct protocol violations

However, the exposed information could facilitate more sophisticated attacks if combined with other vulnerabilities, and undermines the operational security principle that validators should not be easily distinguishable from full nodes at the API level.

## Likelihood Explanation
**Very High Likelihood**:
- The endpoint is publicly accessible with no authentication
- Documented in the OpenAPI specification  
- Validator nodes have API enabled by default in reference configurations
- Exploitation requires only a simple HTTP GET request
- No special privileges or complex attack chain needed

## Recommendation
Implement conditional filtering of validator-specific information from the `/info` endpoint based on node type or configuration:

**Option 1**: Only expose `validator_network_peer_id` if explicitly configured for monitoring/debugging purposes (disabled by default).

**Option 2**: Remove validator network information entirely from the public `/info` endpoint and create a separate authenticated admin endpoint for operational monitoring.

**Option 3**: Add a configuration flag to control information disclosure levels in the API, defaulting to minimal disclosure for production validator nodes.

Example fix for `api/src/basic.rs`:
```rust
// Insert node identity information only if not a validator or if explicitly allowed
if let Some(validator_network) = &self.context.node_config.validator_network {
    // Only expose validator peer ID if explicitly configured for public exposure
    if self.context.node_config.api.expose_validator_info.unwrap_or(false) {
        info.insert(
            "validator_network_peer_id".to_string(),
            serde_json::to_value(validator_network.peer_id()).unwrap(),
        );
    }
}
```

## Proof of Concept
```bash
# Query a validator node's API endpoint
curl http://<validator-api-endpoint>/v1/info

# Response includes validator identification:
{
  "validator_network_peer_id": "0x1234...",  # Validator identified!
  "fullnode_network_peer_id_vfn": "0x5678...",
  "bootstrapping_mode": "...",
  "new_storage_format": true,
  "internal_indexer_config": {...}
}

# Query a full node's API endpoint  
curl http://<fullnode-api-endpoint>/v1/info

# Response lacks validator_network_peer_id field:
{
  "fullnode_network_peer_id_public": "0xabcd...",
  "bootstrapping_mode": "...",
  # No validator_network_peer_id - this is a full node
}

# Attacker can systematically identify all validators by:
# 1. Discovering public API endpoints (DNS enumeration, network scanning)
# 2. Querying /v1/info on each endpoint
# 3. Filtering for responses containing validator_network_peer_id
# 4. Building a map of validator identities and configurations
```

## Notes
While the spec endpoint (`spec_endpoint_json()`) correctly excludes administrative and debug endpoints from public documentation, it includes the `/info` endpoint which leaks validator identity information. The root cause is not improper spec generation, but rather that a legitimate public endpoint exposes more information than appropriate for production validator deployments.

### Citations

**File:** api/src/basic.rs (L119-131)
```rust
        // Insert node identity information
        if let Some(validator_network) = &self.context.node_config.validator_network {
            info.insert(
                "validator_network_peer_id".to_string(),
                serde_json::to_value(validator_network.peer_id()).unwrap(),
            );
        }
        for fullnode_network in &self.context.node_config.full_node_networks {
            info.insert(
                format!("fullnode_network_peer_id_{}", fullnode_network.network_id),
                serde_json::to_value(fullnode_network.peer_id()).unwrap(),
            );
        }
```

**File:** api/src/runtime.rs (L109-163)
```rust
pub fn get_api_service(
    context: Arc<Context>,
) -> OpenApiService<
    (
        AccountsApi,
        BasicApi,
        BlocksApi,
        EventsApi,
        IndexApi,
        StateApi,
        TransactionsApi,
        ViewFunctionApi,
    ),
    (),
> {
    // These APIs get merged.
    let apis = (
        AccountsApi {
            context: context.clone(),
        },
        BasicApi {
            context: context.clone(),
        },
        BlocksApi {
            context: context.clone(),
        },
        EventsApi {
            context: context.clone(),
        },
        IndexApi {
            context: context.clone(),
        },
        StateApi {
            context: context.clone(),
        },
        TransactionsApi {
            context: context.clone(),
        },
        ViewFunctionApi { context },
    );

    let version = VERSION.to_string();
    let license =
        LicenseObject::new("Apache 2.0").url("https://www.apache.org/licenses/LICENSE-2.0.html");
    let contact = ContactObject::new()
        .name("Aptos Labs")
        .url("https://github.com/aptos-labs/aptos-core");

    OpenApiService::new(apis, "Aptos Node API", version.trim())
        .server("/v1")
        .description("The Aptos Node API is a RESTful API for client applications to interact with the Aptos blockchain.")
        .license(license)
        .contact(contact)
        .external_document("https://github.com/aptos-labs/aptos-core")
}
```

**File:** api/src/runtime.rs (L246-251)
```rust
                    // TODO: We add this manually outside of the OpenAPI spec for now.
                    // https://github.com/poem-web/poem/issues/364
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
```

**File:** config/src/config/test_data/validator.yaml (L80-81)
```yaml
api:
    enabled: true
```

**File:** api/doc/spec.json (L2505-2525)
```json
    "/info": {
      "get": {
        "tags": [
          "General"
        ],
        "summary": "Show some basic info of the node.",
        "responses": {
          "200": {
            "description": "",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "additionalProperties": {}
                }
              }
            }
          }
        },
        "operationId": "info"
      }
```
