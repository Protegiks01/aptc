# Audit Report

## Title
Unbounded Aggregate Memory Consumption in Concurrent Resource Viewing Can Crash Validator Nodes

## Summary
The `DEFAULT_LIMIT` of 100MB in move-resource-viewer is designed to prevent individual resource queries from consuming excessive memory. However, this limit only tracks metadata costs (type names, field names) and does not account for actual data allocations in `AnnotatedMoveValue` structures. With validator nodes running API servers by default and allowing up to 64 concurrent blocking requests, aggregate memory consumption from concurrent resource annotation operations can exceed node capacity and cause validator crashes.

## Finding Description

The vulnerability exists in the interaction between the resource viewing system and API concurrency controls. The security guarantee being broken is **Resource Limits** (invariant #9): "All operations must respect gas, storage, and computational limits." [1](#0-0) 

The `Limiter` mechanism charges costs only for metadata elements: [2](#0-1) [3](#0-2) 

However, actual resource data allocations are not counted against this limit. When annotating vectors and nested structures, the system allocates memory proportional to the serialized data size: [4](#0-3) 

Each API request to view account resources creates a **new Limiter for each resource**: [5](#0-4) [6](#0-5) 

The API server uses `api_spawn_blocking` which is limited to 64 concurrent blocking threads: [7](#0-6) [8](#0-7) 

Most critically, **validator nodes run the API server by default**: [9](#0-8) 

The default page size allows processing up to 9,999 resources per request: [10](#0-9) 

**Attack propagation:**
1. Attacker identifies accounts with multiple resources or resources containing large serialized data
2. Sends 64 concurrent `GET /accounts/{address}/resources` requests to a validator's API endpoint
3. Each request invokes `api_spawn_blocking` → `Account::resources()` → `try_into_resources()`
4. For each resource, `view_resource()` deserializes and annotates the data, creating `AnnotatedMoveValue` structures
5. Large `Vec<u8>` fields and nested structures allocate memory not tracked by the 100MB limiter
6. With up to 9,999 resources × 64 concurrent threads, aggregate memory usage is unbounded
7. Node exhausts available memory and crashes or is OOM-killed

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos Bug Bounty program: "Validator node slowdowns" and "API crashes."

Memory exhaustion on validator nodes has severe consequences:
- **Validator crashes**: Nodes become unavailable, reducing network resilience
- **Consensus disruption**: If multiple validators crash simultaneously, the network may experience liveness issues
- **Coordinated attack**: An attacker can target multiple validators to approach the 1/3 Byzantine threshold
- **Service degradation**: Even without complete crashes, memory pressure causes severe performance degradation

While individual resource writes are limited to 1MB by storage constraints, the annotation process can significantly expand this through:
- Recursive structure traversal creating intermediate objects
- Type metadata and field name allocations for each nested level
- Vector element annotation allocating per-element wrappers

## Likelihood Explanation

This vulnerability is **highly likely** to be exploitable:

**Attacker Requirements (Low Barrier):**
- No special privileges needed—only HTTP access to validator API
- API endpoints are publicly accessible on validators by default
- No authentication or rate limiting at the application level shown in code
- Attack requires only standard HTTP clients

**Exploitation Complexity (Low):**
- Simple to execute: send concurrent GET requests
- No need to craft special transactions or bypass security checks
- Resources with large data fields exist naturally on-chain (NFT metadata, large vectors)
- Default configuration enables the attack surface

**Detection Difficulty (High):**
- Appears as legitimate API usage
- Memory exhaustion may be attributed to normal load
- No obvious attack signature in logs

## Recommendation

Implement aggregate memory limits across concurrent API requests:

1. **Add per-endpoint concurrency semaphores** similar to the faucet implementation:
   - Create a semaphore limiting concurrent resource viewing operations
   - Reject requests with 503 Service Unavailable when limit reached

2. **Implement true memory accounting in Limiter**:
   - Track actual allocated bytes, not just metadata
   - Charge for Vec<u8> data, nested structure allocations
   - Enforce limit before allocations, not after

3. **Add API-level rate limiting**:
   - Implement per-IP request rate limits
   - Add exponential backoff for repeated requests

4. **Consider disabling API on validators by default**:
   - Validators should focus on consensus
   - Delegate API serving to dedicated fullnodes
   - Update default configs to set `api.enabled: false` for validator role

**Code Fix Example** (conceptual):
```rust
// In api/src/context.rs
pub struct Context {
    // ... existing fields
    pub resource_viewing_semaphore: Arc<tokio::sync::Semaphore>,
}

// In api/src/accounts.rs
async fn get_account_resources(...) -> BasicResultWith404<Vec<MoveResource>> {
    let _permit = self.context.resource_viewing_semaphore
        .acquire()
        .await
        .map_err(|_| ServiceUnavailableError::new("Resource viewing capacity exceeded"))?;
    
    // ... rest of implementation
}
```

## Proof of Concept

```rust
// Reproduction steps (requires running validator node with API enabled)

use reqwest;
use tokio;

#[tokio::main]
async fn main() {
    let validator_api = "http://validator-node:8080";
    
    // Find an account with many resources or large data
    let target_account = "0x1"; // Or any account with significant resources
    
    // Launch 64 concurrent requests
    let mut handles = vec![];
    for i in 0..64 {
        let api = validator_api.to_string();
        let account = target_account.to_string();
        
        handles.push(tokio::spawn(async move {
            let url = format!("{}/v1/accounts/{}/resources", api, account);
            let resp = reqwest::get(&url).await;
            println!("Request {}: {:?}", i, resp.is_ok());
        }));
    }
    
    // Wait for all requests
    for h in handles {
        let _ = h.await;
    }
    
    // Monitor validator node memory usage during this test
    // Expected: Significant memory spike, potential OOM
}
```

**Observable Impact:**
1. Monitor validator node memory with `top` or `htop`
2. Memory usage spikes significantly during concurrent requests
3. With sufficient resource data, node may crash or be OOM-killed
4. Validator becomes unavailable, affecting consensus participation

### Citations

**File:** third_party/move/tools/move-resource-viewer/src/limit.rs (L7-8)
```rust
// Default limit set to 100mb per query.
const DEFAULT_LIMIT: usize = 100_000_000;
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L336-342)
```rust
    pub fn view_resource(
        &self,
        tag: &StructTag,
        blob: &[u8],
    ) -> anyhow::Result<AnnotatedMoveStruct> {
        self.view_resource_with_limit(tag, blob, &mut Limiter::default())
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L472-474)
```rust
        limit.charge(std::mem::size_of::<AccountAddress>())?;
        limit.charge(module_name.as_bytes().len())?;
        limit.charge(name.as_bytes().len())?;
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L743-746)
```rust
            limit.charge(name.as_bytes().len())?;
        }
        for name in field_names.iter() {
            limit.charge(name.as_bytes().len())?;
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L901-915)
```rust
            (MoveValue::Vector(a), FatType::Vector(ty)) => match ty.as_ref() {
                FatType::U8 => AnnotatedMoveValue::Bytes(
                    a.iter()
                        .map(|v| match v {
                            MoveValue::U8(i) => Ok(*i),
                            _ => Err(anyhow!("unexpected value type")),
                        })
                        .collect::<anyhow::Result<_>>()?,
                ),
                _ => AnnotatedMoveValue::Vector(
                    ty.type_tag(limit).unwrap(),
                    a.iter()
                        .map(|v| self.annotate_value(v, ty.as_ref(), limit))
                        .collect::<anyhow::Result<_>>()?,
                ),
```

**File:** api/types/src/convert.rs (L85-91)
```rust
    pub fn try_into_resources<'b>(
        &self,
        data: impl Iterator<Item = (StructTag, &'b [u8])>,
    ) -> Result<Vec<MoveResource>> {
        data.map(|(typ, bytes)| self.inner.view_resource(&typ, bytes)?.try_into())
            .collect()
    }
```

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

**File:** api/src/context.rs (L1645-1654)
```rust
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L40-42)
```yaml
api:
  enabled: true
  address: "0.0.0.0:8080"
```

**File:** config/src/config/api_config.rs (L100-100)
```rust
const DEFAULT_MAX_ACCOUNT_RESOURCES_PAGE_SIZE: u16 = 9999;
```
