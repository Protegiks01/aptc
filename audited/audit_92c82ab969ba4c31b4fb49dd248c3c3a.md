# Audit Report

## Title
Botnet Can Bypass Per-IP Rate Limiting to Drain Faucet Token Supply via Distributed Requests

## Summary
The Aptos faucet implements rate limiting exclusively on a per-IP basis with no global token distribution limits. A botnet with thousands of unique IP addresses can bypass these controls by distributing requests across many IPs, each staying within the per-IP daily limit while collectively overwhelming the faucet's token supply.

## Finding Description
The faucet's rate limiting mechanisms (`MemoryRatelimitChecker` and `RedisRatelimitChecker`) only enforce limits on a per-IP basis. There is no aggregate control to limit total token distribution across all requesters. [1](#0-0) 

The `MemoryRatelimitChecker` checks if a specific IP has exceeded `max_requests_per_day`, but never validates against a global limit. Each unique IP can request tokens up to the daily limit independently. [2](#0-1) 

The `RedisRatelimitChecker` has the same limitation - it only checks the limit for the specific key (IP address or JWT) without any global aggregation. [3](#0-2) 

Each request can mint up to `amount_to_fund` tokens (default 100 APT or 100,000,000,000 OCTA).

Additionally, the `MemoryRatelimitChecker` uses an LRU cache: [4](#0-3) 

When the cache reaches its maximum size (default 1,000,000 entries), the oldest entries are evicted. If a botnet uses more than 1,000,000 unique IPs, previously evicted IPs can request tokens again.

**Attack Scenario:**
1. Attacker controls a botnet with 10,000 unique IP addresses
2. Faucet configured with `max_requests_per_day = 3` per IP
3. Each request mints 100 APT
4. Total tokens drained: 10,000 IPs × 3 requests/day × 100 APT = **3,000,000 APT per day**

The concurrent requests semaphore only controls parallel processing, not total volume: [5](#0-4) 

## Impact Explanation
This is a **High Severity** issue under the Aptos bug bounty criteria because it allows unauthorized drainage of faucet token supply, constituting "Limited funds loss or manipulation" that could require operational intervention. While the faucet is an auxiliary service rather than a core blockchain component, successful exploitation can:

- Deplete testnet/devnet token reserves, disrupting developer workflows
- Force operational intervention to refill or reconfigure the faucet
- Create significant service degradation for legitimate users

However, this does NOT reach Critical severity because it does not affect consensus, validator operations, or mainnet funds.

## Likelihood Explanation
**Likelihood: High**

- Botnets with thousands of unique IPs are readily available
- No authentication or proof-of-work is required beyond basic IP-based rate limiting
- Attack is simple to execute and requires no blockchain expertise
- Attack can be automated and run continuously

## Recommendation
Implement global rate limiting in addition to per-IP limits:

1. **Add global token distribution tracking** - Track total tokens distributed across all IPs within a time window
2. **Implement tiered limits** - Set both per-IP and global daily/hourly caps
3. **Add anomaly detection** - Monitor for distributed request patterns indicative of botnet activity
4. **Require additional verification** - Consider CAPTCHA, proof-of-work, or account registration for higher amounts

Example code structure to add global limiting to `MemoryRatelimitChecker`:

```rust
pub struct MemoryRatelimitChecker {
    pub max_requests_per_day: u32,
    pub max_global_requests_per_day: Option<u64>, // NEW: global limit
    pub global_requests_today: AtomicU64,          // NEW: global counter
    pub ip_to_requests_today: Mutex<LruCache<IpAddr, u32>>,
    pub current_day: AtomicU64,
}
```

## Proof of Concept

```rust
// Simulated botnet attack demonstration
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn test_botnet_bypass_ratelimit() {
    // Configure faucet with max_requests_per_day = 3
    let checker = MemoryRatelimitChecker::new(MemoryRatelimitCheckerConfig {
        max_requests_per_day: 3,
        max_entries_in_map: NonZeroUsize::new(1000000).unwrap(),
    });
    
    // Simulate 10,000 unique IPs from a botnet
    let num_botnet_ips = 10_000;
    let mut total_successful_requests = 0;
    
    for i in 0..num_botnet_ips {
        let botnet_ip = IpAddr::V4(Ipv4Addr::new(
            (i / 65536) as u8,
            ((i / 256) % 256) as u8,
            (i % 256) as u8,
            1,
        ));
        
        // Each IP makes 3 requests (at the limit)
        for _ in 0..3 {
            let checker_data = CheckerData {
                source_ip: botnet_ip,
                receiver: AccountAddress::random(),
                headers: Arc::new(HeaderMap::new()),
                time_request_received_secs: get_current_time_secs(),
            };
            
            let result = checker.check(checker_data, false).await;
            if result.unwrap().is_empty() {
                total_successful_requests += 1;
            }
        }
    }
    
    // Attacker successfully made 30,000 requests despite per-IP limiting
    assert_eq!(total_successful_requests, 30_000);
    println!("Botnet successfully made {} requests, each minting 100 APT", 
             total_successful_requests);
    println!("Total tokens drained: {} APT", total_successful_requests * 100);
}
```

## Notes
This vulnerability specifically affects the faucet service's ability to fairly distribute tokens. While not a core consensus or blockchain security issue, it represents a significant operational risk for networks relying on faucets for token distribution to developers and users. The fix should balance preventing abuse while maintaining accessibility for legitimate users.

### Citations

**File:** aptos-core-065/crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L19-37)
```rust

```

**File:** aptos-core-065/crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L75-88)
```rust

```

**File:** aptos-core-065/crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L207-221)
```rust

```

**File:** aptos-core-065/crates/aptos-faucet/core/src/funder/mint.rs (L540-550)
```rust

```

**File:** aptos-core-065/crates/aptos-faucet/core/src/endpoints/fund.rs (L204-215)
```rust

```
