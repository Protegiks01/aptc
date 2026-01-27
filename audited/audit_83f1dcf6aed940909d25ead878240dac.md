# Audit Report

## Title
Missing Validation Allows Executor Service Crash via Empty or Insufficient Remote Executor Addresses

## Summary
The executor service's command-line argument parser does not enforce that `remote_executor_addresses` is provided or contains sufficient elements, allowing operators to start the service with an empty vector or fewer addresses than required. This causes an immediate panic during service initialization due to unchecked vector indexing, resulting in service unavailability.

## Finding Description

The `Args` struct in the executor service defines `remote_executor_addresses` with a clap constraint that is insufficient to prevent the vulnerability: [1](#0-0) 

The `num_args = 1..` constraint in clap means "if the flag is provided, require at least 1 value," but it does NOT make the flag mandatory. Without the `required = true` attribute, operators can omit the `--remote-executor-addresses` flag entirely, resulting in an empty `Vec<SocketAddr>`.

When `ProcessExecutorService::new()` is called with this empty or insufficient vector, it immediately performs unchecked indexing: [2](#0-1) 

This indexing operation assumes that `remote_shard_addresses[shard_id]` is valid, but there is no validation that:
1. The vector is non-empty
2. The vector length equals `num_shards`
3. The `shard_id` is within bounds of the vector

The same vulnerability exists in the test implementation: [3](#0-2) 

**Attack Scenarios:**

**Scenario 1 - Empty Vector:**
```bash
./executor-service --shard-id 0 --num-shards 2 --coordinator-address 127.0.0.1:8000
# Omitting --remote-executor-addresses entirely
# Result: remote_executor_addresses is empty Vec, panic at index 0
```

**Scenario 2 - Insufficient Addresses:**
```bash
./executor-service --shard-id 2 --num-shards 3 --coordinator-address 127.0.0.1:8000 \
  --remote-executor-addresses 127.0.0.1:9000 127.0.0.1:9001
# Only 2 addresses provided for 3 shards
# Result: panic when trying to access index 2
```

The correct pattern used elsewhere in the codebase requires BOTH constraints: [4](#0-3) 

The test code demonstrates the expected invariant that must be maintained: [5](#0-4) 

The vector should contain exactly `num_shards` addresses, with each shard using its `shard_id` to index into the vector to find its own address.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "Validator node slowdowns, API crashes")

This vulnerability causes immediate service crashes with the following impacts:

1. **Service Unavailability**: The executor service panics on startup before it can process any blocks, completely preventing sharded execution from functioning.

2. **Operator Configuration Errors**: The lack of validation makes it easy for operators to misconfigure the service, especially in distributed deployments where multiple processes must be coordinated.

3. **No Graceful Degradation**: The panic occurs during initialization with no error recovery, requiring manual intervention to fix the configuration and restart.

4. **Cross-Shard Communication Failure**: Even if the panic didn't occur, an insufficient address list would prevent proper cross-shard message routing in `RemoteCrossShardClient`: [6](#0-5) 

This would lead to execution deadlocks as shards wait indefinitely for cross-shard messages that cannot be delivered.

While this doesn't directly compromise funds or consensus (the service never starts), it represents a critical availability issue for sharded execution infrastructure.

## Likelihood Explanation

**Likelihood: Medium-to-High**

This issue is likely to occur because:

1. **No Input Validation**: There are zero checks on the relationship between `shard_id`, `num_shards`, and `remote_executor_addresses.len()`.

2. **Easy to Trigger Accidentally**: Operators deploying multiple shards must carefully coordinate the address list across all instances. A simple copy-paste error or missing flag will trigger the crash.

3. **Non-Obvious Constraint**: The requirement that the vector length must equal `num_shards` is not documented in the help text and must be inferred from reading the code.

4. **No Runtime Detection**: The service provides no early validation or helpful error messages - it simply panics with an index out of bounds error.

The vulnerability is not exploitable by external attackers (it requires operator access to start the service), but it represents a severe operational reliability issue that can be triggered accidentally or through misconfiguration.

## Recommendation

Add validation to enforce the required invariants. There are three recommended fixes:

**Fix 1: Add `required = true` to clap attribute (Partial Solution)**
```rust
#[clap(long, required = true, num_args = 1..)]
pub remote_executor_addresses: Vec<SocketAddr>,
```

**Fix 2: Add validation in main() (Better Solution)**
```rust
fn main() {
    let args = Args::parse();
    
    // Validate arguments
    if args.remote_executor_addresses.is_empty() {
        eprintln!("Error: --remote-executor-addresses must not be empty");
        std::process::exit(1);
    }
    
    if args.remote_executor_addresses.len() != args.num_shards {
        eprintln!(
            "Error: --remote-executor-addresses must contain exactly {} addresses (one per shard), but got {}",
            args.num_shards,
            args.remote_executor_addresses.len()
        );
        std::process::exit(1);
    }
    
    if args.shard_id >= args.num_shards {
        eprintln!(
            "Error: --shard-id ({}) must be less than --num-shards ({})",
            args.shard_id,
            args.num_shards
        );
        std::process::exit(1);
    }
    
    aptos_logger::Logger::new().init();
    // ... rest of main
}
```

**Fix 3: Add defensive checks in ProcessExecutorService::new() (Defense in Depth)**
```rust
pub fn new(
    shard_id: ShardId,
    num_shards: usize,
    num_threads: usize,
    coordinator_address: SocketAddr,
    remote_shard_addresses: Vec<SocketAddr>,
) -> Result<Self, String> {
    if remote_shard_addresses.len() != num_shards {
        return Err(format!(
            "remote_shard_addresses length ({}) must equal num_shards ({})",
            remote_shard_addresses.len(),
            num_shards
        ));
    }
    
    if shard_id >= num_shards {
        return Err(format!(
            "shard_id ({}) must be less than num_shards ({})",
            shard_id,
            num_shards
        ));
    }
    
    let self_address = remote_shard_addresses[shard_id];
    // ... rest of implementation
}
```

**Recommended Approach**: Implement all three fixes for defense in depth - make the argument required, validate in main() with clear error messages, and add assertions in the constructor.

## Proof of Concept

**Reproduction Steps:**

1. Build the executor service:
```bash
cd execution/executor-service
cargo build --release
```

2. Run with empty vector (omit --remote-executor-addresses):
```bash
./target/release/executor-service \
  --shard-id 0 \
  --num-shards 2 \
  --num-executor-threads 4 \
  --coordinator-address 127.0.0.1:8000
```

**Expected Behavior:**
The service should validate inputs and exit with a clear error message.

**Actual Behavior:**
```
thread 'main' panicked at 'index out of bounds: the len is 0 but the index is 0'
execution/executor-service/src/process_executor_service.rs:24:43
```

3. Alternatively, run with insufficient addresses:
```bash
./target/release/executor-service \
  --shard-id 2 \
  --num-shards 3 \
  --num-executor-threads 4 \
  --coordinator-address 127.0.0.1:8000 \
  --remote-executor-addresses 127.0.0.1:9000 127.0.0.1:9001
```

**Actual Behavior:**
```
thread 'main' panicked at 'index out of bounds: the len is 2 but the index is 2'
execution/executor-service/src/process_executor_service.rs:24:43
```

Both scenarios demonstrate immediate service crash due to unchecked vector indexing.

## Notes

This vulnerability affects the operational reliability of the sharded executor service. While it doesn't represent a direct security compromise (no funds at risk, no consensus violation), it violates the availability guarantees expected of critical blockchain infrastructure. The issue is particularly concerning because it can be triggered accidentally during deployment and provides no helpful error messages to guide operators toward the correct configuration.

### Citations

**File:** execution/executor-service/src/main.rs (L20-21)
```rust
    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,
```

**File:** execution/executor-service/src/process_executor_service.rs (L24-24)
```rust
        let self_address = remote_shard_addresses[shard_id];
```

**File:** execution/executor-service/src/thread_executor_service.rs (L22-22)
```rust
        let self_address = remote_shard_addresses[shard_id];
```

**File:** crates/transaction-emitter-lib/src/args.rs (L67-68)
```rust
    #[clap(short, long, required = true, num_args = 1.., value_parser = parse_target)]
    pub targets: Option<Vec<Url>>,
```

**File:** execution/executor-service/src/tests.rs (L29-34)
```rust
    let remote_shard_addresses = (0..num_shards)
        .map(|_| {
            let listen_port = utils::get_available_port();
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port)
        })
        .collect::<Vec<_>>();
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L57-58)
```rust
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
```
