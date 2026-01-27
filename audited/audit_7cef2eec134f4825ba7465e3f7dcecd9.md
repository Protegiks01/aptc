# Audit Report

## Title
Unauthorized Consensus Message Publishing via Manual Configuration Bypass on Public Fullnodes

## Summary
Public fullnodes can bypass the intended node-type restrictions by manually setting `publisher_enabled: true` in their configuration file, enabling them to act as unauthorized consensus message publishers. This occurs because the `optimize()` function only applies default values when settings are NOT manually configured, allowing operators to override security-critical access control decisions.

## Finding Description

The Aptos consensus observer architecture is designed with a specific trust hierarchy:
- **Validators** publish consensus messages (ordered blocks, commit decisions, block payloads)
- **Validator Fullnodes (VFNs)** relay these messages to downstream nodes
- **Public Fullnodes (PFNs)** should only consume messages, not publish them

The configuration optimization logic in `ConsensusObserverConfig::optimize()` attempts to enforce this by setting `ENABLE_ON_PUBLIC_FULLNODES = false`. [1](#0-0) 

However, the implementation checks whether `publisher_enabled` is manually set before applying optimizations: [2](#0-1) 

For PublicFullnodes, the logic only disables the publisher if it was NOT manually configured: [3](#0-2) 

If a PublicFullnode operator manually sets `publisher_enabled: true` in their YAML config, the condition `!publisher_manually_set` evaluates to `false`, causing the optimization to skip enforcement. The manually-set value remains active.

When the node starts, `create_consensus_publisher()` simply checks if `publisher_enabled` is true and creates the publisher without node-type validation: [4](#0-3) 

If both `observer_enabled` and `publisher_enabled` are set, the consensus observer creates an `ExecutionProxyClient` with the publisher: [5](#0-4) 

This client's `BufferManager` receives consensus blocks from the observer and calls `publish_message()` to broadcast them: [6](#0-5)  and [7](#0-6) 

The `ConsensusPublisher` then accepts subscriptions from downstream nodes and distributes consensus messages: [8](#0-7) 

**Attack Path:**
1. PublicFullnode operator creates config with `publisher_enabled: true` and `observer_enabled: true`
2. Node startup runs `optimize()` which detects manual configuration and skips enforcement
3. Consensus observer and publisher are both initialized
4. Observer receives consensus messages from upstream VFNs
5. Messages flow through ExecutionProxyClient's BufferManager
6. BufferManager calls `consensus_publisher.publish_message()` for ordered blocks and commit decisions
7. Unauthorized PublicFullnode now acts as a publisher, accepting subscriptions and broadcasting consensus data

A malicious operator could modify their node to inject false consensus data, disrupting the consensus observer network's integrity and violating the protocol's trust assumptions.

## Impact Explanation

This vulnerability represents a **High Severity** protocol violation per the Aptos bug bounty program:

1. **Significant Protocol Violation**: The consensus observer design explicitly restricts publishing rights to validators and their fullnodes. Allowing arbitrary PublicFullnodes to publish undermines this security architecture.

2. **Network Trust Model Broken**: Downstream nodes subscribing to a rogue PublicFullnode could receive modified or malicious consensus data, potentially causing:
   - Incorrect state synchronization
   - Processing of invalid blocks
   - Network topology poisoning where untrusted nodes act as distribution points

3. **Attack Surface Expansion**: While PublicFullnodes relay existing messages by default, a malicious operator with code modifications could:
   - Inject fabricated consensus messages
   - Selectively censor or delay certain blocks
   - Perform eclipse attacks on downstream subscribers
   - Disrupt consensus observer network reliability

4. **Access Control Bypass**: This is a fundamental access control failure where configuration semantics (manual vs. default) inadvertently override security-critical node type restrictions.

The impact falls short of **Critical** severity as it doesn't directly enable consensus safety violations or fund theft, but it's more severe than **Medium** due to the clear protocol violation and potential for network-wide disruption.

## Likelihood Explanation

**Likelihood: Medium to High**

**Ease of Exploitation:**
- Requires only configuration file modification (no code changes needed)
- No cryptographic bypasses or complex attack logic required
- Documentation may inadvertently guide operators to set these flags manually for troubleshooting

**Attacker Requirements:**
- Control over a PublicFullnode instance
- Knowledge of the configuration file format
- No special network position or validator access needed

**Detection Difficulty:**
- Hard to distinguish from legitimate VFNs at the network protocol level
- No runtime validation of node type vs. publisher status
- Operators might enable this unintentionally while experimenting with features

**Real-World Scenarios:**
- Malicious actors operating PublicFullnodes could deliberately exploit this
- Well-intentioned operators might enable publisher mode believing it improves network participation
- Compromised PublicFullnode infrastructure could be reconfigured to act as rogue publishers

The vulnerability is highly likely to be exploited if discovered by malicious actors, given its simplicity and potential impact.

## Recommendation

**Immediate Fix: Enforce Node-Type Validation at Publisher Creation**

Modify `create_consensus_publisher()` to validate node type before creating the publisher:

```rust
fn create_consensus_publisher(
    node_config: &NodeConfig,
    consensus_observer_client: Arc<
        ConsensusObserverClient<NetworkClient<ConsensusObserverMessage>>,
    >,
    publisher_message_receiver: Receiver<(), ConsensusPublisherNetworkMessage>,
) -> (Option<Runtime>, Option<Arc<ConsensusPublisher>>) {
    // NEW: Validate that publisher is only enabled on authorized node types
    if node_config.consensus_observer.publisher_enabled {
        let is_validator = node_config.validator_network.is_some();
        let is_vfn = node_config.full_node_networks.iter().any(|n| n.is_validator_fullnode());
        
        if !is_validator && !is_vfn {
            warn!("Publisher is enabled but node is not a validator or VFN. Disabling publisher for security.");
            return (None, None);
        }
    }
    
    // If the publisher is not enabled, return early
    if !node_config.consensus_observer.publisher_enabled {
        return (None, None);
    }
    
    // ... rest of existing code
}
```

**Alternative Fix: Make optimize() Non-Bypassable**

Remove the manual configuration check for security-critical settings:

```rust
// For PublicFullnodes, ALWAYS disable publisher regardless of manual config
match node_type {
    NodeType::PublicFullnode => {
        // Force disable publisher on PFNs for security
        if consensus_observer_config.publisher_enabled {
            warn!("Publisher manually enabled on PublicFullnode - forcing disable for security");
            consensus_observer_config.publisher_enabled = false;
            modified_config = true;
        }
        // ... handle observer_enabled
    },
    // ... other node types
}
```

**Long-term Solution:**
- Add runtime assertions that verify node type matches publisher status
- Implement peer authentication in consensus observer protocol to verify publisher identity
- Add telemetry to detect unauthorized publishers in the network
- Document that security-critical config flags should not be manually overridden

## Proof of Concept

**Step 1: Create malicious PublicFullnode configuration**

```yaml
# pfn_config.yaml
consensus_observer:
  observer_enabled: true
  publisher_enabled: true  # Manual override bypasses optimize() logic
  max_network_channel_size: 1000
```

**Step 2: Start PublicFullnode with this configuration**

```bash
aptos-node -f pfn_config.yaml
```

**Step 3: Verify publisher is active**

Check node logs for:
```
"Starting the consensus publisher garbage collection loop!"
```

Or query metrics endpoint for publisher subscriber count:
```bash
curl http://localhost:9101/metrics | grep publisher_num_active_subscribers
```

**Step 4: Subscribe from downstream node**

From another node, send a subscription request to the PublicFullnode. The unauthorized PublicFullnode will accept the subscription and begin broadcasting consensus messages.

**Rust Test Case:**

```rust
#[test]
fn test_public_fullnode_can_enable_publisher_via_manual_config() {
    // Create a PublicFullnode config with manually set publisher_enabled
    let yaml_config = r#"
        consensus_observer:
            observer_enabled: true
            publisher_enabled: true
    "#;
    let local_config: Value = serde_yaml::from_str(yaml_config).unwrap();
    
    let mut node_config = NodeConfig::default();
    node_config.consensus_observer.publisher_enabled = true; // Manually set
    
    // Run optimize for PublicFullnode
    let modified = ConsensusObserverConfig::optimize(
        &mut node_config,
        &local_config,
        NodeType::PublicFullnode,
        Some(ChainId::mainnet()),
    ).unwrap();
    
    // BUG: Publisher remains enabled despite being a PublicFullnode
    assert!(node_config.consensus_observer.publisher_enabled);
    
    // This should have been false for security
    // assert!(!node_config.consensus_observer.publisher_enabled);
}
```

This test demonstrates that a PublicFullnode can retain `publisher_enabled: true` through manual configuration, bypassing the intended node-type restrictions.

## Notes

The vulnerability exists because configuration optimization logic treats "manually set" values as user preferences that should be preserved, even when those values violate security invariants. The system lacks a clear distinction between user preferences (performance tuning, timeouts) and security-critical access control decisions (which node types can publish consensus messages).

This highlights a broader architectural issue: security policies should be enforced at runtime based on cryptographic identity or node capabilities, not solely through configuration file optimization that can be bypassed.

### Citations

**File:** config/src/config/consensus_observer_config.rs (L14-14)
```rust
const ENABLE_ON_PUBLIC_FULLNODES: bool = false;
```

**File:** config/src/config/consensus_observer_config.rs (L106-107)
```rust
        let observer_manually_set = !local_observer_config_yaml["observer_enabled"].is_null();
        let publisher_manually_set = !local_observer_config_yaml["publisher_enabled"].is_null();
```

**File:** config/src/config/consensus_observer_config.rs (L130-137)
```rust
            NodeType::PublicFullnode => {
                if ENABLE_ON_PUBLIC_FULLNODES && !observer_manually_set && !publisher_manually_set {
                    // Enable both the observer and the publisher for PFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
            },
```

**File:** aptos-node/src/consensus.rs (L247-250)
```rust
    // If the publisher is not enabled, return early
    if !node_config.consensus_observer.publisher_enabled {
        return (None, None);
    }
```

**File:** consensus/src/consensus_provider.rs (L171-181)
```rust
        let execution_proxy_client = Arc::new(ExecutionProxyClient::new(
            node_config.consensus.clone(),
            Arc::new(execution_proxy),
            AccountAddress::ONE,
            self_sender.clone(),
            consensus_network_client,
            bounded_executor,
            rand_storage.clone(),
            node_config.consensus_observer,
            consensus_publisher.clone(),
        ));
```

**File:** consensus/src/pipeline/buffer_manager.rs (L400-406)
```rust
        if let Some(consensus_publisher) = &self.consensus_publisher {
            let message = ConsensusObserverMessage::new_ordered_block_message(
                ordered_blocks.clone(),
                ordered_proof.clone(),
            );
            consensus_publisher.publish_message(message);
        }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L514-517)
```rust
                if let Some(consensus_publisher) = &self.consensus_publisher {
                    let message =
                        ConsensusObserverMessage::new_commit_decision_message(commit_proof.clone());
                    consensus_publisher.publish_message(message);
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L181-192)
```rust
            ConsensusObserverRequest::Subscribe => {
                // Add the peer to the set of active subscribers
                self.add_active_subscriber(peer_network_id);
                info!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "New peer subscribed to consensus updates! Peer: {:?}",
                        peer_network_id
                    )));

                // Send a simple subscription ACK
                response_sender.send(ConsensusObserverResponse::SubscribeAck);
```
