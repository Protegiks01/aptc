# Audit Report

## Title
YAML Empty Map Bypass Allows Eclipse Attacks on Fullnodes via Seed Configuration Manipulation

## Summary
The `optimize_public_network_config()` function uses `is_null()` to check if seeds were specified in the configuration, but this check does not detect empty seed maps (`seeds: {}`). An attacker who can influence a node's configuration file can provide an empty seeds map to bypass the safety mechanism that adds default seed peers for testnet/mainnet fullnodes, enabling eclipse attacks.

## Finding Description

The config optimizer is designed to automatically add default seed peers to fullnode configurations on testnet and mainnet networks as a safety measure. This ensures nodes can bootstrap and connect to the legitimate network. [1](#0-0) 

The vulnerability exists in the conditional check at line 203. The function checks `local_network_config_yaml["seeds"].is_null()` to determine if the user has specified seeds in their configuration file. However, in `serde_yaml`, the `is_null()` method only returns `true` for:
- Missing fields (returns `Value::Null`)
- Explicitly null values (`seeds: null`)

It returns `false` for empty mappings (`seeds: {}`), which is `Value::Mapping` with zero entries.

**Attack Scenario:**

1. Attacker creates a malicious configuration template or influences deployment documentation to include `seeds: {}` in the public network configuration
2. Node operator uses this configuration for their VFN or PFN on testnet/mainnet
3. The optimizer's null check fails because `is_null()` returns false for empty maps
4. No default seed peers are added to the configuration
5. If `discovery_method` is `None` (the default) or not properly configured, the node has no mechanism to discover legitimate peers [2](#0-1) 

6. The ConnectivityManager initializes with an empty seed set [3](#0-2) 

7. With no seeds and no discovery, the `choose_peers_to_dial()` function finds zero eligible peers to dial [4](#0-3) 

8. The node can only accept inbound connections from peers that dial it
9. Attacker connects to the isolated node with malicious peers
10. The node becomes eclipsed, seeing only the attacker's view of the blockchain state

The existing test suite has no coverage for the empty seeds map case, only testing explicit seed entries: [5](#0-4) 

## Impact Explanation

**Severity: High**

This vulnerability enables eclipse attacks on fullnodes, which breaks the network security invariant that nodes should connect to the legitimate Aptos network. An eclipsed fullnode:

1. **Sees manipulated blockchain state** - Attacker can present fake blocks, transactions, and state
2. **Accepts invalid transactions** - Applications relying on this node could process double-spends
3. **Provides incorrect API responses** - Users querying this node receive attacker-controlled data
4. **Cannot detect the attack** - The node appears to be functioning normally

While this doesn't directly compromise consensus (validators are unaffected per line 191), it represents a **significant protocol violation** enabling:
- Fraud against users/applications relying on the eclipsed fullnode
- Data manipulation attacks
- Service disruption for dependent systems

Per Aptos bug bounty criteria, this qualifies as **High Severity** - "Significant protocol violations" that compromise the security guarantees of fullnode operation.

## Likelihood Explanation

**Likelihood: Medium**

**Attack Requirements:**
1. Attacker must influence node configuration (via malicious templates, compromised deployment docs, or config generation tools)
2. Target must be VFN or PFN on testnet/mainnet (checked at lines 191, 204-213)
3. Node operator must not configure `discovery_method` or set it to `None`

**Realistic Scenarios:**
- Automated deployment systems using attacker-influenced config templates
- Copy-pasting from compromised documentation or tutorials
- Supply chain attacks on configuration management tools
- Social engineering node operators to use malicious configs

**Mitigating Factors:**
- Most production configs explicitly set `discovery_method: "onchain"` [6](#0-5) 

- Requires ongoing attacker presence to maintain eclipse
- Limited to fullnodes (not validators)

However, the attack surface is real because the vulnerability makes it trivially easy to bypass a critical safety mechanism through a subtle configuration manipulation.

## Recommendation

The fix should check for BOTH null values AND empty mappings. Modify the check to detect when seeds is either missing, null, or an empty map:

```rust
// In optimize_public_network_config() around line 203
let seeds_value = &local_network_config_yaml["seeds"];
let should_add_seeds = seeds_value.is_null() || 
    matches!(seeds_value, serde_yaml::Value::Mapping(m) if m.is_empty());

if should_add_seeds {
    if let Some(chain_id) = chain_id {
        if chain_id.is_testnet() {
            fullnode_network_config.seeds =
                create_seed_peers(TESTNET_SEED_PEERS.into())?;
            modified_config = true;
        } else if chain_id.is_mainnet() {
            fullnode_network_config.seeds =
                create_seed_peers(MAINNET_SEED_PEERS.into())?;
            modified_config = true;
        }
    }
}
```

Alternatively, add a helper function:
```rust
fn is_empty_or_null(value: &serde_yaml::Value) -> bool {
    value.is_null() || matches!(value, serde_yaml::Value::Mapping(m) if m.is_empty())
}
```

## Proof of Concept

Add this test to `config/src/config/config_optimizer.rs` in the tests module to demonstrate the vulnerability:

```rust
#[test]
fn test_optimize_public_network_config_empty_seeds_bypass() {
    // Create a public network config with no seeds
    let mut node_config = NodeConfig {
        storage: setup_storage_config_with_temp_dir().0,
        full_node_networks: vec![NetworkConfig {
            network_id: NetworkId::Public,
            seeds: HashMap::new(),
            ..Default::default()
        }],
        ..Default::default()
    };

    // Create a local config with an EMPTY seeds map (not null)
    let local_config_yaml = serde_yaml::from_str(
        r#"
        full_node_networks:
            - network_id: "Public"
              seeds: {}
        "#,
    )
    .unwrap();

    // Verify that seeds: {} is NOT null
    assert!(!local_config_yaml["full_node_networks"][0]["seeds"].is_null());

    // Optimize the public network config
    let modified_config = optimize_public_network_config(
        &mut node_config,
        &local_config_yaml,
        NodeType::PublicFullnode,
        Some(ChainId::testnet()),
    )
    .unwrap();

    // BUG: The optimizer does NOT add seeds even though seeds map is empty
    // This allows eclipse attacks if discovery_method is also None
    assert!(!modified_config); // No modifications made
    
    let public_network_config = &node_config.full_node_networks[0];
    let public_seeds = &public_network_config.seeds;
    
    // VULNERABILITY: Node has zero seed peers despite being on testnet
    assert_eq!(public_seeds.len(), 0);
    // Expected: Should have TESTNET_SEED_PEERS.len() seeds added
}
```

This test demonstrates that providing `seeds: {}` successfully bypasses the seed optimization, leaving the node with zero seed peers on testnet, enabling eclipse attacks when combined with missing or disabled discovery mechanisms.

## Notes

The vulnerability is confirmed through code analysis showing that `serde_yaml::Value::is_null()` returns `false` for empty mappings. The codebase's config loading pattern (bracket access returning null for missing fields) works correctly for absent fields, but the empty map case was not considered in the security design. This represents a configuration validation bypass that undermines the safety mechanism intended to protect fullnodes on production networks.

### Citations

**File:** config/src/config/config_optimizer.rs (L183-237)
```rust
/// Optimize the public network config according to the node type and chain ID
fn optimize_public_network_config(
    node_config: &mut NodeConfig,
    local_config_yaml: &Value,
    node_type: NodeType,
    chain_id: Option<ChainId>,
) -> Result<bool, Error> {
    // We only need to optimize the public network config for VFNs and PFNs
    if node_type.is_validator() {
        return Ok(false);
    }

    // Add seeds to the public network config
    let mut modified_config = false;
    for (index, fullnode_network_config) in node_config.full_node_networks.iter_mut().enumerate() {
        let local_network_config_yaml = &local_config_yaml["full_node_networks"][index];

        // Optimize the public network configs
        if fullnode_network_config.network_id == NetworkId::Public {
            // Only add seeds to testnet and mainnet (as they are long living networks)
            if local_network_config_yaml["seeds"].is_null() {
                if let Some(chain_id) = chain_id {
                    if chain_id.is_testnet() {
                        fullnode_network_config.seeds =
                            create_seed_peers(TESTNET_SEED_PEERS.into())?;
                        modified_config = true;
                    } else if chain_id.is_mainnet() {
                        fullnode_network_config.seeds =
                            create_seed_peers(MAINNET_SEED_PEERS.into())?;
                        modified_config = true;
                    }
                }
            }

            // If the identity key was not set in the config, attempt to
            // load it from disk. Otherwise, save the already generated
            // one to disk (for future runs).
            if let Identity::FromConfig(IdentityFromConfig {
                source: IdentitySource::AutoGenerated,
                key: config_key,
                ..
            }) = &fullnode_network_config.identity
            {
                let path = node_config.storage.dir().join(IDENTITY_KEY_FILE);
                if let Some(loaded_identity) = Identity::load_identity(&path)? {
                    fullnode_network_config.identity = loaded_identity;
                } else {
                    Identity::save_private_key(&path, &config_key.private_key())?;
                }
            }
        }
    }

    Ok(modified_config)
}
```

**File:** config/src/config/config_optimizer.rs (L482-517)
```rust
    fn test_optimize_public_network_config_no_override() {
        // Create a public network config
        let mut node_config = NodeConfig {
            storage: setup_storage_config_with_temp_dir().0,
            full_node_networks: vec![NetworkConfig {
                network_id: NetworkId::Public,
                seeds: HashMap::new(),
                ..Default::default()
            }],
            ..Default::default()
        };

        // Create a local config with the public network having seed entries
        let local_config_yaml = serde_yaml::from_str(
            r#"
            full_node_networks:
                - network_id: "Public"
                  seeds:
                      bb14af025d226288a3488b4433cf5cb54d6a710365a2d95ac6ffbd9b9198a86a:
                          addresses:
                              - "/dns4/pfn0.node.devnet.aptoslabs.com/tcp/6182/noise-ik/bb14af025d226288a3488b4433cf5cb54d6a710365a2d95ac6ffbd9b9198a86a/handshake/0"
                          role: "Upstream"
            "#,
        )
            .unwrap();

        // Optimize the public network config and verify no modifications are made
        let modified_config = optimize_public_network_config(
            &mut node_config,
            &local_config_yaml,
            NodeType::PublicFullnode,
            Some(ChainId::testnet()),
        )
        .unwrap();
        assert!(!modified_config);
    }
```

**File:** config/src/config/network_config.rs (L128-146)
```rust
impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig::network_with_id(NetworkId::default())
    }
}

impl NetworkConfig {
    pub fn network_with_id(network_id: NetworkId) -> NetworkConfig {
        let mutual_authentication = network_id.is_validator_network();
        let mut config = Self {
            discovery_method: DiscoveryMethod::None,
            discovery_methods: Vec::new(),
            identity: Identity::None,
            listen_address: "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
            mutual_authentication,
            network_id,
            runtime_threads: None,
            seed_addrs: HashMap::new(),
            seeds: PeerSet::default(),
```

**File:** network/builder/src/builder.rs (L206-219)
```rust
        // Always add a connectivity manager to keep track of known peers
        let seeds = merge_seeds(config);

        network_builder.add_connectivity_manager(
            seeds,
            peers_and_metadata,
            config.max_outbound_connections,
            config.connection_backoff_base,
            config.max_connection_delay_ms,
            config.connectivity_check_interval_ms,
            config.network_channel_size,
            config.mutual_authentication,
            config.enable_latency_aware_dialing,
        );
```

**File:** network/framework/src/connectivity_manager/mod.rs (L571-625)
```rust
    /// Selects a set of peers to dial
    async fn choose_peers_to_dial(&mut self) -> Vec<(PeerId, DiscoveredPeer)> {
        // Get the eligible peers to dial
        let network_id = self.network_context.network_id();
        let role = self.network_context.role();
        let roles_to_dial = network_id.upstream_roles(&role);
        let discovered_peers = self.discovered_peers.read().peer_set.clone();
        let eligible_peers: Vec<_> = discovered_peers
            .into_iter()
            .filter(|(peer_id, peer)| {
                peer.is_eligible_to_be_dialed() // The node is eligible to dial
                    && !self.connected.contains_key(peer_id) // The node is not already connected
                    && !self.dial_queue.contains_key(peer_id) // There is no pending dial to this node
                    && roles_to_dial.contains(&peer.role) // We can dial this role
            })
            .collect();

        // Initialize the dial state for any new peers
        for (peer_id, _) in &eligible_peers {
            self.dial_states
                .entry(*peer_id)
                .or_insert_with(|| DialState::new(self.backoff_strategy.clone()));
        }

        // Limit the number of dialed connections from a fullnode. Note: this does not
        // limit the number of incoming connections. It only enforces that a fullnode
        // cannot have more outgoing connections than the limit (including in-flight dials).
        let num_eligible_peers = eligible_peers.len();
        let num_peers_to_dial =
            if let Some(outbound_connection_limit) = self.outbound_connection_limit {
                // Get the number of outbound connections
                let num_outbound_connections = self
                    .connected
                    .iter()
                    .filter(|(_, metadata)| metadata.origin == ConnectionOrigin::Outbound)
                    .count();

                // Add any pending dials to the count
                let total_outbound_connections =
                    num_outbound_connections.saturating_add(self.dial_queue.len());

                // Calculate the potential number of peers to dial
                let num_peers_to_dial =
                    outbound_connection_limit.saturating_sub(total_outbound_connections);

                // Limit the number of peers to dial by the total number of eligible peers
                min(num_peers_to_dial, num_eligible_peers)
            } else {
                num_eligible_peers // Otherwise, we attempt to dial all eligible peers
            };

        // If we have no peers to dial, return early
        if num_peers_to_dial == 0 {
            return vec![];
        }
```

**File:** docker/compose/aptos-node/fullnode.yaml (L24-26)
```yaml
- network_id: "public"
  discovery_method: "onchain"
  listen_address: "/ip4/0.0.0.0/tcp/6182"
```
