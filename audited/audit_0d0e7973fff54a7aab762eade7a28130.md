# Audit Report

## Title
No Atomic Chain ID Update Mechanism Exposes Network to Permanent Partition During Hard Fork

## Summary
The Aptos blockchain lacks a secure mechanism to atomically update the `ChainId` resource across all validators during a hard fork. Any chain ID change requires a manual genesis restart where all validators must halt consensus, apply a genesis transaction, and restart with the new chain ID. If any validator fails to update or restarts with a mismatched chain ID, the network permanently partitions due to chain ID validation in the network handshake protocol, requiring manual intervention to recover.

## Finding Description

The `ChainId` resource is initialized once during genesis and has no update mechanism: [1](#0-0) 

Unlike other on-chain configurations (e.g., `ExecutionConfig`, `ConsensusConfig`) that support governance-based updates via `set_for_next_epoch()` and `on_new_epoch()` functions: [2](#0-1) 

The `ChainId` module provides only read-only access with no update path.

Chain ID is enforced at two critical layers:

**1. Network Layer**: During peer handshake, mismatched chain IDs cause immediate connection rejection: [3](#0-2) 

**2. Transaction Validation Layer**: Every transaction is validated against the on-chain chain ID: [4](#0-3) 

During a hard fork requiring chain ID change, the operational procedure requires:

1. Halting all validators using `sync_only` mode
2. Manually applying a genesis transaction to each validator's storage
3. Restarting all validators with the new chain ID [5](#0-4) 

**The Vulnerability**: If any validator fails to update (due to operational error, Byzantine behavior, or network issues), they will:
- Reject network connections from validators with the new chain ID (handshake fails)
- Be unable to validate transactions meant for the new chain
- Create a permanent network partition

The handshake error test demonstrates this rejection behavior: [6](#0-5) 

## Impact Explanation

This issue qualifies as **Critical Severity** per Aptos Bug Bounty criteria:
- **Non-recoverable network partition (requires hardfork)**: If validators split between old and new chain IDs, the network permanently partitions into two groups that cannot communicate
- **Total loss of liveness/network availability**: If insufficient validators update to the new chain ID (< 2/3 stake), consensus cannot proceed

The impact affects the entire network and requires manual intervention to resolve, as there is no automatic recovery mechanism for chain ID mismatches.

## Likelihood Explanation

**Likelihood: Low-to-Medium** in practice, but **High Impact** when it occurs.

While hard forks requiring chain ID changes are rare governance events, the likelihood of misconfiguration is non-negligible because:
1. Manual coordination across all validators is required
2. No atomic update mechanism exists to guarantee consistency
3. No validation check prevents validators from restarting with wrong chain ID
4. Byzantine validators could intentionally refuse to update to disrupt the network

The operational complexity increases with network size - the more validators, the higher the probability of at least one failing to update correctly.

## Recommendation

Implement a governance-based chain ID update mechanism following the same pattern as other on-chain configurations:

**Proposed Solution**:
```move
module aptos_framework::chain_id {
    use aptos_framework::config_buffer;
    use aptos_framework::system_addresses;
    
    // Add update capability
    public fun set_for_next_epoch(aptos_framework: &signer, new_id: u8) {
        system_addresses::assert_aptos_framework(aptos_framework);
        config_buffer::upsert(ChainId { id: new_id });
    }
    
    // Add epoch transition handler
    public(friend) fun on_new_epoch(aptos_framework: &signer) acquires ChainId {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (config_buffer::does_exist<ChainId>()) {
            let new_chain_id = config_buffer::extract_v2<ChainId>();
            *borrow_global_mut<ChainId>(@aptos_framework) = new_chain_id;
        }
    }
}
```

Then integrate into the reconfiguration flow: [7](#0-6) 

**Alternative Recommendation**: If chain ID must remain immutable (which is reasonable since it identifies the chain), document that hard forks requiring chain ID changes are intentionally creating a **new chain** rather than updating the existing one, and provide clear operational procedures with rollback mechanisms for failed transitions.

## Proof of Concept

This vulnerability cannot be demonstrated in a simple test because it requires:
1. A full multi-validator network
2. Simulation of a hard fork scenario
3. Intentional misconfiguration of at least one validator

However, the existing test demonstrates the handshake rejection behavior: [6](#0-5) 

**Reproduction Steps**:
1. Start a 4-validator network
2. Initiate hard fork procedure to change chain ID from 4 to 5
3. Update 3 validators to chain ID 5 and restart them
4. Leave 1 validator on chain ID 4
5. Observe: The network partitions - the 3 validators with chain ID 5 cannot communicate with the validator on chain ID 4
6. Observe: If the remaining validator holds >1/3 stake, the new chain cannot achieve consensus
7. Manual intervention required to resolve

## Notes

While the lack of an atomic chain ID update mechanism represents a significant operational risk during hard forks, there is debate whether this constitutes a "vulnerability" versus a "design limitation":

- **Design consideration**: Chain ID is fundamentally meant to identify a distinct blockchain. Changing it effectively creates a new chain, making the coordination challenges inherent rather than a bug.
- **Operational reality**: The manual coordination required exposes the network to partition risks that could be mitigated with better tooling or governance-based updates.
- **Security impact**: Regardless of intent, the current implementation allows network partitions during chain ID transitions without recovery mechanisms.

The recommendation to add governance-based chain ID updates would provide safer operational procedures while maintaining the ability to create truly distinct chains when needed.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/chain_id.move (L13-24)
```text
    /// Only called during genesis.
    /// Publish the chain ID `id` of this instance under the SystemAddresses address
    public(friend) fun initialize(aptos_framework: &signer, id: u8) {
        system_addresses::assert_aptos_framework(aptos_framework);
        move_to(aptos_framework, ChainId { id })
    }

    #[view]
    /// Return the chain ID of this instance.
    public fun get(): u8 acquires ChainId {
        borrow_global<ChainId>(@aptos_framework).id
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L42-65)
```text
    /// This can be called by on-chain governance to update on-chain execution configs for the next epoch.
    /// Example usage:
    /// ```
    /// aptos_framework::execution_config::set_for_next_epoch(&framework_signer, some_config_bytes);
    /// aptos_framework::aptos_governance::reconfigure(&framework_signer);
    /// ```
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }

    /// Only used in reconfigurations to apply the pending `ExecutionConfig`, if there is any.
    public(friend) fun on_new_epoch(framework: &signer) acquires ExecutionConfig {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<ExecutionConfig>()) {
            let config = config_buffer::extract_v2<ExecutionConfig>();
            if (exists<ExecutionConfig>(@aptos_framework)) {
                *borrow_global_mut<ExecutionConfig>(@aptos_framework) = config;
            } else {
                move_to(framework, config);
            };
        }
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L431-441)
```rust
    pub fn perform_handshake(
        &self,
        other: &HandshakeMsg,
    ) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L126-143)
```text
    fun prologue_common(
        sender: &signer,
        gas_payer: &signer,
        replay_protector: ReplayProtector,
        txn_authentication_key: Option<vector<u8>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
    ) {
        let sender_address = signer::address_of(sender);
        let gas_payer_address = signer::address_of(gas_payer);
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));
```

**File:** testsuite/smoke-test/src/genesis.rs (L78-99)
```rust
    println!("3. Enabling `sync_only` mode for every validator!");
    for validator in swarm.validators_mut() {
        enable_sync_only_mode(num_validators, validator).await;
    }

    println!("4. Fetching the halt version and epoch, and stopping all validators!");
    let (halt_version, halt_epoch) =
        get_highest_synced_version_and_epoch(&swarm.get_all_nodes_clients_with_names())
            .await
            .unwrap();
    for node in swarm.validators_mut() {
        node.stop();
    }

    println!("5. Generating a genesis transaction that removes the last validator from the set!");
    let (genesis_blob_path, genesis_transaction) =
        generate_genesis_transaction(&mut swarm, aptos_cli);

    println!("6. Applying the genesis transaction to the first validator!");
    let first_validator_config = swarm.validators_mut().next().unwrap().config().clone();
    let first_validator_storage_dir = first_validator_config.storage.dir();
    let output = Command::new(aptos_debugger.as_path())
```

**File:** network/framework/src/protocols/identity.rs (L123-154)
```rust
    #[test]
    fn handshake_chain_id_mismatch() {
        let (mut outbound, mut inbound) = MemorySocket::new_pair();

        // server state
        let server_handshake = HandshakeMsg::new_for_testing();

        // client state
        let mut client_handshake = server_handshake.clone();
        client_handshake.chain_id = ChainId::new(client_handshake.chain_id.id() + 1);

        // perform the handshake negotiation
        let server = async move {
            let remote_handshake = exchange_handshake(&server_handshake, &mut inbound)
                .await
                .unwrap();
            server_handshake
                .perform_handshake(&remote_handshake)
                .unwrap_err()
        };

        let client = async move {
            let remote_handshake = exchange_handshake(&client_handshake, &mut outbound)
                .await
                .unwrap();
            client_handshake
                .perform_handshake(&remote_handshake)
                .unwrap_err()
        };

        block_on(join(server, client));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L105-159)
```text
    /// Signal validators to start using new configuration. Must be called from friend config modules.
    public(friend) fun reconfigure() acquires Configuration {
        // Do not do anything if genesis has not finished.
        if (chain_status::is_genesis() || timestamp::now_microseconds() == 0 || !reconfiguration_enabled()) {
            return
        };

        let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
        let current_time = timestamp::now_microseconds();

        // Do not do anything if a reconfiguration event is already emitted within this transaction.
        //
        // This is OK because:
        // - The time changes in every non-empty block
        // - A block automatically ends after a transaction that emits a reconfiguration event, which is guaranteed by
        //   VM spec that all transactions comming after a reconfiguration transaction will be returned as Retry
        //   status.
        // - Each transaction must emit at most one reconfiguration event
        //
        // Thus, this check ensures that a transaction that does multiple "reconfiguration required" actions emits only
        // one reconfiguration event.
        //
        if (current_time == config_ref.last_reconfiguration_time) {
            return
        };

        reconfiguration_state::on_reconfig_start();

        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
        storage_gas::on_reconfig();

        assert!(current_time > config_ref.last_reconfiguration_time, error::invalid_state(EINVALID_BLOCK_TIME));
        config_ref.last_reconfiguration_time = current_time;
        spec {
            assume config_ref.epoch + 1 <= MAX_U64;
        };
        config_ref.epoch = config_ref.epoch + 1;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                NewEpoch {
                    epoch: config_ref.epoch,
                },
            );
        };
        event::emit_event<NewEpochEvent>(
            &mut config_ref.events,
            NewEpochEvent {
                epoch: config_ref.epoch,
            },
        );

        reconfiguration_state::on_reconfig_finish();
    }
```
