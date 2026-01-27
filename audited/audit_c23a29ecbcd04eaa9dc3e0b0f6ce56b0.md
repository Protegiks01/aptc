# Audit Report

## Title
Network Address Mismatch Vulnerability in Validator Configuration Allows Creation of Un-connectable Validators

## Summary
The `get_network_configs` method in `InitializeValidator` and `UpdateValidatorNetworkAddresses` commands allows `validator_host` and `validator_network_public_key` to be sourced independently from CLI arguments or operator config file. This creates mismatched network addresses where the host points to one location but the public key belongs to a different entity, rendering validators un-connectable and potentially causing network partition.

## Finding Description

The vulnerability exists in the `ValidatorNetworkAddressesArgs::get_network_configs` method [1](#0-0) , which independently resolves `validator_network_public_key` and `validator_host` from two possible sources (CLI arguments or operator config file).

**The Critical Flaw:**

The method checks these values independently:
- Lines 218-228: `validator_network_public_key` comes from CLI OR config file
- Lines 239-247: `validator_host` comes from CLI OR config file

There is no validation ensuring both come from the same source. This allows an operator to:

1. Provide `--validator-host 10.0.0.1:6180` via CLI (source A)
2. NOT provide `--validator-network-public-key`, causing fallback to config file's key (source B)
3. Result: NetworkAddress with host from source A but public key from source B

The mismatched address is then used in both `InitializeValidator::execute()` [2](#0-1)  and `UpdateValidatorNetworkAddresses::execute()` [3](#0-2)  to construct the network address that gets stored on-chain.

The on-chain storage happens through `stake::initialize_validator` [4](#0-3)  which performs NO validation of the network addresses content - it only validates consensus keys with proof-of-possession.

**Attack Propagation:**

When other validators attempt to connect to the misconfigured validator:

1. They retrieve the NetworkAddress from on-chain ValidatorConfig
2. Connect to the specified host
3. The Noise IK handshake begins [5](#0-4) 
4. The validator at that host presents its actual x25519 public key
5. The authentication check [6](#0-5)  validates if the presented key matches the expected key in the NetworkAddress
6. **Mismatch detected** - connection rejected with `UnauthenticatedClientPubkey` error
7. Validator becomes un-connectable to the network

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria

This vulnerability directly causes:
- **Validator node un-connectability**: Misconfigured validators cannot receive inbound connections from other validators
- **Consensus participation blocked**: Un-connectable validators cannot participate in AptosBFT consensus
- **Potential network liveness issues**: If multiple validators are misconfigured (through operator error or malicious intent), the network could lose sufficient validators for consensus quorum
- **Network partition risk**: In extreme cases with many affected validators, this could fragment the validator set

This maps to the HIGH severity category: "Validator node slowdowns" and "Significant protocol violations" - the validator cannot function properly and protocol-level communication is broken.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability can occur through:

1. **Operator Misconfiguration (Unintentional)**: 
   - Operators managing multiple validators might accidentally mix configuration sources
   - Copy-paste errors when setting up new validators
   - Updating one field but forgetting to update the corresponding field

2. **Malicious Operator (Intentional)**:
   - A compromised or malicious operator could deliberately misconfigure their own validator
   - Could be used to disrupt network operations
   - No special privileges required beyond being a validator operator

3. **Tooling Issues**:
   - Automated deployment scripts that source configuration from multiple files
   - Configuration management systems with partial updates

The attack requires no special privileges and is trivially executable through CLI commands. The lack of validation makes this highly likely to occur in practice.

## Recommendation

Add validation in `get_network_configs` to ensure `validator_host` and `validator_network_public_key` come from the same source:

```rust
fn get_network_configs<'a>(
    &'a self,
    operator_config: &'a Option<OperatorConfiguration>,
) -> CliTypedResult<(
    x25519::PublicKey,
    Option<x25519::PublicKey>,
    &'a HostAndPort,
    Option<&'a HostAndPort>,
)> {
    // Track source of validator config
    let (validator_network_public_key, validator_host) = 
        if self.validator_network_public_key.is_some() && self.validator_host.is_some() {
            // Both from CLI - OK
            (self.validator_network_public_key.unwrap(), self.validator_host.as_ref().unwrap())
        } else if self.validator_network_public_key.is_none() && self.validator_host.is_none() {
            // Both from config - OK
            if let Some(operator_config) = operator_config {
                (operator_config.validator_network_public_key, &operator_config.validator_host)
            } else {
                return Err(CliError::CommandArgumentError(
                    "Must provide either --operator-config-file or both --validator-host and --validator-network-public-key".to_string(),
                ));
            }
        } else {
            // Mixed sources - ERROR
            return Err(CliError::CommandArgumentError(
                "validator-host and validator-network-public-key must be provided together (both from CLI or both from config file)".to_string(),
            ));
        };

    // Similar validation for fullnode config
    let (full_node_network_public_key, full_node_host) = 
        if self.full_node_network_public_key.is_some() || self.full_node_host.is_some() {
            if self.full_node_network_public_key.is_some() != self.full_node_host.is_some() {
                return Err(CliError::CommandArgumentError(
                    "full-node-host and full-node-network-public-key must be provided together".to_string(),
                ));
            }
            (self.full_node_network_public_key, self.full_node_host.as_ref())
        } else if let Some(operator_config) = operator_config {
            (operator_config.full_node_network_public_key, operator_config.full_node_host.as_ref())
        } else {
            (None, None)
        };

    Ok((
        validator_network_public_key,
        full_node_network_public_key,
        validator_host,
        full_node_host,
    ))
}
```

## Proof of Concept

**Scenario: Operator Misconfigures Validator**

1. Operator has `operator.yaml` config file:
```yaml
operator_account_address: "0xabc..."
validator_network_public_key: "0xKEY_FROM_VALIDATOR_A..."
validator_host: "validator-a.example.com:6180"
```

2. Operator wants to update to new host but accidentally only provides new host via CLI:
```bash
aptos node initialize-validator \
  --operator-config-file operator.yaml \
  --validator-host "validator-b.example.com:6180"
  # Missing: --validator-network-public-key for validator-b
```

3. Result: NetworkAddress created with:
   - Host: `validator-b.example.com:6180` (from CLI)
   - Public Key: `0xKEY_FROM_VALIDATOR_A` (from config file)
   - **MISMATCH!**

4. Transaction succeeds and stores mismatched address on-chain

5. Other validators attempt connection:
   - Connect to `validator-b.example.com:6180`
   - Validator B presents its actual public key: `0xKEY_FROM_VALIDATOR_B`
   - Expected public key from NetworkAddress: `0xKEY_FROM_VALIDATOR_A`
   - Handshake fails at authentication check
   - Error: `UnauthenticatedClientPubkey`

6. Validator B is now un-connectable and cannot participate in consensus

**Verification Steps:**
- Monitor validator connection logs for `UnauthenticatedClientPubkey` errors
- Check on-chain ValidatorConfig network addresses for consistency
- Test network connectivity between validators manually
- Observe validator falling out of active set due to inability to participate

## Notes

This vulnerability affects both initial validator setup (`InitializeValidator`) and subsequent updates (`UpdateValidatorNetworkAddresses`). The lack of validation at both the CLI layer and the Move contract layer (which treats network_addresses as opaque bytes) allows this misconfiguration to persist on-chain. The authentication failure only becomes apparent when validators attempt to connect, making this a silent failure that could accumulate across multiple validators before being detected.

### Citations

**File:** crates/aptos/src/node/mod.rs (L209-263)
```rust
    fn get_network_configs<'a>(
        &'a self,
        operator_config: &'a Option<OperatorConfiguration>,
    ) -> CliTypedResult<(
        x25519::PublicKey,
        Option<x25519::PublicKey>,
        &'a HostAndPort,
        Option<&'a HostAndPort>,
    )> {
        let validator_network_public_key =
            if let Some(public_key) = self.validator_network_public_key {
                public_key
            } else if let Some(operator_config) = operator_config {
                operator_config.validator_network_public_key
            } else {
                return Err(CliError::CommandArgumentError(
                    "Must provide either --operator-config-file or --validator-network-public-key"
                        .to_string(),
                ));
            };

        let full_node_network_public_key =
            if let Some(public_key) = self.full_node_network_public_key {
                Some(public_key)
            } else if let Some(operator_config) = operator_config {
                operator_config.full_node_network_public_key
            } else {
                None
            };

        let validator_host = if let Some(ref host) = self.validator_host {
            host
        } else if let Some(operator_config) = operator_config {
            &operator_config.validator_host
        } else {
            return Err(CliError::CommandArgumentError(
                "Must provide either --operator-config-file or --validator-host".to_string(),
            ));
        };

        let full_node_host = if let Some(ref host) = self.full_node_host {
            Some(host)
        } else if let Some(operator_config) = operator_config {
            operator_config.full_node_host.as_ref()
        } else {
            None
        };

        Ok((
            validator_network_public_key,
            full_node_network_public_key,
            validator_host,
            full_node_host,
        ))
    }
```

**File:** crates/aptos/src/node/mod.rs (L627-628)
```rust
        let validator_network_addresses =
            vec![validator_host.as_network_address(validator_network_public_key)?];
```

**File:** crates/aptos/src/node/mod.rs (L1125-1126)
```rust
        let validator_network_addresses =
            vec![validator_host.as_network_address(validator_network_public_key)?];
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L670-692)
```text
    public entry fun initialize_validator(
        account: &signer,
        consensus_pubkey: vector<u8>,
        proof_of_possession: vector<u8>,
        network_addresses: vector<u8>,
        fullnode_addresses: vector<u8>,
    ) acquires AllowedValidators {
        check_stake_permission(account);
        // Checks the public key has a valid proof-of-possession to prevent rogue-key attacks.
        let pubkey_from_pop = &bls12381::public_key_from_bytes_with_pop(
            consensus_pubkey,
            &proof_of_possession_from_bytes(proof_of_possession)
        );
        assert!(option::is_some(pubkey_from_pop), error::invalid_argument(EINVALID_PUBLIC_KEY));

        initialize_owner(account);
        move_to(account, ValidatorConfig {
            consensus_pubkey,
            network_addresses,
            fullnode_addresses,
            validator_index: 0,
        });
    }
```

**File:** network/framework/src/noise/handshake.rs (L313-364)
```rust
    pub async fn upgrade_inbound<TSocket>(
        &self,
        mut socket: TSocket,
    ) -> Result<(NoiseStream<TSocket>, PeerId, PeerRole), NoiseHandshakeError>
    where
        TSocket: AsyncRead + AsyncWrite + Debug + Unpin,
    {
        // buffer to contain the client first message
        let mut client_message = [0; Self::CLIENT_MESSAGE_SIZE];

        // receive the prologue + first noise handshake message
        trace!("{} noise server: handshake read", self.network_context);
        socket
            .read_exact(&mut client_message)
            .await
            .map_err(NoiseHandshakeError::ServerReadFailed)?;

        // extract prologue (remote_peer_id | self_public_key)
        let (remote_peer_id, self_expected_public_key) =
            client_message[..Self::PROLOGUE_SIZE].split_at(PeerId::LENGTH);

        // parse the client's peer id
        // note: in mutual authenticated network, we could verify that their peer_id is in the trust peer set now.
        // We do this later in this function instead (to batch a number of checks) as there is no known attack here.
        let remote_peer_id = PeerId::try_from(remote_peer_id)
            .map_err(|_| NoiseHandshakeError::InvalidClientPeerId(hex::encode(remote_peer_id)))?;
        let remote_peer_short = remote_peer_id.short_str();

        // reject accidental self-dials
        // this situation could occur either as a result of our own discovery
        // mis-configuration or a potentially malicious discovery peer advertising
        // a (loopback ip or mirror proxy) and our public key.
        if remote_peer_id == self.network_context.peer_id() {
            return Err(NoiseHandshakeError::SelfDialDetected);
        }

        // verify that this is indeed our public key
        let actual_public_key = self.noise_config.public_key();
        if self_expected_public_key != actual_public_key.as_slice() {
            return Err(NoiseHandshakeError::ClientExpectingDifferentPubkey(
                remote_peer_short,
                hex::encode(self_expected_public_key),
                hex::encode(actual_public_key.as_slice()),
            ));
        }

        // parse it
        let (prologue, client_init_message) = client_message.split_at(Self::PROLOGUE_SIZE);
        let (remote_public_key, handshake_state, payload) = self
            .noise_config
            .parse_client_init_message(prologue, client_init_message)
            .map_err(|err| NoiseHandshakeError::ServerParseClient(remote_peer_short, err))?;
```

**File:** network/framework/src/noise/handshake.rs (L488-500)
```rust
    fn authenticate_inbound(
        remote_peer_short: ShortHexStr,
        peer: &Peer,
        remote_public_key: &x25519::PublicKey,
    ) -> Result<PeerRole, NoiseHandshakeError> {
        if !peer.keys.contains(remote_public_key) {
            return Err(NoiseHandshakeError::UnauthenticatedClientPubkey(
                remote_peer_short,
                hex::encode(remote_public_key.as_slice()),
            ));
        }
        Ok(peer.role)
    }
```
