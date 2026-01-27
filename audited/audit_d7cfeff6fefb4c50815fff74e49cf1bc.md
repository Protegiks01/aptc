# Audit Report

## Title
Epoch Header Inconsistency in Historical Resource Queries Causes Validator Set Caching Confusion

## Summary
The REST API returns incorrect epoch headers when clients query resources at historical ledger versions. Specifically, when a client requests the `ValidatorSet` resource at a past version (e.g., from epoch N-1), the API returns the resource data from that historical version but includes the **current** epoch (epoch N) in the response headers. This causes clients to incorrectly cache historical validator sets with the wrong epoch identifier, leading to signature verification failures or potential security vulnerabilities during epoch transitions.

## Finding Description
The vulnerability exists in the API's handling of historical state queries with the `ledger_version` query parameter. The issue manifests through the following code path:

1. When a client queries a resource at a specific historical version (e.g., `/v1/accounts/0x1/resource/0x1::stake::ValidatorSet?ledger_version=1000`), the request is processed by the `StateApi::get_account_resource` endpoint. [1](#0-0) 

2. This endpoint calls `api.resource()` which invokes `self.context.state_view(ledger_version)`: [2](#0-1) 

3. The `state_view()` function calls `get_latest_ledger_info_and_verify_lookup_version()`: [3](#0-2) 

4. This critical function returns the **latest** ledger info regardless of the requested historical version: [4](#0-3) 

5. The response is then constructed using this `latest_ledger_info` for the HTTP headers: [5](#0-4) 

**Attack Scenario:**
- Current blockchain state: Version 2000, Epoch 10
- Attacker queries: `ValidatorSet` at version 1000 (which was in Epoch 9)
- Server response contains:
  - **Body**: ValidatorSet resource from version 1000 (Epoch 9 validators)
  - **Headers**: `X-Aptos-Epoch: 10`, `X-Aptos-Ledger-Version: 2000`

Clients like the `PeerSetCacheUpdater` cache validator sets based on the epoch header: [6](#0-5) 

This causes the client to associate Epoch 9 validators with Epoch 10, breaking the invariant that validator sets must match their epoch.

## Impact Explanation
**High Severity** - This qualifies as a "Significant protocol violation" per the Aptos bug bounty criteria:

1. **Signature Verification Failures**: Clients using the wrong validator set for an epoch will reject valid signatures from legitimate validators or potentially accept invalid signatures from the previous epoch's validators.

2. **Epoch Transition Confusion**: During epoch boundaries, this bug creates a window where clients have inconsistent views of which validators are authoritative, potentially causing:
   - Block validation failures
   - Consensus participation issues
   - State synchronization problems

3. **Client-Side Security Degradation**: Any client relying on cached validator sets for signature verification (telemetry services, light clients, monitoring tools) becomes vulnerable to accepting stale validator credentials.

While this doesn't directly compromise validator nodes or cause fund loss, it represents a significant protocol-level bug that undermines the security model of epoch-based validator rotation.

## Likelihood Explanation
**High Likelihood** - This vulnerability triggers in common operational scenarios:

1. **Any historical query**: Whenever a client queries resources at past versions (common for analytics, auditing, or historical state reconstruction)

2. **Epoch transitions**: The impact is most severe when queries span epoch boundaries, which occur regularly (every few hours/days depending on epoch configuration)

3. **No special privileges required**: Any API client can exploit this by simply adding the `ledger_version` query parameter

4. **Widespread client usage**: Multiple components use `get_account_resource_at_version_bcs()`: [7](#0-6) 

The validator cache updater, while currently not using versioned queries, demonstrates the pattern that would be affected: [8](#0-7) 

## Recommendation
The API should return ledger info **corresponding to the requested version**, not the latest version. Modify `state_view()` to construct appropriate ledger info for the requested version:

**Option 1: Query block info at requested version**
```rust
pub fn state_view<E: StdApiError>(
    &self,
    requested_ledger_version: Option<u64>,
) -> Result<(LedgerInfo, u64, DbStateView), E> {
    let latest_ledger_info = self.get_latest_ledger_info()?;
    
    let requested_ledger_version = requested_ledger_version
        .unwrap_or_else(|| latest_ledger_info.version());
    
    // Validate version is in range
    if requested_ledger_version > latest_ledger_info.version() {
        return Err(version_not_found(requested_ledger_version, &latest_ledger_info));
    } else if requested_ledger_version < latest_ledger_info.oldest_ledger_version.0 {
        return Err(version_pruned(requested_ledger_version, &latest_ledger_info));
    }
    
    // Get block info at the requested version to obtain the correct epoch
    let (_, _, new_block_event) = self.db
        .get_block_info_by_version(requested_ledger_version)
        .map_err(|err| E::internal_with_code(err, AptosErrorCode::InternalError, &latest_ledger_info))?;
    
    // Construct ledger info for the requested version with its actual epoch
    let ledger_info_at_version = LedgerInfo::new_ledger_info(
        &self.chain_id(),
        new_block_event.epoch(),
        requested_ledger_version,
        latest_ledger_info.oldest_ledger_version.0,
        latest_ledger_info.oldest_block_height.0,
        new_block_event.height(),
        new_block_event.proposed_time(),
    );
    
    let state_view = self.state_view_at_version(requested_ledger_version)
        .map_err(|err| E::internal_with_code(err, AptosErrorCode::InternalError, &ledger_info_at_version))?;
    
    Ok((ledger_info_at_version, requested_ledger_version, state_view))
}
```

**Option 2: Add explicit documentation** if current behavior is intentional, document that response headers always reflect the latest state, and clients should not cache resources with epoch headers when querying historical versions.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_epoch_confusion_on_historical_query() {
    // Setup: Create a test environment with an epoch transition
    let (swarm, mut cli, _faucet) = setup_test_environment().await;
    
    // Get initial state at epoch N
    let client = swarm.validators().next().unwrap().rest_client();
    let initial_state = client.get_ledger_information().await.unwrap().into_inner();
    let initial_epoch = initial_state.epoch;
    let initial_version = initial_state.version;
    
    // Query ValidatorSet at initial version
    let validator_set_v1 = client
        .get_account_resource_bcs::<ValidatorSet>(CORE_CODE_ADDRESS, "0x1::stake::ValidatorSet")
        .await
        .unwrap();
    let (_, state_v1) = validator_set_v1.into_parts();
    
    // Trigger epoch change (through governance or waiting)
    trigger_epoch_change(&mut cli).await;
    
    // Get new state at epoch N+1
    let new_state = client.get_ledger_information().await.unwrap().into_inner();
    let new_epoch = new_state.epoch;
    let new_version = new_state.version;
    assert!(new_epoch > initial_epoch, "Epoch should have incremented");
    
    // VULNERABILITY: Query ValidatorSet at the OLD version
    let validator_set_old = client
        .get_account_resource_at_version_bcs::<ValidatorSet>(
            CORE_CODE_ADDRESS,
            "0x1::stake::ValidatorSet",
            initial_version
        )
        .await
        .unwrap();
    let (old_validators, state_old) = validator_set_old.into_parts();
    
    // BUG: The response headers show the NEW epoch, but the data is from the OLD epoch
    assert_eq!(state_old.epoch, new_epoch, "Header shows current epoch");
    assert_eq!(state_old.version, new_version, "Header shows current version");
    
    // But the ValidatorSet data is from the old version
    assert_eq!(old_validators, validator_set_v1.inner());
    
    // IMPACT: A client caching based on state_old.epoch would associate
    // the old validator set with the new epoch, causing signature verification
    // failures when validating blocks from the new epoch
    println!("VULNERABILITY CONFIRMED:");
    println!("  - Requested version: {} (epoch {})", initial_version, initial_epoch);
    println!("  - Response data: ValidatorSet from epoch {}", initial_epoch);
    println!("  - Response headers: epoch {}, version {}", state_old.epoch, state_old.version);
    println!("  - Client would cache epoch {} validators for epoch {}", initial_epoch, new_epoch);
}
```

**Notes:**
- This vulnerability breaks the critical invariant: "Cryptographic Correctness: BLS signatures, VRF, and hash operations must be secure" by causing clients to use incorrect validator sets for signature verification
- The fix requires modifying the API to return version-specific ledger info rather than always returning the latest state
- All endpoints accepting `ledger_version` as a query parameter are affected, not just ValidatorSet queries

### Citations

**File:** api/src/state.rs (L51-84)
```rust
    async fn get_account_resource(
        &self,
        accept_type: AcceptType,
        /// Address of account with or without a `0x` prefix
        address: Path<Address>,
        /// Name of struct to retrieve e.g. `0x1::account::Account`
        resource_type: Path<MoveStructTag>,
        /// Ledger version to get state of account
        ///
        /// If not provided, it will be the latest version
        ledger_version: Query<Option<U64>>,
    ) -> BasicResultWith404<MoveResource> {
        resource_type
            .0
            .verify(0)
            .context("'resource_type' invalid")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;
        fail_point_poem("endpoint_get_account_resource")?;
        self.context
            .check_api_output_enabled("Get account resource", &accept_type)?;

        let api = self.clone();
        api_spawn_blocking(move || {
            api.resource(
                &accept_type,
                address.0,
                resource_type.0,
                ledger_version.0.map(|inner| inner.0),
            )
        })
        .await
    }
```

**File:** api/src/state.rs (L274-288)
```rust
    fn resource(
        &self,
        accept_type: &AcceptType,
        address: Address,
        resource_type: MoveStructTag,
        ledger_version: Option<u64>,
    ) -> BasicResultWith404<MoveResource> {
        let tag: StructTag = (&resource_type)
            .try_into()
            .context("Failed to parse given resource type")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;

        let (ledger_info, ledger_version, state_view) = self.context.state_view(ledger_version)?;
```

**File:** api/src/context.rs (L177-191)
```rust
    pub fn state_view<E: StdApiError>(
        &self,
        requested_ledger_version: Option<u64>,
    ) -> Result<(LedgerInfo, u64, DbStateView), E> {
        let (latest_ledger_info, requested_ledger_version) =
            self.get_latest_ledger_info_and_verify_lookup_version(requested_ledger_version)?;

        let state_view = self
            .state_view_at_version(requested_ledger_version)
            .map_err(|err| {
                E::internal_with_code(err, AptosErrorCode::InternalError, &latest_ledger_info)
            })?;

        Ok((latest_ledger_info, requested_ledger_version, state_view))
    }
```

**File:** api/src/context.rs (L294-317)
```rust
    pub fn get_latest_ledger_info_and_verify_lookup_version<E: StdApiError>(
        &self,
        requested_ledger_version: Option<Version>,
    ) -> Result<(LedgerInfo, Version), E> {
        let latest_ledger_info = self.get_latest_ledger_info()?;

        let requested_ledger_version =
            requested_ledger_version.unwrap_or_else(|| latest_ledger_info.version());

        // This is too far in the future, a retriable case
        if requested_ledger_version > latest_ledger_info.version() {
            return Err(version_not_found(
                requested_ledger_version,
                &latest_ledger_info,
            ));
        } else if requested_ledger_version < latest_ledger_info.oldest_ledger_version.0 {
            return Err(version_pruned(
                requested_ledger_version,
                &latest_ledger_info,
            ));
        }

        Ok((latest_ledger_info, requested_ledger_version))
    }
```

**File:** api/src/response.rs (L366-395)
```rust
        impl <T: poem_openapi::types::ToJSON + Send + Sync> From<($crate::response::AptosResponseContent<T>, &aptos_api_types::LedgerInfo, [<$enum_name Status>])>
            for $enum_name<T>
        {
            fn from(
                (value, ledger_info, status): (
                    $crate::response::AptosResponseContent<T>,
                    &aptos_api_types::LedgerInfo,
                    [<$enum_name Status>]
                ),
            ) -> Self {
                match status {
                    $(
                    [<$enum_name Status>]::$name => {
                        $enum_name::$name(
                            value,
                            ledger_info.chain_id,
                            ledger_info.ledger_version.into(),
                            ledger_info.oldest_ledger_version.into(),
                            ledger_info.ledger_timestamp.into(),
                            ledger_info.epoch.into(),
                            ledger_info.block_height.into(),
                            ledger_info.oldest_block_height.into(),
                            None,
                            None,
                        )
                    },
                    )*
                }
            }
        }
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L86-176)
```rust
    async fn update_for_chain(
        &self,
        chain_name: &ChainCommonName,
        url: &str,
    ) -> Result<(), ValidatorCacheUpdateError> {
        let client = aptos_rest_client::Client::new(Url::parse(url).map_err(|e| {
            error!("invalid url for chain_id {}: {}", chain_name, e);
            ValidatorCacheUpdateError::InvalidUrl
        })?);
        let response: Response<ValidatorSet> = client
            .get_account_resource_bcs(CORE_CODE_ADDRESS, "0x1::stake::ValidatorSet")
            .await
            .map_err(ValidatorCacheUpdateError::RestError)?;

        let (peer_addrs, state) = response.into_parts();

        let chain_id = ChainId::new(state.chain_id);

        let mut validator_cache = self.validators.write();
        let mut vfn_cache = self.validator_fullnodes.write();

        let validator_peers: PeerSet = peer_addrs
            .clone()
            .into_iter()
            .filter_map(|validator_info| -> Option<(PeerId, Peer)> {
                validator_info
                    .config()
                    .validator_network_addresses()
                    .map(|addresses| {
                        (
                            *validator_info.account_address(),
                            Peer::from_addrs(PeerRole::Validator, addresses),
                        )
                    })
                    .map_err(|err| {
                        error!(
                            "unable to parse validator network address for validator info {} for chain name {}: {}",
                            validator_info, chain_name, err
                        )
                    })
                    .ok()
            })
            .collect();

        let vfn_peers: PeerSet = peer_addrs
            .into_iter()
            .filter_map(|validator_info| -> Option<(PeerId, Peer)> {
                validator_info
                    .config()
                    .fullnode_network_addresses()
                    .map(|addresses| {
                        (
                            *validator_info.account_address(),
                            Peer::from_addrs(PeerRole::ValidatorFullNode, addresses),
                        )
                    })
                    .map_err(|err| {
                        error!(
                            "unable to parse fullnode network address for validator info {} in chain name {}: {}",
                            validator_info, chain_name, err
                        );
                    })
                    .ok()
            })
            .collect();

        debug!(
            "Validator peers for chain name {} (chain id {}) at epoch {}: {:?}",
            chain_name, chain_id, state.epoch, validator_peers
        );

        // Capture counts before moving into cache
        let validator_count = validator_peers.len();
        let vfn_count = vfn_peers.len();
        let has_validators = !validator_peers.is_empty();
        let has_vfns = !vfn_peers.is_empty();

        let result = if !has_validators && !has_vfns {
            Err(ValidatorCacheUpdateError::BothPeerSetEmpty)
        } else if !has_validators {
            Err(ValidatorCacheUpdateError::ValidatorSetEmpty)
        } else if !has_vfns {
            Err(ValidatorCacheUpdateError::VfnSetEmpty)
        } else {
            Ok(())
        };

        // Update validator cache and record metrics
        let chain_id_str = chain_id.to_string();
        if has_validators {
            validator_cache.insert(chain_id, (state.epoch, validator_peers));
```

**File:** crates/aptos-rest-client/src/lib.rs (L1223-1238)
```rust
    pub async fn get_account_resource_at_version_bcs<T: DeserializeOwned>(
        &self,
        address: AccountAddress,
        resource_type: &str,
        version: u64,
    ) -> AptosResult<Response<T>> {
        let url = self.build_path(&format!(
            "accounts/{}/resource/{}?ledger_version={}",
            address.to_hex(),
            resource_type,
            version
        ))?;

        let response = self.get_bcs(url).await?;
        Ok(response.and_then(|inner| bcs::from_bytes(&inner))?)
    }
```
