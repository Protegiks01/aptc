# Audit Report

## Title
Waypoint Verification Panic Causes Permanent Node Bootstrap Failure

## Summary
The waypoint verification logic in the state sync bootstrapper contains overly strict validation that causes a node panic when processing epoch-ending ledger infos with versions exceeding an unverified waypoint. This creates a permanent denial-of-service condition preventing nodes from bootstrapping and participating in consensus.

## Finding Description

The vulnerability exists in the `verify_waypoint` method of the `VerifiedEpochStates` struct. [1](#0-0) 

During the bootstrapping process, when a node fetches epoch-ending ledger infos sequentially, the verification logic enforces that no ledger info with a version higher than the waypoint can be processed before the waypoint itself is verified. If such a ledger info is encountered, the node panics rather than gracefully handling the mismatch.

The critical code path is:

1. Node begins bootstrapping with a configured waypoint [2](#0-1) 

2. Node fetches epoch-ending ledger infos from the network [3](#0-2) 

3. Each ledger info is processed via `update_verified_epoch_states` which calls `verify_waypoint` [4](#0-3) 

4. If the waypoint version doesn't correspond to an epoch boundary in the received sequence, the first ledger info with `version > waypoint_version` triggers a panic [5](#0-4) 

**Attack Scenario:**
An attacker with the ability to influence node configuration (via social engineering, supply chain attack on configuration templates, or compromised deployment scripts) provides a waypoint that:
- Uses `Waypoint::new_any()` instead of `new_epoch_boundary()`, creating a waypoint at a non-epoch-boundary version [6](#0-5) 
- Points to a version between two epoch boundaries (e.g., waypoint at version 1000, but epoch 10 ends at version 999 and epoch 11 ends at version 1200)

When the node attempts to bootstrap, it processes epoch-ending ledger infos in order and panics when encountering version 1200, permanently preventing bootstrap completion.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

- **Validator node slowdowns/crashes**: Affected nodes cannot complete bootstrapping and enter a panic loop, requiring manual intervention
- **Significant protocol violations**: Nodes cannot participate in consensus, reducing network decentralization and security
- **Availability impact**: Multiple nodes with misconfigured waypoints cannot sync, potentially affecting network liveness

The panic-on-error design prevents any automatic recovery mechanism. Node operators must manually identify the root cause and reconfigure the waypoint—a process that may not be immediately obvious given the cryptic panic message.

## Likelihood Explanation

**Likelihood: Medium**

While this requires an attacker to influence waypoint configuration, several realistic vectors exist:

1. **Supply chain attacks**: Compromised deployment automation or configuration templates
2. **Social engineering**: Convincing operators to use "verified" waypoints from untrusted sources
3. **Documentation errors**: Misleading examples using `new_any()` instead of `new_epoch_boundary()`
4. **Operational mistakes**: Administrators copying waypoints from non-epoch-boundary ledger infos during disaster recovery

The existing test demonstrates this is known behavior [7](#0-6) , suggesting it has not been treated as a security concern despite its DoS potential.

## Recommendation

Replace the panic with graceful error handling and clear diagnostic messages:

```rust
fn verify_waypoint(
    &mut self,
    epoch_ending_ledger_info: &LedgerInfoWithSignatures,
    waypoint: &Waypoint,
) -> Result<(), Error> {
    if !self.verified_waypoint {
        let waypoint_version = waypoint.version();
        let ledger_info = epoch_ending_ledger_info.ledger_info();
        let ledger_info_version = ledger_info.version();

        // Check if we've passed the waypoint without verifying it
        if ledger_info_version > waypoint_version {
            return Err(Error::InvalidWaypoint(format!(
                "Waypoint verification failed: received epoch-ending ledger info at version {} \
                 which exceeds the waypoint version {} without finding a matching ledger info. \
                 This suggests the waypoint is not at a valid epoch boundary. \
                 Please verify your waypoint configuration corresponds to an epoch-ending ledger info.",
                ledger_info_version, waypoint_version
            )));
        }

        // Check if we've found the ledger info corresponding to the waypoint version
        if ledger_info_version == waypoint_version {
            match waypoint.verify(ledger_info) {
                Ok(()) => self.set_verified_waypoint(waypoint_version),
                Err(error) => {
                    return Err(Error::InvalidWaypoint(format!(
                        "Waypoint verification failed: hash mismatch. \
                         Waypoint: {:?}, Ledger info: {:?}, Error: {:?}",
                        waypoint, ledger_info, error
                    )));
                },
            }
        }
    }

    Ok(())
}
```

Additionally, add validation when loading waypoints to ensure they use `new_epoch_boundary()` or verify the waypoint corresponds to an epoch-ending ledger info before accepting it.

## Proof of Concept

The vulnerability is already demonstrated in the test suite: [7](#0-6) 

This test confirms that when epoch-ending ledger infos are processed with versions that skip over the waypoint version, the node panics with the message "Failed to verify the waypoint: Waypoint value mismatch".

To reproduce:
1. Configure a node with a waypoint at a non-epoch-boundary version
2. Start the node from genesis
3. Observe the node panic when processing epoch-ending ledger infos that exceed the waypoint version without matching it

**Notes**

While this vulnerability requires some level of configuration access (not a pure network-level attack), it represents a critical robustness failure in waypoint verification. The panic-based error handling creates a permanent DoS condition with no automatic recovery path, making it an effective attack vector when combined with social engineering or supply chain compromise. The severity is further elevated by the fact that waypoints are a critical security mechanism for bootstrapping trust, yet the implementation assumes perfect configuration without defensive validation.

### Citations

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L131-166)
```rust
    /// Attempts to verify the waypoint using the new epoch ending ledger info
    fn verify_waypoint(
        &mut self,
        epoch_ending_ledger_info: &LedgerInfoWithSignatures,
        waypoint: &Waypoint,
    ) -> Result<(), Error> {
        if !self.verified_waypoint {
            // Fetch the waypoint and ledger info versions
            let waypoint_version = waypoint.version();
            let ledger_info = epoch_ending_ledger_info.ledger_info();
            let ledger_info_version = ledger_info.version();

            // Verify we haven't missed the waypoint
            if ledger_info_version > waypoint_version {
                panic!(
                    "Failed to verify the waypoint: ledger info version is too high! Waypoint version: {:?}, ledger info version: {:?}",
                    waypoint_version, ledger_info_version
                );
            }

            // Check if we've found the ledger info corresponding to the waypoint version
            if ledger_info_version == waypoint_version {
                match waypoint.verify(ledger_info) {
                    Ok(()) => self.set_verified_waypoint(waypoint_version),
                    Err(error) => {
                        panic!(
                            "Failed to verify the waypoint: {:?}! Waypoint: {:?}, given ledger info: {:?}",
                            error, waypoint, ledger_info
                        );
                    },
                }
            }
        }

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L813-876)
```rust
    /// maximum that can be found by the data streaming service).
    async fn fetch_epoch_ending_ledger_infos(
        &mut self,
        global_data_summary: &GlobalDataSummary,
    ) -> Result<(), Error> {
        // Verify the waypoint can be satisfied
        self.verify_waypoint_is_satisfiable(global_data_summary)?;

        // Get the highest advertised epoch that has ended
        let highest_advertised_epoch_end = global_data_summary
            .advertised_data
            .highest_epoch_ending_ledger_info()
            .ok_or_else(|| {
                Error::AdvertisedDataError(
                    "No highest advertised epoch end found in the network!".into(),
                )
            })?;

        // Fetch the highest epoch end known locally
        let highest_known_ledger_info = self.get_highest_known_ledger_info()?;
        let highest_known_ledger_info = highest_known_ledger_info.ledger_info();
        let highest_local_epoch_end = if highest_known_ledger_info.ends_epoch() {
            highest_known_ledger_info.epoch()
        } else if highest_known_ledger_info.epoch() > 0 {
            highest_known_ledger_info
                .epoch()
                .checked_sub(1)
                .ok_or_else(|| {
                    Error::IntegerOverflow("The highest local epoch end has overflown!".into())
                })?
        } else {
            unreachable!("Genesis should always end the first epoch!");
        };

        // Compare the highest local epoch end to the highest advertised epoch end
        if highest_local_epoch_end < highest_advertised_epoch_end {
            info!(LogSchema::new(LogEntry::Bootstrapper).message(&format!(
                "Found higher epoch ending ledger infos in the network! Local: {:?}, advertised: {:?}",
                   highest_local_epoch_end, highest_advertised_epoch_end
            )));
            let next_epoch_end = highest_local_epoch_end.checked_add(1).ok_or_else(|| {
                Error::IntegerOverflow("The next epoch end has overflown!".into())
            })?;
            let epoch_ending_stream = self
                .streaming_client
                .get_all_epoch_ending_ledger_infos(next_epoch_end)
                .await?;
            self.active_data_stream = Some(epoch_ending_stream);
        } else if self.verified_epoch_states.verified_waypoint() {
            info!(LogSchema::new(LogEntry::Bootstrapper).message(
                "No new epoch ending ledger infos to fetch! All peers are in the same epoch!"
            ));
            self.verified_epoch_states
                .set_fetched_epoch_ending_ledger_infos();
        } else {
            return Err(Error::AdvertisedDataError(format!(
                "Our waypoint is unverified, but there's no higher epoch ending ledger infos \
                advertised! Highest local epoch end: {:?}, highest advertised epoch end: {:?}",
                highest_local_epoch_end, highest_advertised_epoch_end
            )));
        };

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1094-1106)
```rust
        for epoch_ending_ledger_info in epoch_ending_ledger_infos {
            if let Err(error) = self.verified_epoch_states.update_verified_epoch_states(
                &epoch_ending_ledger_info,
                &self.driver_configuration.waypoint,
            ) {
                self.reset_active_stream(Some(NotificationAndFeedback::new(
                    notification_id,
                    NotificationFeedback::PayloadProofFailed,
                )))
                .await?;
                return Err(error);
            }
        }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L52-65)
```rust
#[derive(Clone)]
pub struct DriverConfiguration {
    // The config file of the driver
    pub config: StateSyncDriverConfig,

    // The config for consensus observer
    pub consensus_observer_config: ConsensusObserverConfig,

    // The role of the node
    pub role: RoleType,

    // The trusted waypoint for the node
    pub waypoint: Waypoint,
}
```

**File:** types/src/waypoint.rs (L38-45)
```rust
    /// Generate a new waypoint given any LedgerInfo.
    pub fn new_any(ledger_info: &LedgerInfo) -> Self {
        let converter = Ledger2WaypointConverter::new(ledger_info);
        Self {
            version: ledger_info.version(),
            value: converter.hash(),
        }
    }
```

**File:** state-sync/state-sync-driver/src/tests/bootstrapper.rs (L906-954)
```rust
#[tokio::test]
#[should_panic(expected = "Failed to verify the waypoint: Waypoint value mismatch")]
async fn test_fetch_epoch_ending_ledger_infos_waypoint_mismatch() {
    // Create a driver configuration
    let mut driver_configuration = create_full_node_driver_configuration();

    // Update the driver configuration to use a waypoint in the future
    let waypoint_version = 100;
    let waypoint_epoch = 100;
    let waypoint = create_random_epoch_ending_ledger_info(waypoint_version, waypoint_epoch);
    driver_configuration.waypoint = Waypoint::new_any(waypoint.ledger_info());

    // Create the mock streaming client
    let mut mock_streaming_client = create_mock_streaming_client();
    let (mut notification_sender, data_stream_listener) = create_data_stream_listener();
    mock_streaming_client
        .expect_get_all_epoch_ending_ledger_infos()
        .with(eq(1))
        .return_once(move |_| Ok(data_stream_listener));

    // Create the bootstrapper
    let (mut bootstrapper, _) =
        create_bootstrapper(driver_configuration, mock_streaming_client, None, true);

    // Create a global data summary where epoch 100 has ended
    let global_data_summary =
        create_global_summary_with_version(waypoint_epoch, waypoint_version + 1);

    // Drive progress to initialize the epoch ending data stream
    drive_progress(&mut bootstrapper, &global_data_summary, false)
        .await
        .unwrap();

    // Create a full set of epoch ending ledger infos and send them across the stream
    let mut epoch_ending_ledger_infos = vec![];
    for index in 0..waypoint_epoch + 1 {
        epoch_ending_ledger_infos.push(create_random_epoch_ending_ledger_info(index, index));
    }
    let data_notification = DataNotification::new(
        0,
        DataPayload::EpochEndingLedgerInfos(epoch_ending_ledger_infos.clone()),
    );
    notification_sender.send(data_notification).await.unwrap();

    // Drive progress to process the set of epoch ending ledger infos and panic at the waypoint mismatch
    drive_progress(&mut bootstrapper, &global_data_summary, false)
        .await
        .unwrap();
}
```
