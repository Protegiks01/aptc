# Audit Report

## Title
BCS Deserialization Failure Prevents Validator Restart After Consensus Type Schema Evolution

## Summary
The consensus persistent storage recovery mechanism uses `.expect()` on BCS deserialization without version handling or backward compatibility, causing validators to panic and fail to restart if the `Vote` or `TwoChainTimeoutCertificate` struct schemas change between software versions.

## Finding Description

The vulnerability exists in the validator startup recovery path where consensus state is restored from persistent storage. When a validator restarts, it deserializes previously saved `Vote` and `TwoChainTimeoutCertificate` data from the ConsensusDB. [1](#0-0) 

The critical issue is that both `Vote` and `TwoChainTimeoutCertificate` structs derive `Serialize` and `Deserialize` without any versioning mechanism: [2](#0-1) [3](#0-2) 

When the schema of these types changes (field addition, removal, reordering, or type changes), validators that restart with new code cannot deserialize data saved by the old code. The `.expect()` calls cause the validator to panic immediately during the `start()` function, **before** the fallback mechanism can activate.

The fallback mechanism exists but is unreachable in this scenario: [4](#0-3) 

The panic occurs at line 528 or 531 during deserialization, while the fallback only catches errors from `RecoveryData::new()` at line 591. The panic prevents the fallback from ever executing.

**Schema Evolution Scenario:**
1. Validator V1 code saves a `Vote` with fields `[vote_data, author, ledger_info, signature, two_chain_timeout]`
2. Code is updated to V2 where `Vote` adds a new field or reorders existing fields
3. Validator restarts with V2 code
4. Deserialization at line 528: `bcs::from_bytes(&bytes[..])` fails because BCS format doesn't match
5. `.expect("unable to deserialize last vote")` panics
6. Validator cannot start, preventing participation in consensus

This breaks the **liveness invariant** that validators must be able to restart and rejoin consensus.

## Impact Explanation

This qualifies as **HIGH severity** per the Aptos bug bounty program under "Validator node slowdowns" - though more accurately, this completely prevents validator startup rather than merely slowing it down.

**Impact Scope:**
- **Individual Validator Liveness:** Affected validators cannot restart and participate in consensus
- **Network Liveness Risk:** If multiple validators upgrade simultaneously during a coordinated release, a significant portion of the validator set could become unable to restart
- **Recovery Complexity:** Requires manual intervention (deleting consensus DB) to recover, losing consensus state

**Contrast with Protected Types:**
The codebase demonstrates awareness of this issue in other contexts. For example, `OnChainConsensusConfig` uses versioned enums (V1-V5) to handle schema evolution: [5](#0-4) 

Similarly, `WrappedLedgerInfo` explicitly maintains backward compatibility: [6](#0-5) 

However, `Vote` and `TwoChainTimeoutCertificate` lack these protections despite being persisted to storage and loaded during restart.

## Likelihood Explanation

**Likelihood: HIGH** - This will occur whenever:
1. Consensus types are modified as part of protocol evolution (adding features, optimizing structures)
2. Validators perform rolling upgrades with the new code
3. Validators restart (planned maintenance, crashes, deployments)

This is not a theoretical edge case but a **guaranteed failure mode** during legitimate protocol evolution. The Aptos codebase is under active development, and consensus types have evolved (evidenced by features like order votes, validator transactions, DAG consensus variants).

**Historical Evidence:**
The existence of versioned configs and backward compatibility patterns elsewhere in the codebase suggests this issue has been encountered before, but the fix was not applied uniformly to all persistent consensus types.

## Recommendation

Implement versioned enums for persistent consensus types to enable backward-compatible deserialization:

**Option 1: Versioned Enum Wrapper**
```rust
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum Vote {
    V0(VoteV0),
    // Future versions can be added without breaking compatibility
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct VoteV0 {
    vote_data: VoteData,
    author: Author,
    ledger_info: LedgerInfo,
    signature: SignatureWithStatus,
    two_chain_timeout: Option<(TwoChainTimeout, bls12381::Signature)>,
}
```

**Option 2: Graceful Fallback**
Replace `.expect()` with error handling that returns `None` on deserialization failure:
```rust
let last_vote = raw_data
    .0
    .and_then(|bytes| {
        bcs::from_bytes(&bytes[..])
            .map_err(|e| {
                warn!(error = ?e, "Failed to deserialize last vote, ignoring");
                e
            })
            .ok()
    });
```

**Option 3: Storage Migration**
Implement a migration system that detects schema version mismatches and:
- Attempts to migrate old data to new format
- Falls back to clearing stale data if migration fails
- Logs warnings for operators

**Recommended Solution:** Combine Option 1 (for new persistent types) and Option 2 (for immediate fix) to enable both forward compatibility and graceful degradation.

## Proof of Concept

**Rust Reproduction Steps:**

1. **Setup Initial State:**
```rust
// Save a Vote with current schema
let vote = Vote::new(/* ... */);
let db = ConsensusDB::new(path);
db.save_vote(bcs::to_bytes(&vote)?)?;
```

2. **Simulate Schema Change:**
```rust
// Modify consensus-types/src/vote.rs to add a new field:
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Vote {
    vote_data: VoteData,
    author: Author,
    ledger_info: LedgerInfo,
    signature: SignatureWithStatus,
    two_chain_timeout: Option<(TwoChainTimeout, bls12381::Signature)>,
    new_field: u64,  // NEW FIELD ADDED
}
```

3. **Trigger Restart:**
```rust
// Attempt to restart validator with new schema
let storage = StorageWriteProxy::new(&config, aptos_db);
let result = storage.start(order_vote_enabled, window_size);
// Result: PANIC with "unable to deserialize last vote"
```

**Expected Behavior:** Validator panics and cannot start.

**Verification:**
The panic can be verified by examining the code flow:
- [7](#0-6)  saves BCS bytes
- [8](#0-7)  stores raw bytes
- [9](#0-8)  deserializes with `.expect()` causing panic on mismatch

## Notes

This vulnerability represents a **protocol evolution safety issue** rather than a traditional attack vector. However, it poses a real threat to network liveness during upgrades and qualifies as HIGH severity under the bug bounty program's validator availability criteria. The fix is straightforward: apply the same versioning patterns already used elsewhere in the Aptos codebase to consensus persistent storage types.

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L507-509)
```rust
    fn save_vote(&self, vote: &Vote) -> Result<()> {
        Ok(self.db.save_vote(bcs::to_bytes(vote)?)?)
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L526-532)
```rust
        let last_vote = raw_data
            .0
            .map(|bytes| bcs::from_bytes(&bytes[..]).expect("unable to deserialize last vote"));

        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
```

**File:** consensus/src/persistent_liveness_storage.rs (L559-595)
```rust
        match RecoveryData::new(
            last_vote,
            ledger_recovery_data.clone(),
            blocks,
            accumulator_summary.into(),
            quorum_certs,
            highest_2chain_timeout_cert,
            order_vote_enabled,
            window_size,
        ) {
            Ok(mut initial_data) => {
                (self as &dyn PersistentLivenessStorage)
                    .prune_tree(initial_data.take_blocks_to_prune())
                    .expect("unable to prune dangling blocks during restart");
                if initial_data.last_vote.is_none() {
                    self.db
                        .delete_last_vote_msg()
                        .expect("unable to cleanup last vote");
                }
                if initial_data.highest_2chain_timeout_certificate.is_none() {
                    self.db
                        .delete_highest_2chain_timeout_certificate()
                        .expect("unable to cleanup highest 2-chain timeout cert");
                }
                info!(
                    "Starting up the consensus state machine with recovery data - [last_vote {}], [highest timeout certificate: {}]",
                    initial_data.last_vote.as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                    initial_data.highest_2chain_timeout_certificate().as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                );

                LivenessStorageData::FullRecoveryData(initial_data)
            },
            Err(e) => {
                error!(error = ?e, "Failed to construct recovery data");
                LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
            },
        }
```

**File:** consensus/consensus-types/src/vote.rs (L22-34)
```rust
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Vote {
    /// The data of the vote.
    vote_data: VoteData,
    /// The identity of the voter.
    author: Author,
    /// LedgerInfo of a block that is going to be committed in case this vote gathers QC.
    ledger_info: LedgerInfo,
    /// Signature on the LedgerInfo along with a status on whether the signature is verified.
    signature: SignatureWithStatus,
    /// The 2-chain timeout and corresponding signature.
    two_chain_timeout: Option<(TwoChainTimeout, bls12381::Signature)>,
}
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L108-112)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TwoChainTimeoutCertificate {
    timeout: TwoChainTimeout,
    signatures_with_rounds: AggregateSignatureWithRounds,
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L190-213)
```rust
/// The on-chain consensus config, in order to be able to add fields, we use enum to wrap the actual struct.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum OnChainConsensusConfig {
    V1(ConsensusConfigV1),
    V2(ConsensusConfigV1),
    V3 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
    },
    V4 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
        // Execution pool block window
        window_size: Option<u64>,
    },
    V5 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
        // Execution pool block window
        window_size: Option<u64>,
        // Whether to check if we can skip generating randomness for blocks
        rand_check_enabled: bool,
    },
}
```

**File:** consensus/consensus-types/src/wrapped_ledger_info.rs (L14-26)
```rust
/// This struct is similar to QuorumCert, except that the verify function doesn't verify vote_data.
/// This struct is introduced to ensure backward compatibility when upgrading the consensus to use
/// order votes to execute blocks faster. When order votes are enabled, then vote_data and
/// consensus_data_hash inside signed_ledger_info are not used anywhere in the code and can be set
/// to dummy values.
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct WrappedLedgerInfo {
    /// The VoteData here is placeholder for backwards compatibility purpose and should not be used
    /// when order votes are enabled.
    vote_data: VoteData,
    /// The signed LedgerInfo of a committed block that carries the data about the certified block.
    signed_ledger_info: LedgerInfoWithSignatures,
}
```

**File:** consensus/src/consensusdb/schema/single_entry/mod.rs (L59-67)
```rust
impl ValueCodec<SingleEntrySchema> for Vec<u8> {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(self.clone())
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(data.to_vec())
    }
}
```
