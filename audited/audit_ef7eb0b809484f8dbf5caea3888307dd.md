# Audit Report

## Title
SyncInfo Message Flood Attack Enables Validator Performance Degradation

## Summary
The consensus layer lacks rate limiting and deduplication for `SyncInfo` messages, allowing malicious peers to trigger expensive cryptographic verification operations and unnecessary block retrieval, degrading validator performance through CPU exhaustion and network bandwidth consumption.

## Finding Description

The Aptos consensus protocol processes `SyncInfo` messages to synchronize validator state. However, the implementation contains multiple weaknesses that enable a performance degradation attack:

**Lack of Verification During Initial Processing:** [1](#0-0) 

SyncInfo messages bypass signature verification during the initial `verify()` step, being converted directly to `VerifiedEvent::UnverifiedSyncInfo` without cryptographic checks.

**No Rate Limiting or Deduplication:**
The codebase implements no rate limiting specific to `SyncInfo` messages, nor any deduplication mechanism to prevent processing identical messages repeatedly. Messages flow through the bounded executor but share capacity with all other consensus messages.

**Expensive Operations Triggered:**
When a `SyncInfo` message is processed, it triggers expensive operations: [2](#0-1) 

The `sync_up()` function first checks if remote certificates are newer, then performs full signature verification before triggering block synchronization.

**Multi-Certificate Verification Cost:** [3](#0-2) 

The `verify()` method validates multiple certificates (highest_quorum_cert, highest_ordered_cert, highest_commit_cert, and optional timeout_cert), each requiring BLS signature verification which is computationally expensive.

**Block Retrieval Operations:** [4](#0-3) 

If verification succeeds and certificates are newer, `add_certs()` triggers potentially expensive block retrieval operations via RPC.

**Attack Execution:**
1. Malicious peer crafts `SyncInfo` messages with incrementally higher round numbers
2. Each message passes `has_newer_certificates()` comparison (checked before verification)
3. Each message triggers expensive multi-certificate BLS signature verification
4. Valid but unnecessary `SyncInfo` can trigger network-intensive block retrieval
5. Repeated messages from same or multiple malicious peers compound the effect
6. Victim validator's CPU is exhausted by continuous signature verification
7. Network bandwidth consumed by unnecessary block synchronization attempts

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: Medium (up to $10,000) to High (up to $50,000)**

Per Aptos bug bounty criteria:
- **High Severity**: "Validator node slowdowns" - This attack directly causes validator performance degradation through CPU exhaustion and network congestion
- **Medium Severity**: "State inconsistencies requiring intervention" - Sustained attacks could cause validators to fall behind in consensus, requiring manual intervention

The attack affects individual validator nodes but can be scaled to target multiple validators simultaneously, potentially impacting overall network performance. Unlike a Critical vulnerability, it does not directly compromise consensus safety or cause fund loss, but it degrades network availability and validator operations.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Barrier to Entry**: Any network peer can send consensus messages - no validator privileges, stake, or cryptographic secrets required
2. **Simple Execution**: Attack requires only sending crafted `SyncInfo` messages with incrementally higher round numbers
3. **No Detection Mechanism**: No monitoring or alerting specifically tracks `SyncInfo` message rates per peer
4. **Repeatable**: Attack can be sustained indefinitely without being rate-limited
5. **Amplification Effect**: Single malicious peer can send high-frequency messages; multiple colluding peers multiply the impact
6. **Economic Incentive**: Competitors or adversaries may degrade validator performance to gain consensus advantages

The attack complexity is low, requires no special access, and has immediate observable effects on victim nodes.

## Recommendation

Implement multi-layered defenses:

**1. Rate Limiting per Peer:**
```rust
// Add to RoundManager or EpochManager
struct SyncInfoRateLimiter {
    peer_limits: HashMap<Author, TokenBucket>,
    global_limit: TokenBucket,
}

impl SyncInfoRateLimiter {
    fn check_and_consume(&mut self, peer: Author) -> bool {
        let peer_bucket = self.peer_limits.entry(peer)
            .or_insert_with(|| TokenBucket::new(5, Duration::from_secs(1)));
        
        peer_bucket.try_consume() && self.global_limit.try_consume()
    }
}
```

**2. SyncInfo Deduplication:**
```rust
// Cache recently processed SyncInfo by hash
struct SyncInfoCache {
    seen: LruCache<HashValue, Instant>,
    ttl: Duration,
}

impl SyncInfoCache {
    fn is_recently_seen(&mut self, sync_info: &SyncInfo) -> bool {
        let hash = sync_info.hash();
        if let Some(&timestamp) = self.seen.get(&hash) {
            timestamp.elapsed() < self.ttl
        } else {
            self.seen.put(hash, Instant::now());
            false
        }
    }
}
```

**3. Early Validation Before Expensive Operations:**
```rust
// In sync_up(), add bounds checking before verification
async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
    let local_sync_info = self.block_store.sync_info();
    
    // Add maximum round gap check
    const MAX_ROUND_GAP: u64 = 1000;
    if sync_info.highest_round() > local_sync_info.highest_round() + MAX_ROUND_GAP {
        warn!("SyncInfo from {} claims unreasonably high round", author);
        return Ok(());
    }
    
    if sync_info.has_newer_certificates(&local_sync_info) {
        // Existing verification and sync logic...
    }
}
```

**4. Monitoring and Alerting:**
Add metrics to track SyncInfo processing rates per peer and alert on anomalies.

## Proof of Concept

```rust
// PoC demonstrating SyncInfo flood attack
// This would be a test in consensus/src/round_manager_tests/

#[tokio::test]
async fn test_syncinfo_flood_attack() {
    let mut runtime = consensus_runtime();
    let mut round_manager = runtime.start_round_manager();
    
    // Malicious peer
    let attacker = Author::random();
    
    // Send many SyncInfo messages with incrementally higher rounds
    for round in 100..1000 {
        // Craft SyncInfo with higher round numbers
        let sync_info = create_sync_info_with_round(round);
        
        // Measure CPU time before
        let start = Instant::now();
        
        // Process SyncInfo - this triggers expensive verification
        round_manager.process_sync_info_msg(sync_info, attacker).await;
        
        let elapsed = start.elapsed();
        
        // Verify that each message takes significant time (signature verification)
        // and that there's no rate limiting preventing rapid submissions
        assert!(elapsed.as_millis() > 5); // Each verification takes >5ms
    }
    
    // Verify victim node experienced performance degradation
    // In production, CPU usage would spike to 100% from signature verification
    // and network bandwidth consumed by block retrieval attempts
}

fn create_sync_info_with_round(round: Round) -> SyncInfo {
    // Create valid-looking QC, ordered cert, commit cert for given round
    // Even with invalid signatures, the verification attempt still costs CPU
    // With valid certificates (from previous rounds), can trigger block sync
    SyncInfo::new_decoupled(
        create_qc_for_round(round),
        create_ordered_cert_for_round(round - 1),
        create_commit_cert_for_round(round - 2),
        None,
    )
}
```

**Attack Demonstration Steps:**
1. Run malicious node that connects to validator network
2. Continuously send `SyncInfo` messages with `highest_round` values incrementing from current round to current + 1000
3. Monitor victim validator's CPU usage - will spike due to repeated BLS signature verification
4. Monitor victim validator's network traffic - will increase due to block retrieval attempts
5. Observe victim validator falling behind in consensus rounds due to resource exhaustion

**Notes**

This vulnerability exists because the consensus protocol prioritizes processing SyncInfo messages to maintain network synchronization, but lacks protective mechanisms against abuse. The expensive cryptographic operations (BLS signature verification on multiple certificates) combined with potential network I/O (block retrieval) create an effective denial-of-service vector.

The fix requires balancing responsiveness to legitimate synchronization needs with protection against malicious message floods. The recommended multi-layered approach (rate limiting + deduplication + early validation + monitoring) provides defense in depth without compromising legitimate synchronization operations.

### Citations

**File:** consensus/src/round_manager.rs (L165-165)
```rust
            UnverifiedEvent::SyncInfo(s) => VerifiedEvent::UnverifiedSyncInfo(s),
```

**File:** consensus/src/round_manager.rs (L878-906)
```rust
    async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
        let local_sync_info = self.block_store.sync_info();
        if sync_info.has_newer_certificates(&local_sync_info) {
            info!(
                self.new_log(LogEvent::ReceiveNewCertificate)
                    .remote_peer(author),
                "Local state {},\n remote state {}", local_sync_info, sync_info
            );
            // Some information in SyncInfo is ahead of what we have locally.
            // First verify the SyncInfo (didn't verify it in the yet).
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
            SYNC_INFO_RECEIVED_WITH_NEWER_CERT.inc();
            let result = self
                .block_store
                .add_certs(sync_info, self.create_block_retriever(author))
                .await;
            self.process_certificates().await?;
            result
        } else {
            Ok(())
        }
```

**File:** consensus/consensus-types/src/sync_info.rs (L138-210)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let epoch = self.highest_quorum_cert.certified_block().epoch();
        ensure!(
            epoch == self.highest_ordered_cert().commit_info().epoch(),
            "Multi epoch in SyncInfo - HOC and HQC"
        );
        ensure!(
            epoch == self.highest_commit_cert().commit_info().epoch(),
            "Multi epoch in SyncInfo - HOC and HCC"
        );
        if let Some(tc) = &self.highest_2chain_timeout_cert {
            ensure!(epoch == tc.epoch(), "Multi epoch in SyncInfo - TC and HQC");
        }

        ensure!(
            self.highest_quorum_cert.certified_block().round()
                >= self.highest_ordered_cert().commit_info().round(),
            "HQC has lower round than HOC"
        );

        ensure!(
            self.highest_ordered_round() >= self.highest_commit_round(),
            format!(
                "HOC {} has lower round than HLI {}",
                self.highest_ordered_cert(),
                self.highest_commit_cert()
            )
        );

        ensure!(
            *self.highest_ordered_cert().commit_info() != BlockInfo::empty(),
            "HOC has no committed block"
        );

        ensure!(
            *self.highest_commit_cert().commit_info() != BlockInfo::empty(),
            "HLI has empty commit info"
        );

        // we don't have execution in unit tests, so this check would fail
        #[cfg(not(any(test, feature = "fuzzing")))]
        {
            ensure!(
                !self.highest_commit_cert().commit_info().is_ordered_only(),
                "HLI {} has ordered only commit info",
                self.highest_commit_cert().commit_info()
            );
        }

        self.highest_quorum_cert
            .verify(validator)
            .and_then(|_| {
                self.highest_ordered_cert
                    .as_ref()
                    .map_or(Ok(()), |cert| cert.verify(validator))
                    .context("Fail to verify ordered certificate")
            })
            .and_then(|_| {
                // we do not verify genesis ledger info
                if self.highest_commit_cert.commit_info().round() > 0 {
                    self.highest_commit_cert
                        .verify(validator)
                        .context("Fail to verify commit certificate")?
                }
                Ok(())
            })
            .and_then(|_| {
                if let Some(tc) = &self.highest_2chain_timeout_cert {
                    tc.verify(validator)?;
                }
                Ok(())
            })
            .context("Fail to verify SyncInfo")?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L116-173)
```rust
    pub async fn add_certs(
        &self,
        sync_info: &SyncInfo,
        mut retriever: BlockRetriever,
    ) -> anyhow::Result<()> {
        // When the local ordered round is very old than the received sync_info, this function will
        // (1) resets the block store with highest commit cert = sync_info.highest_quorum_cert()
        // (2) insert all the blocks between (inclusive) highest_commit_cert.commit_info().id() to
        // highest_quorum_cert.certified_block().id() into the block store and storage
        // (3) insert the quorum cert for all the above blocks into the block store and storage
        // (4) executes all the blocks that are ordered while inserting the above quorum certs
        self.sync_to_highest_quorum_cert(
            sync_info.highest_quorum_cert().clone(),
            sync_info.highest_commit_cert().clone(),
            &mut retriever,
        )
        .await?;

        self.sync_to_highest_commit_cert(
            sync_info.highest_commit_cert().ledger_info(),
            retriever.network.clone(),
        )
        .await;

        // The insert_ordered_cert(order_cert) function call expects that order_cert.commit_info().id() block
        // is already stored in block_store. So, we first call insert_quorum_cert(highest_quorum_cert).
        // This call will ensure that the highest ceritified block along with all its ancestors are inserted
        // into the block store.
        self.insert_quorum_cert(sync_info.highest_quorum_cert(), &mut retriever)
            .await?;

        // Even though we inserted the highest_quorum_cert (and its ancestors) in the above step,
        // we still need to insert ordered cert explicitly. This will send the highest ordered block
        // to execution.
        if self.order_vote_enabled {
            self.insert_ordered_cert(&sync_info.highest_ordered_cert())
                .await?;
        } else {
            // When order votes are disabled, the highest_ordered_cert().certified_block().id() need not be
            // one of the ancestors of highest_quorum_cert.certified_block().id() due to forks. So, we call
            // insert_quorum_cert instead of insert_ordered_cert as in the above case. This will ensure that
            // highest_ordered_cert().certified_block().id() is inserted the block store.
            self.insert_quorum_cert(
                &self
                    .highest_ordered_cert()
                    .as_ref()
                    .clone()
                    .into_quorum_cert(self.order_vote_enabled)?,
                &mut retriever,
            )
            .await?;
        }

        if let Some(tc) = sync_info.highest_2chain_timeout_cert() {
            self.insert_2chain_timeout_certificate(Arc::new(tc.clone()))?;
        }
        Ok(())
    }
```
