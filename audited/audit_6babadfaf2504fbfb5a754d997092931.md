# Audit Report

## Title
Race Condition in sync_info() Leading to Invalid SyncInfo and Proposal Rejection

## Summary
The `sync_info()` function in `BlockStore` acquires read locks separately for each certificate field, creating a TOCTOU race condition where concurrent BlockTree updates can produce a SyncInfo with violated invariants. This causes validators' proposals and votes to be rejected by peers, potentially causing temporary liveness issues.

## Finding Description

The `sync_info()` function constructs a `SyncInfo` object by making four separate read lock acquisitions on the internal `BlockTree`. [1](#0-0) 

Each call to `highest_quorum_cert()`, `highest_ordered_cert()`, `highest_commit_cert()`, and `highest_2chain_timeout_cert()` independently acquires and releases the read lock. [2](#0-1) 

Between these lock acquisitions, another thread can acquire the write lock and modify the `BlockTree` state. For example, `insert_quorum_cert` can update both `highest_quorum_cert` and `highest_ordered_cert`. [3](#0-2) 

The `insert_ordered_cert` method can independently update `highest_ordered_cert`. [4](#0-3) 

The `commit_callback` method can update `highest_commit_cert` through `update_highest_commit_cert`. [5](#0-4) [6](#0-5) 

This race condition can violate critical SyncInfo invariants enforced by `SyncInfo::verify()`, specifically that HQC.round >= HOC.round and HOC.round >= HCC.round. [7](#0-6) 

**Race Scenario:**
1. Thread A calls `sync_info()`, reads HQC (round 100)
2. Thread B acquires write lock, calls `insert_ordered_cert(round 105)`, updates HOC to 105
3. Thread A reads HOC (round 105)
4. Result: SyncInfo with HQC(100), HOC(105) — violating invariant HQC.round ≥ HOC.round

When this invalid SyncInfo is sent to peers in proposals or votes [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10) , receiving validators verify the SyncInfo. [12](#0-11) 

The verification fails and logs a security event, causing the proposal to be rejected. [13](#0-12) [14](#0-13) 

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria.

This vulnerability causes **temporary liveness degradation**, which aligns with the Medium severity category of "Limited Protocol Violations: Temporary liveness issues."

While this bug does **not** cause validators to request wrong blocks (the verification prevents that), it does cause:
- **Temporary liveness degradation**: When the leader generates invalid SyncInfo, its proposals are rejected by all validators, requiring a round timeout
- **Reduced validator effectiveness**: Affected validators' votes and proposals are ignored
- **Network slowdown**: Under high load when the race is more likely, multiple validators may generate invalid messages

However, this is **not** a critical issue because:
- Consensus safety is maintained (verification prevents use of invalid SyncInfo)
- Network does not permanently stall (other validators can still propose)
- Self-limiting (affects only the validator with the race, not the entire network)

## Likelihood Explanation

**Likelihood: Low to Medium** depending on network conditions.

The race requires:
- Concurrent BlockStore modifications during `sync_info()` execution
- Specific timing window (between read lock acquisitions, typically microseconds)
- Active block processing and QC insertion

More likely during:
- Heavy network load with many concurrent block insertions
- Fast forward sync operations
- Epoch transitions with rapid certificate updates

Less likely during:
- Steady state with infrequent block updates
- Low transaction volume

The race can occur naturally during normal validator operation without any malicious actor, as it results from legitimate concurrent access patterns.

## Recommendation

Fix the race condition by acquiring the read lock once and reading all certificate values atomically. Add a method to `BlockTree` that returns all certificates in a single lock acquisition:

```rust
// In BlockTree
pub(super) fn get_sync_info_data(&self) -> (Arc<QuorumCert>, Arc<WrappedLedgerInfo>, Arc<WrappedLedgerInfo>, Option<Arc<TwoChainTimeoutCertificate>>) {
    (
        Arc::clone(&self.highest_quorum_cert),
        Arc::clone(&self.highest_ordered_cert),
        Arc::clone(&self.highest_commit_cert),
        self.highest_2chain_timeout_cert.clone(),
    )
}

// In BlockStore
fn sync_info(&self) -> SyncInfo {
    let (hqc, hoc, hcc, htc) = self.inner.read().get_sync_info_data();
    SyncInfo::new_decoupled(
        hqc.as_ref().clone(),
        hoc.as_ref().clone(),
        hcc.as_ref().clone(),
        htc.map(|tc| tc.as_ref().clone()),
    )
}
```

This ensures all certificate values are read atomically under a single lock acquisition, preventing the TOCTOU race condition.

## Proof of Concept

While a full PoC would require a complex multi-threaded test environment simulating concurrent consensus operations, the vulnerability is evident from the code structure. The separate lock acquisitions in `sync_info()` combined with concurrent write operations that modify the certificates create a clear TOCTOU race window that can violate SyncInfo invariants during normal validator operation.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L664-678)
```rust
    fn highest_quorum_cert(&self) -> Arc<QuorumCert> {
        self.inner.read().highest_quorum_cert()
    }

    fn highest_ordered_cert(&self) -> Arc<WrappedLedgerInfo> {
        self.inner.read().highest_ordered_cert()
    }

    fn highest_commit_cert(&self) -> Arc<WrappedLedgerInfo> {
        self.inner.read().highest_commit_cert()
    }

    fn highest_2chain_timeout_cert(&self) -> Option<Arc<TwoChainTimeoutCertificate>> {
        self.inner.read().highest_2chain_timeout_cert()
    }
```

**File:** consensus/src/block_storage/block_store.rs (L680-688)
```rust
    fn sync_info(&self) -> SyncInfo {
        SyncInfo::new_decoupled(
            self.highest_quorum_cert().as_ref().clone(),
            self.highest_ordered_cert().as_ref().clone(),
            self.highest_commit_cert().as_ref().clone(),
            self.highest_2chain_timeout_cert()
                .map(|tc| tc.as_ref().clone()),
        )
    }
```

**File:** consensus/src/block_storage/block_store.rs (L907-922)
```rust
    pub(crate) fn commit_callback(
        &self,
        block_id: HashValue,
        block_round: Round,
        commit_proof: WrappedLedgerInfo,
        window_size: Option<u64>,
    ) {
        self.inner.write().commit_callback(
            self.storage.clone(),
            block_id,
            block_round,
            commit_proof.clone(),
            commit_proof.ledger_info().clone(),
            window_size.or(self.window_size),
        )
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L341-346)
```rust
    fn update_highest_commit_cert(&mut self, new_commit_cert: WrappedLedgerInfo) {
        if new_commit_cert.commit_info().round() > self.highest_commit_cert.commit_info().round() {
            self.highest_commit_cert = Arc::new(new_commit_cert);
            self.update_commit_root(self.highest_commit_cert.commit_info().id());
        }
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L349-386)
```rust
    pub(super) fn insert_quorum_cert(&mut self, qc: QuorumCert) -> anyhow::Result<()> {
        let block_id = qc.certified_block().id();
        let qc = Arc::new(qc);

        // Safety invariant: For any two quorum certificates qc1, qc2 in the block store,
        // qc1 == qc2 || qc1.round != qc2.round
        // The invariant is quadratic but can be maintained in linear time by the check
        // below.
        precondition!({
            let qc_round = qc.certified_block().round();
            self.id_to_quorum_cert.values().all(|x| {
                (*(*x).ledger_info()).ledger_info().consensus_data_hash()
                    == (*(*qc).ledger_info()).ledger_info().consensus_data_hash()
                    || x.certified_block().round() != qc_round
            })
        });

        match self.get_block(&block_id) {
            Some(block) => {
                if block.round() > self.highest_certified_block().round() {
                    self.highest_certified_block_id = block.id();
                    self.highest_quorum_cert = Arc::clone(&qc);
                }
            },
            None => bail!("Block {} not found", block_id),
        }

        self.id_to_quorum_cert
            .entry(block_id)
            .or_insert_with(|| Arc::clone(&qc));

        if self.highest_ordered_cert.commit_info().round() < qc.commit_info().round() {
            // Question: We are updating highest_ordered_cert but not highest_ordered_root. Is that fine?
            self.highest_ordered_cert = Arc::new(qc.into_wrapped_ledger_info());
        }

        Ok(())
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L388-392)
```rust
    pub fn insert_ordered_cert(&mut self, ordered_cert: WrappedLedgerInfo) {
        if ordered_cert.commit_info().round() > self.highest_ordered_cert.commit_info().round() {
            self.highest_ordered_cert = Arc::new(ordered_cert);
        }
    }
```

**File:** consensus/consensus-types/src/sync_info.rs (L152-165)
```rust
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
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L14-25)
```rust
pub struct ProposalMsg {
    proposal: Block,
    sync_info: SyncInfo,
}

impl ProposalMsg {
    /// Creates a new proposal.
    pub fn new(proposal: Block, sync_info: SyncInfo) -> Self {
        Self {
            proposal,
            sync_info,
        }
```

**File:** consensus/consensus-types/src/vote_msg.rs (L15-36)
```rust
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct VoteMsg {
    /// The container for the vote (VoteData, LedgerInfo, Signature)
    vote: Vote,
    /// Sync info carries information about highest QC, TC and LedgerInfo
    sync_info: SyncInfo,
}

impl Display for VoteMsg {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "VoteMsg: [{}], SyncInfo: [{}]",
            self.vote, self.sync_info
        )
    }
}

impl VoteMsg {
    pub fn new(vote: Vote, sync_info: SyncInfo) -> Self {
        Self { vote, sync_info }
    }
```

**File:** consensus/src/round_manager.rs (L491-491)
```rust
            let sync_info = self.block_store.sync_info();
```

**File:** consensus/src/round_manager.rs (L743-750)
```rust
        let in_correct_round = self
            .ensure_round_and_sync_up(
                proposal_msg.proposal().round(),
                proposal_msg.sync_info(),
                proposal_msg.proposer(),
            )
            .await
            .context("[RoundManager] Process proposal")?;
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

**File:** consensus/src/round_manager.rs (L1401-1401)
```rust
        let vote_msg = VoteMsg::new(vote.clone(), self.block_store.sync_info());
```
