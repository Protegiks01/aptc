# Audit Report

## Title
Epoch Mismatch in BlockStore Rebuild Allows Stale Timeout Certificates to Persist

## Summary
The `BlockStore::rebuild()` function bypasses epoch filtering by rolling over the previous timeout certificate instead of using the epoch-filtered certificate from RecoveryData, potentially causing consensus liveness failures when a node performs fast-forward sync.

## Finding Description

The vulnerability exists in the interaction between `RecoveryData` epoch filtering and `BlockStore::rebuild()`:

**Step 1: RecoveryData Properly Filters by Epoch** [1](#0-0) 

When RecoveryData is constructed during fast-forward sync, the timeout certificate is explicitly filtered to only retain certificates matching the current epoch. This is the correct behavior.

**Step 2: RecoveryData.take() Discards the Filtered TC** [2](#0-1) 

The `take()` method returns only `(root, root_metadata, blocks, quorum_certs)` but NOT the epoch-filtered timeout certificate, despite it being available via `highest_2chain_timeout_certificate()`.

**Step 3: rebuild() Rolls Over Stale TC** [3](#0-2) 

During fast-forward sync, `rebuild()` is called with the output of `.take()`. Since the filtered TC was not included, `rebuild()` retrieves the OLD timeout certificate from the current BlockStore without any epoch validation, effectively bypassing the epoch filter.

**Step 4: Usage Path** [4](#0-3) 

The rebuilt BlockStore with the stale TC is then used. When the node attempts to participate in consensus, the stale timeout certificate is passed to safety rules: [5](#0-4) 

**Step 5: Verification Failure** [6](#0-5) [7](#0-6) 

The safety rules verify the timeout certificate against the current epoch's validator set. Since the TC contains signatures from a previous epoch's validators, verification fails if validator sets differ between epochs. [8](#0-7) 

The `verify()` method validates signatures against the provided validator verifier, which would be from the new epoch, causing a mismatch.

## Impact Explanation

This is a **High Severity** issue that causes consensus liveness failures:

1. **Liveness Impact**: Affected nodes cannot construct votes or timeout messages because safety rules reject the stale timeout certificate, preventing consensus participation.

2. **Node Isolation**: Nodes that perform fast-forward sync may become unable to participate in consensus until they restart or the timeout certificate expires from memory.

3. **Validator Impact**: If validator nodes are affected, they cannot fulfill their consensus duties, reducing network security and potentially affecting block production.

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to "Validator node slowdowns" and "Significant protocol violations" - nodes cannot participate in consensus due to the stale certificate.

## Likelihood Explanation

The likelihood is **Medium** because:

**Triggering Conditions:**
- Node falls significantly behind (offline, network partition, or slow sync)
- Node performs fast-forward sync via `sync_to_highest_quorum_cert()`
- Network has progressed far enough that validator sets may have changed
- Node attempts consensus operations before proper epoch transition

**Mitigating Factors:**
- Epoch transitions via `initiate_new_epoch()` create fresh BlockStores that are properly filtered
- Message-level epoch validation may prevent some scenarios
- The vulnerability window may be limited in duration

However, the bug is **definitively present** in the code and violates the design intent where RecoveryData performs explicit epoch filtering.

## Recommendation

**Fix**: Modify `RecoveryData::take()` to include the timeout certificate, and update `rebuild()` to use it:

```rust
// In persistent_liveness_storage.rs
pub fn take(self) -> (RootInfo, RootMetadata, Vec<Block>, Vec<QuorumCert>, Option<TwoChainTimeoutCertificate>) {
    (
        self.root,
        self.root_metadata,
        self.blocks,
        self.quorum_certs,
        self.highest_2chain_timeout_certificate, // Add this
    )
}

// In block_store.rs rebuild()
pub async fn rebuild(
    &self,
    root: RootInfo,
    root_metadata: RootMetadata,
    blocks: Vec<Block>,
    quorum_certs: Vec<QuorumCert>,
    highest_2chain_tc: Option<TwoChainTimeoutCertificate>, // Add parameter
) {
    // ...
    // Remove the rollover logic, use the provided TC instead
    let _ = Self::build(
        root,
        root_metadata,
        blocks,
        quorum_certs,
        highest_2chain_tc.map(Arc::new), // Use filtered TC
        // ... other params
    ).await;
}

// In sync_manager.rs
let (root, root_metadata, blocks, quorum_certs, filtered_tc) = 
    Self::fast_forward_sync(/* ... */).await?.take();
self.rebuild(root, root_metadata, blocks, quorum_certs, filtered_tc).await;
```

## Proof of Concept

This vulnerability manifests through the following sequence:

1. Deploy a test network with epoch N validators
2. Take a node offline while storing a timeout certificate from epoch N
3. Progress the network through epoch changes to epoch N+1 with different validators
4. Bring the offline node back and trigger fast-forward sync
5. Observe that `rebuild()` preserves the epoch N timeout certificate
6. Attempt to construct a vote - safety rules will reject it with `Error::InvalidTimeoutCertificate`
7. Node is unable to participate in consensus

The critical code path showing the bug:
- RecoveryData filters TC by epoch but `.take()` doesn't return it
- `rebuild()` uses old TC from memory instead of filtered version  
- Stale TC fails verification in safety rules when validator sets differ

This violates the consensus liveness invariant where nodes must be able to participate after synchronization.

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L414-417)
```rust
            highest_2chain_timeout_certificate: match highest_2chain_timeout_cert {
                Some(tc) if tc.epoch() == epoch => Some(tc),
                _ => None,
            },
```

**File:** consensus/src/persistent_liveness_storage.rs (L429-435)
```rust
    pub fn take(self) -> (RootInfo, RootMetadata, Vec<Block>, Vec<QuorumCert>) {
        (
            self.root,
            self.root_metadata,
            self.blocks,
            self.quorum_certs,
        )
```

**File:** consensus/src/block_storage/block_store.rs (L370-373)
```rust
        // Rollover the previous highest TC from the old tree to the new one.
        let prev_2chain_htc = self
            .highest_2chain_timeout_cert()
            .map(|tc| tc.as_ref().clone());
```

**File:** consensus/src/block_storage/sync_manager.rs (L313-314)
```rust
        self.rebuild(root, root_metadata, blocks, quorum_certs)
            .await;
```

**File:** consensus/src/round_manager.rs (L1520-1523)
```rust
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L62-64)
```rust
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L180-187)
```rust
    fn verify_tc(&self, tc: &TwoChainTimeoutCertificate) -> Result<(), Error> {
        let epoch_state = self.epoch_state()?;

        if !self.skip_sig_verify {
            tc.verify(&epoch_state.verifier)
                .map_err(|e| Error::InvalidTimeoutCertificate(e.to_string()))?;
        }
        Ok(())
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L141-168)
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
```
