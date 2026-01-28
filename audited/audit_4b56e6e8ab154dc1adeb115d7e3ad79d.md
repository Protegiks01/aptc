# Audit Report

## Title
Missing fsync() in OnDiskStorage Causes Safety State Loss and Consensus Equivocation

## Summary
The `OnDiskStorage` backend for `PersistentSafetyStorage` does not call `fsync()` after writing safety-critical consensus state to disk. This creates a vulnerability window where validator crashes can cause loss of `last_voted_round` and other safety data, enabling double-voting (equivocation) that breaks consensus safety guarantees.

## Finding Description

The vulnerability exists in the persistence layer used by SafetyRules for storing consensus safety state. When a validator votes on a block proposal, the following critical sequence occurs:

**1. Vote Processing Path:**
The validator's voting logic is implemented in `guarded_construct_and_sign_vote_two_chain`, which processes vote proposals and updates safety state. [1](#0-0) 

**2. Safety Data Structure:**
The `SafetyData` struct contains consensus-critical fields including `last_voted_round`, which enforces the fundamental rule that a validator cannot vote twice for the same round. [2](#0-1) 

**3. Persistence Layer:**
The voting method calls `set_safety_data` to persist the updated safety state before returning the vote response. [3](#0-2) 

**4. Critical Bug - Missing fsync():**
When using `OnDiskStorage`, the write operation creates a temporary file, writes data, and renames it to the target file **without calling fsync()**. The data may remain in OS write buffers and can be lost on crash. [4](#0-3) 

**5. Production Configuration Exposure:**
Despite README warnings, `OnDiskStorage` is configured in shipped deployment templates including Docker Compose configurations. [5](#0-4) 

And Helm chart base configurations for validator deployments. [6](#0-5) 

**6. Insufficient Protection:**
The configuration sanitizer only prohibits `InMemoryStorage` for mainnet validators but does NOT prevent `OnDiskStorage` usage, despite its lack of durability guarantees. [7](#0-6) 

**7. Documentation Warning:**
While the README warns against production use, this is insufficient protection given that deployment configurations ship with OnDiskStorage enabled. [8](#0-7) 

**Vulnerability Window:**
If the validator process crashes or experiences power loss after the write() call returns but before the OS flushes file buffers (typically within 30 seconds on default Linux settings), the safety state update is permanently lost. Upon restart, the validator loads stale safety data with a lower `last_voted_round` value, allowing it to vote again for a round it already voted on with potentially different vote content—this is equivocation.

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violations per Aptos Bug Bounty - up to $1,000,000)

This vulnerability breaks the **Consensus Safety** invariant by enabling equivocation:

1. **Double-Voting**: A validator can produce two different votes for the same round with different block hashes, violating the fundamental BFT safety assumption

2. **Conflicting Quorum Certificates**: Equivocation can lead to multiple valid QCs for the same round, enabling blockchain forks

3. **BFT Safety Violation**: The AptosBFT consensus protocol's safety guarantee assumes validators cannot equivocate under non-Byzantine failures; this bug violates that assumption through a reliability issue that becomes a security vulnerability

4. **Network Split Risk**: Different validators may commit different blocks at the same height, requiring manual intervention or coordination to recover consensus

The vulnerability affects any validator deployment using the shipped Docker Compose or Helm chart configurations. Even a single equivocating validator can compromise consensus safety by contributing to conflicting quorum certificates, though the full network impact depends on Byzantine fault tolerance thresholds.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability has deterministic triggers that are inevitable over time:

**Triggering Conditions:**
- Validator configured with `OnDiskStorage` backend (present in default deployment configurations)
- Process crash, kernel panic, or power loss during vulnerability window (microseconds to 30 seconds)
- Window exists between write() returning and OS actually flushing dirty buffers to persistent storage

**Probability Factors:**
- Operating systems typically flush dirty buffers within 30 seconds (Linux default `dirty_expire_centisecs`)
- Validators experience crashes due to OOM conditions, software panics, hardware failures, or operational procedures
- With hundreds of validators running 24/7, the probability of at least one crash during a vulnerability window approaches certainty over time
- The vulnerability is **deterministic** - any crash during the window guarantees state loss and potential equivocation

**Real-World Scenarios:**
- Kubernetes pod eviction/preemption during resource pressure
- Out-of-memory kills from memory leaks or spikes
- Hardware failures (power supply, storage controller, memory errors)
- Kernel panics from driver bugs or system issues
- Forced shutdowns during maintenance windows or emergency procedures

## Recommendation

**Immediate Fixes:**

1. **Add fsync() to OnDiskStorage:** Modify the `write()` method to call `file.sync_all()` before the rename operation to ensure data is durably persisted:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?;  // ADD THIS LINE
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

2. **Update Configuration Sanitizer:** Extend the sanitizer to prohibit OnDiskStorage for mainnet validators, similar to the existing InMemoryStorage check:

```rust
if chain_id.is_mainnet()
    && node_type.is_validator()
    && (safety_rules_config.backend.is_in_memory() 
        || matches!(safety_rules_config.backend, SecureBackend::OnDiskStorage(_)))
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "OnDiskStorage lacks durability guarantees and must not be used in mainnet!".to_string(),
    ));
}
```

3. **Update Default Configurations:** Change Docker Compose and Helm chart templates to use Vault backend by default, or add prominent warnings if OnDiskStorage is intentionally used for testing.

## Proof of Concept

The vulnerability is triggered by the following sequence (conceptual - requires actual validator deployment):

1. Deploy validator using Docker Compose or Helm chart with default OnDiskStorage configuration
2. Wait for validator to process vote proposals and update safety state
3. Send SIGKILL to validator process during the vulnerability window (within 30 seconds of a vote)
4. Restart validator and observe that it loads stale `last_voted_round` from disk
5. Send another vote proposal for the same round with different block data
6. Validator will vote again on the same round, creating an equivocation that violates consensus safety

The deterministic nature of the bug (missing fsync) means this can be demonstrated in any deployment using OnDiskStorage, though the exact timing requires careful orchestration or repeated attempts to hit the vulnerability window.

---

**Notes:**

This vulnerability represents a critical gap between documented limitations and actual code enforcement. While the README warns against production use of OnDiskStorage, the fact that:
- Default deployment configurations use it
- The code sanitizer doesn't prevent it
- No fsync() ensures durability

Creates a dangerous situation where validators deployed using standard configurations are vulnerable to consensus safety violations through ordinary process crashes. The impact is amplified because equivocation is one of the most severe consensus violations in BFT protocols, potentially requiring complex recovery procedures or network coordination to resolve.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L53-95)
```rust
    pub(crate) fn guarded_construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<Vote, Error> {
        // Exit early if we cannot sign
        self.signer()?;

        let vote_data = self.verify_proposal(vote_proposal)?;
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
        let proposed_block = vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
        // Construct and sign vote
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;

        Ok(vote)
    }
```

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L150-170)
```rust
    pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
        let _timer = counters::start_timer("set", SAFETY_DATA);
        counters::set_state(counters::EPOCH, data.epoch as i64);
        counters::set_state(counters::LAST_VOTED_ROUND, data.last_voted_round as i64);
        counters::set_state(
            counters::HIGHEST_TIMEOUT_ROUND,
            data.highest_timeout_round as i64,
        );
        counters::set_state(counters::PREFERRED_ROUND, data.preferred_round as i64);

        match self.internal_store.set(SAFETY_DATA, data.clone()) {
            Ok(_) => {
                self.cached_safety_data = Some(data);
                Ok(())
            },
            Err(error) => {
                self.cached_safety_data = None;
                Err(Error::SecureStorageUnexpectedError(error.to_string()))
            },
        }
    }
```

**File:** secure/storage/src/on_disk.rs (L16-22)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
```

**File:** secure/storage/src/on_disk.rs (L64-70)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** docker/compose/aptos-node/validator.yaml (L7-13)
```yaml
consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L10-17)
```yaml
consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
```

**File:** config/src/config/safety_rules_config.rs (L85-96)
```rust
        if let Some(chain_id) = chain_id {
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }
```
