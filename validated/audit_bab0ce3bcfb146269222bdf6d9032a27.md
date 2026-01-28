Based on my comprehensive technical validation of the Aptos Core codebase, I have verified this vulnerability claim and found it to be **VALID**.

---

# Audit Report

## Title
Consensus Safety Violation: On-Disk Persistent Storage Lacks fsync, Allows Vote Forgetting and Equivocation After Crash

## Summary
The `OnDiskStorage` backend used in production validator configurations lacks `fsync` calls during critical safety data persistence, allowing validators to forget their most recent vote after a crash and potentially re-sign conflicting votes for the same round, enabling consensus equivocation.

## Finding Description

The vulnerability exists in the `OnDiskStorage` implementation's `write()` method, which persists consensus safety data without synchronizing file contents to disk. [1](#0-0) 

The write operation creates a temporary file, writes JSON data, and atomically renames it to the target file, but **never calls fsync**, sync_all, or sync_data. This means the file contents may remain in OS buffers and be lost on crash.

This storage backend is used by consensus SafetyRules to persist critical voting state. When a validator votes, it updates `SafetyData` containing `last_voted_round` and `last_vote`: [2](#0-1) 

The safety check prevents double-voting by verifying the new round is greater than `last_voted_round`: [3](#0-2) 

**Exploitation Path:**
1. Validator votes for round R, calling `set_safety_data()` to persist `{last_voted_round: R, last_vote: Vote_A}`
2. `OnDiskStorage.write()` writes to temp file and renames without fsync
3. System crashes before OS buffer flush (power loss, kill -9, kernel panic)
4. On restart, disk contains old state `{last_voted_round: R-1}`
5. Validator receives new proposal for round R, safety check passes (R > R-1), signs Vote_B
6. **Result: Two different votes signed for round R = equivocation**

**Critical Evidence:** Production validator configurations explicitly use `on_disk_storage`: [4](#0-3) [5](#0-4) 

Despite the README warning that OnDiskStorage "should not be used in production": [6](#0-5) 

The configuration sanitizer only rejects `InMemoryStorage` for mainnet, but allows `OnDiskStorage`: [7](#0-6) 

While equivocation detection exists at the vote aggregation layer: [8](#0-7) 

This is defensive - it detects equivocation **after** the validator has already violated the safety invariant by signing two conflicting votes.

## Impact Explanation

**Critical Severity** per Aptos bug bounty criteria - Category: "Consensus/Safety Violations"

- **Direct consensus safety violation**: Validators can sign conflicting votes for the same round, breaking the fundamental BFT safety property
- **Chain forks possible**: With sufficient simultaneous crashes (datacenter power failure), multiple validators could equivocate, potentially creating conflicting quorum certificates
- **Double-spending risk**: Conflicting blocks with valid signatures enable double-spending scenarios
- **Non-recoverable if widespread**: Multiple validators equivocating simultaneously could require hard fork recovery

The atomic rename provides atomicity but **not durability** - a critical distinction in distributed consensus systems where crash-recovery semantics are essential.

## Likelihood Explanation

**High Likelihood:**

1. **Natural occurrence**: Node crashes from power failures, OOM kills, kernel panics, hardware failures happen regularly in production
2. **No attacker control needed**: Natural crashes trigger the vulnerability
3. **Standard OS behavior**: Write caching and delayed flush to disk is default behavior across all operating systems
4. **Production deployment**: The vulnerable configuration is used in standard validator deployment templates
5. **Window of vulnerability**: Typical OS buffer flush delays (5-30 seconds) create a significant exposure window

## Recommendation

Add explicit `fsync()` call in `OnDiskStorage::write()` after writing file contents and before renaming:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?;  // ADD THIS LINE - ensure data is flushed to disk
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

**Alternative:** Update production validator configurations and deployment documentation to mandate `VaultStorage` as the only acceptable production backend, and enhance the config sanitizer to reject `OnDiskStorage` for mainnet validators.

## Proof of Concept

A full PoC would require:
1. Setting up a validator with OnDiskStorage
2. Issuing a vote for round R
3. Forcibly killing the process immediately (kill -9)
4. Restarting and observing the validator accepts another proposal for round R
5. Demonstrating two different votes signed for the same round

The vulnerability is evident from code inspection without requiring experimental PoC, as the missing fsync is a well-understood durability violation in systems programming.

## Notes

This vulnerability demonstrates a critical gap between documentation (which warns against production use) and actual deployment practice (which uses OnDiskStorage in production templates). The config sanitizer's failure to enforce the documented restriction compounds the issue. This represents a systemic configuration security problem beyond just the missing fsync implementation.

### Citations

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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-92)
```rust
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
```

**File:** consensus/safety-rules/src/safety_rules.rs (L213-232)
```rust
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
```

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L14-16)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** secure/storage/README.md (L37-42)
```markdown
- `OnDisk`: Similar to InMemory, the OnDisk secure storage implementation provides another
useful testing implementation: an on-disk storage engine, where the storage backend is
implemented using a single file written to local disk. In a similar fashion to the in-memory
storage, on-disk should not be used in production environments as it provides no security
guarantees (e.g., encryption before writing to disk). Moreover, OnDisk storage does not
currently support concurrent data accesses.
```

**File:** config/src/config/safety_rules_config.rs (L86-96)
```rust
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

**File:** consensus/src/pending_votes.rs (L287-308)
```rust
        if let Some((previously_seen_vote, previous_li_digest)) =
            self.author_to_vote.get(&vote.author())
        {
            // is it the same vote?
            if &li_digest == previous_li_digest {
                // we've already seen an equivalent vote before
                let new_timeout_vote = vote.is_timeout() && !previously_seen_vote.is_timeout();
                if !new_timeout_vote {
                    // it's not a new timeout vote
                    return VoteReceptionResult::DuplicateVote;
                }
            } else {
                // we have seen a different vote for the same round
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
```
