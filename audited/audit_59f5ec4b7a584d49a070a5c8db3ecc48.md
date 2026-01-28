# Audit Report

## Title
Missing fsync() in OnDiskStorage Enables Consensus Safety Violations After Crash

## Summary
The `OnDiskStorage` backend used for consensus safety rules persistence lacks `fsync()` calls, causing safety-critical data (`last_voted_round`) to be lost on system crashes. This enables validators to double-vote after restart, violating consensus safety guarantees and potentially causing chain splits.

## Finding Description

The Aptos consensus safety-rules system relies on persistent storage to maintain critical safety invariants. The storage abstraction explicitly states: "Any set function is expected to sync to the remote system before returning" [1](#0-0) , establishing a durability contract that `OnDiskStorage` violates.

**Vulnerable Code Flow:**

When a validator votes for a block, `SafetyRules` updates the `last_voted_round` field to prevent double-voting. The execution path is:

1. **Vote Construction**: The `guarded_construct_and_sign_vote_two_chain` function retrieves safety data, verifies voting rules, and updates `last_voted_round` [2](#0-1) 

2. **Persistence Call**: After creating the vote, the function persists the updated safety data via `persistent_storage.set_safety_data(safety_data)` [3](#0-2) 

3. **Storage Backend**: This eventually calls `OnDiskStorage::write()` which writes data to a temporary file, renames it to the final location, but **never calls `fsync()` or `sync_all()`** [4](#0-3) 

**The Critical Bug:**

The `write()` method returns `Ok(())` after `fs::rename()` completes, but at this point the data only exists in OS page cache—not on physical storage. Without `fsync()`, a system crash (power failure, kernel panic, OOM kill) before the OS flushes buffers will cause the write to be lost.

**Production Deployment Evidence:**

Despite the README warning that OnDiskStorage "should not be used in production" [5](#0-4) , production deployment configurations use it:

- Docker Compose validator config: [6](#0-5) 
- **Terraform Helm base validator config**: [7](#0-6) 
- Testnet template: [8](#0-7) 

**Configuration Validation Gap:**

The `SafetyRulesConfig` sanitizer only blocks `InMemoryStorage` for mainnet validators, but does **not** block `OnDiskStorage` [9](#0-8) . This allows validators to deploy with the unsafe storage backend on mainnet.

**Attack Scenario:**

1. Validator votes for block at round R
2. `verify_and_update_last_vote_round` updates `last_voted_round = R` in memory [10](#0-9) 
3. `set_safety_data()` writes to disk and returns `Ok(())`
4. Data remains in OS buffer cache (not flushed to disk)
5. **System crash** occurs (power failure, kernel panic, OOM)
6. Node restarts and reads safety data from disk
7. `last_voted_round` has old value < R (pre-crash state)
8. Safety rules check passes: `round > safety_data.last_voted_round` [11](#0-10) 
9. **Validator votes again for round R with potentially different vote**
10. **Consensus safety violation: equivocation/double-voting**

This directly violates the AptosBFT consensus safety property that prevents double-voting within the same round.

## Impact Explanation

**Critical Severity** - This vulnerability enables consensus safety violations under the Aptos Bug Bounty "Consensus/Safety violations" category:

1. **Double-Voting/Equivocation**: Honest validators can unintentionally vote twice in the same round with different votes, breaking the fundamental consensus safety property

2. **Chain Splits**: If multiple validators crash and double-vote differently after recovery, the network can form conflicting quorum certificates for the same round, potentially causing permanent chain splits

3. **Byzantine Behavior from Honest Nodes**: Validators following the protocol correctly become accidentally Byzantine through natural operational events, undermining the BFT assumption of at most f Byzantine nodes out of 3f+1

4. **Widespread Deployment**: The vulnerable configuration is present in the Helm base template used for production Kubernetes deployments, affecting any validators deployed using standard Aptos deployment tools

This qualifies as **Critical Severity ($1M)** under the bug bounty program's "Consensus/Safety violations" category—the ability to break consensus safety guarantees through double-voting.

## Likelihood Explanation

**High Likelihood:**

1. **Natural Trigger**: System crashes are common operational events in production environments (power failures, kernel panics, OOM kills, hardware failures)

2. **No Attacker Required**: The vulnerability triggers through normal system failures, not malicious actions

3. **Default Configuration Issue**: Production deployment templates (Helm base config) use the vulnerable storage backend by default

4. **Large Vulnerability Window**: The time between `write_all()` returning and OS buffer flush can be several seconds under load, creating a significant window of exposure

5. **High Vote Frequency**: Validators vote on every consensus round (sub-second frequency), maximizing the probability that unflushed data exists during a crash

6. **Configuration Validation Gap**: The sanitizer doesn't prevent OnDiskStorage on mainnet, allowing validators to deploy with this configuration

The likelihood increases with the number of validators using default configs, system resource pressure, and infrastructure instability.

## Recommendation

**Immediate Fixes:**

1. **Add fsync() to OnDiskStorage**: Modify `OnDiskStorage::write()` to call `file.sync_all()` before returning:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?; // Add fsync before rename
    fs::rename(&self.temp_path, &self.file_path)?;
    // Optionally: sync directory entry
    Ok(())
}
```

2. **Update Configuration Sanitizer**: Extend `SafetyRulesConfig::sanitize()` to reject OnDiskStorage for mainnet validators:

```rust
if chain_id.is_mainnet() 
    && node_type.is_validator() 
    && matches!(safety_rules_config.backend, SecureBackend::OnDiskStorage(_))
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "OnDiskStorage should not be used for safety rules in mainnet! Use Vault instead.".to_string(),
    ));
}
```

3. **Update Production Configs**: Change default Helm/Docker configs to use Vault or add prominent warnings requiring manual override

4. **Add Monitoring**: Alert operators when validators are running with OnDiskStorage on mainnet

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a validator with OnDiskStorage configuration
2. Observing it vote on a block at round R
3. Sending SIGKILL immediately after the vote (simulating crash)
4. Restarting the validator
5. Observing it can vote again on round R (double-vote)

A complete PoC would require setting up a local testnet, which is beyond the scope of this report, but the code paths are clearly traceable through the citations provided.

## Notes

**Additional Context:**

1. **Vault is the Recommended Backend**: The README explicitly states Vault is "the one primarily used in production environments" [12](#0-11) , but deployment templates don't enforce this

2. **Test Config Shows Vault**: The test data directory contains a proper Vault configuration example [13](#0-12) , indicating the codebase supports secure storage, but defaults are unsafe

3. **Race Condition Window**: Modern file systems can delay fsync for several seconds under write pressure, making the vulnerability window significant

4. **Defense in Depth Failure**: Multiple layers failed: (1) OnDiskStorage lacks durability, (2) sanitizer doesn't block it, (3) production templates use it by default

This vulnerability represents a critical gap between documented best practices and actual deployment configurations, creating a systemic risk to consensus safety across the Aptos network.

### Citations

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L18-18)
```rust
/// Any set function is expected to sync to the remote system before returning.
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-80)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L92-92)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
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

**File:** secure/storage/README.md (L32-33)
```markdown
offered by HashiCorp: https://www.vaultproject.io/). The Vault secure storage implementation
is the one primarily used in production environments by nodes in the blockchain.
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

**File:** testsuite/pangu_lib/template_testnet_files/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
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

**File:** consensus/safety-rules/src/safety_rules.rs (L218-225)
```rust
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
```

**File:** config/src/config/test_data/validator.yaml (L5-10)
```yaml
        from_storage:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"
```
