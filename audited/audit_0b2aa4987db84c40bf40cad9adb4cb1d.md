# Audit Report

## Title
Missing Epoch Consistency Validation in DKG Transcript Processing

## Summary
The DKG transcript verification in the VM lacks an explicit validation that the `in_progress` session's `dealer_epoch` is consistent with the current epoch. While cryptographic signatures bind transcripts to specific epochs, a missing defense-in-depth check could allow old transcripts to be accepted if stale DKG sessions persist across epoch boundaries.

## Finding Description

The `process_dkg_result_inner()` function validates DKG transcripts at the VM level. It performs an epoch check on the wrapper metadata but fails to validate that the `in_progress_session_state` is actually for the expected epoch. [1](#0-0) 

The function only checks that `dkg_node.metadata.epoch` (the unsigned wrapper) matches `config_resource.epoch()`, but does not validate that `in_progress_session_state.metadata.dealer_epoch` is consistent with the current epoch.

The verification constructs `pub_params` from the `in_progress_session_state.metadata`: [2](#0-1) 

During transcript verification, the `aux` parameter (which includes the epoch) is constructed from these `pub_params`: [3](#0-2) 

The transcript signatures are validated against this `aux` data: [4](#0-3) 

**Theoretical Attack Scenario:**
If a stale `in_progress` session persists with `dealer_epoch = N` while the current epoch is `M > N`:
1. Attacker obtains/creates a transcript from epoch N (potentially with compromised keys from that epoch)
2. Sets `dkg_node.metadata.epoch = M` (passes line 100 check)
3. Verification uses `aux = (N, addresses)` from stale in_progress session
4. Old transcript was signed with `aux = (N, addresses)`
5. Signature verification passes despite being from a previous epoch

## Impact Explanation

**Severity: Medium**

This represents a **defense-in-depth** weakness rather than a directly exploitable critical vulnerability. The impact would be:

- Potential acceptance of DKG transcripts from previous epochs if stale sessions persist
- If combined with compromised validator keys from a past epoch, could allow malicious transcript injection
- Could undermine randomness generation security for consensus

However, exploitation requires:
- A separate bug causing stale `in_progress` sessions to persist across epochs
- Precise timing during epoch transitions
- The existing cleanup logic in `try_start()` and `finish()` provides protection [5](#0-4) 

The `try_start()` function should overwrite stale sessions, limiting the attack window.

## Likelihood Explanation

**Likelihood: Low to Medium**

While the code includes cleanup mechanisms (`try_start()` detects and overwrites stale sessions, `finish()` clears incomplete sessions), edge cases could arise during:
- Network partitions causing delayed epoch transitions
- Race conditions between epoch transition and session cleanup
- Node crashes/restarts leaving inconsistent state
- Bugs in the cleanup logic itself

The attack requires precise timing and specific preconditions that are unlikely under normal operation.

## Recommendation

Add an explicit validation in `process_dkg_result_inner()` to ensure the `in_progress` session is for the expected epoch:

```rust
fn process_dkg_result_inner(
    &self,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl AptosModuleStorage,
    log_context: &AdapterLogSchema,
    session_id: SessionId,
    dkg_node: DKGTranscript,
) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
    let dkg_state =
        OnChainConfig::fetch_config(resolver).ok_or(Expected(MissingResourceDKGState))?;
    let config_resource = ConfigurationResource::fetch_config(resolver)
        .ok_or(Expected(MissingResourceConfiguration))?;
    let DKGState { in_progress, .. } = dkg_state;
    let in_progress_session_state =
        in_progress.ok_or(Expected(MissingResourceInprogressDKGSession))?;

    // Check epoch number.
    if dkg_node.metadata.epoch != config_resource.epoch() {
        return Err(Expected(EpochNotCurrent));
    }
    
    // NEW: Validate in_progress session is for the current epoch
    if in_progress_session_state.metadata.dealer_epoch != config_resource.epoch() {
        return Err(Expected(InProgressSessionEpochMismatch));
    }

    // ... rest of function
}
```

This defense-in-depth check ensures that even if stale sessions persist, they cannot be used to verify old transcripts.

## Proof of Concept

**Note:** This vulnerability cannot be directly exploited without a separate bug that causes stale `in_progress` sessions. A full PoC would require:

1. Creating a DKG session in epoch N
2. Forcing an epoch transition to N+1 without clearing the in_progress session
3. Submitting an old transcript from epoch N
4. Observing it being accepted despite being from a previous epoch

The core issue is the **missing validation**, not the exploitability under current code paths. The existing cleanup mechanisms (`try_start()` and `finish()`) provide protection, but this missing check creates unnecessary risk.

**Notes:**
- The cryptographic signature binding provides the primary security through `aux` data validation
- The `verify()` function in `generic_weighting.rs` correctly passes `aux` through to signature verification
- The issue is specifically the lack of consistency validation between `in_progress.dealer_epoch` and current epoch in the VM processing layer
- This is a defense-in-depth improvement rather than a critical exploit

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L99-102)
```rust
        // Check epoch number.
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L105-112)
```rust
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L363-366)
```rust
        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L79-103)
```rust
    let msgs = soks
        .iter()
        .zip(aux)
        .map(|((player, comm, _, _), aux)| Contribution::<Gr, A> {
            comm: *comm,
            player: *player,
            aux: aux.clone(),
        })
        .collect::<Vec<Contribution<Gr, A>>>();
    let msgs_refs = msgs
        .iter()
        .map(|c| c)
        .collect::<Vec<&Contribution<Gr, A>>>();
    let pks = spks
        .iter()
        .map(|pk| pk)
        .collect::<Vec<&bls12381::PublicKey>>();
    let sig = bls12381::Signature::aggregate(
        soks.iter()
            .map(|(_, _, sig, _)| sig.clone())
            .collect::<Vec<bls12381::Signature>>(),
    )?;

    sig.verify_aggregate(&msgs_refs[..], &pks[..])?;
    Ok(())
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-40)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
    }
```
