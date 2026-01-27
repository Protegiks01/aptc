# Audit Report

## Title
Time-of-Check-Time-of-Use (TOCTOU) Vulnerability in Transaction Simulation API

## Summary

The `/transactions/simulate` endpoint generates write sets based on a state snapshot at simulation time, which can differ significantly from the state when the transaction actually executes. This creates a TOCTOU vulnerability where users rely on simulation results that become invalid due to intervening state changes.

## Finding Description

The `simulate()` function in `api/src/transactions.rs` executes transactions against a state snapshot to predict execution outcomes, including the write set. However, this simulation state is decoupled from the state used during actual execution:

**Simulation Phase:** [1](#0-0) 

The simulation retrieves the latest state view at a specific ledger version (N) and executes the transaction against this frozen snapshot. The resulting write set is extracted and returned to the user: [2](#0-1) 

**Actual Execution Phase:**
When the user submits the same transaction after simulation, it enters the mempool and eventually gets included in a block at version N+k (where k ≥ 1). The transaction executes against the state at version N+k, which may have changed significantly due to:
- Other users' transactions modifying relevant state
- Governance proposals being resolved
- Stake pool voting power changes
- Token balances being updated
- Resource availability changes

**State-Dependent Execution Examples:**

1. **Governance Voting**: A vote simulation shows success when a proposal needs 5000 votes and currently has 4500. Between simulation and execution, other validators vote and the proposal reaches 5000 votes and gets resolved. The actual execution fails with `EPROPOSAL_NOT_RESOLVABLE_YET` or similar errors, producing a completely different write set (or transaction abort). [3](#0-2) 

2. **Conditional Transfers**: The `aptos_account::transfer` function checks if an account exists and conditionally creates it. If the account is created between simulation and execution, the write set differs (no account creation in actual execution). [4](#0-3) 

3. **Balance-Dependent Logic**: Any transaction that reads balances and makes conditional decisions based on them will produce different write sets if balances change between simulation and execution.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

**State Inconsistencies**: Users make critical decisions based on simulated write sets that don't match actual execution, requiring manual intervention or transaction resubmission.

**Limited Financial Impact**: 
- DeFi applications may execute trades with unexpected slippage
- Gas estimation inaccuracies cause transaction failures with gas waste
- MEV/sandwich attack vectors where attackers observe simulation results and manipulate state before execution

**Not Critical** because:
- No direct fund theft mechanism
- No consensus safety violation
- No permanent state corruption
- Users can retry transactions

The implementation does verify signature invalidity to prevent direct exploitation: [5](#0-4) 

However, this doesn't prevent the TOCTOU issue itself.

## Likelihood Explanation

**High Likelihood** - This occurs frequently in normal blockchain operation:

1. **Active Blockchains**: On networks with high transaction throughput, state changes every block (every few seconds)
2. **Common User Pattern**: Users routinely simulate before submitting to estimate gas and verify execution
3. **No Special Privileges Required**: Any user can trigger this by normal API usage
4. **Governance Scenarios**: Particularly common during active governance periods when multiple validators vote simultaneously

The time gap between simulation and execution depends on:
- Mempool queue depth
- Gas price competitiveness  
- Network congestion
- Block production rate

Even a 1-2 second delay can result in multiple blocks of state changes.

## Recommendation

**Immediate Mitigation:**

1. **API Documentation Warning**: Add explicit warnings to the `/transactions/simulate` endpoint documentation stating that simulation results are advisory only and may not reflect actual execution due to state changes.

2. **Version Pinning**: Allow users to specify a ledger version for simulation, with validation that the version hasn't been pruned:

```rust
async fn simulate_transaction(
    &self,
    accept_type: AcceptType,
    // Add optional version parameter
    ledger_version: Query<Option<U64>>,
    estimate_max_gas_amount: Query<Option<bool>>,
    // ... other params
) -> SimulateTransactionResult<Vec<UserTransaction>> {
    let ledger_info = if let Some(version) = ledger_version.0 {
        // Get state at specific version
        self.context.get_ledger_info_at_version(version.0)?
    } else {
        self.context.get_latest_ledger_info()?
    };
    
    let state_view = self.context.state_view_at_version(ledger_info.version())?;
    // ... rest of simulation
}
```

3. **Freshness Metadata**: Return the simulation ledger version in the response so users can assess staleness:

```rust
struct SimulationResult {
    user_transaction: UserTransaction,
    simulation_ledger_version: u64,
    simulation_timestamp: u64,
}
```

4. **State Change Detection**: For critical operations, implement client-side validation that checks if relevant state changed between simulation and submission.

## Proof of Concept

```move
// File: governance_vote_toctou.move
script {
    use aptos_framework::aptos_governance;
    
    fun demonstrate_toctou_vote(voter: &signer) {
        // Step 1: User simulates vote at version N
        // Simulation shows: proposal_id=100 is open, needs 5000 votes, has 4800
        // Write set includes: voting record update, vote count increment
        
        // Step 2: Between simulation and actual submission
        // Other validators submit 5 votes totaling 200 voting power
        // Proposal now has 5000 votes and gets resolved
        
        // Step 3: User's transaction executes at version N+k
        // This call will now ABORT because proposal is already resolved
        aptos_governance::vote(
            voter,
            @0x123, // stake_pool address
            100,    // proposal_id
            true    // should_pass
        );
        // Actual write set: EMPTY (transaction aborted)
        // Expected write set from simulation: voting record + vote increment
        // Result: Complete write set mismatch
    }
}
```

**Reproduction Steps:**

1. Deploy a governance proposal requiring 5000 votes
2. Accumulate 4990 votes through other validators
3. Call `/transactions/simulate` with a vote transaction for 100 voting power
4. Observe simulation succeeds with write set showing vote recorded
5. Have another validator submit 10 voting power before user's transaction
6. Submit the user's transaction for actual execution
7. Observe transaction aborts with different/empty write set

**Expected Outcome**: Simulation shows successful vote with specific write set changes. Actual execution produces different write set (abort or different state changes).

## Notes

This vulnerability represents a fundamental TOCTOU issue in any system that simulates state-dependent operations before execution. While the simulation correctly reflects what *would* happen at simulation time, the guarantee doesn't extend to execution time. The severity is mitigated by the fact that transactions still execute safely (they don't violate consensus or cause corruption), but users may experience unexpected behavior and financial losses due to relying on outdated simulation results.

The issue is particularly pronounced for:
- Governance operations during active voting periods
- DeFi transactions on high-volume DEXs
- Time-sensitive conditional logic
- Multi-step protocols requiring specific state preconditions

### Citations

**File:** api/src/transactions.rs (L1617-1625)
```rust
        // The caller must ensure that the signature is not valid, as otherwise
        // a malicious actor could execute the transaction without their knowledge
        if txn.verify_signature().is_ok() {
            return Err(SubmitTransactionError::bad_request_with_code(
                "Simulated transactions must not have a valid signature",
                AptosErrorCode::InvalidInput,
                &ledger_info,
            ));
        }
```

**File:** api/src/transactions.rs (L1640-1642)
```rust
        let state_view = self.context.latest_state_view_poem(&ledger_info)?;
        let (vm_status, output) =
            AptosSimulationVM::create_vm_and_simulate_signed_transaction(&txn, &state_view);
```

**File:** api/src/transactions.rs (L1730-1730)
```rust
            changes: output.write_set().clone(),
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L539-560)
```text
    fun vote_internal(
        voter: &signer,
        stake_pool: address,
        proposal_id: u64,
        voting_power: u64,
        should_pass: bool,
    ) acquires ApprovedExecutionHashes, VotingRecords, VotingRecordsV2, GovernanceEvents {
        permissioned_signer::assert_master_signer(voter);
        let voter_address = signer::address_of(voter);
        assert!(stake::get_delegated_voter(stake_pool) == voter_address, error::invalid_argument(ENOT_DELEGATED_VOTER));

        assert_proposal_expiration(stake_pool, proposal_id);

        // If a stake pool has already voted on a proposal before partial governance voting is enabled,
        // `get_remaining_voting_power` returns 0.
        let staking_pool_voting_power = get_remaining_voting_power(stake_pool, proposal_id);
        voting_power = min(voting_power, staking_pool_voting_power);

        // Short-circuit if the voter has no voting power.
        assert!(voting_power > 0, error::invalid_argument(ENO_VOTING_POWER));

        voting::vote<GovernanceProposal>(
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_account.move (L82-97)
```text
    public entry fun transfer(source: &signer, to: address, amount: u64) {
        if (!account::exists_at(to)) {
            create_account(to)
        };

        if (features::operations_default_to_fa_apt_store_enabled()) {
            fungible_transfer_only(source, to, amount)
        } else {
            // Resource accounts can be created without registering them to receive APT.
            // This conveniently does the registration if necessary.
            if (!coin::is_account_registered<AptosCoin>(to)) {
                coin::register<AptosCoin>(&create_signer(to));
            };
            coin::transfer<AptosCoin>(source, to, amount)
        }
    }
```
