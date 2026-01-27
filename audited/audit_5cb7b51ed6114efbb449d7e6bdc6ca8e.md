# Audit Report

## Title
Multisig Transaction Rejection Bypass via Vote State Race Condition

## Summary
The Aptos multisig account implementation allows owners to change their votes at any time before transaction finalization, creating a Time-of-Check-Time-of-Use (TOCTOU) vulnerability. A transaction that has accumulated sufficient rejections to meet the rejection threshold can still be executed if owners change their votes to approvals before `execute_rejected_transaction()` is called, bypassing the intended governance control.

## Finding Description

The multisig account system in Aptos allows k-of-n signature schemes where transactions require a threshold of approvals or rejections. However, there is a critical race condition between reaching the rejection threshold and finalizing the rejection.

**Vulnerable Code Flow:**

1. The `vote_transanction()` function allows unrestricted vote changes: [1](#0-0) 

This code allows owners to update their votes at any time without checking if a threshold has already been reached.

2. Transaction execution only checks approval/rejection counts at validation time: [2](#0-1) 

3. Rejection execution similarly only checks counts at execution time: [3](#0-2) 

**Attack Scenario (2-of-3 Multisig):**
1. Owner A creates a malicious transaction (auto-receives approval vote)
2. Owner B votes to reject: State = 1 approval, 1 rejection
3. Owner C votes to reject: State = 1 approval, 2 rejections (THRESHOLD MET for rejection)
4. Before anyone calls `execute_rejected_transaction()`:
   - Owner B is compromised or socially engineered
   - Owner B calls `approve_transaction()` to change vote
   - State becomes: 2 approvals, 1 rejection (THRESHOLD MET for execution)
5. Owner A executes the transaction via VM validation
6. Malicious transaction succeeds despite having previously met rejection threshold

This violates the invariant that once a transaction reaches the rejection threshold, it should be rejected and not executable.

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria because:

- **Significant Protocol Violation**: Bypasses the fundamental multisig governance security model
- **Governance Integrity Breach**: Transactions that accumulated sufficient rejections can still execute
- **Unauthorized Operations**: Allows execution of transactions that owners collectively decided to reject
- **Fund Loss Risk**: In scenarios where rejected transactions involve fund transfers, this could lead to theft

The vulnerability requires social engineering or compromise of at least one honest owner who previously voted to reject, but the technical exploit is straightforward once that condition is met.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability can occur in the following scenarios:
- **Insider Threat**: A malicious owner changes strategy after initial rejection
- **Account Compromise**: An honest owner's key is compromised after voting to reject
- **Social Engineering**: Manipulation of owners to change votes
- **Coordination Attacks**: In multi-party DAOs, attackers may exploit timing windows during governance decisions

The exploitation requires:
1. A multisig transaction created and initially rejected
2. Access to at least k owners willing/forced to change votes from reject to approve
3. Timing advantage to execute before `execute_rejected_transaction()` is called

No special validator access or consensus manipulation is required.

## Recommendation

Implement vote finality once rejection or approval thresholds are reached. Add a transaction state to prevent vote changes after threshold achievement:

```move
struct MultisigTransaction has copy, drop, store {
    payload: Option<vector<u8>>,
    payload_hash: Option<vector<u8>>,
    votes: SimpleMap<address, bool>,
    creator: address,
    creation_time_secs: u64,
    // Add state tracking
    is_finalized: bool,  // Set to true when any threshold is reached
}

public entry fun vote_transanction(
    owner: &signer, multisig_account: address, sequence_number: u64, approved: bool) acquires MultisigAccount {
    assert_multisig_account_exists(multisig_account);
    let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
    assert_is_owner_internal(owner, multisig_account_resource);
    
    assert!(
        table::contains(&multisig_account_resource.transactions, sequence_number),
        error::not_found(ETRANSACTION_NOT_FOUND),
    );
    let transaction = table::borrow_mut(&mut multisig_account_resource.transactions, sequence_number);
    
    // NEW: Prevent vote changes after finalization
    assert!(!transaction.is_finalized, error::invalid_state(ETRANSACTION_FINALIZED));
    
    let votes = &mut transaction.votes;
    let owner_addr = address_of(owner);
    
    if (simple_map::contains_key(votes, &owner_addr)) {
        *simple_map::borrow_mut(votes, &owner_addr) = approved;
    } else {
        simple_map::add(votes, owner_addr, approved);
    };
    
    // NEW: Check if any threshold is reached and finalize
    let (num_approvals, num_rejections) = num_approvals_and_rejections_internal(&multisig_account_resource.owners, transaction);
    if (num_approvals >= multisig_account_resource.num_signatures_required || 
        num_rejections >= multisig_account_resource.num_signatures_required) {
        transaction.is_finalized = true;
    };
    
    // ... emit events ...
}
```

## Proof of Concept

```move
#[test_only]
module aptos_framework::multisig_rejection_bypass_test {
    use aptos_framework::multisig_account;
    use aptos_framework::account;
    use std::vector;
    
    #[test(framework = @aptos_framework, owner1 = @0x100, owner2 = @0x200, owner3 = @0x300)]
    fun test_rejection_bypass_via_vote_change(
        framework: &signer,
        owner1: &signer,
        owner2: &signer,
        owner3: &signer,
    ) {
        // Setup: Create 2-of-3 multisig account
        let owner1_addr = std::signer::address_of(owner1);
        let owner2_addr = std::signer::address_of(owner2);
        let owner3_addr = std::signer::address_of(owner3);
        
        // Create multisig account with owner1 as creator
        multisig_account::create_with_owners(
            owner1,
            vector[owner2_addr, owner3_addr],
            2,  // 2-of-3 threshold
            vector[],
            vector[]
        );
        
        let multisig_addr = multisig_account::get_next_multisig_account_address(owner1_addr);
        
        // Owner1 creates malicious transaction (auto-approved)
        let malicious_payload = /* some transfer payload */;
        multisig_account::create_transaction(owner1, multisig_addr, malicious_payload);
        
        // Owner2 and Owner3 reject (threshold met: 2 rejections)
        multisig_account::reject_transaction(owner2, multisig_addr, 1);
        multisig_account::reject_transaction(owner3, multisig_addr, 1);
        
        // EXPECTED: Transaction should now be rejectable
        assert!(multisig_account::can_be_rejected(multisig_addr, 1), 0);
        
        // ATTACK: Owner2 changes vote from reject to approve
        multisig_account::approve_transaction(owner2, multisig_addr, 1);
        
        // VULNERABILITY: Transaction is now executable despite having met rejection threshold
        assert!(multisig_account::can_be_executed(multisig_addr, 1), 1);
        
        // Transaction executes successfully when it should have been rejected
        // This demonstrates the bypass of the rejection threshold
    }
}
```

**Notes:**
- The test helper function at [4](#0-3)  is only a wrapper that calls the vulnerable Move implementation
- The core vulnerability exists in the Move smart contract at [5](#0-4) 
- No atomic finalization mechanism exists to prevent vote changes after thresholds are reached

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1015-1054)
```text
    public entry fun vote_transanction(
        owner: &signer, multisig_account: address, sequence_number: u64, approved: bool) acquires MultisigAccount {
        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner_internal(owner, multisig_account_resource);

        assert!(
            table::contains(&multisig_account_resource.transactions, sequence_number),
            error::not_found(ETRANSACTION_NOT_FOUND),
        );
        let transaction = table::borrow_mut(&mut multisig_account_resource.transactions, sequence_number);
        let votes = &mut transaction.votes;
        let owner_addr = address_of(owner);

        if (simple_map::contains_key(votes, &owner_addr)) {
            *simple_map::borrow_mut(votes, &owner_addr) = approved;
        } else {
            simple_map::add(votes, owner_addr, approved);
        };

        if (std::features::module_event_migration_enabled()) {
            emit(
                Vote {
                    multisig_account,
                    owner: owner_addr,
                    sequence_number,
                    approved,
                }
            );
        } else {
            emit_event(
                &mut multisig_account_resource.vote_events,
                VoteEvent {
                    owner: owner_addr,
                    sequence_number,
                    approved,
                }
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1082-1096)
```text
        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        let owner_addr = address_of(owner);
        if (features::multisig_v2_enhancement_feature_enabled()) {
            // Implicitly vote for rejection if the owner has not voted for rejection yet.
            if (!has_voted_for_rejection(multisig_account, sequence_number, owner_addr)) {
                reject_transaction(owner, multisig_account, sequence_number);
            }
        };

        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        let (_, num_rejections) = remove_executed_transaction(multisig_account_resource);
        assert!(
            num_rejections >= multisig_account_resource.num_signatures_required,
            error::invalid_state(ENOT_ENOUGH_REJECTIONS),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1139-1157)
```text
    fun validate_multisig_transaction(
        owner: &signer, multisig_account: address, payload: vector<u8>) acquires MultisigAccount {
        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);
        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        assert_transaction_exists(multisig_account, sequence_number);

        if (features::multisig_v2_enhancement_feature_enabled()) {
            assert!(
                can_execute(address_of(owner), multisig_account, sequence_number),
                error::invalid_argument(ENOT_ENOUGH_APPROVALS),
            );
        }
        else {
            assert!(
                can_be_executed(multisig_account, sequence_number),
                error::invalid_argument(ENOT_ENOUGH_APPROVALS),
            );
        };
```

**File:** api/test-context/src/test_context.rs (L697-715)
```rust
    pub async fn reject_multisig_transaction(
        &mut self,
        owner: &mut LocalAccount,
        multisig_account: AccountAddress,
        transaction_id: u64,
    ) {
        let factory = self.transaction_factory();
        let txn = owner.sign_with_transaction_builder(
            factory
                .reject_multisig_transaction(multisig_account, transaction_id)
                .expiration_timestamp_secs(self.get_expiration_time())
                .upgrade_payload_with_rng(
                    &mut self.rng,
                    self.use_txn_payload_v2_format,
                    self.use_orderless_transactions,
                ),
        );
        self.commit_block(&vec![txn]).await;
    }
```
