# Audit Report

## Title
Genesis WriteSet Bypasses Economic Invariant Validation Allowing Arbitrary System Account Initialization

## Summary
The genesis bootstrap process in `storage/db-tool/src/bootstrap.rs` accepts `WriteSetPayload::Direct` transactions from external files without validating the content of state writes. This allows a malicious genesis transaction to initialize system accounts (0x1, 0x2) with arbitrary balances and permissions that violate economic security invariants, as the only protection is waypoint verification which validates the state root hash but not the semantic correctness of the state.

## Finding Description

When the Aptos blockchain is bootstrapped, the `Command::run()` function loads a genesis transaction from a file and applies it: [1](#0-0) 

The genesis transaction contains a `WriteSetPayload::Direct` with a `ChangeSet` that specifies all initial state writes: [2](#0-1) [3](#0-2) 

When this transaction is executed, the `execute_write_set` function handles `WriteSetPayload::Direct` by directly applying the ChangeSet WITHOUT running any Move code or validation logic: [4](#0-3) 

The only validation performed is checking for epoch/block events, NOT the content of state writes: [5](#0-4) 

**Critical Gap:** The verification functions `verify_genesis_module_write_set` and `verify_genesis_events` are only called during genesis CREATION in `encode_genesis_change_set`: [6](#0-5) 

These functions are NEVER called when loading a genesis transaction from file. The bootstrap tool only validates:
1. The transaction deserializes successfully
2. It's a `GenesisTransaction` type  
3. The waypoint matches (if provided)

This means an attacker can craft a malicious genesis file that:
- Mints unlimited APT to attacker-controlled addresses
- Gives system accounts (0x1, 0x2) arbitrary balances violating total supply
- Grants arbitrary governance permissions
- Initializes validator sets with compromised configurations
- Violates any economic or security invariant

The malicious genesis will be accepted as long as operators use the corresponding waypoint. While the waypoint is meant to be a trust anchor, it only verifies the HASH of the final state, not the VALIDITY of that state.

## Impact Explanation

**Critical Severity** - This vulnerability allows:

1. **Loss of Funds**: Attacker can mint unlimited APT tokens to their addresses by including writes to `CoinStore<AptosCoin>` resources with arbitrary balances, as shown in the test configuration: [7](#0-6) 

2. **Economic Invariant Violation**: Total supply can be set arbitrarily, breaking fundamental economic guarantees. The system has no validation that initial balances sum correctly or respect any limits.

3. **Governance Compromise**: System accounts can be initialized with arbitrary capabilities and permissions, bypassing all Move-level access controls that would normally enforce: [8](#0-7) 

4. **Consensus Impact**: Different operators bootstrapping with different malicious genesis files (if waypoint verification is bypassed or social engineered) would create chain splits.

This meets the **Critical Severity** threshold of "$1,000,000" for "Loss of Funds (theft or minting)" and "Consensus/Safety violations" per the Aptos Bug Bounty program.

## Likelihood Explanation

**Moderate to High Likelihood** depending on attack scenario:

1. **Social Engineering Attack**: Attacker creates malicious genesis + waypoint, then through social engineering, insider threat, or compromised communication channels, convinces operators to use it. Likelihood increases during network launches or hard forks when new genesis files are distributed.

2. **Waypoint Verification Bypass**: If the `--waypoint-to-verify` parameter is omitted or operators don't verify waypoints through trusted channels, malicious genesis can be applied: [9](#0-8) 

3. **Insider Threat**: A malicious node operator or developer with access to genesis file distribution can inject malicious state.

The attack requires operator cooperation (either malicious or deceived) but no code exploits or validator majority. The lack of content validation violates defense-in-depth principles.

## Recommendation

Add content validation to the bootstrap process to verify economic and security invariants BEFORE applying the genesis WriteSet:

```rust
// In storage/db-tool/src/bootstrap.rs
impl Command {
    pub fn run(self) -> Result<()> {
        let genesis_txn = load_genesis_txn(&self.genesis_txn_file)
            .with_context(|| format_err!("Failed loading genesis txn."))?;
        assert!(
            matches!(genesis_txn, Transaction::GenesisTransaction(_)),
            "Not a GenesisTransaction"
        );
        
        // NEW: Validate genesis content before execution
        validate_genesis_content(&genesis_txn)?;
        
        // ... rest of existing code
    }
}

fn validate_genesis_content(txn: &Transaction) -> Result<()> {
    if let Transaction::GenesisTransaction(WriteSetPayload::Direct(change_set)) = txn {
        // Verify module writes are creations only
        for (state_key, write_op) in change_set.write_set().iter() {
            if state_key.is_module_path() {
                ensure!(write_op.is_creation(), "Genesis module writes must be creations");
            }
        }
        
        // Verify economic invariants
        let mut total_supply = 0u64;
        for (state_key, write_op) in change_set.write_set().iter() {
            // Check CoinStore resources for balance limits
            if is_coin_store(state_key) {
                let balance = extract_balance(write_op)?;
                ensure!(balance <= MAX_GENESIS_BALANCE, "Balance exceeds limit");
                total_supply = total_supply.checked_add(balance)
                    .ok_or_else(|| format_err!("Total supply overflow"))?;
            }
        }
        
        // Verify total supply is reasonable
        ensure!(total_supply <= MAX_TOTAL_SUPPLY, "Total supply exceeds limit");
        
        // Verify events
        ensure!(
            change_set.events().iter().any(|e| e.is_new_epoch_event()),
            "Genesis must emit NewEpochEvent"
        );
    }
    Ok(())
}
```

Additionally, implement cryptographic signing of official genesis files so operators can verify authenticity:

```rust
pub struct SignedGenesis {
    pub genesis_txn: Transaction,
    pub signature: Signature,
    pub signer_public_key: PublicKey,
}

// Operators verify signature against trusted public keys before bootstrap
fn verify_genesis_signature(signed_genesis: &SignedGenesis) -> Result<()> {
    let trusted_keys = load_trusted_genesis_keys()?;
    ensure!(
        trusted_keys.contains(&signed_genesis.signer_public_key),
        "Genesis not signed by trusted key"
    );
    signed_genesis.signature.verify(
        &signed_genesis.genesis_txn.hash(),
        &signed_genesis.signer_public_key
    )
}
```

## Proof of Concept

```rust
// Proof of Concept: Create malicious genesis transaction
use aptos_types::transaction::{Transaction, WriteSetPayload, ChangeSet};
use aptos_types::write_set::{WriteSet, WriteOp};
use aptos_types::state_store::state_key::StateKey;
use aptos_types::account_address::AccountAddress;

fn create_malicious_genesis() -> Transaction {
    let attacker_addr = AccountAddress::from_hex_literal("0xdeadbeef").unwrap();
    
    // Create malicious WriteSet
    let mut writes = vec![];
    
    // 1. Mint unlimited APT to attacker (1 trillion APT)
    let attacker_coin_store_key = StateKey::access_path(
        attacker_addr,
        b"0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>".to_vec()
    );
    let malicious_balance = 1_000_000_000_000u64 * 100_000_000; // 1 trillion APT
    writes.push((
        attacker_coin_store_key,
        WriteOp::Creation(serialize_coin_store_with_balance(malicious_balance))
    ));
    
    // 2. Give attacker governance capabilities
    let gov_capability_key = StateKey::access_path(
        attacker_addr,
        b"0x1::aptos_governance::GovernanceCapability".to_vec()
    );
    writes.push((
        gov_capability_key,
        WriteOp::Creation(serialize_governance_capability())
    ));
    
    // 3. Add required epoch/block events to pass validation
    let events = vec![
        create_new_epoch_event(),
        create_new_block_event(),
    ];
    
    let write_set = WriteSet::new(writes.into_iter().collect());
    let change_set = ChangeSet::new(write_set, events);
    
    Transaction::GenesisTransaction(WriteSetPayload::Direct(change_set))
}

// Serialize and save to file
let malicious_genesis = create_malicious_genesis();
let bytes = bcs::to_bytes(&malicious_genesis).unwrap();
std::fs::write("malicious_genesis.blob", bytes).unwrap();

// Calculate waypoint
let waypoint = calculate_waypoint_for_genesis(&malicious_genesis);
println!("Use waypoint: {}", waypoint);

// When operator runs: 
// ./aptos-db-tool bootstrap --db-dir /data --genesis-txn-file malicious_genesis.blob \
//   --waypoint-to-verify <calculated_waypoint> --commit
// 
// The malicious state will be applied WITHOUT validation of economic invariants
```

The malicious genesis bypasses all Move-level checks because `WriteSetPayload::Direct` applies writes without executing Move code. Only the waypoint hash is verified, not the validity of the state itself.

### Citations

**File:** storage/db-tool/src/bootstrap.rs (L41-47)
```rust
    pub fn run(self) -> Result<()> {
        let genesis_txn = load_genesis_txn(&self.genesis_txn_file)
            .with_context(|| format_err!("Failed loading genesis txn."))?;
        assert!(
            matches!(genesis_txn, Transaction::GenesisTransaction(_)),
            "Not a GenesisTransaction"
        );
```

**File:** storage/db-tool/src/bootstrap.rs (L87-102)
```rust
        if let Some(waypoint) = self.waypoint_to_verify {
            ensure!(
                waypoint == committer.waypoint(),
                "Waypoint verification failed. Expected {:?}, got {:?}.",
                waypoint,
                committer.waypoint(),
            );
            println!("Waypoint verified.");

            if self.commit {
                committer
                    .commit()
                    .with_context(|| format_err!("Committing genesis to DB."))?;
                println!("Successfully committed genesis.")
            }
        }
```

**File:** types/src/transaction/mod.rs (L1008-1018)
```rust
pub enum WriteSetPayload {
    /// Directly passing in the WriteSet.
    Direct(ChangeSet),
    /// Generate the WriteSet by running a script.
    Script {
        /// Execute the script as the designated signer.
        execute_as: AccountAddress,
        /// Script body that gets executed.
        script: Script,
    },
}
```

**File:** types/src/transaction/mod.rs (L2946-2954)
```rust
pub enum Transaction {
    /// Transaction submitted by the user. e.g: P2P payment transaction, publishing module
    /// transaction, etc.
    /// TODO: We need to rename SignedTransaction to SignedUserTransaction, as well as all the other
    ///       transaction types we had in our codebase.
    UserTransaction(SignedTransaction),

    /// Transaction that applies a WriteSet to the current storage, it's applied manually via aptos-db-bootstrapper.
    GenesisTransaction(WriteSetPayload),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2266-2296)
```rust
    fn execute_write_set(
        &self,
        resolver: &impl AptosMoveResolver,
        code_storage: &impl AptosCodeStorage,
        write_set_payload: &WriteSetPayload,
        txn_sender: Option<AccountAddress>,
        session_id: SessionId,
    ) -> Result<(VMChangeSet, ModuleWriteSet), VMStatus> {
        match write_set_payload {
            WriteSetPayload::Direct(change_set) => {
                // this transaction is never delayed field capable.
                // it requires restarting execution afterwards,
                // which allows it to be used as last transaction in delayed_field_enabled context.
                let (change_set, module_write_set) =
                    create_vm_change_set_with_module_write_set_when_delayed_field_optimization_disabled(
                        change_set.clone(),
                    );

                // validate_waypoint_change_set checks that this is true, so we only log here.
                if !Self::should_restart_execution(change_set.events()) {
                    // This invariant needs to hold irrespectively, so we log error always.
                    // but if we are in delayed_field_optimization_capable context, we cannot execute any transaction after this.
                    // as transaction afterwards would be executed assuming delayed fields are exchanged and
                    // resource groups are split, but WriteSetPayload::Direct has materialized writes,
                    // and so after executing this transaction versioned state is inconsistent.
                    error!(
                        "[aptos_vm] direct write set finished without requiring should_restart_execution");
                }

                Ok((change_set, module_write_set))
            },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2365-2382)
```rust
    fn validate_waypoint_change_set(
        events: &[(ContractEvent, Option<MoveTypeLayout>)],
        log_context: &AdapterLogSchema,
    ) -> Result<(), VMStatus> {
        let has_new_block_event = events
            .iter()
            .any(|(e, _)| e.event_key() == Some(&new_block_event_key()));
        let has_new_epoch_event = events.iter().any(|(e, _)| e.is_new_epoch_event());
        if has_new_block_event && has_new_epoch_event {
            Ok(())
        } else {
            error!(
                *log_context,
                "[aptos_vm] waypoint txn needs to emit new epoch and block"
            );
            Err(VMStatus::error(StatusCode::INVALID_WRITE_SET, None))
        }
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L397-402)
```rust

    let change_set = assert_ok!(change_set.try_combine_into_storage_change_set(module_write_set));
    verify_genesis_module_write_set(change_set.write_set());
    verify_genesis_events(change_set.events());

    change_set
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_coin.move (L73-88)
```text
    public(friend) fun configure_accounts_for_test(
        aptos_framework: &signer,
        core_resources: &signer,
        mint_cap: MintCapability<AptosCoin>,
    ) {
        system_addresses::assert_aptos_framework(aptos_framework);

        // Mint the core resource account AptosCoin for gas so it can execute system transactions.
        let coins = coin::mint<AptosCoin>(
            18446744073709551615,
            &mint_cap,
        );
        coin::deposit<AptosCoin>(signer::address_of(core_resources), coins);

        move_to(core_resources, MintCapStore { mint_cap });
        move_to(core_resources, Delegations { inner: vector::empty() });
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L86-98)
```text
        let (aptos_framework_account, aptos_framework_signer_cap) = account::create_framework_reserved_account(@aptos_framework);
        // Initialize account configs on aptos framework account.
        account::initialize(&aptos_framework_account);

        transaction_validation::initialize(
            &aptos_framework_account,
            b"script_prologue",
            b"module_prologue",
            b"multi_agent_script_prologue",
            b"epilogue",
        );
        // Give the decentralized on-chain governance control over the core framework account.
        aptos_governance::store_signer_cap(&aptos_framework_account, @aptos_framework, aptos_framework_signer_cap);
```
