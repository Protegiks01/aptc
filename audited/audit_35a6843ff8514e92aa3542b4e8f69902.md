# Audit Report

## Title
CLI Tool Panic on Empty Vesting Contracts Vector in RequestCommission Command

## Summary
The Aptos CLI's `RequestCommission` command performs an unchecked array access on the `vesting_contracts` vector, causing a panic when the vector is empty. This affects users who have created an `AdminStore` resource but haven't yet created any vesting contracts.

## Finding Description
The vulnerability exists in the CLI tool's request commission functionality. When a user attempts to request commission using the Aptos CLI command `aptos stake request-commission`, the code retrieves the `VestingAdminStore` resource and directly accesses the first element of the `vesting_contracts` vector without verifying the vector contains any elements. [1](#0-0) 

The issue occurs because:
1. An `AdminStore` resource can exist with an empty `vesting_contracts` vector [2](#0-1) 
2. The CLI code assumes if an `AdminStore` exists, it must contain at least one vesting contract [3](#0-2) 
3. Direct indexing `[0]` without bounds checking causes a Rust panic when the vector is empty

The Move smart contracts handle empty vectors correctly using safe iteration patterns [4](#0-3) , but the Rust CLI tool does not.

## Impact Explanation
**Severity: Low** - This is a client-side availability issue that does not affect the blockchain itself. The impact is limited to:
- Local CLI tool crash/panic on the user's machine
- Poor user experience when interacting with the CLI
- No consensus, fund, or state integrity impact
- No effect on validator nodes or network operations

Per Aptos bug bounty criteria, this falls under Low severity as it is a "non-critical implementation bug" affecting only client tooling.

## Likelihood Explanation
**Likelihood: Medium** - This scenario can occur naturally when:
1. A user initializes vesting functionality (creating the `AdminStore`)
2. The user attempts to request commission before creating any vesting contracts
3. The user uses the Aptos CLI tool instead of direct transaction submission

The likelihood is medium because while the scenario is realistic, most users would create vesting contracts before attempting to request commission.

## Recommendation
Add bounds checking before accessing the array:

```rust
let staker_address = if let Ok(vesting_admin_store) = vesting_admin_store {
    let contracts = vesting_admin_store.into_inner().vesting_contracts;
    if contracts.is_empty() {
        self.owner_address
    } else {
        contracts[0]
    }
} else {
    self.owner_address
};
```

Alternatively, use safe access methods:
```rust
let staker_address = if let Ok(vesting_admin_store) = vesting_admin_store {
    vesting_admin_store.into_inner().vesting_contracts.first()
        .copied()
        .unwrap_or(self.owner_address)
} else {
    self.owner_address
};
```

## Proof of Concept
**Reproduction Steps:**
1. Create an account with vesting permissions
2. Initialize the `AdminStore` by calling the vesting module's initialization (but don't create any vesting contracts)
3. Attempt to run: `aptos stake request-commission --owner-address <address> --operator-address <operator>`
4. The CLI tool will panic with an index out of bounds error

**Expected behavior:** The command should handle the empty vector gracefully and either fall back to using the owner address directly or provide a clear error message.

**Notes:**
- This vulnerability only affects the Aptos CLI tool, not the blockchain protocol or consensus
- The underlying Move smart contracts in the vesting module handle empty vectors safely using proper iteration patterns
- The security impact is limited to local tool availability and does not affect blockchain security, consensus, or fund safety
- While this is a real bug that should be fixed, it does not meet the Critical/High/Medium severity thresholds required for the bug bounty program's higher tiers

### Citations

**File:** crates/aptos/src/stake/mod.rs (L653-654)
```rust
        // Note: this only works if the vesting contract has exactly one staking contract
        // associated
```

**File:** crates/aptos/src/stake/mod.rs (L655-656)
```rust
        let staker_address = if let Ok(vesting_admin_store) = vesting_admin_store {
            vesting_admin_store.into_inner().vesting_contracts[0]
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L589-594)
```text
        if (!exists<AdminStore>(admin_address)) {
            move_to(admin, AdminStore {
                vesting_contracts: vector::empty<address>(),
                nonce: 0,
                create_events: new_event_handle<CreateVestingContractEvent>(admin),
            });
```

**File:** aptos-move/framework/aptos-framework/sources/staking_proxy.move (L44-45)
```text
        let vesting_contracts = &vesting::vesting_contracts(owner_address);
        vector::for_each_ref(vesting_contracts, |vesting_contract| {
```
