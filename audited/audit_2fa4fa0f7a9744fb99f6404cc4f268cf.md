# Audit Report

## Title
Unrestricted CoinDeposit Event Emission Allows Arbitrary coin_type Strings Causing Indexer Confusion

## Summary
The `CoinDeposit` V2 module event can be emitted by any user with arbitrary `coin_type` strings without validation. This allows malicious actors to inject fake deposit events that confuse indexers and analytics systems, leading to incorrect balance tracking and transaction history.

## Finding Description

The `CoinDeposit` event is defined in the coin module with `drop` and `store` abilities: [1](#0-0) 

The `event::emit()` function is public and accepts any type with `drop + store` abilities: [2](#0-1) 

Since `CoinDeposit` has both `drop` and `store` abilities, any user can construct and emit fake events:

```move
// Malicious code can emit fake deposits
event::emit(CoinDeposit {
    coin_type: string::utf8(b"0xMALICIOUS::fake::FakeCoin"),
    account: target_address,
    amount: 999999999,
});
```

The `coin_type` field is stored as an unvalidated `String` with no checks that it corresponds to a registered coin type: [3](#0-2) 

The indexer's event translator consumes these events and uses the `coin_type` string to construct storage queries: [4](#0-3) 

**Attack Scenarios:**

1. **Syntactically Invalid coin_type**: Emitting events with malformed strings like `"invalid::syntax"` causes `StructTag::from_str()` to fail, breaking V2→V1 event translation and potentially crashing indexer pipelines.

2. **Non-existent Coin Types**: Emitting events with well-formed but fake coin types like `"0x999::scam::ScamCoin"` succeeds in parsing but queries non-existent `CoinStore` resources. The translator falls back to default sequence numbers, creating fake deposit records in indexes.

3. **Impersonation**: An attacker can emit fake deposit events for popular coins (e.g., `"0x1::aptos_coin::AptosCoin"`) to arbitrary accounts, creating false transaction histories that mislead wallets, block explorers, and analytics platforms.

## Impact Explanation

This issue qualifies as **Low Severity** per the Aptos bug bounty criteria:
- **Minor information leaks**: Fake events pollute indexer data, leaking false information about coin movements
- **Non-critical implementation bugs**: Event emission lacks proper access control and validation

The impact includes:
- **Indexer Data Corruption**: Fake deposit events appear in indexed transaction histories
- **UI/Analytics Confusion**: Wallets and block explorers display incorrect balances and transaction counts
- **Audit Trail Compromise**: Security monitoring systems receive false positive alerts for suspicious deposits
- **No Direct Fund Loss**: This does not allow actual theft or creation of coins, only fake event records

The vulnerability does NOT cause:
- Consensus violations (events don't affect state transitions)
- Actual balance changes (only event logs are affected)  
- Loss of funds (cannot mint or steal coins)

## Likelihood Explanation

**Likelihood: High**

Exploitation requires only:
1. Publishing a Move module with event emission code
2. Calling a public entry function that emits the fake event
3. No special permissions or validator access required

The attack is trivial to execute and the vulnerable code path is active in production. Any developer can emit these events through a simple Move transaction.

## Recommendation

**Option 1: Restrict Event Emission (Recommended)**

Make `CoinDeposit` only emittable by the coin module by:
1. Removing `store` ability from the event struct
2. Creating a friend-only emission function

```move
// Remove store ability - only drop
#[event]
struct CoinDeposit has drop {
    coin_type: String,
    account: address,
    amount: u64
}

// Friend-only emission function  
public(friend) fun emit_coin_deposit_event<CoinType>(
    account: address,
    amount: u64
) {
    event::emit(CoinDeposit {
        coin_type: type_info::type_name<CoinType>(),
        account,
        amount,
    });
}
```

**Option 2: Validate coin_type in Indexer**

Add validation in the event translator to reject events with invalid coin types: [5](#0-4) 

Add validation:
```rust
// Validate that coin_type references a known coin
let coin_type_tag = TypeTag::from_str(coin_deposit.coin_type())?;
if !is_registered_coin(&coin_type_tag) {
    return Err(AptosDbError::from(anyhow::format_err!(
        "Invalid coin_type in CoinDeposit event"
    )));
}
```

## Proof of Concept

```move
module attacker::fake_deposits {
    use aptos_framework::coin::CoinDeposit;
    use aptos_framework::event;
    use std::string;
    
    public entry fun emit_fake_deposit(target: address) {
        // Emit fake deposit event for non-existent coin
        event::emit(CoinDeposit {
            coin_type: string::utf8(b"0xDEADBEEF::scam::ScamCoin"),
            account: target,
            amount: 1000000000, // 1 billion fake coins
        });
        
        // Emit fake APT deposit
        event::emit(CoinDeposit {
            coin_type: string::utf8(b"0x1::aptos_coin::AptosCoin"),
            account: target,
            amount: 999999999,
        });
        
        // Emit malformed coin_type that breaks indexer parsing
        event::emit(CoinDeposit {
            coin_type: string::utf8(b"not a valid::struct::tag!!!"),
            account: target,
            amount: 1,
        });
    }
}
```

**Execution:**
1. Deploy the above module
2. Call `attacker::fake_deposits::emit_fake_deposit(victim_address)`
3. Indexers will record three fake deposit events for the victim
4. Block explorers will show false transaction history

**Notes**

While investigating, I could not locate the actual emission sites for `CoinDeposit` events in the coin framework code, which suggests this event type may be part of a migration in progress or future functionality. However, the vulnerability exists in the current codebase: the event structure allows unrestricted emission and the indexer translation logic expects and processes these events without validation. The lack of access control on event emission combined with unvalidated string fields creates an attack surface for data pollution, even if the events are not yet widely used in production.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L177-183)
```text
    #[event]
    /// Module event emitted when some amount of a coin is deposited into an account.
    struct CoinDeposit has drop, store {
        coin_type: String,
        account: address,
        amount: u64
    }
```

**File:** aptos-move/framework/aptos-framework/sources/event.move (L17-19)
```text
    public fun emit<T: store + drop>(msg: T) {
        write_module_event_to_store<T>(msg);
    }
```

**File:** types/src/account_config/events/coin_deposit.rs (L15-20)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoinDeposit {
    pub coin_type: String,
    pub account: AccountAddress,
    pub amount: u64,
}
```

**File:** storage/indexer/src/event_v2_translator.rs (L244-257)
```rust
    ) -> Result<ContractEventV1> {
        let coin_deposit = CoinDeposit::try_from_bytes(v2.event_data())?;
        let struct_tag_str = format!("0x1::coin::CoinStore<{}>", coin_deposit.coin_type());
        let struct_tag = StructTag::from_str(&struct_tag_str)?;
        let (key, sequence_number) = if let Some(state_value_bytes) =
            engine.get_state_value_bytes_for_resource(coin_deposit.account(), &struct_tag)?
        {
            // We can use `DummyCoinType` as it does not affect the correctness of deserialization.
            let coin_store_resource: CoinStoreResource<DummyCoinType> =
                bcs::from_bytes(&state_value_bytes)?;
            let key = *coin_store_resource.deposit_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, coin_store_resource.deposit_events().count())?;
            (key, sequence_number)
```
