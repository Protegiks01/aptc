# Audit Report

## Title
Information Disclosure via Indexer GraphQL API Exposes All Pending Token Claims

## Summary
The `current_token_pending_claims` table in the Hasura GraphQL indexer API allows unauthenticated enumeration of all pending token offers across the entire Aptos blockchain, exposing trading intentions and potentially enabling market manipulation.

## Finding Description

The `pending_claims` field in the `PendingClaims` resource stores token offers in a Move `Table<TokenOfferId, Token>` data structure. While direct enumeration of table entries via the storage layer is not exposed through public APIs, the indexer processes all table write operations and exposes this data through an unrestricted GraphQL API. [1](#0-0) 

The indexer tracks all changes to pending claims tables and stores them in a PostgreSQL database: [2](#0-1) 

This data is then exposed via Hasura GraphQL with anonymous access and an empty filter, allowing unrestricted queries: [3](#0-2) 

The SQL schema includes indices specifically designed for efficient enumeration by table handle, sender, and recipient: [4](#0-3) 

**Attack Path:**
1. Attacker queries the GraphQL API: `query { current_token_pending_claims(where: {amount: {_gt: "0"}}, limit: 100) { from_address, to_address, token_data_id_hash, amount } }`
2. Discovers all active pending token offers network-wide
3. Monitors valuable token offers in real-time
4. Uses this information for market manipulation or MEV extraction

## Impact Explanation

While this qualifies as an **information disclosure vulnerability**, it does NOT enable direct front-running of claim operations because the `claim()` function enforces that only the specified `to_address` can execute the claim: [5](#0-4) 

However, the exposed information enables:
- **Market intelligence gathering** - discovering trading patterns and intentions
- **Privacy violation** - revealing which users are transferring tokens before transactions complete
- **Indirect MEV opportunities** - using knowledge of pending transfers to manipulate related markets

Per the Aptos bug bounty criteria, this represents a **Low Severity** issue (minor information leak) rather than Medium, as it does not directly enable "limited funds loss or manipulation." The claim operation's access control prevents direct exploitation.

## Likelihood Explanation

**Likelihood: Very High**
- No authentication required
- Simple GraphQL queries
- Data is continuously updated by the indexer
- Standard tooling (GraphQL clients) makes exploitation trivial

## Recommendation

Restrict access to the `current_token_pending_claims` GraphQL table by:

1. **Implement row-level security** - Users should only query their own offers (as sender or recipient):
```json
{
  "role": "anonymous",
  "permission": {
    "columns": [...],
    "filter": {
      "_or": [
        {"from_address": {"_eq": "X-Hasura-User-Address"}},
        {"to_address": {"_eq": "X-Hasura-User-Address"}}
      ]
    }
  }
}
```

2. **Remove anonymous access** - Require authentication to query pending claims

3. **Consider privacy-by-design** - The Move framework could encrypt token offer details, revealing them only to authorized parties

## Proof of Concept

```graphql
# Query to enumerate all pending token offers
query GetAllPendingClaims {
  current_token_pending_claims(
    where: {amount: {_gt: "0"}}
    order_by: {last_transaction_timestamp: desc}
    limit: 100
  ) {
    from_address
    to_address
    token_data_id_hash
    collection_name
    name
    amount
    table_handle
    last_transaction_timestamp
  }
}

# Query to monitor specific user's offers
query GetUserOffers {
  current_token_pending_claims(
    where: {
      from_address: {_eq: "0xUSER_ADDRESS"}
      amount: {_gt: "0"}
    }
  ) {
    to_address
    token_data_id_hash
    amount
  }
}
```

Execute these queries against the Hasura GraphQL endpoint without any authentication to enumerate all pending token claims network-wide.

---

## Notes

This vulnerability represents **information disclosure** rather than a critical security flaw. The blockchain data is inherently public, but the indexer API makes enumeration trivially easy without requiring on-chain access or complex storage queries. While the security question suggests "front-running claim operations," the actual claim function's access control prevents direct exploitation—only privacy and market intelligence are compromised.

### Citations

**File:** aptos-move/framework/aptos-token/sources/token_transfers.move (L18-23)
```text
    struct PendingClaims has key {
        pending_claims: Table<TokenOfferId, Token>,
        offer_events: EventHandle<TokenOfferEvent>,
        cancel_offer_events: EventHandle<TokenCancelOfferEvent>,
        claim_events: EventHandle<TokenClaimEvent>,
    }
```

**File:** aptos-move/framework/aptos-token/sources/token_transfers.move (L163-176)
```text
    public fun claim(
        receiver: &signer,
        sender: address,
        token_id: TokenId,
    ) acquires PendingClaims {
        assert!(exists<PendingClaims>(sender), ETOKEN_OFFER_NOT_EXIST);
        let pending_claims =
            &mut PendingClaims[sender].pending_claims;
        let token_offer_id = create_token_offer_id(signer::address_of(receiver), token_id);
        assert!(pending_claims.contains(token_offer_id), error::not_found(ETOKEN_OFFER_NOT_EXIST));
        let tokens = pending_claims.remove(token_offer_id);
        let amount = token::get_token_amount(&tokens);
        token::deposit_token(receiver, tokens);

```

**File:** crates/indexer/src/models/token_models/token_claims.rs (L35-114)
```rust
impl CurrentTokenPendingClaim {
    /// Token claim is stored in a table in the offerer's account. The key is token_offer_id (token_id + to address)
    /// and value is token (token_id + amount)
    pub fn from_write_table_item(
        table_item: &APIWriteTableItem,
        txn_version: i64,
        txn_timestamp: chrono::NaiveDateTime,
        table_handle_to_owner: &TableHandleToOwner,
    ) -> anyhow::Result<Option<Self>> {
        let table_item_data = table_item.data.as_ref().unwrap();

        let maybe_offer = match TokenWriteSet::from_table_item_type(
            table_item_data.key_type.as_str(),
            &table_item_data.key,
            txn_version,
        )? {
            Some(TokenWriteSet::TokenOfferId(inner)) => Some(inner),
            _ => None,
        };
        if let Some(offer) = maybe_offer {
            let maybe_token = match TokenWriteSet::from_table_item_type(
                table_item_data.value_type.as_str(),
                &table_item_data.value,
                txn_version,
            )? {
                Some(TokenWriteSet::Token(inner)) => Some(inner),
                _ => None,
            };
            if let Some(token) = maybe_token {
                let table_handle = standardize_address(&table_item.handle.to_string());

                let maybe_table_metadata = table_handle_to_owner.get(&table_handle);

                if let Some(table_metadata) = maybe_table_metadata {
                    let token_id = offer.token_id;
                    let token_data_id_struct = token_id.token_data_id;
                    let collection_data_id_hash =
                        token_data_id_struct.get_collection_data_id_hash();
                    let token_data_id_hash = token_data_id_struct.to_hash();
                    // Basically adding 0x prefix to the previous 2 lines. This is to be consistent with Token V2
                    let collection_id = token_data_id_struct.get_collection_id();
                    let token_data_id = token_data_id_struct.to_id();
                    let collection_name = token_data_id_struct.get_collection_trunc();
                    let name = token_data_id_struct.get_name_trunc();

                    return Ok(Some(Self {
                        token_data_id_hash,
                        property_version: token_id.property_version,
                        from_address: standardize_address(&table_metadata.owner_address),
                        to_address: standardize_address(&offer.to_addr),
                        collection_data_id_hash,
                        creator_address: standardize_address(&token_data_id_struct.creator),
                        collection_name,
                        name,
                        amount: token.amount,
                        table_handle,
                        last_transaction_version: txn_version,
                        last_transaction_timestamp: txn_timestamp,
                        token_data_id,
                        collection_id,
                    }));
                } else {
                    aptos_logger::warn!(
                        transaction_version = txn_version,
                        table_handle = table_handle,
                        "Missing table handle metadata for TokenClaim. {:?}",
                        table_handle_to_owner
                    );
                }
            } else {
                aptos_logger::warn!(
                    transaction_version = txn_version,
                    value_type = table_item_data.value_type,
                    value = table_item_data.value,
                    "Expecting token as value for key = token_offer_id",
                );
            }
        }
        Ok(None)
    }
```

**File:** crates/aptos-localnet/src/hasura_metadata.json (L1824-1848)
```json
            "select_permissions": [
              {
                "role": "anonymous",
                "permission": {
                  "columns": [
                    "amount",
                    "collection_data_id_hash",
                    "collection_id",
                    "collection_name",
                    "creator_address",
                    "from_address",
                    "last_transaction_timestamp",
                    "last_transaction_version",
                    "name",
                    "property_version",
                    "table_handle",
                    "to_address",
                    "token_data_id",
                    "token_data_id_hash"
                  ],
                  "filter": {},
                  "limit": 100
                }
              }
            ]
```

**File:** crates/indexer/migrations/2022-09-22-185845_token_offers/up.sql (L77-79)
```sql
CREATE INDEX ctpc_th_index ON current_token_pending_claims (table_handle);
CREATE INDEX ctpc_from_am_index ON current_token_pending_claims (from_address, amount);
CREATE INDEX ctpc_to_am_index ON current_token_pending_claims (to_address, amount);
```
