# Audit Report

## Title
Database DoS Attack via Unbounded Row Loading in NFT Metadata Crawler Asset Uploader API

## Summary
The `query_status()` function in the NFT metadata crawler's asset uploader API loads all database rows matching a given `idempotency_key` and `application_id` into memory without any limits. An attacker can exploit this by first uploading a batch request with thousands or millions of URLs (all sharing the same idempotency key), then triggering a status query that loads all these rows simultaneously, causing excessive memory consumption and service crash.

## Finding Description
The vulnerability exists in the interaction between two API endpoints in the NFT metadata crawler's asset uploader service:

1. **Upload Endpoint** (`POST /upload`): Accepts a `BatchUploadRequest` containing an `idempotency_key`, `application_id`, and an array of `urls`. For each URL in the array, a separate row is inserted into the `asset_uploader_request_statuses` table with the same `idempotency_key` and `application_id` but different `asset_uri` values. [1](#0-0) [2](#0-1) 

The database schema defines a composite primary key of `(idempotency_key, application_id, asset_uri)`: [3](#0-2) 

**Critical Issue**: There is **no validation** on the size of the `urls` array in the upload request.

2. **Status Query Endpoint** (`GET /status/:application_id/:idempotency_key`): Queries the database filtering only by `idempotency_key` and `application_id`, **not** by `asset_uri`: [4](#0-3) 

The query at line 47-50 filters only by `idempotency_key` and `application_id`, meaning it will match ALL rows with that combination regardless of how many different `asset_uri` values exist. The `.load(conn)` call at line 55 then loads **all matching rows into memory at once**.

**Attack Path**:
1. Attacker sends `POST /upload` with payload:
   ```json
   {
     "idempotency_key": "attack-key-123",
     "application_id": "attack-app-456", 
     "urls": ["http://example.com/1", "http://example.com/2", ..., "http://example.com/1000000"]
   }
   ```
2. The system inserts 1,000,000 rows into the database (one per URL)
3. Attacker sends `GET /status/attack-app-456/attack-key-123`
4. The `query_status()` function attempts to load all 1,000,000 rows into memory
5. Service crashes due to Out-of-Memory (OOM) or becomes unresponsive

This breaks **Invariant #9**: "All operations must respect gas, storage, and computational limits" - the service has no resource limits on query result sizes.

## Impact Explanation
**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability qualifies as **Medium severity** because:
- It causes **API crashes** (explicitly listed as High severity in the bounty program, but this is a supporting service, not core validator API)
- It enables **Denial of Service** against the NFT metadata crawler service
- It can degrade database performance affecting all users of the service
- It does **not** directly affect consensus, validator operations, funds, or core blockchain functionality

While the NFT metadata crawler is an ecosystem tool rather than a core blockchain component, service availability attacks that can crash infrastructure services fall under the Medium severity category per the bug bounty guidelines for "State inconsistencies requiring intervention."

## Likelihood Explanation
**Likelihood: High**

This vulnerability is highly likely to be exploited because:
- The API endpoints are publicly accessible (no authentication mentioned in the code)
- The attack requires only standard HTTP requests
- No special permissions or validator access needed
- The attack is simple to execute (single POST followed by single GET)
- No rate limiting or request size validation observed in the code
- An attacker can easily script this attack to repeatedly crash the service

The only limiting factor is whether the upload endpoint accepts arbitrarily large request bodies, but no body size limits are configured in the router setup: [5](#0-4) 

## Recommendation

Implement multiple layers of defense:

**1. Add URL Array Size Validation** (Primary Fix):
```rust
// In upload_batch.rs or mod.rs
const MAX_URLS_PER_BATCH: usize = 100;

pub fn upload_batch(
    pool: Pool<ConnectionManager<PgConnection>>,
    request: &BatchUploadRequest,
) -> anyhow::Result<IdempotencyTuple> {
    // Add validation
    if request.urls.len() > MAX_URLS_PER_BATCH {
        return Err(anyhow::anyhow!(
            "Batch size {} exceeds maximum allowed size of {}",
            request.urls.len(),
            MAX_URLS_PER_BATCH
        ));
    }
    
    let mut conn = pool.get()?;
    // ... rest of implementation
}
```

**2. Add Pagination to Status Query**:
```rust
fn query_status(
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    idempotency_tuple: &IdempotencyTuple,
    limit: Option<i64>,
) -> anyhow::Result<Vec<AssetUploaderRequestStatusesQuery>> {
    use schema::nft_metadata_crawler::asset_uploader_request_statuses::dsl::*;

    let mut query = asset_uploader_request_statuses
        .filter(
            idempotency_key
                .eq(&idempotency_tuple.idempotency_key)
                .and(application_id.eq(&idempotency_tuple.application_id)),
        )
        .into_boxed();
    
    if let Some(limit_val) = limit {
        query = query.limit(limit_val);
    }

    let rows = query.load(conn)?;
    Ok(rows)
}
```

**3. Add Request Body Size Limits** to the Axum router using `RequestBodyLimitLayer`.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[cfg(test)]
mod test_dos_vulnerability {
    use super::*;
    use url::Url;
    
    #[tokio::test]
    async fn test_database_dos_attack() {
        // Setup: Create test database connection pool
        let pool = setup_test_pool();
        
        // Attack Step 1: Upload batch with large number of URLs
        let attack_urls: Vec<Url> = (0..10000)
            .map(|i| Url::parse(&format!("http://example.com/image_{}.png", i)).unwrap())
            .collect();
        
        let attack_request = BatchUploadRequest {
            idempotency_tuple: IdempotencyTuple {
                idempotency_key: "attack-key".to_string(),
                application_id: "attack-app".to_string(),
            },
            urls: attack_urls,
        };
        
        // This should succeed and insert 10,000 rows
        let result = upload_batch(pool.clone(), &attack_request);
        assert!(result.is_ok());
        
        // Attack Step 2: Query status to load all rows into memory
        // This will attempt to load 10,000 rows at once
        let status_result = get_status(
            pool.clone(), 
            &attack_request.idempotency_tuple
        );
        
        // With 10,000 rows, this may succeed but consume excessive memory
        // With 1,000,000 rows, this would likely OOM crash the service
        if let Ok(statuses) = status_result {
            println!("Loaded {} rows into memory", statuses.len());
            assert_eq!(statuses.len(), 10000);
        }
    }
}
```

**Notes**

This vulnerability is specific to the NFT metadata crawler's asset uploader service, which is an ecosystem tool for managing NFT metadata and CDN uploads. While it does not directly impact core blockchain consensus, execution, or state management, it represents a denial-of-service vulnerability against supporting infrastructure that could disrupt NFT-related services in the Aptos ecosystem. The fix is straightforward: add input validation to limit batch sizes and implement pagination for query results.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/mod.rs (L37-42)
```rust
#[derive(Debug, Deserialize)]
struct BatchUploadRequest {
    #[serde(flatten)]
    idempotency_tuple: IdempotencyTuple,
    urls: Vec<Url>,
}
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/mod.rs (L138-148)
```rust
impl Server for AssetUploaderApiContext {
    fn build_router(&self) -> axum::Router {
        let self_arc = Arc::new(self.clone());
        axum::Router::new()
            .route("/upload", post(Self::handle_upload_batch))
            .route(
                "/status/:application_id/:idempotency_key",
                get(Self::handle_get_status),
            )
            .layer(Extension(self_arc.clone()))
    }
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/upload_batch.rs (L26-40)
```rust
    let mut request_statuses = vec![];
    for url in &request.urls {
        if let Some(cdn_image_uri) = existing_rows.get(url.as_str()) {
            request_statuses.push(AssetUploaderRequestStatuses::new_completed(
                &request.idempotency_tuple,
                url.as_str(),
                cdn_image_uri.as_deref().unwrap(), // Safe to unwrap because we checked for existence when querying
            ));
        } else {
            request_statuses.push(AssetUploaderRequestStatuses::new(
                &request.idempotency_tuple,
                url.as_str(),
            ));
        }
    }
```

**File:** ecosystem/nft-metadata-crawler/src/models/asset_uploader_request_statuses_query.rs (L10-10)
```rust
#[diesel(primary_key(idempotency_key, application_id, asset_uri))]
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/get_status.rs (L41-57)
```rust
fn query_status(
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    idempotency_tuple: &IdempotencyTuple,
) -> anyhow::Result<Vec<AssetUploaderRequestStatusesQuery>> {
    use schema::nft_metadata_crawler::asset_uploader_request_statuses::dsl::*;

    let query = asset_uploader_request_statuses.filter(
        idempotency_key
            .eq(&idempotency_tuple.idempotency_key)
            .and(application_id.eq(&idempotency_tuple.application_id)),
    );

    let debug_query = diesel::debug_query::<diesel::pg::Pg, _>(&query).to_string();
    debug!("Executing Query: {}", debug_query);
    let rows = query.load(conn)?;
    Ok(rows)
}
```
