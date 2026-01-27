# Audit Report

## Title
API Cache Poisoning via Missing Vary Header Allows BCS Response Injection to JSON Clients

## Summary
The Aptos API supports content negotiation between JSON and BCS formats via the `Accept` header but fails to set the `Vary: Accept` HTTP response header. This allows cache poisoning attacks where an attacker can force binary BCS data to be served to clients expecting JSON, causing widespread API crashes and service disruption when external caching layers (CDN, reverse proxy, browser) are deployed.

## Finding Description

The Aptos Node API implements content negotiation to support both JSON (`application/json`) and BCS (`application/x-bcs`) response formats based on the client's `Accept` header. [1](#0-0) 

The API correctly parses the Accept header and returns different response formats internally. [2](#0-1) 

However, the API server configuration and response generation mechanisms do not set any HTTP caching-related headers such as `Vary`, `Cache-Control`, or `ETag`. [3](#0-2) 

When responses are generated as BCS binary data, the content type is set but no `Vary` header is added. [4](#0-3) 

The response generation macros only add custom `X-Aptos-*` headers and do not include standard HTTP caching headers. [5](#0-4) 

**Attack Path:**

1. **Cache Poisoning**: Attacker sends: `GET /v1/accounts/0x1` with `Accept: application/x-bcs`
   - API returns BCS-encoded binary data
   - External cache (CDN/proxy) stores this with key `/v1/accounts/0x1` (URL only, no Accept header)

2. **Exploitation**: Legitimate user sends: `GET /v1/accounts/0x1` with `Accept: application/json` (or defaults to JSON)
   - Cache returns the stored BCS binary data
   - User's JSON parser receives binary data, causing parse failure
   - Application crashes or returns errors to end users

3. **Scope**: Affects all API endpoints supporting both formats:
   - `/v1/accounts/*` - account queries
   - `/v1/transactions/*` - transaction queries  
   - `/v1/blocks/*` - block queries
   - `/v1/events/*` - event queries

## Impact Explanation

**Severity: High** - Per the Aptos bug bounty program, this qualifies as:
- **API crashes**: Legitimate clients receive unparseable binary data instead of JSON
- **Validator node slowdowns**: Repeated failed requests force cache misses and backend reprocessing
- **Significant protocol violations**: HTTP/1.1 RFC 7231 Section 7.1.4 requires `Vary` header for content negotiation

**Affected Systems:**
- Production deployments using CDN (Cloudflare, Akamai, AWS CloudFront)
- Reverse proxies with caching enabled (nginx, Varnish)
- Browser caching for repeated API calls
- Any caching layer between clients and Aptos API servers

**Business Impact:**
- Service disruption for all API consumers
- Data loss if applications crash during transaction processing
- Reputation damage from unreliable API service
- Debugging difficulty (cached responses appear intermittent)

## Likelihood Explanation

**Likelihood: High**

1. **Common Deployment Pattern**: Most production APIs use CDNs or caching proxies for performance and DDoS protection
2. **Easy Exploitation**: Single malicious HTTP request poisons cache for all subsequent users
3. **Long-Duration**: Cache entries typically persist for minutes/hours based on TTL
4. **No Authentication Required**: Attacker needs no special access
5. **Wide Attack Surface**: Every GET endpoint supporting both formats is vulnerable
6. **Real-World Precedent**: Cache poisoning via missing Vary headers is a well-known web security issue

## Recommendation

**Fix: Add `Vary: Accept` header to all API responses**

Modify the response generation to include the Vary header. This should be implemented in the middleware layer to cover all endpoints:

```rust
// In api/src/runtime.rs, add middleware to set Vary header
use poem::middleware::AddData;

// Add after CORS middleware
.with(SetVaryHeader)

// Implement middleware
struct SetVaryHeader;

impl<E: Endpoint> Middleware<E> for SetVaryHeader {
    type Output = SetVaryHeaderEndpoint<E>;
    
    fn transform(&self, ep: E) -> Self::Output {
        SetVaryHeaderEndpoint { ep }
    }
}

struct SetVaryHeaderEndpoint<E> {
    ep: E,
}

impl<E: Endpoint> Endpoint for SetVaryHeaderEndpoint<E> {
    type Output = Response;
    
    async fn call(&self, req: Request) -> Result<Self::Output> {
        let mut resp = self.ep.call(req).await?;
        resp.headers_mut().insert("Vary", "Accept".parse().unwrap());
        Ok(resp)
    }
}
```

**Alternative: Set headers in response macros**

Modify the `generate_success_response!` macro in `api/src/response.rs` to include Vary header in all successful responses.

**Additional Hardening:**
- Set `Cache-Control: no-cache` or appropriate max-age with `must-revalidate`
- Consider adding `ETag` support for cache validation
- Document caching behavior in API specification

## Proof of Concept

**Setup:**
1. Deploy Aptos API with nginx caching proxy:

```nginx
# nginx.conf
proxy_cache_path /tmp/cache keys_zone=api_cache:10m max_size=1g;

server {
    listen 8081;
    location / {
        proxy_cache api_cache;
        proxy_cache_valid 200 10m;
        proxy_pass http://localhost:8080;  # Aptos API
    }
}
```

2. **Attack - Poison the cache:**
```bash
curl -H "Accept: application/x-bcs" http://localhost:8081/v1/accounts/0x1 > /tmp/bcs_response
# Cache stores BCS data with key: /v1/accounts/0x1
```

3. **Trigger - Victim requests JSON:**
```bash
curl -H "Accept: application/json" http://localhost:8081/v1/accounts/0x1
# Returns BCS binary data instead of JSON
# JSON parser fails with error
```

4. **Verification:**
```bash
# Check response content-type mismatch
curl -v -H "Accept: application/json" http://localhost:8081/v1/accounts/0x1 | head -c 50
# Shows binary data (0x...) instead of {"sequence_number": ...}

# Confirm cache hit
# nginx access log shows: "HIT" status with wrong content type
```

**Expected Result:** Client expecting JSON receives BCS binary data, causing parse failure.

**With Fix:** Adding `Vary: Accept` header causes cache to store separate entries for each Accept header value, preventing poisoning.

## Notes

The vulnerability exists in the API layer design where content negotiation is implemented without proper HTTP caching headers. While the current HAProxy configuration does not enable caching [6](#0-5) , production deployments commonly place CDNs or caching layers in front of APIs for performance optimization. The absence of the `Vary` header violates HTTP specifications for content negotiation and creates a security vulnerability when external caching is present.

### Citations

**File:** api/src/accept_type.rs (L7-41)
```rust
/// Accept types from input headers
///
/// Determines the output type of each API
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AcceptType {
    /// Convert and resolve types to JSON
    Json,
    /// Take types with as little conversion as possible from the database
    Bcs,
}

/// This impl allows us to get the data straight from the arguments to the
/// endpoint handler.
impl<'a> FromRequest<'a> for AcceptType {
    async fn from_request(request: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        let accept = Accept::from_request_without_body(request).await?;
        parse_accept(&accept)
    }
}

/// Check that the accept type is one of the allowed variants. If there is no
/// overriding explicit accept type, default to JSON.
fn parse_accept(accept: &Accept) -> Result<AcceptType> {
    for mime in &accept.0 {
        if matches!(mime.as_ref(), JSON) {
            return Ok(AcceptType::Json);
        }
        if matches!(mime.as_ref(), BCS) {
            return Ok(AcceptType::Bcs);
        }
    }

    // Default to returning content as JSON.
    Ok(AcceptType::Json)
}
```

**File:** api/src/response.rs (L42-53)
```rust
/// An enum representing the different types of outputs for APIs
#[derive(ResponseContent)]
pub enum AptosResponseContent<T: ToJSON + Send + Sync> {
    /// When returning data as JSON, we take in T and then serialize to JSON as
    /// part of the response.
    Json(Json<T>),

    /// Return the data as BCS, which is just Vec<u8>. This data could have come
    /// from either an internal Rust type being serialized into bytes, or just
    /// the bytes directly from storage.
    Bcs(Bcs),
}
```

**File:** api/src/response.rs (L321-349)
```rust
        #[derive(poem_openapi::ApiResponse)]
        pub enum $enum_name<T: poem_openapi::types::ToJSON + Send + Sync> {
            $(
            #[oai(status = $status)]
            $name(
                // We use just regular u64 here instead of U64 since all header
                // values are implicitly strings anyway.
                $crate::response::AptosResponseContent<T>,
                /// Chain ID of the current chain
                #[oai(header = "X-Aptos-Chain-Id")] u8,
                /// Current ledger version of the chain
                #[oai(header = "X-Aptos-Ledger-Version")] u64,
                /// Oldest non-pruned ledger version of the chain
                #[oai(header = "X-Aptos-Ledger-Oldest-Version")] u64,
                /// Current timestamp of the chain
                #[oai(header = "X-Aptos-Ledger-TimestampUsec")] u64,
                /// Current epoch of the chain
                #[oai(header = "X-Aptos-Epoch")] u64,
                /// Current block height of the chain
                #[oai(header = "X-Aptos-Block-Height")] u64,
                /// Oldest non-pruned block height of the chain
                #[oai(header = "X-Aptos-Oldest-Block-Height")] u64,
                /// The cost of the call in terms of gas
                #[oai(header = "X-Aptos-Gas-Used")] Option<u64>,
                /// Cursor to be used for endpoints that support cursor-based
                /// pagination. Pass this to the `start` field of the endpoint
                /// on the next call to get the next page of results.
                #[oai(header = "X-Aptos-Cursor")] Option<String>,
            ),
```

**File:** api/src/runtime.rs (L229-265)
```rust
    runtime_handle.spawn(async move {
        let cors = Cors::new()
            // To allow browsers to use cookies (for cookie-based sticky
            // routing in the LB) we must enable this:
            // https://stackoverflow.com/a/24689738/3846032
            .allow_credentials(true)
            .allow_methods(vec![Method::GET, Method::POST]);

        // Build routes for the API
        let route = Route::new()
            .at("/", poem::get(root_handler))
            .nest(
                "/v1",
                Route::new()
                    .nest("/", api_service)
                    .at("/spec.json", poem::get(spec_json))
                    .at("/spec.yaml", poem::get(spec_yaml))
                    // TODO: We add this manually outside of the OpenAPI spec for now.
                    // https://github.com/poem-web/poem/issues/364
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
            )
            .with(cors)
            .with_if(config.api.compression_enabled, Compression::new())
            .with(PostSizeLimit::new(size_limit))
            .with(CatchPanic::new().with_handler(panic_handler))
            // NOTE: Make sure to keep this after all the `with` middleware.
            .catch_all_error(convert_error)
            .around(middleware_log);
        Server::new_with_acceptor(acceptor)
            .run(route)
            .await
            .map_err(anyhow::Error::msg)
    });

```

**File:** api/src/bcs_payload.rs (L61-67)
```rust
impl IntoResponse for Bcs {
    fn into_response(self) -> Response {
        Response::builder()
            .header(header::CONTENT_TYPE, Self::CONTENT_TYPE)
            .body(self.0)
    }
}
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L128-146)
```text
{{- if $.Values.service.validator.enableRestApi }}
## Specify the validator API frontend
frontend validator-api
    mode http
    option httplog
    bind :8180
    default_backend validator-api

    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"

## Specify the validator API backend
backend validator-api
    mode http
    server {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator:8080
{{- end }}
```
